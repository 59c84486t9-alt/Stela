// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent hardware/peripheral CRC peers around the actual retained owner.
use super::super::i2c_block::{Controller, OwnedConfiguration};
use super::*;
use crate::bus::pci::{self, ConfigSpace, Function};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};

const ALERT: u8 = 1 << 5;
const AUX_OTHER: u8 = 0x80;
const CONFIG_OTHER: u8 = 0xa0;

#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
struct Lease(Rc<Cell<usize>>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

// Host's serial CRC-8 and the independent peripheral's nibble-table CRC both
// cover on-wire address phases/counts, not just the native payload bytes.
fn host_crc(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for byte in bytes {
        crc ^= byte;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x80 != 0 { 7 } else { 0 };
        }
    }
    crc
}
fn peripheral_crc(bytes: &[u8]) -> u8 {
    const TABLE: [u8; 16] = [0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45];
    bytes.iter().fold(0, |mut crc, byte| {
        for nibble in [byte >> 4, byte & 15] {
            crc = (crc << 4) ^ TABLE[usize::from((crc >> 4) ^ nibble)];
        }
        crc
    })
}

struct Hardware {
    registers: [u8; 32],
    status: u8,
    time: Time,
    device: u16,
    identity: u32,
    configuration: u8,
    configuration_reads: usize,
    identity_reads: usize,
    configuration_writes: usize,
    active: bool,
    due: u64,
    buffer: Vec<u8>,
    index: usize,
    reply: Vec<u8>,
    starts: Vec<(u8, u8, u8)>,
    wire: Vec<Vec<u8>>,
    accesses: Vec<(bool, u8, u8)>,
    read_counts: [usize; 32],
    corrupt_packet: bool,
    completion_status: u8,
    crc_without_device_error: bool,
    sticky_crc: bool,
    reject_crc_enable: bool,
    reject_crc_clear: bool,
    change_unrelated_aux: bool,
    remove_on_completion: bool,
    change_config_on_completion: bool,
    hang: bool,
    kill_stuck: bool,
    kills: usize,
    jump_read: Option<(u8, usize, u64)>,
    jump_write: Option<(u8, u64)>,
    jump_configuration: bool,
    late_status: Option<u8>,
}
impl Hardware {
    fn step(&mut self) {
        if !self.active || self.hang || self.time.now_us().wrapping_sub(self.due) >= (1u64 << 63) {
            return;
        }
        self.active = false;
        let protocol = self.registers[usize::from(HOST_CONTROL)] & 0x1c;
        let address = self.registers[usize::from(HOST_ADDRESS)];
        let read = address & 1 != 0;
        let command = self.registers[usize::from(HOST_COMMAND)];
        let crc = self.registers[usize::from(AUX_CONTROL)] & AUX_CRC != 0;
        let mut wire = Vec::new();
        if protocol == PROTOCOL_BYTE {
            wire.push(address);
            wire.push(if read { self.reply[0] } else { command });
        } else {
            wire.extend_from_slice(&[address & !1, command]);
            if read {
                wire.push(address);
            }
            if protocol == PROTOCOL_BLOCK {
                if read {
                    wire.push(self.reply.len() as u8);
                    wire.extend_from_slice(&self.reply);
                } else {
                    let length = usize::from(self.registers[usize::from(HOST_DATA0)]);
                    assert_eq!(
                        self.buffer.len(),
                        length,
                        "CRC is not a native payload byte"
                    );
                    wire.push(length as u8);
                    wire.extend_from_slice(&self.buffer);
                }
            } else {
                let bytes = if read {
                    &self.reply[..]
                } else {
                    &self.registers[5..7]
                };
                wire.extend_from_slice(
                    &bytes[..if protocol == PROTOCOL_WORD_DATA { 2 } else { 1 }],
                );
            }
        }
        let mut failed_crc = false;
        if crc {
            let mut packet = if read {
                peripheral_crc(&wire)
            } else {
                host_crc(&wire)
            };
            if self.corrupt_packet {
                packet ^= 0x20;
            }
            let verifier = if read {
                host_crc(&wire)
            } else {
                peripheral_crc(&wire)
            };
            failed_crc = packet != verifier;
            wire.push(packet);
        }
        self.wire.push(wire);
        if read {
            self.registers[5] = if protocol == PROTOCOL_BLOCK {
                self.reply.len() as u8
            } else {
                self.reply[0]
            };
            self.registers[6] = self.reply.get(1).copied().unwrap_or(0);
            if protocol == PROTOCOL_BLOCK {
                self.buffer = self.reply.clone();
            }
        }
        self.status = (self.status & (INUSE | ALERT)) | self.completion_status;
        if failed_crc {
            self.registers[usize::from(AUX_STATUS)] |= AUX_CRC_ERROR;
            if !self.crc_without_device_error {
                self.status |= DEV_ERR;
            }
        }
        if self.status & ERROR_FLAGS == 0 {
            self.status |= INTR;
        }
        if self.change_unrelated_aux {
            self.registers[usize::from(AUX_CONTROL)] ^= 0x10;
        }
        if self.remove_on_completion {
            self.identity = u32::MAX;
        }
        if self.change_config_on_completion {
            self.configuration |= HOST_I2C;
        }
    }
}
struct Regs {
    state: Rc<RefCell<Hardware>>,
    _lease: Lease,
}
impl Registers for Regs {
    fn read8(&mut self, offset: u8) -> u8 {
        let mut h = self.state.borrow_mut();
        h.step();
        h.read_counts[usize::from(offset)] += 1;
        let value = match offset {
            HOST_STATUS => {
                let old = h.status;
                h.status |= INUSE;
                if old & ERROR_FLAGS != 0
                    && let Some(status) = h.late_status.take()
                {
                    h.status |= status;
                }
                old
            }
            HOST_CONTROL => {
                h.index = 0;
                h.registers[2]
            }
            BLOCK_DATA => {
                let value = h.buffer[h.index];
                h.index += 1;
                value
            }
            _ => h.registers[usize::from(offset)],
        };
        h.accesses.push((false, offset, value));
        if let Some((reg, count, delta)) = h.jump_read
            && reg == offset
            && count == h.read_counts[usize::from(offset)]
        {
            h.time.0.set(h.time.now_us().wrapping_add(delta));
        }
        value
    }
    fn write8(&mut self, offset: u8, value: u8) {
        let mut h = self.state.borrow_mut();
        h.step();
        h.accesses.push((true, offset, value));
        if let Some((reg, delta)) = h.jump_write
            && reg == offset
        {
            h.time.0.set(h.time.now_us().wrapping_add(delta));
            h.jump_write = None;
        }
        match offset {
            HOST_STATUS => h.status &= !(value & !HOST_BUSY),
            AUX_STATUS => {
                if !h.sticky_crc {
                    h.registers[usize::from(offset)] &= !value;
                }
            }
            AUX_CONTROL => {
                let mut stored = value;
                if h.reject_crc_enable {
                    stored &= !AUX_CRC;
                }
                if h.reject_crc_clear && h.registers[13] & AUX_CRC != 0 {
                    stored |= AUX_CRC;
                }
                h.registers[13] = stored;
            }
            HOST_CONTROL => {
                h.registers[2] = value;
                if value & KILL != 0 {
                    h.kills += 1;
                    if !h.kill_stuck {
                        h.active = false;
                        h.status = (h.status & (INUSE | ALERT)) | FAILED;
                    }
                } else if value & START != 0 {
                    assert!(!h.active);
                    assert_eq!(
                        h.configuration & (HOST_ENABLED | HOST_SMI | HOST_I2C),
                        HOST_ENABLED
                    );
                    assert_ne!(h.status & INUSE, 0);
                    assert_eq!(value & 0x81, 0, "hardware PEC uses AUXCRC, not PEC_EN/IRQ");
                    h.active = true;
                    h.status |= HOST_BUSY;
                    h.due = h.time.now_us().wrapping_add(3);
                    let auxiliary = h.registers[13];
                    let address = h.registers[4];
                    h.starts.push((value, auxiliary, address));
                }
            }
            BLOCK_DATA => {
                if h.index == 0 {
                    h.buffer.clear();
                }
                h.buffer.push(value);
                h.index += 1;
            }
            _ => h.registers[usize::from(offset)] = value,
        }
    }
}
struct NativeConfig(Rc<RefCell<Hardware>>);
impl ConfigSpace for NativeConfig {
    fn read32(&self, offset: u16) -> u32 {
        let mut h = self.0.borrow_mut();
        match offset {
            0 => {
                h.identity_reads += 1;
                h.identity
            }
            8 => 0x0c05_0000,
            12 => 0,
            _ => 0,
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("no wide PCI writes");
    }
    fn read8(&self, offset: u16) -> u8 {
        assert_eq!(offset, 0x40);
        let mut h = self.0.borrow_mut();
        h.configuration_reads += 1;
        if h.jump_configuration && h.configuration_reads == 2 {
            h.time.0.set(h.time.now_us().wrapping_add(1000));
        }
        h.configuration
    }
    fn write8(&mut self, _: u16, _: u8) {
        self.0.borrow_mut().configuration_writes += 1;
        panic!("PEC does not change PCI host timing");
    }
}
type Host = Controller<Regs, Time, OwnedConfiguration<NativeConfig, Lease>>;
struct Fixture {
    host: Host,
    state: Rc<RefCell<Hardware>>,
    register_drop: Rc<Cell<usize>>,
    configuration_drop: Rc<Cell<usize>>,
}
fn fixture(device: u16, buffer: bool) -> Fixture {
    let time = Time(Rc::new(Cell::new(u64::MAX - 10)));
    let state = Rc::new(RefCell::new(Hardware {
        registers: [0; 32],
        status: ALERT,
        time: time.clone(),
        device,
        identity: 0x8086 | u32::from(device) << 16,
        configuration: HOST_ENABLED | CONFIG_OTHER,
        configuration_reads: 0,
        identity_reads: 0,
        configuration_writes: 0,
        active: false,
        due: 0,
        buffer: Vec::new(),
        index: 0,
        reply: vec![0x76, 0x98, 0x4c],
        starts: Vec::new(),
        wire: Vec::new(),
        accesses: Vec::new(),
        read_counts: [0; 32],
        corrupt_packet: false,
        completion_status: 0,
        crc_without_device_error: false,
        sticky_crc: false,
        reject_crc_enable: false,
        reject_crc_clear: false,
        change_unrelated_aux: false,
        remove_on_completion: false,
        change_config_on_completion: false,
        hang: false,
        kill_stuck: false,
        kills: 0,
        jump_read: None,
        jump_write: None,
        jump_configuration: false,
        late_status: None,
    }));
    state.borrow_mut().registers[13] = AUX_OTHER;
    let register_drop = Rc::new(Cell::new(0));
    let configuration_drop = Rc::new(Cell::new(0));
    let host = I801::new(
        Regs {
            state: state.clone(),
            _lease: Lease(register_drop.clone()),
        },
        time,
        ControllerInfo::from_pci_id(0x8086, device).unwrap(),
        HOST_ENABLED | CONFIG_OTHER,
        Config {
            timeout_us: 1000,
            recovery_timeout_us: 20,
            use_block_buffer: buffer,
        },
    )
    .ok()
    .unwrap();
    let function = Function::new(
        pci::Address {
            segment: 0,
            bus: 0,
            device: 31,
            function: 4,
        },
        NativeConfig(state.clone()),
    )
    .unwrap();
    // SAFETY: the actual model function and register owner share the same
    // powered, exclusive controller/reset epoch; these are retained root leases.
    let configuration =
        unsafe { OwnedConfiguration::claim(function, Lease(configuration_drop.clone())) }
            .ok()
            .unwrap();
    let host = unsafe { Controller::claim(host, configuration) }
        .ok()
        .unwrap();
    {
        let mut h = state.borrow_mut();
        h.accesses.clear();
        h.read_counts = [0; 32];
        h.configuration_reads = 0;
        h.identity_reads = 0;
    }
    Fixture {
        host,
        state,
        register_drop,
        configuration_drop,
    }
}
fn address() -> Address {
    Address::new(0x2c).unwrap()
}
fn request(
    host: &mut Host,
    kind: usize,
    byte: &mut u8,
    word: &mut u16,
    block: &mut Block,
) -> Result<(), Error> {
    let transaction = match kind {
        0 => Transaction::ReceiveByte(byte),
        1 => Transaction::ReadByte {
            command: 0xa7,
            data: byte,
        },
        2 => Transaction::ReadWord {
            command: 0xa7,
            data: word,
        },
        3 => Transaction::ReadBlock {
            command: 0xa7,
            data: block,
        },
        _ => unreachable!(),
    };
    host.transaction(address(), transaction, true)
}
fn check_clean(f: &Fixture) {
    let h = f.state.borrow();
    assert_eq!(h.registers[13], AUX_OTHER);
    assert_eq!(h.registers[12] & AUX_CRC_ERROR, 0);
    assert_eq!(h.status, ALERT);
    assert_eq!(h.configuration, HOST_ENABLED | CONFIG_OTHER);
    assert_eq!(h.configuration_writes, 0);
    assert!(!h.active);
    assert!(f.host.failure().is_none());
}

#[test]
fn retained_actual_pci_owner_drives_crc_wire_for_all_admitted_protocols() {
    assert_eq!(host_crc(b"123456789"), 0xf4);
    assert_eq!(peripheral_crc(b"123456789"), 0xf4);
    for device in [0x24c3, 0x24d3, 0x7e22, 0x6e23] {
        let mut f = fixture(device, true);
        f.host
            .transaction(address(), Transaction::SendByte(0x11), true)
            .unwrap();
        f.host
            .transaction(
                address(),
                Transaction::WriteByte {
                    command: 0x22,
                    data: 0x33,
                },
                true,
            )
            .unwrap();
        f.host
            .transaction(
                address(),
                Transaction::WriteWord {
                    command: 0x44,
                    data: 0x5566,
                },
                true,
            )
            .unwrap();
        for kind in 0..4 {
            let (mut byte, mut word, mut block) = (0xa5, 0xa5a5, Block::default());
            request(&mut f.host, kind, &mut byte, &mut word, &mut block).unwrap();
            match kind {
                0 | 1 => assert_eq!(byte, 0x76),
                2 => assert_eq!(word, 0x9876),
                3 => assert_eq!(block.as_slice(), &[0x76, 0x98, 0x4c]),
                _ => unreachable!(),
            }
            check_clean(&f);
        }
        let h = f.state.borrow();
        assert_eq!(h.device, device);
        assert!(
            h.starts
                .iter()
                .all(|(control, auxiliary, _)| control & 0x81 == 0 && auxiliary & AUX_CRC != 0)
        );
        let payloads = [
            vec![0x58, 0x11],
            vec![0x58, 0x22, 0x33],
            vec![0x58, 0x44, 0x66, 0x55],
            vec![0x59, 0x76],
            vec![0x58, 0xa7, 0x59, 0x76],
            vec![0x58, 0xa7, 0x59, 0x76, 0x98],
            vec![0x58, 0xa7, 0x59, 3, 0x76, 0x98, 0x4c],
        ];
        for (wire, bytes) in h.wire.iter().zip(payloads) {
            assert_eq!(&wire[..wire.len() - 1], bytes);
            assert_eq!(host_crc(wire), 0, "complete wire including packet CRC");
        }
        assert_eq!(h.identity_reads, 14);
        assert_eq!(h.configuration_reads, 14);
    }
}

#[test]
fn block_crc_covers_real_count_and_every_payload_byte_lengths_one_through_32() {
    let mut f = fixture(0x24c3, true);
    for length in 1..=MAX_BLOCK {
        let bytes: Vec<u8> = (0..length)
            .map(|n| (n as u8).wrapping_mul(29).wrapping_add(3))
            .collect();
        f.host
            .transaction(
                address(),
                Transaction::WriteBlock {
                    command: 0xa7,
                    data: &bytes,
                },
                true,
            )
            .unwrap();
        f.state.borrow_mut().reply = bytes.clone();
        let mut block = Block::default();
        f.host
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 0xa7,
                    data: &mut block,
                },
                true,
            )
            .unwrap();
        assert_eq!(block.as_slice(), bytes);
        let h = f.state.borrow();
        for read in [false, true] {
            let wire = &h.wire[h.wire.len() - if read { 1 } else { 2 }];
            let count = if read { 3 } else { 2 };
            assert_eq!(wire[count], length as u8);
            assert_eq!(&wire[count + 1..wire.len() - 1], bytes);
            assert_eq!(host_crc(wire), 0);
        }
        drop(h);
        check_clean(&f);
    }
}

#[test]
fn independent_bad_packet_never_publishes_any_caller_read_output() {
    for kind in 0..4 {
        for no_device_flag in [false, true] {
            let mut f = fixture(0x7e22, true);
            f.state.borrow_mut().corrupt_packet = true;
            f.state.borrow_mut().registers[12] = 0x80;
            f.state.borrow_mut().crc_without_device_error = no_device_flag;
            let (mut byte, mut word, mut block) =
                (0xa5, 0xa5a5, Block::from_slice(&[0xa5, 0x5a]).unwrap());
            let error = request(&mut f.host, kind, &mut byte, &mut word, &mut block).unwrap_err();
            assert_eq!(
                error.kind,
                ErrorKind::PecMismatch {
                    auxiliary_status: 0x80 | AUX_CRC_ERROR
                }
            );
            assert_eq!(error.status & DEV_ERR != 0, !no_device_flag);
            assert_eq!(error.recovery, Recovery::Cleared);
            assert_eq!(
                (byte, word, block.as_slice()),
                (0xa5, 0xa5a5, &[0xa5, 0x5a][..])
            );
            check_clean(&f);
            assert_eq!(f.state.borrow().registers[12], 0x80);
            f.state.borrow_mut().corrupt_packet = false;
            request(&mut f.host, kind, &mut byte, &mut word, &mut block).unwrap();
            check_clean(&f);
        }
    }
}

#[test]
fn raw_host_old_profiles_process_calls_and_unbuffered_pec_refuse_before_io() {
    for device in [0x2413, 0x2423, 0x2443, 0x2483] {
        assert!(
            !ControllerInfo::from_pci_id(0x8086, device)
                .unwrap()
                .has_hardware_pec()
        );
        let mut f = fixture(device, true);
        assert_eq!(
            f.host
                .transaction(address(), Transaction::SendByte(1), true)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedPec
        );
        let h = f.state.borrow();
        assert!(h.accesses.is_empty());
        assert_eq!((h.identity_reads, h.configuration_reads), (0, 0));
    }
    for buffer in [false, true] {
        let mut f = fixture(0x7e22, buffer);
        let mut response = 0xa5a5;
        assert_eq!(
            f.host
                .transaction(
                    address(),
                    Transaction::ProcessCall {
                        command: 1,
                        request: 2,
                        response: &mut response
                    },
                    true
                )
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedPec
        );
        if !buffer {
            assert_eq!(
                f.host
                    .transaction(
                        address(),
                        Transaction::WriteBlock {
                            command: 1,
                            data: &[2]
                        },
                        true
                    )
                    .unwrap_err()
                    .kind,
                ErrorKind::UnsupportedPec
            );
        }
        assert_eq!(response, 0xa5a5);
        let h = f.state.borrow();
        assert!(h.accesses.is_empty());
        assert_eq!((h.identity_reads, h.configuration_reads), (0, 0));
    }
    let f = fixture(0x7e22, true);
    let (mut raw, cfg) = f.host.release().ok().unwrap();
    assert_eq!(
        raw.transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedPec
    );
    assert!(f.state.borrow().accesses.is_empty());
    drop((raw, cfg));
    assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (1, 1));
}

#[test]
fn mixed_errors_and_late_hardware_flags_preserve_actual_donor_precedence() {
    for initial in [
        FAILED,
        DEV_ERR,
        FAILED | DEV_ERR,
        FAILED | DEV_ERR | BUS_ERR,
    ] {
        for crc in [false, true] {
            let mut f = fixture(0x7e22, true);
            f.state.borrow_mut().completion_status = initial;
            f.state.borrow_mut().corrupt_packet = crc;
            let error = f
                .host
                .transaction(address(), Transaction::SendByte(1), true)
                .unwrap_err();
            let expected = if initial & BUS_ERR != 0 {
                ErrorKind::ArbitrationLost
            } else if crc {
                ErrorKind::PecMismatch {
                    auxiliary_status: AUX_CRC_ERROR,
                }
            } else if initial & DEV_ERR != 0 {
                ErrorKind::Device
            } else {
                ErrorKind::Failed
            };
            assert_eq!(error.kind, expected);
            assert_eq!(error.status & initial, initial);
            check_clean(&f);
        }
    }
    for late in [DEV_ERR, BUS_ERR] {
        let mut f = fixture(0x7e22, true);
        f.state.borrow_mut().completion_status = FAILED;
        f.state.borrow_mut().late_status = Some(late);
        let error = f
            .host
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err();
        assert_eq!(
            error.kind,
            if late == BUS_ERR {
                ErrorKind::ArbitrationLost
            } else {
                ErrorKind::Device
            }
        );
        assert_eq!(error.status & (FAILED | late), FAILED | late);
        check_clean(&f);
    }
}

#[test]
fn crc_enable_readback_stale_status_and_exact_aux_restore_are_real_guards() {
    let mut rejected = fixture(0x7e22, true);
    rejected.state.borrow_mut().reject_crc_enable = true;
    assert_eq!(
        rejected
            .host
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err()
            .kind,
        ErrorKind::PecModeRejected
    );
    assert!(rejected.state.borrow().starts.is_empty());
    check_clean(&rejected);
    for fault in 0..3 {
        let mut f = fixture(0x7e22, true);
        match fault {
            0 => {
                f.state.borrow_mut().registers[12] = AUX_CRC_ERROR;
                f.state.borrow_mut().sticky_crc = true;
            }
            1 => f.state.borrow_mut().reject_crc_clear = true,
            2 => f.state.borrow_mut().change_unrelated_aux = true,
            _ => unreachable!(),
        }
        let mut byte = 0xa5;
        let error = f
            .host
            .transaction(address(), Transaction::ReceiveByte(&mut byte), true)
            .unwrap_err();
        assert_eq!(byte, 0xa5);
        assert_eq!(error.recovery, Recovery::Failed);
        if fault == 0 {
            assert!(f.state.borrow().starts.is_empty());
        }
        assert!(f.host.failure().is_some());
        assert_eq!(
            f.host
                .transaction(address(), Transaction::SendByte(1), false)
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
        drop(f.host);
        assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (0, 0));
    }
}

#[test]
fn real_pci_identity_and_host_mode_revalidation_precede_read_publication() {
    for removed in [false, true] {
        for kind in 0..4 {
            let mut f = fixture(0x7e22, true);
            f.state.borrow_mut().remove_on_completion = removed;
            f.state.borrow_mut().change_config_on_completion = !removed;
            let (mut byte, mut word, mut block) =
                (0xa5, 0xa5a5, Block::from_slice(&[0xa5]).unwrap());
            let error = request(&mut f.host, kind, &mut byte, &mut word, &mut block).unwrap_err();
            assert_eq!(error.recovery, Recovery::Failed);
            assert_eq!((byte, word, block.as_slice()), (0xa5, 0xa5a5, &[0xa5][..]));
            assert_eq!(f.state.borrow().starts.len(), 1);
            assert!(f.host.failure().is_some());
            assert_eq!(
                f.host
                    .transaction(address(), Transaction::SendByte(1), true)
                    .unwrap_err()
                    .kind,
                ErrorKind::NeedsReset
            );
            drop(f.host);
            assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (0, 0));
        }
    }
    let mut f = fixture(0x7e22, true);
    f.state.borrow_mut().identity = u32::MAX;
    assert_eq!(
        f.host
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err()
            .recovery,
        Recovery::Failed
    );
    assert!(f.state.borrow().accesses.is_empty());
    drop(f.host);
    assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (0, 0));
}

#[test]
fn one_deadline_includes_final_data_aux_restoration_and_actual_pci_guard() {
    for kind in 0..4 {
        for stage in 0..3 {
            let mut f = fixture(0x7e22, true);
            if stage == 2 {
                f.state.borrow_mut().jump_configuration = true;
            } else {
                let offset = if stage == 1 {
                    AUX_CONTROL
                } else if kind == 3 {
                    BLOCK_DATA
                } else if kind == 2 {
                    HOST_DATA1
                } else {
                    HOST_DATA0
                };
                let count = if stage == 1 {
                    7
                } else if kind == 3 {
                    3
                } else {
                    1
                };
                f.state.borrow_mut().jump_read = Some((offset, count, 1000));
            }
            let (mut byte, mut word, mut block) =
                (0xa5, 0xa5a5, Block::from_slice(&[0xa5]).unwrap());
            let error = request(&mut f.host, kind, &mut byte, &mut word, &mut block).unwrap_err();
            assert!(
                matches!(error.kind, ErrorKind::Timeout(_)),
                "kind={kind}, stage={stage}"
            );
            assert_eq!((byte, word, block.as_slice()), (0xa5, 0xa5a5, &[0xa5][..]));
            check_clean(&f);
        }
    }
    for offset in [AUX_CONTROL, HOST_ADDRESS, HOST_COMMAND, HOST_DATA0] {
        let mut f = fixture(0x7e22, true);
        f.state.borrow_mut().jump_write = Some((offset, 1000));
        assert!(matches!(
            f.host
                .transaction(
                    address(),
                    Transaction::WriteByte {
                        command: 2,
                        data: 3
                    },
                    true
                )
                .unwrap_err()
                .kind,
            ErrorKind::Timeout(_)
        ));
        assert!(f.state.borrow().starts.is_empty());
        check_clean(&f);
    }
}

#[test]
fn timeout_kill_acknowledgment_and_failed_kill_retain_real_owners() {
    for stuck in [false, true] {
        let mut f = fixture(0x7e22, true);
        f.state.borrow_mut().hang = true;
        f.state.borrow_mut().kill_stuck = stuck;
        let mut byte = 0xa5;
        let error = f
            .host
            .transaction(address(), Transaction::ReceiveByte(&mut byte), true)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(byte, 0xa5);
        assert_eq!(f.state.borrow().kills, 1);
        assert_eq!(
            error.recovery,
            if stuck {
                Recovery::Failed
            } else {
                Recovery::Killed
            }
        );
        if !stuck {
            check_clean(&f);
        }
        drop(f.host);
        assert_eq!(
            (f.register_drop.get(), f.configuration_drop.get()),
            if stuck { (0, 0) } else { (1, 1) }
        );
    }
}

#[test]
fn foreign_inuse_and_busy_status_are_never_killed_or_stolen() {
    for status in [INUSE, HOST_BUSY, INUSE | HOST_BUSY] {
        let mut f = fixture(0x7e22, true);
        f.state.borrow_mut().status = status | ALERT;
        let error = f
            .host
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Busy);
        let h = f.state.borrow();
        assert!(h.starts.is_empty());
        assert_eq!(h.kills, 0);
        assert_eq!(h.status & INUSE, status & INUSE);
        assert_eq!(h.registers[13], AUX_OTHER);
    }
}

#[test]
fn malformed_wire_counts_and_invalid_write_lengths_cannot_publish_or_start() {
    for length in [0, 33] {
        let mut f = fixture(0x7e22, true);
        let bytes = vec![0x53; length];
        assert_eq!(
            f.host
                .transaction(
                    address(),
                    Transaction::WriteBlock {
                        command: 0xa7,
                        data: &bytes
                    },
                    true
                )
                .unwrap_err()
                .kind,
            ErrorKind::InvalidBlockLength(length)
        );
        {
            let h = f.state.borrow();
            assert!(h.accesses.is_empty());
            assert_eq!((h.identity_reads, h.configuration_reads), (0, 0));
        }
        f.state.borrow_mut().reply = bytes;
        let mut block = Block::from_slice(&[0xa5, 0x5a]).unwrap();
        assert_eq!(
            f.host
                .transaction(
                    address(),
                    Transaction::ReadBlock {
                        command: 0xa7,
                        data: &mut block
                    },
                    true
                )
                .unwrap_err()
                .kind,
            ErrorKind::InvalidBlockLength(length)
        );
        assert_eq!(block.as_slice(), &[0xa5, 0x5a]);
        let h = f.state.borrow();
        assert_eq!(h.starts.len(), 1);
        assert_eq!(h.read_counts[usize::from(BLOCK_DATA)], 0);
        drop(h);
        check_clean(&f);
    }
}

#[test]
fn newly_latched_crc_that_cannot_clear_quarantines_both_native_owners() {
    let mut f = fixture(0x7e22, true);
    f.state.borrow_mut().corrupt_packet = true;
    f.state.borrow_mut().sticky_crc = true;
    let mut word = 0xa5a5;
    let error = f
        .host
        .transaction(
            address(),
            Transaction::ReadWord {
                command: 0xa7,
                data: &mut word,
            },
            true,
        )
        .unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::PecMismatch {
            auxiliary_status: AUX_CRC_ERROR
        }
    );
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(word, 0xa5a5);
    assert_eq!(f.state.borrow().starts.len(), 1);
    assert!(f.host.failure().is_some());
    assert_eq!(
        f.host
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        ErrorKind::NeedsReset
    );
    drop(f.host);
    assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (0, 0));
}

#[test]
fn ordinary_successor_uses_original_no_pec_engine_after_real_crc_mode_cleanup() {
    let mut f = fixture(0x7e22, true);
    f.host
        .transaction(
            address(),
            Transaction::WriteByte {
                command: 0x22,
                data: 0x33,
            },
            true,
        )
        .unwrap();
    check_clean(&f);
    f.host
        .transaction(
            address(),
            Transaction::WriteByte {
                command: 0x22,
                data: 0x33,
            },
            false,
        )
        .unwrap();
    check_clean(&f);
    let h = f.state.borrow();
    assert_ne!(h.starts[0].1 & AUX_CRC, 0);
    assert_eq!(h.starts[1].1 & (AUX_CRC | AUX_BUFFER), 0);
    assert_eq!(&h.wire[0][..3], &h.wire[1]);
    assert_eq!(h.wire[0].len(), h.wire[1].len() + 1);
    drop(h);
    let owners = f.host.release().ok().unwrap();
    drop(owners);
    assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (1, 1));
}

#[test]
#[ignore = "requires a fresh unchanged Linux PEC access/error trace"]
fn unchanged_linux_access_crc_modes_and_error_precedence() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_I801_PEC_ORACLE").expect("fresh oracle trace path"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("I801_PEC a804c5742bff224d4cb4d25dd383554d598be32b 128")
    );
    let statuses = [
        0,
        FAILED,
        DEV_ERR,
        BUS_ERR,
        FAILED | DEV_ERR,
        FAILED | BUS_ERR,
        DEV_ERR | BUS_ERR,
        ERROR_FLAGS,
    ];
    let mut count = 0;
    for (id, line) in lines.enumerate() {
        let fields: Vec<usize> = line
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(fields.len(), 10);
        assert_eq!(fields[0], id);
        let kind = id / 16;
        assert_eq!(fields[1], kind);
        assert_eq!(fields[2], usize::from(statuses[(id % 16) / 2]));
        assert_eq!(fields[3], id % 2);
        assert_eq!(
            fields[4],
            fields[2]
                | if fields[3] != 0 {
                    usize::from(DEV_ERR)
                } else {
                    0
                }
        );
        let mut f = fixture(0x7e22, true);
        f.state.borrow_mut().completion_status = fields[2] as u8;
        f.state.borrow_mut().corrupt_packet = fields[3] != 0;
        let (mut byte, mut word, mut block) = (0xa5, 0xa5a5, Block::from_slice(&[0xa5]).unwrap());
        let result = match kind {
            0 => f
                .host
                .transaction(address(), Transaction::SendByte(0xa7), true),
            1 => request(&mut f.host, 0, &mut byte, &mut word, &mut block),
            2 => f.host.transaction(
                address(),
                Transaction::WriteByte {
                    command: 0xa7,
                    data: 0x21,
                },
                true,
            ),
            3 => request(&mut f.host, 1, &mut byte, &mut word, &mut block),
            4 => f.host.transaction(
                address(),
                Transaction::WriteWord {
                    command: 0xa7,
                    data: 0x3921,
                },
                true,
            ),
            5 => request(&mut f.host, 2, &mut byte, &mut word, &mut block),
            6 => f.host.transaction(
                address(),
                Transaction::WriteBlock {
                    command: 0xa7,
                    data: &[0x21, 0x39, 0x53],
                },
                true,
            ),
            7 => request(&mut f.host, 3, &mut byte, &mut word, &mut block),
            _ => panic!("unexpected oracle protocol"),
        };
        let class = match result {
            Ok(()) => 0,
            Err(error) => {
                assert_eq!(usize::from(error.status & ERROR_FLAGS), fields[4]);
                assert_eq!((byte, word, block.as_slice()), (0xa5, 0xa5a5, &[0xa5][..]));
                match error.kind {
                    ErrorKind::Failed => 1,
                    ErrorKind::Device => 2,
                    ErrorKind::PecMismatch {
                        auxiliary_status: AUX_CRC_ERROR,
                    } => 3,
                    ErrorKind::ArbitrationLost => 4,
                    other => panic!("unexpected native error: {other:?}"),
                }
            }
        };
        assert_eq!(class, fields[5]);
        let h = f.state.borrow();
        assert_eq!(usize::from(h.starts[0].1 & AUX_CRC), fields[6]);
        assert_eq!(usize::from(h.registers[13]), fields[7]);
        assert_eq!(usize::from(h.status & (INUSE | STATUS_FLAGS)), fields[8]);
        assert_eq!(usize::from(h.registers[12]), fields[9]);
        drop(h);
        check_clean(&f);
        count += 1;
    }
    assert_eq!(count, 128);
}
