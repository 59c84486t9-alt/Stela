//! Independent register peripheral with I2C page latch, SMBus mapping RAM,
//! PS/2 companion effects, F01 reset/configuration and IRQ read-to-clear.
use super::*;
use alloc::{rc::Rc, vec};
use core::cell::{Cell, RefCell};
use transport::{Companion, CompanionError, I2c, Smbus};

struct Hardware {
    memory: Vec<u8>,
    page: u8,
    maps: [Option<(u16, u8, bool)>; 8],
    writes: Vec<(u16, Vec<u8>)>,
    transactions: usize,
    page_changes: usize,
    map_writes: usize,
    reads: usize,
    reset_count: usize,
    version: u8,
    smbus_mode: bool,
    companion_owned: bool,
    restore_count: usize,
    fail_companion: bool,
    fail_after_write: bool,
    fail_map: bool,
    malformed_read: Option<usize>,
    fail_read_number: Option<usize>,
    masked: bool,
    require_mask: bool,
    fail_attention: bool,
    ignore_configured: bool,
}
impl Hardware {
    fn new() -> Self {
        let mut h = Self {
            memory: vec![0; 65536],
            page: 0,
            maps: [None; 8],
            writes: Vec::new(),
            transactions: 0,
            page_changes: 0,
            map_writes: 0,
            reads: 0,
            reset_count: 0,
            version: 1,
            smbus_mode: false,
            companion_owned: false,
            restore_count: 0,
            fail_companion: false,
            fail_after_write: false,
            fail_map: false,
            malformed_read: None,
            fail_read_number: None,
            masked: false,
            require_mask: false,
            fail_attention: false,
            ignore_configured: false,
        };
        h.memory[0xe9..0xef].copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 1, 1]);
        h.memory[0xe3..0xe9].copy_from_slice(&[0xa0, 0x31, 0x50, 0x90, 1, 0x11]);
        h.memory[0x10] = 1;
        h.memory[0x11] = 0x64; // adjustable doze, LTS, holdoff
        h.memory[0x12] = 3;
        h.memory[0x13] = 4;
        h.memory[0x1b..0x25].copy_from_slice(b"MODEL-RMI4");
        h.reset();
        h.reset_count = 0;
        h
    }
    fn reset(&mut self) {
        self.reset_count += 1;
        self.page = 0;
        self.maps = [None; 8];
        self.memory[0x40] = 0x27; // charger, no-sleep and stale reserved sleep
        self.memory[0x41] = 0xff;
        self.memory[0x42] = 10;
        self.memory[0x43] = 20;
        self.memory[0x45] = 30;
        self.memory[0x80] = 0x81; // reset event, unconfigured
        self.memory[0x81] = 1;
    }
    fn read(&mut self, address: u16, output: &mut [u8]) -> bool {
        self.reads += 1;
        output.copy_from_slice(
            &self.memory[usize::from(address)..usize::from(address) + output.len()],
        );
        if address == 0x81 {
            self.memory[0x81] = 0;
        }
        self.fail_read_number == Some(self.reads)
    }
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool {
        self.writes.push((address, bytes.to_vec()));
        if address == 0x30 && bytes == [1] {
            self.reset();
        } else {
            self.memory[usize::from(address)..usize::from(address) + bytes.len()]
                .copy_from_slice(bytes);
            if address == 0x40 && bytes[0] & CONFIGURED != 0 {
                if self.ignore_configured {
                    self.memory[0x40] &= !CONFIGURED;
                } else {
                    self.memory[0x80] &= !0x80;
                }
            }
        }
        core::mem::take(&mut self.fail_after_write)
    }
    fn begin(&mut self) {
        self.transactions += 1;
        assert!(
            !self.require_mask || self.masked,
            "bus access before actual attention masking"
        );
    }
}
#[derive(Clone)]
struct I2cBus(Rc<RefCell<Hardware>>);
#[derive(Clone)]
struct SmbusBus(Rc<RefCell<Hardware>>);
struct Ps2(Rc<RefCell<Hardware>>);
struct Attn(Rc<RefCell<Hardware>>);
struct Time(Rc<Cell<u64>>);
impl i2c::Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
fn i2c_error() -> i2c::Error {
    i2c::Error {
        kind: i2c::ErrorKind::Aborted {
            kind: i2c::AbortKind::DataNack,
            source: 8,
        },
        recovery: i2c::Recovery::Disabled,
    }
}
fn smb_error() -> smbus::Error {
    smbus::ErrorKind::Device.into()
}
impl i2c::Bus for I2cBus {
    fn transaction(
        &mut self,
        address: i2c::Address,
        ops: &mut [i2c::Operation<'_>],
    ) -> Result<(), i2c::Error> {
        assert_eq!(address, i2c::Address::SevenBit(0x2c));
        let mut h = self.0.borrow_mut();
        h.begin();
        match ops {
            [i2c::Operation::Write(bytes)] if bytes.len() == 2 && bytes[0] == 0xff => {
                h.page = bytes[1];
                h.page_changes += 1;
            }
            [i2c::Operation::Write(offset), i2c::Operation::Read(output)] => {
                assert_eq!(offset.len(), 1);
                let register = (u16::from(h.page) << 8) | u16::from(offset[0]);
                if h.read(register, output) {
                    return Err(i2c_error());
                }
            }
            [i2c::Operation::Write(bytes)] => {
                let register = (u16::from(h.page) << 8) | u16::from(bytes[0]);
                if h.write(register, &bytes[1..]) {
                    return Err(i2c_error());
                }
            }
            _ => panic!("unexpected I2C operation"),
        }
        Ok(())
    }
}
impl smbus::Bus for SmbusBus {
    fn transaction(
        &mut self,
        address: smbus::Address,
        transaction: smbus::Transaction<'_>,
        pec: bool,
    ) -> Result<(), smbus::Error> {
        assert_eq!(address.get(), 0x2c);
        assert!(!pec);
        let mut h = self.0.borrow_mut();
        h.begin();
        assert!(
            h.companion_owned,
            "SMBus access without actual PS/2 companion acquisition"
        );
        match transaction {
            smbus::Transaction::ReadByte {
                command: 0xfd,
                data,
            } => {
                *data = h.version;
                h.smbus_mode = true;
            }
            smbus::Transaction::WriteBlock {
                command: command @ 0x80..=0x87,
                data,
            } => {
                assert!(h.smbus_mode);
                assert_eq!(data.len(), 4);
                h.map_writes += 1;
                h.maps[usize::from(command - 0x80)] = Some((
                    u16::from_le_bytes([data[0], data[1]]),
                    data[2],
                    data[3] == 1,
                ));
                if core::mem::take(&mut h.fail_map) {
                    return Err(smb_error());
                }
            }
            smbus::Transaction::ReadBlock { command, data } => {
                assert!(h.smbus_mode);
                let (register, length, _) =
                    h.maps[usize::from(command)].expect("unprogrammed SMBus map");
                let mut bytes = vec![0; usize::from(length)];
                if h.read(register, &mut bytes) {
                    return Err(smb_error());
                }
                if let Some(length) = h.malformed_read.take() {
                    bytes.resize(length, 0xee);
                }
                *data = smbus::Block::from_slice(&bytes).unwrap();
            }
            smbus::Transaction::WriteBlock { command, data } => {
                assert!(h.smbus_mode);
                let (register, _, writable) =
                    h.maps[usize::from(command)].expect("unprogrammed SMBus map");
                assert!(writable, "write reused a read-only map");
                if h.write(register, data) {
                    return Err(smb_error());
                }
            }
            _ => panic!("unexpected SMBus protocol"),
        }
        Ok(())
    }
}
impl Companion for Ps2 {
    fn reset_for_smbus(&mut self) -> Result<(), CompanionError> {
        let mut h = self.0.borrow_mut();
        if h.fail_companion {
            return Err(CompanionError::Unavailable);
        }
        h.reset();
        h.smbus_mode = false;
        h.companion_owned = true;
        Ok(())
    }
    fn restore_ps2(&mut self) -> Result<(), CompanionError> {
        let mut h = self.0.borrow_mut();
        if h.fail_companion {
            return Err(CompanionError::Hardware(1));
        }
        h.reset();
        h.smbus_mode = false;
        h.companion_owned = false;
        h.restore_count += 1;
        Ok(())
    }
}
impl Attention for Attn {
    fn mask_and_drain(&mut self) -> Result<(), AttentionError> {
        let mut h = self.0.borrow_mut();
        if h.fail_attention {
            return Err(AttentionError::Unavailable);
        }
        h.masked = true;
        Ok(())
    }
    fn pending(&mut self) -> Result<bool, AttentionError> {
        let h = self.0.borrow();
        if h.fail_attention {
            return Err(AttentionError::Hardware(1));
        }
        Ok(h.memory[0x81] != 0)
    }
    fn acknowledge(&mut self) -> Result<(), AttentionError> {
        let h = self.0.borrow();
        if h.fail_attention {
            return Err(AttentionError::Hardware(2));
        }
        assert_eq!(
            h.memory[0x81], 0,
            "attention retired before peripheral IRQ status was read"
        );
        Ok(())
    }
}
fn hardware() -> Rc<RefCell<Hardware>> {
    Rc::new(RefCell::new(Hardware::new()))
}
fn i2c_transport(h: &Rc<RefCell<Hardware>>) -> I2c<I2cBus> {
    I2c::new(I2cBus(h.clone()), i2c::Address::SevenBit(0x2c)).unwrap()
}
fn smb_transport(h: &Rc<RefCell<Hardware>>) -> Smbus<SmbusBus, Ps2> {
    Smbus::new(
        SmbusBus(h.clone()),
        smbus::Address::new(0x2c).unwrap(),
        Ps2(h.clone()),
    )
}

#[test]
fn paged_i2c_has_actual_page_effects_bounded_packets_and_no_error_replay() {
    let h = hardware();
    let mut bus = i2c_transport(&h);
    bus.activate().unwrap();
    bus.write(0x1234, &[8, 9, 10]).unwrap();
    let mut output = [0; 3];
    bus.read(0x1234, &mut output).unwrap();
    assert_eq!(output, [8, 9, 10]);
    assert_eq!(h.borrow().page_changes, 2);
    let count = h.borrow().transactions;
    for (address, length) in [(0x12ff, 1), (0x1200, 65536), (0xffff, 2), (0, 0)] {
        let mut bytes = vec![0; length];
        assert!(matches!(
            bus.read(address, &mut bytes),
            Err(Error::AddressRange { .. })
        ));
    }
    assert_eq!(h.borrow().transactions, count);
    h.borrow_mut().fail_after_write = true;
    assert!(matches!(bus.write(0x1234, &[11]), Err(Error::I2c(_))));
    assert_eq!(h.borrow().memory[0x1234], 11);
    let count = h.borrow().transactions;
    assert_eq!(bus.write(0x1234, &[12]), Err(Error::NeedsReset));
    assert_eq!(h.borrow().transactions, count);
}

#[test]
fn i2c_failed_read_does_not_commit_partial_data_and_reset_invalidates_page_cache() {
    let h = hardware();
    let mut bus = i2c_transport(&h);
    bus.activate().unwrap();
    bus.write(0x230, &[1]).unwrap(); // ordinary page2 data, not F01 reset
    bus.reset(0x30).unwrap();
    bus.read(0x230, &mut [0]).unwrap();
    assert_eq!(h.borrow().page, 2);
    assert_eq!(h.borrow().reset_count, 1);
    let next_read = h.borrow().reads + 1;
    h.borrow_mut().fail_read_number = Some(next_read);
    let mut bytes = [0xaa; 4];
    assert!(matches!(bus.read(0x200, &mut bytes), Err(Error::I2c(_))));
    assert_eq!(bytes, [0xaa; 4]);
}

#[test]
fn smbus_chunking_round_trips_every_length_and_preserves_mapping_permissions() {
    for length in 1..=97 {
        let h = hardware();
        let mut bus = smb_transport(&h);
        bus.activate().unwrap();
        let input: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_mul(71)).collect();
        bus.write(0x1234, &input).unwrap();
        let mut output = vec![0; length];
        bus.read(0x1234, &mut output).unwrap();
        assert_eq!(output, input);
        assert_eq!(bus.version(), Some(2));
        bus.write(0x1234, &[0x66]).unwrap();
        assert_eq!(h.borrow().memory[0x1234], 0x66);
        assert!(h.borrow().map_writes <= 8);
    }
}

#[test]
fn smbus_versions_and_actual_companion_ownership_are_required() {
    for version in [0u8, 1, 2, 3, 255] {
        let h = hardware();
        h.borrow_mut().version = version;
        let mut bus = smb_transport(&h);
        if matches!(version, 1 | 2) {
            bus.activate().unwrap();
            assert_eq!(bus.version(), Some(version + 1));
        } else {
            assert_eq!(
                bus.activate(),
                Err(Error::SmbusVersion(u16::from(version) + 1))
            );
        }
    }
    let h = hardware();
    h.borrow_mut().fail_companion = true;
    let mut bus = smb_transport(&h);
    assert_eq!(
        bus.activate(),
        Err(Error::Companion(CompanionError::Unavailable))
    );
    assert_eq!(h.borrow().transactions, 0);
}

#[test]
fn smbus_map_eviction_reset_and_real_detach_restore_companion_state() {
    let h = hardware();
    let mut bus = smb_transport(&h);
    bus.activate().unwrap();
    for address in 0x100..0x10a {
        bus.write(address, &[address as u8]).unwrap();
    }
    let mut byte = [0];
    bus.read(0x100, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    assert_eq!(h.borrow().map_writes, 11);
    let before = h.borrow().reset_count;
    bus.reset(0x30).unwrap();
    assert_eq!(h.borrow().reset_count, before + 1);
    assert!(
        !h.borrow()
            .writes
            .iter()
            .any(|(address, _)| *address == 0x30)
    );
    bus.read(0x100, &mut byte).unwrap();
    assert_eq!(h.borrow().map_writes, 12);
    bus.deactivate().unwrap();
    assert_eq!(h.borrow().restore_count, 1);
    assert!(!h.borrow().companion_owned);
    assert_eq!(bus.read(0x100, &mut byte), Err(Error::NotActive));
}

#[test]
fn smbus_short_and_late_failed_reads_leave_caller_bytes_unchanged() {
    let h = hardware();
    let mut bus = smb_transport(&h);
    bus.activate().unwrap();
    h.borrow_mut().malformed_read = Some(31);
    let mut output = [0xaa; 64];
    assert_eq!(
        bus.read(0x100, &mut output),
        Err(Error::BlockLength {
            expected: 32,
            actual: 31
        })
    );
    assert_eq!(output, [0xaa; 64]);
    let h = hardware();
    let mut bus = smb_transport(&h);
    bus.activate().unwrap();
    h.borrow_mut().fail_read_number = Some(2);
    assert!(matches!(bus.read(0x100, &mut output), Err(Error::Smbus(_))));
    assert_eq!(output, [0xaa; 64]);
    let before = h.borrow().transactions;
    assert_eq!(bus.read(0x100, &mut output), Err(Error::NeedsReset));
    assert_eq!(h.borrow().transactions, before);
}

#[test]
fn effect_then_error_in_map_or_payload_is_terminal_without_replay() {
    for fail_map in [true, false] {
        let h = hardware();
        let mut bus = smb_transport(&h);
        bus.activate().unwrap();
        if fail_map {
            h.borrow_mut().fail_map = true;
        } else {
            h.borrow_mut().fail_after_write = true;
        }
        assert!(matches!(bus.write(0x1234, &[7]), Err(Error::Smbus(_))));
        assert_eq!(h.borrow().memory[0x1234], if fail_map { 0 } else { 7 });
        let count = h.borrow().transactions;
        assert_eq!(bus.write(0x1234, &[8]), Err(Error::NeedsReset));
        assert_eq!(h.borrow().transactions, count);
    }
}

fn control_device(h: &Rc<RefCell<Hardware>>) -> Device<I2c<I2cBus>, Attn, Time> {
    h.borrow_mut().require_mask = true;
    Device::new(
        i2c_transport(h),
        Attn(h.clone()),
        Time(Rc::new(Cell::new(0))),
        Configuration::default(),
    )
    .unwrap()
}

#[test]
fn f01_control_has_actual_reset_configuration_irq_ownership_and_power_effects() {
    let h = hardware();
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(d.control_state(), ControlState::Configured);
    assert_eq!(d.functions().len(), 2);
    assert_eq!(d.properties().unwrap().product_id(), b"MODEL-RMI4");
    assert_eq!(h.borrow().memory[0x40], 0xa4);
    assert_eq!(h.borrow().memory[0x41], 1); // F11 bit remains disabled
    assert_eq!(h.borrow().reset_count, 1);
    assert_eq!(d.poll_control().unwrap(), None);
    h.borrow_mut().memory[0x81] = 3;
    let report = d.poll_control().unwrap().unwrap();
    assert_eq!(report.interrupts, [3]);
    assert_eq!(h.borrow().memory[0x81], 0);
    d.sleep().unwrap();
    assert_eq!(h.borrow().memory[0x40], 0xa1);
    d.wake().unwrap();
    assert_eq!(h.borrow().memory[0x40], 0xa4);
    d.stop().unwrap();
    assert_eq!(d.control_state(), ControlState::Stopped);
    d.initialize_control().unwrap();
    assert_eq!(h.borrow().reset_count, 2);
}

#[test]
fn f01_adjustable_power_registers_skip_lts_and_preserve_unrelated_bits() {
    let h = hardware();
    h.borrow_mut().require_mask = true;
    let config = Configuration {
        no_sleep: Some(false),
        doze_interval: Some(11),
        wakeup_threshold: Some(22),
        doze_holdoff: Some(33),
        ..Configuration::default()
    };
    let mut d = Device::new(
        i2c_transport(&h),
        Attn(h.clone()),
        Time(Rc::new(Cell::new(0))),
        config,
    )
    .unwrap();
    d.initialize_control().unwrap();
    assert_eq!(h.borrow().memory[0x40], 0xa0);
    assert_eq!(h.borrow().memory[0x42], 11);
    assert_eq!(h.borrow().memory[0x43], 22);
    assert_eq!(h.borrow().memory[0x44], 0);
    assert_eq!(h.borrow().memory[0x45], 33);
    d.sleep().unwrap();
    d.wake().unwrap();
    assert_eq!(h.borrow().memory[0x40], 0xa0);
}

#[test]
fn f01_can_run_over_actual_smbus_mapping_and_restores_ps2_on_stop() {
    let h = hardware();
    h.borrow_mut().require_mask = true;
    let mut d = Device::new(
        smb_transport(&h),
        Attn(h.clone()),
        Time(Rc::new(Cell::new(0))),
        Configuration::default(),
    )
    .unwrap();
    d.initialize_control().unwrap();
    assert_eq!(h.borrow().memory[0x40], 0xa4);
    assert!(h.borrow().map_writes > 0);
    d.stop().unwrap();
    assert_eq!(h.borrow().restore_count, 1);
}

#[test]
fn f01_unconfigured_bootloader_or_attention_failures_cannot_publish_control_ready() {
    let h = hardware();
    h.borrow_mut().ignore_configured = true;
    let mut d = control_device(&h);
    assert_eq!(d.initialize_control(), Err(Error::ConfigurationRejected));
    assert_eq!(d.control_state(), ControlState::Uncertain);
    let count = h.borrow().transactions;
    assert_eq!(d.initialize_control(), Err(Error::NeedsReset));
    assert_eq!(h.borrow().transactions, count);
    let h = hardware();
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    h.borrow_mut().memory[0x80] = 0x81;
    h.borrow_mut().memory[0x81] = 1;
    assert_eq!(d.poll_control(), Err(Error::UnexpectedReset));
    let h = hardware();
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    h.borrow_mut().memory[0x80] = 0x40;
    h.borrow_mut().memory[0x81] = 1;
    assert_eq!(d.poll_control(), Err(Error::DeviceStatus(0x40)));
    let h = hardware();
    let mut d = control_device(&h);
    h.borrow_mut().fail_attention = true;
    assert!(matches!(d.initialize_control(), Err(Error::Attention(_))));
    assert_eq!(h.borrow().transactions, 0);
    assert_eq!(
        d.quarantine(),
        Quarantine::Failed(AttentionError::Unavailable)
    );
}

#[test]
fn pdt_pages_irq_positions_missing_f01_and_identity_rebind_are_observed() {
    let h = hardware();
    h.borrow_mut().memory[0x2e9..0x2ef].copy_from_slice(&[0x10, 0x20, 0x40, 0x60, 0x62, 0x30]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(d.functions().len(), 3);
    let f = d.functions()[2];
    assert_eq!(f.query, 0x210);
    assert_eq!(f.version, 3);
    assert_eq!(f.interrupt_start, 2);
    assert_eq!(f.interrupt_count, 2);
    d.stop().unwrap();
    h.borrow_mut().memory[0x1b] = b'X';
    assert_eq!(d.initialize_control(), Err(Error::IdentityChanged));
    let h = hardware();
    h.borrow_mut().memory[0xe9] = 0;
    h.borrow_mut().memory[0xee] = 0;
    let mut d = control_device(&h);
    assert_eq!(d.initialize_control(), Err(Error::MissingF01));
}

#[test]
fn pdt_duplicate_irq_overflow_and_missing_power_capability_fail_before_ready() {
    let h = hardware();
    h.borrow_mut().memory[0xe8] = 1;
    let mut d = control_device(&h);
    assert_eq!(d.initialize_control(), Err(Error::DuplicateF01));

    let h = hardware();
    for page in 1..=40usize {
        h.borrow_mut().memory[page * 256 + 0xe9..page * 256 + 0xef]
            .copy_from_slice(&[0x10, 0x20, 0x30, 0x40, 7, 0x30]);
    }
    let mut d = control_device(&h);
    assert_eq!(d.initialize_control(), Err(Error::InterruptLimit));
    assert_eq!(d.control_state(), ControlState::Uncertain);

    let h = hardware();
    h.borrow_mut().memory[0x11] = 0;
    let config = Configuration {
        doze_interval: Some(10),
        ..Configuration::default()
    };
    let mut d = Device::new(
        i2c_transport(&h),
        Attn(h.clone()),
        Time(Rc::new(Cell::new(0))),
        config,
    )
    .unwrap();
    assert_eq!(d.initialize_control(), Err(Error::UnsupportedPowerControl));
    assert!(
        h.borrow()
            .writes
            .iter()
            .all(|(address, _)| *address != 0x40)
    );
}

#[test]
fn late_f01_effect_error_quarantines_without_replaying_control_write() {
    let h = hardware();
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    h.borrow_mut().fail_after_write = true;
    assert!(matches!(d.sleep(), Err(Error::I2c(_))));
    assert_eq!(h.borrow().memory[0x40], 0xa1);
    assert_eq!(d.quarantine(), Quarantine::Masked);
    let writes = h.borrow().writes.len();
    assert_eq!(d.wake(), Err(Error::NeedsReset));
    assert_eq!(h.borrow().writes.len(), writes);
}

#[test]
fn i2c_function_streaming_windows_use_one_complete_burst_without_page_splits() {
    let h = hardware();
    let mut bus = i2c_transport(&h);
    bus.activate().unwrap();
    let payload: Vec<u8> = (0..1024)
        .map(|index| (index as u8).wrapping_mul(19))
        .collect();
    let before = h.borrow().transactions;
    bus.write(0x1200, &payload).unwrap();
    assert_eq!(h.borrow().transactions, before + 2); // one page select, one burst
    let before = h.borrow().transactions;
    let mut output = vec![0; payload.len()];
    bus.read(0x1200, &mut output).unwrap();
    assert_eq!(h.borrow().transactions, before + 1);
    assert_eq!(h.borrow().page, 0x12);
    assert_eq!(output, payload);
}
