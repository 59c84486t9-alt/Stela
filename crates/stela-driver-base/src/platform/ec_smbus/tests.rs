// SPDX-License-Identifier: MIT
//! Independent EC-SMB-HC peripheral, including native EC command/data framing.
extern crate std;
use super::*;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn relax(&self) {
        self.0.fetch_add(10, Ordering::SeqCst);
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
enum Op {
    Read(u8),
    Write(u8, u8),
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Wire {
    protocol: u8,
    address: u8,
    command: u8,
    data: Vec<u8>,
    count: u8,
}
struct Peripheral {
    bytes: [u8; 256],
    base: u8,
    now: Time,
    log: Vec<Op>,
    wire: Vec<Wire>,
    remaining: usize,
    latency: usize,
    hang: bool,
    completion: u8,
    response: Vec<u8>,
    count: u8,
    fault: Option<(usize, bool)>,
    alarm_after_ack: bool,
    jump: Option<(usize, u64)>,
}
impl Peripheral {
    fn complete(&mut self) {
        let b = usize::from(self.base);
        self.bytes[b + 4..b + 4 + self.response.len()].copy_from_slice(&self.response);
        self.bytes[b + 36] = self.count;
        self.bytes[b + 1] = (self.bytes[b + 1] & 64) | self.completion;
        self.bytes[b] = 0;
    }
    fn failed(&self, after: bool) -> bool {
        self.fault == Some((self.log.len(), after))
    }
    fn effect(&mut self, op: Op) -> Result<u8, ec::Error> {
        self.now.0.fetch_add(1, Ordering::SeqCst);
        self.log.push(op.clone());
        let fault = |published| ec::Error {
            kind: ec::ErrorKind::Io,
            status: 0x39,
            published,
            lock_release_failed: false,
            burst_cleanup_failed: false,
            last_data: None,
        };
        if self.failed(false) {
            return Err(fault(false));
        }
        let b = usize::from(self.base);
        let result = match op {
            Op::Read(address) => {
                if usize::from(address) == b && self.bytes[b] != 0 && !self.hang {
                    if self.remaining == 0 {
                        self.complete();
                    } else {
                        self.remaining -= 1;
                    }
                }
                self.bytes[usize::from(address)]
            }
            Op::Write(address, value) => {
                self.bytes[usize::from(address)] = value;
                if usize::from(address) == b {
                    let data = match value & 127 {
                        6 => self.bytes[b + 4..b + 5].to_vec(),
                        8 | 12 => self.bytes[b + 4..b + 6].to_vec(),
                        10 => self.bytes[b + 4..b + 4 + usize::from(self.bytes[b + 36])].to_vec(),
                        _ => Vec::new(),
                    };
                    self.wire.push(Wire {
                        protocol: value,
                        address: self.bytes[b + 2],
                        command: self.bytes[b + 3],
                        data,
                        count: self.bytes[b + 36],
                    });
                    self.bytes[b + 1] &= 64;
                    self.remaining = self.latency;
                    if self.latency == 0 && !self.hang {
                        self.complete();
                    }
                } else if usize::from(address) == b + 1 && self.alarm_after_ack {
                    self.bytes[b + 1] = 64;
                    self.bytes[b + 37] = 0x52;
                    self.bytes[b + 38] = 0x12;
                    self.bytes[b + 39] = 0x34;
                    self.alarm_after_ack = false;
                }
                0
            }
        };
        if let Some((index, micros)) = self.jump
            && index == self.log.len()
        {
            self.now.0.fetch_add(micros, Ordering::SeqCst);
        }
        if self.failed(true) {
            Err(fault(matches!(op, Op::Write(..))))
        } else {
            Ok(result)
        }
    }
}
struct Space {
    state: Arc<Mutex<Peripheral>>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Space {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: this is an independent ordered register peripheral; faults may occur
// before or after their modeled effects, and all state remains owned.
unsafe impl EcAccess for Space {
    fn read(&mut self, address: u8) -> Result<u8, ec::Error> {
        self.state.lock().unwrap().effect(Op::Read(address))
    }
    fn write(&mut self, address: u8, value: u8) -> Result<(), ec::Error> {
        self.state
            .lock()
            .unwrap()
            .effect(Op::Write(address, value))
            .map(|_| ())
    }
}
type ModelHost = Host<Space, Time>;
fn fixture() -> (ModelHost, Arc<Mutex<Peripheral>>, Arc<AtomicUsize>) {
    let now = Time(Arc::new(AtomicU64::new(0)));
    let state = Arc::new(Mutex::new(Peripheral {
        bytes: [0; 256],
        base: 0x40,
        now: now.clone(),
        log: Vec::new(),
        wire: Vec::new(),
        remaining: 0,
        latency: 2,
        hang: false,
        completion: 128,
        response: vec![0x96, 0x5a],
        count: 2,
        fault: None,
        alarm_after_ack: false,
        jump: None,
    }));
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: uniquely owned independent peripheral, no competing AML,
    // query or alarm consumer. The test timer advances on peripheral effects.
    let host = unsafe {
        Host::claim(
            Space {
                state: state.clone(),
                drops: drops.clone(),
            },
            now,
            Descriptor::from_ec(0x4022).unwrap(),
            1000,
        )
    }
    .ok()
    .unwrap();
    (host, state, drops)
}
fn battery() -> Address {
    Address::new(11).unwrap()
}

#[test]
fn every_protocol_uses_wire_fields_and_commits_only_completed_results() {
    for pec in [false, true] {
        for latency in [0, 1, 7] {
            for case in 0..9 {
                let (mut host, state, drops) = fixture();
                state.lock().unwrap().latency = latency;
                let mut byte = 0x11;
                let mut word = 0x1122;
                let mut block = Block::from_slice(&[0x33]).unwrap();
                let transaction = match case {
                    0 => Transaction::SendByte(0x37),
                    1 => Transaction::ReceiveByte(&mut byte),
                    2 => Transaction::WriteByte {
                        command: 0x37,
                        data: 0xa9,
                    },
                    3 => Transaction::ReadByte {
                        command: 0x37,
                        data: &mut byte,
                    },
                    4 => Transaction::WriteWord {
                        command: 0x37,
                        data: 0xc281,
                    },
                    5 => Transaction::ReadWord {
                        command: 0x37,
                        data: &mut word,
                    },
                    6 => Transaction::WriteBlock {
                        command: 0x37,
                        data: &[9, 8, 7],
                    },
                    7 => Transaction::ReadBlock {
                        command: 0x37,
                        data: &mut block,
                    },
                    _ => Transaction::ProcessCall {
                        command: 0x37,
                        request: 0xc281,
                        response: &mut word,
                    },
                };
                host.transaction(battery(), transaction, pec).unwrap();
                let model = state.lock().unwrap();
                let expected = [4, 5, 6, 7, 8, 9, 10, 11, 12][case] | if pec { 128 } else { 0 };
                assert_eq!(model.wire.len(), 1);
                assert_eq!(model.wire[0].protocol, expected);
                assert_eq!(model.wire[0].address, 22);
                assert_eq!(model.wire[0].command, if case == 1 { 0 } else { 0x37 });
                match case {
                    2 => assert_eq!(model.wire[0].data, [0xa9]),
                    4 | 8 => assert_eq!(model.wire[0].data, [0x81, 0xc2]),
                    6 => assert_eq!(model.wire[0].data, [9, 8, 7]),
                    _ => {}
                }
                if case == 1 || case == 3 {
                    assert_eq!(byte, 0x96);
                }
                if case == 5 || case == 8 {
                    assert_eq!(word, 0x5a96);
                }
                if case == 7 {
                    assert_eq!(block.as_slice(), [0x96, 0x5a]);
                }
                assert!(!host.needs_reset());
                drop(model);
                drop(host);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
            }
        }
    }
}
#[test]
fn full_block_counts_and_invalid_inputs_never_truncate_or_publish_partial_output() {
    for length in 0..=255usize {
        let (mut host, state, _) = fixture();
        let old = Block::from_slice(&[0xfa, 0xce]).unwrap();
        let mut block = old.clone();
        {
            let mut m = state.lock().unwrap();
            m.count = length as u8;
            m.response = (0..length.min(32)).map(|i| i as u8 ^ 0xb5).collect();
        }
        let result = host.transaction(
            battery(),
            Transaction::ReadBlock {
                command: 0x20,
                data: &mut block,
            },
            false,
        );
        if (1..=32).contains(&length) {
            result.unwrap();
            assert_eq!(block.as_slice(), state.lock().unwrap().response);
        } else {
            assert!(result.is_err());
            assert_eq!(block, old);
            assert!(host.needs_reset());
        }
    }
    for length in [0, 33, 256, 4096] {
        let (mut host, state, _) = fixture();
        let bytes = vec![0; length];
        assert_eq!(
            host.transaction(
                battery(),
                Transaction::WriteBlock {
                    command: 3,
                    data: &bytes
                },
                false
            )
            .unwrap_err()
            .kind,
            smbus::ErrorKind::InvalidBlockLength(length)
        );
        assert!(state.lock().unwrap().log.is_empty());
        assert!(!host.needs_reset());
    }
    for length in 1..=32 {
        let (mut host, state, _) = fixture();
        let bytes: Vec<u8> = (0..length).map(|i| i ^ 0x71).collect();
        host.transaction(
            battery(),
            Transaction::WriteBlock {
                command: 4,
                data: &bytes,
            },
            false,
        )
        .unwrap();
        let m = state.lock().unwrap();
        assert_eq!(m.wire[0].count, length);
        assert_eq!(m.wire[0].data, bytes);
    }
}
#[test]
fn stale_done_cannot_complete_a_new_silent_transaction_and_busy_is_never_killed() {
    let (mut host, state, drops) = fixture();
    {
        let mut m = state.lock().unwrap();
        m.bytes[0x41] = 128;
        m.hang = true;
    }
    let mut output = 0x7777;
    assert!(
        host.transaction(
            battery(),
            Transaction::ReadWord {
                command: 9,
                data: &mut output
            },
            false
        )
        .is_err()
    );
    assert_eq!(output, 0x7777);
    assert!(host.needs_reset());
    let first = host.last_error();
    let effects = state.lock().unwrap().log.len();
    assert_eq!(
        host.transaction(battery(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        smbus::ErrorKind::NeedsReset
    );
    assert_eq!(host.last_error(), first);
    assert_eq!(state.lock().unwrap().log.len(), effects);
    drop(host);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let (mut host, state, drops) = fixture();
    {
        let mut m = state.lock().unwrap();
        m.bytes[0x40] = 9;
        m.hang = true;
    }
    assert_eq!(
        host.transaction(battery(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        smbus::ErrorKind::Busy
    );
    assert!(state.lock().unwrap().wire.is_empty());
    assert!(!host.needs_reset());
    {
        let mut m = state.lock().unwrap();
        m.bytes[0x40] = 0;
        m.hang = false;
    }
    host.transaction(battery(), Transaction::SendByte(1), false)
        .unwrap();
    drop(host);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
#[test]
fn every_fault_keeps_permission_and_output() {
    for status in 0..=255u8 {
        let (mut host, state, _) = fixture();
        state.lock().unwrap().completion = status;
        let mut word = 0xdead;
        let result = host.transaction(
            battery(),
            Transaction::ReadWord {
                command: 3,
                data: &mut word,
            },
            true,
        );
        if status == 128 || status == 192 {
            result.unwrap();
            assert_eq!(word, 0x5a96);
        } else {
            assert!(result.is_err());
            assert_eq!(word, 0xdead);
            assert_eq!(host.last_error().unwrap().status, status);
        }
    }
    let (mut h, s, _) = fixture();
    let mut v = 0;
    h.transaction(
        battery(),
        Transaction::ReadWord {
            command: 3,
            data: &mut v,
        },
        false,
    )
    .unwrap();
    let operations = s.lock().unwrap().log.len();
    for index in 1..=operations {
        for after in [false, true] {
            let (mut host, state, drops) = fixture();
            state.lock().unwrap().fault = Some((index, after));
            let mut value = 0xa1b2;
            assert!(
                host.transaction(
                    battery(),
                    Transaction::ReadWord {
                        command: 3,
                        data: &mut value
                    },
                    false
                )
                .is_err()
            );
            assert_eq!(value, 0xa1b2);
            let poisoned = host.needs_reset();
            if poisoned {
                let operations = state.lock().unwrap().log.len();
                let original = host.last_error();
                assert!(
                    host.transaction(battery(), Transaction::SendByte(2), false)
                        .is_err()
                );
                assert_eq!(operations, state.lock().unwrap().log.len());
                assert_eq!(host.last_error(), original);
            }
            drop(host);
            assert_eq!(drops.load(Ordering::SeqCst), usize::from(!poisoned));
        }
    }
}
#[test]
fn alarm_ack_keeps_raw_bytes_and_never_erases_a_new_alarm_or_replays_uncertain_ack() {
    let (mut host, state, _) = fixture();
    {
        let mut m = state.lock().unwrap();
        m.bytes[0x41] = 192;
        m.bytes[0x65] = 23;
        m.bytes[0x66] = 0x78;
        m.bytes[0x67] = 0x56;
        m.alarm_after_ack = true;
    }
    assert_eq!(
        host.poll_alarm().unwrap(),
        Some(Alarm {
            raw_address: 23,
            data: [0x78, 0x56]
        })
    );
    assert_eq!(
        host.poll_alarm().unwrap(),
        Some(Alarm {
            raw_address: 0x52,
            data: [0x12, 0x34]
        })
    );
    assert_eq!(host.poll_alarm().unwrap(), None);
    for index in 1..=6 {
        for after in [false, true] {
            let (mut host, state, _) = fixture();
            {
                let mut m = state.lock().unwrap();
                m.bytes[0x41] = 64;
                m.bytes[0x65] = 22;
                m.bytes[0x66] = 0x12;
                m.bytes[0x67] = 0x34;
                m.fault = Some((index, after));
            }
            assert!(host.poll_alarm().is_err());
            if index == 6 {
                assert_eq!(
                    host.alarm_progress(),
                    AlarmProgress {
                        raw_address: Some(22),
                        data: [Some(0x12), Some(0x34)]
                    }
                );
                let count = state.lock().unwrap().log.len();
                assert!(host.poll_alarm().is_err());
                assert_eq!(count, state.lock().unwrap().log.len());
            }
        }
    }
}
#[test]
fn descriptor_bounds_clock_wrap_and_read_side_ec_uncertainty_are_explicit() {
    for base in 0..=255u64 {
        for query in [0, 1, 255] {
            assert_eq!(
                Descriptor::from_ec((base << 8) | query).is_ok(),
                base <= 216 && query != 0
            );
        }
    }
    assert!(Descriptor::from_ec(0x1_4022).is_err());
    let (mut host, state, _) = fixture();
    state
        .lock()
        .unwrap()
        .now
        .0
        .store(u64::MAX - 15, Ordering::SeqCst);
    let mut data = 0;
    host.transaction(
        battery(),
        Transaction::ReadWord {
            command: 2,
            data: &mut data,
        },
        false,
    )
    .unwrap();
    assert_eq!(data, 0x5a96);
    let (host, state, drops) = fixture();
    state.lock().unwrap().fault = Some((1, true));
    // An EC read command itself can have uncertain native byte effects even
    // before the SMBus host has published a mailbox write.
    struct UncertainRead(Space);
    // SAFETY: forwards to the test's modeled EC space, the only owner of its bytes.
    unsafe impl EcAccess for UncertainRead {
        fn read(&mut self, address: u8) -> Result<u8, ec::Error> {
            self.0.read(address).map_err(|mut e| {
                e.published = true;
                e
            })
        }
        fn write(&mut self, address: u8, value: u8) -> Result<(), ec::Error> {
            self.0.write(address, value)
        }
    }
    let (space, timer) = host.release().ok().unwrap();
    // SAFETY: same independently modeled EC owner, now with native
    // read-command fault evidence kept by the adapter.
    let mut host = unsafe {
        Host::claim(
            UncertainRead(space),
            timer,
            Descriptor::from_ec(0x4022).unwrap(),
            1000,
        )
    }
    .ok()
    .unwrap();
    assert!(
        host.transaction(battery(), Transaction::SendByte(1), false)
            .is_err()
    );
    assert!(host.needs_reset());
    drop(host);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}

enum Stage {
    Idle,
    ReadAddress,
    ReadValue(u8),
    WriteAddress,
    WriteValue(u8),
}
struct Ports {
    space: Space,
    stage: Stage,
    commands: Arc<AtomicUsize>,
}
impl ec::Registers for Ports {
    fn status(&mut self) -> Result<u8, ec::IoError> {
        Ok(u8::from(matches!(self.stage, Stage::ReadValue(_))))
    }
    fn command(&mut self, value: u8) -> Result<(), ec::IoError> {
        assert!(matches!(self.stage, Stage::Idle));
        self.commands.fetch_add(1, Ordering::SeqCst);
        self.stage = match value {
            0x80 => Stage::ReadAddress,
            0x81 => Stage::WriteAddress,
            _ => panic!("unexpected EC command {value:02x}"),
        };
        Ok(())
    }
    fn write_data(&mut self, value: u8) -> Result<(), ec::IoError> {
        match self.stage {
            Stage::ReadAddress => self.stage = Stage::ReadValue(value),
            Stage::WriteAddress => self.stage = Stage::WriteValue(value),
            Stage::WriteValue(address) => {
                self.stage = Stage::Idle;
                self.space.write(address, value).map_err(|_| ec::IoError)?;
            }
            _ => panic!("invalid native EC write stage"),
        }
        Ok(())
    }
    fn read_data(&mut self) -> Result<u8, ec::IoError> {
        let Stage::ReadValue(address) = self.stage else {
            panic!("invalid native EC read stage")
        };
        self.stage = Stage::Idle;
        self.space.read(address).map_err(|_| ec::IoError)
    }
}
#[test]
fn ec_command_data_engine_drives_sbs_and_preserves_little_endian_native_bytes() {
    let (host, state, drops) = fixture();
    let (space, timer) = host.release().ok().unwrap();
    let commands = Arc::new(AtomicUsize::new(0));
    // SAFETY: the modeled firmware declares no global-lock users and the
    // entire native EC, host mailbox and battery selector have one owner.
    let lock = unsafe { ec::NoGlobalLock::exclusively_owned() };
    let ec = ec::Ec::new(
        Ports {
            space,
            stage: Stage::Idle,
            commands: commands.clone(),
        },
        timer.clone(),
        lock,
        ec::Config {
            polling_guard_us: 0,
            ..ec::Config::default()
        },
    )
    .unwrap();
    // SAFETY: unique EC byte engine above, real modeled mailbox at the
    // evaluated descriptor, no independent query/alarm handler mutates it.
    let host = unsafe { Host::claim(ec, timer, Descriptor::from_ec(0x4022).unwrap(), 10_000) }
        .ok()
        .unwrap();
    // SAFETY: the source-checked single-battery board has no manager/other
    // selector owner; the EC host owns every native transfer in the sequence.
    let mut battery = unsafe {
        crate::platform::sbs::Sbs::claim(host, crate::platform::sbs::Topology::Single, false)
    }
    .unwrap();
    let snapshot = battery.refresh(0).unwrap().unwrap();
    assert_eq!(snapshot.information.serial, 0x5a96);
    assert_eq!(snapshot.information.manufacturer.as_slice(), [0x96, 0x5a]);
    assert_eq!(snapshot.state.current, 0x5a96);
    assert!(commands.load(Ordering::SeqCst) > 100);
    let model = state.lock().unwrap();
    for command in [0x1c, 0x20, 0x08] {
        assert!(model.wire.iter().any(|wire| wire.command == command));
    }
    assert!(model.wire.iter().all(|w| w.address == 22));
    drop(model);
    drop(battery);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn acknowledged_native_device_error_allows_a_distinct_future_operation_without_replay() {
    for status in [7, 0x10, 0x11, 0x12, 0x13, 0x17, 0x18, 0x19, 0x1a, 0x1f] {
        let (mut host, state, drops) = fixture();
        state.lock().unwrap().completion = status;
        let mut output = 0xbeef;
        assert!(
            host.transaction(
                battery(),
                Transaction::ReadWord {
                    command: 0x1c,
                    data: &mut output
                },
                false
            )
            .is_err()
        );
        assert_eq!(output, 0xbeef);
        assert!(!host.needs_reset());
        assert_eq!(state.lock().unwrap().wire.len(), 1);
        state.lock().unwrap().completion = 128;
        host.transaction(
            battery(),
            Transaction::ReadWord {
                command: 9,
                data: &mut output,
            },
            false,
        )
        .unwrap();
        assert_eq!(output, 0x5a96);
        let state = state.lock().unwrap();
        assert_eq!(state.wire.len(), 2);
        assert_eq!(state.wire[1].command, 9);
        drop(state);
        drop(host);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn a_successful_read_crossing_deadline_keeps_its_byte_without_publishing_output_or_ack() {
    let (mut baseline, state, _) = fixture();
    let mut output = 0;
    baseline
        .transaction(
            battery(),
            Transaction::ReadWord {
                command: 9,
                data: &mut output,
            },
            false,
        )
        .unwrap();
    let operations = state.lock().unwrap().log.clone();
    for (index, operation) in operations.into_iter().enumerate() {
        let Op::Read(address) = operation else {
            continue;
        };
        let (mut host, state, _) = fixture();
        state.lock().unwrap().jump = Some((index + 1, 2_000));
        let mut output = 0xdead;
        assert!(
            host.transaction(
                battery(),
                Transaction::ReadWord {
                    command: 9,
                    data: &mut output
                },
                false
            )
            .is_err()
        );
        assert_eq!(output, 0xdead);
        let error = host.last_error().unwrap();
        assert_eq!(error.kind, ErrorKind::Timeout);
        let model = state.lock().unwrap();
        assert_eq!(model.log.len(), index + 1);
        assert_eq!(
            error.last_read,
            Some(ObservedRead {
                address,
                value: model.bytes[usize::from(address)]
            })
        );
        if address == 0x40 {
            assert_eq!(error.protocol, model.bytes[0x40]);
        }
        if address == 0x41 {
            assert_eq!(error.status, model.bytes[0x41]);
        }
    }
    for index in 2..=5 {
        let (mut host, state, _) = fixture();
        {
            let mut m = state.lock().unwrap();
            m.bytes[0x41] = 64;
            m.bytes[0x65] = 22;
            m.bytes[0x66] = 0xab;
            m.bytes[0x67] = 0xcd;
            m.jump = Some((index, 2_000));
        }
        assert!(host.poll_alarm().is_err());
        let observed = host.alarm_progress();
        assert_eq!(observed.raw_address, (index >= 3).then_some(22));
        assert_eq!(observed.data[0], (index >= 4).then_some(0xab));
        assert_eq!(observed.data[1], (index >= 5).then_some(0xcd));
        let model = state.lock().unwrap();
        assert!(model.log.iter().all(|op| matches!(op, Op::Read(_))));
        assert_eq!(model.bytes[0x41], 64);
        let Op::Read(address) = model.log[index - 1] else {
            panic!("expected acknowledged byte")
        };
        assert_eq!(
            host.last_error().unwrap().last_read,
            Some(ObservedRead {
                address,
                value: model.bytes[usize::from(address)]
            })
        );
    }
}

#[test]
fn lost_firmware_lock_before_any_command_keeps_owner_without_claiming_publication() {
    struct LostLock {
        _owner: Space,
    }
    // SAFETY: independent EC arbitration model reports the original failure
    // before any register operation; the resource is unchanged.
    unsafe impl EcAccess for LostLock {
        fn read(&mut self, _: u8) -> Result<u8, ec::Error> {
            Err(ec::Error {
                kind: ec::ErrorKind::Timeout(ec::Phase::Command),
                status: 2,
                published: false,
                lock_release_failed: true,
                burst_cleanup_failed: false,
                last_data: None,
            })
        }
        fn write(&mut self, _: u8, _: u8) -> Result<(), ec::Error> {
            panic!("no write after lost arbitration")
        }
    }
    let (host, state, drops) = fixture();
    let (space, timer) = host.release().ok().unwrap();
    // SAFETY: same independent register owner, with an EC arbitration
    // failure injected before any host or native EC command is published.
    let mut host = unsafe {
        Host::claim(
            LostLock { _owner: space },
            timer,
            Descriptor::from_ec(0x4022).unwrap(),
            1000,
        )
    }
    .ok()
    .unwrap();
    assert!(
        host.transaction(battery(), Transaction::SendByte(9), false)
            .is_err()
    );
    assert!(host.needs_reset());
    assert!(!host.last_error().unwrap().published);
    assert_eq!(host.last_error().unwrap().last_read, None);
    assert!(state.lock().unwrap().log.is_empty());
    drop(host);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "oracle: STELA_EC_SMBUS_ORACLE"]
fn unchanged_linux_protocol_trace_matches_native_effects_with_explicit_oracle_limits() {
    let path = std::env::var("STELA_EC_SMBUS_ORACLE").expect("set absolute fresh trace.csv path");
    let trace = std::fs::read_to_string(path).unwrap();
    fn unhex(text: &str) -> Vec<u8> {
        assert_eq!(text.len(), 64);
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 6);
        let opcode: u8 = fields[0].parse().unwrap();
        let count: u8 = fields[1].parse().unwrap();
        let source = unhex(fields[4]);
        let source_payload = unhex(fields[5]);
        let (mut host, state, _) = fixture();
        {
            let mut m = state.lock().unwrap();
            m.count = count;
            m.response = (0..32).map(|n| 0xa0 + n).collect();
        }
        let payload: Vec<u8> = (0..count.min(32)).map(|n| 0x31 + n).collect();
        let mut byte = 0xcc;
        let mut word = 0xcccc;
        let mut block = Block::from_slice(&[0xcc; 32]).unwrap();
        let transaction = match opcode & 127 {
            4 => Transaction::SendByte(0x37),
            5 => Transaction::ReceiveByte(&mut byte),
            6 => Transaction::WriteByte {
                command: 0x37,
                data: 0x31,
            },
            7 => Transaction::ReadByte {
                command: 0x37,
                data: &mut byte,
            },
            8 => Transaction::WriteWord {
                command: 0x37,
                data: 0x3231,
            },
            9 => Transaction::ReadWord {
                command: 0x37,
                data: &mut word,
            },
            10 => Transaction::WriteBlock {
                command: 0x37,
                data: &payload,
            },
            11 => Transaction::ReadBlock {
                command: 0x37,
                data: &mut block,
            },
            12 => Transaction::ProcessCall {
                command: 0x37,
                request: 0x3231,
                response: &mut word,
            },
            _ => panic!("unknown source protocol"),
        };
        let result = host.transaction(battery(), transaction, opcode & 128 != 0);
        if opcode & 127 == 11 && count > 32 {
            assert!(result.is_err());
        } else {
            result.unwrap();
        }
        let m = state.lock().unwrap();
        assert_eq!(m.wire.len(), 1);
        assert_eq!(m.wire[0].protocol, opcode);
        assert_eq!(m.wire[0].address, fields[2].parse::<u8>().unwrap());
        if opcode & 127 != 5 {
            assert_eq!(m.wire[0].command, fields[3].parse::<u8>().unwrap());
        }
        assert_eq!(m.wire[0].data, source_payload[..m.wire[0].data.len()]);
        match opcode {
            5 | 7 => assert_eq!(source[0], byte),
            9 => assert_eq!(source[..2], word.to_le_bytes()),
            11 if count < 32 => assert_eq!(&source[..usize::from(count)], block.as_slice()),
            11 => {
                let length = usize::from(count & 31);
                assert_eq!(
                    &source[..length],
                    &(0..(count & 31)).map(|n| 0xa0 + n).collect::<Vec<_>>()
                );
                assert!(source[length..].iter().all(|b| *b == 0xcc));
            }
            12 => {
                assert_eq!(&source[..2], &[0x31, 0x32]);
                assert_eq!(word, 0xa1a0);
            }
            133 | 135 | 137 | 139 => {
                assert!(source.iter().all(|b| *b == 0xcc));
            }
            _ => {}
        }
        cases += 1;
    }
    assert_eq!(cases, 428);
}
