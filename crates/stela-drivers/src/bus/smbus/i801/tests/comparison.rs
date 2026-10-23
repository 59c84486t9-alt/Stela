//! Both real production engines run against independent instances of the same
//! peripheral/controller model. No C oracle mirrors either implementation.
extern crate std;

use super::*;
use crate::bus::smbus::linux_i801::{Config as LinuxConfig, LinuxI801};

fn native(device: u16, buffer: bool) -> (LinuxI801<RegisterModel, ModelTimer>, Rc<RefCell<Model>>) {
    let (registers, timer, info) = model(device);
    let state = registers.0.clone();
    (
        LinuxI801::new(
            registers,
            timer,
            info,
            HOST_ENABLED,
            LinuxConfig {
                timeout_us: 1000,
                use_block_buffer: buffer,
            },
        )
        .unwrap(),
        state,
    )
}

fn ordinary(bus: &mut impl Bus) -> (u8, u16) {
    bus.transaction(address(), Transaction::SendByte(0x11), false)
        .unwrap();
    let mut byte = 0;
    bus.transaction(address(), Transaction::ReceiveByte(&mut byte), false)
        .unwrap();
    bus.transaction(
        address(),
        Transaction::WriteByte {
            command: 0x22,
            data: 0x33,
        },
        false,
    )
    .unwrap();
    bus.transaction(
        address(),
        Transaction::ReadByte {
            command: 0x22,
            data: &mut byte,
        },
        false,
    )
    .unwrap();
    bus.transaction(
        address(),
        Transaction::WriteWord {
            command: 0x44,
            data: 0x5566,
        },
        false,
    )
    .unwrap();
    let mut word = 0;
    bus.transaction(
        address(),
        Transaction::ReadWord {
            command: 0x77,
            data: &mut word,
        },
        false,
    )
    .unwrap();
    bus.transaction(
        address(),
        Transaction::ProcessCall {
            command: 0x88,
            request: 0x1234,
            response: &mut word,
        },
        false,
    )
    .unwrap();
    (byte, word)
}

#[test]
fn upstream_and_rust_engines_match_each_simple_wire_request_and_reply() {
    for device in [0x24c3, 0x7aa3, 0x6e23] {
        for buffer in [false, true] {
            let (mut rust, r) = new_controller(device, buffer);
            let (mut linux, c) = native(device, buffer);
            assert_eq!(ordinary(&mut rust), ordinary(&mut linux));
            assert_eq!(r.borrow().requests, c.borrow().requests);
        }
    }
}

#[test]
fn upstream_and_rust_match_all_block_lengths_buffered_and_byte_handshakes() {
    for buffer in [false, true] {
        for length in 1..=32 {
            let (mut rust, r) = new_controller(0x7aa3, buffer);
            let (mut linux, c) = native(0x7aa3, buffer);
            let payload: Vec<u8> = (0..length as u8).map(|v| v ^ 0xa5).collect();
            for bus in [&mut rust as &mut dyn Bus, &mut linux as &mut dyn Bus] {
                bus.transaction(
                    address(),
                    Transaction::WriteBlock {
                        command: 0x55,
                        data: &payload,
                    },
                    false,
                )
                .unwrap();
            }
            r.borrow_mut().reply = payload.clone();
            c.borrow_mut().reply = payload.clone();
            let (mut a, mut b) = (Block::default(), Block::default());
            rust.transaction(
                address(),
                Transaction::ReadBlock {
                    command: 0x66,
                    data: &mut a,
                },
                false,
            )
            .unwrap();
            linux
                .transaction(
                    address(),
                    Transaction::ReadBlock {
                        command: 0x66,
                        data: &mut b,
                    },
                    false,
                )
                .unwrap();
            assert_eq!(a.as_slice(), payload);
            assert_eq!(b, a);
            assert_eq!(r.borrow().requests, c.borrow().requests);
        }
    }
}

#[test]
fn both_preserve_read_outputs_and_original_error_category_on_device_failures() {
    for (flag, kind) in [
        (DEV_ERR, ErrorKind::Device),
        (BUS_ERR, ErrorKind::ArbitrationLost),
        (FAILED, ErrorKind::Failed),
    ] {
        let (mut rust, r) = new_controller(0x7aa3, true);
        let (mut linux, c) = native(0x7aa3, true);
        r.borrow_mut().error = flag;
        c.borrow_mut().error = flag;
        let (mut a, mut b) = (0xbeef, 0xbeef);
        let aerr = rust
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 3,
                    data: &mut a,
                },
                false,
            )
            .unwrap_err();
        let berr = linux
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 3,
                    data: &mut b,
                },
                false,
            )
            .unwrap_err();
        assert_eq!((aerr.kind, berr.kind), (kind, kind));
        assert_eq!((a, b), (0xbeef, 0xbeef));
        assert_eq!(berr.status & flag, flag);
    }
}

#[test]
fn busy_owner_is_never_killed_and_invalid_inputs_never_publish() {
    let (mut linux, c) = native(0x7aa3, true);
    c.borrow_mut().status |= HOST_BUSY;
    let err = linux
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Busy);
    assert_eq!(c.borrow().kills, 0);
    c.borrow_mut().status &= !HOST_BUSY;
    assert_eq!(
        linux
            .transaction(
                address(),
                Transaction::WriteBlock {
                    command: 1,
                    data: &[]
                },
                false
            )
            .unwrap_err()
            .kind,
        ErrorKind::InvalidBlockLength(0)
    );
    assert_eq!(
        linux
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedPec
    );
    assert!(c.borrow().requests.is_empty());
}

#[test]
fn failed_real_kill_quarantines_and_acknowledged_kill_allows_new_work() {
    for acknowledged in [false, true] {
        let (mut linux, c) = native(0x7aa3, true);
        c.borrow_mut().freeze = true;
        c.borrow_mut().freeze_kill = !acknowledged;
        let err = linux
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert!(matches!(err.kind, ErrorKind::Timeout(_)));
        assert_eq!(linux.needs_reset(), !acknowledged);
        assert_eq!(c.borrow().kills, 1);
        if acknowledged {
            c.borrow_mut().freeze = false;
            linux
                .transaction(address(), Transaction::SendByte(2), false)
                .unwrap();
        } else {
            let before = c.borrow().writes.len();
            assert_eq!(
                linux
                    .transaction(address(), Transaction::SendByte(2), false)
                    .unwrap_err()
                    .kind,
                ErrorKind::NeedsReset
            );
            assert_eq!(c.borrow().writes.len(), before);
        }
    }
}

#[test]
fn native_adapter_respects_semaphore_and_refuses_stuck_status() {
    let (mut linux, c) = native(0x7aa3, true);
    c.borrow_mut().status = INUSE;
    let writes = c.borrow().writes.len();
    assert_eq!(
        linux
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        ErrorKind::Busy
    );
    assert_eq!(c.borrow().writes.len(), writes);
    assert_eq!(c.borrow().status, INUSE);
    c.borrow_mut().status = INTR;
    c.borrow_mut().stuck_status = INTR;
    assert_eq!(
        linux
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        ErrorKind::StatusStuck
    );
    assert!(c.borrow().requests.is_empty());
    c.borrow_mut().status = 0;
    c.borrow_mut().stuck_status = 0;
    // A stuck final W1C must not be reported as successful data delivery.
    c.borrow_mut().stuck_status = INTR;
    let mut output = 0xbeef;
    assert_eq!(
        linux
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 1,
                    data: &mut output
                },
                false
            )
            .unwrap_err()
            .kind,
        ErrorKind::StatusStuck
    );
    assert_eq!(output, 0xbeef);
    assert!(linux.needs_reset());
}

struct FreezeOnMalformedLength(RegisterModel);
impl Registers for FreezeOnMalformedLength {
    fn read8(&mut self, offset: u8) -> u8 {
        let value = self.0.read8(offset);
        if offset == HOST_DATA0 && value == 33 {
            // The controller emits BYTE_DONE with an illegal length, then
            // stays busy forever while the engine attempts to drain it.
            self.0.0.borrow_mut().freeze = true;
        }
        value
    }
    fn write8(&mut self, offset: u8, value: u8) {
        self.0.write8(offset, value);
    }
}

#[test]
fn malformed_block_drain_is_bounded_and_does_not_publish_output() {
    let (registers, timer, info) = model(0x7aa3);
    let c = registers.0.clone();
    c.borrow_mut().reply = vec![0xaa; 33];
    c.borrow_mut().freeze_kill = true;
    let mut linux = LinuxI801::new(
        FreezeOnMalformedLength(registers),
        timer,
        info,
        HOST_ENABLED,
        LinuxConfig {
            timeout_us: 1000,
            use_block_buffer: false,
        },
    )
    .unwrap();
    let mut output = Block::default();
    let error = linux
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 1,
                data: &mut output,
            },
            false,
        )
        .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Timeout(_)));
    assert_eq!(error.recovery, Recovery::Failed);
    assert!(linux.needs_reset());
    assert!(output.as_slice().is_empty());
    assert_eq!(c.borrow().kills, 1);
    assert!(c.borrow().time.get() < 10_000);
}

#[test]
fn malformed_buffered_lengths_fail_without_output_at_large_clock_epochs() {
    for length in [0, 33] {
        let (mut linux, c) = native(0x7aa3, true);
        c.borrow().time.set(1_u64 << 60);
        c.borrow_mut().reply = vec![0xaa; length];
        let mut output = Block::default();
        let error = linux
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 1,
                    data: &mut output,
                },
                false,
            )
            .unwrap_err();
        // Upstream check_post treats EPROTO as a negative completion, runs
        // KILL, then returns ETIMEDOUT. Preserve and document that difference.
        assert!(matches!(error.kind, ErrorKind::Timeout(_)));
        assert_eq!(error.recovery, Recovery::Killed);
        assert_eq!(c.borrow().kills, 1);
        assert!(output.as_slice().is_empty());
        assert!(!linux.needs_reset());
    }
}

#[test]
fn compare_controller_io_counts_and_modeled_time() {
    for buffer in [false, true] {
        let (mut rust, r) = new_controller(0x7aa3, buffer);
        let (mut linux, c) = native(0x7aa3, buffer);
        // Exclude constructor preparation from both transaction measurements.
        r.borrow_mut().reads = 0;
        r.borrow_mut().writes.clear();
        assert_eq!(ordinary(&mut rust), ordinary(&mut linux));
        std::println!(
            "simple-seven buffer={buffer}: rust={}us/{}reads/{}writes linux={}us/{}reads/{}writes",
            r.borrow().time.get(),
            r.borrow().reads,
            r.borrow().writes.len(),
            c.borrow().time.get(),
            c.borrow().reads,
            c.borrow().writes.len()
        );
        assert_eq!(r.borrow().requests, c.borrow().requests);
        assert!(c.borrow().time.get() >= 7 * 250);
        let (rstart, cstart) = (r.borrow().time.get(), c.borrow().time.get());
        r.borrow_mut().reply = vec![0xaa; 32];
        c.borrow_mut().reply = vec![0xaa; 32];
        let (mut a, mut b) = (Block::default(), Block::default());
        rust.transaction(
            address(),
            Transaction::ReadBlock {
                command: 1,
                data: &mut a,
            },
            false,
        )
        .unwrap();
        linux
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 1,
                    data: &mut b,
                },
                false,
            )
            .unwrap();
        assert_eq!(a, b);
        std::println!(
            "read-block32 buffer={buffer}: rust={}us linux={}us",
            r.borrow().time.get() - rstart,
            c.borrow().time.get() - cstart
        );
    }
}

#[test]
fn unsupported_controller_and_host_configuration_are_refused_before_io() {
    for (device, host, timeout, expected) in [
        (
            0x2413,
            HOST_ENABLED,
            1000,
            ErrorKind::UnsupportedTransaction,
        ),
        (0x7aa3, 0, 1000, ErrorKind::HostDisabled),
        (
            0x7aa3,
            HOST_ENABLED | HOST_SMI,
            1000,
            ErrorKind::FirmwareSmi,
        ),
        (
            0x7aa3,
            HOST_ENABLED | HOST_I2C,
            1000,
            ErrorKind::WrongProtocolMode,
        ),
        (0x7aa3, HOST_ENABLED, 0, ErrorKind::InvalidConfiguration),
    ] {
        let (registers, timer, info) = model(device);
        let state = registers.0.clone();
        let error = LinuxI801::new(
            registers,
            timer,
            info,
            host,
            LinuxConfig {
                timeout_us: timeout,
                use_block_buffer: true,
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, expected);
        assert_eq!(state.borrow().reads, 0);
        assert!(state.borrow().writes.is_empty());
    }
}
