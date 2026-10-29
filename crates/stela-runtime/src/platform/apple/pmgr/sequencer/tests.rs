use super::*;
use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
use crate::platform::apple::pmgr::{ACTIVE, Pmgr, PowerState};
use alloc::boxed::Box;
use core::cell::Cell;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Bus, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError,
};
use {stela_contracts::dma::Memory, stela_contracts::dma::test_support::Ram};

const SRAM: u64 = 0x23df05200;

fn cursor(words: &[u32], format: AddressFormat) -> PacketCursor {
    let mut cursor = PacketCursor::unknown();
    cursor.bind_initial_control(test_initial()).unwrap();
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    cursor.install_sram(SRAM, &bytes, format).unwrap();
    cursor
}

#[test]
fn checked_mmio_refusal_keeps_committed_prefix_and_original_error() {
    // Two native stores in one packet, offsets 0/8 in the same 1KiB bank.
    let mut cursor = cursor(
        &[0x105, 0x200, 0x1000000f, 0x1000000f, 0],
        AddressFormat::Compact,
    );
    let mut bus = Bus::new();
    let first = bus.add(Box::new(
        Pmgr::new([PowerState {
            address: 0x1000,
            initial: ACTIVE,
        }])
        .unwrap(),
    ));
    bus.map(first, 0x1000, 4, 0x1000).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let claim = cursor.begin_write().unwrap();
    let write = cursor
        .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
        .unwrap();
    cursor
        .finish_write(&claim, {
            bus.write(write.address, write.width, write.value, &mut access)
                .unwrap();
            RouteOutcome::<MmioError>::Committed
        })
        .unwrap();
    assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0x100000ff));
    assert_eq!(cursor.packet_pc(), Some(SRAM));
    assert_eq!(cursor.packet_progress(), Some((1, 2)));
    let failed = cursor.begin_write().unwrap();
    let write = cursor
        .dispatch_write(&failed, &failed.qualify_context(test_fields()).unwrap())
        .unwrap();
    let result = bus.write(write.address, write.width, write.value, &mut access);
    // Unmapped is established by Bus before any target device is called.
    assert!(matches!(result, Err(MmioError::Unmapped { .. })));
    assert_eq!(
        cursor.finish_write(&failed, RouteOutcome::NoEffect(result.unwrap_err())),
        Err(FinishError::NoEffect(MmioError::Unmapped {
            address: 0x1008,
            width: Width::Word
        }))
    );
    assert_eq!(cursor.committed_writes(), 1);
    // An independent intervening write must not be overwritten by replay
    // of the native packet's already committed first store on retry.
    bus.write(0x1000, Width::Word, 0xf, &mut access).unwrap();
    let second = bus.add(Box::new(
        Pmgr::new([PowerState {
            address: 0x1008,
            initial: ACTIVE,
        }])
        .unwrap(),
    ));
    bus.map(second, 0x1008, 4, 0x1008).unwrap();
    let retry = cursor.begin_write().unwrap();
    assert_eq!(retry.write(), failed.write());
    assert_eq!(
        cursor.finish_write::<MmioError>(&failed, RouteOutcome::Committed),
        Err(FinishError::Ownership(
            Error::StaleClaim,
            RouteOutcome::Committed
        ))
    );
    let write = cursor
        .dispatch_write(&retry, &retry.qualify_context(test_fields()).unwrap())
        .unwrap();
    cursor
        .finish_write(&retry, {
            bus.write(write.address, write.width, write.value, &mut access)
                .unwrap();
            RouteOutcome::<MmioError>::Committed
        })
        .unwrap();
    assert_eq!(cursor.committed_writes(), 2);
    assert_eq!(cursor.packet_pc(), Some(SRAM + 16));
    assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0xff));
    assert_eq!(bus.read(0x1008, Width::Word, &mut access), Ok(0x100000ff));
    assert!(matches!(
        cursor.begin_write(),
        Err(Error::UnqualifiedRetirement)
    ));
    assert_eq!(cursor.packet_pc(), Some(SRAM + 16));
}

#[test]
fn pmgr_coverage_refusal_cannot_be_acknowledged_as_a_write() {
    let mut cursor = cursor(&[0x101, 0, 4, 0], AddressFormat::Compact);
    let mut pmgr = Pmgr::new([PowerState {
        address: 0x1000,
        initial: ACTIVE,
    }])
    .unwrap();
    pmgr.refuse_lifecycle(0x1000).unwrap();
    let mut bus = Bus::new();
    let id = bus.add(Box::new(pmgr));
    bus.map(id, 0x1000, 4, 0x1000).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let claim = cursor.begin_write().unwrap();
    let write = cursor
        .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
        .unwrap();
    let error = bus
        .write(write.address, write.width, write.value, &mut access)
        .unwrap_err();
    assert!(matches!(error, MmioError::Unsupported { .. }));
    // This particular PMGR coverage preflight precedes every state effect;
    // Unsupported from an arbitrary device would not establish no effect.
    assert_eq!(
        cursor.finish_write(&claim, RouteOutcome::NoEffect(error.clone())),
        Err(FinishError::NoEffect(error))
    );
    assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0xff));
    assert_eq!(cursor.packet_pc(), Some(SRAM));
    assert_eq!(cursor.packet_progress(), Some((0, 1)));
    assert_eq!(cursor.committed_writes(), 0);
}

#[test]
fn ram_keeps_wide_values_and_running_sequence_alignment() {
    // The first packet occupies three words. The following wide packet
    // needs padding at word5; aligning each packet in isolation is wrong.
    let mut cursor = cursor(
        &[
            0x101,
            0,
            0x11223344,
            0x103,
            2,
            WIDE_PADDING,
            0x55667788,
            0x99aabbcc,
            0,
        ],
        AddressFormat::Compact,
    );
    let mut ram = Ram::new(0x1000, 32);
    for expected in [
        PhysicalWrite {
            address: 0x1000,
            width: Width::Word,
            value: 0x11223344,
        },
        PhysicalWrite {
            address: 0x1008,
            width: Width::Double,
            value: 0x99aabbcc55667788,
        },
    ] {
        let claim = cursor.begin_write().unwrap();
        let write = cursor
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(write, expected);
        let data = write.value.to_le_bytes();
        let result = ram.write(write.address, &data[..write.width.bytes() as usize]);
        cursor
            .finish_write(
                &claim,
                if result {
                    RouteOutcome::Committed
                } else {
                    RouteOutcome::NoEffect("RAM refused entire write")
                },
            )
            .unwrap();
    }
    assert_eq!(&ram.bytes[..4], &0x11223344u32.to_le_bytes());
    assert_eq!(&ram.bytes[8..16], &0x99aabbcc55667788u64.to_le_bytes());
    assert_eq!(cursor.packet_pc(), Some(SRAM + 32));
    assert!(matches!(
        cursor.begin_write(),
        Err(Error::UnqualifiedRetirement)
    ));
}

#[test]
fn high_address_and_four_byte_aligned_wide_store_use_exact_geometry() {
    let mut cursor = cursor(
        &[0x103, 2, 1, WIDE_PADDING, 0x89abcdef, 0x1234567, 0],
        AddressFormat::HighWord,
    );
    let claim = cursor.begin_write().unwrap();
    let write = cursor
        .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
        .unwrap();
    assert_eq!(
        write,
        PhysicalWrite {
            address: 0x2000001004,
            width: Width::Double,
            value: 0x0123456789abcdef
        }
    );
    // Original emitter checks alignment4 even for wide. The target
    // boundary decides whether this physical access is checked.
    let mut short = Ram::new(0x2000001000, 8);
    short.bytes.fill(0xa5);
    let result = short.write(write.address, &write.value.to_le_bytes());
    assert!(!result);
    assert_eq!(short.bytes, vec![0xa5; 8]);
    assert_eq!(
        cursor.finish_write(
            &claim,
            if result {
                RouteOutcome::Committed
            } else {
                RouteOutcome::NoEffect(stela_contracts::dma::DmaError::Memory)
            }
        ),
        Err(FinishError::NoEffect(
            stela_contracts::dma::DmaError::Memory
        ))
    );
    assert_eq!(cursor.committed_writes(), 0);
    let retry = cursor.begin_write().unwrap();
    assert_eq!(retry.write(), write);
    let mut ram = Ram::new(0x2000001000, 32);
    cursor
        .dispatch_write(&retry, &retry.qualify_context(test_fields()).unwrap())
        .unwrap();
    assert!(ram.write(write.address, &write.value.to_le_bytes()));
    cursor
        .finish_write::<()>(&retry, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(&ram.bytes[4..12], &write.value.to_le_bytes());
    assert_eq!(cursor.packet_pc(), Some(SRAM + 24));
}

#[test]
fn exclusive_claim_cancellation_and_distinct_cursor_identity_reject_stale_results() {
    let mut a = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
    let mut b = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
    let old = a.begin_write().unwrap();
    assert!(matches!(a.begin_write(), Err(Error::InFlight)));
    let other = b.begin_write().unwrap();
    assert_eq!(
        b.finish_write::<()>(&old, RouteOutcome::Committed),
        Err(FinishError::Ownership(
            Error::StaleClaim,
            RouteOutcome::Committed
        ))
    );
    a.cancel_claim(&old).unwrap();
    let new = a.begin_write().unwrap();
    assert_eq!(a.cancel_claim(&old), Err(Error::StaleClaim));
    assert_eq!(
        a.finish_write::<()>(&old, RouteOutcome::Committed),
        Err(FinishError::Ownership(
            Error::StaleClaim,
            RouteOutcome::Committed
        ))
    );
    a.dispatch_write(&new, &new.qualify_context(test_fields()).unwrap())
        .unwrap();
    a.finish_write::<()>(&new, RouteOutcome::Committed).unwrap();
    b.dispatch_write(&other, &other.qualify_context(test_fields()).unwrap())
        .unwrap();
    b.finish_write::<()>(&other, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(a.committed_writes(), 1);
    assert_eq!(b.committed_writes(), 1);
}

#[test]
fn kept_suspend_preserves_in_flight_effect_and_forbids_image_substitution() {
    let mut cursor = cursor(&[0x105, 0, 0xf, 4, 0], AddressFormat::Compact);
    let claim = cursor.begin_write().unwrap();
    cursor.set_suspended(true);
    assert_eq!(
        cursor.dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap()),
        Err(Error::Suspended)
    );
    cursor.set_suspended(false);
    cursor
        .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
        .unwrap();
    cursor.set_suspended(true);
    assert_eq!(
        cursor.install_sram(SRAM, &[0; 4], AddressFormat::Compact),
        Err(Error::SramAlreadyOwned)
    );
    cursor
        .finish_write::<()>(&claim, RouteOutcome::Committed)
        .unwrap();
    assert!(matches!(cursor.begin_write(), Err(Error::Suspended)));
    assert_eq!(cursor.packet_progress(), Some((1, 2)));
    cursor.set_suspended(false);
    let next = cursor.begin_write().unwrap();
    assert_eq!(next.write().value, 4);
    assert_eq!(cursor.packet_pc(), Some(SRAM));
    assert_eq!(
        cursor.install_sram(SRAM, &[0; 4], AddressFormat::Compact),
        Err(Error::SramAlreadyOwned)
    );
}

#[test]
fn dispatched_partial_mmio_error_quarantines_current_store_without_replay() {
    struct PartialDevice(Rc<Cell<u64>>);
    impl MmioDevice for PartialDevice {
        fn name(&self) -> &'static str {
            "partial-effect test device"
        }
        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            Ok(self.0.get())
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            _: u64,
            _: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            self.0.set(self.0.get() + 1);
            Err(MmioError::Unsupported {
                device: self.name(),
                offset,
                width,
                direction: Direction::Write,
                reason: refuse!("failure after committed device effect"),
            })
        }
    }
    let mut cursor = cursor(&[0x109, 0x00020100, 0xf, 4, 0xf, 0], AddressFormat::Compact);
    let mut bus = Bus::new();
    let pmgr = bus.add(Box::new(
        Pmgr::new([PowerState {
            address: 0x1000,
            initial: ACTIVE,
        }])
        .unwrap(),
    ));
    bus.map(pmgr, 0x1000, 4, 0x1000).unwrap();
    let effects = Rc::new(Cell::new(0));
    let partial = bus.add(Box::new(PartialDevice(effects.clone())));
    bus.map(partial, 0x1004, 4, 0).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let prefix = cursor.begin_write().unwrap();
    let write = cursor
        .dispatch_write(&prefix, &prefix.qualify_context(test_fields()).unwrap())
        .unwrap();
    bus.write(write.address, write.width, write.value, &mut access)
        .unwrap();
    cursor
        .finish_write::<()>(&prefix, RouteOutcome::Committed)
        .unwrap();
    let claim = cursor.begin_write().unwrap();
    let write = cursor
        .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
        .unwrap();
    assert_eq!(
        cursor.dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap()),
        Err(Error::AlreadyDispatched)
    );
    assert_eq!(cursor.cancel_claim(&claim), Err(Error::AlreadyDispatched));
    assert!(matches!(cursor.begin_write(), Err(Error::InFlight)));
    let error = bus
        .write(write.address, write.width, write.value, &mut access)
        .unwrap_err();
    assert_eq!(effects.get(), 1);
    assert_eq!(
        cursor.finish_write(&claim, RouteOutcome::Uncertain(error.clone())),
        Err(FinishError::Uncertain(error))
    );
    assert_eq!(cursor.uncertain_write(), Some(write));
    assert_eq!(cursor.committed_writes(), 1);
    assert_eq!(cursor.packet_progress(), Some((1, 3)));
    assert_eq!(cursor.packet_pc(), Some(SRAM));
    for _ in 0..2 {
        assert!(matches!(cursor.begin_write(), Err(Error::UncertainEffects)));
        assert_eq!(
            cursor.dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap()),
            Err(Error::UncertainEffects)
        );
        assert_eq!(cursor.cancel_claim(&claim), Err(Error::UncertainEffects));
    }
    let diagnostic = alloc::string::String::from("retain original routed diagnostic");
    assert_eq!(
        cursor.finish_write(&claim, RouteOutcome::Uncertain(diagnostic.clone())),
        Err(FinishError::Ownership(
            Error::UncertainEffects,
            RouteOutcome::Uncertain(diagnostic)
        ))
    );
    cursor.set_suspended(false);
    assert!(matches!(cursor.begin_write(), Err(Error::UncertainEffects)));
    assert_eq!(effects.get(), 1);
    assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0xff));
    assert_eq!(
        cursor.install_sram(SRAM, &[0; 4], AddressFormat::Compact),
        Err(Error::SramAlreadyOwned)
    );
}

#[test]
fn only_undispatched_or_proven_no_effect_claims_can_release_ownership() {
    let mut cursor = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
    let claim = cursor.begin_write().unwrap();
    assert_eq!(
        cursor.finish_write::<()>(&claim, RouteOutcome::Committed),
        Err(FinishError::Ownership(
            Error::NotDispatched,
            RouteOutcome::Committed
        ))
    );
    cursor.cancel_claim(&claim).unwrap();
    let dispatched = cursor.begin_write().unwrap();
    cursor
        .dispatch_write(
            &dispatched,
            &dispatched.qualify_context(test_fields()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        cursor.cancel_claim(&dispatched),
        Err(Error::AlreadyDispatched)
    );
    assert_eq!(
        cursor.finish_write(
            &dispatched,
            RouteOutcome::NoEffect("preflight proved no effect")
        ),
        Err(FinishError::NoEffect("preflight proved no effect"))
    );
    assert_eq!(cursor.cancel_claim(&dispatched), Err(Error::StaleClaim));
    assert_eq!(cursor.uncertain_write(), None);
    assert_eq!(cursor.committed_writes(), 0);
    let retry = cursor.begin_write().unwrap();
    assert_eq!(retry.write(), dispatched.write());
    cursor.cancel_claim(&retry).unwrap();
    assert_eq!(
        cursor.dispatch_write(&retry, &retry.qualify_context(test_fields()).unwrap()),
        Err(Error::StaleClaim)
    );
}

#[test]
fn every_malformed_or_unknown_packet_refuses_before_any_effect() {
    for (words, format, error) in [
        (
            vec![0x105, 0x200, 7],
            AddressFormat::Compact,
            Error::TruncatedPacket,
        ),
        (
            vec![0x101, 0x100, 7],
            AddressFormat::Compact,
            Error::UnusedOffsets,
        ),
        (
            vec![0x103, 64, 0, WIDE_PADDING, 7, 0],
            AddressFormat::HighWord,
            Error::HighAddress,
        ),
        (
            vec![0x103, 0, 0, 0, 7, 0],
            AddressFormat::HighWord,
            Error::WidePadding,
        ),
        (
            vec![0xffff_ffc3, 63, 255, WIDE_PADDING, 7, 0],
            AddressFormat::HighWord,
            Error::PhysicalAddress,
        ),
        (
            vec![2],
            AddressFormat::Compact,
            Error::ExpectedWrite, // tag2 now requires the separate checked read path
        ),
        (
            vec![0x44],
            AddressFormat::Compact,
            Error::UnqualifiedInstruction(0x44),
        ),
        (
            vec![0],
            AddressFormat::Compact,
            Error::UnqualifiedRetirement,
        ),
    ] {
        let mut cursor = cursor(&words, format);
        assert!(matches!(cursor.begin_write(), Err(actual) if actual == error));
        assert_eq!(cursor.packet_pc(), Some(SRAM));
        assert_eq!(cursor.packet_progress(), None);
        assert_eq!(cursor.committed_writes(), 0);
    }
    let mut cursor = PacketCursor::unknown();
    cursor.bind_initial_control(test_initial()).unwrap();
    assert!(matches!(cursor.begin_write(), Err(Error::UnknownSram)));
    assert_eq!(cursor.packet_pc(), None);
    for (base, bytes) in [
        (SRAM + 4, vec![0; 4]),
        (SRAM, vec![]),
        (SRAM, vec![0; 3]),
        (MAX_PHYSICAL, vec![0; 4]),
    ] {
        assert_eq!(
            cursor.install_sram(base, &bytes, AddressFormat::Compact),
            Err(Error::SramGeometry)
        );
    }
}

#[test]
fn full_sixteen_write_batch_reaches_ram_in_offset_order() {
    let mut words = vec![0x13d, 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c];
    words.extend(0x80..0x90);
    words.push(0);
    let mut cursor = cursor(&words, AddressFormat::Compact);
    let mut ram = Ram::new(0x1000, 64);
    for index in 0..16 {
        let claim = cursor.begin_write().unwrap();
        let write = cursor
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(write.address, 0x1000 + index * 4);
        assert_eq!(write.value, 0x80 + index);
        assert_eq!(write.width, Width::Word);
        assert!(ram.write(write.address, &write.value.to_le_bytes()[..4]));
        cursor
            .finish_write::<()>(&claim, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(cursor.committed_writes(), index + 1);
    }
    assert_eq!(cursor.packet_pc(), Some(SRAM + 21 * 4));
    assert_eq!(&ram.bytes[60..64], &0x8fu32.to_le_bytes());
    assert!(matches!(
        cursor.begin_write(),
        Err(Error::UnqualifiedRetirement)
    ));
}

#[test]
fn ticket_exhaustion_refuses_without_reusing_an_old_generation() {
    let mut cursor = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
    cursor.ticket = u64::MAX;
    assert!(matches!(cursor.begin_write(), Err(Error::TicketExhausted)));
    assert_eq!(cursor.packet_pc(), Some(SRAM));
    assert_eq!(cursor.committed_writes(), 0);
    assert!(cursor.in_flight.is_none());
}
