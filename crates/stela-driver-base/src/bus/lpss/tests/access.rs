//! Owned mapping/context refusal is distinct from geometry and all-ones data.
use super::*;
use crate::bus::{i2c, mmio::owned};
use i2c::Bus;

struct MetadataCut {
    original: Model,
    identity: bool,
}
// SAFETY: forwarding wrapper around the same isolated, exclusively owned model;
// metadata panic adds no register, interrupt or asynchronous access.
unsafe impl Registers for MetadataCut {
    fn identity(&mut self) -> Result<Identity, Error> {
        assert!(!self.identity, "identity callback interrupted");
        self.original.identity()
    }
    fn physical_base(&self) -> u64 {
        panic!("physical-base callback interrupted");
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        self.original.read32(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.original.write32(offset, value)
    }
}

#[test]
fn metadata_unwind_before_programming_keeps_the_original_register_owner() {
    extern crate std;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    for identity in [true, false] {
        let (original, hardware, drops) = model(0x9d60, 0x1000, 0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _owner = Controller::initialize(MetadataCut { original, identity });
        }));
        assert!(result.is_err());
        assert_eq!(drops.get(), 0);
        assert!(hardware.borrow().writes.is_empty());
        assert_eq!(hardware.borrow().calls, if identity { 0 } else { 2 });
    }
}

fn prepare_child() -> (NativeRegisters, Arc<Counters>, BarFixture) {
    let (function, mapping, config, bar) = native_fixture();
    let pointer = mapping.address(0, PRIVATE).unwrap().cast::<u32>();
    // SAFETY: this original isolated fixture owns the entire live RAM aperture
    // and has not published a child or asynchronous actor.
    unsafe {
        pointer.as_ptr().add(0xfc / 4).write_volatile(0x4457_0140);
        pointer
            .as_ptr()
            .add(0xf4 / 4)
            .write_volatile(2 | (1 << 7) | (2 << 2) | (3 << 16) | (3 << 8));
        pointer.as_ptr().add(0xf8 / 4).write_volatile(0x3131_312a);
        pointer.as_ptr().add(0x10 / 4).write_volatile(u32::MAX);
    }
    // SAFETY: same original stopped fixture function, mapping and external BAR
    // source grant. No physical/native-platform qualification is inferred.
    let registers = match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
        Ok(registers) => registers,
        Err((error, _)) => panic!("valid owned fixture: {error:?}"),
    };
    (registers, config, bar)
}

#[test]
fn native_child_reads_all_ones_and_returns_exact_context_denial_without_a_sentinel() {
    let (mut registers, config, bar) = prepare_child();
    assert_eq!(registers.child_read32(0x10), Ok(u32::MAX));
    let before = bar.contexts.load(Ordering::Relaxed);
    assert_eq!(registers.child_read32(PRIVATE), Err(Error::Mapping));
    assert_eq!(registers.child_write32(1, 0), Err(Error::Mapping));
    assert_eq!(
        bar.contexts.load(Ordering::Relaxed),
        before,
        "invalid geometry performs no provider call"
    );
    bar.fail_context_at.store(before + 1, Ordering::Relaxed);
    assert_eq!(
        registers.child_read32(0x10),
        Err(Error::Mmio(owned::Error::Unavailable))
    );
    assert_eq!(bar.contexts.load(Ordering::Relaxed), before + 1);
    // This primitive exposes no child retirement proof; keep the original
    // registers alongside the source grant rather than treating denial as one.
    let _kept = ManuallyDrop::new(registers);
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn denied_constructor_access_retains_platform_timer_and_exact_component_read() {
    let (registers, config, bar) = prepare_child();
    let owner = Controller::initialize(registers).unwrap();
    let before = bar.contexts.load(Ordering::Relaxed);
    bar.fail_context_at.store(before + 1, Ordering::Relaxed);
    {
        // SAFETY: same isolated literal board timing and stopped PIO owner;
        // the original mapping's own context check is deliberately denied.
        let failure = unsafe { owner.into_i2c(Time(Rc::new(Cell::new(0))), timing()) }
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            AttachError::I2c(
                i2c::ErrorKind::Access(i2c::IoError::Lpss(Error::Mmio(owned::Error::Unavailable)))
                    .into()
            )
        );
        let progress = failure.progress().unwrap();
        assert_eq!(progress.accepted, 0);
        assert_eq!(progress.pending, Some(i2c::Access::Read { offset: 0xfc }));
        assert_eq!(bar.contexts.load(Ordering::Relaxed), before + 1);
    }
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.resource_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn restoring_provider_context_does_not_reopen_a_denied_child_or_allow_shutdown_io() {
    let (registers, config, bar) = prepare_child();
    let owner = Controller::initialize(registers).unwrap();
    // SAFETY: this same isolated model has literal board timing, with no DMA,
    // IRQ or external child users. No actual hardware qualification is claimed.
    let mut child = unsafe { owner.into_i2c(Time(Rc::new(Cell::new(0))), timing()) }.unwrap();
    let before = bar.contexts.load(Ordering::Relaxed);
    bar.fail_context_at.store(before + 1, Ordering::Relaxed);
    let error = child
        .transaction(
            i2c::Address::SevenBit(0x2c),
            &mut [i2c::Operation::Write(&[1])],
        )
        .unwrap_err();
    assert_eq!(
        error.kind,
        i2c::ErrorKind::Access(i2c::IoError::Lpss(Error::Mmio(owned::Error::Unavailable)))
    );
    assert_eq!(error.recovery, i2c::Recovery::NotAttempted);
    bar.fail_context_at.store(0, Ordering::Relaxed);
    assert_eq!(
        child.transaction(
            i2c::Address::SevenBit(0x2c),
            &mut [i2c::Operation::Write(&[2])]
        ),
        Err(error)
    );
    {
        let failure = child.shutdown().err().unwrap();
        assert_eq!(failure.error, AttachError::I2c(error));
        assert_eq!(
            failure.progress().unwrap().pending,
            Some(i2c::Access::Read { offset: 0x70 })
        );
    }
    assert_eq!(
        bar.contexts.load(Ordering::Relaxed),
        before + 1,
        "no cleanup or retry provider access"
    );
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.platform_drops.load(Ordering::Relaxed), 0);
}
