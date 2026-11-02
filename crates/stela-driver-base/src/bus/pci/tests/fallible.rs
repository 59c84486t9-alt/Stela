//! Owner-retaining constructor refusal and denied multi-effect transactions.
extern crate std;
use super::*;
use crate::bus::pci::owned::test_support::{ADDRESS, fixture, retire_config};
use crate::bus::pci::{ConfigEffect, ConfigFailure, FunctionError};
use core::sync::atomic::Ordering;

#[test]
fn actual_config_owner_returns_on_absent_crs_and_transport_failure() {
    for (vendor, failed_class) in [(0xffff_u16, false), (1, false), (0x1234, true)] {
        let (mut config, counters) = fixture(ADDRESS);
        config.write32(0, 0x9876_0000 | u32::from(vendor)).unwrap();
        if failed_class {
            // ID read has a pre/post permission check; fail class's precheck.
            counters.fail_context_at.store(
                counters.contexts.load(Ordering::Relaxed) + 3,
                Ordering::Relaxed,
            );
        }
        let failure = match Function::new(ADDRESS, config) {
            Err(f) => f,
            Ok(_) => panic!("unexpected admitted function"),
        };
        match vendor {
            0xffff => assert_eq!(failure.reason, FunctionError::Absent),
            1 => assert_eq!(failure.reason, FunctionError::ConfigurationRetry),
            _ => match failure.reason {
                FunctionError::Access(error) => {
                    assert_eq!(
                        error.reason,
                        ConfigFailure::Mapping(crate::bus::mmio::owned::Error::Unavailable)
                    );
                    assert_eq!(error.effect, ConfigEffect::None);
                }
                other => panic!("transport failure was replaced: {other:?}"),
            },
        }
        assert_eq!(failure.config.address(), ADDRESS);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        counters.fail_context_at.store(0, Ordering::Relaxed);
        // SAFETY: synchronous fixture's original config returned intact; all
        // borrowed/raw users ended and no model DMA/IRQ source can restart.
        unsafe { retire_config(failure.config, &counters) }.unwrap();
    }
}

struct PanickingObservation {
    reads: alloc::rc::Rc<core::cell::Cell<usize>>,
    drops: alloc::rc::Rc<core::cell::Cell<usize>>,
    panic_at: usize,
}
impl Drop for PanickingObservation {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl ConfigSpace for PanickingObservation {
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        let ordinal = self.reads.get() + 1;
        self.reads.set(ordinal);
        assert_ne!(
            ordinal, self.panic_at,
            "interrupted original config observation"
        );
        Ok(match offset {
            0 => 0x9876_1234,
            8 => 0x0200_0000,
            _ => 0,
        })
    }
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), ConfigError> {
        panic!("discovery must not write")
    }
    fn write16(&mut self, _: u16, _: u16) -> Result<(), ConfigError> {
        panic!("discovery must not write")
    }
    fn write32(&mut self, _: u16, _: u32) -> Result<(), ConfigError> {
        panic!("discovery must not write")
    }
}

#[test]
fn constructor_and_inventory_metadata_unwind_keep_the_original_observation() {
    use alloc::rc::Rc;
    use core::cell::Cell;
    for panic_at in 1..=3 {
        let reads = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        let observation = PanickingObservation {
            reads: reads.clone(),
            drops: drops.clone(),
            panic_at,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if panic_at <= 2 {
                let _ = Function::new(ADDRESS, observation);
            } else {
                let mut original = Some(Function::new(ADDRESS, observation).unwrap());
                let window = EcamWindow {
                    base: 0xe000_0000,
                    segment: ADDRESS.segment,
                    start_bus: ADDRESS.bus,
                    end_bus: ADDRESS.bus,
                };
                let _: Result<_, InventoryFailure<_, ()>> = Function::inventory_with(
                    &window,
                    |_| Ok(original.take()),
                    |_| panic!("release after interrupted metadata read"),
                );
            }
        }));
        assert!(result.is_err());
        assert_eq!(reads.get(), panic_at);
        assert_eq!(drops.get(), 0, "caught unwind released original config");
    }
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "conversion refusal returns the same actual config without allocating"
)]
fn owning_phase_conversion_returns_the_same_config_without_reobservation() {
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(0, 0x9876_1234).unwrap();
    let original = Function::new(ADDRESS, config).unwrap();
    let observed = original.identity();
    let contexts = counters.contexts.load(Ordering::Relaxed);
    let error = ConfigError::before_effect(ConfigFailure::ForeignGrant);
    let (cause, original) = original
        .try_map_config::<(), _>(|config| Err((error, config)))
        .unwrap_err();
    assert_eq!(cause, error);
    assert_eq!(original.identity(), observed);
    assert_eq!(counters.contexts.load(Ordering::Relaxed), contexts);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: exact original hosted fixture; conversion exposed no raw user,
    // DMA/IRQ producer or callback, and all temporary borrows ended.
    unsafe { retire_config(original.into_config(), &counters) }.unwrap();
}

#[test]
fn common_msi_programming_stops_at_denied_high_address_store() {
    use crate::bus::pci::owned::test_support::fixture_pointer;
    for after_store in [false, true] {
        let (mut config, counters) = fixture(ADDRESS);
        config.write32(0, 0x9876_1234).unwrap();
        config.write16(0x52, 1).unwrap();
        config.write32(0x58, 0x7654_3210).unwrap();
        config.write16(0x5c, 0x1234).unwrap();
        let pointer = fixture_pointer(&config, 0).as_ptr();
        let mut function = Function::new(ADDRESS, config).unwrap();
        let before = counters.contexts.load(Ordering::Relaxed);
        let ordinal = if after_store { 8 } else { 7 };
        counters
            .fail_context_at
            .store(before + ordinal, Ordering::Relaxed);
        let message = crate::bus::irq::MsiMessage {
            address: 0x1_fee0_0000,
            data: 0x41,
        };
        let error = function
            .enable_msi(
                Msi {
                    offset: 0x50,
                    vectors: 1,
                    wide: true,
                },
                message,
            )
            .unwrap_err();
        assert_eq!(
            error.reason,
            ConfigFailure::Mapping(crate::bus::mmio::owned::Error::Unavailable)
        );
        assert_eq!(
            error.effect,
            ConfigEffect::WriteMayHaveApplied {
                offset: if after_store { 0x58 } else { 0x54 },
                width: 4
            }
        );
        assert_eq!(
            counters.contexts.load(Ordering::Relaxed),
            before + ordinal,
            "effects continued after denial"
        );
        // SAFETY: exclusive diagnostic RAM stays pinned by the original config;
        // these independent observations do not use its denied IO callbacks.
        let (control, low, high, data) = unsafe {
            (
                pointer.add(0x52).cast::<u16>().read_volatile(),
                pointer.add(0x54).cast::<u32>().read_volatile(),
                pointer.add(0x58).cast::<u32>().read_volatile(),
                pointer.add(0x5c).cast::<u16>().read_volatile(),
            )
        };
        assert_eq!(
            u16::from_le(control) & 1,
            0,
            "MSI enabled after incomplete address"
        );
        assert_eq!(u32::from_le(low), 0xfee0_0000);
        assert_eq!(
            u32::from_le(high),
            if after_store { 1 } else { 0x7654_3210 }
        );
        assert_eq!(
            u16::from_le(data),
            0x1234,
            "data publication continued after denied address"
        );
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        counters.fail_context_at.store(0, Ordering::Relaxed);
        if after_store {
            // Clearing the injected fault does not acknowledge this SAME
            // post-store operation. Its original uncertain use stays counted.
            // SAFETY: raw model users ended; the actual retained operation
            // still must prevent mapping/source retirement.
            let failure = unsafe { retire_config(function.into_config(), &counters) }.unwrap_err();
            assert_eq!(failure.error, crate::bus::mmio::owned::Error::Busy);
            drop(failure); // owning refusal retains the SAME original graph
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
            assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
        } else {
            // The high-address access was refused BEFORE its store. The low
            // address is a known acknowledged prefix, not an abandoned use.
            // SAFETY: every actual fixture raw user ended; this consumes the
            // SAME mapping's unmap ACK and original source-retirement checks.
            unsafe { retire_config(function.into_config(), &counters) }.unwrap();
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
            assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
            assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
        }
    }
}
