//! Actual mapped-config effects with independent pre/post-context failures.
use super::*;
use crate::bus::pci::{ConfigEffect, ConfigFailure};

#[test]
fn denied_before_store_and_failed_after_store_keep_distinct_effects_and_mapping_owner() {
    for after_store in [false, true] {
        let (mut config, counters) = fixture(ADDRESS);
        config.write32(0x20, 0x1234_5678).unwrap();
        let start = counters.contexts.load(Ordering::Relaxed);
        counters
            .fail_context_at
            .store(start + if after_store { 2 } else { 1 }, Ordering::Relaxed);
        let error = config.write32(0x20, 0x9abc_def0).unwrap_err();
        assert_eq!(
            error.reason,
            ConfigFailure::Mapping(MappingError::Unavailable)
        );
        assert_eq!(
            error.effect,
            if after_store {
                ConfigEffect::WriteMayHaveApplied {
                    offset: 0x20,
                    width: 4,
                }
            } else {
                ConfigEffect::None
            }
        );
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        counters.fail_context_at.store(0, Ordering::Relaxed);
        // Inspect the actual owned RAM rather than resume terminal IO.
        let pointer = fixture_pointer(&config, 0x20).cast::<u32>();
        // SAFETY: exact same synchronous hosted RAM; config still keeps it.
        assert_eq!(
            // SAFETY: same original synchronous hosted RAM remains pinned by
            // config; no writer or native device can race this observation.
            unsafe { pointer.as_ptr().read_volatile() },
            if after_store {
                0x9abc_def0
            } else {
                0x1234_5678
            }
        );
        if after_store {
            assert_eq!(config.read32(0x20), Err(error));
            // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
            let failure = unsafe { retire_config(config, &counters) }.unwrap_err();
            assert_eq!(failure.error, MappingError::Busy);
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            drop(failure); // exact original grant/state/source remains retained.
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
            assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
        } else {
            // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
            unsafe { retire_config(config, &counters) }.unwrap();
        }
    }
}
#[test]
fn successful_all_ones_remains_data_and_failed_read_never_becomes_a_sentinel() {
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(0x20, u32::MAX).unwrap();
    assert_eq!(config.read32(0x20), Ok(u32::MAX));
    let start = counters.contexts.load(Ordering::Relaxed);
    counters.fail_context_at.store(start + 1, Ordering::Relaxed);
    let error = config.read32(0x20).unwrap_err();
    assert_eq!(
        error.reason,
        ConfigFailure::Mapping(MappingError::Unavailable)
    );
    assert_eq!(error.effect, ConfigEffect::None);
    counters.fail_context_at.store(0, Ordering::Relaxed);
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { retire_config(config, &counters) }.unwrap();
}
