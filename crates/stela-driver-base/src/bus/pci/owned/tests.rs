extern crate std;
use super::test_support::*;
use super::*;
use crate::bus::mmio::owned::PhysicalSpan;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn full_mcfg_geometry_and_mapping_owners_survive_until_retirement() {
    let (mut config, counters) = fixture(ADDRESS);
    assert_eq!(config.address(), ADDRESS);
    assert_eq!(config.window(), window(ADDRESS));
    assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    config.write32(0, 0xabcd1234);
    assert_eq!(config.read32(0), 0xabcd1234);
    let mapping = config.into_mapping();
    assert_eq!(mapping.physical_span().unwrap().start(), 0x8abff000);
    assert_eq!(mapping.bytes().unwrap(), FUNCTION_BYTES);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    retire(mapping, &counters);
}

#[test]
fn native_narrow_accesses_preserve_neighboring_status_and_tail_bytes() {
    // Volatile CPU RAM effects, not an emulation of PCI W1C status.
    // Hardware width is prescribed by each production write_volatile call.
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(4, 0xa5c3_0102);
    config.write16(4, 0x3344);
    assert_eq!(config.read32(4), 0xa5c3_3344);
    config.write8(5, 0x77);
    assert_eq!(config.read32(4), 0xa5c3_7744);
    assert_eq!(config.read16(6), 0xa5c3);
    assert_eq!(config.read8(4), 0x44);
    config.write32(4092, 0x89ab_cdef);
    config.write16(4094, 0x1234);
    config.write8(4095, 0x56);
    assert_eq!(config.read32(4092), 0x5634_cdef);
    assert_eq!(config.read16(4094), 0x5634);
    assert_eq!(config.read8(4095), 0x56);
    retire(config.into_mapping(), &counters);
}

#[test]
fn segment_and_bus_extremes_keep_full_function_offsets() {
    for (address, physical) in [
        (
            Address {
                segment: 0,
                bus: 0,
                device: 0,
                function: 0,
            },
            0x8000_0000,
        ),
        (
            Address {
                segment: u16::MAX,
                bus: u8::MAX,
                device: 31,
                function: 7,
            },
            0x8fff_f000,
        ),
    ] {
        let (config, counters) = fixture(address);
        assert_eq!(config.address(), address);
        let mapping = config.into_mapping();
        assert_eq!(mapping.physical_span().unwrap().start(), physical);
        retire(mapping, &counters);
    }
}

#[test]
fn retired_mapping_is_returned_without_resurrecting_ownership() {
    let (config, counters) = fixture(ADDRESS);
    let mut mapping = config.into_mapping();
    // SAFETY: this synchronous fixture has no config, worker or device access.
    unsafe { mapping.retire() }.unwrap();
    // SAFETY: isolated fixture epoch; rejection must not resurrect the mapping.
    let (error, mapping) = match unsafe { OwnedConfig::attach(ADDRESS, window(ADDRESS), mapping) } {
        Err(failure) => failure,
        Ok(_) => panic!("retired mapping accepted"),
    };
    assert_eq!(error, ConfigError::Mapping(MappingError::Retired));
    assert_eq!(
        mapping.address(0, FUNCTION_BYTES),
        Err(MappingError::Retired)
    );
    drop(mapping);
    assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn invalid_width_alignment_and_complete_bounds_panic_before_access() {
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(4092, 0x1234_5678);
    for offset in [1, 3, 4093, 4094, 4095, 4096, u16::MAX] {
        assert!(catch_unwind(AssertUnwindSafe(|| config.read32(offset))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| config.write32(offset, 0))).is_err());
    }
    for offset in [1, 3, 4095, 4096, u16::MAX] {
        assert!(catch_unwind(AssertUnwindSafe(|| config.read16(offset))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| config.write16(offset, 0))).is_err());
    }
    for offset in [4096, u16::MAX] {
        assert!(catch_unwind(AssertUnwindSafe(|| config.read8(offset))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| config.write8(offset, 0))).is_err());
    }
    assert_eq!(config.read32(4092), 0x1234_5678);
    retire(config.into_mapping(), &counters);
}

#[test]
fn rejected_metadata_returns_the_live_mapping_for_explicit_retirement() {
    let good = window(ADDRESS);
    let mut cases = Vec::new();
    let mut bad = good;
    bad.start_bus = bad.end_bus + 1;
    cases.push((ADDRESS, bad, ConfigError::Window));
    let mut bad = good;
    bad.base += 4096;
    cases.push((ADDRESS, bad, ConfigError::Window));
    let mut bad = good;
    bad.base = !((1u64 << BUS_SHIFT) - 1);
    cases.push((ADDRESS, bad, ConfigError::Window));
    let mut bad = ADDRESS;
    bad.segment ^= 1;
    cases.push((bad, good, ConfigError::Address));
    let mut bad = ADDRESS;
    bad.bus -= 1;
    cases.push((bad, good, ConfigError::Address));
    let mut bad = ADDRESS;
    bad.bus += 1;
    cases.push((bad, good, ConfigError::Address));
    let mut bad = ADDRESS;
    bad.device = 32;
    cases.push((bad, good, ConfigError::Address));
    let mut bad = ADDRESS;
    bad.function = 8;
    cases.push((bad, good, ConfigError::Address));
    for (address, ecam, expected) in cases {
        let (config, counters) = fixture(ADDRESS);
        let mapping = config.into_mapping();
        let original = mapping.address(0, FUNCTION_BYTES).unwrap();
        // SAFETY: fixture grants the ownership; malformed numeric metadata
        // is passed for rejection before any register access.
        let (error, mapping) = match unsafe { OwnedConfig::attach(address, ecam, mapping) } {
            Err(failure) => failure,
            Ok(_) => panic!("invalid config metadata accepted"),
        };
        assert_eq!(error, expected);
        assert_eq!(mapping.address(0, FUNCTION_BYTES).unwrap(), original);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        retire(mapping, &counters);
    }
    for (offset, bytes, attribute, protection, expected) in [
        (
            4096,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
            ConfigError::PhysicalSpan,
        ),
        (
            0,
            8192,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
            ConfigError::PhysicalSpan,
        ),
        (
            0,
            2048,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
            ConfigError::PhysicalSpan,
        ),
        (
            0,
            4096,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite,
            ConfigError::CacheAttribute,
        ),
        (
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
            ConfigError::Protection,
        ),
    ] {
        let span = PhysicalSpan::new(physical(ADDRESS), 8192).unwrap();
        let (mapping, counters) = mapped(span, offset, bytes, attribute, protection);
        // SAFETY: owned fixture; constructor must reject the bad view/policy.
        let (error, mapping) = match unsafe { OwnedConfig::attach(ADDRESS, good, mapping) } {
            Err(failure) => failure,
            Ok(_) => panic!("invalid mapping accepted"),
        };
        assert_eq!(error, expected);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        retire(mapping, &counters);
    }
}

#[test]
fn read_only_epoch_seal_pins_exact_mapping_and_refuses_same_address_substitute() {
    let (config, counters) = fixture(ADDRESS);
    let (foreign, foreign_counters) = fixture(ADDRESS);
    let seal = config.retain_epoch().unwrap();
    assert_eq!(config.matches_retention(&seal), Ok(true));
    assert_eq!(foreign.matches_retention(&seal), Ok(false));
    let mut mapping = config.into_mapping();
    // SAFETY: synchronous RAM fixture has no device/IRQ/work access. The live
    // seal must still prevent retirement of the mapping that backs it.
    assert_eq!(unsafe { mapping.retire() }, Err(MappingError::Busy));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(seal);
    retire(mapping, &counters);
    retire(foreign.into_mapping(), &foreign_counters);
}
