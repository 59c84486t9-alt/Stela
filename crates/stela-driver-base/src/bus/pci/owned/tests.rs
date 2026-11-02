extern crate std;
mod fallible;
use super::test_support::*;
use super::*;
use crate::bus::mmio::owned::{CacheAttribute, PhysicalSpan, Protection};
use crate::bus::pci::{
    ConfigFailure, assignment,
    owned::grant::{ConfigCustody, Operation},
};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

#[test]
fn full_mcfg_geometry_and_mapping_owners_survive_until_retirement() {
    let (mut config, counters) = fixture(ADDRESS);
    assert_eq!(config.address(), ADDRESS);
    assert_eq!(config.window(), window(ADDRESS));
    assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    config.write32(0, 0xabcd1234).unwrap();
    assert_eq!(config.read32(0).unwrap(), 0xabcd1234);
    let (grant, mapping) = config.into_parts();
    assert_eq!(mapping.physical_span().unwrap().start(), 0x8abff000);
    assert_eq!(mapping.bytes().unwrap(), FUNCTION_BYTES);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { retire(grant, mapping, &counters) }.unwrap();
}

#[test]
fn native_narrow_accesses_preserve_neighboring_status_and_tail_bytes() {
    // Volatile CPU RAM effects, not an emulation of PCI W1C status.
    // Hardware width is prescribed by each production write_volatile call.
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(4, 0xa5c3_0102).unwrap();
    config.write16(4, 0x3344).unwrap();
    assert_eq!(config.read32(4).unwrap(), 0xa5c3_3344);
    config.write8(5, 0x77).unwrap();
    assert_eq!(config.read32(4).unwrap(), 0xa5c3_7744);
    assert_eq!(config.read16(6).unwrap(), 0xa5c3);
    assert_eq!(config.read8(4).unwrap(), 0x44);
    config.write32(4092, 0x89ab_cdef).unwrap();
    config.write16(4094, 0x1234).unwrap();
    config.write8(4095, 0x56).unwrap();
    assert_eq!(config.read32(4092).unwrap(), 0x5634_cdef);
    assert_eq!(config.read16(4094).unwrap(), 0x5634);
    assert_eq!(config.read8(4095).unwrap(), 0x56);
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { retire_config(config, &counters) }.unwrap();
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
        let (grant, mapping) = config.into_parts();
        assert_eq!(mapping.physical_span().unwrap().start(), physical);
        // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
        unsafe { retire(grant, mapping, &counters) }.unwrap();
    }
}

#[test]
fn retired_mapping_is_returned_without_resurrecting_ownership() {
    let (config, counters) = fixture(ADDRESS);
    let (grant, mut mapping) = config.into_parts();
    // SAFETY: this synchronous fixture has no config, worker or device access.
    unsafe { mapping.retire() }.unwrap();
    // Reuse the SAME source grant; rejection must not resurrect the mapping.
    let (error, grant, mapping) = match OwnedConfig::attach(grant, mapping) {
        Err(failure) => failure,
        Ok(_) => panic!("retired mapping accepted"),
    };
    assert_eq!(
        error,
        ConfigError::before_effect(ConfigFailure::Mapping(MappingError::Retired))
    );
    assert_eq!(
        mapping.address(0, FUNCTION_BYTES),
        Err(MappingError::Retired)
    );
    drop(mapping);
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { finish_retired(grant, &counters) }.unwrap();
    assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn invalid_width_alignment_and_complete_bounds_refuse_before_access() {
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(4092, 0x1234_5678).unwrap();
    let contexts = counters.contexts.load(Ordering::Relaxed);
    for offset in [1, 3, 4093, 4094, 4095, 4096, u16::MAX] {
        let error = ConfigError::before_effect(ConfigFailure::Access { offset, width: 4 });
        assert_eq!(config.read32(offset), Err(error));
        assert_eq!(config.write32(offset, 0), Err(error));
    }
    for offset in [1, 3, 4095, 4096, u16::MAX] {
        let error = ConfigError::before_effect(ConfigFailure::Access { offset, width: 2 });
        assert_eq!(config.read16(offset), Err(error));
        assert_eq!(config.write16(offset, 0), Err(error));
    }
    for offset in [4096, u16::MAX] {
        let error = ConfigError::before_effect(ConfigFailure::Access { offset, width: 1 });
        assert_eq!(config.read8(offset), Err(error));
        assert_eq!(config.write8(offset, 0), Err(error));
    }
    assert_eq!(counters.contexts.load(Ordering::Relaxed), contexts);
    assert_eq!(config.read32(4092).unwrap(), 0x1234_5678);
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { retire_config(config, &counters) }.unwrap();
}
#[test]
fn rejected_metadata_returns_the_live_mapping_for_explicit_retirement() {
    let good = window(ADDRESS);
    let mut cases = Vec::new();
    let mut bad = good;
    bad.start_bus = bad.end_bus + 1;
    cases.push((
        ADDRESS,
        bad,
        ConfigError::before_effect(ConfigFailure::Window),
    ));
    let mut bad = good;
    bad.base += 4096;
    cases.push((
        ADDRESS,
        bad,
        ConfigError::before_effect(ConfigFailure::Window),
    ));
    let mut bad = good;
    bad.base = !((1u64 << BUS_SHIFT) - 1);
    cases.push((
        ADDRESS,
        bad,
        ConfigError::before_effect(ConfigFailure::Window),
    ));
    let mut bad = ADDRESS;
    bad.segment ^= 1;
    cases.push((
        bad,
        good,
        ConfigError::before_effect(ConfigFailure::Address),
    ));
    let mut bad = ADDRESS;
    bad.bus -= 1;
    cases.push((
        bad,
        good,
        ConfigError::before_effect(ConfigFailure::Address),
    ));
    let mut bad = ADDRESS;
    bad.bus += 1;
    cases.push((
        bad,
        good,
        ConfigError::before_effect(ConfigFailure::Address),
    ));
    let mut bad = ADDRESS;
    bad.device = 32;
    cases.push((
        bad,
        good,
        ConfigError::before_effect(ConfigFailure::Address),
    ));
    let mut bad = ADDRESS;
    bad.function = 8;
    cases.push((
        bad,
        good,
        ConfigError::before_effect(ConfigFailure::Address),
    ));
    for (address, ecam, expected) in cases {
        let span = PhysicalSpan::new(physical(ADDRESS), FUNCTION_BYTES as u64).unwrap();
        let (source, mapping, counters) = mapped(
            address,
            ecam,
            span,
            0,
            FUNCTION_BYTES,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        );
        let original = mapping.address(0, FUNCTION_BYTES).unwrap();
        // Actual newly created fixture source carries its model geometry. The
        // constructor rejects it without descriptor-to-native-grant conversion.
        let (error, grant, mapping) = match OwnedConfig::attach(source.into_grant(), mapping) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid config metadata accepted"),
        };
        assert_eq!(error, expected);
        assert_eq!(mapping.address(0, FUNCTION_BYTES).unwrap(), original);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
        unsafe { retire(grant, mapping, &counters) }.unwrap();
    }
    for (offset, bytes, attribute, protection, expected) in [
        (
            4096,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
            ConfigError::before_effect(ConfigFailure::PhysicalSpan),
        ),
        (
            0,
            8192,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
            ConfigError::before_effect(ConfigFailure::PhysicalSpan),
        ),
        (
            0,
            2048,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
            ConfigError::before_effect(ConfigFailure::PhysicalSpan),
        ),
        (
            0,
            4096,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite,
            ConfigError::before_effect(ConfigFailure::CacheAttribute),
        ),
        (
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
            ConfigError::before_effect(ConfigFailure::Protection),
        ),
    ] {
        let span = PhysicalSpan::new(physical(ADDRESS), 8192).unwrap();
        let (source, mapping, counters) =
            mapped(ADDRESS, good, span, offset, bytes, attribute, protection);
        // SAME actual owned fixture source, with an invalid view/policy.
        let (error, grant, mapping) = match OwnedConfig::attach(source.into_grant(), mapping) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid mapping accepted"),
        };
        assert_eq!(error, expected);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
        unsafe { retire(grant, mapping, &counters) }.unwrap();
    }
}

#[test]
fn read_only_epoch_seal_pins_exact_mapping_and_refuses_same_address_substitute() {
    let (config, counters) = fixture(ADDRESS);
    let (foreign, foreign_counters) = fixture(ADDRESS);
    let seal = config.retain_epoch().unwrap();
    assert_eq!(config.matches_retention(&seal), Ok(true));
    assert_eq!(foreign.matches_retention(&seal), Ok(false));
    let (grant, mut mapping) = config.into_parts();
    // SAFETY: synchronous RAM fixture has no device/IRQ/work access. The live
    // seal must still prevent retirement of the mapping that backs it.
    assert_eq!(unsafe { mapping.retire() }, Err(MappingError::Busy));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(seal);
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { retire(grant, mapping, &counters) }.unwrap();
    // SAFETY: exact synchronous RAM fixture; every pointer/borrower stopped.
    unsafe { retire_config(foreign, &foreign_counters) }.unwrap();
}
#[test]
fn actual_fixture_mapping_and_configuration_share_one_original_gate() {
    let span = PhysicalSpan::new(physical(ADDRESS), FUNCTION_BYTES as u64).unwrap();
    let (mut source, mut mapping, counters) = mapped(
        ADDRESS,
        window(ADDRESS),
        span,
        0,
        FUNCTION_BYTES,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    );
    let retention = source.retention();
    assert_eq!(
        source.uses(),
        1,
        "mapping counted before any config operation"
    );
    let operation = source
        .begin(Operation::Read {
            offset: 0,
            width: 4,
        })
        .unwrap();
    assert_eq!(source.uses(), 2, "same actual mapping/config assignment");
    assert!(matches!(
        source.close(),
        Err(MappingError::Assignment(assignment::Error::Busy {
            uses: 2,
            ..
        }))
    ));
    assert!(matches!(
        retention.begin_mapping(),
        Err(MappingError::Assignment(assignment::Error::Closed))
    ));
    assert!(matches!(
        source.begin(Operation::Read {
            offset: 0,
            width: 4
        }),
        Err(ConfigError {
            reason: ConfigFailure::Ownership(assignment::Error::Closed),
            ..
        })
    ));
    // Existing accepted map is retained; close is not unmap/completion proof.
    let view = mapping.view(0..4).unwrap();
    assert!(view.address(0, 4).is_ok());
    // SAFETY: this counted model observation performed no IO/raw exposure.
    if let Err((error, retained)) = unsafe { operation.release() } {
        let _retained = core::mem::ManuallyDrop::new(retained);
        panic!("actual fixture operation release failed: {error:?}");
    }
    assert_eq!(source.uses(), 1);
    // SAFETY: caller is stopped but the real outstanding view must veto unmap.
    assert_eq!(unsafe { mapping.retire() }, Err(MappingError::Busy));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(view);
    drop(retention);
    // SAFETY: all exact synchronous users ended, only original mapping remains.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(source.uses(), 0);
    drop(mapping);
    // SAFETY: actual model unmap acknowledged and every raw/view user ended.
    unsafe { finish_retired(source.into_grant(), &counters) }.unwrap();
}

#[test]
fn actual_model_epoch_observer_cannot_substitute_same_address_other_allocation() {
    let span = PhysicalSpan::new(physical(ADDRESS), FUNCTION_BYTES as u64).unwrap();
    let (left, left_map, left_counts) = mapped(
        ADDRESS,
        window(ADDRESS),
        span,
        0,
        FUNCTION_BYTES,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    );
    let (right, right_map, right_counts) = mapped(
        ADDRESS,
        window(ADDRESS),
        span,
        0,
        FUNCTION_BYTES,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    );
    let left_epoch = left.retain_epoch().unwrap();
    let right_epoch = right.retain_epoch().unwrap();
    assert_eq!(left_epoch.same_epoch(right_epoch.as_ref()), Ok(false));
    assert_eq!(left_epoch.same_epoch(left_epoch.as_ref()), Ok(true));
    assert_eq!(left.uses(), 1);
    assert_eq!(right.uses(), 1);
    drop(left_epoch);
    drop(right_epoch);
    // SAFETY: both disjoint actual RAM fixtures are synchronous and drained.
    unsafe { retire(left.into_grant(), left_map, &left_counts) }.unwrap();
    // SAFETY: same independent original right-hand model drain.
    unsafe { retire(right.into_grant(), right_map, &right_counts) }.unwrap();
}

#[test]
fn abandoned_retirement_failure_closes_new_admission_and_keeps_original_graph() {
    let (config, counters) = fixture(ADDRESS);
    let epoch = config.retain_epoch().unwrap();
    assert_eq!(epoch.custody.check(), Ok(()));
    // SAFETY: idle isolated RAM has no producer/raw accesses. The kept original
    // epoch deliberately prevents unmap, exercising failure without effects.
    let failure = unsafe { retire_owned(config) }.unwrap_err();
    assert_eq!(failure.error, MappingError::Busy);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(failure);
    // The actual grant's close-only Drop must execute even though its original
    // source object and failed mapping remain retained. No new use is admitted.
    assert_eq!(
        epoch.custody.check(),
        Err(MappingError::Assignment(assignment::Error::Closed))
    );
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}
