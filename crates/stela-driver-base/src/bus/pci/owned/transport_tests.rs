//! Actual isolated RAM count/effect controls. No native permission is minted.
use super::{grant::DriverGrant, test_support, *};
use crate::bus::mmio::owned::{CacheAttribute, PhysicalSpan, Protection, ResourceKind};
use crate::bus::pci::{ConfigEffect, ConfigFailure};
use alloc::boxed::Box;
use core::sync::atomic::Ordering;

fn mapped() -> (
    test_support::FixtureCustody,
    Mapping,
    alloc::sync::Arc<test_support::Counters>,
) {
    let address = Address {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    let window = EcamWindow {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        base: 0x8000_0000,
    };
    test_support::mapped(
        address,
        window,
        PhysicalSpan::new(window.base, 4096).unwrap(),
        0,
        4096,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    )
}
#[test]
fn counted_transport_survives_extraction_without_generic_bme_or_pointer_escape() {
    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let mut config = match OwnedConfig::attach_test(source.into_grant(), mapping) {
        Ok(config) => Box::new(config),
        Err(_) => panic!("actual RAM attachment refused"),
    };
    assert_eq!(retention.uses(), 1);
    config.try_write8(0x40, 0xab).unwrap();
    config.try_write16(0x42, 0xcdef).unwrap();
    config.try_write32(0x44, 0x89ab_cdef).unwrap();
    assert_eq!(config.try_read8(0x40).unwrap(), 0xab);
    assert_eq!(config.try_read16(0x42).unwrap(), 0xcdef);
    assert_eq!(config.try_read32(0x44).unwrap(), 0x89ab_cdef);
    assert_eq!(retention.uses(), 1);
    config.seal_bus_master().unwrap();
    let (grant, mapping) = (*config).into_parts().into_test_parts();
    assert_eq!(mapping.kind(), Ok(ResourceKind::Configuration));
    assert_eq!(
        mapping.address(0, 4096),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(
        mapping.write32(4, 4),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(
        mapping.read32(0x44),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(retention.uses(), 1);
    let mut config = match OwnedConfig::attach_test(grant, mapping) {
        Ok(config) => config,
        Err((error, _, _)) => panic!("original RAM attachment refused: {error:?}"),
    };
    assert_eq!(config.try_read32(0x44).unwrap(), 0x89ab_cdef);
    assert!(matches!(
        config.try_write16(4, 4),
        Err(ConfigError {
            reason: ConfigFailure::BusMasterSealed,
            ..
        })
    ));
    drop(retention);
    // SAFETY: every synchronous isolated fixture raw/callback tail has ended.
    unsafe { test_support::retire_config(config, &counters) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
}
#[test]
fn equal_geometry_register_mapping_cannot_be_used_as_configuration() {
    let (source, original, counters) = mapped();
    let (bar, registers) = test_support::bar_fixture(original.physical_span().unwrap(), 4096);
    let (error, grant, registers) = match OwnedConfig::attach_test(source.into_grant(), registers) {
        Ok(_) => panic!("register mapping accepted as configuration"),
        Err(refusal) => refusal,
    };
    assert_eq!(
        error,
        ConfigError::before_effect(ConfigFailure::Mapping(
            MappingError::ConfigurationOperationRequired,
        ))
    );
    assert_eq!(registers.kind(), Ok(ResourceKind::Registers));
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: only attachment metadata was inspected. Both original
    // fixtures have stopped all users and are retired with their own owners.
    unsafe {
        bar.retire(registers).unwrap();
        test_support::retire(grant, original, &counters).unwrap();
    }
}

#[test]
fn real_poststore_failure_keeps_prefix_count_and_generic_veto() {
    let (source, mapping, counters) = mapped();
    let retention = source.retention();
    let mut parked: Box<(Option<DriverGrant>, Option<Mapping>)> = Box::new((None, None));
    let mut config = match OwnedConfig::attach_test(source.into_grant(), mapping) {
        Ok(config) => Box::new(config),
        Err(_) => panic!("actual RAM attachment refused"),
    };
    counters.fail_after_word.store(0x40 + 1, Ordering::Relaxed);
    counters
        .fail_after_value
        .store(0x89ab_cdef, Ordering::Relaxed);
    let error = config.try_write32(0x40, 0x89ab_cdef).unwrap_err();
    assert_eq!(
        error.effect,
        ConfigEffect::WriteMayHaveApplied {
            offset: 0x40,
            width: 4
        }
    );
    assert_eq!(retention.uses(), 2);
    let mut parts = (*config).into_parts();
    // SAFETY: all synchronous callers have returned. The retained internal
    // operation still has an uncertain effect and must veto unmap.
    assert_eq!(unsafe { parts.retire() }, Err(MappingError::Busy));
    let (grant, mapping) = parts.into_test_parts();
    parked.0 = Some(grant);
    parked.1 = Some(mapping);
    let contexts = counters.contexts.load(Ordering::Relaxed);
    assert_eq!(
        parked.1.as_ref().unwrap().address(0, 4),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(
        parked.1.as_ref().unwrap().write32(4, 4),
        Err(MappingError::ConfigurationOperationRequired)
    );
    assert_eq!(counters.contexts.load(Ordering::Relaxed), contexts);
    assert_eq!(retention.uses(), 2);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    // Keep the SAME boxed grant State/operation/effect/map. Removing a fault
    // flag is not native/model postvalidation or hardware completion proof.
    core::mem::forget(parked);
    core::mem::forget(retention);
}
