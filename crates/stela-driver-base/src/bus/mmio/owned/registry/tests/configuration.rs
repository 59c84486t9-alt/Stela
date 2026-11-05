//! Real isolated allocator-backed mappings; Configuration is denial-only DATA.
use super::*;

#[test]
fn physical_resolution_views_and_safe_pointer_wrappers_cannot_bypass_configuration() {
    let model = Model::fixture();
    // SAFETY: actual isolated owned model machine/root and allocator.
    let authority = unsafe { fixture(Arc::clone(&model), Vec::new()) };
    let (resource, dropped) = make_resource(
        &model,
        PhysicalSpan::new(BASE, 16384).unwrap(),
        ResourceKind::Configuration,
    );
    let id = authority.register_resource(resource.clone()).unwrap();
    let resolved = authority
        .resolve_resource(PhysicalSpan::new(BASE, 4096).unwrap())
        .unwrap();
    assert_eq!(resolved.kind(), ResourceKind::Configuration);
    assert_eq!(resource.clone().kind(), ResourceKind::Configuration);
    let mut mapping = authority
        .map_physical(
            PhysicalSpan::new(BASE, 4096).unwrap(),
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let window = model.state.lock().unwrap().installed[0].memory.clone();
    // SAFETY: inspect/initialize only this owned isolated RAM fixture through
    // its actual allocation, not a native Configuration transport or grant.
    unsafe { window.pointer().cast::<u32>().write_volatile(0xa5c3_19e7) };
    let view = mapping.view(0..4096).unwrap();
    let cloned = view.clone();
    let sub = mapping.view(64..128).unwrap();
    assert_eq!(mapping.shares_authority(&view), Ok(true));
    assert_eq!(mapping.shares_mapping(&sub), Ok(true));
    assert_eq!(mapping.kind(), Ok(ResourceKind::Configuration));
    assert_eq!(sub.kind(), ResourceKind::Configuration);
    assert_eq!(model.controls.borrow()[0].uses(), 1);
    let refused = Err(Error::ConfigurationOperationRequired);
    assert_eq!(mapping.address(0, 4), refused);
    assert_eq!(
        mapping.read32(0),
        Err(Error::ConfigurationOperationRequired)
    );
    assert_eq!(
        mapping.write32(0, 0),
        Err(Error::ConfigurationOperationRequired)
    );
    for candidate in [&view, &cloned, &sub] {
        assert_eq!(candidate.address(0, 4), refused);
        assert_eq!(
            candidate.read32(0),
            Err(Error::ConfigurationOperationRequired)
        );
        assert_eq!(
            candidate.write32(0, 0),
            Err(Error::ConfigurationOperationRequired)
        );
    }
    // SAFETY: same actual owned fixture RAM, no native access permission.
    let original = unsafe { window.pointer().cast::<u32>().read_volatile() };
    assert_eq!(original, 0xa5c3_19e7);
    assert_eq!(model.controls.borrow()[0].uses(), 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    let calls = model.calls();
    assert!(matches!(
        authority.map(
            resource.clone(),
            4096,
            4096,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite
        ),
        Err(Error::UnsupportedCache)
    ));
    assert_eq!(model.calls(), calls);
    drop((view, cloned, sub));
    // SAFETY: every isolated model raw/view tail ended above.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(model.controls.borrow()[0].uses(), 0);
    authority.unregister_resource(id).unwrap();
    drop((mapping, resource, resolved, window));
}
