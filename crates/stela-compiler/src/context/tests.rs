use super::*;

#[test]
fn execution_context_layout_matches_native_offsets() {
    assert_eq!(
        core::mem::size_of::<ExecutionContext>(),
        EXECUTION_CONTEXT_BYTES as usize
    );
    assert_eq!(core::mem::align_of::<ExecutionContext>(), 8);
    assert_eq!(core::mem::offset_of!(ExecutionContext, version), 0);
    assert_eq!(core::mem::offset_of!(ExecutionContext, bytes), 4);
    assert_eq!(
        core::mem::offset_of!(ExecutionContext, memory),
        EXECUTION_CONTEXT_MEMORY_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ExecutionContext, scalable),
        EXECUTION_CONTEXT_SCALABLE_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ExecutionContext, system),
        EXECUTION_CONTEXT_SYSTEM_OFFSET as usize
    );
    assert!(ExecutionContext::default().has_supported_header());
    let mut context = ExecutionContext::default();
    context.bytes -= 1;
    assert!(!context.has_supported_header());
    context.bytes = EXECUTION_CONTEXT_BYTES + 8;
    assert!(context.has_supported_header());
    context.version += 1;
    assert!(!context.has_supported_header());
}

#[test]
fn scalable_view_layout_matches_native_offsets() {
    assert_eq!(
        core::mem::size_of::<ScalableStateView>(),
        SCALABLE_STATE_VIEW_BYTES
    );
    assert_eq!(core::mem::align_of::<ScalableStateView>(), 8);
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, svl_bytes),
        SCALABLE_SVL_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, svcr),
        SCALABLE_SVCR_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, tpidr2_el0),
        SCALABLE_TPIDR2_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, fpmr),
        SCALABLE_FPMR_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, z_upper),
        SCALABLE_Z_UPPER_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, predicates),
        SCALABLE_PREDICATES_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, ffr),
        SCALABLE_FFR_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, za),
        SCALABLE_ZA_OFFSET as usize
    );
    assert_eq!(
        core::mem::offset_of!(ScalableStateView, zt0),
        SCALABLE_ZT0_OFFSET as usize
    );
}
