//! Actual original fixture products and mapper effects, never native admission.
use super::*;

#[test]
fn pending_original_config_use_vetoes_unmap_and_same_parts_retry_after_release() {
    let (config, counters) = fixture(ADDRESS);
    let (grant, mapping) = config.into_parts();
    let usage = grant
        .custody()
        .begin(Operation::Read {
            offset: 0,
            width: 4,
        })
        .unwrap();
    // No volatile read/callback was issued. This held ORIGINAL admission must
    // nevertheless refuse teardown before the actual mapper sees an unmap.
    // SAFETY: all raw model users ended; deliberate pending-use negative case.
    let mut failure = unsafe { retire(grant, mapping, &counters) }.unwrap_err();
    assert_eq!(failure.error, MappingError::Busy);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    let (grant, mapping) = failure._parts.take().expect("SAME original parts retained");
    drop(failure);
    // SAFETY: this exact original read admission issued no volatile effect,
    // pointer, callback or alias. Release that actual token, not a replacement.
    assert!(unsafe { usage.release() }.is_ok());
    // SAFETY: original token ended; this same mapper/source now performs and
    // acknowledges its real unmap/retirement, with all raw users still stopped.
    unsafe { retire(grant, mapping, &counters) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn equal_geometry_foreign_mapping_never_authorizes_original_source_unmap() {
    let (a, ca) = fixture(ADDRESS);
    let (b, cb) = fixture(ADDRESS);
    let (ga, ma) = a.into_parts();
    let (gb, mb) = b.into_parts();
    assert_eq!(ma.physical_span(), mb.physical_span());
    // SAFETY: both actual model pools have no raw/callback users; this negative
    // input pairs distinct original objects with equal DATA, never native owners.
    let mut failure = unsafe { retire(ga, mb, &ca) }.unwrap_err();
    assert_eq!(failure.error, MappingError::InvalidPlatformReply);
    assert_eq!(ca.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(cb.unmaps.load(Ordering::Relaxed), 0);
    let (ga, mb) = failure
        ._parts
        .take()
        .expect("both exact original owners retained");
    drop(failure);
    // SAFETY: restore SAME owned pairings by moving original objects, not by
    // reconstructing a grant or mapping from their shared numeric geometry.
    unsafe { retire(ga, ma, &ca) }.unwrap();
    // SAFETY: the second original allocation also has no users and its own ACK.
    unsafe { retire(gb, mb, &cb) }.unwrap();
    assert_eq!(ca.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(cb.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_unmap_after_actual_prefix_retains_mapping_and_source_without_completion() {
    let (config, counters) = fixture(ADDRESS);
    counters.fail_unmap_after_effect.store(1, Ordering::Relaxed);
    // SAFETY: all raw model users ended. Mapper removes its actual installed
    // record then reports failure, which is deliberately NOT a completion ACK.
    let failure = unsafe { retire_owned(config) }.unwrap_err();
    assert_eq!(failure.error, MappingError::UnmapFailed);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    assert!(
        failure._parts.is_some(),
        "post-prefix failure kept complete original parts"
    );
    drop(failure);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn same_mapper_transaction_ack_retry_does_not_repeat_removal_prefix() {
    let (config, counters) = fixture(ADDRESS);
    counters.fail_unmap_after_effect.store(1, Ordering::Relaxed);
    // SAFETY: isolated original pool's raw users ended; the first mapper call
    // deliberately refuses after removal and retains its original transaction.
    let mut failure = unsafe { retire_owned(config) }.unwrap_err();
    assert_eq!(failure.error, MappingError::UnmapFailed);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    let (grant, mut mapping) = failure
        ._parts
        .take()
        .expect("SAME original transaction retained");
    drop(failure);
    // SAFETY: no user restarted; the mapper recognizes this exact kept token
    // and acknowledges its prior removal instead of repeating its effect.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    drop(mapping);
    // SAFETY: the SAME actual mapper now ACKed, original counted use ended,
    // and every source/raw user remained stopped across that checked retry.
    unsafe { finish_retired(grant, &counters) }.unwrap();
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}
