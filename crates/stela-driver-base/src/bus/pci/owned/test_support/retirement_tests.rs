//! Actual original fixture products and mapper effects, never native admission.
use super::*;

#[test]
fn closing_retained_parts_blocks_new_users_without_unmapping_the_original() {
    let (config, counters) = fixture(ADDRESS);
    let epoch = config.retain_epoch().unwrap();
    assert!(epoch.check_live().is_ok());

    let mut parts = config.into_parts();
    parts.close_admission();
    parts.close_admission();
    assert_eq!(
        epoch.check_live(),
        Err(MappingError::Assignment(assignment::Error::Closed))
    );
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    drop(epoch);

    // SAFETY: no fixture users remain. The same kept mapping can now withdraw.
    unsafe { parts.retire() }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn pending_original_config_use_vetoes_unmap_and_same_parts_retry_after_release() {
    let (config, counters) = fixture(ADDRESS);
    let (grant, mapping) = config.into_parts().into_test_parts();
    let mut usage = grant
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
    let Some(KeptFailure::Parts {
        _grant: grant,
        _mapping: mapping,
    }) = failure.kept.take()
    else {
        panic!("same original parts retained");
    };
    drop(failure);
    // SAFETY: this exact original read admission issued no volatile effect,
    // pointer, callback or alias. Release that actual token, not a replacement.
    assert!(unsafe { usage.finish() }.is_ok());
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
    let (ga, ma) = a.into_parts().into_test_parts();
    let (gb, mb) = b.into_parts().into_test_parts();
    assert_eq!(ma.physical_span(), mb.physical_span());
    // SAFETY: both actual model pools have no raw/callback users; this negative
    // input pairs distinct original objects with equal DATA, never native owners.
    let mut failure = unsafe { retire(ga, mb, &ca) }.unwrap_err();
    assert_eq!(failure.error, MappingError::InvalidPlatformReply);
    assert_eq!(ca.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(cb.unmaps.load(Ordering::Relaxed), 0);
    let Some(KeptFailure::Parts {
        _grant: ga,
        _mapping: mb,
    }) = failure.kept.take()
    else {
        panic!("both exact original owners retained");
    };
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
        matches!(failure.kept, Some(KeptFailure::Envelope { .. })),
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
    let Some(KeptFailure::Envelope { _parts: parts }) = failure.kept.take() else {
        panic!("same original envelope retained");
    };
    drop(failure);
    // SAFETY: no user restarted. The same mapper token acknowledges prior
    // removal and the original fixture source now retires in place.
    unsafe { retire_parts(parts) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn unattempted_attachment_retires_the_same_pending_source_without_unmap() {
    let span = PhysicalSpan::new(physical(ADDRESS), FUNCTION_BYTES as u64).unwrap();
    let (source, authority, counters) =
        unmapped(ADDRESS, window(ADDRESS), span, CacheAttribute::Uncached);
    let parts = OwnedConfig::prepare(source.into_grant()).into_parts();
    drop(authority);
    // SAFETY: the isolated fixture issued no map and has no other users.
    unsafe { retire_parts(parts) }.unwrap();
    assert_eq!(counters.maps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn rejected_attachment_retires_the_original_mapping_without_valid_geometry() {
    let span = PhysicalSpan::new(physical(ADDRESS), FUNCTION_BYTES as u64).unwrap();
    let (source, authority, counters) =
        unmapped(ADDRESS, window(ADDRESS), span, CacheAttribute::Uncached);
    let prepared = OwnedConfig::prepare(source.into_grant());
    let mapping = authority
        .map(
            prepared.configuration_resource().clone(),
            0,
            FUNCTION_BYTES,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        )
        .unwrap();
    drop(authority);
    let Err((error, parts)) = prepared.attach(mapping) else {
        panic!("read-only mapping accepted for writable configuration");
    };
    assert_eq!(error, ConfigError::before_effect(ConfigFailure::Protection));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: this exact source and mapping never admitted an actual config user.
    unsafe { retire_parts(parts) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn attachment_unwind_closes_and_keeps_the_original_mapping_count() {
    let span = PhysicalSpan::new(physical(ADDRESS), FUNCTION_BYTES as u64).unwrap();
    let (source, authority, counters) =
        unmapped(ADDRESS, window(ADDRESS), span, CacheAttribute::Uncached);
    let retention = source.retention();
    let prepared = OwnedConfig::prepare(source.into_grant());
    let mapping = authority
        .map(
            prepared.configuration_resource().clone(),
            0,
            FUNCTION_BYTES,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let contexts = counters.contexts.load(Ordering::Relaxed);
    counters
        .panic_context_at
        .store(contexts + 1, Ordering::Relaxed);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = prepared.attach(mapping);
    }));
    assert!(failure.is_err());
    assert_eq!(counters.contexts.load(Ordering::Relaxed), contexts + 1);
    assert_eq!(
        retention.check_admission(),
        Err(MappingError::Assignment(assignment::Error::Closed))
    );
    assert_eq!(retention.uses(), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    drop(authority);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}
