use super::*;
#[test]
fn erased_use_keeps_original_storage_and_count_until_real_completion() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let use_ = owner
        .retain()
        .begin_use(UseKind::Configuration)
        .unwrap()
        .erase();
    assert_eq!(use_.kind(), UseKind::Configuration);
    assert!(matches!(owner.close(), Err(Error::Busy { uses: 1, .. })));
    assert_eq!(releases.load(Ordering::Relaxed), 0);
    // SAFETY: actual bounded model operation has ended, original owner current.
    unsafe { use_.release() }.unwrap_or_else(|_| panic!("opaque original use refused"));
    // SAFETY: original use ended and actual allocation custody returned.
    unsafe { returned(owner).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 1);
}
#[test]
fn exclusive_control_requires_closed_zero_users_and_keeps_parent_busy() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut parent = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let mut owner = Assignment::from_owned(OwnedAllocation::new(
        Some(parent.parent()),
        releases.clone(),
    ));
    assert!(matches!(owner.exclusive_control_use(), Err(Error::Open)));
    let use_ = owner.retain().begin_use(UseKind::Mapping).unwrap();
    assert!(matches!(owner.close(), Err(Error::Busy { uses: 1, .. })));
    assert!(matches!(
        owner.exclusive_control_use(),
        Err(Error::Busy { uses: 1, .. })
    ));
    // SAFETY: model mapping user ended with no exposed CPU pointer.
    unsafe { release(use_) };
    let control = owner.exclusive_control_use().unwrap().erase();
    assert_eq!(parent.uses(), 1);
    assert!(matches!(parent.close(), Err(Error::Busy { uses: 1, .. })));
    assert!(matches!(
        owner.retain().begin_use(UseKind::Mapping),
        Err(Error::Closed)
    ));
    // SAFETY: exact original exclusive model operation completed.
    unsafe { control.release() }.unwrap_or_else(|_| panic!("control release refused"));
    // SAFETY: no remaining model users or child retentions.
    unsafe {
        returned(owner).finish();
        returned(parent).finish();
    }
}
#[test]
fn abandoned_erased_operation_never_invents_completion() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    drop(
        owner
            .retain()
            .begin_use(UseKind::Configuration)
            .unwrap()
            .erase(),
    );
    assert_eq!(owner.uses(), 1);
    assert!(matches!(owner.close(), Err(Error::Busy { uses: 1, .. })));
    assert_eq!(releases.load(Ordering::Relaxed), 0);
}
#[test]
fn explicit_abandonment_closes_without_context_or_native_effect() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let pin = owner.retain();
    let use_ = pin.begin_use(UseKind::Mapping).unwrap();
    owner.abandon_admission();
    assert_eq!(owner.uses(), 1);
    assert!(matches!(
        pin.begin_use(UseKind::Configuration),
        Err(Error::Closed)
    ));
    assert_eq!(releases.load(Ordering::Relaxed), 0);
    // SAFETY: original model user ended; abandonment did not invent this join.
    unsafe { release(use_) };
    drop(pin);
    // SAFETY: same original physical custody returned after actual completion.
    unsafe { returned(owner).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 1);
}
