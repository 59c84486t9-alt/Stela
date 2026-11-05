use super::*;

#[test]
fn foreign_close_handle_denies_descendants_without_context_or_completion() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut root = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let mut child =
        Assignment::from_owned(OwnedAllocation::new(Some(root.parent()), releases.clone()));
    let held = child.retain();
    let user = held.begin_use(UseKind::Mapping).unwrap();
    let close = root.admission_close();
    thread::spawn(move || {
        close.close();
        close.dismiss();
    })
    .join()
    .unwrap();
    assert_eq!(root.uses(), 1);
    assert_eq!(child.uses(), 1);
    assert!(matches!(
        held.begin_use(UseKind::Configuration),
        Err(Error::Closed)
    ));
    assert_eq!(releases.load(Ordering::Relaxed), 0);
    // SAFETY: actual model user ended on its original creating thread.
    unsafe { release(user) };
    drop(held);
    child.close().unwrap();
    // SAFETY: closed original child has no users/retentions, same Box returns.
    unsafe { returned(child).finish() };
    root.close().unwrap();
    // SAFETY: source-owned child product finished before original root returns.
    unsafe { returned(root).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 2);
}

#[test]
fn dismissed_return_key_handle_does_not_close_original_admission() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut root = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    root.admission_close().dismiss();
    let user = root.retain().begin_use(UseKind::Configuration).unwrap();
    assert_eq!(root.uses(), 1);
    // SAFETY: completed bounded model operation, no CPU/native user remains.
    unsafe { release(user) };
    root.close().unwrap();
    // SAFETY: actual original allocation returned with no user or key retention.
    unsafe { returned(root).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 1);
}

#[test]
fn abandoned_key_handle_closes_and_keeps_original_storage() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut root = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    drop(root.admission_close());
    assert!(matches!(
        root.retain().begin_use(UseKind::Mapping),
        Err(Error::Closed)
    ));
    root.close().unwrap();
    assert!(matches!(
        root.into_original(),
        Err(Refusal {
            error: Error::Busy {
                uses: 0,
                retentions: 1
            },
            ..
        })
    ));
    assert_eq!(releases.load(Ordering::Relaxed), 0);
}
