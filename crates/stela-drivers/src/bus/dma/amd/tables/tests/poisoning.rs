//! AMD DMA table poisoning fixtures.
use super::*;

#[test]
fn uncertain_publication_retains_pins() {
    for stage in [3, 4, 5] {
        let (mut tree, monitor) = new_tree(2, 12);
        let root = tree.root_for_publication().unwrap().value();
        {
            let mut state = monitor.state.lock().unwrap();
            if stage == 5 {
                state.fail_invalidate = true;
            } else {
                state.fail_publish = Some(stage);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        monitor.state.lock().unwrap().watch_payload = Some(drops.clone());
        // SAFETY: no model requester is active; injected uncertainty is retained.
        let result = unsafe { tree.map(0x8000, payload(0x600000, &drops), Direction::FromDevice) };
        let expected = if stage == 5 {
            TranslationError::Invalidation(DmaError::InvalidationFailed)
        } else {
            TranslationError::Table(TableError::Memory(MemoryError::Unavailable))
        };
        assert_eq!(result, Err(expected));
        assert!(tree.is_poisoned());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(monitor.live_tables(), 2);
        if stage == 3 {
            assert_eq!(monitor.walk(root, 2, 0x8000), None);
        } else {
            assert_eq!(monitor.walk(root, 2, 0x8000).unwrap().physical, 0x600000);
        }
        let replacement = Arc::new(AtomicUsize::new(0));
        // SAFETY: refusal must precede any attempted IOVA/payload reuse.
        assert_eq!(
            unsafe { tree.map(0x8000, payload(0x700000, &replacement), Direction::ToDevice) },
            Err(TranslationError::Poisoned)
        );
        assert_eq!(replacement.load(Ordering::Relaxed), 1);
        assert_eq!(
            unsafe { tree.unmap(0x8000) },
            Err(TranslationError::Poisoned)
        );
        assert_eq!(tree.root_for_publication(), Err(TranslationError::Poisoned));
        retired(tree, &monitor);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn unmap_failures_and_callback_unwinds() {
    for scenario in [0, 1, 2, 3] {
        let (mut tree, monitor) = new_tree(2, 12);
        let root = tree.root_for_publication().unwrap().value();
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: this model reserves the exact idle IOVA span.
        unsafe { tree.map(0, payload(0x300000, &drops), Direction::Bidirectional) }.unwrap();
        let publications = monitor.state.lock().unwrap().publications;
        {
            let mut state = monitor.state.lock().unwrap();
            state.watch_payload = Some(drops.clone());
            match scenario {
                0 => state.fail_invalidate = true,
                1 => state.fail_publish = Some(publications + 1),
                2 => state.panic_publish = Some(publications + 1),
                _ => state.panic_invalidate = true,
            }
        }
        if scenario < 2 {
            // SAFETY: model is stopped; an unacknowledged removal retains pins.
            assert!(unsafe { tree.unmap(0) }.is_err());
        } else {
            // SAFETY: same stopped model. The injected callback unwinds after
            // a real leaf clear; the owner must stay conservatively poisoned.
            assert!(catch_unwind(AssertUnwindSafe(|| unsafe { tree.unmap(0) })).is_err());
        }
        assert!(tree.is_poisoned());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            monitor.walk(root, 2, 0),
            None,
            "uncertain clear still retains its payload"
        );
        let rejected = Arc::new(AtomicUsize::new(0));
        // SAFETY: attempting reuse exercises the poisoned-owner refusal only.
        assert_eq!(
            unsafe { tree.map(0, payload(0x500000, &rejected), Direction::ToDevice) },
            Err(TranslationError::Poisoned)
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    for panic_stage in [2, 3, 4, 5] {
        let (mut tree, monitor) = new_tree(2, 12);
        let root = tree.root_for_publication().unwrap().value();
        {
            let mut state = monitor.state.lock().unwrap();
            if panic_stage == 5 {
                state.panic_invalidate = true;
            } else {
                state.panic_publish = Some(panic_stage);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: idle fixture injects unwind during fresh cache visibility,
        // live parent/leaf publication, or acknowledged-completion callback.
        assert!(
            catch_unwind(AssertUnwindSafe(|| unsafe {
                tree.map(0, payload(0x300000, &drops), Direction::ToDevice)
            }))
            .is_err()
        );
        assert!(tree.is_poisoned());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(monitor.live_tables(), if panic_stage == 2 { 1 } else { 2 });
        if panic_stage < 4 {
            assert_eq!(monitor.walk(root, 2, 0), None);
        } else {
            assert_eq!(monitor.walk(root, 2, 0).unwrap().physical, 0x300000);
        }
        let rejected = Arc::new(AtomicUsize::new(0));
        // SAFETY: caught provider unwind grants no mapping or IOVA reuse.
        assert_eq!(
            unsafe { tree.map(0, payload(0x500000, &rejected), Direction::ToDevice) },
            Err(TranslationError::Poisoned)
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn exposed_tree_drop_quarantine() {
    let (tree, monitor) = new_tree(1, 12);
    drop(tree);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 1);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);

    let (mut tree, monitor) = new_tree(1, 12);
    tree.root_for_publication().unwrap();
    retired(tree, &monitor);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 1);

    let (mut tree, monitor) = new_tree(1, 12);
    tree.root_for_publication().unwrap();
    // One deliberately leaked 4K fixture proves actual Drop quarantine. Do
    // not reclaim its RAM behind the retained forgotten pin/context owners.
    let before = quarantine_status();
    drop(tree);
    let after = quarantine_status();
    assert!(after.trees >= before.trees.saturating_add(1));
    assert!(after.tables >= before.tables.saturating_add(1));
    assert!(after.payload_bytes >= before.payload_bytes);
    assert_eq!(monitor.live_tables(), 1);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 0);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);

    let (mut tree, monitor) = new_tree(1, 12);
    tree.root_for_publication().unwrap();
    monitor.state.lock().unwrap().fail_invalidate = true;
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: the isolated model has no actual requester; failed completion
    // conservatively models an exposed, uncertain payload mapping.
    assert_eq!(
        unsafe { tree.map(0, payload(0x300000, &drops), Direction::Bidirectional) },
        Err(TranslationError::Invalidation(DmaError::InvalidationFailed))
    );
    let before = quarantine_status();
    drop(tree);
    let after = quarantine_status();
    assert!(after.trees >= before.trees.saturating_add(1));
    assert!(after.tables >= before.tables.saturating_add(1));
    assert!(after.payload_bytes >= before.payload_bytes.saturating_add(4096));
    assert_eq!(monitor.live_tables(), 1);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}
