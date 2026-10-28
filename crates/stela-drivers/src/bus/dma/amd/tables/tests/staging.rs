//! AMD DMA table staging fixtures.
use super::*;

#[test]
fn unpublished_child_rollback() {
    for allocate_failure in [true, false] {
        let (mut tree, monitor) = new_tree(2, 12);
        let root = tree.root_for_publication().unwrap().value();
        {
            let mut state = monitor.state.lock().unwrap();
            if allocate_failure {
                state.fail_allocate = Some(2);
            } else {
                state.fail_publish = Some(2);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: fresh isolated model span; failures precede any parent store.
        let result = unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) };
        assert_eq!(
            result,
            Err(TranslationError::Table(TableError::Memory(
                if allocate_failure {
                    MemoryError::OutOfMemory
                } else {
                    MemoryError::Unavailable
                }
            )))
        );
        assert!(!tree.is_poisoned());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.live_tables(), 1);
        assert_eq!(monitor.walk(root, 2, 0), None);
        {
            let mut state = monitor.state.lock().unwrap();
            state.fail_allocate = None;
            state.fail_publish = None;
        }
        let retry = Arc::new(AtomicUsize::new(0));
        // SAFETY: pre-mutation rollback left this exact model IOVA reusable.
        unsafe { tree.map(0, payload(0x500000, &retry), Direction::ToDevice) }.unwrap();
        // SAFETY: The retry mapping is exclusively owned by this synchronous software
        // model; all reads have returned and no hardware or deferred user can access
        // its payload during removal.
        unsafe { tree.unmap(0) }.unwrap();
        assert_eq!(retry.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);
    }
}

#[test]
fn deeper_staging_rollback() {
    for allocation_failure in [true, false] {
        let (mut tree, monitor) = new_tree(3, 12);
        let root = tree.root_for_publication().unwrap().value();
        let before = monitor.words();
        {
            let mut state = monitor.state.lock().unwrap();
            // The level2 child is staged, but no parent store may happen
            // before allocation and visibility of the level1 child succeed.
            if allocation_failure {
                state.fail_allocate = Some(3);
            } else {
                state.fail_publish = Some(3);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: exact idle model interval; later staging failure injected.
        let result = unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) };
        assert_eq!(
            result,
            Err(TranslationError::Table(TableError::Memory(
                if allocation_failure {
                    MemoryError::OutOfMemory
                } else {
                    MemoryError::Unavailable
                }
            )))
        );
        assert!(!tree.is_poisoned());
        assert_eq!(monitor.live_tables(), 1);
        assert_eq!(monitor.words(), before);
        assert_eq!(tree.state.as_ref().unwrap().nodes.len(), 1);
        assert!(tree.state.as_ref().unwrap().bindings.is_empty());
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.walk(root, 3, 0), None);
        {
            let mut state = monitor.state.lock().unwrap();
            assert!(
                !state
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Invalidate(..)))
            );
            state.fail_allocate = None;
            state.fail_publish = None;
        }
        let retry = Arc::new(AtomicUsize::new(0));
        // SAFETY: complete staging rollback leaves the exact IOVA reusable.
        unsafe { tree.map(0, payload(0x500000, &retry), Direction::ToDevice) }.unwrap();
        assert_eq!(monitor.walk(root, 3, 0).unwrap().physical, 0x500000);
        // SAFETY: The smaller retry mapping is idle after the synchronous walk; no
        // device, worker or concurrent table reader exists while unmap releases its
        // exact payload.
        unsafe { tree.unmap(0) }.unwrap();
        assert_eq!(retry.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);
    }
}

#[test]
fn descendant_before_root_publication() {
    let (mut tree, monitor) = new_tree(3, 12);
    let root = tree.root_for_publication().unwrap().value();
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: the software model exclusively reserves this idle IOVA.
    unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) }.unwrap();
    let events = monitor.state.lock().unwrap().events.clone();
    let publications: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Publish {
                physical,
                words,
                success,
            } => {
                assert!(*success);
                Some((*physical, words))
            }
            _ => None,
        })
        .collect();
    assert_eq!(publications.len(), 6);
    for (_, words) in &publications[..3] {
        assert!(words.iter().all(|word| *word == 0));
    }
    let level2 = publications[1].0;
    let level1 = publications[2].0;
    assert_eq!(publications[3].0, level2);
    assert_eq!(publications[3].1[0] & PA_MASK, level1);
    assert_eq!(publications[4].0, root);
    assert_eq!(publications[4].1[0] & PA_MASK, level2);
    assert_eq!(publications[5].0, level1);
    assert_eq!(publications[5].1[0] & PA_MASK, 0x300000);
    assert_eq!(monitor.walk(root, 3, 4095).unwrap().physical, 0x300fff);
    assert!(matches!(
        events.last(),
        Some(Event::Invalidate(0, 4096, true))
    ));
    // SAFETY: model has no asynchronous walker, requester or worker.
    unsafe { tree.unmap(0) }.unwrap();
    retired(tree, &monitor);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
