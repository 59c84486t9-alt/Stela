//! AMD DMA table node budget fixtures.
use super::*;

#[test]
fn node_budget_staging_rollback() {
    let (mut tree, monitor) = new_tree_with_limits(3, 12, 4, TEST_TABLE_BUDGET * 4096);
    let root = tree.root_for_publication().unwrap().value();
    let before = monitor.words();
    let drops = Arc::new(AtomicUsize::new(0));
    let pages = pin(vec![0x300000, 0x301000], 12, drops.clone(), None).into();
    // SAFETY: two idle pages cross a 1GiB path boundary. Root + three
    // staged pages fit, but the fourth child exceeds the four-node policy.
    assert_eq!(
        // SAFETY: Both payload pages have live backing and the fresh crossing IOVA is
        // exclusive. The synchronous software model must exhaust its node budget
        // before publishing an edge.
        unsafe { tree.map(0x3fff_f000, pages, Direction::ToDevice) },
        Err(TranslationError::ResourceLimit)
    );
    assert!(!tree.is_poisoned());
    assert_eq!(monitor.words(), before);
    assert_eq!(monitor.live_tables(), 1);
    assert_eq!(tree.state.as_ref().unwrap().nodes.len(), 1);
    assert_eq!(tree.state.as_ref().unwrap().backing_bytes, 4096);
    assert!(tree.state.as_ref().unwrap().bindings.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 3);
    let state = monitor.state.lock().unwrap();
    assert_eq!(state.allocation_calls, 4);
    assert_eq!(state.publications, 4);
    assert!(
        !state
            .events
            .iter()
            .any(|event| matches!(event, Event::Invalidate(..)))
    );
    drop(state);
    assert_eq!(monitor.walk(root, 3, 0x3fff_f000), None);
    assert_eq!(monitor.walk(root, 3, 0x4000_0000), None);

    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    // SAFETY: rollback left the model healthy; both smaller paths fit the
    // exact four-table budget and exclusively owned IOVAs.
    unsafe { tree.map(0, payload(0x500000, &first), Direction::ToDevice) }.unwrap();
    // SAFETY: The second IOVA is disjoint from the first mapping and fits
    // the rolled-back node budget. Its payload pin stays owned and no requester or
    // concurrent walker exists.
    unsafe { tree.map(0x20_0000, payload(0x600000, &second), Direction::ToDevice) }.unwrap();
    assert_eq!(monitor.live_tables(), 4);
    assert_eq!(monitor.walk(root, 3, 0).unwrap().physical, 0x500000);
    assert_eq!(monitor.walk(root, 3, 0x20_0000).unwrap().physical, 0x600000);
    // SAFETY: The first model mapping has no hardware, worker or outstanding
    // software reader; the disjoint second mapping keeps its own independent pin.
    unsafe { tree.unmap(0) }.unwrap();
    // SAFETY: The remaining exact second mapping is idle, with no hardware or
    // deferred user. Its last synchronous software walk has completed before pin
    // release.
    unsafe { tree.unmap(0x20_0000) }.unwrap();
    retired(tree, &monitor);
    assert_eq!(first.load(Ordering::Relaxed), 1);
    assert_eq!(second.load(Ordering::Relaxed), 1);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 7);
}

#[test]
fn staged_failure_preserves_existing_mapping() {
    for native_shift in [12, 13] {
        for failure in 0..3 {
            // Five tables allow two staged nodes after the three-table
            // established path; the crossing interval needs a third node.
            let (mut tree, monitor) = new_tree_with_limits(
                3,
                native_shift,
                5,
                TEST_TABLE_BUDGET * (1usize << native_shift),
            );
            let root = tree.root_for_publication().unwrap().value();
            let retained = Arc::new(AtomicUsize::new(0));
            // SAFETY: exact synchronous model mapping with no submissions.
            unsafe { tree.map(0, payload(0x300000, &retained), Direction::FromDevice) }.unwrap();
            let before = monitor.words();
            let previous_drops = monitor.table_drops.load(Ordering::Relaxed);
            let (allocation_calls, publications, events) = {
                let mut state = monitor.state.lock().unwrap();
                if failure == 0 {
                    state.fail_allocate = Some(state.allocation_calls + 2);
                } else if failure == 1 {
                    state.fail_publish = Some(state.publications + 2);
                }
                (
                    state.allocation_calls,
                    state.publications,
                    state.events.len(),
                )
            };
            let rejected = Arc::new(AtomicUsize::new(0));
            let pages = pin(vec![0x500000, 0x501000], 12, rejected.clone(), None).into();
            // SAFETY: fresh idle span crosses a root-child boundary, while
            // the previous mapping stays held and independently walked.
            let result = unsafe { tree.map(0x3fff_f000, pages, Direction::ToDevice) };
            let expected = match failure {
                0 => TranslationError::Table(TableError::Memory(MemoryError::OutOfMemory)),
                1 => TranslationError::Table(TableError::Memory(MemoryError::Unavailable)),
                _ => TranslationError::ResourceLimit,
            };
            assert_eq!(result, Err(expected));
            assert!(!tree.is_poisoned());
            assert_eq!(monitor.words(), before);
            assert_eq!(monitor.live_tables(), 3);
            assert_eq!(tree.state.as_ref().unwrap().nodes.len(), 3);
            assert_eq!(
                tree.state.as_ref().unwrap().backing_bytes,
                3usize << native_shift
            );
            assert_eq!(retained.load(Ordering::Relaxed), 0);
            assert_eq!(rejected.load(Ordering::Relaxed), 1);
            assert_eq!(
                monitor.walk(root, 3, 123).unwrap(),
                Walk {
                    physical: 0x30007b,
                    read: false,
                    write: true,
                    coherent: true,
                }
            );
            assert_eq!(monitor.walk(root, 3, 0x3fff_f000), None);
            assert_eq!(monitor.walk(root, 3, 0x4000_0000), None);
            let mut state = monitor.state.lock().unwrap();
            assert_eq!(state.allocation_calls, allocation_calls + 2);
            assert_eq!(
                state.publications,
                publications + if failure == 0 { 1 } else { 2 }
            );
            assert!(
                !state.events[events..]
                    .iter()
                    .any(|event| matches!(event, Event::Invalidate(..)))
            );
            state.fail_allocate = None;
            state.fail_publish = None;
            drop(state);
            assert_eq!(
                monitor.table_drops.load(Ordering::Relaxed) - previous_drops,
                if failure == 0 { 1 } else { 2 }
            );
            let retry = Arc::new(AtomicUsize::new(0));
            // SAFETY: reuse this rolled-back path with a smaller mapping
            // that fits the node budget.
            unsafe { tree.map(0x3fff_f000, payload(0x700000, &retry), Direction::ToDevice) }
                .unwrap();
            assert_eq!(
                monitor.walk(root, 3, 0x3fff_f000).unwrap().physical,
                0x700000
            );
            // SAFETY: The retried crossing mapping is idle after its walk; the
            // established zero-page mapping remains independently kept. The model
            // has no asynchronous requester.
            unsafe { tree.unmap(0x3fff_f000) }.unwrap();
            // SAFETY: The established zero-page mapping has no outstanding reader,
            // worker or physical requester after the retry was removed; its exact pin
            // may now be released.
            unsafe { tree.unmap(0) }.unwrap();
            retired(tree, &monitor);
            assert_eq!(retained.load(Ordering::Relaxed), 1);
            assert_eq!(retry.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn empty_table_budget_and_pin_reuse() {
    for native_shift in [12, 13] {
        let (mut tree, monitor) = new_tree_with_limits(
            3,
            native_shift,
            3,
            TEST_TABLE_BUDGET * (1usize << native_shift),
        );
        let root = tree.root_for_publication().unwrap().value();
        let first = Arc::new(AtomicUsize::new(0));
        // SAFETY: exclusively reserved synchronous software IOVA.
        unsafe { tree.map(0, payload(0x300000, &first), Direction::ToDevice) }.unwrap();
        // SAFETY: The just-established model mapping has no asynchronous user and its
        // software accesses are complete. Removing it leaves table pins kept for
        // the subsequent reuse checks.
        unsafe { tree.unmap(0) }.unwrap();
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.live_tables(), 3);
        let before = monitor.words();
        let calls = monitor.state.lock().unwrap().allocation_calls;
        let events = monitor.state.lock().unwrap().events.len();
        let rejected = Arc::new(AtomicUsize::new(0));
        // SAFETY: this disjoint idle IOVA needs a fourth table; the owner
        // must count its empty leaf rather than reassign that pin.
        assert_eq!(
            // SAFETY: The disjoint candidate owns live backing and an idle symbolic
            // IOVA. The software model must count kept empty tables and reject
            // the new path before publication.
            unsafe { tree.map(0x20_0000, payload(0x500000, &rejected), Direction::ToDevice) },
            Err(TranslationError::ResourceLimit)
        );
        assert_eq!(monitor.words(), before);
        assert_eq!(monitor.state.lock().unwrap().allocation_calls, calls);
        assert!(
            !monitor.state.lock().unwrap().events[events..]
                .iter()
                .any(|event| matches!(event, Event::Publish { .. } | Event::Invalidate(..)))
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        assert!(!tree.is_poisoned());
        for address in [4096, 0, 4096] {
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: packed/reused IOVA lies in the existing idle leaf;
            // no allocation or reassignment of native tail bytes is needed.
            unsafe { tree.map(address, payload(0x700000, &drops), Direction::Bidirectional) }
                .unwrap();
            assert_eq!(monitor.walk(root, 3, address).unwrap().physical, 0x700000);
            assert_eq!(monitor.state.lock().unwrap().allocation_calls, calls);
            // SAFETY: This exact packed or reused IOVA is idle after its synchronous
            // walk. There is no device or background walker, so its current payload
            // pin can be removed safely.
            unsafe { tree.unmap(address) }.unwrap();
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(monitor.words(), before);
        }
        let words = monitor.words();
        assert_eq!(
            words
                .iter()
                .map(|(_, words)| words.len() * 8)
                .sum::<usize>(),
            3usize << native_shift
        );
        for (_, words) in &words {
            assert!(words[512..].iter().all(|word| *word == 0));
        }
        assert_eq!(
            tree.state.as_ref().unwrap().backing_bytes,
            3usize << native_shift
        );
        retired(tree, &monitor);
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 3);
    }
}
