//! AMD DMA table backing budget fixtures.
use super::*;

#[test]
fn backing_limit_rollback_preserves_mapping() {
    let (mut tree, monitor) = new_tree_with_limits(3, 12, 8, 6 * 4096);
    let root = tree.root_for_publication().unwrap().value();
    let retained = Arc::new(AtomicUsize::new(0));
    // SAFETY: established mapping belongs exclusively to the idle model.
    unsafe { tree.map(0, payload(0x300000, &retained), Direction::ToDevice) }.unwrap();
    let before = monitor.words();
    let (calls, publications, events) = {
        let mut state = monitor.state.lock().unwrap();
        state.returned_granules = 2;
        (
            state.allocation_calls,
            state.publications,
            state.events.len(),
        )
    };
    let rejected = Arc::new(AtomicUsize::new(0));
    let pages = pin(vec![0x500000, 0x501000], 12, rejected.clone(), None).into();
    // SAFETY: exclusive idle crossing range. One full8K pin fits after the
    // established12K; the next full8K pin exceeds the24K byte budget, even
    // though logical node capacity and its initial4K lower bound fit.
    assert_eq!(
        // SAFETY: The fresh crossing IOVA and live payload pin are exclusive to this
        // synchronous model. Full backing-budget rejection must preserve every
        // already-retained table and mapping.
        unsafe { tree.map(0x3fff_f000, pages, Direction::Bidirectional) },
        Err(TranslationError::ResourceLimit)
    );
    assert!(!tree.is_poisoned());
    assert_eq!(monitor.words(), before);
    assert_eq!(monitor.live_tables(), 3);
    assert_eq!(tree.state.as_ref().unwrap().backing_bytes, 3 * 4096);
    assert_eq!(tree.state.as_ref().unwrap().bindings.len(), 1);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 2);
    assert_eq!(retained.load(Ordering::Relaxed), 0);
    assert_eq!(rejected.load(Ordering::Relaxed), 1);
    assert_eq!(monitor.walk(root, 3, 0).unwrap().physical, 0x300000);
    assert_eq!(monitor.walk(root, 3, 0x3fff_f000), None);
    assert_eq!(monitor.walk(root, 3, 0x4000_0000), None);
    let mut state = monitor.state.lock().unwrap();
    assert_eq!(state.allocation_calls, calls + 2);
    assert_eq!(state.publications, publications + 1);
    assert!(
        !state.events[events..]
            .iter()
            .any(|event| matches!(event, Event::Invalidate(..)))
    );
    state.returned_granules = 1;
    drop(state);
    let retry = Arc::new(AtomicUsize::new(0));
    let pages = pin(vec![0x700000, 0x701000], 12, retry.clone(), None).into();
    // SAFETY: complete rollback permits retry; three genuinely fresh4K
    // pins now fit exactly, with no use of the prior unused8K pin tails.
    unsafe { tree.map(0x3fff_f000, pages, Direction::Bidirectional) }.unwrap();
    assert_eq!(tree.state.as_ref().unwrap().backing_bytes, 6 * 4096);
    assert_eq!(monitor.walk(root, 3, 0).unwrap().physical, 0x300000);
    assert_eq!(
        monitor.walk(root, 3, 0x3fff_f000).unwrap().physical,
        0x700000
    );
    assert_eq!(
        monitor.walk(root, 3, 0x4000_0000).unwrap().physical,
        0x701000
    );
    // SAFETY: The retried crossing mapping has finished all software walks; its
    // payload is not used by a device or deferred worker and the established mapping
    // stays separately retained.
    unsafe { tree.unmap(0x3fff_f000) }.unwrap();
    // SAFETY: The established zero-page mapping is idle after the crossing retry was
    // removed; no asynchronous requester, software walker or worker can access its
    // pin.
    unsafe { tree.unmap(0) }.unwrap();
    retired(tree, &monitor);
    assert_eq!(retained.load(Ordering::Relaxed), 1);
    assert_eq!(retry.load(Ordering::Relaxed), 1);
    assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 8);
}

#[test]
fn native_pins_and_provider_tail_budget() {
    // The first case has native8K backing; the second returns two native4K
    // pages for one logical table. Neither unused tail is a spare table.
    for (native_shift, child_granules, byte_limit) in [(13, 1, 12_288), (12, 2, 8192)] {
        let (mut tree, monitor) = new_tree_with_limits(2, native_shift, 2, byte_limit);
        let root = tree.root_for_publication().unwrap().value();
        let before = monitor.words();
        let root_bytes = 1usize << native_shift;
        assert_eq!(
            tree.state.as_ref().unwrap().nodes[0].table.retained_bytes(),
            root_bytes
        );
        monitor.state.lock().unwrap().returned_granules = child_granules;
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: a complete fresh child pin exceeds the byte budget even
        // though a second logical4K table fits the node/index budget.
        assert_eq!(
            // SAFETY: The candidate pin is live and its symbolic IOVA is exclusive.
            // The model has no requester; rejecting oversized native backing must
            // precede child publication.
            unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) },
            Err(TranslationError::ResourceLimit)
        );
        assert!(!tree.is_poisoned());
        assert_eq!(monitor.words(), before);
        assert_eq!(monitor.walk(root, 2, 0), None);
        assert_eq!(monitor.live_tables(), 1);
        assert_eq!(tree.state.as_ref().unwrap().backing_bytes, root_bytes);
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        let state = monitor.state.lock().unwrap();
        assert_eq!(state.allocation_calls, 2);
        assert_eq!(
            state.publications, 1,
            "over-budget child never reaches visibility"
        );
        assert!(
            !state
                .events
                .iter()
                .any(|event| matches!(event, Event::Invalidate(..)))
        );
        drop(state);
        if native_shift == 12 {
            monitor.state.lock().unwrap().returned_granules = 1;
            let retry = Arc::new(AtomicUsize::new(0));
            // SAFETY: a smaller, genuinely fresh complete pin now fits the
            // same byte budget; the original failed IOVA remains reusable.
            unsafe { tree.map(0, payload(0x500000, &retry), Direction::ToDevice) }.unwrap();
            assert_eq!(monitor.walk(root, 2, 0).unwrap().physical, 0x500000);
            assert_eq!(tree.state.as_ref().unwrap().backing_bytes, 8192);
            // SAFETY: The smaller retry has completed its software walk and has no
            // requester or deferred user; removal releases only that exact retained
            // payload mapping.
            unsafe { tree.unmap(0) }.unwrap();
            assert_eq!(retry.load(Ordering::Relaxed), 1);
        }
        retired(tree, &monitor);
    }

    for (native_shift, returned_granules) in [(13, 1), (12, 2)] {
        let monitor = Monitor::new();
        monitor.state.lock().unwrap().returned_granules = returned_granules;
        let hardware = Hardware {
            monitor: monitor.clone(),
            native_shift,
        };
        // SAFETY: a valid4K numeric budget cannot admit an actual8K root
        // pin. No root address, visibility callback or hardware use escapes.
        let result =
            unsafe { PageTables::new(hardware, TableLevel::new(2).unwrap(), 48, 30, 2, 4096) };
        match result {
            Err(error) => assert_eq!(error, TranslationError::ResourceLimit),
            Ok(_) => panic!("oversized root backing accepted"),
        }
        assert!(monitor.words().is_empty());
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        let state = monitor.state.lock().unwrap();
        assert_eq!(state.allocation_calls, 1);
        assert!(state.events.is_empty());
    }
}
