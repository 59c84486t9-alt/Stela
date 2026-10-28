//! AMD DMA table admission fixtures.
use super::*;

#[test]
fn range_overlap_width_and_payload_admission_refuse_before_mutation() {
    let (mut tree, monitor) = new_tree(1, 12);
    let root = tree.root_for_publication().unwrap().value();
    let retained = Arc::new(AtomicUsize::new(0));
    // SAFETY: exact exclusive idle model span.
    unsafe {
        tree.map(
            0x2000,
            payload(0x300000, &retained),
            Direction::Bidirectional,
        )
    }
    .unwrap();
    for (address, pa, expected) in [
        (1, 0x400000, TranslationError::InvalidRange),
        (0x2000, 0x400000, TranslationError::Overlap),
        (0x200000, 0x400000, TranslationError::AddressLimit),
        (
            0xffff_ffff_ffff_f000,
            0x400000,
            TranslationError::AddressLimit,
        ),
        (0x4000, 1u64 << 48, TranslationError::AddressLimit),
    ] {
        let before = monitor.state.lock().unwrap().events.len();
        let rejected = Arc::new(AtomicUsize::new(0));
        // SAFETY: only numeric metadata is intentionally inadmissible.
        assert_eq!(
            unsafe { tree.map(address, payload(pa, &rejected), Direction::ToDevice) },
            Err(expected)
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.state.lock().unwrap().events.len(), before);
        assert!(!tree.is_poisoned());
    }
    // A multi-page range that overlaps at either edge is refused in full.
    for address in [0x1000, 0x2000] {
        let rejected = Arc::new(AtomicUsize::new(0));
        let pages = pin(vec![0x500000, 0x501000], 12, rejected.clone(), None).into();
        // SAFETY: model deliberately probes an overlapping reserved interval.
        assert_eq!(
            unsafe { tree.map(address, pages, Direction::ToDevice) },
            Err(TranslationError::Overlap)
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
    }
    monitor.state.lock().unwrap().fail_admit = true;
    let rejected = Arc::new(AtomicUsize::new(0));
    let before = monitor.state.lock().unwrap().publications;
    // SAFETY: the fixed model context explicitly refuses this payload policy.
    assert_eq!(
        unsafe { tree.map(0x4000, payload(0x600000, &rejected), Direction::ToDevice) },
        Err(TranslationError::Payload(DmaError::VisibilityFailed))
    );
    assert_eq!(rejected.load(Ordering::Relaxed), 1);
    assert_eq!(monitor.state.lock().unwrap().publications, before);
    assert!(!tree.is_poisoned());
    monitor.state.lock().unwrap().fail_admit = false;
    assert_eq!(monitor.walk(root, 1, 0x2000).unwrap().physical, 0x300000);
    assert_eq!(monitor.walk(root, 1, 0x4000), None);
    // Exact-start removal only, not an interior or absent interval.
    // SAFETY: synchronous fixture has no in-flight hardware accesses.
    assert_eq!(
        unsafe { tree.unmap(0x2001) },
        Err(TranslationError::NotMapped)
    );
    unsafe { tree.unmap(0x2000) }.unwrap();
    assert_eq!(retained.load(Ordering::Relaxed), 1);
    retired(tree, &monitor);
}

#[test]
fn invalid_table_and_backing_budgets_refuse_before_provider_effects() {
    let mut budgets = vec![(0, 4096), (1, 0), (1, 4095)];
    if let Some(overwidth) = (u32::MAX as usize).checked_add(1) {
        budgets.push((overwidth, 4096));
    }
    for (nodes, backing_bytes) in budgets {
        let monitor = Monitor::new();
        let hardware = Hardware {
            monitor: monitor.clone(),
            native_shift: 12,
        };
        // SAFETY: isolated software root; invalid resource admission must
        // precede allocation, publication and any escaping root address.
        let result = unsafe {
            PageTables::new(
                hardware,
                TableLevel::new(2).unwrap(),
                48,
                30,
                nodes,
                backing_bytes,
            )
        };
        match result {
            Err(error) => assert_eq!(error, TranslationError::ResourceLimit),
            Ok(_) => panic!("invalid table budget accepted"),
        }
        assert!(monitor.words().is_empty());
        let state = monitor.state.lock().unwrap();
        assert_eq!(state.allocation_calls, 0);
        assert!(state.events.is_empty());
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 0);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
    }
}
