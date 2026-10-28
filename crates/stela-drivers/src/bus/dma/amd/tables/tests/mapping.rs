//! AMD DMA table mapping fixtures.
use super::*;

#[test]
fn expanded_unsorted_eight_k_scatter_aliases_publish_children_before_parents() {
    let (mut tree, monitor) = new_tree(2, 13);
    let root = tree.root_for_publication().unwrap().value();
    let drops = Arc::new(AtomicUsize::new(0));
    let first = pin(vec![0x900000, 0x700000], 13, drops.clone(), None);
    let second = pin(vec![0x300000], 13, drops.clone(), None);
    let pages = DmaPages::from_ranges(vec![
        PageRange::new(first.clone(), 8192..16384).unwrap(),
        PageRange::new(second, 0..8192).unwrap(),
        PageRange::new(first, 8192..16384).unwrap(),
    ])
    .unwrap();
    monitor.state.lock().unwrap().watch_payload = Some(drops.clone());
    let address = 0x1ff000;
    // SAFETY: the complete crossing span is exclusive and the model is idle.
    unsafe { tree.map(address, pages, Direction::ToDevice) }.unwrap();
    for (index, physical) in [0x700000, 0x701000, 0x300000, 0x301000, 0x700000, 0x701000]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            monitor.walk(root, 2, address + index as u64 * 4096),
            Some(Walk {
                physical,
                read: true,
                write: false,
                coherent: true,
            })
        );
    }
    assert_eq!(monitor.walk(root, 2, address + 6 * 4096), None);
    let events = monitor.state.lock().unwrap().events.clone();
    let published: Vec<_> = events
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
    assert_eq!(published.len(), 7);
    assert!(published[0].1.iter().all(|word| *word == 0));
    assert!(published[1].1.iter().all(|word| *word == 0));
    assert!(published[2].1.iter().all(|word| *word == 0));
    assert_eq!(published[3].0, root);
    assert_eq!(published[3].1[0], 0);
    assert_eq!(published[3].1[1] & PA_MASK, published[2].0);
    assert_eq!(published[4].0, root);
    assert_eq!(published[4].1[0] & PA_MASK, published[1].0);
    assert_eq!(published[4].1[1] & PA_MASK, published[2].0);
    assert_eq!(published[5].0, published[1].0);
    assert_eq!(published[6].0, published[2].0);
    assert!(matches!(
        events.last(),
        Some(Event::Invalidate(0x1ff000, 24576, true))
    ));
    assert!(events.iter().any(|event| matches!(event, Event::Admit(pages, Direction::ToDevice) if pages.as_slice() == [0x700000, 0x300000, 0x700000])));
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let allocated = monitor.live_tables();
    // SAFETY: every modeled access is synchronous and stopped.
    unsafe { tree.unmap(address) }.unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(
        monitor.live_tables(),
        allocated,
        "child pins wait for root retirement"
    );
    retired(tree, &monitor);
}

#[test]
fn leaf_permissions_follow_direction_and_fixed_payload_policy() {
    for (direction, read, write, coherent) in [
        (Direction::ToDevice, true, false, false),
        (Direction::FromDevice, false, true, true),
        (Direction::Bidirectional, true, true, true),
    ] {
        let (mut tree, monitor) = new_tree(3, 12);
        monitor.state.lock().unwrap().coherent = coherent;
        let root = tree.root_for_publication().unwrap().value();
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: exact isolated span; no device/worker can submit.
        unsafe { tree.map(0x1234_5000, payload(0x4567_8000, &drops), direction) }.unwrap();
        assert_eq!(
            monitor.walk(root, 3, 0x1234_5678),
            Some(Walk {
                physical: 0x4567_8678,
                read,
                write,
                coherent,
            })
        );
        // SAFETY: exact synchronous software mapping has finished all accesses.
        unsafe { tree.unmap(0x1234_5000) }.unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);
    }
}
