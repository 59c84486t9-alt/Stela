//! AMD DMA table geometry fixtures.
use super::*;

#[test]
fn host_modes_and_top_level_slots() {
    for mode in 1..=6 {
        let (mut tree, monitor) = new_tree(mode, 12);
        let root = tree.root_for_publication().unwrap().value();
        let bits = 12 + 9 * u32::from(mode);
        let address = if bits >= 64 {
            u64::MAX - 4095
        } else {
            (1u64 << bits) - 4096
        };
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: the synchronous model exclusively reserves this final page.
        unsafe {
            tree.map(
                address,
                payload(0x2345_6000, &drops),
                Direction::Bidirectional,
            )
        }
        .unwrap();
        assert_eq!(
            monitor.walk(root, mode, address + 4095),
            Some(Walk {
                physical: 0x2345_6fff,
                read: true,
                write: true,
                coherent: true,
            })
        );
        assert_eq!(monitor.walk(root, mode, address - 4096), None);
        if mode == 6 {
            let state = monitor.state.lock().unwrap();
            let root = state
                .allocations
                .iter()
                .find(|item| item.physical == root)
                .unwrap();
            for slot in 128..512 {
                // SAFETY: the exact root allocation, read-only model.
                assert_eq!(
                    // SAFETY: The monitor guard keeps this exact 512-word aligned
                    // root allocation and excludes retirement; slots 128..512 are in
                    // bounds and no model writer runs during this read.
                    unsafe { (root.cpu as *const u64).add(slot).read_volatile() },
                    0
                );
            }
        }
        // SAFETY: no asynchronous requester exists in this fixture.
        unsafe { tree.unmap(address) }.unwrap();
        assert_eq!(monitor.walk(root, mode, address), None);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        let state = monitor.state.lock().unwrap();
        assert!(state.events.iter().any(
            |event| matches!(event, Event::Invalidate(start, 4096, true) if *start == address)
        ));
        drop(state);
        retired(tree, &monitor);
    }
}

#[test]
fn final_mode_six_native_span() {
    let (mut tree, monitor) = new_tree(6, 13);
    let root = tree.root_for_publication().unwrap().value();
    let rejected = Arc::new(AtomicUsize::new(0));
    let pages = pin(vec![0x300000], 13, rejected.clone(), None).into();
    // SAFETY: an oversized numeric IOVA interval must fail before mutation.
    assert_eq!(
        // SAFETY: The 8K payload pin remains live and the model has no requester.
        // Only the overflowing numeric IOVA extent is rejected, before it can publish
        // a mapping.
        unsafe { tree.map(u64::MAX - 4095, pages, Direction::ToDevice) },
        Err(TranslationError::AddressLimit)
    );
    assert_eq!(rejected.load(Ordering::Relaxed), 1);
    assert!(!tree.is_poisoned());
    let drops = Arc::new(AtomicUsize::new(0));
    let physical = (1u64 << 48) - 8192;
    let address = u64::MAX - 8191;
    let pages = pin(vec![physical], 13, drops.clone(), None).into();
    // SAFETY: exact last8K model interval; its exclusive end requires the
    // TableHardware provider's full-domain invalidation, not wrapped bytes.
    unsafe { tree.map(address, pages, Direction::Bidirectional) }.unwrap();
    assert_eq!(
        monitor.walk(root, 6, u64::MAX),
        Some(Walk {
            physical: (1u64 << 48) - 1,
            read: true,
            write: true,
            coherent: true,
        })
    );
    assert!(address.checked_add(8192).is_none());
    // SAFETY: the fixture has no asynchronous requester or table writer.
    unsafe { tree.unmap(address) }.unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(
        monitor
            .state
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|event| matches!(event,
        Event::Invalidate(start, 8192, true) if *start == address))
    );
    retired(tree, &monitor);
}

#[test]
fn virtual_aperture_and_host_capacity() {
    let monitor = Monitor::new();
    let hardware = Hardware {
        monitor: monitor.clone(),
        native_shift: 12,
    };
    // SAFETY: this software fixture admits a 32-bit virtual aperture even
    // though its three-level host format can represent 39 address bits.
    let mut tree = unsafe {
        PageTables::new(
            hardware,
            TableLevel::new(3).unwrap(),
            48,
            32,
            TEST_TABLE_BUDGET,
            TEST_TABLE_BUDGET * 4096,
        )
    }
    .unwrap();
    let root = tree.root_for_publication().unwrap().value();
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: exact final page of the admitted 32-bit aperture is exclusive.
    unsafe { tree.map(0xffff_f000, payload(0x300000, &drops), Direction::ToDevice) }.unwrap();
    assert_eq!(
        monitor.walk(root, 3, 0xffff_ffff).unwrap().physical,
        0x300fff
    );
    for address in [1u64 << 32, (1u64 << 32) + 0xffff_f000] {
        let rejected = Arc::new(AtomicUsize::new(0));
        let before = monitor.state.lock().unwrap().events.len();
        // SAFETY: an address representable by mode3 but outside the
        // admitted aperture must not alias or mutate any mapping.
        assert_eq!(
            // SAFETY: The candidate payload has live backing with symbolic addresses.
            // No hardware or worker is present; the out-of-aperture IOVA must fail
            // before any table changes.
            unsafe { tree.map(address, payload(0x500000, &rejected), Direction::FromDevice) },
            Err(TranslationError::AddressLimit)
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.state.lock().unwrap().events.len(), before);
        assert!(!tree.is_poisoned());
    }
    assert_eq!(
        monitor.walk(root, 3, 0xffff_ffff).unwrap().physical,
        0x300fff
    );
    // SAFETY: no asynchronous requester exists; model mapping is idle.
    unsafe { tree.unmap(0xffff_f000) }.unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    retired(tree, &monitor);

    for (mode, virtual_bits) in [(3, 0), (3, 11), (3, 40), (3, 65), (6, u8::MAX)] {
        let monitor = Monitor::new();
        let hardware = Hardware {
            monitor: monitor.clone(),
            native_shift: 12,
        };
        // SAFETY: only invalid numeric admission metadata is tested; this
        // failure must precede every allocation and visibility callback.
        let result = unsafe {
            PageTables::new(
                hardware,
                TableLevel::new(mode).unwrap(),
                48,
                virtual_bits,
                TEST_TABLE_BUDGET,
                TEST_TABLE_BUDGET * 4096,
            )
        };
        match result {
            Err(error) => assert_eq!(error, TranslationError::VirtualWidth),
            Ok(_) => panic!("invalid virtual aperture accepted"),
        }
        let state = monitor.state.lock().unwrap();
        assert_eq!(state.allocation_calls, 0);
        assert_eq!(state.publications, 0);
        assert!(state.events.is_empty());
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
    }
}
