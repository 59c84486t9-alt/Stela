//! AMD DMA table construction fixtures.
use super::*;

#[test]
fn unpublished_root_failures() {
    for stage in 0..4 {
        let monitor = Monitor::new();
        {
            let mut state = monitor.state.lock().unwrap();
            match stage {
                1 => state.fail_allocate = Some(1),
                2 => state.fail_publish = Some(1),
                3 => state.panic_publish = Some(1),
                _ => (),
            }
        }
        let hardware = Hardware {
            monitor: monitor.clone(),
            native_shift: 12,
        };
        let width = if stage == 0 { 31 } else { 48 };
        if stage == 3 {
            // SAFETY: an isolated unpublished root cannot be used by a
            // device. Unwinding its initial publication must release it.
            assert!(
                catch_unwind(AssertUnwindSafe(||
                // SAFETY: This software root has never escaped or reached a device.
                // The injected publication unwind occurs while its fresh CPU pin and
                // provider remain owned by construction.
                unsafe {
                    PageTables::new(
                        hardware,
                        TableLevel::new(2).unwrap(),
                        width,
                        30,
                        TEST_TABLE_BUDGET,
                        TEST_TABLE_BUDGET * 4096,
                    )
                }))
                .is_err()
            );
        } else {
            // SAFETY: same isolated model; invalid metadata/provider results
            // are injected before a root address can escape the constructor.
            let result = unsafe {
                PageTables::new(
                    hardware,
                    TableLevel::new(2).unwrap(),
                    width,
                    30,
                    TEST_TABLE_BUDGET,
                    TEST_TABLE_BUDGET * 4096,
                )
            };
            let expected = match stage {
                0 => TranslationError::Format(FormatError::PhysicalWidth),
                1 => TranslationError::Table(TableError::Memory(MemoryError::OutOfMemory)),
                _ => TranslationError::Table(TableError::Memory(MemoryError::Unavailable)),
            };
            match result {
                Err(error) => assert_eq!(error, expected),
                Ok(_) => panic!("root failure accepted"),
            }
        }
        assert_eq!(monitor.live_tables(), 0);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            monitor.table_drops.load(Ordering::Relaxed),
            usize::from(stage >= 2)
        );
        if stage == 0 {
            assert_eq!(monitor.state.lock().unwrap().allocation_calls, 0);
        }
    }
}

#[test]
fn node_budget_endpoints() {
    for nodes in [1, u32::MAX as usize] {
        let (mut tree, monitor) = new_tree_with_limits(1, 12, nodes, 4096);
        let root = tree.root_for_publication().unwrap().value();
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: a one-page idle model needs only its root. The upper
        // legal node cap does not reserve that many allocations.
        unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) }.unwrap();
        assert_eq!(monitor.walk(root, 1, 0).unwrap().physical, 0x300000);
        assert_eq!(monitor.state.lock().unwrap().allocation_calls, 1);
        assert_eq!(tree.state.as_ref().unwrap().backing_bytes, 4096);
        // SAFETY: This exact root-only model mapping has no requester or deferred
        // user, and the synchronous walker has returned before its payload pin is
        // removed.
        unsafe { tree.unmap(0) }.unwrap();
        retired(tree, &monitor);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
