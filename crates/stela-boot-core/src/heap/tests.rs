use super::*;
use std::{boxed::Box, sync::Barrier, thread};

#[repr(align(4096))]
struct Ram([u8; 128 * 1024]);

fn backing() -> Box<Ram> {
    Box::new(Ram([0; 128 * 1024]))
}

fn usage_values(heap: &Heap) -> [usize; 5] {
    let u = heap.usage();
    [u.total, u.live, u.carved, u.peak, u.largest]
}

#[test]
fn attempted_unready_zero_and_contended_requests_preserve_state() {
    let heap = Heap::new();
    let mut ram = backing();
    let layouts = [
        Layout::from_size_align(17, 16).unwrap(),
        Layout::from_size_align(256, 128).unwrap(),
        Layout::from_size_align(4097, 4096).unwrap(),
    ];
    // SAFETY: these are valid layouts; unready allocation cannot access RAM.
    unsafe {
        for layout in layouts {
            assert!(heap.try_allocate(layout).is_null());
            assert!(heap.try_allocate_zeroed(layout).is_null());
        }
    }
    assert_eq!(usage_values(&heap), [0; 5]);
    // SAFETY: exclusive test backing, kept through every exact free.
    unsafe { heap.initialize(ram.0.as_mut_ptr(), ram.0.len()) };
    let before = usage_values(&heap);
    let image = ram.0.to_vec();
    let zero = Layout::from_size_align(0, 128).unwrap();
    // SAFETY: the new APIs explicitly reject zero without allocation.
    unsafe {
        assert!(heap.try_allocate(zero).is_null());
        assert!(heap.try_allocate_zeroed(zero).is_null());
    }
    assert_eq!(ram.0.as_slice(), image.as_slice());
    assert_eq!(usage_values(&heap), before);
    let guard = heap.lock();
    // A blocking or recursively acquired implementation cannot pass this.
    // SAFETY: the existing guard keeps exclusive metadata ownership;
    // attempted allocation must fail without accessing that metadata.
    unsafe {
        for layout in layouts {
            assert!(heap.try_allocate(layout).is_null());
            assert!(heap.try_allocate_zeroed(layout).is_null());
            assert!(heap.held.load(Ordering::Relaxed));
        }
    }
    assert_eq!(ram.0.as_slice(), image.as_slice());
    drop(guard);
    assert_eq!(usage_values(&heap), before);
}

#[test]
fn attempted_zeroed_reuse_keeps_other_live_payloads_and_global_free_rules() {
    let heap = Heap::new();
    let mut ram = backing();
    let layout = Layout::from_size_align(17, 16).unwrap();
    // SAFETY: fresh exclusive backing; every successful block is freed once
    // through this exact heap/layout while the backing remains live.
    unsafe {
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        let a = heap.alloc(layout);
        let b = heap.alloc(layout);
        assert!(!a.is_null() && !b.is_null() && a != b);
        a.write_bytes(0xa5, layout.size());
        b.write_bytes(0x5a, layout.size());
        heap.dealloc(a, layout);
        let tried = heap.try_allocate_zeroed(layout);
        assert_eq!(tried, a);
        assert!(
            core::slice::from_raw_parts(tried, layout.size())
                .iter()
                .all(|v| *v == 0)
        );
        assert!(
            core::slice::from_raw_parts(b, layout.size())
                .iter()
                .all(|v| *v == 0x5a)
        );
        assert_eq!(heap.usage().live, 64);
        heap.dealloc(tried, layout);
        let ordinary = heap.alloc(layout);
        assert_eq!(ordinary, tried);
        ordinary.write_bytes(0x7c, layout.size());
        heap.dealloc(ordinary, layout);
        let unzeroed = heap.try_allocate(layout);
        assert_eq!(unzeroed, ordinary);
        heap.dealloc(unzeroed, layout);
        heap.dealloc(b, layout);
    }
    assert_eq!(heap.usage().live, 0);
    // The existing small-object cache still keeps its own two blocks.
    assert!(heap.usage().carved > 0);
}

#[test]
fn attempted_general_alignment_zeroing_and_ordinary_free_coalesce() {
    let heap = Heap::new();
    let mut ram = backing();
    // SAFETY: all disjoint payloads keep this exclusive backing/layout.
    unsafe {
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        for (bytes, align) in [(256, 128), (4097, 4096), (8193, 32768)] {
            let layout = Layout::from_size_align(bytes, align).unwrap();
            let tried = heap.try_allocate_zeroed(layout);
            let other = heap.alloc(layout);
            assert!(!tried.is_null() && !other.is_null() && tried != other);
            assert!((tried as usize).is_multiple_of(align));
            assert!(
                core::slice::from_raw_parts(tried, bytes)
                    .iter()
                    .all(|v| *v == 0)
            );
            tried.write_bytes(0xa5, bytes);
            other.write_bytes(0x5a, bytes);
            heap.dealloc(tried, layout);
            let again = heap.try_allocate_zeroed(layout);
            assert!(!again.is_null() && (again as usize).is_multiple_of(align));
            assert!(
                core::slice::from_raw_parts(again, bytes)
                    .iter()
                    .all(|v| *v == 0)
            );
            assert!(
                core::slice::from_raw_parts(other, bytes)
                    .iter()
                    .all(|v| *v == 0x5a)
            );
            heap.dealloc(other, layout);
            heap.dealloc(again, layout);
            assert_eq!(heap.usage().live, 0);
            assert_eq!(heap.usage().carved, 0);
            assert_eq!(heap.usage().largest, ram.0.len());
        }
    }
}

#[test]
fn attempted_exhaustion_preserves_live_bytes_then_reclaims_the_full_extent() {
    let heap = Heap::new();
    let mut ram = backing();
    let layout = Layout::from_size_align(256, 128).unwrap();
    // SAFETY: each raw allocation keeps the same real backing and exact
    // layout; no payload slice survives subsequent allocation/deallocation.
    unsafe {
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        let mut blocks = Vec::new();
        loop {
            let block = heap.try_allocate(layout);
            if block.is_null() {
                break;
            }
            assert!((block as usize).is_multiple_of(128));
            block.write_bytes(0x39, layout.size());
            blocks.push(block);
        }
        assert!(blocks.len() > 32);
        let before = usage_values(&heap);
        let image = ram.0.to_vec();
        assert!(heap.try_allocate(layout).is_null());
        assert!(heap.try_allocate_zeroed(layout).is_null());
        assert!(heap.alloc(layout).is_null());
        assert_eq!(ram.0.as_slice(), image.as_slice());
        assert_eq!(usage_values(&heap), before);
        for block in blocks {
            assert!(
                core::slice::from_raw_parts(block, layout.size())
                    .iter()
                    .all(|v| *v == 0x39)
            );
            heap.dealloc(block, layout);
        }
    }
    assert_eq!(heap.usage().live, 0);
    assert_eq!(heap.usage().carved, 0);
    assert_eq!(heap.usage().largest, ram.0.len());
}

#[test]
fn aligned_extents_coalesce_after_exhaustion() {
    let heap = Heap::new();
    let mut ram = backing();
    let layout = Layout::from_size_align(4097, 4096).unwrap();
    // SAFETY: `ram` is this test's own backing, handed to the heap once and outliving every
    // block.
    unsafe {
        assert!(heap.alloc(layout).is_null());
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        let mut blocks = Vec::new();
        loop {
            let block = heap.alloc(layout);
            if block.is_null() {
                break;
            }
            assert!((block as usize).is_multiple_of(4096));
            blocks.push(block);
        }
        assert!(blocks.len() > 8);
        // Interleave holes to exercise coalescing on both sides.
        for block in blocks.iter().step_by(2) {
            heap.dealloc(*block, layout);
        }
        for block in blocks.iter().skip(1).step_by(2) {
            heap.dealloc(*block, layout);
        }
    }
    let usage = heap.usage();
    assert_eq!(usage.live, 0);
    assert_eq!(usage.carved, 0);
    assert_eq!(usage.largest, ram.0.len());
    assert!(usage.peak > 0);
}

#[test]
fn size_class_reuse_preserves_other_live_bytes() {
    let heap = Heap::new();
    let mut ram = backing();
    let layout = Layout::from_size_align(17, 16).unwrap();
    // SAFETY: `ram` is this test's own backing, handed to the heap once and outliving every
    // block.
    unsafe {
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        let a = heap.alloc(layout);
        let b = heap.alloc(layout);
        assert!(!a.is_null() && !b.is_null() && a != b);
        b.write_bytes(0x5a, layout.size());
        heap.dealloc(a, layout);
        let reused = heap.alloc(layout);
        assert_eq!(reused, a);
        reused.write_bytes(0xa5, layout.size());
        assert!(
            core::slice::from_raw_parts(b, layout.size())
                .iter()
                .all(|v| *v == 0x5a)
        );
        heap.dealloc(reused, layout);
        heap.dealloc(b, layout);
    }
    assert_eq!(heap.usage().live, 0);
}

#[test]
fn constrained_pages_use_real_cpu_interval_and_exact_payload_end() {
    let heap = Heap::new();
    let mut ram = backing();
    let base = ram.0.as_mut_ptr() as usize;
    let page = Layout::from_size_align(PAGE_BYTES, PAGE_BYTES).unwrap();
    // SAFETY: this dedicated real RAM stays live through exact deallocation.
    unsafe {
        assert!(
            heap.alloc_pages_zeroed_in(page, base..base + ram.0.len())
                .is_null()
        );
        heap.initialize(base as *mut u8, ram.0.len());
        let window = base + 7 * PAGE_BYTES..base + 8 * PAGE_BYTES;
        let block = heap.alloc_pages_zeroed_in(page, window.clone());
        assert_eq!(block as usize, window.start);
        assert_eq!(block as usize + page.size(), window.end);
        assert!(
            core::slice::from_raw_parts(block, page.size())
                .iter()
                .all(|byte| *byte == 0)
        );
        block.write_bytes(0xa5, page.size());
        assert_eq!(heap.usage().live, page.size());
        heap.dealloc(block, page);
        let again = heap.alloc_pages_zeroed_in(page, window);
        assert_eq!(again, block);
        assert!(
            core::slice::from_raw_parts(again, page.size())
                .iter()
                .all(|byte| *byte == 0)
        );
        heap.dealloc(again, page);
    }
    let usage = heap.usage();
    assert_eq!(usage.live, 0);
    assert_eq!(usage.carved, 0);
    assert_eq!(usage.largest, ram.0.len());
}

#[test]
fn constrained_failure_preserves_all_free_bytes_and_accounting() {
    let heap = Heap::new();
    let mut ram = backing();
    let base = ram.0.as_mut_ptr() as usize;
    // SAFETY: fresh exclusive model RAM; no users before initialization.
    unsafe { heap.initialize(base as *mut u8, ram.0.len()) };
    let page = Layout::from_size_align(PAGE_BYTES, PAGE_BYTES).unwrap();
    let end = base + ram.0.len();
    for (layout, allowed) in [
        (page, base..base),
        (page, end..base),
        (page, base..base + PAGE_BYTES), // no space for canonical Header
        (page, base + PAGE_BYTES..base + 2 * PAGE_BYTES - 1),
        (page, base + PAGE_BYTES + 1..base + 2 * PAGE_BYTES),
        (page, end..end + PAGE_BYTES),
        (Layout::from_size_align(0, PAGE_BYTES).unwrap(), base..end),
        (
            Layout::from_size_align(PAGE_BYTES - 1, PAGE_BYTES).unwrap(),
            base..end,
        ),
        (Layout::from_size_align(PAGE_BYTES, 16).unwrap(), base..end),
    ] {
        let image = ram.0.to_vec();
        let before = heap.usage();
        // SAFETY: valid layout, kept real heap, no other consumers.
        let block = unsafe { heap.alloc_pages_zeroed_in(layout, allowed) };
        assert!(block.is_null());
        assert_eq!(ram.0.as_slice(), image.as_slice());
        let after = heap.usage();
        assert_eq!(
            (after.live, after.carved, after.peak, after.largest),
            (before.live, before.carved, before.peak, before.largest)
        );
    }
}

/// A remainder too small for any block stays in the allocation instead
/// of becoming a free extent that every later walk passes.
#[test]
fn remainders_too_small_for_a_block_stay_allocated() {
    let heap = Heap::new();
    let mut ram = backing();
    let header = core::mem::size_of::<Header>();
    let layout = Layout::from_size_align(ram.0.len() - header - 24, WORD).unwrap();
    // SAFETY: the one payload is freed with its layout before `ram` goes.
    unsafe {
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        let block = heap.alloc(layout);
        assert!(!block.is_null());
        assert_eq!(heap.usage().carved, ram.0.len());
        heap.dealloc(block, layout);
    }
    assert_eq!(heap.usage().carved, 0);
    assert_eq!(heap.usage().largest, ram.0.len());
}

#[test]
fn fragmented_selection_skips_earlier_extents_and_preserves_other_owners() {
    let heap = Heap::new();
    let mut ram = backing();
    let base = ram.0.as_mut_ptr() as usize;
    let page = Layout::from_size_align(PAGE_BYTES, PAGE_BYTES).unwrap();
    let small = Layout::from_size_align(17, 16).unwrap();
    // SAFETY: each raw payload is held until its exact deallocation;
    // no slice or device alias exists while the heap mutates its metadata.
    unsafe {
        heap.initialize(base as *mut u8, ram.0.len());
        let a = heap.alloc(page);
        let b = heap.alloc(page);
        let c = heap.alloc(page);
        assert!(!a.is_null() && !b.is_null() && !c.is_null());
        b.write_bytes(0x39, page.size());
        heap.dealloc(a, page);
        heap.dealloc(c, page);
        // An earlier free extent is large enough but outside this request.
        let chosen = heap.alloc_pages_zeroed_in(page, c as usize..c as usize + PAGE_BYTES);
        assert_eq!(chosen, c);
        let metadata = heap.alloc(small);
        assert!(!metadata.is_null());
        metadata.write_bytes(0x6e, small.size());
        assert!(
            core::slice::from_raw_parts(b, page.size())
                .iter()
                .all(|byte| *byte == 0x39)
        );
        heap.dealloc(chosen, page);
        assert!(
            core::slice::from_raw_parts(metadata, small.size())
                .iter()
                .all(|byte| *byte == 0x6e)
        );
        heap.dealloc(metadata, small);
        heap.dealloc(b, page);
    }
    // The ordinary small-object cache keeps its own block, as before.
    assert_eq!(heap.usage().live, 0);
    assert!(heap.usage().carved < 2 * PAGE_BYTES);
}

#[test]
fn constrained_alignment_and_ordinary_pages_coalesce_together() {
    let heap = Heap::new();
    let mut ram = backing();
    let base = ram.0.as_mut_ptr() as usize;
    let ordinary = Layout::from_size_align(PAGE_BYTES, PAGE_BYTES).unwrap();
    // SAFETY: exclusive fixed test RAM and stopped payload consumers.
    unsafe {
        heap.initialize(base as *mut u8, ram.0.len());
        for alignment in [PAGE_BYTES, 2 * PAGE_BYTES, 4 * PAGE_BYTES, 8 * PAGE_BYTES] {
            let layout = Layout::from_size_align(3 * PAGE_BYTES, alignment).unwrap();
            let other = heap.alloc(ordinary);
            assert!(!other.is_null());
            other.write_bytes(0x7c, ordinary.size());
            let block =
                heap.alloc_pages_zeroed_in(layout, base + PAGE_BYTES + 7..base + ram.0.len());
            assert!(!block.is_null() && (block as usize).is_multiple_of(alignment));
            assert!(block as usize + layout.size() <= base + ram.0.len());
            assert!(
                core::slice::from_raw_parts(other, ordinary.size())
                    .iter()
                    .all(|byte| *byte == 0x7c)
            );
            heap.dealloc(other, ordinary);
            heap.dealloc(block, layout);
            assert_eq!(heap.usage().live, 0);
            assert_eq!(heap.usage().carved, 0);
            assert_eq!(heap.usage().largest, ram.0.len());
        }
    }
}

#[test]
fn core_caches_move_blocks_between_cores_in_batches() {
    let heap = Heap::new();
    let mut ram = backing();
    let layout = Layout::from_size_align(24, 8).unwrap();
    let class = class(layout).unwrap();
    heap.tagged.store(2, Ordering::Relaxed);
    // SAFETY: exclusive test backing; no interrupts reach these calls,
    // and every block goes back to a cache of its class.
    unsafe {
        heap.initialize(ram.0.as_mut_ptr(), ram.0.len());
        let blocks: Vec<_> = (0..CACHED + BATCH)
            .map(|_| heap.take_cached(0, class))
            .collect();
        assert!(blocks.iter().all(|block| !block.is_null()));
        let mut distinct = blocks.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), blocks.len());
        assert_eq!(heap.usage().live, blocks.len() * 32);
        // Freed on another core than allocated them: its cache fills
        // and moves a batch to the class list.
        for &block in &blocks {
            heap.give_cached(1, class, block);
        }
        assert_eq!(heap.usage().live, 0);
        assert_eq!((*heap.caches[1].get()).counts[class], CACHED);
        // The other core's allocations reuse the blocks the list holds.
        let reused = heap.alloc(layout);
        assert!(blocks.contains(&reused));
        heap.dealloc(reused, layout);
    }
    assert_eq!(heap.usage().live, 0);
}

#[test]
fn concurrent_allocations_preserve_data_and_reclaim_live_bytes() {
    let heap = Heap::new();
    let mut ram = backing();
    // SAFETY: `ram` is this test's own backing, handed to the heap once and outliving every
    // block.
    unsafe { heap.initialize(ram.0.as_mut_ptr(), ram.0.len()) };
    let barrier = Barrier::new(8);
    thread::scope(|scope| {
        for id in 1..=8 {
            let heap = &heap;
            let barrier = &barrier;
            scope.spawn(move || {
                let layout = Layout::from_size_align(257, 64).unwrap();
                for _ in 0..64 {
                    // SAFETY: `ram` is this test's own backing, handed to the heap once and
                    // outliving every block.
                    unsafe {
                        let block = heap.alloc(layout);
                        assert!(!block.is_null() && (block as usize).is_multiple_of(64));
                        block.write_bytes(id, layout.size());
                        barrier.wait();
                        assert!(
                            core::slice::from_raw_parts(block, layout.size())
                                .iter()
                                .all(|byte| *byte == id)
                        );
                        heap.dealloc(block, layout);
                    }
                }
            });
        }
    });
    assert_eq!(heap.usage().live, 0);
    assert_eq!(heap.usage().carved, 0);
    assert_eq!(heap.usage().largest, ram.0.len());
}
