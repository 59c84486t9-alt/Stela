//! Boot heap. Each allocation records its full extent, including alignment gaps,
//! so deallocation can coalesce the original physical range.
//!
//! The address-ordered free list costs a walk per allocation and release, and
//! the system engine allocates and frees small blocks constantly. Blocks of up
//! to 4 KiB with at most 16-byte alignment are therefore rounded up to a
//! power-of-two size class and, once freed, kept on that class's LIFO list
//! for the next allocation of the class instead of returning to the free list.
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    marker::PhantomData,
    ops::Range,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
const WORD: usize = core::mem::align_of::<usize>();
const PAGE_BYTES: usize = 4096;
#[repr(C)]
struct Free {
    bytes: usize,
    next: *mut Free,
}
#[repr(C)]
struct Header {
    base: usize,
    bytes: usize,
}
/// A freed size-class block, linked through its first word.
struct Small {
    next: *mut Small,
}
const SMALLEST: usize = 16;
const CLASSES: usize = 9;
const SMALL_ALIGNMENT: usize = 16;
/// The size class of `layout`, or `None` for the free list.
fn class(layout: Layout) -> Option<usize> {
    let bytes = layout.size().max(SMALLEST).next_power_of_two();
    (layout.align() <= SMALL_ALIGNMENT && bytes <= SMALLEST << (CLASSES - 1))
        .then(|| (bytes / SMALLEST).trailing_zeros() as usize)
}
struct State {
    first: *mut Free,
    small: [*mut Small; CLASSES],
    ready: bool,
    total: usize,
    /// Bytes allocated and not freed, size-class blocks by their class.
    live: usize,
    /// Bytes carved from the free list and not released: live blocks and
    /// the size-class blocks kept for reuse.
    carved: usize,
    peak: usize,
}

/// How full the heap is, in bytes.
#[derive(Clone, Copy, Debug)]
pub struct Usage {
    pub total: usize,
    pub live: usize,
    pub carved: usize,
    pub peak: usize,
    /// The largest free extent: the most one allocation can get.
    pub largest: usize,
}
pub struct Heap {
    held: AtomicBool,
    state: UnsafeCell<State>,
}
// SAFETY: all list/header mutations use the real acquire/release exclusion.
// UEFI callers mask local interrupts before acquiring the lock. Critical
// sections cannot migrate/block; NMI and fault handlers never reenter the heap.
unsafe impl Sync for Heap {}
impl Heap {
    pub const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            state: UnsafeCell::new(State {
                first: ptr::null_mut(),
                small: [ptr::null_mut(); CLASSES],
                ready: false,
                total: 0,
                live: 0,
                carved: 0,
                peak: 0,
            }),
        }
    }
    fn lock(&self) -> Guard<'_> {
        // Save before spinning: an ISR must not wait for its interrupted
        // context to release this same lock. No state access crosses the asm.
        #[cfg(target_os = "uefi")]
        let flags: usize;
        #[cfg(target_os = "uefi")]
        unsafe {
            core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard {
            heap: self,
            #[cfg(target_os = "uefi")]
            flags,
            same_cpu: PhantomData,
        }
    }
    /// # Safety
    /// The entire aligned extent is live RW+NX boot-private Normal-WB RAM, has
    /// no aliases/references/other owners, and remains reserved for the boot.
    /// Called exactly once before any Rust allocation with reentry excluded.
    pub unsafe fn initialize(&self, base: *mut u8, bytes: usize) {
        let _guard = self.lock();
        let state = unsafe { &mut *self.state.get() };
        assert!(!state.ready && !base.is_null() && (base as usize).is_multiple_of(WORD));
        assert!(bytes >= core::mem::size_of::<Free>() && bytes.is_multiple_of(WORD));
        let node = base.cast::<Free>();
        unsafe {
            node.write(Free {
                bytes,
                next: ptr::null_mut(),
            });
        }
        state.first = node;
        state.ready = true;
        state.total = bytes;
    }

    /// Select whole, zeroed pages inside a CPU interval from this same heap.
    /// No reservation or CPU-to-physical relationship is inferred here.
    /// Invalid geometry and exhaustion change no free-list bytes/accounting.
    /// Returned pointers use ordinary `GlobalAlloc::dealloc` and their original
    /// layout; page alignment excludes the small-object size-class route.
    ///
    /// # Safety
    /// The caller obeys the initialized heap's allocation/exclusion contract,
    /// retains its actual RAM/mapping/root epoch, and owns the returned payload
    /// exclusively until exact-layout deallocation. `allowed` constrains payload
    /// bytes only; the canonical allocation header remains private heap metadata.
    pub unsafe fn alloc_pages_zeroed_in(&self, layout: Layout, allowed: Range<usize>) -> *mut u8 {
        if layout.size() == 0
            || !layout.size().is_multiple_of(PAGE_BYTES)
            || layout.align() < PAGE_BYTES
            || allowed
                .end
                .checked_sub(allowed.start)
                .is_none_or(|bytes| bytes < layout.size())
        {
            return ptr::null_mut();
        }
        let guard = self.lock();
        // SAFETY: actual acquire/release exclusion, as for ordinary allocation.
        let state = unsafe { &mut *self.state.get() };
        if !state.ready {
            return ptr::null_mut();
        }
        // SAFETY: lock held; selection changes nothing until a complete fit.
        let block = unsafe { carve_within(state, layout.size(), layout.align(), allowed) };
        if !block.is_null() {
            state.live += layout.size();
        }
        // No metadata/state borrow survives zeroing or a possible IRQ restore.
        drop(guard);
        if !block.is_null() {
            // SAFETY: the selected full payload is exclusively owned and live.
            unsafe { block.write_bytes(0, layout.size()) };
        }
        block
    }

    /// Whether more than three quarters of the heap is allocated.
    pub fn low(&self) -> bool {
        let _guard = self.lock();
        let state = unsafe { &*self.state.get() };
        state.live > state.total / 4 * 3
    }

    /// The heap's usage, walking the free list for its largest extent.
    pub fn usage(&self) -> Usage {
        let _guard = self.lock();
        let state = unsafe { &*self.state.get() };
        let mut largest = 0;
        let mut node = state.first;
        while !node.is_null() {
            // SAFETY: a free-list node, read with the lock held.
            unsafe {
                largest = largest.max((*node).bytes);
                node = (*node).next;
            }
        }
        Usage {
            total: state.total,
            live: state.live,
            carved: state.carved,
            peak: state.peak,
            largest,
        }
    }
}
struct Guard<'a> {
    heap: &'a Heap,
    #[cfg(target_os = "uefi")]
    flags: usize,
    // A saved interrupt state belongs to the acquiring CPU, even though the
    // underlying heap may be shared. Do not make this guard Send or Sync.
    same_cpu: PhantomData<*mut ()>,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.heap.held.store(false, Ordering::Release);
        #[cfg(target_os = "uefi")]
        // SAFETY: this CPU's saved flags; the guard cannot migrate and no
        // lock/state access spans restoration. An incoming clear IF stays clear.
        unsafe {
            core::arch::asm!("push {}", "popfq", in(reg) self.flags);
        }
    }
}
fn aligned(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}
// SAFETY: callers follow the GlobalAlloc contract. The free-list split returns
// a disjoint aligned extent, and its header records the original bytes until
// the single matching deallocation.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = self.lock();
        let state = unsafe { &mut *self.state.get() };
        if !state.ready {
            return ptr::null_mut();
        }
        let Some(class) = class(layout) else {
            let block = unsafe { carve(state, layout.size(), layout.align()) };
            if !block.is_null() {
                state.live += layout.size();
            }
            return block;
        };
        let head = state.small[class];
        let block = if head.is_null() {
            unsafe { carve(state, SMALLEST << class, SMALL_ALIGNMENT) }
        } else {
            // SAFETY: a block of this class that `dealloc` linked and
            // nothing else owns.
            state.small[class] = unsafe { (*head).next };
            head.cast()
        };
        if !block.is_null() {
            state.live += SMALLEST << class;
        }
        block
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _guard = self.lock();
        let state = unsafe { &mut *self.state.get() };
        if let Some(class) = class(layout) {
            state.live -= SMALLEST << class;
            let block = pointer.cast::<Small>();
            // SAFETY: the caller's block of this class, at least 16 bytes
            // and 16-byte aligned, which it no longer accesses.
            unsafe {
                block.write(Small {
                    next: state.small[class],
                })
            };
            state.small[class] = block;
        } else {
            state.live -= layout.size();
            unsafe { release(state, pointer) };
        }
    }
}

/// Split `size` bytes aligned to `alignment` from the free list.
///
/// # Safety
/// The heap's lock is held and `state` is initialized.
unsafe fn carve(state: &mut State, size: usize, alignment: usize) -> *mut u8 {
    let header = core::mem::size_of::<Header>();
    let alignment = alignment.max(WORD);
    let mut link = &mut state.first as *mut *mut Free;
    loop {
        let node = unsafe { *link };
        if node.is_null() {
            return ptr::null_mut();
        }
        let base = node as usize;
        let Some(end) = base.checked_add(unsafe { (*node).bytes }) else {
            return ptr::null_mut();
        };
        let Some(user) = base.checked_add(header).and_then(|v| aligned(v, alignment)) else {
            return ptr::null_mut();
        };
        let Some(used_end) = user.checked_add(size.max(1)).and_then(|v| aligned(v, WORD)) else {
            return ptr::null_mut();
        };
        if used_end > end {
            link = unsafe { &mut (*node).next };
            continue;
        }
        // SAFETY: the original selection proved a complete aligned fit.
        return unsafe { publish_carve(state, link, node, end, user, used_end) };
    }
}

/// Page selection over the same address-ordered free extents. All candidate
/// arithmetic precedes publication, including skipped fragmented extents.
///
/// # Safety
/// Heap lock held; nonzero page-sized payload and at least page alignment.
unsafe fn carve_within(
    state: &mut State,
    size: usize,
    alignment: usize,
    allowed: Range<usize>,
) -> *mut u8 {
    let header = core::mem::size_of::<Header>();
    let mut link = &mut state.first as *mut *mut Free;
    loop {
        // SAFETY: the lock protects the original live free-list links.
        let node = unsafe { *link };
        if node.is_null() {
            return ptr::null_mut();
        }
        let base = node as usize;
        let Some(end) = base.checked_add(unsafe { (*node).bytes }) else {
            return ptr::null_mut();
        };
        let Some(user) = base
            .checked_add(header)
            .map(|start| start.max(allowed.start))
            .and_then(|start| aligned(start, alignment))
        else {
            return ptr::null_mut();
        };
        let Some(used_end) = user.checked_add(size) else {
            return ptr::null_mut();
        };
        if used_end > allowed.end {
            // Later free extents cannot start at a smaller CPU address.
            return ptr::null_mut();
        }
        if used_end > end {
            link = unsafe { &mut (*node).next };
            continue;
        }
        // Page-sized/aligned requests already end on WORD alignment.
        // SAFETY: complete payload/header fit, actual locked free-list owner.
        return unsafe { publish_carve(state, link, node, end, user, used_end) };
    }
}

/// Publish one fully checked selection. Ordinary and constrained allocations
/// share exactly this header, split and accounting operation.
///
/// # Safety
/// Heap lock held. `link` names `node` in the actual free list; `end` is that
/// node's end, and aligned `[user, used_end)` plus the preceding Header fit
/// inside it. No pointer or state reference escapes the owning exclusion.
#[inline(always)]
unsafe fn publish_carve(
    state: &mut State,
    link: *mut *mut Free,
    node: *mut Free,
    end: usize,
    user: usize,
    mut used_end: usize,
) -> *mut u8 {
    let base = node as usize;
    let minimum = core::mem::size_of::<Free>();
    let header_base = user - core::mem::size_of::<Header>();
    let prefix = header_base - base;
    let allocated_base = if prefix >= minimum { header_base } else { base };
    if end - used_end < minimum {
        used_end = end;
    }
    let next = unsafe { (*node).next };
    let suffix = if used_end < end {
        let suffix = used_end as *mut Free;
        unsafe {
            suffix.write(Free {
                bytes: end - used_end,
                next,
            });
        }
        suffix
    } else {
        next
    };
    if prefix >= minimum {
        unsafe {
            node.write(Free {
                bytes: prefix,
                next: suffix,
            });
        }
    } else {
        unsafe {
            *link = suffix;
        }
    }
    unsafe {
        (header_base as *mut Header).write(Header {
            base: allocated_base,
            bytes: used_end - allocated_base,
        });
    }
    state.carved += used_end - allocated_base;
    state.peak = state.peak.max(state.carved);
    user as *mut u8
}

/// Return the extent of a block `carve` made to the free list, coalescing it
/// with its neighbours.
///
/// # Safety
/// The heap's lock is held, and `pointer` came from `carve` and is no longer
/// accessed.
unsafe fn release(state: &mut State, pointer: *mut u8) {
    // SAFETY: exact pointer from alloc; the caller has ended all accesses.
    let header = unsafe { (pointer.sub(core::mem::size_of::<Header>()) as *const Header).read() };
    let base = header.base;
    let end = base + header.bytes;
    state.carved -= header.bytes;
    let mut previous: *mut Free = ptr::null_mut();
    let mut next = state.first;
    while !next.is_null() && (next as usize) < base {
        previous = next;
        next = unsafe { (*next).next };
    }
    let node = base as *mut Free;
    unsafe {
        node.write(Free {
            bytes: header.bytes,
            next,
        });
    }
    if !next.is_null() && end == next as usize {
        unsafe {
            (*node).bytes += (*next).bytes;
            (*node).next = (*next).next;
        }
    }
    if previous.is_null() {
        state.first = node;
    } else if previous as usize + unsafe { (*previous).bytes } == base {
        unsafe {
            (*previous).bytes += (*node).bytes;
            (*previous).next = (*node).next;
        }
    } else {
        unsafe {
            (*previous).next = node;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{boxed::Box, sync::Barrier, thread};

    #[repr(align(4096))]
    struct Ram([u8; 128 * 1024]);

    fn backing() -> Box<Ram> {
        Box::new(Ram([0; 128 * 1024]))
    }

    #[test]
    fn aligned_extents_coalesce_after_exhaustion() {
        let heap = Heap::new();
        let mut ram = backing();
        let layout = Layout::from_size_align(4097, 4096).unwrap();
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
            // SAFETY: valid layout, retained real heap, no other consumers.
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

    #[test]
    fn fragmented_selection_skips_earlier_extents_and_preserves_other_owners() {
        let heap = Heap::new();
        let mut ram = backing();
        let base = ram.0.as_mut_ptr() as usize;
        let page = Layout::from_size_align(PAGE_BYTES, PAGE_BYTES).unwrap();
        let small = Layout::from_size_align(17, 16).unwrap();
        // SAFETY: each raw payload is retained until its exact deallocation;
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
        // The ordinary small-object cache retains its own block, as before.
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
    fn concurrent_allocations_preserve_data_and_reclaim_live_bytes() {
        let heap = Heap::new();
        let mut ram = backing();
        unsafe { heap.initialize(ram.0.as_mut_ptr(), ram.0.len()) };
        let barrier = Barrier::new(8);
        thread::scope(|scope| {
            for id in 1..=8 {
                let heap = &heap;
                let barrier = &barrier;
                scope.spawn(move || {
                    let layout = Layout::from_size_align(257, 64).unwrap();
                    for _ in 0..64 {
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
}
