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
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
const WORD: usize = core::mem::align_of::<usize>();
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
// The loader excludes interrupts, reentry, migration, other PEs and firmware.
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
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard(self)
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
struct Guard<'a>(&'a Heap);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
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
    let minimum = core::mem::size_of::<Free>();
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
        let Some(mut used_end) = user.checked_add(size.max(1)).and_then(|v| aligned(v, WORD))
        else {
            return ptr::null_mut();
        };
        if used_end > end {
            link = unsafe { &mut (*node).next };
            continue;
        }
        let header_base = user - header;
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
        return user as *mut u8;
    }
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
