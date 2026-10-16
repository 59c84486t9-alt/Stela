//! Boot heap. Each allocation records its full extent, including alignment gaps,
//! so deallocation can coalesce the original physical range.
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
struct State {
    first: *mut Free,
    ready: bool,
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
                ready: false,
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
        let minimum = core::mem::size_of::<Free>();
        let header = core::mem::size_of::<Header>();
        let alignment = layout.align().max(WORD);
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
            let Some(mut used_end) = user
                .checked_add(layout.size().max(1))
                .and_then(|v| aligned(v, WORD))
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
            return user as *mut u8;
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        let _guard = self.lock();
        let state = unsafe { &mut *self.state.get() };
        // SAFETY: exact pointer from alloc; the caller has ended all accesses.
        let header =
            unsafe { (pointer.sub(core::mem::size_of::<Header>()) as *const Header).read() };
        let base = header.base;
        let end = base + header.bytes;
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
}
