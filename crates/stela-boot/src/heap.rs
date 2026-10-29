//! Boot heap. Each allocation records its full extent, including alignment gaps,
//! so deallocation can coalesce the original physical range.
//!
//! The address-ordered free list costs a walk per allocation and release, and
//! the system engine allocates and frees small blocks constantly. Blocks of up
//! to 4 KiB with at most 16-byte alignment are therefore rounded up to a
//! power-of-two size class and, once freed, kept on that class's LIFO list
//! for the next allocation of the class instead of returning to the free list.
//!
//! Every PE on a core of its own allocates at once, so each core the engine
//! runs on keeps a small cache of free blocks per class ([`Heap::tag_cpu`]),
//! which it takes from and gives back to without the lock, moving them to
//! and from the class lists [`BATCH`] at a time under it.
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    marker::PhantomData,
    ops::Range,
    ptr,
    sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering},
};
#[path = "heap/failure.rs"]
mod failure;

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
/// Cores with a cache of their own; later ones take the lock every time.
const CPUS: usize = 64;
/// Free blocks a core keeps per class, and moves to or from the class list
/// at once.
const CACHED: usize = 64;
const BATCH: usize = 32;
/// What IA32_TSC_AUX holds, for RDTSCP to read: `TAG` and the core's cache
/// index.
const TAG: u32 = 0x5a7e_0000;

/// One core's free blocks by class.
struct Cache {
    blocks: [[*mut Small; CACHED]; CLASSES],
    counts: [usize; CLASSES],
}

impl Cache {
    const EMPTY: Self = Self {
        blocks: [[ptr::null_mut(); CACHED]; CLASSES],
        counts: [0; CLASSES],
    };
}
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
    failure_reported: AtomicBool,
    state: UnsafeCell<State>,
    caches: [UnsafeCell<Cache>; CPUS],
    /// Each core's bytes allocated from its cache less those freed to it,
    /// which [`State::live`] does not count; written by that core alone.
    cached: [AtomicIsize; CPUS],
    /// Each core's bytes allocated less those it freed, by every route:
    /// what its own work holds, which other cores' allocations leave
    /// alone; written by that core alone.
    own: [AtomicIsize; CPUS],
    /// Cores tagged so far, and whether any is.
    tagged: AtomicUsize,
    any_tagged: AtomicBool,
    /// `State::live` and `State::total` as the lock last left them, for
    /// [`Heap::low`] to read without taking it.
    live: AtomicUsize,
    total: AtomicUsize,
    waits: AtomicU64,
}
// SAFETY: all list/header mutations use the real acquire/release exclusion.
// UEFI callers mask local interrupts before acquiring the lock. Critical
// sections cannot migrate/block; NMI and fault handlers never reenter the heap.
unsafe impl Sync for Heap {}
impl Heap {
    pub const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            failure_reported: AtomicBool::new(false),
            caches: [const { UnsafeCell::new(Cache::EMPTY) }; CPUS],
            cached: [const { AtomicIsize::new(0) }; CPUS],
            own: [const { AtomicIsize::new(0) }; CPUS],
            tagged: AtomicUsize::new(0),
            any_tagged: AtomicBool::new(false),
            live: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            waits: AtomicU64::new(0),
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
        // SAFETY: the UEFI allocator executes at CPL0 on this CPU; save IF
        // before masking reentry, with no state borrow spanning restoration.
        unsafe {
            core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.waits.fetch_add(1, Ordering::Relaxed);
            while self
                .held
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
        }
        Guard {
            heap: self,
            #[cfg(target_os = "uefi")]
            flags,
            same_cpu: PhantomData,
        }
    }
    fn try_lock(&self) -> Option<Guard<'_>> {
        // Mask before the single attempt, as for the blocking owner. An ISR
        // cannot safely wait on its interrupted context's allocator lock.
        #[cfg(target_os = "uefi")]
        let flags: usize;
        #[cfg(target_os = "uefi")]
        // SAFETY: the UEFI allocator executes at CPL0 on this CPU; save IF
        // before masking reentry, with no state borrow spanning restoration.
        unsafe {
            core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            #[cfg(target_os = "uefi")]
            // SAFETY: no guard/state access was acquired. Restore this CPU's
            // exact incoming flags, including an already-clear interrupt flag.
            unsafe {
                core::arch::asm!("push {}", "popfq", in(reg) flags);
            }
            return None;
        }
        Some(Guard {
            heap: self,
            #[cfg(target_os = "uefi")]
            flags,
            same_cpu: PhantomData,
        })
    }
    /// # Safety
    /// The entire aligned extent is live RW+NX boot-private Normal-WB RAM, has
    /// no aliases/references/other owners, and remains reserved for the boot.
    /// Called exactly once before any Rust allocation with reentry excluded.
    pub unsafe fn initialize(&self, base: *mut u8, bytes: usize) {
        let _guard = self.lock();
        // SAFETY: this live acquire/release guard excludes every metadata
        // writer and masks local reentry until this state borrow ends.
        let state = unsafe { &mut *self.state.get() };
        assert!(!state.ready && !base.is_null() && (base as usize).is_multiple_of(WORD));
        assert!(bytes >= core::mem::size_of::<Free>() && bytes.is_multiple_of(WORD));
        let node = base.cast::<Free>();
        // SAFETY: initialize's exclusive live extent is aligned for Free and
        // the assertions above establish space for its complete first node.
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

    /// Attempt ordinary heap allocation without waiting for the heap lock.
    /// Zero-sized requests, an uninitialized heap, contention and exhaustion
    /// return NULL without changing heap bytes or accounting. Success uses the
    /// ordinary size-class/alignment/header rules and exact-layout deallocation.
    /// This makes one lock attempt; a successful free-list search is finite,
    /// but is not promised to take constant time.
    ///
    /// # Safety
    /// The caller preserves the initialized heap's actual RAM/mapping/owner
    /// lifetime and exclusively owns a successful payload until its one matching
    /// `GlobalAlloc::dealloc` on this same heap with this exact layout. NMI/fault
    /// handlers do not reenter the heap. No physical/page/DMA authority follows.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "reserved nonblocking entry for the retained Linux GPU heap registration"
        )
    )]
    pub unsafe fn try_allocate(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return ptr::null_mut();
        }
        let Some(guard) = self.try_lock() else {
            return ptr::null_mut();
        };
        // SAFETY: this actual guard exclusively protects the heap state. The
        // shared body checks initialization before accessing backing storage.
        let block = unsafe { allocate_locked(&mut *self.state.get(), layout) };
        drop(guard);
        block
    }

    /// Attempt allocation as in `try_allocate`, then zero the entire payload
    /// before returning it. Zeroing owns only the successful payload and takes
    /// place after releasing the metadata guard/restoring the incoming IRQ state.
    ///
    /// # Safety
    /// The complete `try_allocate` ownership and exclusion contract applies.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "zeroed counterpart of the reserved Linux GPU heap entry"
        )
    )]
    pub unsafe fn try_allocate_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller retains the same heap, mapping and exact layout.
        let block = unsafe { self.try_allocate(layout) };
        if !block.is_null() {
            // SAFETY: successful allocation gives this full payload exclusively.
            unsafe { block.write_bytes(0, layout.size()) };
        }
        block
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

    /// Whether more than three quarters of the heap is allocated, as the
    /// lock and each core's cache last left it.
    pub fn low(&self) -> bool {
        self.live() > self.total.load(Ordering::Relaxed) / 4 * 3
    }

    /// Bytes allocated and not freed: the class lists' and the caches'.
    fn live(&self) -> usize {
        self.live
            .load(Ordering::Relaxed)
            .saturating_add_signed(self.cached_live())
    }

    /// Bytes the caches allocated less those freed to them.
    fn cached_live(&self) -> isize {
        (0..self.tagged.load(Ordering::Relaxed).min(CPUS))
            .map(|cpu| self.cached[cpu].load(Ordering::Relaxed))
            .sum()
    }

    /// Give the calling core a cache of its own, which every later
    /// allocation on it uses. Once per core, where it RDTSCP reads
    /// IA32_TSC_AUX and no one else uses it.
    ///
    /// # Safety
    /// Ring 0, on a core that runs no other code using IA32_TSC_AUX.
    #[cfg(target_os = "uefi")]
    pub unsafe fn tag_cpu(&self) {
        // RDTSCP: CPUID 8000_0001h EDX bit 27.
        let highest = core::arch::x86_64::__cpuid(0x8000_0000).eax;
        if highest < 0x8000_0001 || core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 27) == 0 {
            return;
        }
        let cpu = self.tagged.fetch_add(1, Ordering::Relaxed);
        if cpu >= CPUS {
            return;
        }
        // SAFETY: as the caller guarantees.
        unsafe { crate::cpu::msr::TSC_AUX.write(u64::from(TAG | cpu as u32)) };
        self.any_tagged.store(true, Ordering::Release);
    }

    /// The calling core's cache, if it has one.
    fn cpu(&self) -> Option<usize> {
        if !self.any_tagged.load(Ordering::Relaxed) {
            return None;
        }
        #[cfg(not(target_os = "uefi"))]
        let aux = 0;
        #[cfg(target_os = "uefi")]
        let aux: u32;
        // SAFETY: RDTSCP exists, as some core was tagged.
        #[cfg(target_os = "uefi")]
        unsafe {
            core::arch::asm!("rdtscp", out("eax") _, out("edx") _, out("ecx") aux,
                options(nomem, nostack, preserves_flags));
        }
        (aux & !0xffff == TAG)
            .then_some((aux & 0xffff) as usize)
            .filter(|&cpu| cpu < CPUS)
    }

    /// A block of `class` from core `cpu`'s cache, refilled under the lock
    /// when empty; null when the heap has none.
    ///
    /// # Safety
    /// On core `cpu`, with interrupts disabled.
    unsafe fn take_cached(&self, cpu: usize, class: usize) -> *mut u8 {
        // SAFETY: only this core reaches its cache, and nothing interrupts.
        let cache = unsafe { &mut *self.caches[cpu].get() };
        if cache.counts[class] == 0 {
            let _guard = self.lock();
            // SAFETY: the actual guard excludes all free-list writers, while
            // CPU-local cache ownership is already exclusive to this core.
            let state = unsafe { &mut *self.state.get() };
            while cache.counts[class] < BATCH {
                let head = state.small[class];
                let block = if head.is_null() {
                    // SAFETY: the initialized heap is exclusively guarded;
                    // this class supplies its nonzero extent and alignment.
                    unsafe { carve(state, SMALLEST << class, SMALL_ALIGNMENT) }
                } else {
                    // SAFETY: the guarded class head is a complete free Small
                    // node previously published by matching deallocation.
                    state.small[class] = unsafe { (*head).next };
                    head.cast()
                };
                if block.is_null() {
                    break;
                }
                cache.blocks[class][cache.counts[class]] = block.cast();
                cache.counts[class] += 1;
            }
        }
        if cache.counts[class] == 0 {
            return ptr::null_mut();
        }
        cache.counts[class] -= 1;
        self.count_cached(cpu, (SMALLEST << class) as isize);
        cache.blocks[class][cache.counts[class]].cast()
    }

    /// Give `block` of `class` to core `cpu`'s cache, moving a batch to the
    /// class list under the lock when full.
    ///
    /// # Safety
    /// On core `cpu`, with interrupts disabled; `block` is a freed block of
    /// `class`.
    unsafe fn give_cached(&self, cpu: usize, class: usize, block: *mut u8) {
        // SAFETY: only this core reaches its cache, and nothing interrupts.
        let cache = unsafe { &mut *self.caches[cpu].get() };
        if cache.counts[class] == CACHED {
            let _guard = self.lock();
            // SAFETY: the actual guard excludes all free-list writers, while
            // CPU-local cache ownership is already exclusive to this core.
            let state = unsafe { &mut *self.state.get() };
            for _ in 0..BATCH {
                cache.counts[class] -= 1;
                let freed = cache.blocks[class][cache.counts[class]];
                // SAFETY: a free block of this class that only the cache held.
                unsafe {
                    freed.write(Small {
                        next: state.small[class],
                    })
                };
                state.small[class] = freed;
            }
        }
        cache.blocks[class][cache.counts[class]] = block.cast();
        cache.counts[class] += 1;
        self.count_cached(cpu, -((SMALLEST << class) as isize));
    }

    /// Add `bytes` to core `cpu`'s count, which only it writes.
    fn count_cached(&self, cpu: usize, bytes: isize) {
        let count = &self.cached[cpu];
        count.store(count.load(Ordering::Relaxed) + bytes, Ordering::Relaxed);
    }

    /// Acquisitions of the heap's lock that found it held: with every PE
    /// on a core of its own, the cores' allocations meet there.
    pub fn waits(&self) -> u64 {
        self.waits.load(Ordering::Relaxed)
    }

    /// The calling core's bytes allocated less those it freed, once it is
    /// tagged.
    pub fn own(&self) -> Option<isize> {
        self.cpu().map(|cpu| self.own[cpu].load(Ordering::Relaxed))
    }

    /// Add `bytes` to the calling core's own count, which only it writes.
    fn count_own(&self, bytes: isize) {
        if let Some(cpu) = self.cpu() {
            let count = &self.own[cpu];
            count.store(count.load(Ordering::Relaxed) + bytes, Ordering::Relaxed);
        }
    }

    /// The heap's usage, walking the free list for its largest extent.
    pub fn usage(&self) -> Usage {
        let _guard = self.lock();
        // SAFETY: the retained guard excludes metadata writers throughout
        // this free-list walk; no state reference escapes the guard.
        let state = unsafe { &*self.state.get() };
        self.usage_locked(state)
    }

    // The caller retains the actual metadata guard; CPU cache counters remain
    // relaxed estimates even while this free-list metadata is exclusively read.
    fn usage_locked(&self, state: &State) -> Usage {
        let mut largest = 0;
        let mut node = state.first;
        while !node.is_null() {
            // SAFETY: a free-list node, read with the lock held.
            unsafe {
                largest = largest.max((*node).bytes);
                node = (*node).next;
            }
        }
        let live = state.live.saturating_add_signed(self.cached_live());
        Usage {
            total: state.total,
            live,
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
        // SAFETY: the lock is still held; no other borrow of the state lives.
        let state = unsafe { &*self.heap.state.get() };
        self.heap.live.store(state.live, Ordering::Relaxed);
        self.heap.total.store(state.total, Ordering::Relaxed);
        self.heap.held.store(false, Ordering::Release);
        #[cfg(target_os = "uefi")]
        // SAFETY: this CPU's saved flags; the guard cannot migrate and no
        // lock/state access spans restoration. An incoming clear IF stays clear.
        unsafe {
            core::arch::asm!("push {}", "popfq", in(reg) self.flags);
        }
    }
}
/// Disable interrupts, returning RFLAGS before.
fn interrupts_off() -> usize {
    #[cfg(not(target_os = "uefi"))]
    let flags = 0;
    #[cfg(target_os = "uefi")]
    let flags: usize;
    // SAFETY: CPL0; changes only IF.
    #[cfg(target_os = "uefi")]
    unsafe {
        core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags)
    };
    flags
}

/// Restore RFLAGS' interrupt flag as [`interrupts_off`] found it.
fn restore_interrupts(flags: usize) {
    // SAFETY: this core's flags from `interrupts_off`.
    #[cfg(target_os = "uefi")]
    unsafe {
        core::arch::asm!("push {}", "popfq", in(reg) flags)
    };
    #[cfg(not(target_os = "uefi"))]
    let _ = flags;
}

fn aligned(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}
/// Ordinary and attempted allocation share the original locked algorithm.
///
/// # Safety
/// The heap's actual guard exclusively owns `state`. Initialization is checked
/// before backing access; successful allocations retain their original layout.
unsafe fn allocate_locked(state: &mut State, layout: Layout) -> *mut u8 {
    if !state.ready {
        return ptr::null_mut();
    }
    let Some(class) = class(layout) else {
        // SAFETY: this helper retains the actual initialized state guard and
        // GlobalAlloc's layout supplies the payload size and alignment.
        let block = unsafe { carve(state, layout.size(), layout.align()) };
        if !block.is_null() {
            state.live += layout.size();
        }
        return block;
    };
    let head = state.small[class];
    let block = if head.is_null() {
        // SAFETY: guarded initialized state and a validated nonzero class.
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

// SAFETY: callers follow the GlobalAlloc contract. The free-list split returns
// a disjoint aligned extent, and its header records the original bytes until
// the single matching deallocation.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(class) = class(layout)
            && let Some(cpu) = self.cpu()
        {
            let flags = interrupts_off();
            // SAFETY: on this core, with interrupts disabled.
            let block = unsafe { self.take_cached(cpu, class) };
            restore_interrupts(flags);
            if !block.is_null() {
                self.count_own((SMALLEST << class) as isize);
            }
            #[cfg(target_os = "uefi")]
            if block.is_null() {
                failure::report(self, layout);
            }
            return block;
        }
        let block = {
            let _guard = self.lock();
            // SAFETY: the actual guard excludes all free-list writers, while
            // CPU-local cache ownership is already exclusive to this core.
            let state = unsafe { &mut *self.state.get() };
            // SAFETY: the actual guard owns this state for the entire operation.
            unsafe { allocate_locked(state, layout) }
        };
        if !block.is_null() {
            self.count_own(class(layout).map_or(layout.size(), |class| SMALLEST << class) as isize);
        }
        #[cfg(target_os = "uefi")]
        if block.is_null() {
            failure::report(self, layout);
        }
        block
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        self.count_own(-(class(layout).map_or(layout.size(), |class| SMALLEST << class) as isize));
        if let Some(class) = class(layout)
            && let Some(cpu) = self.cpu()
        {
            let flags = interrupts_off();
            // SAFETY: on this core, with interrupts disabled; the caller's
            // block of this class, which it no longer accesses.
            unsafe { self.give_cached(cpu, class, pointer) };
            restore_interrupts(flags);
            return;
        }
        let _guard = self.lock();
        // SAFETY: this live acquire/release guard excludes every metadata
        // writer and masks local reentry until this state borrow ends.
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
            // SAFETY: GlobalAlloc requires this exact live allocation and
            // layout; its last owner has ended all payload access, lock held.
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
        // SAFETY: link is State.first or a next field in its retained free
        // node, protected against mutation by the same heap guard.
        let node = unsafe { *link };
        if node.is_null() {
            return ptr::null_mut();
        }
        let base = node as usize;
        // SAFETY: a nonnull live free node owned by this locked list; read
        // its initialized extent before any split/publication changes it.
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
            // SAFETY: the whole current node is still free and locked; its
            // next link remains live until the following iteration completes.
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
        // SAFETY: a nonnull live free node owned by this locked list; read
        // its initialized extent before any split/publication changes it.
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
            // SAFETY: the whole current node is still free and locked; its
            // next link remains live until the following iteration completes.
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
    // A gap smaller than a header and the smallest block could never be
    // carved, so it stays in the allocation rather than lengthening every
    // later walk.
    let minimum = core::mem::size_of::<Header>() + SMALLEST;
    let header_base = user - core::mem::size_of::<Header>();
    let prefix = header_base - base;
    let allocated_base = if prefix >= minimum { header_base } else { base };
    if end - used_end < minimum {
        used_end = end;
    }
    // SAFETY: caller retains this actual free node and link under the guard;
    // save the successor before splitting or overwriting the node.
    let next = unsafe { (*node).next };
    let suffix = if used_end < end {
        let suffix = used_end as *mut Free;
        // SAFETY: the checked fit leaves at least minimum bytes at this
        // WORD-aligned suffix, disjoint from payload and allocation header.
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
        // SAFETY: the original aligned node owns this retained prefix, large
        // enough for Free, disjoint from header/payload and suffix.
        unsafe {
            node.write(Free {
                bytes: prefix,
                next: suffix,
            });
        }
    } else {
        // SAFETY: link is the exclusively guarded predecessor/State.first;
        // replacing it removes the consumed original node from the list.
        unsafe {
            *link = suffix;
        }
    }
    // SAFETY: the caller proved this aligned Header lies inside the removed
    // extent immediately before the disjoint user payload; it stays private.
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
        // SAFETY: nonnull free-list nodes stay allocated and initialized
        // throughout the guarded walk; address order prevents aliasing payload.
        next = unsafe { (*next).next };
    }
    let node = base as *mut Free;
    // SAFETY: the exact allocation header returns its original WORD-aligned
    // extent; its owner ended all accesses and the extent can hold Free.
    unsafe {
        node.write(Free {
            bytes: header.bytes,
            next,
        });
    }
    if !next.is_null() && end == next as usize {
        // SAFETY: both guarded free nodes are contiguous and disjoint from
        // live payload; absorb the complete initialized successor once.
        unsafe {
            (*node).bytes += (*next).bytes;
            (*node).next = (*next).next;
        }
    }
    if previous.is_null() {
        state.first = node;
    // SAFETY: a nonnull predecessor is an initialized node in this guarded
    // address-ordered list; its extent is valid through this comparison.
    } else if previous as usize + unsafe { (*previous).bytes } == base {
        // SAFETY: contiguous guarded free extents; relink before the removed
        // node can be allocated again, with no references escaping this call.
        unsafe {
            (*previous).bytes += (*node).bytes;
            (*previous).next = (*node).next;
        }
    } else {
        // SAFETY: initialized guarded predecessor; the new free node lies
        // between it and its prior successor in the same owned heap extent.
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
        // SAFETY: exclusive test backing, retained through every exact free.
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
        // SAFETY: the existing guard retains exclusive metadata ownership;
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
        // The existing small-object cache still retains its own two blocks.
        assert!(heap.usage().carved > 0);
    }

    #[test]
    fn attempted_general_alignment_zeroing_and_ordinary_free_coalesce() {
        let heap = Heap::new();
        let mut ram = backing();
        // SAFETY: all disjoint payloads retain this exclusive backing/layout.
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
        // SAFETY: each raw allocation retains the same real backing and exact
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
    fn core_caches_refill_and_flush_in_batches_and_count_live_bytes() {
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
