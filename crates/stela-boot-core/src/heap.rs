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
// Explicit, so the NVIDIA LUT fixture can compile this file by path.
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
    /// Where the first failed allocation is reported; it must not allocate.
    failure_sink: fn(core::fmt::Arguments<'_>),
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
impl Default for Heap {
    fn default() -> Self {
        Self::new()
    }
}

impl Heap {
    /// Report the first failed allocation to `sink`, which must neither
    /// allocate nor wait (the mount's serial port).
    pub const fn reporting_failures(self, sink: fn(core::fmt::Arguments<'_>)) -> Self {
        Self {
            failure_sink: sink,
            ..self
        }
    }

    pub const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            failure_reported: AtomicBool::new(false),
            failure_sink: |_| {},
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
    /// The caller preserves the initialized heap's RAM/mapping/owner
    /// lifetime and exclusively owns a successful payload until its one matching
    /// `GlobalAlloc::dealloc` on this same heap with this exact layout. NMI/fault
    /// handlers do not reenter the heap. No physical/page/DMA permission follows.
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
        // SAFETY: this guard exclusively protects the heap state. The
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
        // SAFETY: the caller keeps the same heap, mapping and exact layout.
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
    /// keeps its RAM/mapping/root epoch, and owns the returned payload
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
        // SAFETY: acquire/release exclusion, as for ordinary allocation.
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
        unsafe { crate::msr::TSC_AUX.write(u64::from(TAG | cpu as u32)) };
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
            // SAFETY: the guard excludes all free-list writers, while
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
            // SAFETY: the guard excludes all free-list writers, while
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
        // SAFETY: the guard excludes metadata writers throughout
        // this free-list walk; no state reference escapes the guard.
        let state = unsafe { &*self.state.get() };
        self.usage_locked(state)
    }

    // The caller keeps the metadata guard; CPU cache counters remain
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
/// The heap's guard exclusively owns `state`. Initialization is checked
/// before backing access; successful allocations keep their original layout.
unsafe fn allocate_locked(state: &mut State, layout: Layout) -> *mut u8 {
    if !state.ready {
        return ptr::null_mut();
    }
    let Some(class) = class(layout) else {
        // SAFETY: this helper keeps the initialized state guard and
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
            if block.is_null() {
                failure::report(self, layout);
            }
            return block;
        }
        let block = {
            let _guard = self.lock();
            // SAFETY: the guard excludes all free-list writers, while
            // CPU-local cache ownership is already exclusive to this core.
            let state = unsafe { &mut *self.state.get() };
            // SAFETY: the guard owns this state for the entire operation.
            unsafe { allocate_locked(state, layout) }
        };
        if !block.is_null() {
            self.count_own(class(layout).map_or(layout.size(), |class| SMALLEST << class) as isize);
        }
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
            // SAFETY: GlobalAlloc requires this live allocation and
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
        // SAFETY: link is State.first or a next field in its free
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
        // SAFETY: complete payload/header fit, locked free-list owner.
        return unsafe { publish_carve(state, link, node, end, user, used_end) };
    }
}

/// Publish one fully checked selection. Ordinary and constrained allocations
/// share exactly this header, split and accounting operation.
///
/// # Safety
/// Heap lock held. `link` names `node` in the free list; `end` is that
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
    // SAFETY: caller keeps this free node and link under the guard;
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
        // SAFETY: the original aligned node owns this prefix, large
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

// Explicit for the same reason as `failure`.
#[cfg(test)]
#[path = "heap/tests.rs"]
mod tests;
