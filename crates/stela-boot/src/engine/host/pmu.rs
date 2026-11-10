//! `--profile`'s hardware performance counters: the `PES PMU` heartbeat line.
//!
//! Each PE programs its core's counters once ([`start`]) to count in ring 0
//! and reads them with RDPMC at the step loop's phase charges
//! ([`stela_engine::machine::Host::profile_boundary`]): the counts since the
//! previous charge go to the charged phase, so the step loop's unattributed
//! time lands in the phase charged next. Shadow page-fault fills taken during
//! native runs are counted again apart (`fill`); `native` includes them.
//!
//! RDPMC may trap under a hypervisor. [`start`] times it, and reads take at
//! most 0.2% of a PE's time (`READ_SHARE`; the line prints the beat's
//! estimate as `overhead=`). A cheap read reads the counters around one
//! charged interval at most every `2 * READ_SHARE` read costs
//! (`method=interval:GKticks`); every interval's TSC ticks are kept, and the
//! line scales each phase's counts by its ticks over its sampled ticks. A
//! trapped read would bias short intervals (each starts with the cache and
//! predictor refill after the trap), so the core instead reads at most once
//! per window of 2 ms or more (`method=window`): the whole PE takes every
//! window, and a phase only the windows it held 90% of. Counter MSRs are written only
//! at [`start`] and when the event set rotates, once a beat: with more events
//! than counters the two fixed events (cycles, instructions) stay and the
//! others rotate in sets (`set=S/N`), each beat reporting the set it ran.
//!
//! Events: AMD families 19h and 1Ah (Zen 3 to 5) from the PPR for family 1Ah
//! (PMCx076 cycles not halted, PMCx0C0 retired instructions, PMCx0C3 retired
//! mispredicted branches, PMCx18E umask 18h instruction cache misses,
//! PMCx084 L1 ITLB miss L2 hit, PMCx085 umask 0Fh L2 ITLB miss (walk),
//! PMCx045 umask 0Fh / F0h L1 DTLB miss L2 hit / L2 miss (walk), PMCx064
//! umask 09h L2 misses of instruction and data requests, PMCx044 umask 48h
//! data fills from DRAM or I/O, the core PMU's last-level miss proxy: L3
//! misses proper are only in the L3 PMU). Other AMD families count cycles,
//! instructions and mispredicts. Intel counts the architectural events
//! CPUID leaf 0Ah reports (cycles, instructions, mispredicted branches, LLC
//! misses); the rest are unsupported there, said once.
use super::super::interrupts::Frame;
use crate::output;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::arch::{
    asm, global_asm,
    x86_64::{__cpuid, __cpuid_count},
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering::Relaxed};
use stela_engine::machine::engine::step_timing::Phase;

/// Counters this module uses at most.
const MAX_COUNTERS: usize = 6;
/// The step loop's phases, then shadow fills.
const BUCKETS: usize = Phase::COUNT + 1;
const FILL: usize = Phase::COUNT;
const BUCKET_NAMES: [&str; BUCKETS] = ["sch", "dev", "fetch", "nat", "exit", "fill"];
/// Report order: the phases that matter most first.
const REPORT_ORDER: [usize; BUCKETS] = [3, 5, 2, 4, 0, 1];
const MAX_SETS: usize = 4;
const MAX_CORES: usize = 256;
/// Reading the counters may take at most 1/READ_SHARE of a PE's time
/// (0.2%): a core reads the set again only READ_SHARE read costs after its
/// previous read. A trapped read (about 50 us under KVM) then allows one
/// read per 25 ms; a native one (tens of cycles) dense sampling.
const READ_SHARE: u64 = 500;
/// A read of the set dearer than this (RDPMC trapped by a hypervisor)
/// switches the core to windows: reading around short intervals would
/// measure the refill after each trap, not the interval.
const WINDOW_READ_TICKS: u64 = 2_000;
/// A window lasts at least this many ticks (about 2 ms at 3 GHz), and at
/// least READ_SHARE reads' cost. A tick count, not a time: the engine image
/// must not ask the firmware for the TSC rate (`firmware::tsc_hz` searches
/// firmware tables that the engine's roots do not map).
const WINDOW_TICKS: u64 = 6_000_000;
/// A window is credited to a bucket that holds at least this share of its
/// ticks, in tenths.
const DOMINANT_TENTHS: u64 = 9;

global_asm!(
    ".text",
    ".global stela_pmu_wrmsr",
    "stela_pmu_wrmsr:",
    "mov ecx, edi",
    "mov eax, esi",
    "mov rdx, rsi",
    "shr rdx, 32",
    ".global stela_pmu_wrmsr_instruction",
    "stela_pmu_wrmsr_instruction:",
    "wrmsr",
    "xor eax, eax",
    "ret",
    ".global stela_pmu_rdpmc",
    "stela_pmu_rdpmc:",
    "mov ecx, edi",
    ".global stela_pmu_rdpmc_instruction",
    "stela_pmu_rdpmc_instruction:",
    "rdpmc",
    "xor eax, eax",
    "ret",
    ".global stela_pmu_refused",
    "stela_pmu_refused:",
    "mov eax, 1",
    "ret",
);

unsafe extern "sysv64" {
    fn stela_pmu_wrmsr(index: u32, value: u64) -> u32;
    fn stela_pmu_rdpmc(counter: u32) -> u32;
    static stela_pmu_wrmsr_instruction: u8;
    static stela_pmu_rdpmc_instruction: u8;
    static stela_pmu_refused: u8;
}

/// Resume a #GP of the probing WRMSR or RDPMC at its refusal: the event or
/// counter is unsupported.
pub(crate) fn fixup(frame: &mut Frame) -> bool {
    let rip = frame.rip;
    if frame.vector != 13
        || frame.cs & 3 != 0
        || (rip != (&raw const stela_pmu_wrmsr_instruction).addr() as u64
            && rip != (&raw const stela_pmu_rdpmc_instruction).addr() as u64)
    {
        return false;
    }
    frame.rip = (&raw const stela_pmu_refused).addr() as u64;
    true
}

/// WRMSR that answers a #GP with `false`.
fn write(index: u32, value: u64) -> bool {
    // SAFETY: ring 0; a refused write takes #GP, which `fixup` resumes.
    unsafe { stela_pmu_wrmsr(index, value) == 0 }
}

#[inline]
fn rdpmc(counter: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: ring 0, a counter `start` probed.
    unsafe {
        asm!("rdpmc", in("ecx") counter, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    u64::from(high) << 32 | u64::from(low)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Event {
    name: &'static str,
    code: u16,
    umask: u8,
}

const fn event(name: &'static str, code: u16, umask: u8) -> Event {
    Event { name, code, umask }
}

const CYCLES_AMD: Event = event("cyc", 0x076, 0);
const INSTRUCTIONS_AMD: Event = event("ins", 0x0c0, 0);
const ZEN: [Event; 8] = [
    event("brmisp", 0x0c3, 0),
    event("icmiss", 0x18e, 0x18),
    event("itlbh", 0x084, 0),
    event("itlbw", 0x085, 0x0f),
    event("dtlbh", 0x045, 0x0f),
    event("dtlbw", 0x045, 0xf0),
    event("l2miss", 0x064, 0x09),
    event("dram", 0x044, 0x48),
];
const CYCLES_INTEL: Event = event("cyc", 0x3c, 0);
const INSTRUCTIONS_INTEL: Event = event("ins", 0xc0, 0);
const MISPREDICTS_INTEL: Event = event("brmisp", 0xc5, 0);
const LLC_MISSES_INTEL: Event = event("llcmiss", 0x2e, 0x41);

/// How this core's counters are reached, and what they count.
struct Layout {
    counters: usize,
    /// Event select of counter `i`: `select + i * stride`.
    select: u32,
    stride: u32,
    /// The global enable register and its value, where there is one.
    global: Option<(u32, u64)>,
    amd: bool,
    fixed: Vec<Event>,
    rotating: Vec<Event>,
    described: String,
}

const AMD_VENDOR: [u32; 3] = [0x6874_7541, 0x6974_6e65, 0x444d_4163];
const INTEL_VENDOR: [u32; 3] = [0x756e_6547, 0x4965_6e69, 0x6c65_746e];

fn family() -> u32 {
    let eax = __cpuid(1).eax;
    let base = (eax >> 8) & 0xf;
    if base == 0xf {
        base + ((eax >> 20) & 0xff)
    } else {
        base
    }
}

fn layout() -> Option<Layout> {
    let vendor = __cpuid(0);
    let vendor = [vendor.ebx, vendor.edx, vendor.ecx];
    if vendor == AMD_VENDOR {
        let extended = __cpuid(0x8000_0000).eax;
        let core_ext = extended >= 0x8000_0001 && __cpuid(0x8000_0001).ecx & (1 << 23) != 0;
        let v2 = extended >= 0x8000_0022 && __cpuid(0x8000_0022).eax & 1 != 0;
        let (counters, select, stride) = if core_ext {
            let counters = if v2 {
                (__cpuid(0x8000_0022).ebx & 0xf) as usize
            } else {
                6
            };
            (counters, 0xc001_0200, 2)
        } else {
            (4, 0xc001_0000, 1)
        };
        let counters = counters.min(MAX_COUNTERS);
        let family = family();
        let zen = matches!(family, 0x19 | 0x1a);
        let rotating = if zen { ZEN.to_vec() } else { ZEN[..1].to_vec() };
        Some(Layout {
            counters,
            select,
            stride,
            global: v2.then(|| (0xc000_0301, (1u64 << counters) - 1)),
            amd: true,
            fixed: alloc::vec![CYCLES_AMD, INSTRUCTIONS_AMD],
            rotating,
            described: format!(
                "AMD family {family:#x} counters={counters} core_ext={core_ext} perfmon_v2={v2}{}",
                if zen {
                    ""
                } else {
                    " (no Zen event table: cycles, instructions, mispredicts only)"
                }
            ),
        })
    } else if vendor == INTEL_VENDOR && __cpuid(0).eax >= 0xa {
        let leaf = __cpuid_count(0xa, 0);
        let version = leaf.eax & 0xff;
        let counters = (((leaf.eax >> 8) & 0xff) as usize).min(MAX_COUNTERS);
        let known = ((leaf.eax >> 24) & 0xff) as usize;
        if version == 0 || counters == 0 {
            return None;
        }
        // EBX bit set: the architectural event is unavailable.
        let available = |bit: usize| bit < known && leaf.ebx & (1 << bit) == 0;
        let mut fixed = Vec::new();
        for (bit, event) in [(0, CYCLES_INTEL), (1, INSTRUCTIONS_INTEL)] {
            if available(bit) {
                fixed.push(event);
            }
        }
        let mut rotating = Vec::new();
        for (bit, event) in [(6, MISPREDICTS_INTEL), (4, LLC_MISSES_INTEL)] {
            if available(bit) {
                rotating.push(event);
            }
        }
        Some(Layout {
            counters,
            select: 0x186,
            stride: 1,
            global: (version >= 2).then(|| (0x38f, (1u64 << counters) - 1)),
            amd: false,
            fixed,
            rotating,
            described: format!(
                "Intel perfmon v{version} counters={counters}; instruction cache, ITLB, DTLB and L2 events unsupported"
            ),
        })
    } else {
        None
    }
}

impl Layout {
    fn per_set(&self) -> usize {
        self.counters.saturating_sub(self.fixed.len()).max(1)
    }

    fn sets(&self) -> usize {
        self.rotating
            .len()
            .div_ceil(self.per_set())
            .clamp(1, MAX_SETS)
    }

    /// The events counter by counter while set `set` runs.
    fn events(&self, set: usize) -> Vec<Event> {
        let per = self.per_set();
        let mut events: Vec<Event> = self.fixed.clone();
        events.extend(self.rotating.iter().skip(set * per).take(per));
        events.truncate(self.counters);
        events
    }

    fn select(&self, event: Event) -> u64 {
        const OS: u64 = 1 << 17;
        const USR: u64 = 1 << 16;
        const ENABLE: u64 = 1 << 22;
        let code = u64::from(event.code);
        let high = if self.amd { (code >> 8 & 0xf) << 32 } else { 0 };
        (code & 0xff) | u64::from(event.umask) << 8 | OS | USR | ENABLE | high
    }
}

#[derive(Default)]
struct Bucket {
    counts: [AtomicU64; MAX_COUNTERS],
    ticks: AtomicU64,
    sampled: AtomicU64,
}

/// The owner core's own state: only its boundaries and fills touch it.
#[derive(Default)]
struct Own {
    set: usize,
    /// Counters read in the running set.
    read: usize,
    last: u64,
    snap: [u64; MAX_COUNTERS],
    sampling: bool,
    /// Where the sampled interval began, after its reads.
    sample_start: u64,
    /// The TSC before which the core does not start another sampled
    /// interval.
    next_sample: u64,
    /// Ticks between sampled interval starts at least: two reads each.
    gap: u64,
    fill: Option<(u64, [u64; MAX_COUNTERS])>,
    /// TSC ticks a window lasts at least; 0 reads around sampled intervals.
    window: u64,
    window_start: u64,
    /// Each phase's ticks in the open window (`FILL` stays 0: fills are
    /// inside `nat`).
    window_ticks: [u64; BUCKETS],
}

struct Core {
    pe: usize,
    own: UnsafeCell<Own>,
    buckets: [[Bucket; BUCKETS]; MAX_SETS],
    /// Window mode: every closed window's counts and ticks, per set.
    whole: [Bucket; MAX_SETS],
    /// Reads of the set since start, for the overhead estimate.
    reads: AtomicU64,
}

// SAFETY: `own` is touched only by the owner core, from its boundaries and
// its page-fault handler, which never interleave; the rest are atomics.
unsafe impl Sync for Core {}

/// Each host processor's core record, once its PE started profiling.
static CORES: [AtomicPtr<Core>; MAX_CORES] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CORES];
/// The event set every core should run.
static SET: AtomicU32 = AtomicU32::new(0);
static SETS: AtomicU32 = AtomicU32::new(1);
/// The longest interval-sampling gap any core uses, in TSC ticks.
static GAP: AtomicU64 = AtomicU64::new(0);
/// The dearest read of the set any core measured, in TSC ticks.
static COST: AtomicU64 = AtomicU64::new(0);
/// The longest window any core uses, in TSC ticks; 0 while every core
/// samples intervals.
static WINDOW: AtomicU64 = AtomicU64::new(0);
static DESCRIBED: AtomicBool = AtomicBool::new(false);
/// Counters whose event select some core refused, bit `set * MAX_COUNTERS +
/// counter`: their fields are left out of the line.
static REFUSED: AtomicU32 = AtomicU32::new(0);
static LAYOUT: AtomicPtr<Layout> = AtomicPtr::new(core::ptr::null_mut());

fn shared_layout() -> Option<&'static Layout> {
    let pointer = LAYOUT.load(Relaxed);
    // SAFETY: published once, leaked, never written after.
    (!pointer.is_null()).then(|| unsafe { &*pointer })
}

fn core() -> Option<&'static Core> {
    let pointer = CORES.get(super::local::processor() as usize)?.load(Relaxed);
    // SAFETY: leaked at `start`, never freed.
    (!pointer.is_null()).then(|| unsafe { &*pointer })
}

/// Program this core's counters for `set`. Says once per event what the
/// core refused.
fn program(layout: &Layout, set: usize) -> usize {
    let events = layout.events(set);
    for counter in 0..layout.counters {
        let index = layout.select + counter as u32 * layout.stride;
        let value = events.get(counter).map_or(0, |event| layout.select(*event));
        if !write(index, value) && value != 0 {
            let bit = 1 << (set * MAX_COUNTERS + counter);
            if REFUSED.fetch_or(bit, Relaxed) & bit == 0 {
                output::arguments(format_args!(
                    "PMU event {} refused (#GP at {index:#x}): left out of PES PMU\n",
                    events[counter].name
                ));
            }
        }
    }
    if let Some((index, value)) = layout.global
        && !write(index, value)
    {
        output::arguments(format_args!(
            "PMU global enable {index:#x} refused (#GP); counters may stay off\n"
        ));
    }
    events.len()
}

/// Under `--profile`, program this host core's counters for PE `pe`.
pub(crate) fn start(pe: usize) {
    let slot = super::local::processor() as usize;
    if slot >= MAX_CORES {
        return;
    }
    let layout = match shared_layout() {
        Some(layout) => layout,
        None => {
            let Some(layout) = layout() else {
                if !DESCRIBED.swap(true, Relaxed) {
                    output::arguments(format_args!(
                        "PMU unavailable: no AMD core counters or Intel architectural perfmon; PES PMU left out\n"
                    ));
                }
                return;
            };
            let leaked = Box::into_raw(Box::new(layout));
            match LAYOUT.compare_exchange(core::ptr::null_mut(), leaked, Relaxed, Relaxed) {
                Ok(_) => {}
                // SAFETY: ours, never published.
                Err(_) => drop(unsafe { Box::from_raw(leaked) }),
            }
            shared_layout().expect("published")
        }
    };
    // SAFETY: ring 0; an unknown counter takes #GP, which `fixup` resumes.
    if unsafe { stela_pmu_rdpmc(0) } != 0 {
        output::arguments(format_args!(
            "PMU pe={pe}: RDPMC refused; PES PMU leaves this PE out\n"
        ));
        return;
    }
    let read = program(layout, SET.load(Relaxed) as usize % layout.sets());
    // What reading the set costs: RDPMC may trap under a hypervisor.
    let before = crate::apic::rdtsc();
    for _ in 0..4 {
        for counter in 0..read {
            core::hint::black_box(rdpmc(counter as u32));
        }
    }
    let cost = crate::apic::rdtsc().wrapping_sub(before) / 4;
    COST.fetch_max(cost, Relaxed);
    let gap = 2 * cost * READ_SHARE;
    let window = if cost > WINDOW_READ_TICKS {
        WINDOW_TICKS.max(cost * READ_SHARE)
    } else {
        0
    };
    if window == 0 {
        GAP.fetch_max(gap, Relaxed);
    } else {
        WINDOW.fetch_max(window, Relaxed);
    }
    SETS.store(layout.sets() as u32, Relaxed);
    if !DESCRIBED.swap(true, Relaxed) {
        let mut sets = String::new();
        for set in 0..layout.sets() {
            let names: Vec<&str> = layout.events(set).iter().map(|event| event.name).collect();
            sets.push_str(&format!(" set{}={}", set + 1, names.join(",")));
        }
        let method = if window == 0 {
            format!("sampling a charged interval at most every {gap} ticks (reads under 0.2%)")
        } else {
            format!(
                "too dear to read around intervals: whole-PE windows of {window} ticks or more (reads under 0.2%), phases from windows one phase holds 90% of"
            )
        };
        output::arguments(format_args!(
            "PMU {}{sets}; one read of the set costs {cost} TSC ticks, {method}\n",
            layout.described
        ));
    }
    let own = Own {
        set: SET.load(Relaxed) as usize % layout.sets(),
        read,
        last: crate::apic::rdtsc(),
        gap,
        window,
        window_start: crate::apic::rdtsc(),
        snap: read_all(None, read),
        ..Own::default()
    };
    let record = Box::into_raw(Box::new(Core {
        pe,
        own: UnsafeCell::new(own),
        buckets: Default::default(),
        whole: Default::default(),
        reads: AtomicU64::new(0),
    }));
    CORES[slot].store(record, Relaxed);
}

/// Read the set, counting the read on `core` if it has a record yet.
fn read_all(core: Option<&Core>, read: usize) -> [u64; MAX_COUNTERS] {
    if let Some(core) = core {
        add(&core.reads, 1);
    }
    let mut values = [0; MAX_COUNTERS];
    for (counter, value) in values.iter_mut().enumerate().take(read) {
        *value = rdpmc(counter as u32);
    }
    values
}

/// Add to a counter only its core writes.
#[inline]
fn add(counter: &AtomicU64, value: u64) {
    counter.store(counter.load(Relaxed).wrapping_add(value), Relaxed);
}

/// The counters' 48-bit delta.
fn delta(now: u64, then: u64) -> u64 {
    now.wrapping_sub(then) & ((1 << 48) - 1)
}

/// A charge of the interval ending at TSC `now` to `phase`.
#[inline]
pub(crate) fn boundary(phase: Phase, now: u64) {
    let Some(core) = core() else {
        return;
    };
    // SAFETY: the owner core, outside its fault handler.
    let own = unsafe { &mut *core.own.get() };
    let bucket = &core.buckets[own.set][phase as usize];
    let ticks = now.wrapping_sub(own.last);
    add(&bucket.ticks, ticks);
    if own.window != 0 {
        own.window_ticks[phase as usize] += ticks;
        own.last = now;
        let wanted = SET.load(Relaxed) as usize;
        if wanted != own.set
            && let Some(layout) = shared_layout()
        {
            // The open window counted the old set: drop it.
            own.read = program(layout, wanted);
            own.set = wanted;
            open_window(core, own);
        } else if now.wrapping_sub(own.window_start) >= own.window {
            close_window(core, own);
        }
        return;
    }
    if own.sampling {
        let values = read_all(Some(core), own.read);
        for (counter, value) in values.iter().enumerate().take(own.read) {
            add(&bucket.counts[counter], delta(*value, own.snap[counter]));
        }
        add(&bucket.sampled, now.wrapping_sub(own.sample_start));
        own.sampling = false;
    }
    own.last = now;
    let wanted = SET.load(Relaxed) as usize;
    if wanted != own.set
        && let Some(layout) = shared_layout()
    {
        own.read = program(layout, wanted);
        own.set = wanted;
    }
    if now.wrapping_sub(own.next_sample) < 1 << 63 {
        own.next_sample = now.wrapping_add(own.gap);
        own.snap = read_all(Some(core), own.read);
        own.sampling = true;
        own.sample_start = crate::apic::rdtsc();
    }
}

fn open_window(core: &Core, own: &mut Own) {
    own.snap = read_all(Some(core), own.read);
    own.window_ticks = [0; BUCKETS];
    own.window_start = crate::apic::rdtsc();
}

/// Credit the window that ends now to the whole PE, and to the bucket that
/// holds most of its ticks if one does, then open the next.
fn close_window(core: &Core, own: &mut Own) {
    let values = read_all(Some(core), own.read);
    let ticks: u64 = own.window_ticks.iter().sum();
    if ticks == 0 {
        return;
    }
    let mut counts = [0; MAX_COUNTERS];
    for (counter, count) in counts.iter_mut().enumerate().take(own.read) {
        *count = delta(values[counter], own.snap[counter]);
    }
    let credit = |bucket: &Bucket| {
        for (counter, count) in counts.iter().enumerate().take(own.read) {
            add(&bucket.counts[counter], *count);
        }
        add(&bucket.sampled, ticks);
    };
    credit(&core.whole[own.set]);
    if let Some(dominant) = own
        .window_ticks
        .iter()
        .position(|phase| *phase * 10 >= ticks * DOMINANT_TENTHS)
    {
        credit(&core.buckets[own.set][dominant]);
    }
    own.snap = values;
    own.window_ticks = [0; BUCKETS];
    own.window_start = crate::apic::rdtsc();
}

/// Before a shadow page-fault fill: a mark while profiling.
#[inline]
pub(crate) fn fill_begin() {
    let Some(core) = core() else {
        return;
    };
    // SAFETY: the owner core; its boundary code is not running.
    let own = unsafe { &mut *core.own.get() };
    let values = if own.sampling {
        read_all(Some(core), own.read)
    } else {
        [0; MAX_COUNTERS]
    };
    own.fill = Some((crate::apic::rdtsc(), values));
}

/// After the fill [`fill_begin`] marked.
#[inline]
pub(crate) fn fill_end() {
    let Some(core) = core() else {
        return;
    };
    // SAFETY: as `fill_begin`.
    let own = unsafe { &mut *core.own.get() };
    let Some((then, before)) = own.fill.take() else {
        return;
    };
    let bucket = &core.buckets[own.set][FILL];
    let ticks = crate::apic::rdtsc().wrapping_sub(then);
    add(&bucket.ticks, ticks);
    if own.sampling {
        let values = read_all(Some(core), own.read);
        for (counter, value) in values.iter().enumerate().take(own.read) {
            add(&bucket.counts[counter], delta(*value, before[counter]));
        }
        add(&bucket.sampled, ticks);
    }
}

/// What the line compares against: each core's bucket totals at the last
/// beat, per set.
pub(crate) struct Seen {
    totals: Vec<[[[u64; MAX_COUNTERS + 2]; BUCKETS + 1]; MAX_SETS]>,
    /// Each core's reads of the set at the last beat.
    reads: Vec<u64>,
}

impl Seen {
    pub(crate) const fn new() -> Self {
        Self {
            totals: Vec::new(),
            reads: Vec::new(),
        }
    }
}

fn totals(core: &Core) -> [[[u64; MAX_COUNTERS + 2]; BUCKETS + 1]; MAX_SETS] {
    let mut all = [[[0; MAX_COUNTERS + 2]; BUCKETS + 1]; MAX_SETS];
    for (set, (buckets, whole)) in core.buckets.iter().zip(&core.whole).enumerate() {
        for (bucket, values) in buckets.iter().chain([whole]).enumerate() {
            let entry = &mut all[set][bucket];
            for (slot, count) in entry.iter_mut().zip(&values.counts) {
                *slot = count.load(Relaxed);
            }
            entry[MAX_COUNTERS] = values.ticks.load(Relaxed);
            entry[MAX_COUNTERS + 1] = values.sampled.load(Relaxed);
        }
    }
    all
}

/// The `PES PMU` line for the beat that ends now, then the next set.
///
/// `PES PMU set=S/N events=E1,E2,... method=M units=cyc,ins:M other:K`,
/// then for each PE `pe:` and for each bucket that ran (`nat`, `fill`,
/// `fetch`, `exit`, `sch`, `dev`) `name=v1/v2/...` in the order of
/// `events`, then `all:` the machine's sums. Counts are scaled by each
/// bucket's TSC ticks over its sampled ticks; cycles and instructions in
/// millions, the other events in thousands. `nat` includes `fill`. A
/// bucket with no sampled interval shows `-`.
///
/// `overhead=`: the beat's reads times the dearest read cost over the
/// PEs' charged ticks.
///
/// `method=interval:GKticks`: each bucket from the intervals read at both
/// ends. `method=window:NMticks` (RDPMC trapped): a leading `pe=` is the
/// whole PE from every window, unbiased; each phase bucket comes only from
/// the windows that phase held 90% of, so a phase that never dominates a
/// window shows `-` (`fill` always does).
pub(crate) fn report(seen: &mut Seen) {
    let Some(layout) = shared_layout() else {
        return;
    };
    let sets = layout.sets();
    let set = SET.load(Relaxed) as usize % sets;
    let events = layout.events(set);
    let mut cores: Vec<&Core> = CORES
        .iter()
        .filter_map(|slot| {
            let pointer = slot.load(Relaxed);
            // SAFETY: leaked at `start`, never freed.
            (!pointer.is_null()).then(|| unsafe { &*pointer })
        })
        .collect();
    cores.sort_by_key(|core| core.pe);
    let pes = cores.last().map_or(0, |core| core.pe + 1);
    if seen.totals.len() < pes {
        seen.totals
            .resize(pes, [[[0; MAX_COUNTERS + 2]; BUCKETS + 1]; MAX_SETS]);
        seen.reads.resize(pes, 0);
    }
    // What the beat's reads cost: reads times the dearest measured read,
    // over every PE's charged ticks (all sets; `fill` is inside `nat`).
    let (mut reads, mut ticks) = (0u64, 0u64);
    for core in &cores {
        let now = core.reads.load(Relaxed);
        reads += now.wrapping_sub(seen.reads[core.pe]);
        seen.reads[core.pe] = now;
        let before = &seen.totals[core.pe];
        for (set, buckets) in core.buckets.iter().enumerate() {
            for (bucket, values) in buckets.iter().enumerate().take(Phase::COUNT) {
                ticks += values
                    .ticks
                    .load(Relaxed)
                    .wrapping_sub(before[set][bucket][MAX_COUNTERS]);
            }
        }
    }
    let overhead = (u128::from(reads) * u128::from(COST.load(Relaxed)) * 10_000)
        .checked_div(u128::from(ticks))
        .unwrap_or(0) as u64;
    let refused = REFUSED.load(Relaxed) >> (set * MAX_COUNTERS);
    let kept = |counter: usize| refused & (1 << counter) == 0;
    let names: Vec<&str> = events
        .iter()
        .enumerate()
        .filter(|(counter, _)| kept(*counter))
        .map(|(_, event)| event.name)
        .collect();
    let window = WINDOW.load(Relaxed);
    let method = if window == 0 {
        format!("interval:{}Kticks", GAP.load(Relaxed).div_ceil(1_000))
    } else {
        format!("window:{}Mticks", window.div_ceil(1_000_000))
    };
    let mut line = format!(
        "PES PMU set={}/{sets} events={} method={method} overhead={}.{:02}% units=cyc,ins:M other:K",
        set + 1,
        names.join(","),
        overhead / 100,
        overhead % 100,
    );
    let mut machine = [[0u64; MAX_COUNTERS]; BUCKETS + 1];
    let mut ran = [false; BUCKETS + 1];
    let format_bucket = |line: &mut String, name: &str, values: &[u64]| {
        line.push_str(&format!(" {name}="));
        let mut first = true;
        for (counter, value) in values.iter().enumerate().take(events.len()) {
            if !kept(counter) {
                continue;
            }
            if !core::mem::take(&mut first) {
                line.push('/');
            }
            let unit = if counter < layout.fixed.len() {
                1_000_000
            } else {
                1_000
            };
            line.push_str(&format!("{}", value / unit));
        }
    };
    // Window mode leads with the whole PE (`pe`), read once a window.
    let order: Vec<usize> = (window != 0)
        .then_some(BUCKETS)
        .into_iter()
        .chain(REPORT_ORDER)
        .collect();
    let name = |bucket: usize| BUCKET_NAMES.get(bucket).copied().unwrap_or("pe");
    for core in &cores {
        let now = totals(core);
        let before = &seen.totals[core.pe];
        let elapsed = |bucket: usize| {
            now[set][bucket][MAX_COUNTERS].wrapping_sub(before[set][bucket][MAX_COUNTERS])
        };
        line.push_str(&format!(" {}:", core.pe));
        for &bucket in &order {
            // The whole PE ran every phase's ticks.
            let ticks = if bucket == BUCKETS {
                (0..Phase::COUNT).map(elapsed).sum()
            } else {
                elapsed(bucket)
            };
            let (now, before) = (&now[set][bucket], &before[set][bucket]);
            let sampled = now[MAX_COUNTERS + 1].wrapping_sub(before[MAX_COUNTERS + 1]);
            if ticks == 0 {
                continue;
            }
            if sampled == 0 {
                line.push_str(&format!(" {}=-", name(bucket)));
                continue;
            }
            let mut scaled = [0u64; MAX_COUNTERS];
            for counter in 0..events.len() {
                let count = now[counter].wrapping_sub(before[counter]);
                scaled[counter] =
                    (u128::from(count) * u128::from(ticks) / u128::from(sampled)) as u64;
                machine[bucket][counter] += scaled[counter];
            }
            ran[bucket] = true;
            format_bucket(&mut line, name(bucket), &scaled);
        }
        seen.totals[core.pe] = now;
    }
    line.push_str(" all:");
    for &bucket in &order {
        if ran[bucket] {
            format_bucket(&mut line, name(bucket), &machine[bucket]);
        }
    }
    line.push('\n');
    output::arguments(format_args!("{line}"));
    if sets > 1 {
        SET.store(((set + 1) % sets) as u32, Relaxed);
    }
}
