//! The bare-metal [`Host`]: guest RAM, the native code arena, shadow paging,
//! precise native faults, the local APIC timer and the TSC counter.
//!
//! Shadow roots are PML5 pages under LA57 and PML4 pages otherwise, whose
//! entries hold the guest's native ranges and the shared window
//! (`layout::window_entries`), which native code's guest range checks keep
//! every guest access out of; no other entry is ever mapped, which those
//! checks rely on. There is one root per
//! permission view (EL0, EL1, EL1 with PAN, GL1), and a second set for the
//! same views while tag checks keep Tagged memory out (`Regime::tag_checks`),
//! filled on demand by the #PF handler from the software walk of the
//! guest's tables, a window of the guest leaf per fault. Each half takes its tables from its own part of the
//! pool, so a change of TTBR0 alone (a context switch) drops the lower half
//! and keeps the upper half's, and records the leaves it was filled from
//! (`mmu::shadow::Extents`), so a TLBI unmaps only the ranges it reaches.
use super::interrupts::{Frame, SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::{
    apic::{self, Apic},
    layout,
    tables::{self, Frames, NX, PAGE, PRESENT, WRITABLE},
};
use alloc::vec::Vec;
use core::{
    arch::{asm, global_asm},
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_compiler::{GuestState, block::BlockExit};
use stela_runtime::machine::{
    FaultCause, Host, InstallError, NativeCode, NativeExit, NativeFault, Regime,
    mmu::{
        self, Access, Outcome,
        placement::Placement,
        shadow::{self, Extents},
        tlbi::Reach,
        translated::Tlb,
    },
};

mod translated;

/// Guest DRAM backed by one contiguous host range.
#[derive(Debug, Clone, Copy)]
pub struct RamRange {
    pub guest: u64,
    pub host: u64,
    pub bytes: u64,
}

/// Page-table frames from the handoff pool: a permanent part for roots and a
/// shadow part, split between the guest's two halves, each of which resets
/// wholesale.
struct Pool {
    base: u64,
    bytes: u64,
    permanent: u64,
    /// The next free shadow frame's offset of each half ([`LOWER`],
    /// [`UPPER`]).
    shadow: [u64; 2],
    /// First shadow frame.
    shadow_base: u64,
    /// The half the next frames map.
    half: usize,
}

/// The guest halves: VAs with bit 63 clear and set.
const LOWER: usize = 0;
const UPPER: usize = 1;

impl Frames for Pool {
    fn frame(&mut self) -> Option<u64> {
        let (_, end) = self.range(self.half);
        if self.shadow[self.half] + PAGE > end {
            return None;
        }
        let frame = self.base + self.shadow[self.half];
        self.shadow[self.half] += PAGE;
        zero(frame);
        Some(frame)
    }
    fn table(&self, physical: u64) -> *mut u64 {
        layout::physical(physical) as *mut u64
    }
}

fn zero(frame: u64) {
    // SAFETY: a pool frame reached through the physmap.
    unsafe { (layout::physical(frame) as *mut u8).write_bytes(0, PAGE as usize) };
}

impl Pool {
    fn permanent(&mut self) -> Option<u64> {
        if self.permanent + PAGE > self.shadow_base - self.base {
            return None;
        }
        let frame = self.base + self.permanent;
        self.permanent += PAGE;
        zero(frame);
        Some(frame)
    }
    /// The offsets of `half`'s shadow frames: the lower half of the shadow
    /// part, or the upper.
    fn range(&self, half: usize) -> (u64, u64) {
        let start = self.shadow_base - self.base;
        let middle = start + (self.bytes - start) / 2 / PAGE * PAGE;
        if half == LOWER {
            (start, middle)
        } else {
            (middle, self.bytes)
        }
    }
    fn reset_half(&mut self, half: usize) {
        self.shadow[half] = self.range(half).0;
    }
}

/// Permission views; the tag-checked roots follow the unchecked ones.
const VIEWS: usize = 4;
const ROOTS: usize = 2 * VIEWS;
/// Frames reserved for roots and other permanent tables.
const PERMANENT_FRAMES: u64 = 64;
/// A root's entries.
const ROOT_ENTRIES: usize = 512;
/// log2 of the bytes a four-level root entry maps: 512 GiB.
const PML4_ENTRY_BITS: u32 = 39;
/// The last address of the lower half under LA57 (48 bits) and four-level
/// paging (47 bits).
const FIVE_LEVEL_LOWER_END: u64 = (1 << 48) - 1;
const FOUR_LEVEL_LOWER_END: u64 = (1 << 47) - 1;
/// The aligned bytes of a guest leaf one fault maps.
const FILL_WINDOW: u64 = 64 * 1024;
/// Pages a scoped invalidation flushes one by one; more reload CR3.
const INVLPG_PAGES: u64 = 16;
const FAULT_KIND: u64 = 0xffff;
pub(crate) const COUNTER_HZ: u64 = 24_000_000;

#[derive(Clone, Copy)]
struct Recorded {
    rip: u64,
    address: u64,
    write: bool,
    cause: FaultCause,
    /// RAX through R15 at the faulting instruction, by x86 register number.
    registers: [u64; 16],
}

pub struct State {
    ram: Vec<RamRange>,
    pool: Pool,
    /// Engine root without any guest mapping.
    host_root: u64,
    roots: [u64; ROOTS],
    current: usize,
    regime: Option<Regime>,
    /// The halves whose Tagged memory the tag-checked roots keep out.
    tag_checks: [bool; 2],
    code_physical: u64,
    code_bytes: u64,
    /// The arena's part new code goes to, and the offset after the code
    /// installed last.
    code_unit: u64,
    code_used: u64,
    recorded: Option<Recorded>,
    native: bool,
    tsc_base: u64,
    tsc_hz: u64,
    /// COUNTER_HZ / tsc_hz as a 0.64 fixed-point fraction: the counter is
    /// read several times per block, and a 128-bit division is a library
    /// call.
    counter_per_tsc: u64,
    apic: Apic,
    /// The APIC timer's ticks per second at divide-by-one.
    apic_hz: u64,
    pub fills: u64,
    pub resets: u64,
    /// Resets of the lower half alone.
    pub lower_resets: u64,
    /// The leaves each half was filled from.
    extents: [Extents; 2],
    /// TLBIs that unmapped ranges rather than whole halves.
    pub scoped: u64,
    /// Pages mapped beside a fault's from the same leaf.
    pub prefills: u64,
    pub stray: u64,
    /// TSC ticks spent in compiled guest code, its exits and faults.
    pub native_ticks: u64,
    /// Where the guest's address space lies beside the window.
    placement: Placement,
    /// The translated variant's software TLB, tagged by root, and the
    /// helper's bounce slot; without the slot the host has no helper.
    tlb: Tlb,
    bounce: Option<translated::Bounce>,
    /// Translation helper calls, the TLB fills they made and the accesses
    /// they ran through the bounce slot; shadow faults in the guard.
    pub helper_calls: u64,
    pub helper_fills: u64,
    pub bounces: u64,
    pub guard_faults: u64,
}

struct Global(UnsafeCell<Option<State>>);
// SAFETY: one CPU; the fault handler runs only while native code runs, and
// the engine touches the state only through `state()` outside native code.
unsafe impl Sync for Global {}
static STATE: Global = Global(UnsafeCell::new(None));
static HOST_INTERRUPT: AtomicBool = AtomicBool::new(false);

fn state() -> &'static mut State {
    // SAFETY: see `Global`; callers never hold two of these at once.
    unsafe { (*STATE.0.get()).as_mut().expect("host state installed") }
}

pub use crate::apic::rdtsc;

fn load_root(root: u64) {
    // SAFETY: every root maps the window, which holds all code and data in use.
    unsafe { asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}

fn invlpg(address: u64) {
    // SAFETY: invalidating a TLB entry has no other effect.
    unsafe { asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags)) };
}

pub struct Config {
    pub ram: Vec<RamRange>,
    pub pool_physical: u64,
    pub pool_bytes: u64,
    /// The loader's root, whose window entries every root shares.
    pub window_root: u64,
    pub code_physical: u64,
    pub code_bytes: u64,
    pub tsc_hz: u64,
    pub apic_base: u64,
    pub placement: Placement,
    /// The translation helper's bounce slot: its first page's address and
    /// the physical addresses of its two leaf entries.
    pub bounce: Option<(u64, [u64; 2])>,
}

/// Install the host state, leave the identity map and start the APIC.
///
/// # Safety
/// Runs once, in the engine phase, with interrupts disabled.
pub unsafe fn install(config: Config) -> Result<(), &'static str> {
    let mut pool = Pool {
        base: config.pool_physical,
        bytes: config.pool_bytes,
        permanent: 0,
        shadow: [0; 2],
        shadow_base: config.pool_physical + PERMANENT_FRAMES * PAGE,
        half: LOWER,
    };
    for half in [LOWER, UPPER] {
        pool.reset_half(half);
    }
    let (first, last) = layout::window_entries();
    let window = layout::physical(config.window_root) as *const u64;
    let mut root = || -> Result<u64, &'static str> {
        let frame = pool.permanent().ok_or("page-table pool too small")?;
        for entry in first..=last {
            // SAFETY: a fresh permanent frame and the loader's root, both
            // through the physmap.
            unsafe {
                (layout::physical(frame) as *mut u64)
                    .add(entry)
                    .write(window.add(entry).read())
            };
        }
        Ok(frame)
    };
    let host_root = root()?;
    let mut roots = [0; ROOTS];
    for slot in &mut roots {
        *slot = root()?;
    }
    load_root(host_root);
    let apic = Apic::new(
        config.apic_base,
        layout::physical(config.apic_base & apic::BASE_ADDRESS),
    );
    // SAFETY: the single initialization.
    unsafe {
        *STATE.0.get() = Some(State {
            ram: config.ram,
            pool,
            host_root,
            roots,
            current: usize::MAX,
            regime: None,
            tag_checks: [false; 2],
            code_physical: config.code_physical,
            code_bytes: config.code_bytes,
            code_unit: 0,
            code_used: 0,
            recorded: None,
            native: false,
            tsc_base: rdtsc(),
            tsc_hz: config.tsc_hz,
            counter_per_tsc: u64::try_from(
                (u128::from(COUNTER_HZ) << 64) / u128::from(config.tsc_hz),
            )
            .expect("the TSC is faster than the 24 MHz counter"),
            apic,
            apic_hz: 0,
            fills: 0,
            native_ticks: 0,
            resets: 0,
            lower_resets: 0,
            extents: [Extents::new(), Extents::new()],
            scoped: 0,
            prefills: 0,
            stray: 0,
            placement: config.placement,
            tlb: Tlb::default(),
            bounce: config
                .bounce
                .map(|(address, entries)| translated::Bounce::new(address, entries)),
            helper_calls: 0,
            helper_fills: 0,
            bounces: 0,
            guard_faults: 0,
        });
    }
    let state = state();
    state.apic_hz = state
        .apic
        .start(SPURIOUS_VECTOR, TIMER_VECTOR, state.tsc_hz);
    Ok(())
}

/// The host's counters for the statistics line.
pub struct Statistics {
    /// Shadow faults filled, and the pages beside them mapped from the
    /// same leaves.
    pub fills: u64,
    pub prefills: u64,
    /// Resets of the whole shadow, of the lower half alone, and TLBIs that
    /// unmapped ranges instead.
    pub resets: u64,
    pub lower_resets: u64,
    pub scoped: u64,
    pub stray: u64,
    /// The APIC timer frequency.
    pub apic_hz: u64,
    /// Translation helper calls, their TLB fills and bounced accesses, and
    /// shadow faults in the four-level guard.
    pub helper_calls: u64,
    pub helper_fills: u64,
    pub bounces: u64,
    pub guard_faults: u64,
}

pub fn statistics() -> Statistics {
    let state = state();
    Statistics {
        fills: state.fills,
        prefills: state.prefills,
        resets: state.resets,
        lower_resets: state.lower_resets,
        scoped: state.scoped,
        stray: state.stray,
        apic_hz: state.apic_hz,
        helper_calls: state.helper_calls,
        helper_fills: state.helper_fills,
        bounces: state.bounces,
        guard_faults: state.guard_faults,
    }
}

/// TSC ticks spent in compiled guest code so far.
pub fn native_ticks() -> u64 {
    state().native_ticks
}

impl State {
    fn host_physical(&self, guest: u64) -> Option<u64> {
        let index = self.ram.partition_point(|range| range.guest <= guest);
        let range = self.ram.get(index.checked_sub(1)?)?;
        (guest - range.guest < range.bytes).then(|| range.host + (guest - range.guest))
    }

    /// The longest RAM run starting at `guest`, as (host, bytes).
    fn run(&self, guest: u64) -> Option<(u64, u64)> {
        let index = self.ram.partition_point(|range| range.guest <= guest);
        let range = self.ram.get(index.checked_sub(1)?)?;
        let offset = guest - range.guest;
        (offset < range.bytes).then(|| (range.host + offset, range.bytes - offset))
    }

    fn copy(&self, guest: u64, length: usize, mut action: impl FnMut(u64, usize, usize)) -> bool {
        let mut done = 0;
        while done < length {
            let Some((host, available)) = self.run(guest + done as u64) else {
                return false;
            };
            let chunk = (available as usize).min(length - done);
            action(layout::physical(host), done, chunk);
            done += chunk;
        }
        true
    }

    fn reset_shadow(&mut self) {
        self.clear(LOWER);
        self.clear(UPPER);
        self.tlb.clear();
        self.resets += 1;
        self.reload();
    }

    /// Drop the lower half's translations only.
    fn reset_lower(&mut self) {
        self.clear(LOWER);
        self.tlb.clear();
        self.lower_resets += 1;
        self.reload();
    }

    /// Unmap `half` from every root and free its frames.
    fn clear(&mut self, half: usize) {
        self.pool.reset_half(half);
        self.extents[half].clear();
        let (first, last) = self.half_entries(half);
        for root in self.roots {
            for entry in first..=last {
                // SAFETY: permanent root frames through the physmap.
                unsafe { (layout::physical(root) as *mut u64).add(entry).write(0) };
            }
        }
    }

    /// The first and last root entries of `half` of the guest's native
    /// ranges: under LA57 PML5 entry 0 or 511; on a four-level host the
    /// PML4 entries of the lower half, or those from `U` up.
    fn half_entries(&self, half: usize) -> (usize, usize) {
        match (self.placement, half) {
            (Placement::FiveLevel, LOWER) => (0, 0),
            (Placement::FiveLevel, _) => (ROOT_ENTRIES - 1, ROOT_ENTRIES - 1),
            (Placement::FourLevel { .. }, LOWER) => (0, ROOT_ENTRIES / 2 - 1),
            (Placement::FourLevel { .. }, _) => (
                ((self.placement.native_upper() >> PML4_ENTRY_BITS) as usize) % ROOT_ENTRIES,
                ROOT_ENTRIES - 1,
            ),
        }
    }

    /// The first and last address of `half` of the native ranges.
    fn half_range(&self, half: usize) -> (u64, u64) {
        match (self.placement, half) {
            (Placement::FiveLevel, LOWER) => (0, FIVE_LEVEL_LOWER_END),
            (Placement::FourLevel { .. }, LOWER) => (0, FOUR_LEVEL_LOWER_END),
            _ => (self.placement.native_upper(), u64::MAX),
        }
    }

    /// Load the current root again, which flushes the TLB of the guest's
    /// (non-global) mappings.
    fn reload(&mut self) {
        let root = if self.current < ROOTS {
            self.roots[self.current]
        } else {
            self.host_root
        };
        load_root(root);
    }
}

/// Guest page tables read through the RAM map.
struct GuestTables<'a>(&'a State);

impl mmu::TableMemory for GuestTables<'_> {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        let host = self.0.host_physical(physical)?;
        // SAFETY: guest RAM through the physmap.
        Some(unsafe { (layout::physical(host) as *const u64).read_volatile() })
    }
    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool> {
        let host = self.0.host_physical(physical)?;
        let slot = layout::physical(host) as *mut u64;
        // SAFETY: guest RAM through the physmap; one PE, no concurrent walker.
        unsafe {
            if slot.read_volatile() != old {
                return Some(false);
            }
            slot.write_volatile(new);
        }
        Some(true)
    }
}

global_asm!(
    ".global stela_enter_block",
    "stela_enter_block:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rip + stela_recovery_rsp], rsp",
    "call rsi",
    "mov qword ptr [rip + stela_recovery_rsp], 0",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".global stela_native_recover",
    "stela_native_recover:",
    "mov rsp, [rip + stela_recovery_rsp]",
    "mov qword ptr [rip + stela_recovery_rsp], 0",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "xor eax, eax",
    "mov edx, 0xffff",
    "ret",
    ".data",
    ".balign 8",
    "stela_recovery_rsp: .quad 0",
    ".text",
);

unsafe extern "sysv64" {
    fn stela_enter_block(state: *mut GuestState, code: usize) -> BlockExit;
    fn stela_native_recover();
}

fn in_code(state: &State, rip: u64) -> bool {
    state.native && (layout::code()..layout::code() + state.code_bytes).contains(&rip)
}

/// End the native block at `frame` and report `cause` to the engine.
fn abandon(state: &mut State, frame: &mut Frame, address: u64, write: bool, cause: FaultCause) {
    state.recorded = Some(Recorded {
        rip: frame.rip,
        address,
        write,
        cause,
        registers: [
            frame.rax, frame.rcx, frame.rdx, frame.rbx, frame.rsp, frame.rbp, frame.rsi, frame.rdi,
            frame.r8, frame.r9, frame.r10, frame.r11, frame.r12, frame.r13, frame.r14, frame.r15,
        ],
    });
    frame.rip = stela_native_recover as *const () as u64;
}

/// The guest's translation of the access at `address`, through the same
/// software walk for shadow faults and the translation helper: the
/// translation and the host physical address of its RAM page, or why the
/// engine must take the access (Arm checks watchpoints after translation,
/// `AArch64_TranslateAddress`, then Tag Checks).
fn resolve(
    state: &mut State,
    address: u64,
    write: bool,
    unprivileged: bool,
) -> Result<(mmu::Translation, u64), FaultCause> {
    let regime = state.regime.ok_or(FaultCause::NonCanonical)?;
    let access = if write { Access::Write } else { Access::Read };
    let requester = mmu::Requester {
        unprivileged: regime.requester.unprivileged || unprivileged,
        ..regime.requester
    };
    let translation = match mmu::translate(
        &regime.controls,
        address,
        access,
        requester,
        &mut GuestTables(state),
    ) {
        Outcome::Mapped(translation) => translation,
        Outcome::Fault(fault) => return Err(FaultCause::Guest(fault)),
        Outcome::Unsupported(unsupported) => return Err(FaultCause::Translation(unsupported)),
    };
    if regime.watch.blocks(address & !(PAGE - 1)) {
        return Err(FaultCause::Watched);
    }
    if regime.tag_blocks(address, translation.attributes) {
        return Err(FaultCause::TagChecked);
    }
    let page = translation.physical & !(PAGE - 1);
    let host = state.host_physical(page).ok_or(FaultCause::Device {
        physical: translation.physical,
    })?;
    Ok((translation, host))
}

/// #PF: fill the shadow from the guest's tables or end the block precisely.
pub fn page_fault(frame: &mut Frame, address: u64) {
    let state = state();
    if !in_code(state, frame.rip) {
        super::interrupts::fatal(frame);
    }
    let write = frame.error & 2 != 0;
    let Some(regime) = state.regime else {
        super::interrupts::fatal(frame);
    };
    // Only the native ranges are shadow; the rest is the engine's. An
    // access past a check an earlier one stood for may reach the guard
    // (`mmu::placement`): its own check finds where it goes.
    if !state.placement.native(address) {
        state.guard_faults += u64::from(state.placement.in_guard(address));
        return abandon(state, frame, address, write, FaultCause::NonCanonical);
    }
    let (translation, host) = match resolve(state, address, write, false) {
        Ok(resolved) => resolved,
        Err(cause) => return abandon(state, frame, address, write, cause),
    };
    let rights = PRESENT | NX | if translation.writable { WRITABLE } else { 0 };
    let root = state.roots[state.current];
    let virtual_page = address & !(PAGE - 1);
    let half = if address >> 63 == 0 { LOWER } else { UPPER };
    state.pool.half = half;
    if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
        // The shadow pool is exhausted: start over and map again.
        state.reset_shadow();
        state.pool.half = half;
        if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
            super::interrupts::fatal(frame);
        }
    }
    invlpg(virtual_page);
    state.extents[half].record(address, translation.size, translation.global);
    // The rest of the leaf's window has the same translation and rights:
    // map its RAM pages that are not watched now, as a TLB entry covers
    // the whole leaf. Pages that were absent need no flush. A Tagged leaf
    // whose tags are checked maps only the passed page.
    if regime.tag_checks[half] && translation.attributes == mmu::attributes::TAGGED {
        state.fills += 1;
        return;
    }
    let (first, last) = shadow::window(address, translation.size, FILL_WINDOW);
    let mut page = first;
    loop {
        if page != virtual_page && !regime.watch.blocks(page) {
            let physical = translation
                .physical
                .wrapping_sub(address)
                .wrapping_add(page);
            if let Some(host) = state.host_physical(physical) {
                if tables::map_page(&mut state.pool, root, page, host, rights).is_err() {
                    // Out of frames: the rest stays to fault.
                    break;
                }
                state.prefills += 1;
            }
        }
        if page >= last & !(PAGE - 1) {
            break;
        }
        page += PAGE;
    }
    state.fills += 1;
}

/// #GP or #UD inside native code ends the block; elsewhere it is fatal.
pub fn native_exception(frame: &mut Frame) {
    let state = state();
    if !in_code(state, frame.rip) {
        super::interrupts::fatal(frame);
    }
    let cause = if frame.vector == 13 {
        FaultCause::NonCanonical
    } else {
        FaultCause::InvalidOpcode
    };
    abandon(state, frame, 0, false, cause);
}

pub fn timer_interrupt() {
    HOST_INTERRUPT.store(true, Ordering::Release);
    state().apic.eoi();
}

pub fn stray_interrupt(_vector: u8) {
    let state = state();
    state.stray += 1;
    state.apic.eoi();
}

/// The engine's handle; all state is in [`STATE`].
pub struct BareHost;

/// The parts of the code arena, reclaimed for new code oldest first: the
/// code of the most recent seven eighths of the run is kept, and only the
/// oldest eighth's blocks compile again when they next run.
const CODE_UNITS: u64 = 8;

fn code_unit_bytes(state: &State) -> u64 {
    state.code_bytes / CODE_UNITS / 16 * 16
}

impl Host for BareHost {
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        // The engine reads guest RAM only once its translation allowed it.
        super::speculation::fence();
        state().copy(physical, buffer.len(), |host, done, chunk| {
            // SAFETY: guest RAM through the physmap and a distinct buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    host as *const u8,
                    buffer[done..].as_mut_ptr(),
                    chunk,
                )
            };
        })
    }

    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        state().copy(physical, data.len(), |host, done, chunk| {
            // SAFETY: guest RAM through the physmap and a distinct buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), host as *mut u8, chunk)
            };
        })
    }

    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        let state = state();
        let offset = state.code_used.next_multiple_of(16);
        let end = offset + code.len() as u64;
        if end > (state.code_unit + 1) * code_unit_bytes(state) {
            return Err(InstallError::Full);
        }
        // SAFETY: arena bytes through the writable physmap alias.
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                layout::physical(state.code_physical + offset) as *mut u8,
                code.len(),
            );
        }
        // Serialize before the executable alias runs the new bytes.
        core::arch::x86_64::__cpuid(0);
        state.code_used = end;
        Ok(NativeCode((layout::code() + offset) as usize))
    }

    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        let state = state();
        let offset = code.0 as u64 - layout::code();
        assert!(
            offset + bytes.len() as u64 <= state.code_bytes,
            "a patch outside the code arena"
        );
        // SAFETY: installed arena bytes through the writable physmap alias.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                layout::physical(state.code_physical + offset) as *mut u8,
                bytes.len(),
            );
        }
        // Serialize before the executable alias runs the new bytes.
        core::arch::x86_64::__cpuid(0);
    }

    fn discard_code(&mut self) {
        let state = state();
        state.code_unit = 0;
        state.code_used = 0;
    }

    fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
        let state = state();
        let unit = code_unit_bytes(state);
        state.code_unit = (state.code_unit + 1) % CODE_UNITS;
        state.code_used = state.code_unit * unit;
        let start = (layout::code() + state.code_used) as usize;
        Some(start..start + unit as usize)
    }

    fn memory_low(&self) -> bool {
        crate::ALLOCATOR.low()
    }

    unsafe fn execute(&mut self, code: NativeCode, guest: &mut GuestState) -> NativeExit {
        state().native = true;
        let entered = rdtsc();
        // SAFETY: the engine passes installed system-mode block code.
        let exit = unsafe { stela_enter_block(guest, code.0) };
        let state = state();
        state.native = false;
        state.native_ticks += rdtsc() - entered;
        if exit.kind == FAULT_KIND
            && let Some(recorded) = state.recorded.take()
        {
            return NativeExit::Fault(NativeFault {
                // A chained block may lie below the entered one.
                offset: recorded.rip.wrapping_sub(code.0 as u64) as usize,
                address: recorded.address,
                write: recorded.write,
                cause: recorded.cause,
                registers: recorded.registers,
            });
        }
        NativeExit::Exit {
            next_pc: exit.next_pc,
            kind: exit.kind,
        }
    }

    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        // Installed code is callable where it lies, through the executable arena alias.
        Some(code.0)
    }

    fn set_regime(&mut self, regime: &Regime) {
        let state = state();
        if let Some(current) = state.regime
            && current.controls != regime.controls
        {
            // TTBR0 alone translates only the lower half, but it can name
            // the ASID the upper half's non-global entries were made in.
            let ttbr0 = mmu::Controls {
                ttbr0: regime.controls.ttbr0,
                ..current.controls
            };
            let asid = mmu::current_asid(&current.controls) == mmu::current_asid(&regime.controls);
            if ttbr0 == regime.controls && (asid || !state.extents[UPPER].private()) {
                state.reset_lower();
            } else {
                state.reset_shadow();
            }
        }
        // The tag-checked roots hold one pattern of checked halves.
        if regime.tag_checked() && regime.tag_checks != state.tag_checks {
            if state.tag_checks.contains(&true) {
                state.reset_shadow();
            }
            state.tag_checks = regime.tag_checks;
        }
        state.regime = Some(*regime);
        // EL0, EL1, EL1 with PAN, and the GXF guarded level (GL1).
        let view = match (
            regime.requester.el,
            regime.requester.pan,
            regime.requester.guarded,
        ) {
            (0, _, _) => 0,
            (_, _, true) => 3,
            (_, false, false) => 1,
            (_, true, false) => 2,
        } + if regime.tag_checked() { VIEWS } else { 0 };
        if state.current != view {
            state.current = view;
            load_root(state.roots[view]);
        }
    }

    fn isolate_predictions(&mut self) {
        super::speculation::isolate();
    }

    fn speculation_barrier(&self) {
        super::speculation::fence();
    }

    fn invalidate_translations(&mut self) {
        state().reset_shadow();
    }

    fn invalidate_reach(&mut self, reach: Reach) {
        let state = state();
        if reach == Reach::All {
            return state.reset_shadow();
        }
        state.tlb.clear();
        let mut unmapped = Vec::new();
        let mut whole = false;
        for half in [LOWER, UPPER] {
            match state.extents[half].ranges(reach, state.half_range(half)) {
                None => {
                    state.clear(half);
                    whole = true;
                }
                Some(ranges) => unmapped.extend(ranges),
            }
        }
        let mut pages = 0u64;
        for &(first, last) in &unmapped {
            for root in state.roots {
                tables::unmap(&state.pool, root, first, last);
            }
            pages = pages.saturating_add(((last - first) >> 12) + 1);
        }
        if whole || pages > INVLPG_PAGES {
            state.reload();
        } else {
            for &(first, last) in &unmapped {
                let mut page = first & !(PAGE - 1);
                loop {
                    invlpg(page);
                    if page >= last & !(PAGE - 1) {
                        break;
                    }
                    page += PAGE;
                }
            }
        }
        if whole {
            state.resets += 1;
        } else {
            state.scoped += 1;
        }
    }

    fn counter(&mut self) -> u64 {
        let state = state();
        let ticks = rdtsc() - state.tsc_base;
        ((u128::from(ticks) * u128::from(state.counter_per_tsc)) >> 64) as u64
    }

    fn arm_timer(&mut self, deadline: Option<u64>) {
        let now = self.counter();
        let state = state();
        let Some(deadline) = deadline else {
            state.apic.write(apic::INITIAL, 0);
            return;
        };
        let guest = deadline.saturating_sub(now).max(1);
        let ticks = u128::from(guest) * u128::from(state.apic_hz) / u128::from(COUNTER_HZ);
        let ticks = ticks.clamp(1, u128::from(u32::MAX)) as u32;
        state.apic.write(apic::LVT_TIMER, u32::from(TIMER_VECTOR));
        state.apic.write(apic::INITIAL, ticks);
    }

    fn wait_for_interrupt(&mut self) {
        HOST_INTERRUPT.store(false, Ordering::Relaxed);
        // SAFETY: STI's interrupt shadow covers HLT, so no wake-up is lost.
        unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    }

    fn report(&mut self, event: &stela_runtime::machine::Event) {
        super::report(event);
    }

    fn placement(&self) -> Placement {
        state().placement
    }

    fn translation_helper(&self) -> Option<u64> {
        state().bounce.as_ref().map(|_| translated::slot())
    }

    fn translations(&mut self) -> Option<&mut dyn stela_runtime::machine::Translations> {
        super::translations::store()
            .map(|store| store as &mut dyn stela_runtime::machine::Translations)
    }
}
