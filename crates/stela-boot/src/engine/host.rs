//! The bare-metal [`Host`]: guest RAM, the native code arena, shadow paging,
//! precise native faults, the local APIC timer and the TSC counter.
//!
//! Shadow roots are PML5 pages whose entry 0 and 511 hold the guest's two
//! halves and whose entry 64 is the shared window. There is one root per
//! permission view (EL0, EL1, EL1 with PAN, GL1), filled on demand by the #PF
//! handler from the software walk of the guest's tables.
use super::interrupts::{Frame, SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::{
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
    mmu::{self, Access, Outcome},
};

/// Guest DRAM backed by one contiguous host range.
#[derive(Debug, Clone, Copy)]
pub struct RamRange {
    pub guest: u64,
    pub host: u64,
    pub bytes: u64,
}

/// Page-table frames from the handoff pool: a permanent part for roots and a
/// shadow part that resets wholesale.
struct Pool {
    base: u64,
    bytes: u64,
    permanent: u64,
    shadow: u64,
    /// First shadow frame.
    shadow_base: u64,
}

impl Frames for Pool {
    fn frame(&mut self) -> Option<u64> {
        if self.shadow + PAGE > self.bytes {
            return None;
        }
        let frame = self.base + self.shadow;
        self.shadow += PAGE;
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
    fn reset_shadow(&mut self) {
        self.shadow = self.shadow_base - self.base;
    }
}

const ROOTS: usize = 4;
/// Frames reserved for roots and other permanent tables.
const PERMANENT_FRAMES: u64 = 64;
const GUEST_LOW: usize = 0;
const GUEST_HIGH: usize = 511;
const FAULT_KIND: u64 = 0xffff;
const COUNTER_HZ: u64 = 24_000_000;

#[derive(Clone, Copy)]
struct Recorded {
    rip: u64,
    address: u64,
    write: bool,
    cause: FaultCause,
}

struct Apic {
    x2: bool,
    base: u64,
    /// Timer ticks per second at divide-by-one.
    hz: u64,
}

impl Apic {
    fn read(&self, register: u32) -> u32 {
        if self.x2 {
            let (low, _high): (u32, u32);
            // SAFETY: an x2APIC MSR of this CPU.
            unsafe {
                asm!("rdmsr", in("ecx") 0x800 + (register >> 4), out("eax") low, out("edx") _high,
                    options(nomem, nostack, preserves_flags));
            }
            low
        } else {
            // SAFETY: the xAPIC page is in the physmap.
            unsafe {
                ((layout::physical(self.base) + u64::from(register)) as *const u32).read_volatile()
            }
        }
    }
    fn write(&self, register: u32, value: u32) {
        if self.x2 {
            // SAFETY: an x2APIC MSR of this CPU.
            unsafe {
                asm!("wrmsr", in("ecx") 0x800 + (register >> 4), in("eax") value, in("edx") 0,
                    options(nostack, preserves_flags));
            }
        } else {
            // SAFETY: the xAPIC page is in the physmap.
            unsafe {
                ((layout::physical(self.base) + u64::from(register)) as *mut u32)
                    .write_volatile(value)
            };
        }
    }
}

const APIC_EOI: u32 = 0xb0;
const APIC_SVR: u32 = 0xf0;
const APIC_LVT_TIMER: u32 = 0x320;
const APIC_LVT_LINT0: u32 = 0x350;
const APIC_INITIAL: u32 = 0x380;
const APIC_CURRENT: u32 = 0x390;
const APIC_DIVIDE: u32 = 0x3e0;
const LVT_MASKED: u32 = 1 << 16;

pub struct State {
    ram: Vec<RamRange>,
    pool: Pool,
    /// Engine root without any guest mapping.
    host_root: u64,
    roots: [u64; ROOTS],
    current: usize,
    regime: Option<Regime>,
    code_physical: u64,
    code_bytes: u64,
    code_used: u64,
    recorded: Option<Recorded>,
    native: bool,
    tsc_base: u64,
    tsc_hz: u64,
    apic: Apic,
    pub fills: u64,
    pub resets: u64,
    pub stray: u64,
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

pub fn rdtsc() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: RDTSC has no side effects.
    unsafe { asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack)) };
    (u64::from(high) << 32) | u64::from(low)
}

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
    pub window: u64,
    pub code_physical: u64,
    pub code_bytes: u64,
    pub tsc_hz: u64,
    pub apic_base: u64,
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
        shadow: PERMANENT_FRAMES * PAGE,
        shadow_base: config.pool_physical + PERMANENT_FRAMES * PAGE,
    };
    let window_entry = config.window | PRESENT | WRITABLE;
    let mut root = || -> Result<u64, &'static str> {
        let frame = pool.permanent().ok_or("page-table pool too small")?;
        // SAFETY: a fresh permanent frame through the physmap.
        unsafe {
            (layout::physical(frame) as *mut u64)
                .add(layout::WINDOW_INDEX)
                .write(window_entry)
        };
        Ok(frame)
    };
    let host_root = root()?;
    let roots = [root()?, root()?, root()?, root()?];
    load_root(host_root);
    let x2 = config.apic_base & (1 << 10) != 0;
    let apic = Apic {
        x2,
        base: config.apic_base & 0x000f_ffff_ffff_f000,
        hz: 0,
    };
    // SAFETY: the single initialization.
    unsafe {
        *STATE.0.get() = Some(State {
            ram: config.ram,
            pool,
            host_root,
            roots,
            current: usize::MAX,
            regime: None,
            code_physical: config.code_physical,
            code_bytes: config.code_bytes,
            code_used: 0,
            recorded: None,
            native: false,
            tsc_base: rdtsc(),
            tsc_hz: config.tsc_hz,
            apic,
            fills: 0,
            resets: 0,
            stray: 0,
        });
    }
    start_apic();
    Ok(())
}

/// Mask the legacy PICs, enable the local APIC and measure its timer.
fn start_apic() {
    // SAFETY: legacy PIC data ports; masking every line.
    unsafe {
        asm!("out 0x21, al", "out 0xa1, al", in("al") 0xffu8, options(nomem, nostack));
    }
    let state = state();
    let apic = &mut state.apic;
    apic.write(APIC_SVR, 0x100 | u32::from(SPURIOUS_VECTOR));
    apic.write(APIC_LVT_LINT0, LVT_MASKED);
    apic.write(APIC_DIVIDE, 0b1011);
    apic.write(APIC_LVT_TIMER, LVT_MASKED | u32::from(TIMER_VECTOR));
    apic.write(APIC_INITIAL, u32::MAX);
    let start = rdtsc();
    let wait = state.tsc_hz / 100;
    while rdtsc() - start < wait {
        core::hint::spin_loop();
    }
    let elapsed = u64::from(u32::MAX - apic.read(APIC_CURRENT));
    let tsc = rdtsc() - start;
    apic.write(APIC_INITIAL, 0);
    apic.hz = (u128::from(elapsed) * u128::from(state.tsc_hz) / u128::from(tsc.max(1))) as u64;
}

pub fn statistics() -> (u64, u64, u64, u64) {
    let state = state();
    (state.fills, state.resets, state.stray, state.apic.hz)
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
        self.pool.reset_shadow();
        for root in self.roots {
            let entries = layout::physical(root) as *mut u64;
            // SAFETY: permanent root frames through the physmap.
            unsafe {
                entries.add(GUEST_LOW).write(0);
                entries.add(GUEST_HIGH).write(0);
            }
        }
        self.resets += 1;
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
    state.native && (layout::CODE..layout::CODE + state.code_bytes).contains(&rip)
}

/// End the native block at `frame` and report `cause` to the engine.
fn abandon(state: &mut State, frame: &mut Frame, address: u64, write: bool, cause: FaultCause) {
    state.recorded = Some(Recorded {
        rip: frame.rip,
        address,
        write,
        cause,
    });
    frame.rip = stela_native_recover as *const () as u64;
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
    let access = if write { Access::Write } else { Access::Read };
    let outcome = mmu::translate(
        &regime.controls,
        address,
        access,
        regime.requester,
        &mut GuestTables(state),
    );
    let translation = match outcome {
        Outcome::Mapped(translation) => translation,
        Outcome::Fault(fault) => {
            return abandon(state, frame, address, write, FaultCause::Guest(fault));
        }
        Outcome::Unsupported(unsupported) => {
            return abandon(
                state,
                frame,
                address,
                write,
                FaultCause::Translation(unsupported),
            );
        }
    };
    // Watchpoints are checked after translation (Arm
    // `AArch64_TranslateAddress`); the engine checks this access.
    if regime.watch.blocks(address & !(PAGE - 1)) {
        return abandon(state, frame, address, write, FaultCause::Watched);
    }
    let page = translation.physical & !(PAGE - 1);
    let Some(host) = state.host_physical(page) else {
        let physical = translation.physical;
        return abandon(
            state,
            frame,
            address,
            write,
            FaultCause::Device { physical },
        );
    };
    let rights = PRESENT | NX | if translation.writable { WRITABLE } else { 0 };
    let root = state.roots[state.current];
    let virtual_page = address & !(PAGE - 1);
    if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
        // The shadow pool is exhausted: start over and map again.
        state.reset_shadow();
        if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
            super::interrupts::fatal(frame);
        }
    }
    invlpg(virtual_page);
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
    state().apic.write(APIC_EOI, 0);
}

pub fn stray_interrupt(_vector: u8) {
    let state = state();
    state.stray += 1;
    state.apic.write(APIC_EOI, 0);
}

/// The engine's handle; all state is in [`STATE`].
pub struct BareHost;

impl Host for BareHost {
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
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
        if end > state.code_bytes {
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
        Ok(NativeCode((layout::CODE + offset) as usize))
    }

    fn discard_code(&mut self) {
        state().code_used = 0;
    }

    unsafe fn execute(&mut self, code: NativeCode, guest: &mut GuestState) -> NativeExit {
        state().native = true;
        // SAFETY: the engine passes installed system-mode block code.
        let exit = unsafe { stela_enter_block(guest, code.0) };
        let state = state();
        state.native = false;
        if exit.kind == FAULT_KIND
            && let Some(recorded) = state.recorded.take()
        {
            return NativeExit::Fault(NativeFault {
                offset: (recorded.rip - code.0 as u64) as usize,
                address: recorded.address,
                write: recorded.write,
                cause: recorded.cause,
            });
        }
        NativeExit::Exit {
            next_pc: exit.next_pc,
            kind: exit.kind,
        }
    }

    fn set_regime(&mut self, regime: &Regime) {
        let state = state();
        if state
            .regime
            .is_some_and(|current| current.controls != regime.controls)
        {
            state.reset_shadow();
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
        };
        if state.current != view {
            state.current = view;
            load_root(state.roots[view]);
        }
    }

    fn invalidate_translations(&mut self) {
        state().reset_shadow();
    }

    fn counter(&mut self) -> u64 {
        let state = state();
        let ticks = rdtsc() - state.tsc_base;
        (u128::from(ticks) * u128::from(COUNTER_HZ) / u128::from(state.tsc_hz)) as u64
    }

    fn arm_timer(&mut self, deadline: Option<u64>) {
        let now = self.counter();
        let state = state();
        let Some(deadline) = deadline else {
            state.apic.write(APIC_INITIAL, 0);
            return;
        };
        let guest = deadline.saturating_sub(now).max(1);
        let ticks = u128::from(guest) * u128::from(state.apic.hz) / u128::from(COUNTER_HZ);
        let ticks = ticks.clamp(1, u128::from(u32::MAX)) as u32;
        state.apic.write(APIC_LVT_TIMER, u32::from(TIMER_VECTOR));
        state.apic.write(APIC_INITIAL, ticks);
    }

    fn wait_for_interrupt(&mut self) {
        HOST_INTERRUPT.store(false, Ordering::Relaxed);
        // SAFETY: STI's interrupt shadow covers HLT, so no wake-up is lost.
        unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    }

    fn report(&mut self, event: &stela_runtime::machine::Event) {
        super::report(event);
    }
}
