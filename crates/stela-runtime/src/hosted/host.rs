//! The x86-64 macOS process beneath the hosted PE: guest memory is this
//! process's own memory at the same addresses, native blocks run on the
//! calling host thread, and a fault inside native code ends the block
//! precisely through a signal handler, as the bare-metal mount's #PF
//! handler does.
//!
//! The guest's stage 1 is the identity map of [`super::tables`], so a guest
//! physical address is the host virtual address. Native code reaches guest
//! memory directly; the engine's own accesses copy through the kernel
//! (`mach_vm_read_overwrite`, `mach_vm_write`), which refuses an unmapped or
//! protected page instead of faulting the host.
use super::tables::Tables;
use crate::machine::{
    FaultCause, Host, InstallError, NativeCode, NativeExit, NativeFault, Regime,
    mmu::{Fault, FaultKind},
};
use core::{
    arch::global_asm,
    cell::Cell,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_compiler::{GuestState, block::BlockExit};

/// Bytes reserved for native blocks and chain thunks. Chained jumps are
/// rel32, so the arena stays below 2 GiB.
const ARENA_BYTES: usize = 512 << 20;
/// The exit kind the recovery path returns; no block exit uses it.
const FAULT_KIND: u64 = 0xffff;
/// The guest's system counter: 24 MHz, the M2's (`CNTFRQ_EL0`).
pub const COUNTER_HZ: u64 = 24_000_000;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
/// x86 exception vectors in the signal context's `__trapno`.
const TRAP_INVALID_OPCODE: u16 = 6;
const TRAP_PAGE_FAULT: u16 = 14;
/// #PF error code bit 1: the access was a write.
const PAGE_FAULT_WRITE: u32 = 1 << 1;
/// The longest a WFE/WFI wait sleeps before the engine looks again.
const LONGEST_WAIT_NANOSECONDS: u64 = 1_000_000;
const KERN_SUCCESS: i32 = 0;

/// `<i386/_mcontext.h>` `__darwin_x86_exception_state64`.
#[repr(C)]
pub(crate) struct ExceptionState {
    pub(crate) trapno: u16,
    pub(crate) cpu: u16,
    pub(crate) err: u32,
    pub(crate) faultvaddr: u64,
}

/// `<mach/i386/_structs.h>` `__darwin_x86_thread_state64`.
#[repr(C)]
pub(crate) struct ThreadState {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rbp: u64,
    pub(crate) rsp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
    pub(crate) cs: u64,
    pub(crate) fs: u64,
    pub(crate) gs: u64,
}

/// The leading `__darwin_mcontext64` fields the handler reads and redirects.
#[repr(C)]
pub(crate) struct MachineContext {
    pub(crate) exception: ExceptionState,
    pub(crate) thread: ThreadState,
}

/// `<sys/_types/_ucontext.h>` `__darwin_ucontext` (LP64).
#[repr(C)]
pub(crate) struct UserContext {
    pub(crate) onstack: i32,
    pub(crate) sigmask: u32,
    pub(crate) stack_pointer: u64,
    pub(crate) stack_size: u64,
    pub(crate) stack_flags: i32,
    pub(crate) link: u64,
    pub(crate) machine_context_size: u64,
    pub(crate) machine_context: *mut MachineContext,
}

/// A fault that stopped native code: where, why, and the host GPRs at the
/// faulting instruction, which a block's fault recovery table reads
/// (`stela_compiler::block::FaultRecovery`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFault {
    pub rip: u64,
    pub address: u64,
    pub write: bool,
    /// The x86 exception vector (`__trapno`).
    pub trap: u16,
    /// RAX through R15, by x86 register number.
    pub registers: [u64; 16],
}

impl HostFault {
    /// The cause of a fault other than a page fault; a page fault's guest
    /// fault is the host's translation to decide.
    pub fn check_cause(&self) -> Option<FaultCause> {
        match self.trap {
            TRAP_PAGE_FAULT => None,
            TRAP_INVALID_OPCODE => Some(FaultCause::InvalidOpcode),
            // #GP and anything else: a non-canonical guest address.
            _ => Some(FaultCause::NonCanonical),
        }
    }

    /// The fault as the engine takes it, at `offset` in the entered code.
    pub fn native(&self, offset: usize, cause: FaultCause) -> NativeFault {
        NativeFault {
            offset,
            address: self.address,
            write: self.write,
            cause,
            registers: self.registers,
        }
    }
}

/// The native run in progress on this host thread: its recovery stack, the
/// code ranges whose faults end it, and the fault that did. The handler
/// finds it through [`ACTIVE`].
struct Recovery {
    /// RSP after the entry pushed the callee-saved registers; the recovery
    /// path returns from there.
    stack: u64,
    ranges: *const (u64, u64),
    count: usize,
    recorded: Option<HostFault>,
}

impl Recovery {
    fn covers(&self, rip: u64) -> bool {
        // SAFETY: the ranges of the run in progress, which outlive it.
        let ranges = unsafe { core::slice::from_raw_parts(self.ranges, self.count) };
        ranges
            .iter()
            .any(|&(start, end)| (start..end).contains(&rip))
    }
}

std::thread_local! {
    static ACTIVE: Cell<*mut Recovery> = const { Cell::new(core::ptr::null_mut()) };
}

static HANDLERS: AtomicBool = AtomicBool::new(false);

global_asm!(
    ".global _stela_hosted_enter",
    "_stela_hosted_enter:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rdx], rsp",
    "call rsi",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".global _stela_hosted_recover",
    "_stela_hosted_recover:",
    "mov rsp, [rdi]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "xor eax, eax",
    "mov edx, 0xffff",
    "ret",
);

unsafe extern "sysv64" {
    fn stela_hosted_enter(state: *mut GuestState, code: usize, stack: *mut u64) -> BlockExit;
    fn stela_hosted_recover();
}

/// SIGSEGV, SIGBUS and SIGILL: inside native code, end the block at the
/// faulting instruction; elsewhere the host's default action follows.
extern "C" fn fault_handler(signal: i32, _info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let recovery = ACTIVE.with(Cell::get);
    // SAFETY: the kernel passes a valid ucontext; ACTIVE is set only while
    // this thread runs native code with that Recovery alive.
    unsafe {
        let context = &mut *(context as *mut UserContext);
        let machine = &mut *context.machine_context;
        let rip = machine.thread.rip;
        if let Some(recovery) = recovery.as_mut()
            && recovery.covers(rip)
            && recovery.recorded.is_none()
        {
            let thread = &machine.thread;
            recovery.recorded = Some(HostFault {
                rip,
                address: machine.exception.faultvaddr,
                write: machine.exception.err & PAGE_FAULT_WRITE != 0,
                trap: machine.exception.trapno,
                registers: [
                    thread.rax, thread.rcx, thread.rdx, thread.rbx, thread.rsp, thread.rbp,
                    thread.rsi, thread.rdi, thread.r8, thread.r9, thread.r10, thread.r11,
                    thread.r12, thread.r13, thread.r14, thread.r15,
                ],
            });
            machine.thread.rdi = &raw mut recovery.stack as u64;
            machine.thread.rip = stela_hosted_recover as *const () as u64;
            return;
        }
        // Not ours: take the default action at the same instruction.
        libc::signal(signal, libc::SIG_DFL);
    }
}

/// Runs native block code on the host thread with fault recovery: a
/// SIGSEGV, SIGBUS or SIGILL whose RIP lies in one of its code ranges (all
/// the code a run may reach, chained blocks and thunks too) ends the run at
/// that instruction and is returned. Its recovery slot is allocated once
/// and the run is inlined into its caller with no allocation on any path,
/// as every block entry goes through it: a run that built its slot on the
/// stack, or that boxed the fault it returns, made the hosted engine's
/// block entries measurably slower.
pub struct NativeRunner {
    recovery: Box<Recovery>,
    ranges: Vec<(u64, u64)>,
}

impl NativeRunner {
    pub fn new(ranges: Vec<(u64, u64)>) -> Self {
        install_handlers();
        let mut runner = Self {
            recovery: Box::new(Recovery {
                stack: 0,
                ranges: core::ptr::null(),
                count: 0,
                recorded: None,
            }),
            ranges: Vec::new(),
        };
        runner.set_ranges(ranges);
        runner
    }

    /// Replace the code ranges whose faults end a run.
    pub fn set_ranges(&mut self, ranges: Vec<(u64, u64)>) {
        self.ranges = ranges;
        self.recovery.ranges = self.ranges.as_ptr();
        self.recovery.count = self.ranges.len();
    }

    /// Run the native block code at `code` on `state` on this thread: its
    /// exit, or the fault that ended it.
    ///
    /// # Safety
    /// `code` must be native code for the system-mode block ABI, whose
    /// memory accesses either succeed or fault inside the runner's ranges.
    #[inline(always)]
    // Inlined, the fault moves straight into the caller's exit.
    #[allow(clippy::result_large_err)]
    pub unsafe fn run(
        &mut self,
        code: usize,
        state: &mut GuestState,
    ) -> Result<BlockExit, HostFault> {
        let recovery: *mut Recovery = &mut *self.recovery;
        ACTIVE.with(|active| active.set(recovery));
        // SAFETY: the caller passes block code; the recovery slot and the
        // ranges it points to outlive the run.
        let exit = unsafe { stela_hosted_enter(state, code, &raw mut (*recovery).stack) };
        ACTIVE.with(|active| active.set(core::ptr::null_mut()));
        if exit.kind == FAULT_KIND
            && let Some(fault) = self.recovery.recorded.take()
        {
            return Err(fault);
        }
        Ok(exit)
    }
}

fn install_handlers() {
    if HANDLERS.swap(true, Ordering::AcqRel) {
        return;
    }
    for signal in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
        // SAFETY: a zeroed sigaction with a SA_SIGINFO handler.
        unsafe {
            let mut action: libc::sigaction = core::mem::zeroed();
            action.sa_sigaction = fault_handler as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, core::ptr::null_mut());
        }
    }
}

/// `mach_vm_read_overwrite`/`mach_vm_write`/`mach_vm_region` on this task.
mod kernel {
    unsafe extern "C" {
        pub fn mach_vm_read_overwrite(
            task: u32,
            address: u64,
            size: u64,
            data: u64,
            out: *mut u64,
        ) -> i32;
        pub fn mach_vm_write(task: u32, address: u64, data: usize, count: u32) -> i32;
    }
}

/// `mach_timebase_info_data_t`.
#[repr(C)]
struct Timebase {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_absolute_time() -> u64;
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut Timebase) -> i32;
}

/// This task's port name (`mach_task_self()`).
pub fn task() -> u32 {
    // SAFETY: libSystem initializes the name before any Rust code runs.
    unsafe { mach_task_self_ }
}

/// The host's `mach_timebase_info` numerator and denominator.
pub fn timebase() -> (u32, u32) {
    let mut info = Timebase { numer: 0, denom: 0 };
    // SAFETY: the out-parameter is this frame's.
    unsafe { mach_timebase_info(&raw mut info) };
    (info.numer, info.denom)
}

/// The host's `mach_continuous_time`, in nanoseconds on x86.
pub fn continuous_nanoseconds() -> u64 {
    // SAFETY: no arguments.
    unsafe { mach_continuous_time() }
}

/// Copy `buffer.len()` bytes of this process's memory at `address`, or
/// false when any page is unmapped or unreadable.
pub fn copy_in(address: u64, buffer: &mut [u8]) -> bool {
    if buffer.is_empty() {
        return true;
    }
    let mut copied = 0u64;
    // SAFETY: the kernel copies into the distinct buffer and checks the source.
    let status = unsafe {
        kernel::mach_vm_read_overwrite(
            task(),
            address,
            buffer.len() as u64,
            buffer.as_mut_ptr() as u64,
            &mut copied,
        )
    };
    status == KERN_SUCCESS && copied == buffer.len() as u64
}

/// Write `data` to this process's memory at `address`, or false when any
/// page is unmapped or not writable.
pub fn copy_out(address: u64, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let Ok(count) = u32::try_from(data.len()) else {
        return false;
    };
    // SAFETY: the kernel checks the destination's mapping and protection.
    let status = unsafe { kernel::mach_vm_write(task(), address, data.as_ptr() as usize, count) };
    status == KERN_SUCCESS
}

/// The guest's counter at host time `nanoseconds` of `mach_absolute_time`,
/// whose x86 timebase is 1/1.
pub fn counter_at(nanoseconds: u64) -> u64 {
    (u128::from(nanoseconds) * u128::from(COUNTER_HZ) / u128::from(NANOSECONDS_PER_SECOND)) as u64
}

/// Host nanoseconds for guest counter value `ticks`.
pub fn nanoseconds_at(ticks: u64) -> u64 {
    (u128::from(ticks) * u128::from(NANOSECONDS_PER_SECOND) / u128::from(COUNTER_HZ)) as u64
}

pub fn host_nanoseconds() -> u64 {
    // SAFETY: no arguments; x86 macOS reports nanoseconds.
    unsafe { mach_absolute_time() }
}

/// The host of one hosted PE, owned by the host thread that runs it: its
/// native code arena and fault recovery are that thread's alone.
pub struct ProcessHost {
    arena: *mut u8,
    used: usize,
    tables: std::sync::Arc<Tables>,
    deadline: Option<u64>,
    runner: NativeRunner,
    /// The process's translation store, if it has one.
    translations: Option<super::translations::Store>,
    /// Where this thread's IC invalidations reach the other threads,
    /// whose engines keep compiled code of their own.
    peers: Option<Box<dyn FnMut(Option<u64>) + Send>>,
}

impl ProcessHost {
    pub fn new(tables: std::sync::Arc<Tables>) -> anyhow::Result<Self> {
        // SAFETY: a fresh private anonymous mapping the host never shares.
        let arena = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                ARENA_BYTES,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        anyhow::ensure!(
            arena != libc::MAP_FAILED,
            "cannot map the native code arena: {}",
            std::io::Error::last_os_error()
        );
        let start = arena as u64;
        Ok(Self {
            arena: arena.cast(),
            used: 0,
            tables,
            deadline: None,
            // Installed blocks, chained ones and thunks lie in the arena.
            runner: NativeRunner::new(vec![(start, start + ARENA_BYTES as u64)]),
            translations: super::translations::Store::open(),
            peers: None,
        })
    }

    /// Reach the process's other threads with this thread's IC
    /// invalidations through `peers`, given the page (`None` for all).
    pub fn set_peers(&mut self, peers: Box<dyn FnMut(Option<u64>) + Send>) {
        self.peers = Some(peers);
    }

    pub fn tables(&self) -> &Tables {
        &self.tables
    }

    /// Classify a native fault the way the guest's translation would have:
    /// an unmapped page is a level-3 translation fault and a mapped page
    /// without the access's permission a level-3 permission fault.
    fn classify(fault: &HostFault) -> FaultCause {
        fault.check_cause().unwrap_or_else(|| {
            let kind = if super::memory::mapped(fault.address) {
                FaultKind::Permission
            } else {
                FaultKind::Translation
            };
            FaultCause::Guest(Fault {
                kind,
                level: 3,
                second_stage: None,
            })
        })
    }
}

impl Drop for ProcessHost {
    fn drop(&mut self) {
        // SAFETY: the arena this host mapped; no native run is in progress.
        unsafe { libc::munmap(self.arena.cast(), ARENA_BYTES) };
    }
}

impl Host for ProcessHost {
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        self.tables.read(physical, buffer) || copy_in(physical, buffer)
    }

    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        !self.tables.contains(physical, data.len()) && copy_out(physical, data)
    }

    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        let offset = self.used.next_multiple_of(16);
        let end = offset + code.len();
        if end > ARENA_BYTES {
            return Err(InstallError::Full);
        }
        // SAFETY: arena bytes no native run executes while the engine installs.
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.arena.add(offset), code.len());
        }
        self.used = end;
        Ok(NativeCode(self.arena as usize + offset))
    }

    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        let offset = code.0 - self.arena as usize;
        assert!(
            offset + bytes.len() <= self.used,
            "a patch outside the installed code"
        );
        // SAFETY: installed arena bytes; no native run is in progress.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.arena.add(offset), bytes.len());
        }
    }

    fn discard_code(&mut self) {
        self.used = 0;
    }

    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        // SAFETY: the engine passes installed system-mode block code, which
        // with its chained blocks and thunks lies in the arena.
        match unsafe { self.runner.run(code.0, state) } {
            Ok(exit) => NativeExit::Exit {
                next_pc: exit.next_pc,
                kind: exit.kind,
            },
            Err(fault) => NativeExit::Fault(fault.native(
                fault.rip.wrapping_sub(code.0 as u64) as usize,
                Self::classify(&fault),
            )),
        }
    }

    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        // Installed code is callable where it lies in the arena.
        Some(code.0)
    }

    fn set_regime(&mut self, _regime: &Regime) {}

    fn invalidate_translations(&mut self) {}

    fn code_invalidated(&mut self, page: Option<u64>) {
        if let Some(peers) = &mut self.peers {
            peers(page);
        }
    }

    fn translations(&mut self) -> Option<&mut dyn crate::machine::Translations> {
        self.translations
            .as_mut()
            .map(|store| store as &mut dyn crate::machine::Translations)
    }

    fn counter(&mut self) -> u64 {
        counter_at(host_nanoseconds())
    }

    fn arm_timer(&mut self, deadline: Option<u64>) {
        self.deadline = deadline;
    }

    fn wait_for_interrupt(&mut self) {
        let now = self.counter();
        let wait = self
            .deadline
            .map_or(LONGEST_WAIT_NANOSECONDS, |deadline| {
                nanoseconds_at(deadline.saturating_sub(now))
            })
            .clamp(1, LONGEST_WAIT_NANOSECONDS);
        std::thread::sleep(std::time::Duration::from_nanos(wait));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_conversion_is_the_24_mhz_timebase() {
        assert_eq!(counter_at(NANOSECONDS_PER_SECOND), COUNTER_HZ);
        assert_eq!(counter_at(125), 3);
        assert_eq!(nanoseconds_at(3), 125);
        assert_eq!(nanoseconds_at(COUNTER_HZ), NANOSECONDS_PER_SECOND);
    }

    #[test]
    fn copies_refuse_unmapped_memory_and_follow_mapped_memory() {
        let mut word = [0u8; 8];
        assert!(!copy_in(0x10, &mut word));
        assert!(!copy_out(0x10, &word));
        let mut source = [1u8, 2, 3, 4];
        let address = source.as_mut_ptr() as u64;
        assert!(copy_in(address, &mut word[..4]));
        assert_eq!(&word[..4], &source);
        assert!(copy_out(address, &[9, 8]));
        assert_eq!(source[..2], [9, 8]);
    }
}
