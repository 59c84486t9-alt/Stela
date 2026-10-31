//! Linux-only native execution for bounded hardware-reference tests.
//! No guest OS services are supplied. Only faults in the executable
//! ranges of the active test invocation can be converted to a native exit.
use crate::machine::{FaultCause, NativeFault};
use core::{
    arch::global_asm,
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
};
use stela_compiler::{GuestState, block::BlockExit};
const FAULT_KIND: u64 = 0xffff;
const TRAP_INVALID_OPCODE: u16 = 6;
const TRAP_PAGE_FAULT: u16 = 14;
const PAGE_FAULT_WRITE: u32 = 1 << 1;
/// A fault that stopped native code: where, why, and the host GPRs at the
/// faulting instruction, which a block's fault recovery table reads
/// (`stela_compiler::block::FaultRecovery`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFault {
    pub rip: u64,
    pub address: u64,
    pub write: bool,
    /// The x86 exception vector captured by Linux ucontext.
    pub trap: u16,
    pub error_code: u64,
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
            origin: crate::machine::NativeFaultOrigin::Exception,
            offset,
            address: self.address,
            write: self.write,
            cause,
            trap: self.trap,
            error_code: self.error_code,
            spills: stela_compiler::block::HostSpillSnapshot::new(),
            registers: stela_compiler::block::HostGprSnapshot::legacy(self.registers),
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

global_asm!(
    ".global stela_reference_enter",
    "stela_reference_enter:",
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
    ".global stela_reference_recover",
    "stela_reference_recover:",
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
    fn stela_reference_enter(
        state: *mut GuestState,
        code: usize,
        stack: *mut u64,
        block: usize,
    ) -> BlockExit;
    fn stela_reference_recover();
}
/// The signals [`fault_handler`] takes.
const SIGNALS: [i32; 3] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL];
/// The SA_SIGINFO handler each of [`SIGNALS`] had, zero for none.
static PRIOR: [AtomicUsize; SIGNALS.len()] = [const { AtomicUsize::new(0) }; SIGNALS.len()];

extern "C" fn fault_handler(signal: i32, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let recovery = ACTIVE.with(Cell::get);
    // SAFETY: Linux supplies a valid ucontext for SA_SIGINFO. ACTIVE belongs to
    // this thread and is non-null only while its boxed Recovery and code live.
    unsafe {
        let frame = &mut *context.cast::<libc::ucontext_t>();
        let registers = &mut frame.uc_mcontext.gregs;
        let rip = registers[libc::REG_RIP as usize] as u64;
        if let Some(recovery) = recovery.as_mut()
            && recovery.covers(rip)
            && recovery.recorded.is_none()
        {
            let get = |index: i32| registers[index as usize] as u64;
            recovery.recorded = Some(HostFault {
                rip,
                address: get(libc::REG_CR2),
                write: get(libc::REG_ERR) & u64::from(PAGE_FAULT_WRITE) != 0,
                trap: u16::try_from(get(libc::REG_TRAPNO)).unwrap_or(u16::MAX),
                error_code: get(libc::REG_ERR),
                registers: [
                    get(libc::REG_RAX),
                    get(libc::REG_RCX),
                    get(libc::REG_RDX),
                    get(libc::REG_RBX),
                    get(libc::REG_RSP),
                    get(libc::REG_RBP),
                    get(libc::REG_RSI),
                    get(libc::REG_RDI),
                    get(libc::REG_R8),
                    get(libc::REG_R9),
                    get(libc::REG_R10),
                    get(libc::REG_R11),
                    get(libc::REG_R12),
                    get(libc::REG_R13),
                    get(libc::REG_R14),
                    get(libc::REG_R15),
                ],
            });
            registers[libc::REG_RDI as usize] = (&raw mut recovery.stack) as libc::greg_t;
            registers[libc::REG_RIP as usize] =
                stela_reference_recover as *const () as libc::greg_t;
            return;
        }
        // An unrelated host fault keeps its normal behavior: the handler it
        // had, or termination.
        let slot = SIGNALS.iter().position(|&candidate| candidate == signal);
        let prior = slot.map_or(0, |slot| PRIOR[slot].load(Ordering::Relaxed));
        if prior != 0 {
            let prior: extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) =
                core::mem::transmute(prior);
            prior(signal, info, context);
        } else {
            libc::signal(signal, libc::SIG_DFL);
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalInstallError {
    pub errno: i32,
}
impl core::fmt::Display for SignalInstallError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "reference signal setup failed (errno {})",
            self.errno
        )
    }
}
impl core::error::Error for SignalInstallError {}
fn install_handlers() -> Result<(), SignalInstallError> {
    static HANDLERS: std::sync::OnceLock<Result<(), SignalInstallError>> =
        std::sync::OnceLock::new();
    *HANDLERS.get_or_init(|| {
        for (slot, signal) in SIGNALS.into_iter().enumerate() {
            // SAFETY: zero is a valid initial sigaction, SA_SIGINFO selects the
            // matching callback, and sigemptyset initializes its signal mask.
            unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                let mut prior: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = fault_handler as *const () as usize;
                action.sa_flags = libc::SA_SIGINFO;
                if libc::sigemptyset(&raw mut action.sa_mask) != 0
                    || libc::sigaction(signal, &raw const action, &raw mut prior) != 0
                {
                    return Err(SignalInstallError {
                        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                    });
                }
                if prior.sa_flags & libc::SA_SIGINFO != 0 {
                    PRIOR[slot].store(prior.sa_sigaction, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    })
}
/// Runs native block code on the host thread with fault recovery: a
/// SIGSEGV, SIGBUS or SIGILL whose RIP lies in one of its code ranges (all
/// the code a run may reach, chained blocks and thunks too) ends the run at
/// that instruction and is returned. Its recovery slot is allocated once
/// and the run is inlined into its caller with no allocation on any path,
/// as every block entry goes through it: a run that built its slot on the
/// stack, or that boxed the fault it returns, made the reference engine's
/// block entries measurably slower.
pub struct NativeRunner {
    recovery: Box<Recovery>,
    ranges: Vec<(u64, u64)>,
}

impl NativeRunner {
    pub fn new(ranges: Vec<(u64, u64)>) -> Result<Self, SignalInstallError> {
        install_handlers()?;
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
        Ok(runner)
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
    #[allow(
        clippy::result_large_err,
        reason = "fixed captured register bank avoids fault-path allocation"
    )]
    pub unsafe fn run(
        &mut self,
        code: usize,
        state: &mut GuestState,
    ) -> Result<BlockExit, HostFault> {
        // SAFETY: as the caller keeps this function's.
        unsafe { self.run_through(code, 0, state) }
    }

    /// Run `code` as [`Self::run`] does with `block` in RCX, as
    /// [`stela_compiler::x86_64::pinned::entry`] takes the block it runs.
    ///
    /// # Safety
    /// As [`Self::run`], of `code` and `block`.
    #[inline(always)]
    #[allow(
        clippy::result_large_err,
        reason = "fixed captured register bank avoids fault-path allocation"
    )]
    pub unsafe fn run_through(
        &mut self,
        code: usize,
        block: usize,
        state: &mut GuestState,
    ) -> Result<BlockExit, HostFault> {
        let recovery: *mut Recovery = &mut *self.recovery;
        ACTIVE.with(|active| {
            assert!(active.get().is_null(), "nested reference native invocation");
            active.set(recovery);
        });
        // SAFETY: the caller passes block code; the recovery slot and the
        // ranges it points to outlive the run.
        let exit = unsafe { stela_reference_enter(state, code, &raw mut (*recovery).stack, block) };
        ACTIVE.with(|active| active.set(core::ptr::null_mut()));
        if exit.kind == FAULT_KIND
            && let Some(fault) = self.recovery.recorded.take()
        {
            return Err(fault);
        }
        Ok(exit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::platform::Mapping;

    #[test]
    fn normal_return_and_fault_recovery_reuse_the_owned_slot() {
        // SysV block ABI: return its two-word BlockExit in RAX/RDX.
        let normal = Mapping::new(&[0xb8, 42, 0, 0, 0, 0xba, 3, 0, 0, 0, 0xc3]).unwrap();
        // Clobber the guest-state argument before UD2. Recovery must use its
        // separate pinned slot, never the interrupted RDI as a state pointer.
        let invalid = Mapping::new(&[0xbf, 0x23, 0x01, 0, 0, 0x0f, 0x0b]).unwrap();
        let start = invalid.entry() as u64;
        let mut runner = NativeRunner::new(vec![(start, start + 7)]).unwrap();
        let mut state = GuestState::default();
        state.x[0] = 0xfeed;
        let original = state.clone();
        for _ in 0..3 {
            // SAFETY: both owned mappings contain bounded test block-ABI code;
            // only UD2 faults, and its full executable extent is held.
            let fault = unsafe { runner.run(invalid.entry(), &mut state) }.unwrap_err();
            assert_eq!(fault.trap, TRAP_INVALID_OPCODE);
            assert_eq!(fault.rip, start + 5);
            assert_eq!(fault.registers[7], 0x123);
            assert_eq!(fault.check_cause(), Some(FaultCause::InvalidOpcode));
            assert_eq!(state, original);
            // SAFETY: this block writes only its return registers.
            let returned = unsafe { runner.run(normal.entry(), &mut state) }.unwrap();
            assert_eq!((returned.next_pc, returned.kind), (42, 3));
            assert_eq!(state, original);
        }
    }

    #[test]
    fn page_fault_captures_exact_access_and_legacy_registers() {
        // MOV EAX,0; MOV RAX,[RAX]. No host object lives at the null page.
        let code = Mapping::new(&[0xb8, 0, 0, 0, 0, 0x48, 0x8b, 0x00]).unwrap();
        let start = code.entry() as u64;
        let mut runner = NativeRunner::new(vec![(start, start + 8)]).unwrap();
        let mut state = GuestState::default();
        // SAFETY: the only memory operand is the intentional null read in this
        // mapping; Linux delivers its fault to the bounded runner.
        let fault = unsafe { runner.run(code.entry(), &mut state) }.unwrap_err();
        assert_eq!(
            (fault.trap, fault.rip, fault.address, fault.write),
            (14, start + 5, 0, false)
        );
        assert_eq!(fault.registers[0], 0);
        assert_eq!(fault.check_cause(), None);
        let native = fault.native(5, FaultCause::InvalidOpcode);
        assert_eq!(native.registers.get(0), Some(0));
        assert!(!native.registers.extended_available());
    }
}
