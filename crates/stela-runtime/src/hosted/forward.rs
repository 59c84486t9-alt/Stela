//! Calls into the x86-64 host kernel with a guest call's own arguments.
//!
//! XNU's x86-64 `syscall` entry selects the class from RAX bits 31:24 (1
//! Mach, 2 BSD) and the call from its low bits, takes six arguments in RDI,
//! RSI, RDX, R10, R8 and R9 and copies any further ones from the user stack
//! above the return-address slot (`osfmk/i386/bsd_i386.c`
//! `mach_call_munger64`, `bsd/dev/i386/systemcalls.c` `unix_syscall64`).
//! A BSD error sets CF with the errno in RAX; success returns RAX and RDX
//! munged by return type exactly as arm64 munges X0 and X1
//! (`arm_prepare_u64_syscall_return`), so a forwarded result needs no
//! conversion. Guest pointers are host pointers in this process.
use core::arch::global_asm;

pub const MAX_ARGUMENTS: usize = 8;
const CLASS_SHIFT: u32 = 24;
const CLASS_MACH: u64 = 1;
const CLASS_UNIX: u64 = 2;

/// One host call's result registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Returned {
    pub rax: u64,
    pub rdx: u64,
    /// CF: a BSD call failed and `rax` is its errno.
    pub carry: bool,
}

global_asm!(
    ".global _stela_host_syscall",
    ".global _stela_host_syscall_ready",
    ".global _stela_host_syscall_instruction",
    ".global _stela_host_syscall_done",
    "_stela_host_syscall:",
    "push rbx",
    "push r12",
    "push r13",
    "mov r12, rdx",
    "mov r13, rcx",
    "mov rax, rdi",
    "mov rbx, rsi",
    // Arguments seven and eight above the return-address slot.
    "sub rsp, 24",
    "mov rcx, [rbx + 48]",
    "mov [rsp + 8], rcx",
    "mov rcx, [rbx + 56]",
    "mov [rsp + 16], rcx",
    "mov rdi, [rbx]",
    "mov rsi, [rbx + 8]",
    "mov rdx, [rbx + 16]",
    "mov r10, [rbx + 24]",
    "mov r8, [rbx + 32]",
    "mov r9, [rbx + 40]",
    // From here to the call, a signal for a guest handler skips the call
    // (`interruptible`), and so does a set interrupt flag.
    "_stela_host_syscall_ready:",
    "test r13, r13",
    "jz 2f",
    "cmp byte ptr [r13], 0",
    "jne 3f",
    "2:",
    "_stela_host_syscall_instruction:",
    "syscall",
    "_stela_host_syscall_done:",
    "setc cl",
    "movzx ecx, cl",
    "mov [r12], rax",
    "mov [r12 + 8], rdx",
    "mov [r12 + 16], rcx",
    "add rsp, 24",
    "pop r13",
    "pop r12",
    "pop rbx",
    "ret",
    "3:",
    "mov rax, -1",
    "stc",
    "jmp _stela_host_syscall_done",
);

unsafe extern "sysv64" {
    fn stela_host_syscall(
        selector: u64,
        arguments: *const u64,
        results: *mut u64,
        interrupt: *const u8,
    );
    fn stela_host_syscall_ready();
    fn stela_host_syscall_instruction();
    fn stela_host_syscall_done();
}

/// The result of a BSD call skipped or restarted for a signal (XNU
/// `ERESTART`, -1): the guest repeats the call after its handler runs.
pub const ERESTART: u64 = u64::MAX;

/// Where a host signal handler finds an interruptible call: the stub's
/// instructions from its interrupt-flag check through the `syscall`, and
/// the instruction after it. R13 holds the call's interrupt flag, zero for
/// an uninterruptible call.
#[derive(Debug, Clone, Copy)]
pub struct Interruptible {
    pub ready: u64,
    pub instruction: u64,
    pub done: u64,
}

/// The stub's interruptible window. A host signal handler that finds RIP
/// in `ready..=instruction` with a nonzero R13 and a BSD selector in RAX
/// may move RIP to `done` with RAX [`ERESTART`] and CF set: the call has
/// not entered the host kernel, or the host kernel rewound it to restart
/// it (`pal_syscall_restart`), so the guest repeats it after its handler.
pub fn interruptible() -> Interruptible {
    Interruptible {
        ready: stela_host_syscall_ready as *const () as u64,
        instruction: stela_host_syscall_instruction as *const () as u64,
        done: stela_host_syscall_done as *const () as u64,
    }
}

/// Whether `rax` holds a BSD call's selector.
pub fn is_bsd_selector(rax: u64) -> bool {
    (rax >> CLASS_SHIFT) & 0xff == CLASS_UNIX
}

fn call(selector: u64, arguments: &[u64]) -> Returned {
    call_with(selector, arguments, core::ptr::null())
}

fn call_with(selector: u64, arguments: &[u64], interrupt: *const u8) -> Returned {
    let mut padded = [0u64; MAX_ARGUMENTS];
    padded[..arguments.len()].copy_from_slice(arguments);
    let mut results = [0u64; 3];
    // SAFETY: the guest's own request; its pointers are this process's
    // memory and the kernel validates every one of them.
    unsafe { stela_host_syscall(selector, padded.as_ptr(), results.as_mut_ptr(), interrupt) };
    Returned {
        rax: results[0],
        rdx: results[1],
        carry: results[2] != 0,
    }
}

/// BSD call `number` with up to eight arguments.
pub fn bsd(number: u16, arguments: &[u64]) -> Returned {
    assert!(arguments.len() <= MAX_ARGUMENTS);
    call(CLASS_UNIX << CLASS_SHIFT | u64::from(number), arguments)
}

/// BSD call `number` on behalf of the guest: skipped with [`ERESTART`]
/// while `interrupt` is set, or when a signal for a guest handler arrives
/// before the host kernel takes it.
pub fn bsd_interruptible(number: u16, arguments: &[u64], interrupt: *const u8) -> Returned {
    assert!(arguments.len() <= MAX_ARGUMENTS);
    call_with(
        CLASS_UNIX << CLASS_SHIFT | u64::from(number),
        arguments,
        interrupt,
    )
}

/// Mach trap `index` (the guest's `-x16`), returning its kern_return_t or
/// port name in `rax`.
pub fn mach(index: u32, arguments: &[u64]) -> Returned {
    assert!(arguments.len() <= MAX_ARGUMENTS);
    call(CLASS_MACH << CLASS_SHIFT | u64::from(index), arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::darwin::{EBADF, TASK_SELF_TRAP};

    const GETPID: u16 = 20;
    const CLOSE: u16 = 6;

    #[test]
    fn host_calls_return_results_and_errors() {
        let pid = bsd(GETPID, &[]);
        assert!(!pid.carry);
        assert_eq!(pid.rax, u64::from(std::process::id()));
        let close = bsd(CLOSE, &[u64::MAX >> 33]);
        assert!(close.carry);
        assert_eq!(close.rax, EBADF);
        let task = crate::hosted::host::task();
        assert_eq!(mach(TASK_SELF_TRAP, &[]).rax as u32, task);
    }

    #[test]
    fn a_set_interrupt_flag_skips_the_call() {
        let flag = core::sync::atomic::AtomicU8::new(1);
        let skipped = bsd_interruptible(GETPID, &[], flag.as_ptr());
        assert!(skipped.carry);
        assert_eq!(skipped.rax, ERESTART);
        flag.store(0, core::sync::atomic::Ordering::SeqCst);
        let pid = bsd_interruptible(GETPID, &[], flag.as_ptr());
        assert_eq!((pid.carry, pid.rax), (false, u64::from(std::process::id())));
        let window = interruptible();
        assert!(window.ready < window.instruction && window.instruction < window.done);
        assert!(is_bsd_selector(2 << CLASS_SHIFT | u64::from(GETPID)));
        assert!(!is_bsd_selector(1 << CLASS_SHIFT | 28));
    }
}
