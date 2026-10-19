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
    "_stela_host_syscall:",
    "push rbx",
    "push r12",
    "mov r12, rdx",
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
    "syscall",
    "setc cl",
    "movzx ecx, cl",
    "mov [r12], rax",
    "mov [r12 + 8], rdx",
    "mov [r12 + 16], rcx",
    "add rsp, 24",
    "pop r12",
    "pop rbx",
    "ret",
);

unsafe extern "sysv64" {
    fn stela_host_syscall(selector: u64, arguments: *const u64, results: *mut u64);
}

fn call(selector: u64, arguments: &[u64]) -> Returned {
    let mut padded = [0u64; MAX_ARGUMENTS];
    padded[..arguments.len()].copy_from_slice(arguments);
    let mut results = [0u64; 3];
    // SAFETY: the guest's own request; its pointers are this process's
    // memory and the kernel validates every one of them.
    unsafe { stela_host_syscall(selector, padded.as_ptr(), results.as_mut_ptr()) };
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

/// Mach trap `index` (the guest's `-x16`), returning its kern_return_t or
/// port name in `rax`.
pub fn mach(index: u32, arguments: &[u64]) -> Returned {
    assert!(arguments.len() <= MAX_ARGUMENTS);
    call(CLASS_MACH << CLASS_SHIFT | u64::from(index), arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GETPID: u16 = 20;
    const CLOSE: u16 = 6;
    const EBADF: u64 = 9;
    const TASK_SELF_TRAP: u32 = 28;

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
}
