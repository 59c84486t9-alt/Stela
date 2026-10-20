//! Darwin ABI values the hosted kernel's services share: `errno` values,
//! signals and their action flags, descriptor and open flags, kevent flags,
//! Mach message, port-right and `kern_return_t` values and the self-port
//! traps, from the xnu-12377.121.6 headers (`bsd/sys/errno.h`,
//! `bsd/sys/signal.h`, `bsd/sys/fcntl.h`, `bsd/sys/event.h`,
//! `osfmk/mach/message.h`, `port.h`, `kern_return.h`, `vm_prot.h`,
//! `syscall_sw.h`), which hold on both LP64 ABIs, and the host Mach calls
//! the hosted kernel makes through the host's own library (the host task's
//! name is [`super::host::task`]).
//!
//! A value one service alone uses stays in that service's module.

// `errno` values, as a BSD call's X0 when it fails.
pub(crate) const EPERM: u64 = 1;
pub(crate) const ENOENT: u64 = 2;
pub(crate) const ESRCH: u64 = 3;
pub(crate) const EINTR: u64 = 4;
pub(crate) const E2BIG: u64 = 7;
pub(crate) const EBADF: u64 = 9;
pub(crate) const ENOMEM: u64 = 12;
pub(crate) const EACCES: u64 = 13;
pub(crate) const EFAULT: u64 = 14;
pub(crate) const EINVAL: u64 = 22;
pub(crate) const ERANGE: u64 = 34;
pub(crate) const EAGAIN: u64 = 35;
pub(crate) const EALREADY: u64 = 37;
pub(crate) const ENOTSUP: u64 = 45;
pub(crate) const ENOSYS: u64 = 78;
pub(crate) const EBADEXEC: u64 = 85;

/// `MAXPATHLEN`.
pub(crate) const MAX_PATH: usize = 1024;

// Signals and `sigaction` flags.
pub(crate) const SIGKILL: u32 = 9;
pub(crate) const SIGSTOP: u32 = 17;
pub(crate) const SIG_DFL: u64 = 0;
pub(crate) const SIG_IGN: u64 = 1;
pub(crate) const SA_RESTART: u32 = 0x0002;
pub(crate) const SA_NOCLDSTOP: u32 = 0x0008;
pub(crate) const SA_NOCLDWAIT: u32 = 0x0020;

// `fcntl` commands and open flags.
pub(crate) const F_SETFD: u32 = 2;
pub(crate) const F_GETFL: u32 = 3;
pub(crate) const O_RDONLY: u32 = 0;
pub(crate) const O_RDWR: u32 = 2;
pub(crate) const O_ACCMODE: u32 = 3;
pub(crate) const O_CREAT: u32 = 0x200;
pub(crate) const O_CLOEXEC: u32 = 0x0100_0000;

// `struct kevent` flags.
pub(crate) const EV_ADD: u16 = 0x0001;
pub(crate) const EV_DELETE: u16 = 0x0002;
pub(crate) const EV_ENABLE: u16 = 0x0004;
pub(crate) const EV_ONESHOT: u16 = 0x0010;
pub(crate) const EV_CLEAR: u16 = 0x0020;
pub(crate) const EV_ERROR: u16 = 0x4000;

// Mach `kern_return_t` values.
pub(crate) const KERN_SUCCESS: u32 = 0;
pub(crate) const KERN_INVALID_ADDRESS: u32 = 1;
pub(crate) const KERN_INVALID_ARGUMENT: u32 = 4;
pub(crate) const KERN_FAILURE: u32 = 5;
pub(crate) const KERN_NOT_SUPPORTED: u32 = 46;
pub(crate) const MACH_SEND_INVALID_DEST: u32 = 0x1000_0003;

// Mach messages and port rights.
pub(crate) const MACH_SEND_MSG: i32 = 0x1;
pub(crate) const MACH_RCV_MSG: i32 = 0x2;
pub(crate) const MACH_SEND_TIMEOUT: i32 = 0x10;
pub(crate) const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
pub(crate) const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
pub(crate) const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;

/// `VM_PROT_READ | VM_PROT_WRITE`.
pub(crate) const VM_PROT_DEFAULT: u32 = 3;

// Thread states (`osfmk/mach/arm/thread_status.h`, `_structs.h`).
pub(crate) const ARM_DEBUG_STATE64: u32 = 15;
/// `ARM_DEBUG_STATE64_COUNT`, in `natural_t` words.
pub(crate) const DEBUG_STATE64_COUNT: u32 = 130;
/// `__DARWIN_ARM_THREAD_STATE64_FLAGS_*` and the user diversifier field.
pub(crate) const FLAGS_NO_PTRAUTH: u32 = 0x1;
pub(crate) const FLAGS_IB_SIGNED_LR: u32 = 0x2;
pub(crate) const FLAGS_KERNEL_SIGNED_PC: u32 = 0x4;
pub(crate) const FLAGS_KERNEL_SIGNED_LR: u32 = 0x8;
pub(crate) const USER_DIVERSIFIER_MASK: u32 = 0xff00_0000;
/// `ptrauth_string_discriminator` of "pc", "lr", "sp" and "fp", as the
/// arm64e compiler folds them.
pub(crate) const DISCRIMINATOR_PC: u64 = 0x7481;
pub(crate) const DISCRIMINATOR_LR: u64 = 0x77d3;
pub(crate) const DISCRIMINATOR_SP: u64 = 0xcbed;
pub(crate) const DISCRIMINATOR_FP: u64 = 0x4517;
/// `PSR64_NZCV_MASK` (`PSR64_USER_MASK`) and `PSR64_MODE_MASK`.
pub(crate) const PSR64_NZCV_MASK: u32 = 0xf000_0000;
pub(crate) const PSR64_MODE_MASK: u32 = 0x1f;

/// `ptrauth_blend_discriminator(pointer, integer)`, which the compiler
/// lowers to a MOVK of the integer into bits 63:48.
pub(crate) fn blend_discriminator(pointer: u64, integer: u64) -> u64 {
    (integer << 48) | (pointer & 0x0000_ffff_ffff_ffff)
}

/// The CPSR a user thread state `requested` leaves on a thread whose saved
/// CPSR is `current`: NZCV copied, the mode cleared (EL0t), the rest kept
/// (`thread_state64_to_saved_state`).
pub(crate) fn user_cpsr(current: u32, requested: u32) -> u32 {
    (current & !(PSR64_NZCV_MASK | PSR64_MODE_MASK)) | (requested & PSR64_NZCV_MASK)
}

// The self-port traps (`-x16`).
pub(crate) const THREAD_SELF_TRAP: u32 = 27;
pub(crate) const TASK_SELF_TRAP: u32 = 28;
pub(crate) const HOST_SELF_TRAP: u32 = 29;

/// `mach_msg_header_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MessageHeader {
    pub(crate) bits: u32,
    pub(crate) size: u32,
    pub(crate) remote: u32,
    pub(crate) local: u32,
    pub(crate) voucher: u32,
    pub(crate) id: i32,
}

// The host library's Mach calls on the host task.
unsafe extern "C" {
    pub(crate) fn mach_host_self() -> u32;
    pub(crate) fn mach_port_allocate(task: u32, right: u32, name: *mut u32) -> i32;
    pub(crate) fn mach_port_insert_right(task: u32, name: u32, right: u32, kind: u32) -> i32;
    pub(crate) fn mach_port_destruct(task: u32, name: u32, send_delta: i32, guard: u64) -> i32;
    pub(crate) fn mach_msg(
        message: *mut u8,
        option: i32,
        send_size: u32,
        receive_size: u32,
        receive_name: u32,
        timeout: u32,
        notify: u32,
    ) -> i32;
    pub(crate) fn semaphore_create(task: u32, semaphore: *mut u32, policy: i32, value: i32) -> i32;
    pub(crate) fn semaphore_destroy(task: u32, semaphore: u32) -> i32;
    pub(crate) fn semaphore_signal(semaphore: u32) -> i32;
    pub(crate) fn host_request_notification(host: u32, kind: i32, port: u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cpsr_keeps_only_nzcv_from_the_user() {
        assert_eq!(user_cpsr(0x0000_1000, 0xf000_03c5), 0xf000_1000);
        assert_eq!(user_cpsr(0x6000_0000, 0), 0);
    }

    #[test]
    fn a_blend_puts_the_integer_in_the_top_sixteen_bits() {
        assert_eq!(
            blend_discriminator(0xffff_1234_5678_9abc, DISCRIMINATOR_PC),
            0x7481_1234_5678_9abc
        );
    }
}
