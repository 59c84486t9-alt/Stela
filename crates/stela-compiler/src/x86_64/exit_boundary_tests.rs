//! The native boundary a device site's access crosses, run on the host: an
//! entry like the bare-metal host's (`stela_enter_block`) into a device
//! site's stub ([`chain::direct_exit`] with a System exit), which returns at
//! once, and the way back.

use super::{chain, flag_word};
use crate::{GuestAddress, GuestState, block::ExitKind};

// The bare-metal entry with its per-processor words (GS) in a static: the
// callee-saved pushes, the recovery checks, MXCSR, the pinned registers and
// the flag word in and out, the call and the restore.
core::arch::global_asm!(
    r#"
.global stela_test_enter_block
stela_test_enter_block:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    cmp qword ptr [rip + {recovery}], 0
    jne 2f
    ldmxcsr [rip + {mxcsr}]
    mov [rip + {recovery}], rsp
    sub rsp, 8
    mov rax, rsi
    mov ecx, [rdi + {nzcv}]
    shr ecx, {arm_shift}
    imul ecx, ecx, {pack}
    and ecx, {word_mask}
    mov [rdi + {nzcv}], ecx
    mov rbx, [rdi + {sp}]
    mov rsi, [rdi + 64]
    mov r14, [rdi + 152]
    mov r15, [rdi + 0]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 128]
    mov r13, [rdi + 136]
    call rax
    mov [rdi + {sp}], rbx
    mov [rdi + 64], rsi
    mov [rdi + 152], r14
    mov [rdi + 0], r15
    mov [rdi + 8], rbp
    mov [rdi + 128], r12
    mov [rdi + 136], r13
    mov ecx, [rdi + {nzcv}]
    and ecx, {word_mask}
    imul ecx, ecx, {unpack}
    and ecx, {arm_mask}
    mov [rdi + {nzcv}], ecx
    mov rsp, [rip + {recovery}]
    mov qword ptr [rip + {recovery}], 0
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
2:
    ud2
"#,
    sp = const core::mem::offset_of!(GuestState, sp),
    nzcv = const core::mem::offset_of!(GuestState, nzcv),
    arm_shift = const flag_word::ARM_SHIFT,
    pack = const flag_word::PACK_MULTIPLIER,
    unpack = const flag_word::UNPACK_MULTIPLIER,
    word_mask = const flag_word::WORD_MASK,
    arm_mask = const flag_word::ARM_MASK,
    recovery = sym RECOVERY,
    mxcsr = sym MXCSR,
);

static mut RECOVERY: u64 = 0;
static MXCSR: u32 = 0x1f80;

/// What the stub returns: its target and exit word.
#[repr(C)]
struct BlockExit {
    next_pc: u64,
    kind: u64,
}

unsafe extern "sysv64" {
    fn stela_test_enter_block(state: *mut GuestState, code: usize) -> BlockExit;
}

/// Host nanoseconds of one native entry into a device site's stub and the
/// return from it: the part of a trapped device access that is neither the
/// engine's handling (`device_site_cost`) nor the device's. A measurement,
/// not a check:
/// `cargo test --release -p stela-compiler device_site_boundary_cost -- --ignored --nocapture`.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
#[ignore = "manual: opt-in"]
fn device_site_boundary_cost() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    const CALLS: u64 = 10_000_000;
    const PC: u64 = 0x8_0000_0004;
    let stub = chain::direct_exit(GuestAddress(PC), ExitKind::System);
    // SAFETY: private anonymous memory, RX after the copy, unmapped after
    // the calls; the stub touches no memory and returns.
    unsafe {
        let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
        assert_ne!(page as usize, usize::MAX);
        core::ptr::copy_nonoverlapping(stub.as_ptr(), page.cast(), stub.len());
        assert_eq!(mprotect(page, PAGE, 5), 0);
        let mut state = GuestState::default();
        let started = std::time::Instant::now();
        for _ in 0..CALLS {
            let exit = stela_test_enter_block(&mut state, page as usize);
            assert_eq!(exit.next_pc, PC);
        }
        let each = started.elapsed().as_nanos() as f64 / CALLS as f64;
        assert_eq!(munmap(page, PAGE), 0);
        std::println!("DEVICE SITE BOUNDARY ns per entry and exit: {each:.1}");
    }
}
