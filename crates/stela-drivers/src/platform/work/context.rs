//! Actual cooperative x86-64 SysV call continuations. The UEFI caller may use
//! Win64: the switch explicitly retains XMM6..15 because the UEFI soft-float
//! target does not emit their cross-ABI spills. Callbacks keep their declared
//! extern C ABI, never a transmuted one.
use super::WorkError;
use core::arch::{asm, naked_asm};
#[repr(C, align(16))]
pub(super) struct Frame {
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    mxcsr: u32,
    fcw: u16,
    _padding: u16,
    // Win64 nonvolatile SIMD state, saved explicitly even for soft-float Rust.
    xmm: [[u64; 2]; 10],
}
const _: () = {
    assert!(size_of::<Frame>() == 224);
    assert!(core::mem::offset_of!(Frame, mxcsr) == 56);
    assert!(core::mem::offset_of!(Frame, fcw) == 60);
    assert!(core::mem::offset_of!(Frame, xmm) == 64);
};
#[derive(Clone, Copy)]
pub(super) struct Controls {
    pub(super) mxcsr: u32,
    pub(super) fcw: u16,
}
/// Read-only capability/control qualification on the actual native CPL0 CPU.
pub(super) unsafe fn controls() -> Result<Controls, WorkError> {
    let cpuid = core::arch::x86_64::__cpuid(1);
    if cpuid.edx & (7 << 24) != 7 << 24 {
        return Err(WorkError::Unavailable);
    }
    let cr0: u64;
    let cr4: u64;
    // SAFETY: covered by this function's own safety contract.
    unsafe {
        asm!("mov {}, cr0",out(reg) cr0,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr4",out(reg) cr4,options(nomem,nostack,preserves_flags));
    }
    // Kernel shadow stacks require a genuine paired shadow-stack switch;
    // this bounded continuation backend does not supply one.
    if cr0 & 12 != 0 || cr4 & (1 << 9) == 0 || cr4 & (1 << 23) != 0 {
        return Err(WorkError::Unavailable);
    }
    // SAFETY: covered by this function's own safety contract.
    Ok(unsafe { read_controls() })
}
/// Save the actual ABI control state; privileged qualification happens before
/// production construction. Hosted context tests call only this unprivileged
/// component and never attest a native CPU/IRQ provider.
pub(super) unsafe fn read_controls() -> Controls {
    let mut controls = Controls { mxcsr: 0, fcw: 0 };
    // SAFETY: covered by this function's own safety contract.
    unsafe {
        asm!("stmxcsr [{}]",in(reg) &mut controls.mxcsr,options(nostack,preserves_flags));
        asm!("fnstcw [{}]",in(reg) &mut controls.fcw,options(nostack,preserves_flags));
    }
    controls
}
pub(super) fn stack_pointer() -> usize {
    let rsp: usize;
    // SAFETY: reading RSP has no memory or flag effects.
    unsafe {
        asm!("mov {}, rsp",out(reg)rsp,options(nomem,nostack,preserves_flags));
    }
    rsp
}
impl Frame {
    pub(super) fn saved_stack_pointer(&self) -> usize {
        self.rsp as usize
    }
    pub(super) fn new(controls: Controls) -> Self {
        Self {
            rsp: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            mxcsr: controls.mxcsr,
            fcw: controls.fcw,
            _padding: 0,
            xmm: [[0; 2]; 10],
        }
    }
    /// # Safety
    /// Exclusive actual retained stack. Top is 16-byte aligned; no live frame
    /// exists in it. The actual executor/function pointers stay pinned forever
    /// if teardown cannot prove every continuation has stopped.
    pub(super) unsafe fn start(
        &mut self,
        top: usize,
        argument: usize,
        index: usize,
        entry: unsafe extern "sysv64" fn(usize, usize) -> !,
    ) {
        self.rsp = (top - 16) as u64;
        self.r12 = argument as u64;
        self.r13 = index as u64;
        self.r14 = entry as usize as u64;
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            ((top - 16) as *mut usize).write(trampoline as *const () as usize);
            ((top - 8) as *mut usize).write(0);
        }
        // switch's RET consumes the trampoline pointer; task entry receives
        // RSP%16=8 exactly as a normal SysV call. Entry never returns.
    }
}
#[unsafe(naked)]
unsafe extern "sysv64" fn trampoline() -> ! {
    naked_asm!("mov rdi, r12", "mov rsi, r13", "jmp r14");
}
/// Save/restore one actual call continuation. IF remains disabled throughout;
/// caller restores flags only after target RSP/metadata is consistent. This
/// explicit SysV boundary permits caller-saved clobbers. UEFI soft-float does
/// not emit Win64 XMM spills at this boundary, so the actual frame explicitly
/// retains every XMM6..15 lane (SSE2 baseline), including dispatcher state.
/// MXCSR and x87 control are callee-saved and belong to each real task.
#[unsafe(naked)]
pub(super) unsafe extern "sysv64" fn switch(from: *mut Frame, to: *const Frame) {
    naked_asm!(
        "mov [rdi], rsp",
        "mov [rdi+8], rbx",
        "mov [rdi+16], rbp",
        "mov [rdi+24], r12",
        "mov [rdi+32], r13",
        "mov [rdi+40], r14",
        "mov [rdi+48], r15",
        "stmxcsr [rdi+56]",
        "fnstcw [rdi+60]",
        "movdqu [rdi+64], xmm6",
        "movdqu [rdi+80], xmm7",
        "movdqu [rdi+96], xmm8",
        "movdqu [rdi+112], xmm9",
        "movdqu [rdi+128], xmm10",
        "movdqu [rdi+144], xmm11",
        "movdqu [rdi+160], xmm12",
        "movdqu [rdi+176], xmm13",
        "movdqu [rdi+192], xmm14",
        "movdqu [rdi+208], xmm15",
        "mov rbx, [rsi+8]",
        "mov rbp, [rsi+16]",
        "mov r12, [rsi+24]",
        "mov r13, [rsi+32]",
        "mov r14, [rsi+40]",
        "mov r15, [rsi+48]",
        "ldmxcsr [rsi+56]",
        "fldcw [rsi+60]",
        "movdqu xmm6, [rsi+64]",
        "movdqu xmm7, [rsi+80]",
        "movdqu xmm8, [rsi+96]",
        "movdqu xmm9, [rsi+112]",
        "movdqu xmm10, [rsi+128]",
        "movdqu xmm11, [rsi+144]",
        "movdqu xmm12, [rsi+160]",
        "movdqu xmm13, [rsi+176]",
        "movdqu xmm14, [rsi+192]",
        "movdqu xmm15, [rsi+208]",
        "mov rsp, [rsi]",
        "ret",
    );
}
