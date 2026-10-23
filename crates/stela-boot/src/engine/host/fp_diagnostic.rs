//! Authored actual native-entry/context/#UD recovery FP qualification.
//! No ARM image is modified, no target is widened and no result is fabricated
//! from a copied frame. Run only before production frames/artifacts are lent.
use super::{BareHost, native_return, state};
use crate::output;
use core::{arch::global_asm, mem::offset_of, ptr};
use stela_compiler::{GuestState, block::BlockExit, context::ExecutionContext};
use stela_runtime::machine::{FaultCause, Host, NativeExit};

const RETURN_RAX: u64 = 0x1234_5678_9abc_def0;
const RETURN_RDX: u64 = 0x0fed_cba9_8765_4321;
const EXECUTED: u32 = 0x4650_5253;
const SEED_MXCSR: u32 = 0x5fa1;
const SEED_X87_CONTROL: u16 = 0x0b7f;

#[repr(C, align(64))]
struct Image([u8; 512]);
#[repr(C, align(64))]
struct Probe {
    original: Image,
    expected: Image,
    returned: Image,
    result_rax: u64,
    result_rdx: u64,
    gpr_errors: u64,
}

static SEED_VECTOR: [u8; 256] = {
    let mut seed = [0; 256];
    let mut index = 0;
    while index < seed.len() {
        seed[index] = (index as u8).wrapping_mul(17).wrapping_add(7);
        index += 1;
    }
    seed
};
static ZERO: f64 = 0.0;
static MXCSR: u32 = SEED_MXCSR;
static X87_CONTROL: u16 = SEED_X87_CONTROL;

global_asm!(
    r#"
.global stela_native_fp_probe
stela_native_fp_probe:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], rsp
    fxsave64 [rdi + {original}]
    fninit
    fldcw [rip + {x87_control}]
    ldmxcsr [rip + {mxcsr}]
    fld1
    fld1
    fld1
    fld1
    fld1
    fld1
    fld1
    fldz
    .global stela_native_fp_seed_divide
stela_native_fp_seed_divide:
    fdiv qword ptr [rip + {zero}]
    movdqu xmm0, [rip + {seed} + 0]
    movdqu xmm1, [rip + {seed} + 16]
    movdqu xmm2, [rip + {seed} + 32]
    movdqu xmm3, [rip + {seed} + 48]
    movdqu xmm4, [rip + {seed} + 64]
    movdqu xmm5, [rip + {seed} + 80]
    movdqu xmm6, [rip + {seed} + 96]
    movdqu xmm7, [rip + {seed} + 112]
    movdqu xmm8, [rip + {seed} + 128]
    movdqu xmm9, [rip + {seed} + 144]
    movdqu xmm10, [rip + {seed} + 160]
    movdqu xmm11, [rip + {seed} + 176]
    movdqu xmm12, [rip + {seed} + 192]
    movdqu xmm13, [rip + {seed} + 208]
    movdqu xmm14, [rip + {seed} + 224]
    movdqu xmm15, [rip + {seed} + 240]
    fxsave64 [rdi + {expected}]
    // Modern Intel need not update FOP for a masked divide. Seed the actual
    // architectural registers through FXRSTOR, then reobserve with FXSAVE.
    // Expected comparison bytes are that real observation, never a patched
    // report or a claim that the masked divide had to set these fields.
    mov word ptr [rdi + {expected} + 6], 0x435
    lea rax, [rip + stela_native_fp_seed_divide]
    mov [rdi + {expected} + 8], rax
    lea rax, [rip + {zero}]
    mov [rdi + {expected} + 16], rax
    fxrstor64 [rdi + {expected}]
    fxsave64 [rdi + {expected}]
    mov ebp, 0x11111111
    mov ebx, 0x22222222
    mov r12d, 0x33333333
    mov r13d, 0x44444444
    mov r14d, 0x55555555
    mov r15d, 0x66666666
    mov rdi, [rsp + 16]
    mov rsi, [rsp + 8]
    cmp qword ptr [rsp + 32], 0
    jne stela_native_fp_probe_context
    call {enter}
    jmp stela_native_fp_probe_returned
stela_native_fp_probe_context:
    mov rdx, rsi
    mov rsi, [rsp + 24]
    call {enter_context}
stela_native_fp_probe_returned:
    mov r10, [rsp]
    mov [r10 + {result_rax}], rax
    mov [r10 + {result_rdx}], rdx
    fxsave64 [r10 + {returned}]
    xor r9d, r9d
    cmp rbp, 0x11111111
    je stela_native_fp_gpr_1
    or r9d, 1
stela_native_fp_gpr_1:
    cmp rbx, 0x22222222
    je stela_native_fp_gpr_2
    or r9d, 2
stela_native_fp_gpr_2:
    cmp r12, 0x33333333
    je stela_native_fp_gpr_4
    or r9d, 4
stela_native_fp_gpr_4:
    cmp r13, 0x44444444
    je stela_native_fp_gpr_8
    or r9d, 8
stela_native_fp_gpr_8:
    cmp r14, 0x55555555
    je stela_native_fp_gpr_16
    or r9d, 16
stela_native_fp_gpr_16:
    cmp r15, 0x66666666
    je stela_native_fp_gpr_32
    or r9d, 32
stela_native_fp_gpr_32:
    cmp rsp, [rsp + 40]
    je stela_native_fp_stack_ok
    or r9d, 64
stela_native_fp_stack_ok:
    mov [r10 + {gpr_errors}], r9
    fxrstor64 [r10 + {original}]
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

// Baseline-only poison bodies are copied intact into this actual Host's arena.
// Their only architectural guest-frame mutation records that execution reached
// the real callee, independently of return-register or FP comparisons.
.global stela_native_fp_normal
stela_native_fp_normal:
    mov dword ptr [rdi + {guest_reserved}], {executed}
    fninit
    fldz
    sub rsp, 16
    mov dword ptr [rsp], 0x1f80
    ldmxcsr [rsp]
    add rsp, 16
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
    mov rbp, 0xaaaaaaaabbbbbbbb
    mov rbx, 0xccccccccdddddddd
    mov r12, 0xeeeeeeeeffffffff
    mov r13, 0x1111111122222222
    mov r14, 0x3333333344444444
    mov r15, 0x5555555566666666
    mov rax, {return_rax}
    mov rdx, {return_rdx}
    ret
.global stela_native_fp_normal_end
stela_native_fp_normal_end:
.global stela_native_fp_fault
stela_native_fp_fault:
    mov dword ptr [rdi + {guest_reserved}], {executed}
    fninit
    fldz
    sub rsp, 16
    mov dword ptr [rsp], 0x1f80
    ldmxcsr [rsp]
    add rsp, 16
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
    mov rbp, 0xaaaaaaaabbbbbbbb
    mov rbx, 0xccccccccdddddddd
    mov r12, 0xeeeeeeeeffffffff
    mov r13, 0x1111111122222222
    mov r14, 0x3333333344444444
    mov r15, 0x5555555566666666
    mov rax, {return_rax}
    mov rdx, {return_rdx}
    ud2
.global stela_native_fp_fault_end
stela_native_fp_fault_end:
"#,
    original = const offset_of!(Probe, original),
    expected = const offset_of!(Probe, expected),
    returned = const offset_of!(Probe, returned),
    result_rax = const offset_of!(Probe, result_rax),
    result_rdx = const offset_of!(Probe, result_rdx),
    gpr_errors = const offset_of!(Probe, gpr_errors),
    guest_reserved = const offset_of!(GuestState, reserved),
    executed = const EXECUTED,
    return_rax = const RETURN_RAX,
    return_rdx = const RETURN_RDX,
    seed = sym SEED_VECTOR,
    zero = sym ZERO,
    mxcsr = sym MXCSR,
    x87_control = sym X87_CONTROL,
    enter = sym super::stela_enter_block,
    enter_context = sym super::stela_enter_context_block,
);

unsafe extern "sysv64" {
    fn stela_native_fp_probe(
        probe: *mut Probe,
        code: usize,
        guest: *mut GuestState,
        context: *mut ExecutionContext,
        context_abi: u64,
    );
    static stela_native_fp_seed_divide: u8;
    static stela_native_fp_normal: u8;
    static stela_native_fp_normal_end: u8;
    static stela_native_fp_fault: u8;
    static stela_native_fp_fault_end: u8;
}

fn same_legacy(left: &Image, right: &Image) -> bool {
    // Compare defined fields, excluding reserved byte5/FOP[15:11] and the
    // padding in each80-bit x87 slot. XMM0..15 are all architectural.
    left.0[..5] == right.0[..5]
        && u16::from_le_bytes([left.0[6], left.0[7]]) & 0x7ff
            == u16::from_le_bytes([right.0[6], right.0[7]]) & 0x7ff
        && left.0[8..32] == right.0[8..32]
        && (0..8).all(|register| {
            let offset = 32 + register * 16;
            left.0[offset..offset + 10] == right.0[offset..offset + 10]
        }) && left.0[160..416] == right.0[160..416]
}

fn pointer(image: &Image, start: usize) -> u64 {
    u64::from_le_bytes(image.0[start..start + 8].try_into().expect("FXSAVE field"))
}

/// Actual native owner startup diagnostic, before guest frames/artifacts are
/// published. The current physical Host/GS/root, code arena and private stack
/// remain installed until all four actual returns complete. Source-only until
/// a fresh actual run qualifies every case and its meaningful FP pointer seed.
pub(crate) fn check(host: &mut BareHost<'_>) -> Result<(), &'static str> {
    let bodies = [
        (ptr::addr_of!(stela_native_fp_normal), ptr::addr_of!(stela_native_fp_normal_end), false),
        (ptr::addr_of!(stela_native_fp_fault), ptr::addr_of!(stela_native_fp_fault_end), true),
    ];
    for (start, end, faulting) in bodies {
        let bytes = (end as usize).checked_sub(start as usize)
            .filter(|&bytes| bytes != 0 && bytes < 4096)
            .ok_or("native FP fixture source extent differs")?;
        // SAFETY: exact mapped read-only image symbols delimit the authored
        // body, including only baseline instructions and its true RET/UD2.
        let body = unsafe { core::slice::from_raw_parts(start, bytes) };
        let code = host.install(body).map_err(|_| "native FP fixture arena full")?;
        for context_abi in [0, 1] {
            let mut guest = GuestState::default();
            let mut context = ExecutionContext::default();
            let context_before = (context.version, context.bytes, context.memory, context.scalable, context.system);
            let mut expected_guest = guest.clone();
            expected_guest.reserved = EXECUTED;
            let mut probe = Probe {
                original: Image([0; 512]), expected: Image([0; 512]), returned: Image([0; 512]),
                result_rax: 0, result_rdx: 0, gpr_errors: u64::MAX,
            };
            if state().native || state().recorded.is_some() {
                return Err("native FP fixture entered with a live preceding frame");
            }
            state().native = true;
            let entered = super::rdtsc();
            // SAFETY: this actual startup Host owns the installed code/body,
            // retained private GuestState/context/probe and real recovery slot.
            // The wrapper restores the complete caller legacy state before any
            // Rust comparison; it uses no wider instruction or control write.
            unsafe {
                stela_native_fp_probe(&mut probe, code.0, &mut guest, &mut context, context_abi);
            }
            let result = native_return(code, BlockExit { next_pc: probe.result_rax, kind: probe.result_rdx }, entered);
            let fip = pointer(&probe.expected, 8);
            let fdp = pointer(&probe.expected, 16);
            let fop = u16::from_le_bytes([probe.expected.0[6], probe.expected.0[7]]) & 0x7ff;
            output::arguments(format_args!(
                "NATIVE FP context={context_abi} fault={faulting} fip={fip:#x} fdp={fdp:#x} fop={fop:#x} gpr={:#x} rax={:#x} rdx={:#x}\n",
                probe.gpr_errors, probe.result_rax, probe.result_rdx,
            ));
            if fip != ptr::addr_of!(stela_native_fp_seed_divide) as u64
                || fdp != ptr::addr_of!(ZERO) as u64 || fop != 0x435
            {
                return Err("native FP fixture lacks exact meaningful x87 pointer sentinels");
            }
            if guest != expected_guest
                || (context.version, context.bytes, context.memory, context.scalable, context.system) != context_before
                || probe.gpr_errors != 0 || !same_legacy(&probe.expected, &probe.returned)
            {
                return Err("native FP caller state or real callee execution differs");
            }
            if faulting {
                if !matches!(result, NativeExit::Fault(fault) if fault.offset == bytes - 2
                    && fault.cause == FaultCause::InvalidOpcode && !fault.write && fault.address == 0
                    && fault.registers[0] == RETURN_RAX && fault.registers[2] == RETURN_RDX
                    && fault.registers[7] == ptr::from_mut(&mut guest) as u64
                    && (context_abi == 0 || fault.registers[6] == ptr::from_mut(&mut context) as u64))
                {
                    return Err("native FP fixture did not enter actual #UD recovery");
                }
            } else if result != (NativeExit::Exit { next_pc: RETURN_RAX, kind: RETURN_RDX }) {
                return Err("native FP full native return ABI differs");
            }
        }
    }
    host.discard_code();
    Ok(())
}
