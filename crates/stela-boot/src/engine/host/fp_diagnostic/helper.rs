//! Real translated-access helper return and abandonment on owned ARM tables.
use super::super::{BareHost, RamRange, load_root, native_return, state};
use super::{Image, Probe, RETURN_RAX, RETURN_RDX, pointer, same_legacy, stela_native_fp_probe};
use alloc::vec::Vec;
use core::{arch::global_asm, mem, mem::offset_of, ptr};
use stela_compiler::{GuestState, block::BlockExit, context::ExecutionContext};
use stela_drivers::bus::dma::memory::{CacheAttribute, CpuMapping, PageSource, PinnedPages};
use stela_runtime::machine::{FaultCause, Host, NativeExit, Regime, engine::Watch, mmu};

const PAGE: usize = 4096;
const TABLE_BASE: u64 = 0x10_0000;
const DATA_PHYSICAL: u64 = TABLE_BASE + 4 * PAGE as u64;
const MAPPED: u64 = 0x4000;
const MISSING: u64 = 0x8000;
const VALUE: u64 = 0x7291_3846_55a4_6302;
const STARTED: u32 = 0x4845_4c50;
const RETURNED: u32 = 0x5245_5455;

#[repr(C, align(64))]
struct Observation {
    expected: Image,
    returned: Image,
    expected_registers: [u64; 16],
    returned_registers: [u64; 16],
    fp_errors: u64,
}

// Own the actual native heap pins/verified WB CPU mapping through the last
// native/helper frame. The original guest RAM is never read or modified.
struct GuestScope {
    _pages: PinnedPages,
    mapping: CpuMapping,
    original_ram: Option<Vec<RamRange>>,
    original_tlb: Option<mmu::translated::Tlb>,
}
impl GuestScope {
    fn new() -> Result<Self, &'static str> {
        if state().native
            || state().recorded.is_some()
            || state().regime.is_some()
            || state().current != usize::MAX
            || state().registered_ram.is_some()
            || state().legacy_translations_dirty
            || state().tag_checks != [false; 2]
        {
            return Err("helper FP diagnostic requires fresh actual startup ownership");
        }
        let pages = crate::native_memory::SOURCE
            .allocate(5 * PAGE, PAGE, CacheAttribute::WriteBack)
            .map_err(|_| "helper FP private page reservation unavailable")?;
        if pages.page_shift() != 12
            || pages.physical_pages().len() != 5
            || !pages
                .physical_pages()
                .windows(2)
                .all(|pair| pair[0].checked_add(PAGE as u64) == Some(pair[1]))
        {
            return Err("helper FP private page geometry differs");
        }
        let mapping = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|_| "helper FP private CPU mapping unavailable")?;
        // Four genuinely owned ARM 4KiB tables followed by one data page.
        // Software walks read them through this same actual RAM reservation.
        for level in 0..3 {
            let table = mapping
                .address(level * PAGE, 8)
                .map_err(|_| "helper FP table bounds")?;
            // SAFETY: exclusive aligned zeroed private pinned page; no other
            // CPU/guest/DMA has access to this authored fixture reservation.
            unsafe {
                table
                    .cast::<u64>()
                    .as_ptr()
                    .write_volatile((TABLE_BASE + (level as u64 + 1) * PAGE as u64) | 3);
            }
        }
        let leaf = mapping
            .address(3 * PAGE + (MAPPED as usize / PAGE) * 8, 8)
            .map_err(|_| "helper FP leaf bounds")?;
        let data = mapping
            .address(4 * PAGE, 8)
            .map_err(|_| "helper FP data bounds")?;
        // SAFETY: same uniquely owned table/data pages; valid privileged RW,
        // AF-set normal-WB leaf, with both execute-never bits set.
        unsafe {
            leaf.cast::<u64>()
                .as_ptr()
                .write_volatile(DATA_PHYSICAL | 3 | (1 << 10) | (3 << 8) | (1 << 53) | (1 << 54));
            data.cast::<u64>().as_ptr().write_volatile(VALUE);
        }
        let mut ram = Vec::new();
        ram.try_reserve_exact(1)
            .map_err(|_| "helper FP RAM metadata unavailable")?;
        ram.push(RamRange {
            guest: TABLE_BASE,
            host: pages.physical_pages()[0],
            bytes: (5 * PAGE) as u64,
        });
        let original_ram = mem::replace(&mut state().ram, ram);
        let original_tlb = mem::take(&mut state().tlb);
        Ok(Self {
            _pages: pages,
            mapping,
            original_ram: Some(original_ram),
            original_tlb: Some(original_tlb),
        })
    }
    fn regime(&self) -> Regime {
        Regime {
            controls: mmu::Controls {
                sctlr: mmu::SCTLR_M | (1 << 2) | (1 << 12),
                tcr: 16 | (16 << 16) | (2 << 30) | (5 << 32),
                ttbr0: TABLE_BASE,
                mair: 0xff,
                ..mmu::Controls::default()
            },
            requester: mmu::Requester {
                el: 1,
                pan: false,
                unprivileged: false,
                guarded: false,
            },
            watch: Watch::default(),
            tag_checks: [false; 2],
        }
    }
}
impl Drop for GuestScope {
    fn drop(&mut self) {
        // No allocation or pin release can bypass a live native/helper frame.
        // A failure here is terminal, retaining this stack and backing.
        assert!(
            !state().native && super::super::local::native_frames_idle(),
            "helper FP private RAM still has a live frame"
        );
        let state = state();
        state.reset_shadow();
        load_root(state.host_root);
        state.current = usize::MAX;
        state.regime = None;
        state.ram = self
            .original_ram
            .take()
            .expect("actual original RAM retained");
        state.tlb = self
            .original_tlb
            .take()
            .expect("actual original TLB retained");
    }
}

// Copied body is position-independent: every data/label reference stays inside
// its exact source extent. The real helper address is supplied through the
// retained private GuestState, never identified by an application/call site.
global_asm!(
    r#"
.global stela_helper_fp_body
stela_helper_fp_body:
    mov rbp, rdi
    mov r12, [rbp + {observation_argument}]
    mov dword ptr [rbp + {guest_reserved}], {started}
    fninit
    fldcw [rip + stela_helper_fp_cw]
    ldmxcsr [rip + stela_helper_fp_mxcsr]
    fld1
    fld1
    fld1
    fld1
    fld1
    fld1
    fld1
    fldz
.global stela_helper_fp_divide
stela_helper_fp_divide:
    fdiv qword ptr [rip + stela_helper_fp_zero]
    movdqu xmm0, [rip + stela_helper_fp_vectors + 0]
    movdqu xmm1, [rip + stela_helper_fp_vectors + 16]
    movdqu xmm2, [rip + stela_helper_fp_vectors + 32]
    movdqu xmm3, [rip + stela_helper_fp_vectors + 48]
    movdqu xmm4, [rip + stela_helper_fp_vectors + 64]
    movdqu xmm5, [rip + stela_helper_fp_vectors + 80]
    movdqu xmm6, [rip + stela_helper_fp_vectors + 96]
    movdqu xmm7, [rip + stela_helper_fp_vectors + 112]
    movdqu xmm8, [rip + stela_helper_fp_vectors + 128]
    movdqu xmm9, [rip + stela_helper_fp_vectors + 144]
    movdqu xmm10, [rip + stela_helper_fp_vectors + 160]
    movdqu xmm11, [rip + stela_helper_fp_vectors + 176]
    movdqu xmm12, [rip + stela_helper_fp_vectors + 192]
    movdqu xmm13, [rip + stela_helper_fp_vectors + 208]
    movdqu xmm14, [rip + stela_helper_fp_vectors + 224]
    movdqu xmm15, [rip + stela_helper_fp_vectors + 240]
    fxsave64 [r12 + {expected}]
    mov word ptr [r12 + {expected} + 6], 0x435
    lea rax, [rip + stela_helper_fp_divide]
    mov [r12 + {expected} + 8], rax
    lea rax, [rip + stela_helper_fp_zero]
    mov [r12 + {expected} + 16], rax
    fxrstor64 [r12 + {expected}]
    fxsave64 [r12 + {expected}]
    mov rbx, 0x1828384858687888
    mov rdx, 0x1929394959697989
    mov rsi, 0x1a2a3a4a5a6a7a8a
    mov r8, 0x1b2b3b4b5b6b7b8b
    mov r9, 0x1c2c3c4c5c6c7c8c
    mov r10, 0x1d2d3d4d5d6d7d8d
    mov r11, 0x1e2e3e4e5e6e7e8e
    mov r13, 0x1f2f3f4f5f6f7f8f
    mov r14, 0x2030405060708090
    mov r15, 0x2131415161718191
    mov rcx, [rbp + {address_argument}]
    mov rax, [rbp + {helper_argument}]
    mov [r12 + {expected_regs} + 0], rax
    mov [r12 + {expected_regs} + 8], rcx
    mov [r12 + {expected_regs} + 16], rdx
    mov [r12 + {expected_regs} + 24], rbx
    mov [r12 + {expected_regs} + 32], rsp
    mov [r12 + {expected_regs} + 40], rbp
    mov [r12 + {expected_regs} + 48], rsi
    mov [r12 + {expected_regs} + 56], rdi
    mov [r12 + {expected_regs} + 64], r8
    mov [r12 + {expected_regs} + 72], r9
    mov [r12 + {expected_regs} + 80], r10
    mov [r12 + {expected_regs} + 88], r11
    mov [r12 + {expected_regs} + 96], r12
    mov [r12 + {expected_regs} + 104], r13
    mov [r12 + {expected_regs} + 112], r14
    mov [r12 + {expected_regs} + 120], r15
    call qword ptr [rax]
.global stela_helper_fp_return
stela_helper_fp_return:
    .byte 8, 0
    mov [r12 + {returned_regs} + 0], rax
    mov [r12 + {returned_regs} + 8], rcx
    mov [r12 + {returned_regs} + 16], rdx
    mov [r12 + {returned_regs} + 24], rbx
    mov [r12 + {returned_regs} + 32], rsp
    mov [r12 + {returned_regs} + 40], rbp
    mov [r12 + {returned_regs} + 48], rsi
    mov [r12 + {returned_regs} + 56], rdi
    mov [r12 + {returned_regs} + 64], r8
    mov [r12 + {returned_regs} + 72], r9
    mov [r12 + {returned_regs} + 80], r10
    mov [r12 + {returned_regs} + 88], r11
    mov [r12 + {returned_regs} + 96], r12
    mov [r12 + {returned_regs} + 104], r13
    mov [r12 + {returned_regs} + 112], r14
    mov [r12 + {returned_regs} + 120], r15
    fxsave64 [r12 + {returned}]
    mov rcx, [rax]
    mov [rbp], rcx
    mov dword ptr [rbp + {guest_reserved}], {done}
    // Compare actual defined FP fields before returning through any Rust.
    mov eax, [r12 + {expected}]
    cmp eax, [r12 + {returned}]
    jne stela_helper_fp_bad
    mov al, [r12 + {expected} + 4]
    cmp al, [r12 + {returned} + 4]
    jne stela_helper_fp_bad
    movzx eax, word ptr [r12 + {expected} + 6]
    xor ax, word ptr [r12 + {returned} + 6]
    test eax, 0x7ff
    jnz stela_helper_fp_bad
    mov rax, [r12 + {expected} + 8]
    cmp rax, [r12 + {returned} + 8]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 16]
    cmp rax, [r12 + {returned} + 16]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 24]
    cmp rax, [r12 + {returned} + 24]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 32]
    cmp rax, [r12 + {returned} + 32]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 40]
    cmp ax, [r12 + {returned} + 40]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 48]
    cmp rax, [r12 + {returned} + 48]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 56]
    cmp ax, [r12 + {returned} + 56]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 64]
    cmp rax, [r12 + {returned} + 64]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 72]
    cmp ax, [r12 + {returned} + 72]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 80]
    cmp rax, [r12 + {returned} + 80]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 88]
    cmp ax, [r12 + {returned} + 88]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 96]
    cmp rax, [r12 + {returned} + 96]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 104]
    cmp ax, [r12 + {returned} + 104]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 112]
    cmp rax, [r12 + {returned} + 112]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 120]
    cmp ax, [r12 + {returned} + 120]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 128]
    cmp rax, [r12 + {returned} + 128]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 136]
    cmp ax, [r12 + {returned} + 136]
    jne stela_helper_fp_bad
    mov rax, [r12 + {expected} + 144]
    cmp rax, [r12 + {returned} + 144]
    jne stela_helper_fp_bad
    mov ax, [r12 + {expected} + 152]
    cmp ax, [r12 + {returned} + 152]
    jne stela_helper_fp_bad
    lea rsi, [r12 + {expected} + 160]
    lea rdi, [r12 + {returned} + 160]
    mov ecx, 32
    cld
    repe cmpsq
    jne stela_helper_fp_bad
    mov qword ptr [r12 + {fp_errors}], 0
    jmp stela_helper_fp_done
stela_helper_fp_bad:
    mov qword ptr [r12 + {fp_errors}], 1
stela_helper_fp_done:
    mov rax, {return_rax}
    mov rdx, {return_rdx}
    ret
.balign 16
stela_helper_fp_vectors:
    .byte 53,82,111,140,169,198,227,0,29,58,87,116,145,174,203,232
    .byte 5,34,63,92,121,150,179,208,237,10,39,68,97,126,155,184
    .byte 213,242,15,44,73,102,131,160,189,218,247,20,49,78,107,136
    .byte 165,194,223,252,25,54,83,112,141,170,199,228,1,30,59,88
    .byte 117,146,175,204,233,6,35,64,93,122,151,180,209,238,11,40
    .byte 69,98,127,156,185,214,243,16,45,74,103,132,161,190,219,248
    .byte 21,50,79,108,137,166,195,224,253,26,55,84,113,142,171,200
    .byte 229,2,31,60,89,118,147,176,205,234,7,36,65,94,123,152
    .byte 181,210,239,12,41,70,99,128,157,186,215,244,17,46,75,104
    .byte 133,162,191,220,249,22,51,80,109,138,167,196,225,254,27,56
    .byte 85,114,143,172,201,230,3,32,61,90,119,148,177,206,235,8
    .byte 37,66,95,124,153,182,211,240,13,42,71,100,129,158,187,216
    .byte 245,18,47,76,105,134,163,192,221,250,23,52,81,110,139,168
    .byte 197,226,255,28,57,86,115,144,173,202,231,4,33,62,91,120
    .byte 149,178,207,236,9,38,67,96,125,154,183,212,241,14,43,72
    .byte 101,130,159,188,217,246,19,48,77,106,135,164,193,222,251,24
stela_helper_fp_mxcsr:
    .long 0x7fa1
stela_helper_fp_cw:
    .word 0x0b7f
.global stela_helper_fp_zero
stela_helper_fp_zero:
    .quad 0
.global stela_helper_fp_body_end
stela_helper_fp_body_end:
"#,
    guest_reserved = const offset_of!(GuestState, reserved),
    observation_argument = const offset_of!(GuestState, x) + 8,
    helper_argument = const offset_of!(GuestState, x) + 16,
    address_argument = const offset_of!(GuestState, x) + 24,
    started = const STARTED,
    done = const RETURNED,
    expected = const offset_of!(Observation, expected),
    returned = const offset_of!(Observation, returned),
    expected_regs = const offset_of!(Observation, expected_registers),
    returned_regs = const offset_of!(Observation, returned_registers),
    fp_errors = const offset_of!(Observation, fp_errors),
    return_rax = const RETURN_RAX,
    return_rdx = const RETURN_RDX,
);
unsafe extern "C" {
    static stela_helper_fp_body: u8;
    static stela_helper_fp_body_end: u8;
    static stela_helper_fp_return: u8;
    static stela_helper_fp_divide: u8;
    static stela_helper_fp_zero: u8;
}

pub(super) fn check(host: &mut BareHost<'_>) -> Result<(), &'static str> {
    let scope = GuestScope::new()?;
    let source = ptr::addr_of!(stela_helper_fp_body) as usize;
    let bytes = (ptr::addr_of!(stela_helper_fp_body_end) as usize)
        .checked_sub(source)
        .filter(|&bytes| bytes != 0 && bytes < 4096)
        .ok_or("helper FP source extent differs")?;
    let return_offset = (ptr::addr_of!(stela_helper_fp_return) as usize)
        .checked_sub(source)
        .filter(|&offset| offset < bytes)
        .ok_or("helper FP source return differs")?;
    // SAFETY: source symbols delimit the exact baseline authored body and its
    // position-independent literals; original guest inputs are untouched.
    let code = host
        .install(unsafe { core::slice::from_raw_parts(source as *const u8, bytes) })
        .map_err(|_| "helper FP code arena full")?;
    let copied_address = |label: *const u8| -> Result<u64, &'static str> {
        let offset = (label as usize)
            .checked_sub(source)
            .filter(|&offset| offset < bytes)
            .ok_or("helper FP source label outside body")?;
        code.0
            .checked_add(offset)
            .map(|address| address as u64)
            .ok_or("helper FP installed label overflow")
    };
    let expected_fip = copied_address(ptr::addr_of!(stela_helper_fp_divide))?;
    let expected_fdp = copied_address(ptr::addr_of!(stela_helper_fp_zero))?;
    host.set_regime(&scope.regime());
    for address in [MAPPED, MISSING] {
        for context_abi in [0, 1] {
            state().tlb.clear();
            let calls = state().helper_calls;
            let fills = state().helper_fills;
            let mut observed = Observation {
                expected: Image([0; 512]),
                returned: Image([0; 512]),
                expected_registers: [0; 16],
                returned_registers: [0; 16],
                fp_errors: u64::MAX,
            };
            let mut guest = GuestState::default();
            guest.x[1] = ptr::from_mut(&mut observed) as u64;
            guest.x[2] = super::super::translated::slot();
            guest.x[3] = address;
            let mut expected = guest.clone();
            let mut context = ExecutionContext::default();
            let mut probe = Probe {
                original: Image([0; 512]),
                expected: Image([0; 512]),
                returned: Image([0; 512]),
                result_rax: 0,
                result_rdx: 0,
                gpr_errors: u64::MAX,
                fp_errors: u64::MAX,
            };
            if state().native || state().recorded.is_some() {
                return Err("helper FP entered with preceding live native frame");
            }
            state().native = true;
            let entered = super::super::rdtsc();
            // SAFETY: sealed current actual Host, private pinned ARM tables/data,
            // caller/probe/frame/context and exact installed code remain owned
            // through the true helper/return/recovery. No synthetic TLB fill.
            unsafe {
                stela_native_fp_probe(&mut probe, code.0, &mut guest, &mut context, context_abi);
            }
            let result = native_return(
                code,
                BlockExit {
                    next_pc: probe.result_rax,
                    kind: probe.result_rdx,
                },
                entered,
            );
            let fip = pointer(&observed.expected, 8);
            let fdp = pointer(&observed.expected, 16);
            let fop = u16::from_le_bytes([observed.expected.0[6], observed.expected.0[7]]) & 0x7ff;
            crate::output::arguments(format_args!(
                "NATIVE HELPER FP context={context_abi} va={address:#x} caller_fp={:#x} helper_fp={:#x} fip={fip:#x} fdp={fdp:#x} fop={fop:#x} calls_before={calls} calls_after={} fills_before={fills} fills_after={}\n",
                probe.fp_errors,
                observed.fp_errors,
                state().helper_calls,
                state().helper_fills,
            ));
            if probe.gpr_errors != 0
                || probe.fp_errors != 0
                || !same_legacy(&probe.expected, &probe.returned)
                || state().helper_calls != calls + 1
                || state().helper_fills != fills + 1
            {
                return Err("helper FP original caller or actual walk differs");
            }
            if fip != expected_fip || fdp != expected_fdp || fop != 0x435 {
                return Err("helper FP actual guest register seed differs");
            }
            if address == MAPPED {
                expected.reserved = RETURNED;
                expected.x[0] = VALUE;
                let data = scope
                    .mapping
                    .address(4 * PAGE, 8)
                    .map_err(|_| "helper FP data mapping differs")?;
                if result
                    != (NativeExit::Exit {
                        next_pc: RETURN_RAX,
                        kind: RETURN_RDX,
                    })
                    || observed.fp_errors != 0
                    || !same_legacy(&observed.expected, &observed.returned)
                    || observed.returned_registers[0] != data.as_ptr() as u64
                    || observed.expected_registers[1..] != observed.returned_registers[1..]
                {
                    return Err("helper FP real mapped return or full Saved ABI differs");
                }
            } else {
                expected.reserved = STARTED;
                if !matches!(result, NativeExit::Fault(fault) if fault.offset == return_offset
                    && fault.cause == FaultCause::NonCanonical && fault.address == MISSING && !fault.write
                    && fault.registers == observed.expected_registers)
                    || observed.returned_registers != [0; 16]
                    || observed.fp_errors != u64::MAX
                {
                    return Err("helper FP missing mapping did not abandon exact actual frame");
                }
            }
            if guest != expected {
                return Err("helper FP private source execution marker/state differs");
            }
        }
    }
    // Retire every actual translation while its real pages/mapping stay owned.
    drop(scope);
    host.discard_code();
    Ok(())
}
