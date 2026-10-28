//! The shared memory-service call. Instruction families supply predicates,
//! addresses and load staging; the service performs translation, splitting,
//! tag checks and writer tracking.
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, Size};

use core::mem::offset_of;

use crate::context::{
    EXECUTION_CONTEXT_MEMORY_OFFSET,
    memory::{MEMORY_CALLBACK_OFFSET, MemoryStatus},
};

const HOST_POINTER_BYTES: u32 = size_of::<u64>() as u32;
const CALLBACK_SAVE_BYTES: u32 = 16;
/// MXCSR's power-on value: every exception masked, round to nearest.
const DEFAULT_MXCSR: i32 = 0x1f80;
/// The caller's MXCSR, in the 16-byte reservation.
const SAVED_MXCSR: Mem = Mem::base(Gpr::Rsp, 0);
/// The default MXCSR, after the caller's. This baseline recipe costs 2
/// instructions/13 bytes, with no literal relocation or additional GPR spill.
const LOADED_MXCSR: Mem = Mem::base(Gpr::Rsp, 4);

/// The memory view field at `offset` from RDX.
fn field(offset: usize) -> Mem {
    Mem::base_disp8(
        Gpr::Rdx,
        i8::try_from(offset).expect("memory view field fits positive disp8"),
    )
}

/// The memory view pointer in the execution context at R15.
const fn memory_view() -> Mem {
    Mem::base_disp8(Gpr::R15, EXECUTION_CONTEXT_MEMORY_OFFSET as i8)
}

fn memory_pointer(code: &mut Code) {
    code.asm().mov_load(Size::Qword, Gpr::Rdx, memory_view());
}

/// Start one instruction's exact reached-prefix record. Clobbers RDX only.
pub(crate) fn begin(code: &mut Code) {
    use crate::context::memory::MemoryContextView;
    memory_pointer(code);
    // v2 places the validated fault-access code directly after fault_kind.
    // Clear both before each reached instruction, including local faults.
    let mut asm = code.asm();
    asm.mov_rm_imm32(
        Size::Qword,
        field(offset_of!(MemoryContextView, fault_kind)),
        MemoryStatus::Success as i32,
    );
    asm.mov_rm_imm32(
        Size::Qword,
        field(offset_of!(MemoryContextView, completed_bytes)),
        0,
    );
}

/// Build a request at a private stack offset. RAX supplies the guest address;
/// data_offset names private staging relative to the current RSP. Clobbers RCX/RDX.
pub(crate) fn request(
    code: &mut Code,
    request_offset: u32,
    data_offset: u32,
    bytes: u32,
    flags: u32,
    pc: u64,
) {
    use crate::context::memory::{
        MEMORY_REQUEST_ADDRESS_OFFSET, MEMORY_REQUEST_DATA_OFFSET, MEMORY_REQUEST_FLAGS_OFFSET,
        MEMORY_REQUEST_LENGTH_OFFSET, MEMORY_REQUEST_PC_OFFSET,
    };
    let stack = |offset: u32| Mem::base_disp32(Gpr::Rsp, offset as i32);
    let mut asm = code.asm();
    asm.mov_store(
        Size::Qword,
        stack(request_offset + MEMORY_REQUEST_ADDRESS_OFFSET),
        Gpr::Rax,
    );
    asm.lea(Size::Qword, Gpr::Rdx, stack(data_offset));
    asm.mov_store(
        Size::Qword,
        stack(request_offset + MEMORY_REQUEST_DATA_OFFSET),
        Gpr::Rdx,
    );
    for (field, value) in [
        (MEMORY_REQUEST_LENGTH_OFFSET, bytes),
        (MEMORY_REQUEST_FLAGS_OFFSET, flags),
    ] {
        asm.mov_rm_imm32(Size::Dword, stack(request_offset + field), value as i32);
    }
    asm.mov_imm64(Gpr::Rcx, pc);
    asm.mov_store(
        Size::Qword,
        stack(request_offset + MEMORY_REQUEST_PC_OFFSET),
        Gpr::Rcx,
    );
}

/// Invoke the validated memory service. Before entry RSP must be 8 modulo16,
/// as at extended body entry; family scratch allocations are multiples of16.
/// Preserves RDI/R15. Other caller-saved GPRs and XMM registers are clobbered.
/// Runs the callback under default MXCSR, then preserves the full caller
/// MXCSR, including exception status bits, on success and refusal. Returns the
/// typed MemoryStatus encoding in EAX. No callback address is embedded.
pub(crate) fn call(code: &mut Code, request_offset: u32) {
    let mut asm = code.asm();
    asm.push(Gpr::Rdi);
    asm.alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, CALLBACK_SAVE_BYTES as i8);
    asm.stmxcsr(SAVED_MXCSR);
    asm.mov_rm_imm32(Size::Dword, LOADED_MXCSR, DEFAULT_MXCSR);
    asm.ldmxcsr(LOADED_MXCSR);
    asm.mov_load(Size::Qword, Gpr::Rdi, memory_view());
    asm.lea(
        Size::Qword,
        Gpr::Rsi,
        Mem::base_disp32(
            Gpr::Rsp,
            (request_offset + HOST_POINTER_BYTES + CALLBACK_SAVE_BYTES) as i32,
        ),
    );
    asm.call_rm(Mem::base_disp8(Gpr::Rdi, MEMORY_CALLBACK_OFFSET as i8));
    asm.ldmxcsr(SAVED_MXCSR);
    asm.alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, CALLBACK_SAVE_BYTES as i8);
    asm.pop(Gpr::Rdi);
}

/// Emit a failure branch; patch the returned displacement to family cleanup.
pub(crate) fn branch_failed(code: &mut Code) -> usize {
    let mut asm = code.asm();
    asm.test(Size::Dword, Gpr::Rax, Gpr::Rax);
    asm.jcc(Cond::Ne).offset()
}

pub(crate) fn patch_branch(code: &mut [u8], displacement: usize, destination: usize) {
    let end = displacement + size_of::<i32>();
    let relative = i32::try_from(destination as i64 - end as i64)
        .expect("native memory cleanup branch fits rel32");
    code[displacement..end].copy_from_slice(&relative.to_le_bytes());
}

/// Record a fault found in emitted code (such as SP misalignment). RAX is the
/// faulting address; the completed prefix stays. Clobbers RCX/RDX.
pub(crate) fn fault(code: &mut Code, status: MemoryStatus, pc: u64) {
    use crate::context::memory::MemoryContextView;
    memory_pointer(code);
    let mut asm = code.asm();
    asm.mov_rm_imm32(
        Size::Dword,
        field(offset_of!(MemoryContextView, fault_kind)),
        status as i32,
    );
    asm.mov_store(
        Size::Qword,
        field(offset_of!(MemoryContextView, fault_address)),
        Gpr::Rax,
    );
    asm.mov_imm64(Gpr::Rcx, pc);
    asm.mov_store(
        Size::Qword,
        field(offset_of!(MemoryContextView, fault_pc)),
        Gpr::Rcx,
    );
    asm.mov_imm32(Gpr::Rax, status as u32);
}
