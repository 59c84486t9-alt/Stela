//! The shared memory-service call. Instruction families supply predicates,
//! addresses and load staging; the service performs translation, splitting,
//! tag checks and writer tracking.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::context::{
    EXECUTION_CONTEXT_MEMORY_OFFSET,
    memory::{MEMORY_CALLBACK_OFFSET, MemoryStatus},
};

const HOST_POINTER_BYTES: u32 = size_of::<u64>() as u32;
const CALLBACK_SAVE_BYTES: u32 = 16;
const SUB_RSP_SAVE: &[u8] = &[0x48, 0x83, 0xec, CALLBACK_SAVE_BYTES as u8];
const ADD_RSP_SAVE: &[u8] = &[0x48, 0x83, 0xc4, CALLBACK_SAVE_BYTES as u8];
const STMXCSR_RSP: &[u8] = &[0x0f, 0xae, 0x1c, 0x24];
const LDMXCSR_RSP: &[u8] = &[0x0f, 0xae, 0x14, 0x24];
// Reuse the existing 16-byte reservation: original MXCSR at 0, default at 4.
// This baseline recipe costs 2 instructions/13 bytes, with no literal relocation
// or additional GPR spill. Actual emitted-code/timing gates remain separate.
const MOV_DEFAULT_MXCSR_RSP_4: &[u8] = &[0xc7, 0x44, 0x24, 4, 0x80, 0x1f, 0, 0];
const LDMXCSR_RSP_4: &[u8] = &[0x0f, 0xae, 0x54, 0x24, 4];
const PUSH_RDI: &[u8] = &[0x57];
const POP_RDI: &[u8] = &[0x5f];
const MOV_RDI_CONTEXT_DISP8: &[u8] = &[0x49, 0x8b, 0x7f];
const LEA_RSI_RSP_DISP32: &[u8] = &[0x48, 0x8d, 0xb4, 0x24];
const CALL_RDI_DISP8: &[u8] = &[0xff, 0x57];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JNE_REL32: &[u8] = &[0x0f, 0x85];
const MOV_RSP_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const LEA_RDX_RSP_DISP32: &[u8] = &[0x48, 0x8d, 0x94, 0x24];
const MOV_RSP_DISP32_RDX: &[u8] = &[0x48, 0x89, 0x94, 0x24];
const MOV_RSP_DISP32_IMM32: &[u8] = &[0xc7, 0x84, 0x24];
const MOVABS_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const MOV_RSP_DISP32_RCX: &[u8] = &[0x48, 0x89, 0x8c, 0x24];
const MOV_RDX_CONTEXT_DISP8: &[u8] = &[0x49, 0x8b, 0x57];
const MOV_RDX_DISP8_IMM32: &[u8] = &[0xc7, 0x42];
const MOV_RDX_DISP8_RAX: &[u8] = &[0x48, 0x89, 0x42];
const MOV_RDX_DISP8_RCX: &[u8] = &[0x48, 0x89, 0x4a];
const MOV_RDX_DISP8_IMM32_QWORD: &[u8] = &[0x48, 0xc7, 0x42];
const MOV_EAX_IMM32: u8 = 0xb8;

fn field_offset(offset: usize) -> u8 {
    u8::try_from(offset).expect("memory view field fits positive disp8")
}

fn memory_pointer(code: &mut Vec<u8>) {
    code.extend(MOV_RDX_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_MEMORY_OFFSET as u8);
}

/// Start one instruction's exact reached-prefix record. Clobbers RDX only.
pub(crate) fn begin(code: &mut Vec<u8>) {
    use crate::context::memory::MemoryContextView;
    memory_pointer(code);
    // v2 places the validated fault-access code directly after fault_kind.
    // Clear both before each reached instruction, including local faults.
    code.extend(MOV_RDX_DISP8_IMM32_QWORD);
    code.push(field_offset(offset_of!(MemoryContextView, fault_kind)));
    code.extend((MemoryStatus::Success as u32).to_le_bytes());
    code.extend(MOV_RDX_DISP8_IMM32_QWORD);
    code.push(field_offset(offset_of!(MemoryContextView, completed_bytes)));
    code.extend(0_u32.to_le_bytes());
}

/// Build a request at a private stack offset. RAX supplies the guest address;
/// data_offset names private staging relative to the current RSP. Clobbers RCX/RDX.
pub(crate) fn request(
    code: &mut Vec<u8>,
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
    code.extend(MOV_RSP_DISP32_RAX);
    code.extend((request_offset + MEMORY_REQUEST_ADDRESS_OFFSET).to_le_bytes());
    code.extend(LEA_RDX_RSP_DISP32);
    code.extend(data_offset.to_le_bytes());
    code.extend(MOV_RSP_DISP32_RDX);
    code.extend((request_offset + MEMORY_REQUEST_DATA_OFFSET).to_le_bytes());
    for (field, value) in [
        (MEMORY_REQUEST_LENGTH_OFFSET, bytes),
        (MEMORY_REQUEST_FLAGS_OFFSET, flags),
    ] {
        code.extend(MOV_RSP_DISP32_IMM32);
        code.extend((request_offset + field).to_le_bytes());
        code.extend(value.to_le_bytes());
    }
    code.extend(MOVABS_RCX_IMM64);
    code.extend(pc.to_le_bytes());
    code.extend(MOV_RSP_DISP32_RCX);
    code.extend((request_offset + MEMORY_REQUEST_PC_OFFSET).to_le_bytes());
}

/// Invoke the validated memory service. Before entry RSP must be 8 modulo16,
/// as at extended body entry; family scratch allocations are multiples of16.
/// Preserves RDI/R15. Other caller-saved GPRs and XMM registers are clobbered.
/// Runs the callback under default MXCSR, then preserves the full caller
/// MXCSR, including exception status bits, on success and refusal. Returns the
/// typed MemoryStatus encoding in EAX. No callback address is embedded.
pub(crate) fn call(code: &mut Vec<u8>, request_offset: u32) {
    code.extend(PUSH_RDI);
    code.extend(SUB_RSP_SAVE);
    code.extend(STMXCSR_RSP);
    code.extend(MOV_DEFAULT_MXCSR_RSP_4);
    code.extend(LDMXCSR_RSP_4);
    code.extend(MOV_RDI_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_MEMORY_OFFSET as u8);
    code.extend(LEA_RSI_RSP_DISP32);
    code.extend((request_offset + HOST_POINTER_BYTES + CALLBACK_SAVE_BYTES).to_le_bytes());
    code.extend(CALL_RDI_DISP8);
    code.push(MEMORY_CALLBACK_OFFSET as u8);
    code.extend(LDMXCSR_RSP);
    code.extend(ADD_RSP_SAVE);
    code.extend(POP_RDI);
}

/// Emit a failure branch; patch the returned displacement to family cleanup.
pub(crate) fn branch_failed(code: &mut Vec<u8>) -> usize {
    code.extend(TEST_EAX_EAX);
    code.extend(JNE_REL32);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

pub(crate) fn patch_branch(code: &mut [u8], displacement: usize, destination: usize) {
    let end = displacement + size_of::<i32>();
    let relative = i32::try_from(destination as i64 - end as i64)
        .expect("native memory cleanup branch fits rel32");
    code[displacement..end].copy_from_slice(&relative.to_le_bytes());
}

/// Record a fault found in emitted code (such as SP misalignment). RAX is the
/// faulting address; the completed prefix stays. Clobbers RCX/RDX.
pub(crate) fn fault(code: &mut Vec<u8>, status: MemoryStatus, pc: u64) {
    use crate::context::memory::MemoryContextView;
    memory_pointer(code);
    code.extend(MOV_RDX_DISP8_IMM32);
    code.push(field_offset(offset_of!(MemoryContextView, fault_kind)));
    code.extend((status as u32).to_le_bytes());
    code.extend(MOV_RDX_DISP8_RAX);
    code.push(field_offset(offset_of!(MemoryContextView, fault_address)));
    code.extend(MOVABS_RCX_IMM64);
    code.extend(pc.to_le_bytes());
    code.extend(MOV_RDX_DISP8_RCX);
    code.push(field_offset(offset_of!(MemoryContextView, fault_pc)));
    code.push(MOV_EAX_IMM32);
    code.extend((status as u32).to_le_bytes());
}
