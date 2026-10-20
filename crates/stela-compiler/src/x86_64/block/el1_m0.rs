//! Emission of EL1 blocks with the MMU off.
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::{Instruction, Register},
    block::{Terminator, el1_m0::LiteralRead64},
    context::memory::MEMORY_REQUEST_BYTES,
    x86_64::{self, memory_context as service},
};
use alloc::vec::Vec;

const REQUEST_OFFSET: u32 = 0;
const DATA_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
// Request + staged u64 + padding; preserve body RSP at 8 modulo16.
const SCRATCH_BYTES: u8 = 48;
const SUB_RSP: &[u8] = &[0x48, 0x83, 0xec, SCRATCH_BYTES];
const ADD_RSP: &[u8] = &[0x48, 0x83, 0xc4, SCRATCH_BYTES];
const MOV_RAX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

fn literal(code: &mut Vec<u8>, read: LiteralRead64) {
    code.extend(SUB_RSP);
    service::begin(code);
    x86_64::immediate(code, read.address);
    service::request(
        code,
        REQUEST_OFFSET,
        DATA_OFFSET,
        size_of::<u64>() as u32,
        0,
        read.source_pc.0,
    );
    service::call(code, REQUEST_OFFSET);
    let failed = service::branch_failed(code);
    if read.destination != Register::Zero {
        code.extend(MOV_RAX_RSP_DISP32);
        code.extend(DATA_OFFSET.to_le_bytes());
        x86_64::store(code, read.destination);
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    service::patch_branch(code, failed, cleanup);
    code.extend(ADD_RSP);
    // The runtime reads the fault details before the ABI result. A failed read
    // commits nothing.
    service::address::return_if_failed(code);
}

pub(crate) fn emit(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    read: Option<LiteralRead64>,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let mut block = NativeBlock {
        x86_64_code: crate::extended::context_wrapper(),
        source_map: Vec::new(),
    };
    let mut fixups = Vec::new();
    for instruction in instructions {
        block
            .source_map
            .push((instruction.pc, block.x86_64_code.len()));
        if let Some(read) = read {
            literal(&mut block.x86_64_code, read);
        } else {
            x86_64::emit_instruction(
                &mut block.x86_64_code,
                instruction,
                &mut fixups,
                target,
                x86_64::MemoryChecks::DEFAULT,
            );
        }
    }
    if !fixups.is_empty() {
        return Err(CompileError(
            "EL1 integer prefix unexpectedly branches".into(),
        ));
    }
    super::emit_terminal(
        &mut block.x86_64_code,
        &mut block.source_map,
        terminal,
        fallthrough,
        target,
        crate::x86_64::NativeSystem::NONE,
        crate::x86_64::RangeCheck::FIVE_LEVEL,
        crate::x86_64::Rax::Unknown,
    );
    Ok(block)
}

/// One source-derived scalar read using the shared checked scalar staging body.
pub(crate) fn emit_scalar_load(
    instruction: &Instruction,
    load: crate::block::el1_platform::ScalarLoad,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    if !load.matches_instruction(instruction) {
        return Err(CompileError("changed M0 scalar load instruction".into()));
    }
    emit_scalar(instruction, load.operand(), target)
}

/// The same staged body as the scalar load, under the store capability.
pub(crate) fn emit_scalar_store(
    instruction: &Instruction,
    store: crate::block::el1_platform::ScalarStore,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    if !store.matches_instruction(instruction) {
        return Err(CompileError("changed M0 scalar store instruction".into()));
    }
    emit_scalar(instruction, store.operand(), target)
}

fn emit_scalar(
    instruction: &Instruction,
    operand: x86_64::memory_store::checked_scalar::Operand,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let mut block = NativeBlock {
        x86_64_code: crate::extended::context_wrapper(),
        source_map: Vec::new(),
    };
    block
        .source_map
        .push((instruction.pc, block.x86_64_code.len()));
    x86_64::memory_store::checked_scalar::emit_context(
        &mut block.x86_64_code,
        &operand,
        instruction.pc.0,
    );
    let next = instruction
        .pc
        .0
        .checked_add(size_of::<u32>() as u64)
        .ok_or_else(|| CompileError("M0 scalar continuation overflow".into()))?;
    super::emit_terminal(
        &mut block.x86_64_code,
        &mut block.source_map,
        None,
        GuestAddress(next),
        target,
        crate::x86_64::NativeSystem::NONE,
        crate::x86_64::RangeCheck::FIVE_LEVEL,
        crate::x86_64::Rax::Unknown,
    );
    Ok(block)
}

/// The checked pair emitter in the context ABI. The M0 variant stages inputs
/// and writes back the base only after the callback succeeds.
pub(crate) fn emit_write_pair(
    instruction: &Instruction,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let operand =
        x86_64::memory_store::checked_pair::Operand::from_m0_write_pair(&instruction.operation)
            .ok_or_else(|| CompileError("unqualified M0 pair-write emitter operand".into()))?;
    emit_pair(instruction, operand, target)
}

/// The same body for reads, on a PE without FEAT_LSE2.
pub(crate) fn emit_read_pair(
    instruction: &Instruction,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let operand =
        x86_64::memory_store::checked_pair::Operand::from_m0_read_pair(&instruction.operation)
            .ok_or_else(|| CompileError("unqualified M0 pair-read emitter operand".into()))?;
    emit_pair(instruction, operand, target)
}

fn emit_pair(
    instruction: &Instruction,
    operand: x86_64::memory_store::checked_pair::Operand,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let mut block = NativeBlock {
        x86_64_code: crate::extended::context_wrapper(),
        source_map: Vec::new(),
    };
    block
        .source_map
        .push((instruction.pc, block.x86_64_code.len()));
    x86_64::memory_store::checked_pair::emit_context(
        &mut block.x86_64_code,
        &operand,
        instruction.pc.0,
    );
    let next = instruction
        .pc
        .0
        .checked_add(size_of::<u32>() as u64)
        .ok_or_else(|| CompileError("M0 pair continuation overflow".into()))?;
    super::emit_terminal(
        &mut block.x86_64_code,
        &mut block.source_map,
        None,
        GuestAddress(next),
        target,
        crate::x86_64::NativeSystem::NONE,
        crate::x86_64::RangeCheck::FIVE_LEVEL,
        crate::x86_64::Rax::Unknown,
    );
    Ok(block)
}
