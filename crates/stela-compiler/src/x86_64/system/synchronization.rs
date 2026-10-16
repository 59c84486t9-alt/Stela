//! Baseline native mappings for reviewed instruction-execution barriers and hints.
use crate::aarch64::system::synchronization::Operation;
use alloc::vec::Vec;

const MOV_R8_RBX: &[u8] = &[0x49, 0x89, 0xd8];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const CPUID: &[u8] = &[0x0f, 0xa2];
const MOV_RBX_R8: &[u8] = &[0x4c, 0x89, 0xc3];
const PAUSE: &[u8] = &[0xf3, 0x90];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    ContextRequired,
}

/// Emit only effects independent of guest system context. R8 is host scratch.
/// CPUID leaf0 serializes execution; preserve the System V callee-saved RBX.
/// All guest state remains in memory and is untouched by these recipes.
/// Other operations require their explicit runtime/context owner.
pub fn emit(code: &mut Vec<u8>, operation: &Operation) -> Result<(), EmitError> {
    match operation {
        Operation::Yield => code.extend_from_slice(PAUSE),
        Operation::ConsumptionBarrier
        | Operation::SpeculationBarrier
        | Operation::StoreBypassBarrier { .. } => {
            code.extend_from_slice(MOV_R8_RBX);
            code.extend_from_slice(XOR_EAX_EAX);
            code.extend_from_slice(CPUID);
            code.extend_from_slice(MOV_RBX_R8);
        }
        _ => return Err(EmitError::ContextRequired),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
