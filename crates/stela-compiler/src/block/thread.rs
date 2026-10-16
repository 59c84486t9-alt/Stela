//! Explicit guest thread-register reads through the runtime-owned TSD domain.
use crate::{CompileError, GuestAddress};
use serde::Serialize;

const INSTRUCTION_BYTES: u64 = 4;
const DESTINATION_MASK: u32 = 0x1f;
const MRS_TPIDRRO_EL0: u32 = 0xd53bd060;

/// Only MRS TPIDRRO_EL0 is admitted. X31 discards the value, never writes SP.
/// Native code requests a helper without reading host TLS or changing guest state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ThreadRegisterInstruction {
    pub destination: u8,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

pub fn decode_thread_register_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<ThreadRegisterInstruction>, CompileError> {
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(CompileError(
            "thread-register instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    if word & !DESTINATION_MASK != MRS_TPIDRRO_EL0 {
        return Ok(None);
    }
    Ok(Some(ThreadRegisterInstruction {
        destination: (word & DESTINATION_MASK) as u8,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(INSTRUCTION_BYTES).ok_or_else(|| {
            CompileError("thread-register continuation PC overflows guest address range".into())
        })?),
    }))
}

#[cfg(test)]
mod tests;
