//! Counter and synchronization instructions completed by the runtime clock service.
use crate::{CompileError, GuestAddress};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClockOperation {
    ReadVirtualCounter { destination: u8 },
    InstructionSynchronization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClockInstruction {
    pub operation: ClockOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

/// Only ISB SY and MRS CNTVCT_EL0 (X31 discards). Other counter registers and
/// barrier options are refused; both need the clock service.
pub fn decode_clock_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<ClockInstruction>, CompileError> {
    if !pc.0.is_multiple_of(4) {
        return Err(CompileError(
            "clock instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    let operation = if word == 0xd5033fdf {
        ClockOperation::InstructionSynchronization
    } else if word & 0xffffffe0 == 0xd53be040 {
        ClockOperation::ReadVirtualCounter {
            destination: (word & 31) as u8,
        }
    } else {
        return Ok(None);
    };
    Ok(Some(ClockInstruction {
        operation,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(4).ok_or_else(|| {
            CompileError("clock continuation PC overflows guest address range".into())
        })?),
    }))
}
