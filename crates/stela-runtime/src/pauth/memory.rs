//! Authenticated-load operand staging and architectural commit ordering.
//!
//! Authentication policy, keys and faults belong to the process PAuth context.
//! The read callback owns data address translation, permissions and RAM effects;
//! it receives the full tagged effective address, never a silently stripped one.
use stela_compiler::{
    GuestState,
    block::pauth_memory::{DataKey, Load},
};

const ZERO_REGISTER_INDEX: u8 = 31;
const STACK_ALIGNMENT: u64 = 16;

/// Effective stack-alignment and access privilege from the selected CPU controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Controls {
    pub check_sp_alignment: bool,
    pub privileged: bool,
}

impl Default for Controls {
    fn default() -> Self {
        Self {
            check_sp_alignment: true,
            privileged: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault<A, E> {
    InvalidOperands,
    UndefinedOverlap,
    Authentication(A),
    StackAlignment { stack_pointer: u64 },
    Read { address: u64, error: E },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub effective_address: u64,
}

/// Complete one decoded LDRA instruction. No architectural destination is
/// changed before authentication, alignment and the complete read succeed.
/// The fixed addressing profile disables checked pointer arithmetic (CPA2).
pub fn complete<A, E>(
    instruction: Load,
    controls: Controls,
    registers: &mut GuestState,
    authenticate: impl FnOnce(DataKey, u64) -> Result<u64, A>,
    read: impl FnOnce(u64) -> Result<u64, E>,
) -> Result<Completion, Fault<A, E>> {
    if !instruction.is_valid() {
        return Err(Fault::InvalidOperands);
    }
    if instruction.undefined_overlap() {
        return Err(Fault::UndefinedOverlap);
    }
    let pointer = if instruction.base == ZERO_REGISTER_INDEX {
        registers.sp
    } else {
        registers.x[usize::from(instruction.base)]
    };
    // The June2026 architectural sequence authenticates before CheckSPAlignment.
    // The zero modifier and combined-operation policy are supplied by the caller.
    let address = authenticate(instruction.key, pointer).map_err(Fault::Authentication)?;
    if controls.check_sp_alignment
        && instruction.base == ZERO_REGISTER_INDEX
        && registers.sp & (STACK_ALIGNMENT - 1) != 0
    {
        return Err(Fault::StackAlignment {
            stack_pointer: registers.sp,
        });
    }
    let address = address.wrapping_add_signed(i64::from(instruction.displacement));
    let value = read(address).map_err(|error| Fault::Read { address, error })?;
    if instruction.destination != ZERO_REGISTER_INDEX {
        registers.x[usize::from(instruction.destination)] = value;
    }
    if instruction.writeback {
        if instruction.base == ZERO_REGISTER_INDEX {
            registers.sp = address;
        } else {
            registers.x[usize::from(instruction.base)] = address;
        }
    }
    Ok(Completion {
        effective_address: address,
    })
}

#[cfg(test)]
mod tests;
