//! PACGA.
use stela_compiler::{GuestState, block::pauth_memory::GenericCode};

const ZERO_REGISTER_INDEX: u8 = 31;
const GENERIC_CODE_MASK: u64 = (u32::MAX as u64) << u32::BITS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault<E> {
    InvalidOperands,
    Compute(E),
}

pub fn complete<E>(
    instruction: GenericCode,
    registers: &mut GuestState,
    compute: impl FnOnce(u64, u64) -> Result<u64, E>,
) -> Result<(), Fault<E>> {
    if !instruction.is_valid() {
        return Err(Fault::InvalidOperands);
    }
    let source = if instruction.source == ZERO_REGISTER_INDEX {
        0
    } else {
        registers.x[usize::from(instruction.source)]
    };
    let modifier = if instruction.modifier == ZERO_REGISTER_INDEX {
        registers.sp
    } else {
        registers.x[usize::from(instruction.modifier)]
    };
    // Rd may alias either input. XZR discards only after the key service succeeds.
    let value = compute(source, modifier).map_err(Fault::Compute)? & GENERIC_CODE_MASK;
    if instruction.destination != ZERO_REGISTER_INDEX {
        registers.x[usize::from(instruction.destination)] = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
