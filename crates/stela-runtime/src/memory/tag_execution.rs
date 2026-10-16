//! Executing MTE instructions with the current controls and guest memory.

use super::{
    domain::{AllocationTagPolicy, MemoryThread},
    tag_transfer,
    tags::{
        AllocationTag, TagGenerationControls, TagGenerationError, TagGenerationState,
        TagRandomization,
    },
};
use stela_compiler::{
    GuestState,
    aarch64::{Register, tag_memory::Operand},
    context::memory::MemoryStatus,
};

const ENTROPY_BYTES: usize = 16;
const RANDOM_BYTE_VALUES: u16 = u8::MAX as u16 + 1;
const ALLOCATION_TAG_COUNT: u32 = u16::BITS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomTagFault {
    InvalidOperands,
    NotRandomTag,
    Generation(TagGenerationError),
}

/// Complete IRG without requiring a RAM mapping or native memory capability.
/// Kernel entropy is requested only for an enabled, nonempty RRND selection.
/// Failure preserves all guest registers and the authoritative RGSR state.
pub fn complete_random_tag(
    operand: Operand,
    registers: &mut GuestState,
    controls: TagGenerationControls,
    generation: &mut TagGenerationState,
) -> Result<AllocationTag, RandomTagFault> {
    complete_random_tag_with_entropy(operand, registers, controls, generation, host_entropy)
}

/// Complete a dedicated tag memory instruction through the checked domain. The
/// caller keeps the instruction PC for exceptions.
pub fn complete_memory<P: AllocationTagPolicy>(
    operand: Operand,
    registers: &mut GuestState,
    profile: tag_transfer::Profile,
    memory: &mut MemoryThread<P>,
) -> Result<tag_transfer::Completion, tag_transfer::Fault<MemoryStatus>> {
    memory.complete_tag_memory(operand, registers, profile)
}

fn complete_random_tag_with_entropy(
    operand: Operand,
    registers: &mut GuestState,
    controls: TagGenerationControls,
    generation: &mut TagGenerationState,
    mut entropy: impl FnMut(&mut [u8]) -> Result<(), TagGenerationError>,
) -> Result<AllocationTag, RandomTagFault> {
    if !operand.is_valid() {
        return Err(RandomTagFault::InvalidOperands);
    }
    let Operand::RandomTag {
        destination,
        address,
        mask,
    } = operand
    else {
        return Err(RandomTagFault::NotRandomTag);
    };
    // Inputs can alias the destination, including SP. Snapshot both before
    // generating or committing any architectural state.
    let original_address = read(registers, address);
    let register_exclude = read(registers, mask);
    let external = external_tag(controls, register_exclude, &mut entropy)
        .map_err(RandomTagFault::Generation)?;
    let mut next_generation = *generation;
    let tag = next_generation
        .generate_tag(controls, register_exclude, external)
        .map_err(RandomTagFault::Generation)?;
    write(
        registers,
        destination,
        tag.apply_to_address(original_address),
    );
    *generation = next_generation;
    Ok(tag)
}

fn external_tag(
    controls: TagGenerationControls,
    register_exclude: u64,
    entropy: &mut impl FnMut(&mut [u8]) -> Result<(), TagGenerationError>,
) -> Result<Option<AllocationTag>, TagGenerationError> {
    let excluded = controls.excluded_tags | register_exclude as u16;
    if !controls.allocation_access_enabled
        || controls.randomization != TagRandomization::External
        || excluded == u16::MAX
    {
        return Ok(None);
    }
    let allowed = !excluded;
    // The early return above guarantees a nonzero mask. A singleton selection
    // is already uniform and needs neither entropy nor a population count.
    if allowed & (allowed - 1) == 0 {
        return Ok(AllocationTag::new(allowed.trailing_zeros() as u8));
    }
    let allowed_count = allowed.count_ones() as u16;
    // Reject the incomplete last interval instead of biasing a modulo choice.
    // One kernel sample covers sixteen candidate bytes; if it runs out, report
    // failure rather than choosing a tag.
    let unbiased_limit = RANDOM_BYTE_VALUES / allowed_count * allowed_count;
    let mut bytes = [0; ENTROPY_BYTES];
    entropy(&mut bytes)?;
    let byte = bytes
        .into_iter()
        .find(|byte| u16::from(*byte) < unbiased_limit)
        .ok_or(TagGenerationError::EntropyUnavailable)?;
    let mut ordinal = u16::from(byte) % allowed_count;
    for value in 0..ALLOCATION_TAG_COUNT {
        if excluded & (1_u16 << value) == 0 {
            if ordinal == 0 {
                return Ok(AllocationTag::new(value as u8));
            }
            ordinal -= 1;
        }
    }
    unreachable!("a selected ordinal names one allowed allocation tag")
}

fn read(registers: &GuestState, register: Register) -> u64 {
    match register {
        Register::X(index) => registers.x[usize::from(index)],
        Register::Sp => registers.sp,
        Register::Zero => 0,
    }
}

fn write(registers: &mut GuestState, register: Register, value: u64) {
    match register {
        Register::X(index) => registers.x[usize::from(index)] = value,
        Register::Sp => registers.sp = value,
        Register::Zero => {}
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn host_entropy(bytes: &mut [u8]) -> Result<(), TagGenerationError> {
    // SAFETY: a private bounded buffer, disjoint from guest RAM and
    // architectural state.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } == 0 {
        Ok(())
    } else {
        Err(TagGenerationError::EntropyUnavailable)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_entropy(_bytes: &mut [u8]) -> Result<(), TagGenerationError> {
    Err(TagGenerationError::EntropyUnavailable)
}

#[cfg(test)]
mod tests;
