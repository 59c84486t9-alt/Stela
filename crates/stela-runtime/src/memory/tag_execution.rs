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
mod tests {
    use super::*;
    use stela_compiler::aarch64::{AddressMode, tag_memory::StoreKind};

    const ORIGINAL_TAG: u8 = 9;
    const ORIGINAL_SEED: u16 = 0x1234;
    const ADDRESS: u64 = 0xa123_4567_89ab_cdef;

    fn generation() -> TagGenerationState {
        TagGenerationState {
            seed: ORIGINAL_SEED,
            tag: AllocationTag::new(ORIGINAL_TAG).unwrap(),
        }
    }

    fn controls(randomization: TagRandomization) -> TagGenerationControls {
        TagGenerationControls {
            allocation_access_enabled: true,
            excluded_tags: 0,
            randomization,
        }
    }

    fn registers() -> GuestState {
        let mut registers = GuestState {
            sp: ADDRESS,
            nzcv: 0xa000_0000,
            fpcr: 0x400_0000,
            fpsr: 0x81,
            ..GuestState::default()
        };
        registers.x[0] = ADDRESS;
        registers.x[1] = 0x1234;
        registers.x[2] = u64::MAX;
        registers
    }

    #[test]
    fn lfsr_completion_snapshots_aliases_and_preserves_unrelated_state() {
        for (destination, address, mask) in [
            (Register::X(0), Register::X(0), Register::X(0)),
            (Register::X(1), Register::X(0), Register::X(1)),
            (Register::Sp, Register::Sp, Register::X(0)),
            (Register::X(0), Register::Sp, Register::X(0)),
            (Register::Sp, Register::X(0), Register::Zero),
            (Register::X(1), Register::X(0), Register::Zero),
        ] {
            let mut registers = registers();
            let mut generation = generation();
            let controls = controls(TagRandomization::ArchitecturalLfsr);
            let mut expected_registers = registers.clone();
            let mut expected_generation = generation;
            let expected_tag = expected_generation
                .generate_tag(controls, read(&registers, mask), None)
                .unwrap();
            write(
                &mut expected_registers,
                destination,
                expected_tag.apply_to_address(read(&registers, address)),
            );
            let actual = complete_random_tag_with_entropy(
                Operand::RandomTag {
                    destination,
                    address,
                    mask,
                },
                &mut registers,
                controls,
                &mut generation,
                |_| panic!("LFSR mode must not request host entropy"),
            );
            assert_eq!(actual, Ok(expected_tag));
            assert_eq!(registers, expected_registers);
            assert_eq!(generation, expected_generation);
        }
    }

    #[test]
    fn invalid_or_wrong_operations_never_index_state_or_request_entropy() {
        for operand in [
            Operand::RandomTag {
                destination: Register::X(u8::MAX),
                address: Register::X(0),
                mask: Register::Zero,
            },
            Operand::RandomTag {
                destination: Register::X(0),
                address: Register::Zero,
                mask: Register::Zero,
            },
            Operand::StoreTags {
                kind: StoreKind::Tag,
                source: Register::X(0),
                base: Register::X(1),
                displacement: 0,
                mode: AddressMode::Offset,
            },
        ] {
            let mut registers = registers();
            let before = registers.clone();
            let mut generation = generation();
            let previous_generation = generation;
            let expected = if operand.is_valid() {
                RandomTagFault::NotRandomTag
            } else {
                RandomTagFault::InvalidOperands
            };
            assert_eq!(
                complete_random_tag_with_entropy(
                    operand,
                    &mut registers,
                    controls(TagRandomization::External),
                    &mut generation,
                    |_| panic!("invalid requests must not request entropy"),
                ),
                Err(expected)
            );
            assert_eq!(registers, before);
            assert_eq!(generation, previous_generation);
        }
    }

    #[test]
    fn disabled_and_all_excluded_external_modes_do_not_need_entropy_or_update_rgsr() {
        for disabled in [false, true] {
            let mut controls = controls(TagRandomization::External);
            controls.allocation_access_enabled = !disabled;
            controls.excluded_tags = if disabled { 0 } else { u16::MAX };
            let mut registers = registers();
            let mut generation = generation();
            let before = generation;
            assert_eq!(
                complete_random_tag_with_entropy(
                    Operand::RandomTag {
                        destination: Register::X(1),
                        address: Register::X(0),
                        mask: Register::Zero,
                    },
                    &mut registers,
                    controls,
                    &mut generation,
                    |_| panic!("disabled or empty selection must not request entropy"),
                ),
                Ok(AllocationTag::ZERO)
            );
            assert_eq!(generation, before);
            assert_eq!(
                registers.x[1],
                AllocationTag::ZERO.apply_to_address(ADDRESS)
            );
        }
    }

    #[test]
    fn entropy_failures_preserve_registers_and_authoritative_generation() {
        let mut controls = controls(TagRandomization::External);
        controls.excluded_tags = !(1 << 1 | 1 << 7 | 1 << 14);
        for unavailable in [false, true] {
            let mut registers = registers();
            let before = registers.clone();
            let mut generation = generation();
            let previous_generation = generation;
            assert_eq!(
                complete_random_tag_with_entropy(
                    Operand::RandomTag {
                        destination: Register::Sp,
                        address: Register::Sp,
                        mask: Register::Zero,
                    },
                    &mut registers,
                    controls,
                    &mut generation,
                    |bytes| {
                        bytes.fill(u8::MAX);
                        if unavailable {
                            Err(TagGenerationError::EntropyUnavailable)
                        } else {
                            Ok(())
                        }
                    },
                ),
                Err(RandomTagFault::Generation(
                    TagGenerationError::EntropyUnavailable
                ))
            );
            assert_eq!(registers, before);
            assert_eq!(generation, previous_generation);
        }
    }

    #[test]
    fn external_selection_is_unbiased_and_applies_both_exclusion_sources() {
        let mut controls = controls(TagRandomization::External);
        controls.excluded_tags = !(1 << 1 | 1 << 7 | 1 << 14);
        let mut counts = [0; ALLOCATION_TAG_COUNT as usize];
        for byte in 0..u8::MAX {
            let tag = external_tag(controls, 0, &mut |bytes| {
                bytes.fill(byte);
                Ok(())
            })
            .unwrap()
            .unwrap();
            counts[usize::from(tag.value())] += 1;
        }
        for (value, count) in counts.into_iter().enumerate() {
            assert_eq!(count, if [1, 7, 14].contains(&value) { 85 } else { 0 });
        }
        assert_eq!(
            external_tag(controls, 1 << 1 | 1 << 14, &mut |bytes| {
                bytes.fill(u8::MAX);
                Ok(())
            }),
            Ok(AllocationTag::new(7))
        );
    }

    #[test]
    fn production_external_provider_returns_an_allowed_tag_or_explicit_failure() {
        let mut controls = controls(TagRandomization::External);
        controls.excluded_tags = !(1 << 7 | 1 << 14);
        let mut registers = registers();
        let before = registers.clone();
        let mut generation = generation();
        let previous_generation = generation;
        match complete_random_tag(
            Operand::RandomTag {
                destination: Register::Sp,
                address: Register::Sp,
                mask: Register::Zero,
            },
            &mut registers,
            controls,
            &mut generation,
        ) {
            Ok(tag) => {
                assert!([7, 14].contains(&tag.value()));
                let mut expected = before.clone();
                expected.sp = tag.apply_to_address(ADDRESS);
                assert_eq!(registers, expected);
            }
            Err(error) => {
                assert_eq!(
                    error,
                    RandomTagFault::Generation(TagGenerationError::EntropyUnavailable)
                );
                assert_eq!(registers, before);
            }
        }
        assert_eq!(generation, previous_generation);
    }

    #[test]
    fn singleton_external_selection_has_no_entropy_platform_requirement() {
        let mut controls = controls(TagRandomization::External);
        controls.excluded_tags = !(1 << 7 | 1 << 14);
        let mut registers = registers();
        registers.x[1] = 1 << 14;
        let mut expected = registers.clone();
        let tag = AllocationTag::new(7).unwrap();
        expected.sp = tag.apply_to_address(ADDRESS);
        let mut generation = generation();
        let previous_generation = generation;
        assert_eq!(
            complete_random_tag_with_entropy(
                Operand::RandomTag {
                    destination: Register::Sp,
                    address: Register::Sp,
                    mask: Register::X(1)
                },
                &mut registers,
                controls,
                &mut generation,
                |_| panic!("one allowed tag needs no entropy source"),
            ),
            Ok(tag)
        );
        assert_eq!(registers, expected);
        assert_eq!(generation, previous_generation);
    }
}
