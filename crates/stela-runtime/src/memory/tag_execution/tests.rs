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
