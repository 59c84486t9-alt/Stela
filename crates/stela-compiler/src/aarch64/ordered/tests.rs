use super::*;

const SBO_SOURCE: u32 = REGISTER_MASK << 16;
const SBO_SECOND: u32 = REGISTER_MASK << 10;

#[test]
fn all_twenty_forms_preserve_register_roles_and_aliases() {
    for (class, kind) in [
        (ACQUIRE_CLASS, Kind::Acquire),
        (RELEASE_CLASS, Kind::Release),
        (LIMITED_ACQUIRE_CLASS, Kind::Acquire),
        (LIMITED_RELEASE_CLASS, Kind::Release),
        (ACQUIRE_PC_CLASS, Kind::AcquirePc),
    ] {
        for size in 0..4 {
            for data in 0..=REGISTER_MASK {
                for base in 0..=REGISTER_MASK {
                    let word = class | (size << SIZE_SHIFT) | (base << BASE_SHIFT) | data;
                    let expected = Operand::Transfer {
                        kind,
                        bytes: 1 << size,
                        data: register(data, false),
                        base: register(base, true),
                        displacement: 0,
                        extension: LoadExtension::Zero,
                    };
                    assert_eq!(decode(word), Some(expected));
                }
            }
        }
    }
}

#[test]
fn should_be_one_fields_choose_execute_as_one() {
    for class in [
        ACQUIRE_CLASS,
        RELEASE_CLASS,
        LIMITED_ACQUIRE_CLASS,
        LIMITED_RELEASE_CLASS,
    ] {
        let canonical = class | SBO_SOURCE | SBO_SECOND;
        for source in 0..=REGISTER_MASK {
            for second in 0..=REGISTER_MASK {
                assert_eq!(
                    decode(class | (source << 16) | (second << 10)),
                    decode(canonical)
                );
            }
        }
    }
    for source in 0..=REGISTER_MASK {
        assert_eq!(
            decode(ACQUIRE_PC_CLASS | (source << 16)),
            decode(ACQUIRE_PC_CLASS | SBO_SOURCE)
        );
    }
}

#[test]
fn all_barrier_options_include_reserved_sy_fallback() {
    for option in 0..=OPTION_MASK {
        let expected = match option & u32::from(REQUIREMENT_MASK) {
            1 => Barrier::Reads,
            2 => Barrier::Writes,
            _ => Barrier::All,
        };
        assert_eq!(
            decode(DMB_CLASS | (option << OPTION_SHIFT)),
            Some(Operand::Barrier {
                option: option as u8,
                requirement: expected,
            })
        );
    }
}

#[test]
fn unscaled_allocations_and_signed_result_widths_are_explicit() {
    let mut forms = 0;
    for size in 0..=DOUBLEWORD_SIZE {
        for opcode in 0..=OPCODE_MASK {
            let word = UNSCALED_CLASS | (size << SIZE_SHIFT) | (opcode << OPCODE_SHIFT);
            let expected = match (size, opcode) {
                (_, STORE_OPCODE) => (Kind::Release, LoadExtension::Zero),
                (_, UNSIGNED_LOAD_OPCODE) => (Kind::AcquirePc, LoadExtension::Zero),
                (0..=WORD_SIZE, SIGNED_LOAD_X_OPCODE) => {
                    (Kind::AcquirePc, LoadExtension::Sign(Width::X64))
                }
                (0..=1, SIGNED_LOAD_W_OPCODE) => (Kind::AcquirePc, LoadExtension::Sign(Width::W32)),
                _ => {
                    assert!(decode(word).is_none());
                    assert!(
                        crate::Lifter::lift(&super::super::Decoder, crate::GuestAddress(0), word,)
                            .is_err()
                    );
                    continue;
                }
            };
            assert_eq!(
                decode(word),
                Some(Operand::Transfer {
                    kind: expected.0,
                    bytes: 1 << size,
                    data: Register::X(0),
                    base: Register::X(0),
                    displacement: 0,
                    extension: expected.1,
                })
            );
            forms += 1;
        }
    }
    assert_eq!(forms, 13);
}

#[test]
fn unscaled_immediates_and_all_register_aliases_have_no_writeback() {
    for immediate in 0..=IMMEDIATE_MASK {
        let word = UNSCALED_CLASS
            | (SIGNED_LOAD_X_OPCODE << OPCODE_SHIFT)
            | (immediate << IMMEDIATE_SHIFT)
            | (REGISTER_MASK << BASE_SHIFT)
            | REGISTER_MASK;
        let displacement = if immediate < (1 << (IMMEDIATE_BITS - 1)) {
            immediate as i32
        } else {
            immediate as i32 - (1 << IMMEDIATE_BITS)
        };
        assert_eq!(
            decode(word),
            Some(Operand::Transfer {
                kind: Kind::AcquirePc,
                bytes: 1,
                data: Register::Zero,
                base: Register::Sp,
                displacement,
                extension: LoadExtension::Sign(Width::X64),
            })
        );
    }
    for data in 0..=REGISTER_MASK {
        for base in 0..=REGISTER_MASK {
            let word =
                UNSCALED_CLASS | (DOUBLEWORD_SIZE << SIZE_SHIFT) | (base << BASE_SHIFT) | data;
            assert_eq!(
                decode(word),
                Some(Operand::Transfer {
                    kind: Kind::Release,
                    bytes: 8,
                    data: register(data, false),
                    base: register(base, true),
                    displacement: 0,
                    extension: LoadExtension::Zero,
                })
            );
        }
    }
    for bit in [10, 11, 21, 24, 25, 26, 27, 28, 29] {
        assert!(decode(UNSCALED_CLASS ^ (1 << bit)).is_none());
    }
}

#[test]
fn neighboring_instruction_classes_are_not_claimed() {
    // Exclusives, LRCPC3 writeback, CAS, SWP,
    // DSB (including SSBB/PSSBB), nXS and ISB remain separate.
    for word in [
        0xc85f_7c20,
        0xd940_0820,
        0xd900_0820,
        0xc8a0_7c20,
        0xf820_8021,
        0xd503_309f,
        0xd503_349f,
        0xd503_3f9f,
        0xd503_323f,
        0xd503_3fdf,
    ] {
        assert!(decode(word).is_none(), "neighbor {word:08x}");
    }
}
