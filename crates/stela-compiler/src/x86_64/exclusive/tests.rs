use super::*;
use crate::aarch64::exclusive::{ConstrainedUndefined, decode};

// The historical contracts retain the Enabled specialization. Production callers
// must construct the immutable profile-bound operand explicitly.
fn requirements(operand: &Operand) -> Result<MemoryRequirements, CompileError> {
    Ok(super::requirements(&CheckedOperand::new(
        *operand,
        CheckedMemoryProfile::SpAlignmentEnabled,
    )?))
}
fn emit_context(code: &mut Vec<u8>, operand: &Operand, pc: u64) -> Result<(), CompileError> {
    super::emit_context(
        code,
        &CheckedOperand::new(*operand, CheckedMemoryProfile::SpAlignmentEnabled)?,
        pc,
    )
}

const SCALAR_CLASS: u32 = 0x0800_0000;
const PAIR_CLASS: u32 = 0x8820_0000;
const CLEAR_CLASS: u32 = 0xd503_305f;
const SIZE_SHIFT: u32 = 30;
const LOAD_BIT: u32 = 1 << 22;
const ACQUIRE_RELEASE_BIT: u32 = 1 << 15;
const STATUS_SHIFT: u32 = 16;
const SECOND_SHIFT: u32 = 10;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const SBO_STATUS: u32 = REGISTER_MASK << STATUS_SHIFT;
const SBO_SECOND: u32 = REGISTER_MASK << SECOND_SHIFT;
const OBSERVED_LOAD_WORD: u32 = 0x885f_7d2a;

#[test]
fn existing_decoder_covers_all_twenty_five_forms_without_reinterpretation() {
    let mut forms = 0;
    for size in 0..4 {
        for load in [false, true] {
            for ordered in [false, true] {
                let word = SCALAR_CLASS
                    | (size << SIZE_SHIFT)
                    | if load { LOAD_BIT | SBO_STATUS } else { 0 }
                    | if ordered { ACQUIRE_RELEASE_BIT } else { 0 }
                    | SBO_SECOND
                    | (2 << BASE_SHIFT)
                    | 1;
                let operand = decode(word).unwrap().unwrap();
                assert!(validate(&operand).is_ok());
                let required = requirements(&operand).unwrap();
                assert_eq!(required.required_flags & flags::EXCLUSIVE, flags::EXCLUSIVE);
                assert_eq!(required.required_flags & flags::WRITE != 0, !load);
                assert_eq!(
                    required.required_flags & flags::TAG_CHECKED,
                    flags::TAG_CHECKED
                );
                assert_eq!(required.required_flags & flags::PAIR, 0);
                assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
                forms += 1;
            }
        }
    }
    for size in 0..2 {
        for load in [false, true] {
            for ordered in [false, true] {
                let word = PAIR_CLASS
                    | (size << SIZE_SHIFT)
                    | if load { LOAD_BIT | SBO_STATUS } else { 0 }
                    | if ordered { ACQUIRE_RELEASE_BIT } else { 0 }
                    | (2 << SECOND_SHIFT)
                    | (3 << BASE_SHIFT)
                    | 1;
                let operand = decode(word).unwrap().unwrap();
                assert!(validate(&operand).is_ok());
                assert_eq!(
                    requirements(&operand).unwrap().required_flags & flags::PAIR,
                    0
                );
                forms += 1;
            }
        }
    }
    assert_eq!(decode(CLEAR_CLASS), Some(Ok(Operand::Clear)));
    assert!(validate(&Operand::Clear).is_ok());
    forms += 1;
    assert_eq!(forms, 25);
    assert_eq!(
        decode(OBSERVED_LOAD_WORD),
        Some(Ok(Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(9),
            data: Data::Scalar(Register::X(10)),
            kind: Kind::Load { acquire: false }
        }))
    );
}

#[test]
fn source_register_aliases_zr_and_acquire_intent_remain_explicit() {
    for element_bytes in [BYTE_BYTES, HALFWORD_BYTES, WORD_BYTES, DOUBLEWORD_BYTES] {
        for base in [Register::X(1), Register::Sp] {
            for data in [Register::X(1), Register::Zero] {
                let operand = Operand::Transfer {
                    element_bytes,
                    base,
                    data: Data::Scalar(data),
                    kind: Kind::Load { acquire: true },
                };
                assert!(validate(&operand).is_ok());
                assert!(matches!(
                    operand,
                    Operand::Transfer {
                        kind: Kind::Load { acquire: true },
                        ..
                    }
                ));
                assert_eq!(
                    requirements(&operand).unwrap().required_sp_alignment,
                    if base == Register::Sp {
                        SpAlignmentRequirement::Enabled
                    } else {
                        SpAlignmentRequirement::Any
                    }
                );
                let store = Operand::Transfer {
                    element_bytes,
                    base,
                    data: Data::Scalar(data),
                    kind: Kind::Store {
                        release: true,
                        status: Register::X(2),
                    },
                };
                assert!(validate(&store).is_ok());
            }
        }
    }
    let duplicate_sources = Operand::Transfer {
        element_bytes: DOUBLEWORD_BYTES,
        base: Register::X(1),
        data: Data::Pair([Register::X(1); 2]),
        kind: Kind::Store {
            release: false,
            status: Register::Zero,
        },
    };
    assert!(validate(&duplicate_sources).is_ok());
}

#[test]
fn malformed_and_constrained_operands_fail_before_any_emission() {
    let valid = Operand::Transfer {
        element_bytes: WORD_BYTES,
        base: Register::X(3),
        data: Data::Scalar(Register::X(1)),
        kind: Kind::Store {
            release: false,
            status: Register::X(0),
        },
    };
    assert!(validate(&valid).is_ok());
    let invalid = [
        Operand::Transfer {
            element_bytes: 0,
            base: Register::X(3),
            data: Data::Scalar(Register::X(1)),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: HALFWORD_BYTES,
            base: Register::X(3),
            data: Data::Pair([Register::X(1), Register::X(2)]),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::Zero,
            data: Data::Scalar(Register::X(1)),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(GPR_COUNT),
            data: Data::Scalar(Register::X(1)),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(3),
            data: Data::Scalar(Register::Sp),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(3),
            data: Data::Scalar(Register::X(GPR_COUNT)),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::Sp,
            data: Data::Pair([Register::Zero; 2]),
            kind: Kind::Load { acquire: false },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(3),
            data: Data::Scalar(Register::X(1)),
            kind: Kind::Store {
                release: false,
                status: Register::X(1),
            },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(3),
            data: Data::Scalar(Register::X(1)),
            kind: Kind::Store {
                release: false,
                status: Register::X(3),
            },
        },
        Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(3),
            data: Data::Scalar(Register::Zero),
            kind: Kind::Store {
                release: false,
                status: Register::Zero,
            },
        },
    ];
    for operand in invalid {
        assert!(requirements(&operand).is_err());
        let mut code = vec![0x90];
        assert!(emit_context(&mut code, &operand, 0x1000).is_err());
        assert_eq!(code, [0x90]);
    }
    assert_eq!(
        decode(PAIR_CLASS | LOAD_BIT | SBO_STATUS | (2 << BASE_SHIFT)),
        Some(Err(ConstrainedUndefined::PairLoadOutputs))
    );
    assert_eq!(
        decode(SCALAR_CLASS | SBO_SECOND | (1 << BASE_SHIFT)),
        Some(Err(ConstrainedUndefined::StoreStatusData))
    );
}

#[test]
fn exact_atomic_quantities_derive_read_and_write_host_requirements() {
    for base in [Register::X(3), Register::Sp] {
        for element_bytes in [BYTE_BYTES, HALFWORD_BYTES, WORD_BYTES, DOUBLEWORD_BYTES] {
            let load = Operand::Transfer {
                element_bytes,
                base,
                data: Data::Scalar(Register::Zero),
                kind: Kind::Load { acquire: true },
            };
            let required = requirements(&load).unwrap();
            assert_eq!(
                required.required_host_caps,
                if base != Register::Sp && element_bytes > BYTE_BYTES {
                    host_caps::ATOMIC_LOAD16
                } else {
                    0
                }
            );
            let store = Operand::Transfer {
                element_bytes,
                base,
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Store {
                    release: true,
                    status: Register::X(0),
                },
            };
            assert_eq!(requirements(&store).unwrap().required_host_caps, 0);
        }
        for element_bytes in [WORD_BYTES, DOUBLEWORD_BYTES] {
            let data = Data::Pair([Register::X(1), Register::X(2)]);
            let load = Operand::Transfer {
                element_bytes,
                base,
                data,
                kind: Kind::Load { acquire: true },
            };
            assert_eq!(
                requirements(&load).unwrap().required_host_caps,
                if base != Register::Sp || element_bytes == DOUBLEWORD_BYTES {
                    host_caps::ATOMIC_LOAD16
                } else {
                    0
                }
            );
            let store = Operand::Transfer {
                element_bytes,
                base,
                data,
                kind: Kind::Store {
                    release: true,
                    status: Register::X(0),
                },
            };
            assert_eq!(
                requirements(&store).unwrap().required_host_caps,
                if element_bytes == DOUBLEWORD_BYTES {
                    host_caps::CX16
                } else {
                    0
                }
            );
        }
    }
    let clear = requirements(&Operand::Clear).unwrap();
    assert_eq!(
        clear,
        MemoryRequirements {
            required_flags: flags::EXCLUSIVE,
            ..MemoryRequirements::default()
        }
    );
}

#[test]
fn immutable_profile_binds_sp_checks_and_conservative_read_capabilities() {
    for profile in [
        CheckedMemoryProfile::SpAlignmentEnabled,
        CheckedMemoryProfile::SpAlignmentDisabled,
    ] {
        for base in [Register::X(3), Register::Sp] {
            for (element_bytes, data) in [
                (BYTE_BYTES, Data::Scalar(Register::X(1))),
                (HALFWORD_BYTES, Data::Scalar(Register::X(1))),
                (WORD_BYTES, Data::Scalar(Register::X(1))),
                (DOUBLEWORD_BYTES, Data::Scalar(Register::X(1))),
                (WORD_BYTES, Data::Pair([Register::X(1), Register::X(2)])),
                (
                    DOUBLEWORD_BYTES,
                    Data::Pair([Register::X(1), Register::X(2)]),
                ),
            ] {
                for kind in [
                    Kind::Load { acquire: true },
                    Kind::Store {
                        release: true,
                        status: Register::X(0),
                    },
                ] {
                    let operand = Operand::Transfer {
                        element_bytes,
                        base,
                        data,
                        kind,
                    };
                    let checked = CheckedOperand::new(operand, profile).unwrap();
                    let required = super::requirements(&checked);
                    assert_eq!(
                        required.required_sp_alignment,
                        if base == Register::Sp {
                            profile.sp_requirement()
                        } else {
                            SpAlignmentRequirement::Any
                        }
                    );
                    let quantity = total_bytes(element_bytes, data);
                    let expected_caps = match kind {
                        Kind::Load { .. }
                            if quantity == u32::from(DOUBLEWORD_PAIR_BYTES)
                                || quantity > u32::from(BYTE_BYTES)
                                    && (base != Register::Sp
                                        || profile
                                            == CheckedMemoryProfile::SpAlignmentDisabled) =>
                        {
                            host_caps::ATOMIC_LOAD16
                        }
                        Kind::Store { .. } if quantity == u32::from(DOUBLEWORD_PAIR_BYTES) => {
                            host_caps::CX16
                        }
                        _ => 0,
                    };
                    assert_eq!(required.required_host_caps, expected_caps);
                    assert_eq!(required.required_flags, descriptor(&operand));
                }
            }
        }
        let clear = CheckedOperand::new(Operand::Clear, profile).unwrap();
        assert_eq!(
            super::requirements(&clear),
            MemoryRequirements {
                required_flags: flags::EXCLUSIVE,
                ..MemoryRequirements::default()
            }
        );
    }
}

#[test]
fn profile_specialization_preserves_gpr_clear_bytes() {
    const SOURCE_PC: u64 = 0x4100_0000;
    const ENTRY: &[u8] = &[
        0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3,
    ];
    const RET: u8 = 0xc3;
    const HISTORICAL_CLEAR_BODY: usize = 0;
    const HISTORICAL_GPR_WORD_LOAD_BODY: usize = 25;
    const HISTORICAL_SP_WORD_LOAD_BODY: usize = 97;
    let mut cases = vec![(Operand::Clear, HISTORICAL_CLEAR_BODY)];
    for (base, historical_body) in [
        (Register::X(3), HISTORICAL_GPR_WORD_LOAD_BODY),
        (Register::Sp, HISTORICAL_SP_WORD_LOAD_BODY),
    ] {
        cases.push((
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base,
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Load { acquire: false },
            },
            historical_body,
        ));
    }
    let historical =
        std::env::var_os("STELA_EXCLUSIVE_HISTORICAL_BODIES").map(std::path::PathBuf::from);
    for (operand, historical_body) in cases {
        let mut enabled = ENTRY.to_vec();
        let mut disabled = ENTRY.to_vec();
        super::emit_context(
            &mut enabled,
            &CheckedOperand::new(operand, CheckedMemoryProfile::SpAlignmentEnabled).unwrap(),
            SOURCE_PC,
        )
        .unwrap();
        super::emit_context(
            &mut disabled,
            &CheckedOperand::new(operand, CheckedMemoryProfile::SpAlignmentDisabled).unwrap(),
            SOURCE_PC,
        )
        .unwrap();
        enabled.push(RET);
        disabled.push(RET);
        if let Some(path) = &historical {
            assert_eq!(
                enabled,
                std::fs::read(path.join(format!("body-{historical_body}.bin"))).unwrap()
            );
        }
        if matches!(
            operand,
            Operand::Transfer {
                base: Register::Sp,
                ..
            }
        ) {
            assert!(disabled.len() < enabled.len());
        } else {
            assert_eq!(enabled, disabled);
        }
    }
}
