use super::*;
use crate::{GuestAddress, Lifter, aarch64::Decoder};

const TEST_PC: u64 = 0x1000;
const STP_W_OFFSET: u32 = 0x2900_0000;
const STP_W_PRE: u32 = 0x2980_0000;
const STP_W_POST: u32 = 0x2880_0000;
const STP_X_OFFSET: u32 = 0xa900_0000;
const STP_X_PRE: u32 = 0xa980_0000;
const STP_X_POST: u32 = 0xa880_0000;
const STNP_W: u32 = 0x2800_0000;
const STNP_X: u32 = 0xa800_0000;
const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const SECOND_DATA_SHIFT: u32 = 10;
const IMMEDIATE_SHIFT: u32 = 15;
const IMMEDIATE_MASK: u32 = 127;
const FORMS: [(u32, u8, AddressMode, bool); 8] = [
    (STP_W_OFFSET, WORD_BYTES, AddressMode::Offset, false),
    (STP_W_PRE, WORD_BYTES, AddressMode::PreIndex, false),
    (STP_W_POST, WORD_BYTES, AddressMode::PostIndex, false),
    (STP_X_OFFSET, DOUBLEWORD_BYTES, AddressMode::Offset, false),
    (STP_X_PRE, DOUBLEWORD_BYTES, AddressMode::PreIndex, false),
    (STP_X_POST, DOUBLEWORD_BYTES, AddressMode::PostIndex, false),
    (STNP_W, WORD_BYTES, AddressMode::Offset, true),
    (STNP_X, DOUBLEWORD_BYTES, AddressMode::Offset, true),
];

fn word(form: u32, data: [u32; 2], base: u32, immediate: i32) -> u32 {
    form | data[0]
        | (base << BASE_SHIFT)
        | (data[1] << SECOND_DATA_SHIFT)
        | ((immediate as u32 & IMMEDIATE_MASK) << IMMEDIATE_SHIFT)
}

fn lifted(word: u32) -> Operation {
    Decoder.lift(GuestAddress(TEST_PC), word).unwrap().operation
}

#[test]
fn allocated_pair_stores_keep_register_roles_and_descriptor_intent() {
    for (form, bytes, mode, non_temporal) in FORMS {
        for data in [
            [0, 1],
            [1, 1],
            [30, 0],
            [REGISTER_MASK, 0],
            [0, REGISTER_MASK],
            [REGISTER_MASK; 2],
        ] {
            for base in [2, 30, REGISTER_MASK] {
                for immediate in [IMMEDIATE_MIN, -1, 0, 1, IMMEDIATE_MAX] {
                    let operation = lifted(word(form, data, base, immediate));
                    if mode != AddressMode::Offset && base != REGISTER_MASK && data.contains(&base)
                    {
                        assert_eq!(operation, Operation::Nop);
                        continue;
                    }
                    let operand = Operand::from_operation(
                        &operation,
                        CheckedMemoryProfile::SpAlignmentEnabled,
                    )
                    .unwrap();
                    assert_eq!(operand.bytes, bytes);
                    assert_eq!(operand.mode, mode);
                    assert_eq!(operand.non_temporal, non_temporal);
                    assert_eq!(operand.displacement, immediate * i32::from(bytes));
                    assert_eq!(operand.base == Register::Sp, base == REGISTER_MASK);
                    for (actual, encoded) in operand.data.into_iter().zip(data) {
                        assert_eq!(
                            actual,
                            if encoded == REGISTER_MASK {
                                Register::Zero
                            } else {
                                Register::X(encoded as u8)
                            }
                        );
                    }
                    let required = requirements(&operand);
                    assert_eq!(
                        required.required_flags & (flags::WRITE | flags::PAIR),
                        flags::WRITE | flags::PAIR
                    );
                    assert_eq!(
                        required.required_flags & flags::NON_TEMPORAL != 0,
                        non_temporal
                    );
                    assert_eq!(
                        required.required_flags & flags::TAG_CHECKED != 0,
                        mode != AddressMode::Offset || base != REGISTER_MASK
                    );
                    assert_eq!(
                        required.required_host_caps,
                        if bytes == DOUBLEWORD_BYTES
                            && (base != REGISTER_MASK
                                || mode == AddressMode::PostIndex
                                || immediate & 1 == 0)
                        {
                            host_caps::CX16
                        } else {
                            0
                        }
                    );
                    assert_eq!(
                        required.required_sp_alignment,
                        if base == REGISTER_MASK {
                            SpAlignmentRequirement::Enabled
                        } else {
                            SpAlignmentRequirement::Any
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn constrained_writeback_nops_never_enter_pair_service() {
    for form in [STP_W_PRE, STP_W_POST, STP_X_PRE, STP_X_POST] {
        for base in 0..REGISTER_MASK {
            for data in [[base, 0], [0, base], [base, base]] {
                let operation = lifted(word(form, data, base, 1));
                assert_eq!(operation, Operation::Nop);
                assert_eq!(
                    Operand::from_operation(&operation, CheckedMemoryProfile::SpAlignmentEnabled),
                    None
                );
            }
        }
    }
}

#[test]
fn forged_store_descriptors_decline_before_emission() {
    let valid = Operand {
        profile: Profile::NormalWb(CheckedMemoryProfile::SpAlignmentEnabled),
        transfer: MemoryTransfer::Store,
        bytes: DOUBLEWORD_BYTES,
        data: [Register::X(0), Register::Zero],
        base: Register::X(2),
        displacement: 0,
        mode: AddressMode::PreIndex,
        non_temporal: false,
    };
    assert!(valid.is_valid());
    for invalid in [
        Operand { bytes: 0, ..valid },
        Operand {
            bytes: WORD_BYTES / 2,
            ..valid
        },
        Operand {
            data: [Register::Sp, Register::Zero],
            ..valid
        },
        Operand {
            data: [Register::X(REGISTER_COUNT), Register::Zero],
            ..valid
        },
        Operand {
            base: Register::Zero,
            ..valid
        },
        Operand {
            base: Register::X(REGISTER_COUNT),
            ..valid
        },
        Operand {
            base: Register::X(0),
            ..valid
        },
        Operand {
            displacement: 1,
            ..valid
        },
        Operand {
            displacement: (IMMEDIATE_MAX + 1) * i32::from(DOUBLEWORD_BYTES),
            ..valid
        },
        Operand {
            displacement: (IMMEDIATE_MIN - 1) * i32::from(DOUBLEWORD_BYTES),
            ..valid
        },
    ] {
        assert!(!invalid.is_valid(), "{invalid:?}");
    }
}

#[test]
fn checked_sp_fixed_half_pairs_need_no_unused_quadword_capability() {
    for mode in [
        AddressMode::Offset,
        AddressMode::PreIndex,
        AddressMode::PostIndex,
    ] {
        for (displacement, fixed_half) in [
            (-512, false),
            (-8, true),
            (0, false),
            (8, true),
            (16, false),
            (504, true),
        ] {
            for base in [Register::Sp, Register::X(2)] {
                let operand = Operand {
                    profile: Profile::NormalWb(CheckedMemoryProfile::SpAlignmentEnabled),
                    transfer: MemoryTransfer::Store,
                    bytes: DOUBLEWORD_BYTES,
                    data: [Register::X(0), Register::X(1)],
                    base,
                    displacement,
                    mode,
                    non_temporal: false,
                };
                assert!(operand.is_valid());
                let required = requirements(&operand);
                let expected =
                    if base == Register::Sp && mode != AddressMode::PostIndex && fixed_half {
                        0
                    } else {
                        host_caps::CX16
                    };
                assert_eq!(required.required_host_caps, expected, "{operand:?}");
                assert_eq!(
                    required.required_sp_alignment,
                    if base == Register::Sp {
                        SpAlignmentRequirement::Enabled
                    } else {
                        SpAlignmentRequirement::Any
                    }
                );
            }
        }
    }
}

#[test]
fn disabled_sp_policy_never_borrows_enabled_alignment_proofs() {
    for (form, bytes, _, _) in FORMS {
        for base in [2, REGISTER_MASK] {
            for immediate in [IMMEDIATE_MIN, -1, 0, 1, IMMEDIATE_MAX] {
                let operation = lifted(word(form, [0, 1], base, immediate));
                let operand =
                    Operand::from_operation(&operation, CheckedMemoryProfile::SpAlignmentDisabled)
                        .unwrap();
                let required = requirements(&operand);
                assert_eq!(
                    required.required_sp_alignment,
                    if base == REGISTER_MASK {
                        SpAlignmentRequirement::Disabled
                    } else {
                        SpAlignmentRequirement::Any
                    }
                );
                assert_eq!(
                    required.required_host_caps,
                    if bytes == DOUBLEWORD_BYTES {
                        host_caps::CX16
                    } else {
                        0
                    }
                );
            }
        }
    }
}

const LOAD_FORMS: [(u32, u8, bool, Width); 11] = [
    (0x2940_0000, WORD_BYTES, false, Width::W32),
    (0x29c0_0000, WORD_BYTES, false, Width::W32),
    (0x28c0_0000, WORD_BYTES, false, Width::W32),
    (0xa940_0000, DOUBLEWORD_BYTES, false, Width::X64),
    (0xa9c0_0000, DOUBLEWORD_BYTES, false, Width::X64),
    (0xa8c0_0000, DOUBLEWORD_BYTES, false, Width::X64),
    (0x6940_0000, WORD_BYTES, true, Width::X64),
    (0x69c0_0000, WORD_BYTES, true, Width::X64),
    (0x68c0_0000, WORD_BYTES, true, Width::X64),
    (0x2840_0000, WORD_BYTES, false, Width::W32),
    (0xa840_0000, DOUBLEWORD_BYTES, false, Width::X64),
];

#[test]
fn allocated_load_pairs_keep_transfer_and_readonly_capability() {
    for (form, bytes, signed, width) in LOAD_FORMS {
        for profile in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            for data in [[0, 1], [REGISTER_MASK, 0], [0, REGISTER_MASK]] {
                for base in [0, 1, 2, REGISTER_MASK] {
                    for immediate in [IMMEDIATE_MIN, -1, 0, 1, IMMEDIATE_MAX] {
                        let operation = lifted(word(form, data, base, immediate));
                        if operation == Operation::Nop {
                            continue;
                        }
                        let operand = Operand::from_operation(&operation, profile).unwrap();
                        assert_eq!(operand.transfer, MemoryTransfer::Load { signed, width });
                        assert_eq!(operand.bytes, bytes);
                        let required = requirements(&operand);
                        assert_eq!(
                            required.required_flags & (flags::WRITE | flags::PAIR),
                            flags::PAIR
                        );
                        assert_eq!(required.required_host_caps, host_caps::ATOMIC_LOAD16);
                        assert_eq!(
                            required.required_sp_alignment,
                            if base == REGISTER_MASK {
                                profile.sp_requirement()
                            } else {
                                SpAlignmentRequirement::Any
                            }
                        );
                        assert_eq!(
                            required.required_flags & flags::TAG_CHECKED != 0,
                            operand.mode != AddressMode::Offset || base != REGISTER_MASK
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn constructed_invalid_load_pairs_decline_and_constrained_encodings_stay_nop() {
    let valid = Operand::from_operation(
        &lifted(word(0xa940_0000, [0, 1], 2, 0)),
        CheckedMemoryProfile::SpAlignmentDisabled,
    )
    .unwrap();
    for invalid in [
        Operand {
            data: [Register::X(0); 2],
            ..valid
        },
        Operand {
            data: [Register::Zero; 2],
            ..valid
        },
        Operand {
            transfer: MemoryTransfer::Load {
                signed: true,
                width: Width::X64,
            },
            ..valid
        },
        Operand {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            ..valid
        },
        Operand {
            bytes: WORD_BYTES,
            transfer: MemoryTransfer::Load {
                signed: true,
                width: Width::W32,
            },
            ..valid
        },
        Operand {
            bytes: WORD_BYTES,
            non_temporal: true,
            transfer: MemoryTransfer::Load {
                signed: true,
                width: Width::X64,
            },
            ..valid
        },
        Operand {
            base: Register::X(0),
            mode: AddressMode::PostIndex,
            ..valid
        },
    ] {
        assert!(!invalid.is_valid(), "{invalid:?}");
    }
    for (form, _, _, _) in LOAD_FORMS {
        assert_eq!(lifted(word(form, [0, 0], 2, 0)), Operation::Nop);
        for base in [0, 1] {
            let operation = lifted(word(form, [0, 1], base, 1));
            if (form >> 23) & 3 == 1 || (form >> 23) & 3 == 3 {
                assert_eq!(operation, Operation::Nop);
            }
        }
    }
}
