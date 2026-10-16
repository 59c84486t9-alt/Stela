use super::*;
const FORMS: [(u32, bool, bool); 27] = [
    (LDPSW_X_OFFSET, true, false),
    (LDPSW_X_POST, true, true),
    (LDPSW_X_PRE, true, true),
    (LDP_W_OFFSET, true, false),
    (LDP_W_POST, true, true),
    (LDP_W_PRE, true, true),
    (LDP_X_OFFSET, true, false),
    (LDP_X_POST, true, true),
    (LDP_X_PRE, true, true),
    (STP_W_POST, false, true),
    (STP_W_PRE, false, true),
    (STP_X_POST, false, true),
    (STP_X_PRE, false, true),
    (LDP_D_OFFSET, true, false),
    (LDP_D_POST, true, false),
    (LDP_D_PRE, true, false),
    (LDP_Q_OFFSET, true, false),
    (LDP_Q_POST, true, false),
    (LDP_Q_PRE, true, false),
    (LDP_S_OFFSET, true, false),
    (LDP_S_POST, true, false),
    (LDP_S_PRE, true, false),
    (LDNP_W, true, false),
    (LDNP_X, true, false),
    (LDNP_D, true, false),
    (LDNP_Q, true, false),
    (LDNP_S, true, false),
];
const IMMEDIATE_SHIFT: u32 = 15;
const IMMEDIATE_MASK: u32 = 127;

fn expected(
    load: bool,
    check_writeback_overlap: bool,
    first: u32,
    second: u32,
    base: u32,
) -> Option<ConstrainedUnpredictable> {
    if check_writeback_overlap && base < REGISTER_MASK && (base == first || base == second) {
        Some(if load {
            ConstrainedUnpredictable::LoadWritebackOverlap
        } else {
            ConstrainedUnpredictable::StoreWritebackOverlap
        })
    } else if load && first == second {
        Some(ConstrainedUnpredictable::PairLoadDestinationOverlap)
    } else {
        None
    }
}

#[test]
fn every_register_pair_base_and_constraint_priority_is_explicit() {
    for (form, load, check_writeback_overlap) in FORMS {
        for first in 0..=REGISTER_MASK {
            for second in 0..=REGISTER_MASK {
                for base in 0..=REGISTER_MASK {
                    let word =
                        form | first | (second << SECOND_REGISTER_SHIFT) | (base << BASE_SHIFT);
                    assert_eq!(
                        decode(word),
                        expected(load, check_writeback_overlap, first, second, base)
                    );
                }
            }
        }
    }
}

#[test]
fn all_immediates_preserve_constraint_identity_and_sp_is_a_separate_base() {
    for (form, load, check_writeback_overlap) in FORMS {
        for immediate in 0..=IMMEDIATE_MASK {
            for (first, second, base) in [
                (0, 0, 0),
                (0, 1, 0),
                (0, 1, 1),
                (0, 1, 31),
                (31, 31, 31),
                (31, 0, 0),
            ] {
                let word = form
                    | first
                    | (second << SECOND_REGISTER_SHIFT)
                    | (base << BASE_SHIFT)
                    | (immediate << IMMEDIATE_SHIFT);
                assert_eq!(
                    decode(word),
                    expected(load, check_writeback_overlap, first, second, base)
                );
            }
        }
    }
}

#[test]
fn other_allocations_and_store_offset_neighbors_do_not_become_nops() {
    for word in [
        0x2900_0000,
        0xa900_0000,
        0x6800_0000,
        0x6840_0000,
        0xe840_0000,
        0xecc0_0000,
        0xed40_0000,
        0xedc0_0000,
        0xc87f_0000,
        0x885f_7c00,
        0x3dc0_0000,
        0xd503_201f,
    ] {
        assert_eq!(decode(word), None);
    }
}
const SCALAR_FORMS: [(u32, bool); 26] = [
    (LDRB_W_POST, true),
    (LDRB_W_PRE, true),
    (LDRH_W_POST, true),
    (LDRH_W_PRE, true),
    (LDRSB_W_POST, true),
    (LDRSB_W_PRE, true),
    (LDRSB_X_POST, true),
    (LDRSB_X_PRE, true),
    (LDRSH_W_POST, true),
    (LDRSH_W_PRE, true),
    (LDRSH_X_POST, true),
    (LDRSH_X_PRE, true),
    (LDRSW_X_POST, true),
    (LDRSW_X_PRE, true),
    (LDR_W_POST, true),
    (LDR_W_PRE, true),
    (LDR_X_POST, true),
    (LDR_X_PRE, true),
    (STRB_W_POST, false),
    (STRB_W_PRE, false),
    (STRH_W_POST, false),
    (STRH_W_PRE, false),
    (STR_W_POST, false),
    (STR_W_PRE, false),
    (STR_X_POST, false),
    (STR_X_PRE, false),
];
const SCALAR_IMMEDIATE_SHIFT: u32 = 12;
const SCALAR_IMMEDIATE_MASK: u32 = 511;

#[test]
fn scalar_register_aliases_and_full_imm9_are_orthogonal() {
    for (form, load) in SCALAR_FORMS {
        for data in 0..=REGISTER_MASK {
            for base in 0..=REGISTER_MASK {
                let expected = (data == base && base != REGISTER_MASK).then_some(if load {
                    ConstrainedUnpredictable::LoadWritebackOverlap
                } else {
                    ConstrainedUnpredictable::StoreWritebackOverlap
                });
                assert_eq!(decode(form | data | (base << BASE_SHIFT)), expected);
            }
        }
        for immediate in 0..=SCALAR_IMMEDIATE_MASK {
            for (data, base) in [(0, 0), (30, 30), (31, 31), (0, 1), (31, 0), (0, 31)] {
                let expected = (data == base && base != REGISTER_MASK).then_some(if load {
                    ConstrainedUnpredictable::LoadWritebackOverlap
                } else {
                    ConstrainedUnpredictable::StoreWritebackOverlap
                });
                assert_eq!(
                    decode(
                        form | data | (base << BASE_SHIFT) | (immediate << SCALAR_IMMEDIATE_SHIFT)
                    ),
                    expected
                );
            }
        }
    }
}

#[test]
fn scalar_reserved_opcodes_unscaled_register_and_vector_neighbors_are_explicit() {
    for word in [
        0xb8c0_0400,
        0xb8c0_0c00,
        0xf880_0400,
        0xf880_0c00,
        0xf8c0_0400,
        0xf8c0_0c00,
        0x3840_0000,
        0x3840_0800,
        0x3860_0400,
        0x3c40_0400,
        0x3c40_0c00,
        0x3900_0000,
        0x3940_0000,
    ] {
        assert_eq!(decode(word), None);
    }
}
