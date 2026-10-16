//! Load/store encodings with CONSTRAINED UNPREDICTABLE register overlaps
//! (LDPOVERLAP, WBOVERLAPLD, WBOVERLAPST) and the outcome Stela selects for each.

const PAIR_FORM_MASK: u32 = 0xffc0_0000;
const LDPSW_X_OFFSET: u32 = 0x6940_0000;
const LDPSW_X_POST: u32 = 0x68c0_0000;
const LDPSW_X_PRE: u32 = 0x69c0_0000;
const LDP_W_OFFSET: u32 = 0x2940_0000;
const LDP_W_POST: u32 = 0x28c0_0000;
const LDP_W_PRE: u32 = 0x29c0_0000;
const LDP_X_OFFSET: u32 = 0xa940_0000;
const LDP_X_POST: u32 = 0xa8c0_0000;
const LDP_X_PRE: u32 = 0xa9c0_0000;
const STP_W_POST: u32 = 0x2880_0000;
const STP_W_PRE: u32 = 0x2980_0000;
const STP_X_POST: u32 = 0xa880_0000;
const STP_X_PRE: u32 = 0xa980_0000;
const LDP_D_OFFSET: u32 = 0x6d40_0000;
const LDP_D_POST: u32 = 0x6cc0_0000;
const LDP_D_PRE: u32 = 0x6dc0_0000;
const LDP_Q_OFFSET: u32 = 0xad40_0000;
const LDP_Q_POST: u32 = 0xacc0_0000;
const LDP_Q_PRE: u32 = 0xadc0_0000;
const LDP_S_OFFSET: u32 = 0x2d40_0000;
const LDP_S_POST: u32 = 0x2cc0_0000;
const LDP_S_PRE: u32 = 0x2dc0_0000;
const LDNP_W: u32 = 0x2840_0000;
const LDNP_X: u32 = 0xa840_0000;
const LDNP_D: u32 = 0x6c40_0000;
const LDNP_Q: u32 = 0xac40_0000;
const LDNP_S: u32 = 0x2c40_0000;
const SCALAR_FORM_MASK: u32 = 0xffe0_0c00;
const LDRB_W_POST: u32 = 0x3840_0400;
const LDRB_W_PRE: u32 = 0x3840_0c00;
const LDRH_W_POST: u32 = 0x7840_0400;
const LDRH_W_PRE: u32 = 0x7840_0c00;
const LDRSB_W_POST: u32 = 0x38c0_0400;
const LDRSB_W_PRE: u32 = 0x38c0_0c00;
const LDRSB_X_POST: u32 = 0x3880_0400;
const LDRSB_X_PRE: u32 = 0x3880_0c00;
const LDRSH_W_POST: u32 = 0x78c0_0400;
const LDRSH_W_PRE: u32 = 0x78c0_0c00;
const LDRSH_X_POST: u32 = 0x7880_0400;
const LDRSH_X_PRE: u32 = 0x7880_0c00;
const LDRSW_X_POST: u32 = 0xb880_0400;
const LDRSW_X_PRE: u32 = 0xb880_0c00;
const LDR_W_POST: u32 = 0xb840_0400;
const LDR_W_PRE: u32 = 0xb840_0c00;
const LDR_X_POST: u32 = 0xf840_0400;
const LDR_X_PRE: u32 = 0xf840_0c00;
const STRB_W_POST: u32 = 0x3800_0400;
const STRB_W_PRE: u32 = 0x3800_0c00;
const STRH_W_POST: u32 = 0x7800_0400;
const STRH_W_PRE: u32 = 0x7800_0c00;
const STR_W_POST: u32 = 0xb800_0400;
const STR_W_PRE: u32 = 0xb800_0c00;
const STR_X_POST: u32 = 0xf800_0400;
const STR_X_PRE: u32 = 0xf800_0c00;

const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const SECOND_REGISTER_SHIFT: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedUnpredictable {
    PairLoadDestinationOverlap,
    LoadWritebackOverlap,
    StoreWritebackOverlap,
}

/// Only exact allocated classes participate. Integer writeback overlap is
/// resolved before duplicate destinations, matching the pinned decode order.
/// Vector/base register numbers are independent banks; encoded31 is SP as base.
fn decode_pair(word: u32) -> Option<ConstrainedUnpredictable> {
    let (load, check_writeback_overlap) = match word & PAIR_FORM_MASK {
        LDPSW_X_POST | LDPSW_X_PRE | LDP_W_POST | LDP_W_PRE | LDP_X_POST | LDP_X_PRE => {
            (true, true)
        }
        STP_W_POST | STP_W_PRE | STP_X_POST | STP_X_PRE => (false, true),
        LDPSW_X_OFFSET | LDP_W_OFFSET | LDP_X_OFFSET | LDP_D_OFFSET | LDP_D_POST | LDP_D_PRE
        | LDP_Q_OFFSET | LDP_Q_POST | LDP_Q_PRE | LDP_S_OFFSET | LDP_S_POST | LDP_S_PRE
        | LDNP_W | LDNP_X | LDNP_D | LDNP_Q | LDNP_S => (true, false),
        _ => return None,
    };
    let first = word & REGISTER_MASK;
    let second = (word >> SECOND_REGISTER_SHIFT) & REGISTER_MASK;
    let base = (word >> BASE_SHIFT) & REGISTER_MASK;
    if check_writeback_overlap && base != REGISTER_MASK && (base == first || base == second) {
        return Some(if load {
            ConstrainedUnpredictable::LoadWritebackOverlap
        } else {
            ConstrainedUnpredictable::StoreWritebackOverlap
        });
    }
    (load && first == second).then_some(ConstrainedUnpredictable::PairLoadDestinationOverlap)
}

/// Resolve only source-proved allocated constrained operands. All other words
/// continue through their ordinary decoder, including reserved neighbors.
pub fn decode(word: u32) -> Option<ConstrainedUnpredictable> {
    decode_pair(word).or_else(|| decode_scalar(word))
}

fn decode_scalar(word: u32) -> Option<ConstrainedUnpredictable> {
    let load = match word & SCALAR_FORM_MASK {
        LDRB_W_POST | LDRB_W_PRE | LDRH_W_POST | LDRH_W_PRE | LDRSB_W_POST | LDRSB_W_PRE
        | LDRSB_X_POST | LDRSB_X_PRE | LDRSH_W_POST | LDRSH_W_PRE | LDRSH_X_POST | LDRSH_X_PRE
        | LDRSW_X_POST | LDRSW_X_PRE | LDR_W_POST | LDR_W_PRE | LDR_X_POST | LDR_X_PRE => true,
        STRB_W_POST | STRB_W_PRE | STRH_W_POST | STRH_W_PRE | STR_W_POST | STR_W_PRE
        | STR_X_POST | STR_X_PRE => false,
        _ => return None,
    };
    let data = word & REGISTER_MASK;
    let base = (word >> BASE_SHIFT) & REGISTER_MASK;
    (base != REGISTER_MASK && base == data).then_some(if load {
        ConstrainedUnpredictable::LoadWritebackOverlap
    } else {
        ConstrainedUnpredictable::StoreWritebackOverlap
    })
}

#[cfg(test)]
mod tests {
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
                            form | data
                                | (base << BASE_SHIFT)
                                | (immediate << SCALAR_IMMEDIATE_SHIFT)
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
}
