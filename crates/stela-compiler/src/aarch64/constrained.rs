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
mod tests;
