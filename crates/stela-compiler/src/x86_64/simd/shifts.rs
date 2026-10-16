//! AdvSIMD shifts by immediate and per-lane register, including width changes.
use super::{
    Host, commit, greater, packed, read_vector, rearrange::constant, shuffle, vector_offset,
};
use crate::{
    TargetCpu,
    aarch64::simd::shifts::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};
use alloc::vec::Vec;

const BITS_PER_BYTE: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const LOW_DWORDS_OF_QWORDS: u8 = 0x88;
const HIGH_DWORDS_OF_QWORDS: u8 = 0xdd;

fn lane_mask(code: &mut Vec<u8>, xmm: u8, lane_bytes: u8, value: u64) {
    let bytes = value.to_le_bytes();
    constant(
        code,
        xmm,
        core::array::from_fn(|i| bytes[i % usize::from(lane_bytes)]),
    );
}
fn add(code: &mut Vec<u8>, destination: u8, source: u8, lane_bytes: u8) {
    packed(
        code,
        match lane_bytes {
            1 => Host::AddByte,
            2 => Host::AddWord,
            4 => Host::AddDword,
            8 => Host::AddQword,
            _ => unreachable!(),
        },
        destination,
        source,
    );
}
pub(crate) fn logical_shift(code: &mut Vec<u8>, xmm: u8, lane_bytes: u8, amount: u8, left: bool) {
    if amount == 0 {
        return;
    }
    let opcode = match (left, lane_bytes) {
        (true, 1 | 2) => Shift::LeftWord,
        (true, 4) => Shift::LeftDword,
        (true, 8) => Shift::LeftQword,
        (false, 1 | 2) => Shift::RightWord,
        (false, 4) => Shift::RightDword,
        (false, 8) => Shift::RightQword,
        _ => unreachable!("reviewed lane width"),
    };
    opcode.emit(code, xmm, amount);
    if lane_bytes == 1 {
        // Word shifts otherwise move bits across the neighboring byte lane.
        let mask = if left {
            (0xffu16 << amount) & 0xff
        } else {
            0xffu16 >> amount
        };
        lane_mask(code, 5, 1, u64::from(mask));
        packed(code, Host::And, xmm, 5);
    }
}
pub(crate) fn right_shift(code: &mut Vec<u8>, xmm: u8, lane_bytes: u8, amount: u8, signed: bool) {
    if amount == 0 {
        return;
    }
    if !signed {
        logical_shift(code, xmm, lane_bytes, amount, false);
        return;
    }
    match lane_bytes {
        2 => Shift::ArithmeticWord.emit(code, xmm, amount),
        4 => Shift::ArithmeticDword.emit(code, xmm, amount),
        1 | 8 => {
            // XMM4 is the replicated lane sign. Signed qwords use their high
            // dword; signed bytes use PCMPGTB zero,source. Both handle shift=width.
            if lane_bytes == 8 {
                packed(code, Host::MoveAligned, 4, xmm);
                Shift::ArithmeticDword.emit(code, 4, 31);
                shuffle(code, 4, 4, 0xf5);
            } else {
                packed(code, Host::Xor, 4, 4);
                packed(code, Host::GreaterByte, 4, xmm);
            }
            logical_shift(code, xmm, lane_bytes, amount, false);
            logical_shift(code, 4, lane_bytes, lane_bytes * 8 - amount, true);
            packed(code, Host::Or, xmm, 4);
        }
        _ => unreachable!("reviewed lane width"),
    }
}
pub(crate) fn rounded_right(
    code: &mut Vec<u8>,
    lane_bytes: u8,
    amount: u8,
    signed: bool,
    round: bool,
) {
    if round {
        packed(code, Host::MoveAligned, 1, 0);
        logical_shift(code, 1, lane_bytes, amount - 1, false);
        lane_mask(code, 2, lane_bytes, 1);
        packed(code, Host::And, 1, 2);
    }
    right_shift(code, 0, lane_bytes, amount, signed);
    if round {
        add(code, 0, 1, lane_bytes);
    }
}
fn narrow(
    code: &mut Vec<u8>,
    lane_bytes: u8,
    amount: u8,
    round: bool,
    upper: bool,
    destination: u8,
) {
    rounded_right(code, lane_bytes * 2, amount, false, round);
    pack_truncated(code, lane_bytes, upper, destination);
}

/// Shift first, then clamp. Rounding is computed as shifted value plus the
/// discarded high bit, so signed overflow and unsigned carry are never lost.
fn saturating_narrow(
    code: &mut Vec<u8>,
    operand: &Operand,
    signed_source: bool,
    unsigned_result: bool,
    round: bool,
    upper: bool,
    target: TargetCpu,
) {
    let lane = operand.lane_bytes;
    let wide = lane * 2;
    let may_saturate =
        round || operand.amount != lane * BITS_PER_BYTE || signed_source == unsigned_result;
    if !may_saturate {
        // Both signednesses extract the source's high half as bits. Arithmetic
        // H/S shifts put that half in signed pack range; D needs only a shuffle.
        // QC stays untouched, including poisoned inactive scalar lanes.
        match lane {
            1 | 2 => {
                right_shift(code, 0, wide, operand.amount, true);
                packed(
                    code,
                    if lane == 1 {
                        Host::PackSignedWordToByte
                    } else {
                        Host::PackSignedDwordToWord
                    },
                    0,
                    0,
                );
            }
            4 => shuffle(code, 0, 0, HIGH_DWORDS_OF_QWORDS),
            _ => unreachable!("allocated in-range narrowing width"),
        }
        packed(code, Host::MoveAligned, 6, 0);
    } else {
        rounded_right(code, wide, operand.amount, signed_source, round);
        if lane < 4 {
            saturating_narrow_pack(code, lane, signed_source, unsigned_result, target);
        } else {
            saturating_narrow_qword(code, unsigned_result, signed_source, target);
        }
    }
    let scalar = operand.bytes == lane;
    if may_saturate {
        super::saturating::publish_qc(code, if scalar { wide } else { VECTOR_BYTES });
    }
    if upper {
        read_vector(code, operand.destination, 1);
        packed(code, Host::UnpackLowQword, 1, 6);
        commit(code, operand.destination, 1);
    } else {
        if scalar {
            constant(
                code,
                1,
                core::array::from_fn(|i| if i < usize::from(lane) { u8::MAX } else { 0 }),
            );
            packed(code, Host::And, 6, 1);
        } else {
            packed(code, Host::MoveQword, 6, 6);
        }
        commit(code, operand.destination, 6);
    }
}

/// Native packs clamp H/S sources. Reconstructing the result and comparing it
/// with the shifted source derives QC without reimplementing the pack bounds.
/// XMM6 retains the packed result and XMM4 receives the wide saturation mask.
fn saturating_narrow_pack(
    code: &mut Vec<u8>,
    lane: u8,
    signed_source: bool,
    unsigned_result: bool,
    target: TargetCpu,
) {
    let wide = lane * 2;
    packed(code, Host::MoveAligned, 3, 0);
    if !signed_source {
        // Shift>=1 leaves only one possible negative signed representation:
        // unsigned MAX rounded by one becomes exactly the wide sign bit.
        // Change it to signed MAX before the signed-input host pack; both
        // values saturate to the same bound. Compare against the original.
        super::saturating::sign_mask(code, 4, 0, wide);
        packed(code, Host::Xor, 0, 4);
    }
    match (unsigned_result, lane) {
        (false, 1) => packed(code, Host::PackSignedWordToByte, 0, 0),
        (true, 1) => packed(code, Host::PackUnsignedWordToByte, 0, 0),
        (false, 2) => packed(code, Host::PackSignedDwordToWord, 0, 0),
        (true, 2) if target >= TargetCpu::Sse41 => {
            Host::PackUnsignedDwordToWord.register(code, 0, 0, target);
        }
        (true, 2) => {
            // Translate [0,65535] into signed halfword bounds. The shifted
            // source range keeps this subtraction within signed dword range.
            let bias = 1u64 << (lane * BITS_PER_BYTE - 1);
            lane_mask(code, 1, wide, bias);
            packed(code, Host::SubDword, 0, 1);
            packed(code, Host::PackSignedDwordToWord, 0, 0);
            lane_mask(code, 1, lane, bias);
            packed(code, Host::Xor, 0, 1);
        }
        _ => unreachable!("allocated native narrowing pack"),
    }
    packed(code, Host::MoveAligned, 6, 0);
    if unsigned_result {
        packed(code, Host::Xor, 1, 1);
    } else {
        super::saturating::sign_mask(code, 1, 0, lane);
    }
    packed(
        code,
        if lane == 1 {
            Host::UnpackLowByte
        } else {
            Host::UnpackLowWord
        },
        0,
        1,
    );
    packed(code, Host::MoveAligned, 4, 0);
    packed(
        code,
        if wide == 2 {
            Host::EqualWord
        } else {
            Host::EqualDword
        },
        4,
        3,
    );
    packed(code, Host::EqualDword, 1, 1);
    packed(code, Host::Xor, 4, 1);
}

/// SSE2 has no saturating qword pack. Compare both bounds before selecting
/// clamped qwords; the checked SSE4.2 comparison replaces its baseline recipe.
fn saturating_narrow_qword(
    code: &mut Vec<u8>,
    unsigned_result: bool,
    signed_source: bool,
    target: TargetCpu,
) {
    const DESTINATION_BYTES: u8 = 4;
    const SOURCE_BYTES: u8 = DESTINATION_BYTES * 2;
    let high = if unsigned_result {
        u64::from(u32::MAX)
    } else {
        i32::MAX as u64
    };
    let low = if unsigned_result {
        0
    } else {
        i64::from(i32::MIN) as u64
    };
    packed(code, Host::MoveAligned, 5, 0);
    lane_mask(code, 1, SOURCE_BYTES, high);
    greater(code, SOURCE_BYTES, !signed_source, target);
    packed(code, Host::MoveAligned, 6, 0);
    if signed_source {
        lane_mask(code, 0, SOURCE_BYTES, low);
        packed(code, Host::MoveAligned, 1, 5);
        greater(code, SOURCE_BYTES, false, target);
    } else {
        packed(code, Host::Xor, 0, 0);
    }
    lane_mask(code, 1, SOURCE_BYTES, low);
    packed(code, Host::Xor, 1, 5);
    packed(code, Host::And, 1, 0);
    packed(code, Host::Xor, 5, 1);
    lane_mask(code, 1, SOURCE_BYTES, high);
    packed(code, Host::Xor, 1, 5);
    packed(code, Host::And, 1, 6);
    packed(code, Host::Xor, 5, 1);
    packed(code, Host::MoveAligned, 4, 0);
    packed(code, Host::Or, 4, 6);
    shuffle(code, 6, 5, LOW_DWORDS_OF_QWORDS);
}
pub(super) fn pack_truncated(code: &mut Vec<u8>, lane_bytes: u8, upper: bool, destination: u8) {
    match lane_bytes {
        1 => {
            lane_mask(code, 2, 2, 0xff);
            packed(code, Host::And, 0, 2);
            packed(code, Host::PackUnsignedWordToByte, 0, 0);
        }
        2 => {
            // Convert each low halfword to a signed dword before PACKSSDW:
            // every input is in range, so this truncates instead of saturating.
            Shift::LeftDword.emit(code, 0, 16);
            Shift::ArithmeticDword.emit(code, 0, 16);
            packed(code, Host::PackSignedDwordToWord, 0, 0);
        }
        4 => shuffle(code, 0, 0, 0x88), // select low dword of each qword
        _ => unreachable!("reviewed narrowing width"),
    }
    if upper {
        read_vector(code, destination, 1);
        packed(code, Host::UnpackLowQword, 1, 0);
        commit(code, destination, 1);
    } else {
        packed(code, Host::MoveQword, 0, 0);
        commit(code, destination, 0);
    }
}
fn widen(code: &mut Vec<u8>, lane_bytes: u8, amount: u8, signed: bool, upper: bool) {
    if upper {
        Shift::RightBytes.emit(code, 0, 8);
    }
    packed(code, Host::Xor, 1, 1);
    if signed {
        packed(
            code,
            match lane_bytes {
                1 => Host::GreaterByte,
                2 => Host::GreaterWord,
                4 => Host::GreaterDword,
                _ => unreachable!(),
            },
            1,
            0,
        );
    }
    packed(
        code,
        match lane_bytes {
            1 => Host::UnpackLowByte,
            2 => Host::UnpackLowWord,
            4 => Host::UnpackLowDword,
            _ => unreachable!(),
        },
        0,
        1,
    );
    logical_shift(code, 0, lane_bytes * 2, amount, true);
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Operand {
        kind,
        destination,
        source,
        lane_bytes,
        amount,
        bytes,
    } = *operand;
    match kind {
        Kind::Register {
            signed,
            round,
            saturating,
            counts,
        } => {
            register_shift(
                code,
                operand,
                Some(counts),
                signed,
                !signed,
                round,
                saturating,
            );
            return;
        }
        Kind::SaturatingImmediate {
            signed_source,
            unsigned_result,
        } => {
            if bytes > lane_bytes {
                saturating_immediate_vector(code, operand, signed_source, unsigned_result);
                return;
            }
            register_shift(
                code,
                operand,
                None,
                signed_source,
                unsigned_result,
                false,
                true,
            );
            return;
        }
        _ => {}
    }
    if matches!(kind, Kind::Right { insert: true, .. }) && amount == lane_bytes * 8 {
        // SRI by the complete element width preserves every active old bit.
        // Retain a real load/store interval for precise source-map entries.
        read_vector(code, destination, 0);
        if bytes == 8 {
            packed(code, Host::MoveQword, 0, 0);
        }
        commit(code, destination, 0);
        return;
    }
    read_vector(code, source, 0);
    match kind {
        Kind::Register { .. } | Kind::SaturatingImmediate { .. } => unreachable!(),
        Kind::Narrow { round, upper } => {
            narrow(code, lane_bytes, amount, round, upper, destination);
            return;
        }
        Kind::SaturatingNarrow {
            signed_source,
            unsigned_result,
            round,
            upper,
        } => {
            saturating_narrow(
                code,
                operand,
                signed_source,
                unsigned_result,
                round,
                upper,
                target,
            );
            return;
        }
        Kind::Widen { signed, upper } => widen(code, lane_bytes, amount, signed, upper),
        Kind::Left { insert } => {
            logical_shift(code, 0, lane_bytes, amount, true);
            if insert && amount != 0 {
                read_vector(code, destination, 1);
                let preserve = (1u64 << amount) - 1; // amount is 0..lane_bits-1, including qword
                lane_mask(code, 2, lane_bytes, preserve);
                packed(code, Host::And, 1, 2);
                packed(code, Host::Or, 0, 1);
            }
        }
        Kind::Right {
            signed,
            round,
            accumulate,
            insert,
        } => {
            rounded_right(code, lane_bytes, amount, signed, round);
            if accumulate || insert {
                read_vector(code, destination, 1);
                if accumulate {
                    add(code, 0, 1, lane_bytes);
                } else {
                    let bits = lane_bytes * 8;
                    let preserve = (!(u128::from(u64::MAX) >> (64 - bits + amount))) as u64;
                    // The u128 shift permits bits=64, amount=64 without Rust or
                    // x86 count masking. lane_mask keeps only this lane's bits.
                    lane_mask(code, 2, lane_bytes, preserve);
                    packed(code, Host::And, 1, 2);
                    packed(code, Host::Or, 0, 1);
                }
            }
        }
    }
    if bytes == 8 {
        packed(code, Host::MoveQword, 0, 0);
    }
    commit(code, destination, 0);
}

/// Constant counts permit packed SSE2 shifts. The general path stages wrapped
/// results in XMM3 and originals in XMM6; XMM4's active-byte sign bits publish QC.
fn saturating_immediate_vector(
    code: &mut Vec<u8>,
    operand: &Operand,
    signed_source: bool,
    unsigned_result: bool,
) {
    let lane = operand.lane_bytes;
    read_vector(code, operand.source, 0);
    if operand.amount == 0 {
        if signed_source && unsigned_result {
            // SQSHLU zero clamps negative lanes to zero. Publish their original
            // sign mask before PANDN consumes it; the publisher only uses ECX.
            super::saturating::sign_mask(code, 4, 0, lane);
            super::saturating::publish_qc(code, operand.bytes);
            packed(code, Host::AndNot, 4, 0);
            finish_immediate_vector(code, operand, 4);
        } else {
            // SQSHL/UQSHL zero cannot saturate, including inactive poison lanes.
            finish_immediate_vector(code, operand, 0);
        }
        return;
    }
    if operand.amount == 1 && lane <= 2 && signed_source != unsigned_result {
        // A shift by one is a saturating add of identical operands. Unlike the
        // general add_sub recipe, doubling needs no second source/copy. Signed
        // overflow flips the sign between wrapped and saturated results. For
        // unsigned inputs, saturation occurs exactly when the original MSB is
        // set; signed-word replication prevents low-byte MSBs publishing QC.
        if !signed_source && lane == 2 {
            super::saturating::sign_mask(code, 4, 0, lane);
        } else {
            packed(code, Host::MoveAligned, 4, 0);
        }
        if signed_source {
            add(code, 4, 4, lane);
        }
        packed(
            code,
            match (signed_source, lane) {
                (true, 1) => Host::AddSignedSaturatingByte,
                (true, 2) => Host::AddSignedSaturatingWord,
                (false, 1) => Host::AddUnsignedSaturatingByte,
                (false, 2) => Host::AddUnsignedSaturatingWord,
                _ => unreachable!("reviewed doubling lane"),
            },
            0,
            0,
        );
        if signed_source {
            packed(code, Host::Xor, 4, 0);
        }
        super::saturating::publish_qc(code, operand.bytes);
        finish_immediate_vector(code, operand, 0);
        return;
    }
    packed(code, Host::MoveAligned, 6, 0);
    logical_shift(code, 0, lane, operand.amount, true);
    packed(code, Host::MoveAligned, 3, 0);
    right_shift(code, 0, lane, operand.amount, !unsigned_result);
    packed(code, Host::MoveAligned, 1, 6);
    super::equal(code, lane, crate::TargetCpu::Baseline);
    packed(code, Host::EqualDword, 4, 4);
    packed(code, Host::Xor, 4, 0); // reverse-shift mismatch means lost bits
    if signed_source {
        super::saturating::sign_mask(code, 5, 6, lane);
        if unsigned_result {
            // A negative original source must clamp to zero even when shifting
            // by zero leaves its raw bits unchanged (including qword lanes).
            packed(code, Host::Or, 4, 5);
            packed(code, Host::EqualDword, 1, 1);
            packed(code, Host::Xor, 5, 1); // positive bound=MAX, negative bound=0
        } else {
            packed(code, Host::EqualDword, 1, 1);
            if lane == 1 {
                // 0xffff >> 9 = 0x007f, in PACKUSWB's unsigned byte range.
                // One bound serves all sixteen lanes without immediate loads.
                Shift::RightWord.emit(code, 1, 9);
                packed(code, Host::PackUnsignedWordToByte, 1, 1);
            } else {
                logical_shift(code, 1, lane, 1, false);
            }
            packed(code, Host::Xor, 5, 1); // MAX for positive, MIN for negative
        }
    } else {
        packed(code, Host::EqualDword, 5, 5); // unsigned MAX
    }
    packed(code, Host::Xor, 5, 3);
    packed(code, Host::And, 5, 4);
    packed(code, Host::Xor, 3, 5);
    super::saturating::publish_qc(code, operand.bytes);
    finish_immediate_vector(code, operand, 3);
}

fn finish_immediate_vector(code: &mut Vec<u8>, operand: &Operand, result: u8) {
    if operand.bytes == 8 {
        packed(code, Host::MoveQword, result, result);
    }
    commit(code, operand.destination, result);
}

/// Local near branches avoid assuming that every lane recipe fits in rel8.
#[derive(Clone, Copy)]
enum LaneBranch {
    Always,
    Nonnegative,
    Equal,
    Above,
    AboveOrEqual,
}
fn lane_branch(code: &mut Vec<u8>, condition: LaneBranch) -> usize {
    match condition {
        LaneBranch::Always => code.push(0xe9),
        LaneBranch::Nonnegative => code.extend([0x0f, 0x89]),
        LaneBranch::Equal => code.extend([0x0f, 0x84]),
        LaneBranch::Above => code.extend([0x0f, 0x87]),
        LaneBranch::AboveOrEqual => code.extend([0x0f, 0x83]),
    }
    let patch = code.len();
    code.extend([0; 4]);
    patch
}
fn resolve_lane_branch(code: &mut [u8], patch: usize) {
    let relative = i32::try_from(code.len() - patch - 4).expect("lane recipe rel32");
    code[patch..patch + 4].copy_from_slice(&relative.to_le_bytes());
}
#[derive(Clone, Copy)]
enum LaneShift {
    Left,
    LogicalRight,
    ArithmeticRight,
}
impl LaneShift {
    /// RAX or R10, count CL, baseline 64-bit shift group.
    fn count(self, code: &mut Vec<u8>, r10: bool) {
        let group = match self {
            Self::Left => 4,
            Self::LogicalRight => 5,
            Self::ArithmeticRight => 7,
        };
        code.extend([
            if r10 { 0x49 } else { 0x48 },
            0xd3,
            0xc0 | (group << 3) | if r10 { 2 } else { 0 },
        ]);
    }
}
fn normalize_lane(code: &mut Vec<u8>, bits: u8, signed: bool) {
    if bits < 64 {
        code.extend([0x48, 0xc1, 0xe0, 64 - bits]); // shl rax,64-width
        code.extend([0x48, 0xc1, if signed { 0xf8 } else { 0xe8 }, 64 - bits]);
    }
}
fn load_shift_lane(code: &mut Vec<u8>, operand: &Operand, byte: u8, signed: bool) {
    match (operand.lane_bytes, signed) {
        (1, false) => code.extend([0x0f, 0xb6, 0x87]),
        (1, true) => code.extend([0x48, 0x0f, 0xbe, 0x87]),
        (2, false) => code.extend([0x0f, 0xb7, 0x87]),
        (2, true) => code.extend([0x48, 0x0f, 0xbf, 0x87]),
        (4, false) => code.extend([0x8b, 0x87]),
        (4, true) => code.extend([0x48, 0x63, 0x87]),
        (8, _) => code.extend([0x48, 0x8b, 0x87]),
        _ => unreachable!("allocated shift lane"),
    }
    code.extend((vector_offset(operand.source) + u32::from(byte)).to_le_bytes());
}
fn load_bound(code: &mut Vec<u8>, bound: u64) {
    code.extend([0x48, 0xb8]); // movabs rax,bound
    code.extend(bound.to_le_bytes());
}
/// Count CL is 1..128. Rounding adds CF from the final discarded bit rather
/// than adding a potentially overflowing bias to the original qword.
fn register_right(code: &mut Vec<u8>, signed: bool, round: bool) {
    code.extend([0x83, 0xf9, 64]); // cmp ecx,64
    let large = lane_branch(code, LaneBranch::AboveOrEqual);
    if signed {
        LaneShift::ArithmeticRight
    } else {
        LaneShift::LogicalRight
    }
    .count(code, false);
    if round {
        code.extend([0x48, 0x83, 0xd0, 0]);
    } // adc rax,0
    let done = lane_branch(code, LaneBranch::Always);
    resolve_lane_branch(code, large);
    if signed && !round {
        code.extend([0x48, 0xc1, 0xf8, 63]); // sign fill
    } else if !signed && round {
        // At exactly 64 the rounded result is the source top bit. Above 64
        // every unsigned 64-bit value rounds to zero.
        let beyond = lane_branch(code, LaneBranch::Above);
        code.extend([0x48, 0xc1, 0xe8, 63]);
        let end = lane_branch(code, LaneBranch::Always);
        resolve_lane_branch(code, beyond);
        code.extend([0x31, 0xc0]);
        resolve_lane_branch(code, end);
    } else {
        code.extend([0x31, 0xc0]);
    }
    resolve_lane_branch(code, done);
}
fn register_left(
    code: &mut Vec<u8>,
    bits: u8,
    signed_source: bool,
    unsigned_result: bool,
    saturating: bool,
) {
    let mut finished = Vec::new();
    let mut negative_mixed = None;
    if saturating {
        code.extend([0x48, 0x89, 0xc2]);
    } // rdx=original
    if signed_source && unsigned_result {
        code.extend([0x48, 0x85, 0xc0]);
        let nonnegative = lane_branch(code, LaneBranch::Nonnegative);
        negative_mixed = Some(lane_branch(code, LaneBranch::Always));
        resolve_lane_branch(code, nonnegative);
    }
    code.extend([0x83, 0xf9, bits]); // cmp ecx,width
    let large = lane_branch(code, LaneBranch::AboveOrEqual);
    LaneShift::Left.count(code, false);
    if saturating {
        normalize_lane(code, bits, !unsigned_result);
        code.extend([0x49, 0x89, 0xc2]); // mov r10,rax
        if unsigned_result {
            LaneShift::LogicalRight
        } else {
            LaneShift::ArithmeticRight
        }
        .count(code, true);
        code.extend([0x49, 0x39, 0xd2]); // cmp r10,rdx
        finished.push(lane_branch(code, LaneBranch::Equal));
        let clamp = lane_branch(code, LaneBranch::Always);
        resolve_lane_branch(code, large);
        code.extend([0x48, 0x85, 0xc0]); // zero never saturates, even huge counts
        finished.push(lane_branch(code, LaneBranch::Equal));
        resolve_lane_branch(code, clamp);
        if let Some(patch) = negative_mixed {
            resolve_lane_branch(code, patch);
        }
        let maximum = if unsigned_result {
            u64::MAX >> (64 - bits)
        } else {
            (1u64 << (bits - 1)) - 1
        };
        load_bound(code, maximum);
        if signed_source {
            code.extend([0x48, 0x85, 0xd2]); // original sign
            let positive = lane_branch(code, LaneBranch::Nonnegative);
            load_bound(
                code,
                if unsigned_result {
                    0
                } else {
                    0u64.wrapping_sub(1u64 << (bits - 1))
                },
            );
            resolve_lane_branch(code, positive);
        }
        code.extend([0x81, 0x8f]); // or dword [rdi+fpsr],QC: sticky, other bits preserved
        code.extend((core::mem::offset_of!(crate::GuestState, fpsr) as u32).to_le_bytes());
        code.extend(crate::aarch64::simd::saturating::FPSR_QC.to_le_bytes());
    } else {
        finished.push(lane_branch(code, LaneBranch::Always));
        resolve_lane_branch(code, large);
        code.extend([0x31, 0xc0]);
    }
    for patch in finished {
        resolve_lane_branch(code, patch);
    }
}
#[allow(clippy::too_many_arguments)]
fn register_shift(
    code: &mut Vec<u8>,
    operand: &Operand,
    counts: Option<u8>,
    signed_source: bool,
    unsigned_result: bool,
    round: bool,
    saturating: bool,
) {
    // R8/R9 hold staged result halves. Guest sources remain unchanged until both
    // have been consumed, including d=n=m and scalar inactive-lane poisoning.
    code.extend([0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9]);
    let bits = operand.lane_bytes * 8;
    for byte in (0..operand.bytes).step_by(usize::from(operand.lane_bytes)) {
        load_shift_lane(code, operand, byte, signed_source);
        if let Some(counts) = counts {
            code.extend([0x0f, 0xbe, 0x8f]); // movsx ecx,byte [rdi+count lane]
            code.extend((vector_offset(counts) + u32::from(byte)).to_le_bytes());
            code.extend([0x85, 0xc9]);
            let left = lane_branch(code, LaneBranch::Nonnegative);
            code.extend([0xf7, 0xd9]); // neg ecx (signed byte -128 becomes +128)
            register_right(code, signed_source, round);
            let merged = lane_branch(code, LaneBranch::Always);
            resolve_lane_branch(code, left);
            register_left(code, bits, signed_source, unsigned_result, saturating);
            resolve_lane_branch(code, merged);
        } else {
            code.push(0xb9); // mov ecx,imm32
            code.extend(u32::from(operand.amount).to_le_bytes());
            register_left(code, bits, signed_source, unsigned_result, true);
        }
        normalize_lane(code, bits, false);
        if byte % 8 != 0 {
            code.extend([0x48, 0xc1, 0xe0, byte % 8 * 8]);
        }
        code.extend([0x49, 0x09, if byte < 8 { 0xc0 } else { 0xc1 }]); // or r8/r9,rax
    }
    code.extend([0x4c, 0x89, 0x87]); // commit both staged halves
    code.extend(vector_offset(operand.destination).to_le_bytes());
    code.extend([0x4c, 0x89, 0x8f]);
    code.extend((vector_offset(operand.destination) + 8).to_le_bytes());
}

#[cfg(test)]
mod tests;
