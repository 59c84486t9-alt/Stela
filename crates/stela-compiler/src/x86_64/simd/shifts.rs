//! AdvSIMD shifts by immediate and per-lane register, including width changes.
use super::{
    Host, commit, greater, packed, read_vector, rearrange::constant, shuffle, vector_offset,
};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, ShiftOp, Size, Unary};
use crate::x86_64::simd::encode::guest;
use crate::{
    TargetCpu,
    aarch64::simd::shifts::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};
use Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx};
use alloc::vec::Vec;

const BITS_PER_BYTE: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const LOW_DWORDS_OF_QWORDS: u8 = 0x88;
const HIGH_DWORDS_OF_QWORDS: u8 = 0xdd;

fn lane_mask(code: &mut Code, xmm: u8, lane_bytes: u8, value: u64) {
    let bytes = value.to_le_bytes();
    constant(
        code,
        xmm,
        core::array::from_fn(|i| bytes[i % usize::from(lane_bytes)]),
    );
}
fn add(code: &mut Code, destination: u8, source: u8, lane_bytes: u8) {
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
pub(crate) fn logical_shift(code: &mut Code, xmm: u8, lane_bytes: u8, amount: u8, left: bool) {
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
pub(crate) fn right_shift(code: &mut Code, xmm: u8, lane_bytes: u8, amount: u8, signed: bool) {
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
    code: &mut Code,
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
fn narrow(code: &mut Code, lane_bytes: u8, amount: u8, round: bool, upper: bool, destination: u8) {
    rounded_right(code, lane_bytes * 2, amount, false, round);
    pack_truncated(code, lane_bytes, upper, destination);
}

/// Shift first, then clamp. Rounding is computed as shifted value plus the
/// discarded high bit, so signed overflow and unsigned carry are never lost.
fn saturating_narrow(
    code: &mut Code,
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
    code: &mut Code,
    lane: u8,
    signed_source: bool,
    unsigned_result: bool,
    target: TargetCpu,
) {
    let wide = lane * 2;
    packed(code, Host::MoveAligned, 3, 0);
    if !signed_source {
        // With a shift of at least one, only one negative signed pattern is
        // possible: unsigned MAX rounded by one becomes exactly the wide sign
        // bit. Change it to signed MAX before the signed host pack (both
        // saturate to the same bound), comparing against the original value.
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
    code: &mut Code,
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
pub(super) fn pack_truncated(code: &mut Code, lane_bytes: u8, upper: bool, destination: u8) {
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
fn widen(code: &mut Code, lane_bytes: u8, amount: u8, signed: bool, upper: bool) {
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

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
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
                    // A u128 shift allows bits = 64 and amount = 64 without
                    // Rust or x86 count masking; `lane_mask` keeps only this
                    // lane's bits.
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

/// Constant counts allow packed SSE2 shifts. The general path stages wrapped
/// results in XMM3 and the originals in XMM6; the sign bits of XMM4's active
/// bytes set QC.
fn saturating_immediate_vector(
    code: &mut Code,
    operand: &Operand,
    signed_source: bool,
    unsigned_result: bool,
) {
    let lane = operand.lane_bytes;
    read_vector(code, operand.source, 0);
    if operand.amount == 0 {
        if signed_source && unsigned_result {
            // SQSHLU clamps negative lanes to zero. Record their sign mask for
            // QC before PANDN consumes it; the recorder uses only ECX.
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
        // A shift by one is a saturating add of a value to itself, so no second
        // source copy is needed. Signed overflow shows as a sign change between
        // wrapped and saturated results; unsigned inputs saturate exactly when
        // the MSB is set, and replicating to signed words keeps low-byte MSBs
        // from setting QC.
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
            // A negative source must clamp to zero even when a zero shift
            // leaves its bits unchanged (qword lanes included).
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

fn finish_immediate_vector(code: &mut Code, operand: &Operand, result: u8) {
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
fn lane_branch(code: &mut Code, condition: LaneBranch) -> usize {
    let mut asm = code.asm();
    match condition {
        LaneBranch::Always => asm.jmp(),
        LaneBranch::Nonnegative => asm.jcc(Cond::Ns),
        LaneBranch::Equal => asm.jcc(Cond::E),
        LaneBranch::Above => asm.jcc(Cond::A),
        LaneBranch::AboveOrEqual => asm.jcc(Cond::Ae),
    }
    .offset()
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
    fn count(self, code: &mut Code, r10: bool) {
        let op = match self {
            Self::Left => ShiftOp::Shl,
            Self::LogicalRight => ShiftOp::Shr,
            Self::ArithmeticRight => ShiftOp::Sar,
        };
        code.asm()
            .shift_cl(op, Size::Qword, if r10 { R10 } else { Rax });
    }
}
fn normalize_lane(code: &mut Code, bits: u8, signed: bool) {
    if bits < 64 {
        let mut asm = code.asm();
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Rax, 64 - bits);
        let right = if signed { ShiftOp::Sar } else { ShiftOp::Shr };
        asm.shift_imm(right, Size::Qword, Rax, 64 - bits);
    }
}
fn load_shift_lane(code: &mut Code, operand: &Operand, byte: u8, signed: bool) {
    let lane = guest(vector_offset(operand.source) + u32::from(byte));
    let mut asm = code.asm();
    match (operand.lane_bytes, signed) {
        (1, false) => asm.movzx(Size::Dword, Rax, Size::Byte, lane),
        (1, true) => asm.movsx(Size::Qword, Rax, Size::Byte, lane),
        (2, false) => asm.movzx(Size::Dword, Rax, Size::Word, lane),
        (2, true) => asm.movsx(Size::Qword, Rax, Size::Word, lane),
        (4, false) => asm.mov_load(Size::Dword, Rax, lane),
        (4, true) => asm.movsxd(Rax, lane),
        (8, _) => asm.mov_load(Size::Qword, Rax, lane),
        _ => unreachable!("allocated shift lane"),
    }
}
fn load_bound(code: &mut Code, bound: u64) {
    code.asm().mov_imm64(Rax, bound);
}
/// `xor eax, eax`.
fn zero_lane(code: &mut Code) {
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
}
/// CL is 1 to 128. Rounding adds CF from the last discarded bit instead of
/// adding a bias that could overflow the qword.
fn register_right(code: &mut Code, signed: bool, round: bool) {
    code.asm().alu_imm8(Alu::Cmp, Size::Dword, Rcx, 64);
    let large = lane_branch(code, LaneBranch::AboveOrEqual);
    if signed {
        LaneShift::ArithmeticRight
    } else {
        LaneShift::LogicalRight
    }
    .count(code, false);
    if round {
        code.asm().alu_imm8(Alu::Adc, Size::Qword, Rax, 0);
    }
    let done = lane_branch(code, LaneBranch::Always);
    resolve_lane_branch(code, large);
    if signed && !round {
        // Sign fill.
        code.asm().shift_imm(ShiftOp::Sar, Size::Qword, Rax, 63);
    } else if !signed && round {
        // At exactly 64 the rounded result is the source top bit. Above 64
        // every unsigned 64-bit value rounds to zero.
        let beyond = lane_branch(code, LaneBranch::Above);
        code.asm().shift_imm(ShiftOp::Shr, Size::Qword, Rax, 63);
        let end = lane_branch(code, LaneBranch::Always);
        resolve_lane_branch(code, beyond);
        zero_lane(code);
        resolve_lane_branch(code, end);
    } else {
        zero_lane(code);
    }
    resolve_lane_branch(code, done);
}
fn register_left(
    code: &mut Code,
    bits: u8,
    signed_source: bool,
    unsigned_result: bool,
    saturating: bool,
) {
    let mut finished = Vec::new();
    let mut negative_mixed = None;
    if saturating {
        // RDX keeps the original.
        code.asm().mov(Size::Qword, Rdx, Rax);
    }
    if signed_source && unsigned_result {
        code.asm().test(Size::Qword, Rax, Rax);
        let nonnegative = lane_branch(code, LaneBranch::Nonnegative);
        negative_mixed = Some(lane_branch(code, LaneBranch::Always));
        resolve_lane_branch(code, nonnegative);
    }
    code.asm().alu_imm8(Alu::Cmp, Size::Dword, Rcx, bits as i8);
    let large = lane_branch(code, LaneBranch::AboveOrEqual);
    LaneShift::Left.count(code, false);
    if saturating {
        normalize_lane(code, bits, !unsigned_result);
        code.asm().mov(Size::Qword, R10, Rax);
        if unsigned_result {
            LaneShift::LogicalRight
        } else {
            LaneShift::ArithmeticRight
        }
        .count(code, true);
        code.asm().alu(Alu::Cmp, Size::Qword, R10, Rdx);
        finished.push(lane_branch(code, LaneBranch::Equal));
        let clamp = lane_branch(code, LaneBranch::Always);
        resolve_lane_branch(code, large);
        // Zero never saturates, even for huge counts.
        code.asm().test(Size::Qword, Rax, Rax);
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
            // The original sign.
            code.asm().test(Size::Qword, Rdx, Rdx);
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
        // Sticky QC, other bits preserved.
        code.asm().alu_imm32(
            Alu::Or,
            Size::Dword,
            guest(core::mem::offset_of!(crate::GuestState, fpsr) as u32),
            crate::aarch64::simd::saturating::FPSR_QC as i32,
        );
    } else {
        finished.push(lane_branch(code, LaneBranch::Always));
        resolve_lane_branch(code, large);
        zero_lane(code);
    }
    for patch in finished {
        resolve_lane_branch(code, patch);
    }
}
/// SSHL and USHL of the extended lane in RAX by the signed count in ECX,
/// without a branch: both directions are computed and CMOVs pick one, so
/// the timing depends on neither the count nor the data (FEAT_DIT lists
/// both). A left count of 64 or more gives zero; a right count is clamped to
/// 63, which fills with the sign (SSHL) or, below -63, is replaced by zero
/// (USHL of a 64-bit lane). Narrower lanes are truncated by the caller.
fn register_plain(code: &mut Code, signed: bool) {
    const LEFT_LIMIT: i8 = 64;
    const RIGHT_LIMIT: u32 = 63;
    const RIGHT_ZERO: i8 = -64;
    let mut asm = code.asm();
    asm.mov(Size::Qword, R10, Rax);
    asm.shift_cl(ShiftOp::Shl, Size::Qword, R10);
    asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rcx, LEFT_LIMIT);
    asm.cmov(Cond::Ge, Size::Qword, R10, Rdx);
    asm.mov(Size::Dword, Rdx, Rcx);
    asm.unary(Unary::Neg, Size::Dword, Rdx);
    asm.mov_imm32(R11, RIGHT_LIMIT);
    asm.alu(Alu::Cmp, Size::Dword, Rdx, R11);
    asm.cmov(Cond::G, Size::Dword, Rdx, R11);
    // R11D keeps the signed count.
    asm.mov(Size::Dword, R11, Rcx);
    asm.mov(Size::Dword, Rcx, Rdx);
    if signed {
        LaneShift::ArithmeticRight
    } else {
        LaneShift::LogicalRight
    }
    .count(code, false);
    let mut asm = code.asm();
    if !signed {
        asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
        asm.alu_imm8(Alu::Cmp, Size::Dword, R11, RIGHT_ZERO);
        asm.cmov(Cond::Le, Size::Qword, Rax, Rdx);
    }
    asm.test(Size::Dword, R11, R11);
    asm.cmov(Cond::Ns, Size::Qword, Rax, R10);
}

fn register_shift(
    code: &mut Code,
    operand: &Operand,
    counts: Option<u8>,
    signed_source: bool,
    unsigned_result: bool,
    round: bool,
    saturating: bool,
) {
    // R8/R9 hold staged result halves. Guest sources remain unchanged until both
    // have been consumed, including d=n=m and scalar inactive-lane poisoning.
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Size::Dword, R8, R8);
    asm.alu(Alu::Xor, Size::Dword, R9, R9);
    let bits = operand.lane_bytes * 8;
    for byte in (0..operand.bytes).step_by(usize::from(operand.lane_bytes)) {
        load_shift_lane(code, operand, byte, signed_source);
        if let Some(counts) = counts {
            // The count lane.
            code.asm().movsx(
                Size::Dword,
                Rcx,
                Size::Byte,
                guest(vector_offset(counts) + u32::from(byte)),
            );
            if !round && !saturating {
                register_plain(code, signed_source);
            } else {
                code.asm().test(Size::Dword, Rcx, Rcx);
                let left = lane_branch(code, LaneBranch::Nonnegative);
                // A signed byte -128 becomes +128.
                code.asm().unary(Unary::Neg, Size::Dword, Rcx);
                register_right(code, signed_source, round);
                let merged = lane_branch(code, LaneBranch::Always);
                resolve_lane_branch(code, left);
                register_left(code, bits, signed_source, unsigned_result, saturating);
                resolve_lane_branch(code, merged);
            }
        } else {
            code.asm().mov_imm32(Rcx, u32::from(operand.amount));
            register_left(code, bits, signed_source, unsigned_result, true);
        }
        normalize_lane(code, bits, false);
        let mut asm = code.asm();
        if byte % 8 != 0 {
            asm.shift_imm(ShiftOp::Shl, Size::Qword, Rax, byte % 8 * 8);
        }
        asm.alu(Alu::Or, Size::Qword, if byte < 8 { R8 } else { R9 }, Rax);
    }
    // Commit both staged halves.
    let mut asm = code.asm();
    asm.mov_store(Size::Qword, guest(vector_offset(operand.destination)), R8);
    asm.mov_store(
        Size::Qword,
        guest(vector_offset(operand.destination) + 8),
        R9,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn full_width_nonround_narrowing_omits_qc_only_when_bounds_prove_it() {
        for lane in [1, 2, 4] {
            for scalar in [false, true] {
                for upper in [false, true] {
                    if scalar && upper {
                        continue;
                    }
                    for (signed_source, unsigned_result) in
                        [(true, false), (false, true), (true, true)]
                    {
                        for round in [false, true] {
                            let operand = Operand {
                                kind: Kind::SaturatingNarrow {
                                    signed_source,
                                    unsigned_result,
                                    round,
                                    upper,
                                },
                                destination: 31,
                                source: 31,
                                lane_bytes: lane,
                                amount: lane * BITS_PER_BYTE,
                                bytes: if scalar { lane } else { VECTOR_BYTES },
                            };
                            let mut code = Code::new();
                            emit(&mut code, &operand, TargetCpu::Baseline);
                            let mut qc = Code::new();
                            Host::ByteSignMask.register(&mut qc, 1, 4, TargetCpu::Baseline);
                            assert_eq!(
                                code.windows(qc.len()).any(|w| w == qc),
                                round || signed_source == unsigned_result
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn saturating_narrow_packs_keep_checked_features_and_active_qc_masks() {
        for lane in [1, 2, 4] {
            for scalar in [false, true] {
                for target in [TargetCpu::Baseline, TargetCpu::Sse41, TargetCpu::Sse42] {
                    let operand = Operand {
                        kind: Kind::SaturatingNarrow {
                            signed_source: false,
                            unsigned_result: true,
                            round: true,
                            upper: !scalar,
                        },
                        destination: 31,
                        source: 31,
                        lane_bytes: lane,
                        amount: 1,
                        bytes: if scalar { lane } else { VECTOR_BYTES },
                    };
                    let mut code = Code::new();
                    emit(&mut code, &operand, target);
                    let mut checked_pack = Code::new();
                    Host::PackUnsignedDwordToWord.register(
                        &mut checked_pack,
                        0,
                        0,
                        TargetCpu::Sse41,
                    );
                    assert_eq!(
                        code.windows(checked_pack.len()).any(|w| w == checked_pack),
                        lane == 2 && target >= TargetCpu::Sse41,
                    );
                    let active_bytes = if scalar { lane * 2 } else { VECTOR_BYTES };
                    let mut active_mask = vec![0x81, 0xe1]; // AND ECX, active mask
                    active_mask.extend(((1u32 << active_bytes) - 1).to_le_bytes());
                    assert!(code.windows(active_mask.len()).any(|w| w == active_mask));
                }
            }
        }
    }

    fn immediate(lane_bytes: u8, bytes: u8, amount: u8, signed: bool) -> Operand {
        Operand {
            kind: Kind::SaturatingImmediate {
                signed_source: signed,
                unsigned_result: !signed,
            },
            destination: 1,
            source: 1, // Exercise the in-place emission shape too.
            lane_bytes,
            amount,
            bytes,
        }
    }

    #[test]
    fn nonsaturating_zero_immediates_keep_a_real_minimal_write_interval() {
        for bytes in [8, 16] {
            for lane in [1, 2, 4, 8] {
                if bytes == 8 && lane == 8 {
                    continue;
                }
                for signed in [false, true] {
                    let mut code = Code::new();
                    emit(
                        &mut code,
                        &immediate(lane, bytes, 0, signed),
                        TargetCpu::Baseline,
                    );
                    // Load, optional upper clearing, store. No FPSR write and
                    // no empty source-map interval for an in-place identity.
                    assert_eq!(code.len(), if bytes == 8 { 20 } else { 16 });
                }
            }
        }
    }

    #[test]
    fn byte_and_word_immediate_doubling_use_baseline_saturating_adds() {
        for (lane, signed, opcode) in [
            (1, true, Host::AddSignedSaturatingByte),
            (2, true, Host::AddSignedSaturatingWord),
            (1, false, Host::AddUnsignedSaturatingByte),
            (2, false, Host::AddUnsignedSaturatingWord),
        ] {
            for bytes in [8, 16] {
                let mut code = Code::new();
                emit(
                    &mut code,
                    &immediate(lane, bytes, 1, signed),
                    TargetCpu::Baseline,
                );
                let mut saturating_add = Code::new();
                packed(&mut saturating_add, opcode, 0, 0);
                assert!(
                    code.windows(saturating_add.len())
                        .any(|w| w == saturating_add)
                );
                // Includes full sticky QC publication and the active-byte
                // mask; excludes the harness RET supplied by the caller.
                let body_bytes = if signed {
                    57
                } else if lane == 1 {
                    49
                } else {
                    54
                };
                assert_eq!(code.len(), body_bytes + if bytes == 8 { 4 } else { 0 });
            }
        }
    }

    #[test]
    fn identity_insert_immediates_preserve_destination_clearing() {
        for bytes in [8, 16] {
            for lane in [1, 2, 4, 8] {
                if bytes == 8 && lane == 8 {
                    continue;
                }
                for kind in [
                    Kind::Left { insert: true },
                    Kind::Right {
                        signed: false,
                        round: false,
                        accumulate: false,
                        insert: true,
                    },
                ] {
                    let mut operand = immediate(lane, bytes, 0, false);
                    operand.kind = kind;
                    if matches!(kind, Kind::Right { .. }) {
                        operand.amount = lane * 8;
                    }
                    let mut code = Code::new();
                    emit(&mut code, &operand, TargetCpu::Baseline);
                    assert_eq!(code.len(), if bytes == 8 { 20 } else { 16 });
                }
            }
        }
    }
}
