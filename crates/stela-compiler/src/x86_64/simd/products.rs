//! Integer multiplies, widening arithmetic and absolute differences.
use super::rearrange::{add_or_subtract, lane_constant};
use super::{Host, commit, greater, packed, packed_imm, read_vector, rearrange::constant, shuffle};
use crate::x86_64::asm::{Code, Cond, Gpr, Size, resolve, vector_extensions};
use crate::{
    TargetCpu,
    aarch64::simd::products::{Accumulate, Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

/// Extend the selected 64-bit input half into doubled-width lanes. XMM3 is the
/// extension mask; extending one operand never changes the other in XMM0/1.
pub(super) fn extend(code: &mut Code, xmm: u8, lane: u8, upper: bool, signed: bool) {
    if upper {
        Shift::RightBytes.emit(code, xmm, 8);
    }
    packed(code, Host::Xor, 3, 3);
    if signed {
        packed(
            code,
            match lane {
                1 => Host::GreaterByte,
                2 => Host::GreaterWord,
                4 => Host::GreaterDword,
                _ => unreachable!(),
            },
            3,
            xmm,
        );
    }
    packed(
        code,
        match lane {
            1 => Host::UnpackLowByte,
            2 => Host::UnpackLowWord,
            4 => Host::UnpackLowDword,
            _ => unreachable!(),
        },
        xmm,
        3,
    );
}
fn low_product(code: &mut Code, lane: u8, target: TargetCpu) {
    match lane {
        1 => {
            // Multiply even and odd bytes separately in 16-bit lanes, then mask
            // or shift each product back to a byte before merging.
            packed(code, Host::MoveAligned, 2, 0);
            packed(code, Host::MoveAligned, 3, 1);
            constant(
                code,
                4,
                [
                    0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0,
                ],
            );
            packed(code, Host::And, 0, 4);
            packed(code, Host::And, 1, 4);
            packed(code, Host::MultiplyLowWord, 0, 1);
            packed(code, Host::And, 0, 4);
            Shift::RightWord.emit(code, 2, 8);
            Shift::RightWord.emit(code, 3, 8);
            packed(code, Host::MultiplyLowWord, 2, 3);
            Shift::LeftWord.emit(code, 2, 8);
            packed(code, Host::Or, 0, 2);
        }
        2 => packed(code, Host::MultiplyLowWord, 0, 1),
        4 if target >= TargetCpu::Sse41 => Host::MultiplyLowDword.register(code, 0, 1, target),
        4 => {
            packed(code, Host::MoveAligned, 2, 0);
            packed(code, Host::MoveAligned, 3, 1);
            packed(code, Host::MultiplyUnsignedDword, 0, 1);
            Shift::RightBytes.emit(code, 2, 4);
            Shift::RightBytes.emit(code, 3, 4);
            packed(code, Host::MultiplyUnsignedDword, 2, 3);
            shuffle(code, 0, 0, 0x88);
            shuffle(code, 2, 2, 0x88);
            packed(code, Host::UnpackLowDword, 0, 2);
        }
        _ => unreachable!("allocated product lane size"),
    }
}
fn long_product(code: &mut Code, lane: u8, signed: bool, target: TargetCpu) {
    if lane < 4 {
        low_product(code, lane * 2, target);
        return;
    }
    if signed && target >= TargetCpu::Sse41 {
        Host::MultiplySignedDword.register(code, 0, 1, target);
        return;
    }
    if signed {
        // Signed(a)*Signed(b) = UInt(a)*UInt(b) - sign(a)*UInt(b)*2^32
        //                      - sign(b)*UInt(a)*2^32, modulo 64 bits.
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::MoveAligned, 3, 1);
        Shift::ArithmeticDword.emit(code, 2, 31);
        Shift::ArithmeticDword.emit(code, 3, 31);
        packed(code, Host::And, 2, 1);
        packed(code, Host::And, 3, 0);
        Shift::LeftQword.emit(code, 2, 32);
        Shift::LeftQword.emit(code, 3, 32);
        packed(code, Host::MultiplyUnsignedDword, 0, 1);
        packed(code, Host::SubQword, 0, 2);
        packed(code, Host::SubQword, 0, 3);
    } else {
        packed(code, Host::MultiplyUnsignedDword, 0, 1);
    }
}
fn accumulate(code: &mut Code, destination: u8, lane: u8, operation: Accumulate) -> u8 {
    if operation == Accumulate::None {
        return 0;
    }
    read_vector(code, destination, 1);
    if operation == Accumulate::Subtract {
        packed(code, add_or_subtract(lane, true), 1, 0);
        1
    } else {
        packed(code, add_or_subtract(lane, false), 0, 1);
        0
    }
}
fn absolute_difference(code: &mut Code, lane: u8, signed: bool, target: TargetCpu) {
    if lane <= 2 {
        if signed {
            let bits = (1u64 << (lane * 8 - 1)).to_le_bytes();
            constant(
                code,
                4,
                core::array::from_fn(|i| bits[i % usize::from(lane)]),
            );
            packed(code, Host::Xor, 0, 4);
            packed(code, Host::Xor, 1, 4);
        }
        let opcode = if lane == 1 {
            Host::SubUnsignedSaturatingByte
        } else {
            Host::SubUnsignedSaturatingWord
        };
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, opcode, 0, 1);
        packed(code, opcode, 1, 2);
        packed(code, Host::Or, 0, 1);
    } else {
        packed(code, Host::MoveAligned, 5, 0);
        packed(code, add_or_subtract(lane, true), 5, 1);
        // Keep the wrapped difference in XMM5 while comparison uses XMM0..4.
        // Ordering decides the direction of subtraction before interpreting ABS.
        greater(code, lane, !signed, target);
        packed(code, Host::EqualDword, 1, 1);
        packed(code, Host::Xor, 0, 1);
        packed(code, Host::Xor, 5, 0);
        packed(code, add_or_subtract(lane, true), 5, 0);
        packed(code, Host::MoveAligned, 0, 5);
    }
}

fn indexed(code: &mut Code, lane: u8, index: u8) {
    if lane == 2 {
        // Halfword shuffles leave the other 64-bit half unchanged. Broadcast
        // one repeated dword from the selected half to complete all eight lanes.
        packed_imm(
            code,
            if index < 4 {
                Host::ShuffleLowWord
            } else {
                Host::ShuffleHighWord
            },
            1,
            1,
            (index % 4) * 0x55,
        );
        shuffle(code, 1, 1, if index < 4 { 0 } else { 0xaa });
    } else {
        // Select and broadcast the dword in one shuffle.
        shuffle(code, 1, 1, index * 0x55);
    }
}

/// Indexed long products have a uniform right operand; avoid materializing
/// widened input lanes which the native multiply does not consume.
fn indexed_long_product(code: &mut Code, lane: u8, upper: bool, signed: bool, target: TargetCpu) {
    if lane == 2 && !upper && target >= TargetCpu::Sse41 {
        let extension = if signed {
            Host::SignExtendWordToDword
        } else {
            Host::ZeroExtendWordToDword
        };
        extension.register(code, 0, 0, target);
        extension.register(code, 1, 1, target);
        Host::MultiplyLowDword.register(code, 0, 1, target);
    } else if lane == 2 {
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::MultiplyLowWord, 0, 1);
        packed(
            code,
            if signed {
                Host::MultiplyHighSignedWord
            } else {
                Host::MultiplyHighUnsignedWord
            },
            2,
            1,
        );
        packed(
            code,
            if upper {
                Host::UnpackHighWord
            } else {
                Host::UnpackLowWord
            },
            0,
            2,
        );
    } else {
        shuffle(code, 0, 0, if upper { 0xfa } else { 0x50 });
        long_product(code, lane, signed, target);
    }
}

fn indexed_low_product(code: &mut Code, lane: u8, bytes: u8, target: TargetCpu) {
    if lane != 4 || target >= TargetCpu::Sse41 {
        low_product(code, lane, target);
    } else if bytes == 8 {
        // Both low dwords fit one PMULUDQ pair after repositioning the left
        // operand; the right operand is already uniform in every dword.
        shuffle(code, 0, 0, 0x50);
        packed(code, Host::MultiplyUnsignedDword, 0, 1);
        shuffle(code, 0, 0, 0x88);
    } else {
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::MultiplyUnsignedDword, 0, 1);
        Shift::RightBytes.emit(code, 2, 4);
        packed(code, Host::MultiplyUnsignedDword, 2, 1);
        shuffle(code, 0, 0, 0x88);
        shuffle(code, 2, 2, 0x88);
        packed(code, Host::UnpackLowDword, 0, 2);
    }
}

/// Even/odd byte products form two exact PMADDWD pair sums per dword. Their
/// sum is the four-byte dot product, with no saturating intermediate operation.
fn dot(code: &mut Code, operand: &Operand, signed: bool, target: TargetCpu) {
    const BYTE_BITS: u8 = 8;
    const LOW_BYTE_MASK: u64 = 0x00ff;
    if let Some(index) = operand.index {
        indexed(code, 4, index);
    }
    if vector_extensions::byte_dot(code, 2, &[[0, 1]], [signed; 2], [3, 4], target) {
        read_vector(code, operand.destination, 0);
        packed(code, Host::AddDword, 0, 2);
        return;
    }
    packed(code, Host::MoveAligned, 2, 0);
    packed(code, Host::MoveAligned, 3, 1);
    if signed {
        for xmm in [0, 1] {
            Shift::LeftWord.emit(code, xmm, BYTE_BITS);
            Shift::ArithmeticWord.emit(code, xmm, BYTE_BITS);
        }
        for xmm in [2, 3] {
            Shift::ArithmeticWord.emit(code, xmm, BYTE_BITS);
        }
    } else {
        lane_constant(code, 4, 2, LOW_BYTE_MASK);
        for xmm in [0, 1] {
            packed(code, Host::And, xmm, 4);
        }
        for xmm in [2, 3] {
            Shift::RightWord.emit(code, xmm, BYTE_BITS);
        }
    }
    packed(code, Host::MultiplyAddWords, 0, 1);
    packed(code, Host::MultiplyAddWords, 2, 3);
    packed(code, Host::AddDword, 0, 2);
    accumulate(code, operand.destination, 4, Accumulate::Add);
}

/// Clamp the doubled-width sums once, after the rounded product is added to the
/// accumulator. XMM6 survives for assembling the halves.
fn clamp_rounded_accumulate(code: &mut Code, lane: u8, active: u8) {
    packed(code, Host::MoveAligned, 5, 0);
    if lane == 2 {
        packed(code, Host::PackSignedDwordToWord, 0, 0);
        packed(code, Host::MoveAligned, 2, 0);
        extend(code, 2, lane, false, true);
        packed(code, Host::MoveAligned, 4, 5);
        packed(code, Host::EqualDword, 4, 2);
    } else {
        const COMPACT_LOW_DWORDS: u8 = 0x88;
        const SWAP_QWORD_DWORDS: u8 = 0xb1;
        const DWORD_SIGN_BIT: u8 = 31;
        // Sign-extend each truncated low dword; equality with the qword marks
        // the sums that fit in 32 bits.
        shuffle(code, 2, 0, COMPACT_LOW_DWORDS);
        packed(code, Host::MoveAligned, 3, 2);
        Shift::ArithmeticDword.emit(code, 3, DWORD_SIGN_BIT);
        packed(code, Host::UnpackLowDword, 2, 3);
        packed(code, Host::MoveAligned, 4, 5);
        packed(code, Host::EqualDword, 4, 2);
        shuffle(code, 3, 4, SWAP_QWORD_DWORDS);
        packed(code, Host::And, 4, 3);
    }
    packed(code, Host::EqualDword, 3, 3);
    packed(code, Host::Xor, 4, 3);
    if lane == 4 {
        const SIGNED_DWORD_MAXIMUM: u64 = i32::MAX as u64;
        super::saturating::sign_mask(code, 2, 5, 8);
        lane_constant(code, 3, 8, SIGNED_DWORD_MAXIMUM);
        packed(code, Host::Xor, 2, 3);
        packed(code, Host::Xor, 2, 5);
        packed(code, Host::And, 2, 4);
        packed(code, Host::Xor, 5, 2);
        shuffle(code, 0, 5, 0x88);
    }
    super::saturating::publish_qc(code, active * 2);
}

/// floor((acc*2^n +/- 2*a*b + 2^(n-1))/2^n) equals
/// acc + floor((+/- a*b + 2^(n-2))/2^(n-1)). The latter needs only
/// signed2n intermediates and preserves MIN*MIN cancellation and subtract ties.
fn rounded_accumulate_half(
    code: &mut Code,
    operand: &Operand,
    upper: bool,
    active: u8,
    subtract: bool,
    target: TargetCpu,
) {
    const BITS_PER_BYTE: u8 = 8;
    let lane = operand.lane_bytes;
    let bits = lane * BITS_PER_BYTE;
    read_vector(code, operand.left, 0);
    read_vector(code, operand.right, 1);
    if let Some(index) = operand.index {
        indexed(code, lane, index);
    }
    if lane == 2 {
        // Assemble full signed32 products directly; pre-extending halfwords
        // would make the baseline perform two unnecessary dword multiplies.
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::MultiplyLowWord, 0, 1);
        packed(code, Host::MultiplyHighSignedWord, 2, 1);
        packed(
            code,
            if upper {
                Host::UnpackHighWord
            } else {
                Host::UnpackLowWord
            },
            0,
            2,
        );
    } else {
        const REPEAT_LOW_DWORD_PAIR: u8 = 0x50;
        const REPEAT_HIGH_DWORD_PAIR: u8 = 0xfa;
        let selection = if upper {
            REPEAT_HIGH_DWORD_PAIR
        } else {
            REPEAT_LOW_DWORD_PAIR
        };
        shuffle(code, 0, 0, selection);
        if operand.index.is_none() {
            shuffle(code, 1, 1, selection);
        }
        long_product(code, lane, true, target);
    }
    if subtract {
        packed(code, Host::Xor, 1, 1);
        packed(code, add_or_subtract(lane * 2, true), 1, 0);
        packed(code, Host::MoveAligned, 0, 1);
    }
    lane_constant(code, 1, lane * 2, 1u64 << (bits - 2));
    packed(code, add_or_subtract(lane * 2, false), 0, 1);
    if lane == 2 {
        Shift::ArithmeticDword.emit(code, 0, bits - 1);
    } else {
        // SSE2 has no arithmetic qword shift. Preserve the high sign above
        // the n+1 significant result bits before shifting the exact product.
        super::saturating::sign_mask(code, 1, 0, 8);
        Shift::LeftQword.emit(code, 1, bits + 1);
        Shift::RightQword.emit(code, 0, bits - 1);
        packed(code, Host::Or, 0, 1);
    }
    packed(code, Host::MoveAligned, 5, 0);
    read_vector(code, operand.destination, 0);
    extend(code, 0, lane, upper, true);
    packed(code, add_or_subtract(lane * 2, false), 0, 5);
    clamp_rounded_accumulate(code, lane, active);
}

fn rounded_accumulate(code: &mut Code, operand: &Operand, subtract: bool, target: TargetCpu) {
    const SOURCE_HALF_BYTES: u8 = 8;
    rounded_accumulate_half(
        code,
        operand,
        false,
        operand.bytes.min(SOURCE_HALF_BYTES),
        subtract,
        target,
    );
    if operand.bytes == 16 {
        packed(code, Host::MoveAligned, 6, 0);
        rounded_accumulate_half(code, operand, true, SOURCE_HALF_BYTES, subtract, target);
        packed(code, Host::UnpackLowQword, 6, 0);
        packed(code, Host::MoveAligned, 0, 6);
    }
}
/// Full-width 16-bit high products need no widening or per-half processing.
/// PMULHRSW shares Arm's ties-up rounding but wraps MIN*MIN instead of clamping.
fn high_product_words(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let Kind::Doubling { rounding, .. } = operand.kind else {
        unreachable!()
    };
    read_vector(code, operand.left, 0);
    read_vector(code, operand.right, 1);
    if let Some(index) = operand.index {
        indexed(code, 2, index);
    }
    if rounding && target.supports(TargetCpu::Ssse3) {
        Host::MultiplyHighRoundedScaledWord.register(code, 0, 1, target);
    } else {
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::MultiplyLowWord, 2, 1);
        packed(code, Host::MultiplyHighSignedWord, 0, 1);
        packed(code, Host::AddWord, 0, 0);
        if rounding {
            // ((L>>14)+1)>>1 keeps the carry2 for L>=0xc000. A wrapping
            // word addition of 0x4000 to L would silently discard that carry.
            Shift::RightWord.emit(code, 2, 14);
            packed(code, Host::EqualDword, 3, 3);
            Shift::RightWord.emit(code, 3, 15);
            packed(code, Host::AddWord, 2, 3);
            Shift::RightWord.emit(code, 2, 1);
        } else {
            Shift::RightWord.emit(code, 2, 15);
        }
        packed(code, Host::AddWord, 0, 2);
    }
    // A valid high product cannot reach -32768: its minimum is -32767.
    // Thus wrapped 0x8000 uniquely identifies positive MIN*MIN overflow.
    packed(code, Host::EqualDword, 4, 4);
    Shift::LeftWord.emit(code, 4, 15);
    packed(code, Host::EqualWord, 4, 0);
    packed(code, Host::AddWord, 0, 4);
    super::saturating::publish_qc(code, operand.bytes);
}
/// One selected 64-bit half -> a low 64-bit high-product result. XMM6 survives.
fn high_product(code: &mut Code, operand: &Operand, upper: bool, active: u8, target: TargetCpu) {
    let Kind::Doubling { rounding, .. } = operand.kind else {
        unreachable!()
    };
    let lane = operand.lane_bytes;
    read_vector(code, operand.left, 0);
    read_vector(code, operand.right, 1);
    if let Some(index) = operand.index {
        indexed(code, lane, index);
    }
    extend(code, 0, lane, upper, true);
    extend(code, 1, lane, upper && operand.index.is_none(), true);
    long_product(code, lane, true, target);
    // Compute (product + 2^(n-2)) >> (n-1), avoiding a doubled-product overflow.
    if rounding {
        lane_constant(code, 1, lane * 2, 1u64 << (lane * 8 - 2));
        packed(code, add_or_subtract(lane * 2, false), 0, 1);
    }
    if lane == 2 {
        Shift::ArithmeticDword.emit(code, 0, 15);
    } else {
        Shift::RightQword.emit(code, 0, 31);
    }
    // MIN*MIN is the only overflow, represented by the exact positive 2^(n-1).
    lane_constant(code, 4, lane * 2, 1u64 << (lane * 8 - 1));
    packed(code, Host::EqualDword, 4, 0);
    if lane == 4 {
        shuffle(code, 3, 4, 0xb1);
        packed(code, Host::And, 4, 3);
    }
    packed(code, add_or_subtract(lane * 2, false), 0, 4);
    super::saturating::publish_qc(code, active * 2);
    if lane == 2 {
        packed(code, Host::PackSignedDwordToWord, 0, 0);
    } else {
        shuffle(code, 0, 0, 0x88);
    }
}
fn doubling(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let Kind::Doubling {
        high, accumulate, ..
    } = operand.kind
    else {
        unreachable!()
    };
    if high && operand.lane_bytes == 2 {
        high_product_words(code, operand, target);
    } else if high {
        high_product(code, operand, false, operand.bytes.min(8), target);
        if operand.bytes == 16 {
            packed(code, Host::MoveAligned, 6, 0);
            high_product(code, operand, true, 8, target);
            packed(code, Host::UnpackLowQword, 6, 0);
            packed(code, Host::MoveAligned, 0, 6);
        }
    } else {
        let lane = operand.lane_bytes;
        if let Some(index) = operand.index {
            indexed(code, lane, index);
        }
        extend(code, 0, lane, operand.upper, true);
        extend(
            code,
            1,
            lane,
            operand.upper && operand.index.is_none(),
            true,
        );
        long_product(code, lane, true, target);
        packed(code, Host::MoveAligned, 1, 0);
        super::saturating::add_sub(code, lane * 2, true, false);
        super::saturating::publish_qc(code, operand.bytes);
        if accumulate != Accumulate::None {
            packed(code, Host::MoveAligned, 1, 0);
            read_vector(code, operand.destination, 0);
            super::saturating::add_sub(code, lane * 2, true, accumulate == Accumulate::Subtract);
            super::saturating::publish_qc(code, operand.bytes);
        }
    }
}
fn polynomial(code: &mut Code, lane: u8, widen: bool, upper: bool, target: TargetCpu) {
    if lane == 8 {
        if target.supports(TargetCpu::Pclmulqdq) {
            // Immediate bit 0 selects the left half; bit 4 selects the right.
            Host::CarrylessMultiplyQword.register_imm(
                code,
                0,
                1,
                if upper { 0x11 } else { 0x00 },
                target,
            );
            return;
        }
        if upper {
            Shift::RightBytes.emit(code, 0, 8);
            Shift::RightBytes.emit(code, 1, 8);
        }
        packed(code, Host::MoveQword, 0, 0);
        packed(code, Host::MoveQword, 1, 1);
        packed(code, Host::Xor, 5, 5);
        lane_constant(code, 4, 8, 1);
        // A counted loop bounds native code size; this register-only operation
        // has no intermediate guest fault or precise-entry boundary.
        code.asm().mov_imm32(Gpr::R10, 64);
        let loop_start = code.len();
        {
            packed(code, Host::MoveAligned, 2, 4);
            packed(code, Host::And, 2, 1);
            packed(code, Host::Xor, 3, 3);
            packed(code, Host::SubQword, 3, 2);
            packed(code, Host::UnpackLowQword, 3, 3);
            packed(code, Host::And, 3, 0);
            packed(code, Host::Xor, 5, 3);
            packed(code, Host::MoveAligned, 2, 0);
            Shift::RightQword.emit(code, 2, 63);
            packed(code, Host::Xor, 3, 3);
            packed(code, Host::UnpackLowQword, 3, 2);
            Shift::LeftQword.emit(code, 0, 1);
            packed(code, Host::Or, 0, 3);
            Shift::RightQword.emit(code, 1, 1);
        }
        let mut asm = code.asm();
        asm.dec(Size::Dword, Gpr::R10);
        let repeat = asm.jcc(Cond::Ne);
        resolve(code, repeat, loop_start);
    } else {
        let output_lane = if widen { 2 } else { 1 };
        if widen {
            extend(code, 0, 1, upper, false);
            extend(code, 1, 1, upper, false);
        }
        packed(code, Host::Xor, 5, 5);
        lane_constant(code, 4, output_lane, 1);
        if !widen {
            lane_constant(code, 3, 1, 0xfe);
            lane_constant(code, 6, 1, 0x7f);
        }
        for _ in 0..8 {
            packed(code, Host::MoveAligned, 2, 1);
            packed(code, Host::And, 2, 4);
            packed(
                code,
                if widen {
                    Host::EqualWord
                } else {
                    Host::EqualByte
                },
                2,
                4,
            );
            packed(code, Host::And, 2, 0);
            packed(code, Host::Xor, 5, 2);
            Shift::LeftWord.emit(code, 0, 1);
            Shift::RightWord.emit(code, 1, 1);
            if !widen {
                packed(code, Host::And, 0, 3);
                packed(code, Host::And, 1, 6);
            }
        }
    }
    packed(code, Host::MoveAligned, 0, 5);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let Operand {
        kind,
        destination,
        left,
        right,
        lane_bytes: lane,
        bytes,
        upper,
        index: _,
    } = *operand;
    if !matches!(
        kind,
        Kind::Doubling { high: true, .. } | Kind::RoundedDoublingAccumulate { .. }
    ) {
        read_vector(code, left, 0);
        read_vector(code, right, 1);
    }
    let mut result = 0;
    match kind {
        Kind::Dot { signed } => dot(code, operand, signed, target),
        Kind::RoundedDoublingAccumulate { subtract } => {
            rounded_accumulate(code, operand, subtract, target)
        }
        Kind::Polynomial { widen } => polynomial(code, lane, widen, upper, target),
        Kind::Doubling { .. } => doubling(code, operand, target),
        Kind::Product {
            signed,
            widen,
            accumulate: operation,
        } => {
            if let Some(index) = operand.index {
                indexed(code, lane, index);
            }
            if widen && operand.index.is_some() {
                indexed_long_product(code, lane, upper, signed, target);
            } else if widen {
                extend(code, 0, lane, upper, signed);
                extend(code, 1, lane, upper, signed);
                long_product(code, lane, signed, target);
            } else if operand.index.is_some() {
                indexed_low_product(code, lane, bytes, target);
            } else {
                low_product(code, lane, target);
            }
            result = accumulate(
                code,
                destination,
                if widen { lane * 2 } else { lane },
                operation,
            );
        }
        Kind::Arithmetic {
            signed,
            wide_left,
            subtract,
        } => {
            if !wide_left {
                extend(code, 0, lane, upper, signed);
            }
            extend(code, 1, lane, upper, signed);
            packed(code, add_or_subtract(lane * 2, subtract), 0, 1);
        }
        Kind::Difference {
            signed,
            widen,
            accumulate: accumulated,
        } => {
            if widen {
                extend(code, 0, lane, upper, signed);
                extend(code, 1, lane, upper, signed);
            }
            let output_lane = if widen { lane * 2 } else { lane };
            absolute_difference(code, output_lane, signed, target);
            if accumulated {
                accumulate(code, destination, output_lane, Accumulate::Add);
            }
        }
    }
    if bytes == 8 {
        packed(code, Host::MoveQword, result, result);
    } else if bytes < 8 {
        let mask = 1 - result;
        constant(
            code,
            mask,
            core::array::from_fn(|i| if i < usize::from(bytes) { 255 } else { 0 }),
        );
        packed(code, Host::And, result, mask);
    }
    commit(code, destination, result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_products_use_exact_unsaturated_pairs_on_every_target() {
        for word in [0x4e829420, 0x6e829420, 0x4fa2e820, 0x6fa2e820] {
            let operand = crate::aarch64::simd::products::decode(word)
                .unwrap()
                .unwrap();
            for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                let mut code = Code::new();
                emit(&mut code, &operand, target);
                let count = |opcode: Host| {
                    code.windows(opcode.encoding().len())
                        .filter(|bytes| *bytes == opcode.encoding())
                        .count()
                };
                assert_eq!(count(Host::MultiplyAddWords), 2);
                assert_eq!(count(Host::MultiplyAddUnsignedBytes), 0);
                assert_eq!(
                    count(Host::ByteSignMask),
                    0,
                    "dot accumulation preserves QC"
                );
            }
        }
    }

    #[test]
    fn rounded_accumulation_clamps_only_the_final_sum_and_checks_dword_multiply() {
        for word in [0x6e428420, 0x6e428c20, 0x6e828420, 0x6e828c20] {
            let operand = crate::aarch64::simd::products::decode(word)
                .unwrap()
                .unwrap();
            for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                let mut code = Code::new();
                emit(&mut code, &operand, target);
                let count = |opcode: Host| {
                    code.windows(opcode.encoding().len())
                        .filter(|bytes| *bytes == opcode.encoding())
                        .count()
                };
                assert_eq!(
                    count(Host::ByteSignMask),
                    2,
                    "one final QC decision per half"
                );
                assert_eq!(count(Host::AddSignedSaturatingWord), 0);
                assert_eq!(count(Host::SubSignedSaturatingWord), 0);
                assert_eq!(
                    count(Host::MultiplySignedDword),
                    if operand.lane_bytes == 4 && target >= TargetCpu::Sse41 {
                        2
                    } else {
                        0
                    }
                );
                assert_eq!(
                    count(Host::MultiplyHighSignedWord),
                    if operand.lane_bytes == 2 { 2 } else { 0 }
                );
            }
        }
    }

    #[test]
    fn indexed_products_share_packed_lowering_and_checked_dword_multiply() {
        for (word, lane, widen, signed) in [
            (0x4f628820, 2, false, false),
            (0x0f62a820, 2, true, true),
            (0x2f62a820, 2, true, false),
            (0x4f62a820, 2, true, true),
            (0x6f62a820, 2, true, false),
            (0x4fa28820, 4, false, false),
            (0x4fa2a820, 4, true, true),
            (0x6fa2a820, 4, true, false),
        ] {
            let operand = crate::aarch64::simd::products::decode(word)
                .unwrap()
                .unwrap();
            for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                let mut code = Code::new();
                emit(&mut code, &operand, target);
                let has = |opcode: Host| {
                    code.windows(opcode.encoding().len())
                        .any(|w| w == opcode.encoding())
                };
                let extended_words =
                    lane == 2 && widen && !operand.upper && target >= TargetCpu::Sse41;
                assert_eq!(
                    has(Host::MultiplyLowDword),
                    lane == 4 && !widen && target >= TargetCpu::Sse41 || extended_words
                );
                assert_eq!(
                    has(Host::MultiplySignedDword),
                    lane == 4 && widen && signed && target >= TargetCpu::Sse41
                );
                assert_eq!(has(Host::MultiplyLowWord), lane == 2 && !extended_words);
                assert_eq!(has(Host::SignExtendWordToDword), extended_words && signed);
                assert_eq!(has(Host::ZeroExtendWordToDword), extended_words && !signed);
                assert_eq!(
                    has(Host::MultiplyHighSignedWord),
                    lane == 2 && widen && signed && !extended_words
                );
                assert_eq!(
                    has(Host::MultiplyHighUnsignedWord),
                    lane == 2 && widen && !signed && !extended_words
                );
                if lane == 4 && widen {
                    assert!(
                        !has(Host::UnpackLowDword),
                        "PMULUDQ/PMULDQ consume only the selected even dwords"
                    );
                }
                assert_eq!(
                    code.windows(Host::LoadUnaligned.encoding().len())
                        .filter(|w| *w == Host::LoadUnaligned.encoding())
                        .count(),
                    2
                );
                assert!(
                    !has(Host::ByteSignMask),
                    "ordinary multiplication preserves FPSR/QC"
                );
                assert!(code.len() < 160, "bounded whole-vector packed product");
            }
        }
    }

    #[test]
    fn word_high_products_use_one_packed_pair_and_only_checked_rounding_extension() {
        for (word, rounded) in [(0x4e62b420, false), (0x6e62b420, true)] {
            let operand = crate::aarch64::simd::products::decode(word)
                .unwrap()
                .unwrap();
            for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Pclmulqdq] {
                let mut code = Code::new();
                emit(&mut code, &operand, target);
                let has = |opcode: Host| {
                    code.windows(opcode.encoding().len())
                        .any(|w| w == opcode.encoding())
                };
                let direct = rounded && target.supports(TargetCpu::Ssse3);
                assert_eq!(has(Host::MultiplyHighRoundedScaledWord), direct);
                assert_eq!(has(Host::MultiplyHighSignedWord), !direct);
                assert_eq!(has(Host::MultiplyLowWord), !direct);
                assert!(!has(Host::PackSignedDwordToWord));
                assert!(!has(Host::UnpackLowWord));
                let loads = code
                    .windows(Host::LoadUnaligned.encoding().len())
                    .filter(|w| *w == Host::LoadUnaligned.encoding())
                    .count();
                assert_eq!(loads, 2, "whole128 high products read each input once");
                assert!(has(Host::ByteSignMask));
                assert!(code.len() < 160, "packed high products stay compact");
            }
        }
    }
}
