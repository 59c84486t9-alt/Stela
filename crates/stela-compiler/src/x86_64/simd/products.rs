//! Packed SIMD products, widened arithmetic and exact absolute differences.
use super::{Host, commit, greater, packed, read_vector, rearrange::constant, shuffle};
use crate::{
    TargetCpu,
    aarch64::simd::products::{Accumulate, Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

fn arithmetic(lane: u8, subtract: bool) -> Host {
    match (subtract, lane) {
        (false, 1) => Host::AddByte,
        (false, 2) => Host::AddWord,
        (false, 4) => Host::AddDword,
        (false, 8) => Host::AddQword,
        (true, 1) => Host::SubByte,
        (true, 2) => Host::SubWord,
        (true, 4) => Host::SubDword,
        (true, 8) => Host::SubQword,
        _ => unreachable!("reviewed lane size"),
    }
}
/// Extend the selected 64-bit input half into doubled-width lanes. XMM3 is the
/// extension mask; extending one operand never changes the other in XMM0/1.
pub(super) fn extend(code: &mut Vec<u8>, xmm: u8, lane: u8, upper: bool, signed: bool) {
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
fn low_product(code: &mut Vec<u8>, lane: u8, target: TargetCpu) {
    match lane {
        1 => {
            // Compute even and odd bytes separately in 16-bit lanes. Mask/shift
            // each product back to one byte before merging the original order.
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
fn long_product(code: &mut Vec<u8>, lane: u8, signed: bool, target: TargetCpu) {
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
fn accumulate(code: &mut Vec<u8>, destination: u8, lane: u8, operation: Accumulate) {
    if operation == Accumulate::None {
        return;
    }
    read_vector(code, destination, 1);
    if operation == Accumulate::Subtract {
        packed(code, arithmetic(lane, true), 1, 0);
        packed(code, Host::MoveAligned, 0, 1);
    } else {
        packed(code, arithmetic(lane, false), 0, 1);
    }
}
fn absolute_difference(code: &mut Vec<u8>, lane: u8, signed: bool, target: TargetCpu) {
    if lane <= 2 {
        if signed {
            let bits = (1u64 << (lane * 8 - 1)).to_le_bytes();
            constant(
                code,
                4,
                std::array::from_fn(|i| bits[i % usize::from(lane)]),
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
        packed(code, arithmetic(lane, true), 5, 1);
        // Keep the wrapped difference in XMM5 while comparison uses XMM0..4.
        // Ordering decides the direction of subtraction before interpreting ABS.
        greater(code, lane, !signed, target);
        packed(code, Host::EqualDword, 1, 1);
        packed(code, Host::Xor, 0, 1);
        packed(code, Host::Xor, 5, 0);
        packed(code, arithmetic(lane, true), 5, 0);
        packed(code, Host::MoveAligned, 0, 5);
    }
}

fn lane_constant(code: &mut Vec<u8>, xmm: u8, lane: u8, value: u64) {
    let bytes = value.to_le_bytes();
    constant(
        code,
        xmm,
        std::array::from_fn(|i| bytes[i % usize::from(lane)]),
    );
}
fn indexed(code: &mut Vec<u8>, lane: u8, index: u8) {
    Shift::RightBytes.emit(code, 1, index * lane);
    if lane == 2 {
        // Repeat the low halfword without requiring PSHUFLW or SSSE3.
        packed(code, Host::UnpackLowWord, 1, 1);
    }
    shuffle(code, 1, 1, 0);
}
/// Full-width 16-bit high products need no widening or per-half processing.
/// PMULHRSW shares Arm's ties-up rounding but wraps MIN*MIN instead of clamping.
fn high_product_words(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
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
            // ((L>>14)+1)>>1 retains the carry2 for L>=0xc000. A wrapping
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
fn high_product(code: &mut Vec<u8>, operand: &Operand, upper: bool, active: u8, target: TargetCpu) {
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
        packed(code, arithmetic(lane * 2, false), 0, 1);
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
    packed(code, arithmetic(lane * 2, false), 0, 4);
    super::saturating::publish_qc(code, active * 2);
    if lane == 2 {
        packed(code, Host::PackSignedDwordToWord, 0, 0);
    } else {
        shuffle(code, 0, 0, 0x88);
    }
}
fn doubling(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
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
fn polynomial(code: &mut Vec<u8>, lane: u8, widen: bool, upper: bool, target: TargetCpu) {
    if lane == 8 {
        if target.supports(TargetCpu::Pclmulqdq) {
            Host::CarrylessMultiplyQword.register(code, 0, 1, target);
            // Immediate bit 0 selects the left half; bit 4 selects the right.
            code.push(if upper { 0x11 } else { 0x00 });
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
        code.extend([0x41, 0xba, 64, 0, 0, 0]); // mov r10d,64
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
        code.extend([0x41, 0xff, 0xca]); // dec r10d
        code.extend([0x0f, 0x85]); // jnz loop_start
        let displacement = i32::try_from(loop_start as isize - (code.len() + 4) as isize)
            .expect("bounded polynomial loop");
        code.extend(displacement.to_le_bytes());
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

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
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
    if !matches!(kind, Kind::Doubling { high: true, .. }) {
        read_vector(code, left, 0);
        read_vector(code, right, 1);
    }
    match kind {
        Kind::Polynomial { widen } => polynomial(code, lane, widen, upper, target),
        Kind::Doubling { .. } => doubling(code, operand, target),
        Kind::Product {
            signed,
            widen,
            accumulate: operation,
        } => {
            if widen {
                extend(code, 0, lane, upper, signed);
                extend(code, 1, lane, upper, signed);
                long_product(code, lane, signed, target);
            } else {
                low_product(code, lane, target);
            }
            accumulate(
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
            packed(code, arithmetic(lane * 2, subtract), 0, 1);
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
        packed(code, Host::MoveQword, 0, 0);
    } else if bytes < 8 {
        constant(
            code,
            1,
            std::array::from_fn(|i| if i < usize::from(bytes) { 255 } else { 0 }),
        );
        packed(code, Host::And, 0, 1);
    }
    commit(code, destination, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_high_products_use_one_packed_pair_and_only_checked_rounding_extension() {
        for (word, rounded) in [(0x4e62b420, false), (0x6e62b420, true)] {
            let operand = crate::aarch64::simd::products::decode(word)
                .unwrap()
                .unwrap();
            for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Pclmulqdq] {
                let mut code = Vec::new();
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
