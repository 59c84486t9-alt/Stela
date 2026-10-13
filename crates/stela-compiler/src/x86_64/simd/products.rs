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
fn extend(code: &mut Vec<u8>, xmm: u8, lane: u8, upper: bool, signed: bool) {
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

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Operand {
        kind,
        destination,
        left,
        right,
        lane_bytes: lane,
        bytes,
        upper,
    } = *operand;
    read_vector(code, left, 0);
    read_vector(code, right, 1);
    match kind {
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
    }
    commit(code, destination, 0);
}
