//! Overflow-safe halving arithmetic and narrowing/widening helpers.
use super::{
    Host, commit, packed,
    products::extend,
    read_vector,
    rearrange::constant,
    shifts::{pack_truncated, right_shift, rounded_right},
};
use crate::{
    TargetCpu,
    aarch64::simd::halving::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};
use alloc::vec::Vec;

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
        _ => unreachable!(),
    }
}
fn lane_constant(code: &mut Vec<u8>, xmm: u8, lane: u8, value: u64) {
    let bytes = value.to_le_bytes();
    constant(
        code,
        xmm,
        core::array::from_fn(|i| bytes[i % usize::from(lane)]),
    );
}
fn half(code: &mut Vec<u8>, lane: u8, signed: bool, subtract: bool, round: bool) {
    if round && lane <= 2 {
        if signed {
            lane_constant(code, 2, lane, 1u64 << (lane * 8 - 1));
            packed(code, Host::Xor, 0, 2);
            packed(code, Host::Xor, 1, 2);
        }
        packed(
            code,
            if lane == 1 {
                Host::AverageByte
            } else {
                Host::AverageWord
            },
            0,
            1,
        );
        if signed {
            packed(code, Host::Xor, 0, 2);
        }
    } else if subtract {
        // floor((a-b)/2) = floor(a/2)-floor(b/2)-((~a & b) & 1).
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::AndNot, 2, 1);
        lane_constant(code, 3, lane, 1);
        packed(code, Host::And, 2, 3);
        right_shift(code, 0, lane, 1, signed);
        right_shift(code, 1, lane, 1, signed);
        packed(code, arithmetic(lane, true), 0, 1);
        packed(code, arithmetic(lane, true), 0, 2);
    } else {
        // floor average: (a&b)+((a^b)>>1). Ceil average: (a|b)-((a^b)>>1).
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, if round { Host::Or } else { Host::And }, 2, 1);
        packed(code, Host::Xor, 0, 1);
        right_shift(code, 0, lane, 1, signed);
        if round {
            packed(code, arithmetic(lane, true), 2, 0);
            packed(code, Host::MoveAligned, 0, 2);
        } else {
            packed(code, arithmetic(lane, false), 0, 2);
        }
    }
}
fn pair_long(code: &mut Vec<u8>, lane: u8, signed: bool, target: TargetCpu) {
    if lane == 1 && !signed && target >= TargetCpu::Ssse3 {
        constant(code, 1, [1; 16]);
        Host::MultiplyAddUnsignedBytes.register(code, 0, 1, target);
        return;
    }
    if lane == 2 && signed {
        lane_constant(code, 1, 2, 1);
        packed(code, Host::MultiplyAddWords, 0, 1);
        return;
    }
    if lane == 4 && target >= TargetCpu::Sse41 {
        packed(code, Host::MoveAligned, 2, 0);
        Shift::RightBytes.emit(code, 2, 8);
        let opcode = if signed {
            Host::SignExtendDwordToQword
        } else {
            Host::ZeroExtendDwordToQword
        };
        opcode.register(code, 0, 0, target);
        opcode.register(code, 2, 2, target);
        packed(code, Host::MoveAligned, 1, 0);
        packed(code, Host::UnpackLowQword, 0, 2);
        packed(code, Host::UnpackHighQword, 1, 2);
    } else {
        packed(code, Host::MoveAligned, 1, 0);
        if signed {
            match lane {
                1 => {
                    Shift::LeftWord.emit(code, 0, 8);
                    Shift::ArithmeticWord.emit(code, 0, 8);
                    Shift::ArithmeticWord.emit(code, 1, 8);
                }
                4 => {
                    Shift::LeftQword.emit(code, 0, 32);
                    right_shift(code, 0, 8, 32, true);
                    right_shift(code, 1, 8, 32, true);
                }
                _ => unreachable!("signed halfword path uses PMADDWD"),
            }
        } else {
            lane_constant(code, 2, lane * 2, (1u64 << (lane * 8)) - 1);
            packed(code, Host::And, 0, 2);
            match lane {
                1 => Shift::RightWord,
                2 => Shift::RightDword,
                4 => Shift::RightQword,
                _ => unreachable!(),
            }
            .emit(code, 1, lane * 8);
        }
    }
    packed(code, arithmetic(lane * 2, false), 0, 1);
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Operand {
        kind,
        destination,
        left,
        right,
        lane_bytes: lane,
        bytes,
    } = *operand;
    read_vector(code, left, 0);
    match kind {
        Kind::Half {
            signed,
            subtract,
            round,
        } => {
            read_vector(code, right, 1);
            half(code, lane, signed, subtract, round);
        }
        Kind::HighNarrow {
            subtract,
            round,
            upper,
        } => {
            read_vector(code, right, 1);
            packed(code, arithmetic(lane * 2, subtract), 0, 1);
            rounded_right(code, lane * 2, lane * 8, false, round);
            pack_truncated(code, lane, upper, destination);
            return;
        }
        Kind::Truncate { upper } => {
            pack_truncated(code, lane, upper, destination);
            return;
        }
        Kind::ShiftLong { upper } => {
            extend(code, 0, lane, upper, false);
            match lane {
                1 => Shift::LeftWord,
                2 => Shift::LeftDword,
                4 => Shift::LeftQword,
                _ => unreachable!(),
            }
            .emit(code, 0, lane * 8);
        }
        Kind::PairLong { signed, accumulate } => {
            pair_long(code, lane, signed, target);
            if accumulate {
                read_vector(code, destination, 1);
                packed(code, arithmetic(lane * 2, false), 0, 1);
            }
        }
    }
    if bytes == 8 {
        packed(code, Host::MoveQword, 0, 0);
    }
    commit(code, destination, 0);
}
