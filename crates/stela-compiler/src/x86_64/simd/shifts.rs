//! SSE2 non-saturating packed shifts, including byte/qword emulation and width
//! changes. Host flags/MXCSR are never substituted for guest NZCV/FP status.
use super::{Host, commit, packed, read_vector, rearrange::constant, shuffle};
use crate::{
    aarch64::simd::shifts::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

fn lane_mask(code: &mut Vec<u8>, xmm: u8, lane_bytes: u8, value: u64) {
    let bytes = value.to_le_bytes();
    constant(
        code,
        xmm,
        std::array::from_fn(|i| bytes[i % usize::from(lane_bytes)]),
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
pub(super) fn logical_shift(code: &mut Vec<u8>, xmm: u8, lane_bytes: u8, amount: u8, left: bool) {
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
fn right_shift(code: &mut Vec<u8>, xmm: u8, lane_bytes: u8, amount: u8, signed: bool) {
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
fn rounded_right(code: &mut Vec<u8>, lane_bytes: u8, amount: u8, signed: bool, round: bool) {
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

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    let Operand {
        kind,
        destination,
        source,
        lane_bytes,
        amount,
        bytes,
    } = *operand;
    read_vector(code, source, 0);
    match kind {
        Kind::Narrow { round, upper } => {
            narrow(code, lane_bytes, amount, round, upper, destination);
            return;
        }
        Kind::Widen { signed, upper } => widen(code, lane_bytes, amount, signed, upper),
        Kind::Left { insert } => {
            logical_shift(code, 0, lane_bytes, amount, true);
            if insert {
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
