//! Native packed integer combining, horizontal reductions and bit counts.
use super::{
    Host, commit, packed, read_vector, rearrange::constant, shifts::logical_shift, shuffle,
};
use crate::{
    TargetCpu,
    aarch64::simd::reductions::{BitCount, Combine, Kind, Operand, Shape},
    x86_64::isa::ShiftOpcode as Shift,
};

fn add_opcode(lane: u8) -> Host {
    match lane {
        1 => Host::AddByte,
        2 => Host::AddWord,
        4 => Host::AddDword,
        8 => Host::AddQword,
        _ => unreachable!(),
    }
}
fn compare_opcode(lane: u8) -> Host {
    match lane {
        1 => Host::GreaterByte,
        2 => Host::GreaterWord,
        4 => Host::GreaterDword,
        _ => unreachable!(),
    }
}
fn equal_opcode(lane: u8) -> Host {
    match lane {
        1 => Host::EqualByte,
        2 => Host::EqualWord,
        4 => Host::EqualDword,
        _ => unreachable!(),
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
fn select_minmax(code: &mut Vec<u8>, lane: u8, signed: bool, maximum: bool, target: TargetCpu) {
    let native = match (signed, maximum, lane) {
        (false, false, 1) => Host::MinUnsignedByte,
        (false, true, 1) => Host::MaxUnsignedByte,
        (true, false, 2) => Host::MinSignedWord,
        (true, true, 2) => Host::MaxSignedWord,
        (true, false, 1) => Host::MinSignedByte,
        (true, true, 1) => Host::MaxSignedByte,
        (false, false, 2) => Host::MinUnsignedWord,
        (false, true, 2) => Host::MaxUnsignedWord,
        (true, false, 4) => Host::MinSignedDword,
        (true, true, 4) => Host::MaxSignedDword,
        (false, false, 4) => Host::MinUnsignedDword,
        (false, true, 4) => Host::MaxUnsignedDword,
        _ => unreachable!("allocated min/max lane"),
    };
    if target >= native.requires() {
        native.register(code, 0, 1, target);
        return;
    }
    packed(code, Host::MoveAligned, 2, 0);
    packed(code, Host::MoveAligned, 3, 1);
    if !signed {
        lane_constant(code, 4, lane, 1u64 << (lane * 8 - 1));
        packed(code, Host::Xor, 2, 4);
        packed(code, Host::Xor, 3, 4);
    }
    packed(code, compare_opcode(lane), 2, 3); // mask where original left > right
    if !maximum {
        packed(code, Host::EqualDword, 3, 3);
        packed(code, Host::Xor, 2, 3);
    }
    // right XOR ((left XOR right) AND selected-left mask)
    packed(code, Host::Xor, 0, 1);
    packed(code, Host::And, 0, 2);
    packed(code, Host::Xor, 0, 1);
}
fn combine(code: &mut Vec<u8>, operation: Combine, lane: u8, target: TargetCpu) {
    match operation {
        Combine::Add | Combine::LongAdd { .. } => packed(code, add_opcode(lane), 0, 1),
        Combine::Minimum { signed } => select_minmax(code, lane, signed, false, target),
        Combine::Maximum { signed } => select_minmax(code, lane, signed, true, target),
    }
}

/// Produce adjacent even or odd lanes from XMM2/XMM3, respecting active width.
/// XMM6 preserves the first selection while the second uses XMM0/XMM4/XMM5/7.
fn pair_selection(code: &mut Vec<u8>, lane: u8, bytes: u8, odd: bool) {
    packed(code, Host::MoveAligned, 0, 2);
    packed(code, Host::MoveAligned, 4, 3);
    match lane {
        1 => {
            if odd {
                Shift::RightWord.emit(code, 0, 8);
                Shift::RightWord.emit(code, 4, 8);
            } else {
                lane_constant(code, 5, 2, 0xff);
                packed(code, Host::And, 0, 5);
                packed(code, Host::And, 4, 5);
            }
            packed(code, Host::PackUnsignedWordToByte, 0, 4);
            if bytes == 8 {
                shuffle(code, 0, 0, 0x88);
            }
        }
        2 => {
            if !odd {
                Shift::LeftDword.emit(code, 0, 16);
                Shift::LeftDword.emit(code, 4, 16);
            }
            Shift::ArithmeticDword.emit(code, 0, 16);
            Shift::ArithmeticDword.emit(code, 4, 16);
            packed(code, Host::PackSignedDwordToWord, 0, 4);
            if bytes == 8 {
                shuffle(code, 0, 0, 0x88);
            }
        }
        4 => {
            let control = if odd { 0xdd } else { 0x88 };
            shuffle(code, 0, 0, control);
            shuffle(code, 4, 4, control);
            packed(
                code,
                if bytes == 8 {
                    Host::UnpackLowDword
                } else {
                    Host::UnpackLowQword
                },
                0,
                4,
            );
        }
        8 => packed(
            code,
            if odd {
                Host::UnpackHighQword
            } else {
                Host::UnpackLowQword
            },
            0,
            4,
        ),
        _ => unreachable!("allocated pair lane"),
    }
}
fn pair_operands(code: &mut Vec<u8>, operand: &Operand) {
    read_vector(code, operand.left, 2);
    read_vector(code, operand.right, 3);
    pair_selection(code, operand.lane_bytes, operand.bytes, false);
    packed(code, Host::MoveAligned, 6, 0);
    pair_selection(code, operand.lane_bytes, operand.bytes, true);
    packed(code, Host::MoveAligned, 1, 0);
    packed(code, Host::MoveAligned, 0, 6);
}

fn long_sum_inputs(code: &mut Vec<u8>, lane: u8, bytes: u8, signed: bool) {
    packed(code, Host::Xor, 1, 1);
    if signed {
        packed(code, compare_opcode(lane), 1, 0);
    }
    if bytes == 16 {
        packed(code, Host::MoveAligned, 2, 0);
        packed(
            code,
            match lane {
                1 => Host::UnpackHighByte,
                2 => Host::UnpackHighWord,
                4 => Host::UnpackHighDword,
                _ => unreachable!(),
            },
            2,
            1,
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
        0,
        1,
    );
    if bytes == 16 {
        packed(code, add_opcode(lane * 2), 0, 2);
    }
}
fn across(code: &mut Vec<u8>, operation: Combine, mut lane: u8, mut bytes: u8, target: TargetCpu) {
    if let Combine::LongAdd { signed } = operation {
        long_sum_inputs(code, lane, bytes, signed);
        lane *= 2;
        bytes = 16;
    }
    let mut stride = bytes / 2;
    while stride >= lane {
        packed(code, Host::MoveAligned, 1, 0);
        Shift::RightBytes.emit(code, 1, stride);
        combine(code, operation, lane, target);
        stride /= 2;
    }
    constant(
        code,
        1,
        std::array::from_fn(|i| if i < usize::from(lane) { 255 } else { 0 }),
    );
    packed(code, Host::And, 0, 1);
}

fn nibble_lookup(code: &mut Vec<u8>, reverse: bool, target: TargetCpu) {
    let table = std::array::from_fn(|i| {
        if reverse {
            (i as u8).reverse_bits() >> 4
        } else {
            (i as u8).count_ones() as u8
        }
    });
    constant(code, 2, table);
    packed(code, Host::MoveAligned, 4, 2);
    packed(code, Host::MoveAligned, 1, 0);
    constant(code, 3, [15; 16]);
    packed(code, Host::And, 0, 3);
    Shift::RightWord.emit(code, 1, 4);
    packed(code, Host::And, 1, 3);
    Host::ByteShuffle.register(code, 2, 0, target);
    Host::ByteShuffle.register(code, 4, 1, target);
    if reverse {
        Shift::LeftWord.emit(code, 2, 4);
        packed(code, Host::Or, 2, 4);
    } else {
        packed(code, Host::AddByte, 2, 4);
    }
    packed(code, Host::MoveAligned, 0, 2);
}
fn bit_population(code: &mut Vec<u8>, target: TargetCpu) {
    if target >= TargetCpu::Ssse3 {
        nibble_lookup(code, false, target);
        return;
    }
    packed(code, Host::MoveAligned, 1, 0);
    Shift::RightWord.emit(code, 1, 1);
    constant(code, 2, [0x55; 16]);
    packed(code, Host::And, 1, 2);
    packed(code, Host::SubByte, 0, 1);
    packed(code, Host::MoveAligned, 1, 0);
    Shift::RightWord.emit(code, 1, 2);
    constant(code, 2, [0x33; 16]);
    packed(code, Host::And, 0, 2);
    packed(code, Host::And, 1, 2);
    packed(code, Host::AddByte, 0, 1);
    packed(code, Host::MoveAligned, 1, 0);
    Shift::RightWord.emit(code, 1, 4);
    packed(code, Host::AddByte, 0, 1);
    constant(code, 2, [15; 16]);
    packed(code, Host::And, 0, 2);
}
fn bit_reverse(code: &mut Vec<u8>, target: TargetCpu) {
    if target >= TargetCpu::Ssse3 {
        nibble_lookup(code, true, target);
        return;
    }
    for (amount, mask) in [(1, 0x55), (2, 0x33), (4, 0x0f)] {
        packed(code, Host::MoveAligned, 1, 0);
        Shift::RightWord.emit(code, 1, amount);
        constant(code, 2, [mask; 16]);
        packed(code, Host::And, 1, 2);
        packed(code, Host::And, 0, 2);
        Shift::LeftWord.emit(code, 0, amount);
        packed(code, Host::Or, 0, 1);
    }
}
fn leading_count(code: &mut Vec<u8>, lane: u8, sign: bool) {
    if sign {
        packed(code, Host::Xor, 1, 1);
        packed(code, compare_opcode(lane), 1, 0);
        packed(code, Host::Xor, 0, 1);
    }
    packed(code, Host::Xor, 2, 2); // accumulated per-lane count
    packed(code, Host::Xor, 3, 3); // zero comparison operand
    let mut step = lane * 4;
    while step != 0 {
        packed(code, Host::MoveAligned, 1, 0);
        logical_shift(code, 1, lane, lane * 8 - step, false);
        packed(code, equal_opcode(lane), 1, 3); // missing high half: increment and shift
        lane_constant(code, 4, lane, u64::from(step));
        packed(code, Host::And, 4, 1);
        packed(code, add_opcode(lane), 2, 4);
        packed(code, Host::MoveAligned, 4, 0);
        logical_shift(code, 4, lane, step, true);
        packed(code, Host::Xor, 4, 0);
        packed(code, Host::And, 4, 1);
        packed(code, Host::Xor, 0, 4);
        step /= 2;
    }
    packed(code, equal_opcode(lane), 0, 3);
    lane_constant(code, 1, lane, 1);
    packed(code, Host::And, 0, 1);
    packed(code, add_opcode(lane), 2, 0);
    if sign {
        packed(
            code,
            match lane {
                1 => Host::SubByte,
                2 => Host::SubWord,
                4 => Host::SubDword,
                _ => unreachable!(),
            },
            2,
            1,
        );
    }
    packed(code, Host::MoveAligned, 0, 2);
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Operand {
        kind,
        destination,
        left,
        right,
        bytes,
        lane_bytes,
    } = *operand;
    if !matches!(
        kind,
        Kind::Combine {
            shape: Shape::Pairs,
            ..
        }
    ) {
        read_vector(code, left, 0);
    }
    let mut scalar = false;
    match kind {
        Kind::Combine { operation, shape } => match shape {
            Shape::Lanes => {
                read_vector(code, right, 1);
                combine(code, operation, lane_bytes, target);
            }
            Shape::Pairs => {
                pair_operands(code, operand);
                combine(code, operation, lane_bytes, target);
            }
            Shape::Across => {
                across(code, operation, lane_bytes, bytes, target);
                scalar = true;
            }
        },
        Kind::Bits(operation) => match operation {
            BitCount::Population => bit_population(code, target),
            BitCount::Reverse => bit_reverse(code, target),
            BitCount::LeadingZeros => leading_count(code, lane_bytes, false),
            BitCount::LeadingSign => leading_count(code, lane_bytes, true),
            BitCount::Not => {
                packed(code, Host::EqualDword, 1, 1);
                packed(code, Host::Xor, 0, 1);
            }
        },
    }
    if !scalar && bytes == 8 {
        packed(code, Host::MoveQword, 0, 0);
    }
    commit(code, destination, 0);
}
