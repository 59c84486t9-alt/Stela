//! SVE shifts. Scalar recipes use host flags only as scratch.
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, Predication, VectorLength},
        sve::shifts::{Count, Kind, Operand},
    },
    x86_64::{
        isa::{SimdOpcode as Host, clear_upper_vector_state},
        scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
        simd::shifts::{logical_shift, right_shift, rounded_right},
    },
};
use alloc::vec::Vec;

mod saturating;
mod scalar;
mod variable;
pub(crate) use scalar::rounding_variable_chunk;

const SUB_RSP_IMM8: [u8; 3] = [0x48, 0x83, 0xec];
const ADD_RSP_IMM8: [u8; 3] = [0x48, 0x83, 0xc4];
const BITS_PER_BYTE: u8 = 8;
const PACKED_SATURATION_VECTOR_BYTES: usize = 256;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8, target: TargetCpu) {
    opcode.register(code, destination, source, target);
}

#[derive(Clone, Copy)]
enum Mapping {
    Immediate,
    Scalar,
    Packed,
    PackedSaturating,
}
fn mapping(operand: Operand, length: VectorLength) -> Mapping {
    if matches!(operand.count, Count::Elements(_)) {
        if operand.element_size == ElementSize::Byte
            && matches!(operand.kind, Kind::LogicalLeft | Kind::LogicalRight)
        {
            return Mapping::Packed;
        }
        if operand.kind == Kind::SaturatingRoundingSigned
            && matches!(
                operand.element_size,
                ElementSize::Byte | ElementSize::Halfword
            )
            && length.bytes() == PACKED_SATURATION_VECTOR_BYTES
        {
            return Mapping::PackedSaturating;
        }
    }
    if !matches!(operand.count, Count::Immediate(_))
        || matches!(
            operand.kind,
            Kind::DivideSigned
                | Kind::SaturatingSigned
                | Kind::SaturatingUnsigned
                | Kind::SaturatingSignedToUnsigned
        )
    {
        Mapping::Scalar
    } else {
        Mapping::Immediate
    }
}
/// Whether the selected host route needs an explicit DIT=0 declaration.
/// Fixed packed/immediate routes retain the original profile; only noted
/// variable instructions using scalar count-dependent control flow need V2.
pub(crate) fn requires_declared_dit_zero(operand: Operand, length: VectorLength) -> bool {
    operand.has_dit_guarantee
        && !matches!(operand.count, Count::Immediate(_))
        && matches!(mapping(operand, length), Mapping::Scalar)
}

fn adjust_stack(code: &mut Vec<u8>, bytes: u8, allocate: bool) {
    if bytes != 0 {
        code.extend(if allocate { SUB_RSP_IMM8 } else { ADD_RSP_IMM8 });
        code.push(bytes);
    }
}

pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let mapping = mapping(operand, length);
    let avx2 = variable::avx2_opcode(operand.kind, operand.element_size, operand.count, target);
    let scratch = match (avx2, mapping) {
        (Some(_), _) => 0,
        (_, Mapping::Scalar) => scalar::STACK_BYTES,
        (_, Mapping::PackedSaturating) => saturating::STACK_BYTES,
        _ => 0,
    };
    if avx2.is_some() {
        clear_upper_vector_state(code, target);
    }
    adjust_stack(code, scratch, true);
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, 0, length, target);
        load_z_chunk(code, operand.destination, chunk, 6, length, target);
        let count_register = match operand.count {
            Count::Elements(register) | Count::Doublewords(register) => Some(register),
            Count::Immediate(_) => operand.second_source,
        };
        if let Some(register) = count_register {
            load_z_chunk(code, register, chunk, 1, length, target);
        }
        if let Some(opcode) = avx2 {
            opcode.register(code, 0, 0, 1, target);
        } else {
            match mapping {
                Mapping::Immediate => immediate_chunk(code, operand, target),
                Mapping::Scalar => {
                    scalar::chunk(code, operand.kind, operand.element_size, operand.count)
                }
                Mapping::Packed => variable::chunk(code, operand.kind, operand.element_size),
                Mapping::PackedSaturating => {
                    saturating::chunk(code, operand.kind, operand.element_size)
                }
            }
        }
        match operand.predication {
            Predication::Unpredicated => {}
            Predication::Merging(predicate) => {
                read_predicate_mask(
                    code,
                    predicate,
                    chunk,
                    operand.element_size,
                    2,
                    3,
                    length,
                    target,
                );
                packed(code, Host::And, 0, 2, target);
                packed(code, Host::AndNot, 2, 6, target);
                packed(code, Host::Or, 0, 2, target);
            }
            Predication::Zeroing(_) => unreachable!("shift forms merge inactive elements"),
        }
        store_z_chunk(code, operand.destination, chunk, 0, length, target);
    }
    adjust_stack(code, scratch, false);
}

fn immediate_chunk(code: &mut Vec<u8>, operand: Operand, target: TargetCpu) {
    let Count::Immediate(amount) = operand.count else {
        unreachable!()
    };
    let lane = operand.element_size.bytes() as u8;
    let bits = lane * BITS_PER_BYTE;
    match operand.kind {
        Kind::LogicalLeft => logical_shift(code, 0, lane, amount, true),
        Kind::LogicalRight => logical_shift(code, 0, lane, amount, false),
        Kind::ArithmeticRight => right_shift(code, 0, lane, amount, true),
        Kind::RoundRightSigned | Kind::RoundRightUnsigned => rounded_right(
            code,
            lane,
            amount,
            operand.kind == Kind::RoundRightSigned,
            true,
        ),
        Kind::AccumulateSigned
        | Kind::AccumulateUnsigned
        | Kind::RoundAccumulateSigned
        | Kind::RoundAccumulateUnsigned => {
            let signed = matches!(
                operand.kind,
                Kind::AccumulateSigned | Kind::RoundAccumulateSigned
            );
            let round = matches!(
                operand.kind,
                Kind::RoundAccumulateSigned | Kind::RoundAccumulateUnsigned
            );
            rounded_right(code, lane, amount, signed, round);
            let add = match operand.element_size {
                ElementSize::Byte => Host::AddByte,
                ElementSize::Halfword => Host::AddWord,
                ElementSize::Word => Host::AddDword,
                ElementSize::Doubleword => Host::AddQword,
                _ => unreachable!(),
            };
            packed(code, add, 0, 6, target);
        }
        Kind::InsertLeft => {
            if amount != 0 {
                logical_shift(code, 6, lane, bits - amount, true);
                logical_shift(code, 6, lane, bits - amount, false);
                logical_shift(code, 0, lane, amount, true);
                packed(code, Host::Or, 0, 6, target);
            }
        }
        Kind::InsertRight => {
            if amount == bits {
                packed(code, Host::MoveAligned, 0, 6, target);
            } else {
                logical_shift(code, 6, lane, bits - amount, false);
                logical_shift(code, 6, lane, bits - amount, true);
                logical_shift(code, 0, lane, amount, false);
                packed(code, Host::Or, 0, 6, target);
            }
        }
        Kind::XorRotate => {
            packed(code, Host::Xor, 0, 1, target);
            if amount != bits {
                packed(code, Host::MoveAligned, 1, 0, target);
                logical_shift(code, 0, lane, amount, false);
                logical_shift(code, 1, lane, bits - amount, true);
                packed(code, Host::Or, 0, 1, target);
            }
        }
        _ => unreachable!("scalar-only immediate mapping"),
    }
}

#[cfg(test)]
mod tests;
