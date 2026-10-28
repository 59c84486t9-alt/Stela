//! SVE shifts. Scalar recipes use host flags only as scratch.
use crate::x86_64::asm::Gpr::{Rax, Rsp};
use crate::x86_64::asm::{Alu, Code, Mem, Size};
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

mod saturating;
mod scalar;
mod variable;
pub(crate) use scalar::rounding_variable_chunk;

const BITS_PER_BYTE: u8 = 8;
const PACKED_SATURATION_VECTOR_BYTES: usize = 256;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8, target: TargetCpu) {
    opcode.register(code, destination, source, target);
}

/// Load `value` repeated in each `element` lane of `xmm`, through RAX.
pub(super) fn repeated_constant(code: &mut Code, xmm: u8, element: ElementSize, value: u64) {
    let limbs = value.to_le_bytes();
    let repeated: [u8; core::mem::size_of::<u64>()] =
        core::array::from_fn(|i| limbs[i % element.bytes()]);
    let mut asm = code.asm();
    asm.mov_imm64(Rax, u64::from_le_bytes(repeated));
    asm.simd(Host::MoveGprQword, xmm, Rax, TargetCpu::Baseline);
    packed(code, Host::UnpackLowQword, xmm, xmm, TargetCpu::Baseline);
}

/// Store `xmm` to, or load it from, the stack slot at RSP + `slot`.
pub(super) fn stack_vector(code: &mut Code, xmm: u8, slot: u8, store: bool) {
    let slot = Mem::base_disp8(Rsp, slot as i8);
    if store {
        code.asm().movdqu_store(slot, xmm);
    } else {
        code.asm().movdqu_load(xmm, slot);
    }
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
/// Whether the selected recipe needs a profile declaring DIT clear. Only
/// variable shifts with count-dependent scalar control flow do.
pub(crate) fn requires_declared_dit_zero(operand: Operand, length: VectorLength) -> bool {
    operand.has_dit_guarantee
        && !matches!(operand.count, Count::Immediate(_))
        && matches!(mapping(operand, length), Mapping::Scalar)
}

fn adjust_stack(code: &mut Code, bytes: u8, allocate: bool) {
    if bytes != 0 {
        let op = if allocate { Alu::Sub } else { Alu::Add };
        code.asm().alu_imm8(op, Size::Qword, Rsp, bytes as i8);
    }
}

pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
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

fn immediate_chunk(code: &mut Code, operand: Operand, target: TargetCpu) {
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
mod tests {
    use super::*;

    fn variable_operand(element_size: ElementSize, kind: Kind) -> Operand {
        Operand {
            kind,
            element_size,
            destination: 31,
            source: 31,
            count: Count::Elements(31),
            predication: Predication::Merging(7),
            second_source: None,
            has_dit_guarantee: true,
        }
    }

    #[test]
    fn avx2_variable_shift_body_replaces_scalar_scratch_without_widening_state_access() {
        let length = VectorLength::from_bytes(64).unwrap();
        let operand = variable_operand(ElementSize::Word, Kind::LogicalLeft);
        let mut baseline = Code::new();
        let mut avx2 = Code::new();
        emit(&mut baseline, operand, length, TargetCpu::Baseline);
        emit(&mut avx2, operand, length, TargetCpu::Avx2);
        assert!(baseline.starts_with(&[0x48, 0x83, 0xec, scalar::STACK_BYTES]));
        assert!(avx2.starts_with(&[0xc5, 0xf8, 0x77]));
        let shift = [0xc4, 0xe2, 0x79, 0x47, 0xc1];
        assert_eq!(
            avx2.windows(shift.len())
                .filter(|row| *row == shift)
                .count(),
            length.chunks()
        );
        assert!(!baseline.windows(shift.len()).any(|row| row == shift));
        assert!(avx2.len() < baseline.len());
        assert!(requires_declared_dit_zero(operand, length));

        let excluded = variable_operand(ElementSize::Doubleword, Kind::ArithmeticRight);
        baseline = Code::new();
        avx2 = Code::new();
        emit(&mut baseline, excluded, length, TargetCpu::Baseline);
        emit(&mut avx2, excluded, length, TargetCpu::Avx2);
        assert_eq!(baseline, avx2);
    }
}
