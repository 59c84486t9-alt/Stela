//! SVE single/double min/max. NaNs, subnormals and zero/zero ties use software
//! completion.
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::FloatOp;
use crate::x86_64::asm::Gpr::Rax;
use crate::x86_64::asm::{Code, Cond, Rm, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, minmax::MinMaxOperation},
        scalable::{ElementSize, VectorLength},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
    },
};
use alloc::vec::Vec;

use super::classify::{
    guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ACTIVE: u8 = 2;
const CLASSIFICATION_SCRATCH: [u8; 3] = [3, 4, 5];
const PREDICATE_SCRATCH: u8 = CLASSIFICATION_SCRATCH[0];
const CLASSIFICATION_MASKS: [u8; 2] = [6, 7];
const ZERO_PAIR: u8 = CLASSIFICATION_SCRATCH[0];
const ZERO_VECTOR: u8 = CLASSIFICATION_SCRATCH[1];
const DOUBLE_ZERO_SCRATCH: u8 = CLASSIFICATION_SCRATCH[2];
const OLD_DESTINATION: u8 = CLASSIFICATION_SCRATCH[0];
const OUTPUT_SLOT: usize = 0;
const REMOVE_SIGN_BITS: u8 = 1;
const REPEAT_LOW_DWORD: u8 = 0;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;

fn inputs(operand: Operand) -> Option<(MinMaxOperation, u8, Source, u8)> {
    let Kind::MinMax(operation) = operand.kind else {
        return None;
    };
    let Inputs::Binary {
        left: Source::Vector(left),
        right,
    } = operand.inputs
    else {
        return None;
    };
    if operand.shape != ResultShape::Vector || left != operand.destination {
        return None;
    }
    let predicate = operand.predicate?;
    match right {
        Source::Vector(_) => {}
        Source::ImmediateBits(bits)
            if bits == 0
                || bits
                    == u64::from(operand.format.exponent_bias())
                        << operand.format.fraction_bits() => {}
        Source::ImmediateBits(_) | Source::Indexed { .. } => return None,
    }
    Some((operation, left, right, predicate))
}

fn immediate(code: &mut Code, format: Format, bits: u64, target: TargetCpu) {
    if bits == 0 {
        Host::Xor.register(code, RIGHT, RIGHT, target);
        return;
    }
    if format == Format::Single {
        code.asm().mov_imm32(Rax, bits as u32);
    } else {
        code.asm().mov_imm64(Rax, bits);
    }
    code.asm().simd(Host::MoveGprQword, RIGHT, Rax, target);
    if format == Format::Single {
        code.asm().simd_imm(
            Host::ShuffleDword,
            RIGHT,
            Rm::Xmm(RIGHT),
            REPEAT_LOW_DWORD,
            target,
        );
    } else {
        Host::UnpackLowQword.register(code, RIGHT, RIGHT, target);
    }
}

/// Reject only active pairs whose two magnitudes are zero. Removing the sign
/// after OR accepts exactly-one-zero inputs while retaining every signed-zero
/// tie for the shared semantic helper. Double requires both dwords to be zero.
/// LEFT/RIGHT/ACTIVE and the invariant classification masks remain live.
pub(super) fn guard_zero_pairs(
    code: &mut Code,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::MoveAligned.register(code, ZERO_PAIR, LEFT, target);
    Host::Or.register(code, ZERO_PAIR, RIGHT, target);
    match format {
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
        Format::Half => unreachable!("native min/max width validated before emission"),
    }
    .emit(code, ZERO_PAIR, REMOVE_SIGN_BITS);
    Host::Xor.register(code, ZERO_VECTOR, ZERO_VECTOR, target);
    Host::EqualDword.register(code, ZERO_PAIR, ZERO_VECTOR, target);
    if format == Format::Double {
        code.asm().simd_imm(
            Host::ShuffleDword,
            DOUBLE_ZERO_SCRATCH,
            Rm::Xmm(ZERO_PAIR),
            SWAP_ADJACENT_DWORDS,
            target,
        );
        Host::And.register(code, ZERO_PAIR, DOUBLE_ZERO_SCRATCH, target);
    }
    Host::And.register(code, ZERO_PAIR, ACTIVE, target);
    code.asm()
        .simd_to_gpr(Host::ByteSignMask, Rax, ZERO_PAIR, target);
    code.asm().test(Size::Dword, Rax, Rax);
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

pub(super) fn selection(code: &mut Code, operation: MinMaxOperation, format: Format) {
    let minimum = matches!(
        operation,
        MinMaxOperation::Minimum | MinMaxOperation::MinimumNumber
    );
    let mut asm = code.asm();
    match (format == Format::Double, minimum) {
        (true, true) => asm.float(FloatOp::Min, FloatLanes::PackedDouble, LEFT, Rm::Xmm(RIGHT)),
        (true, false) => asm.float(FloatOp::Max, FloatLanes::PackedDouble, LEFT, Rm::Xmm(RIGHT)),
        (false, true) => asm.float(FloatOp::Min, FloatLanes::PackedSingle, LEFT, Rm::Xmm(RIGHT)),
        (false, false) => asm.float(FloatOp::Max, FloatLanes::PackedSingle, LEFT, Rm::Xmm(RIGHT)),
    }
}

/// Emit the eight predicated vector and immediate min/max forms. Half precision
/// and unsupported shapes leave `code` untouched. A failed guard exits at the
/// instruction with every source unchanged. Accepted lanes keep the caller's
/// MXCSR and add no FPSR bits. Clobbers RAX/RCX/RDX, flags and XMM0-7;
/// preserves RDI/R15 and NZCV.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let element = match operand.format {
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
        Format::Half => return Ok(false),
    };
    let Some((operation, left, right, predicate)) = inputs(operand) else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let classification = prepare_classification(code, operand.format, CLASSIFICATION_MASKS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            element,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, left, chunk, LEFT, length, target);
        Host::And.register(code, LEFT, ACTIVE, target);
        guard_normal_zero_or_infinity(
            code,
            classification,
            LEFT,
            CLASSIFICATION_SCRATCH,
            &mut failures,
            target,
        );
        match right {
            Source::Vector(register) => load_z_chunk(code, register, chunk, RIGHT, length, target),
            Source::ImmediateBits(bits) => immediate(code, operand.format, bits, target),
            Source::Indexed { .. } => unreachable!("indexed inputs refused before emission"),
        }
        Host::And.register(code, RIGHT, ACTIVE, target);
        if matches!(right, Source::Vector(_)) {
            guard_normal_zero_or_infinity(
                code,
                classification,
                RIGHT,
                CLASSIFICATION_SCRATCH,
                &mut failures,
                target,
            );
        }
        guard_zero_pairs(code, operand.format, &mut failures, target);
        selection(code, operation, operand.format);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        Host::And.register(code, LEFT, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        Host::Or.register(code, LEFT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn half_and_non_minmax_shapes_emit_no_frame() {
        let base = Operand {
            kind: Kind::MinMax(MinMaxOperation::Minimum),
            format: Format::Half,
            destination: 0,
            predicate: Some(7),
            inputs: Inputs::Binary {
                left: Source::Vector(0),
                right: Source::Vector(31),
            },
            shape: ResultShape::Vector,
        };
        for operand in [
            base,
            Operand {
                format: Format::Single,
                predicate: None,
                ..base
            },
            Operand {
                format: Format::Double,
                shape: ResultShape::ScalarReduction,
                ..base
            },
            Operand {
                format: Format::Single,
                inputs: Inputs::Binary {
                    left: Source::Vector(1),
                    right: Source::ImmediateBits(0),
                },
                ..base
            },
        ] {
            let mut code = Code::from(vec![0x90]);
            assert!(
                !emit(
                    &mut code,
                    operand,
                    VectorLength::from_bytes(256).unwrap(),
                    NumericalFeatures::new(true, true, true),
                    GuestAddress(0x1000),
                    TargetCpu::Baseline,
                )
                .unwrap()
            );
            assert_eq!(code, [0x90]);
        }
    }
}
