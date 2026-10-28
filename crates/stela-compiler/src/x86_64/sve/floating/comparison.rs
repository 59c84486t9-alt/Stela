//! SVE FP comparisons without exceptions; signaling cases use software completion.
use crate::x86_64::asm::Code;
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::floating::comparison::{Kind, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{load_z_chunk, read_predicate_mask},
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
const MAGNITUDE_MASK: u8 = CLASSIFICATION_SCRATCH[0];
const EAX_REGISTER: u8 = 0;
const REGISTER_DIRECT: u8 = 0xc0;
const REGISTER_FIELD_SHIFT: u8 = 3;
const CMPPS: &[u8] = &[0x0f, 0xc2];
const CMPPD: &[u8] = &[0x66, 0x0f, 0xc2];
const AND_EAX_IMMEDIATE: &[u8] = &[0x25];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const SIGN_BITS: u8 = 1;

#[repr(u8)]
#[derive(Clone, Copy)]
enum Comparison {
    Equal = 0,
    Less = 1,
    LessEqual = 2,
    NotEqual = 4,
}

fn magnitudes(code: &mut Code, format: Format, target: TargetCpu) {
    Host::EqualDword.register(code, MAGNITUDE_MASK, MAGNITUDE_MASK, target);
    match format {
        Format::Single => ShiftOpcode::RightDword,
        Format::Double => ShiftOpcode::RightQword,
        Format::Half => unreachable!("native comparison width validated before emission"),
    }
    .emit(code, MAGNITUDE_MASK, SIGN_BITS);
    Host::And.register(code, LEFT, MAGNITUDE_MASK, target);
    Host::And.register(code, RIGHT, MAGNITUDE_MASK, target);
}

/// Operands contain only normals, signed zero or infinity. Return FF/00 lanes.
/// Masking inactive lanes and classification belong to the instruction emitter.
fn compare_mask(code: &mut Code, kind: Kind, format: Format, target: TargetCpu) -> u8 {
    if matches!(kind, Kind::AbsoluteGreaterEqual | Kind::AbsoluteGreater) {
        magnitudes(code, format, target);
    }
    let (destination, source, comparison) = match kind {
        Kind::Equal => (LEFT, RIGHT, Comparison::Equal),
        Kind::NotEqual => (LEFT, RIGHT, Comparison::NotEqual),
        Kind::Greater | Kind::AbsoluteGreater => (RIGHT, LEFT, Comparison::Less),
        Kind::GreaterEqual | Kind::AbsoluteGreaterEqual => (RIGHT, LEFT, Comparison::LessEqual),
        Kind::Less => (LEFT, RIGHT, Comparison::Less),
        Kind::LessEqual => (LEFT, RIGHT, Comparison::LessEqual),
        Kind::Unordered => {
            // Classification rejected every NaN, including inactive poison
            // masked to zero before classification. UN is therefore false.
            Host::Xor.register(code, LEFT, LEFT, target);
            return LEFT;
        }
    };
    code.extend(match format {
        Format::Single => CMPPS,
        Format::Double => CMPPD,
        Format::Half => unreachable!("native comparison width validated before emission"),
    });
    code.extend([
        REGISTER_DIRECT | (destination << REGISTER_FIELD_SHIFT) | source,
        comparison as u8,
    ]);
    destination
}

fn packed_leading_bits(element: ElementSize) -> u32 {
    (0..VECTOR_CHUNK_BYTES)
        .step_by(element.bytes())
        .fold(0, |bits, offset| bits | (1 << offset))
}

/// Stage one complete packed P result, committing only after every guard passes.
/// Half and exceptional active inputs retain whole-instruction completion.
/// Accepted host comparisons preserve caller MXCSR without saving/installing it.
/// Clobbers RAX/RCX/RDX, host flags and XMM0..7; preserves RDI/R15 and guest NZCV.
pub(crate) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    use crate::x86_64::scalable::numerical::{self, Environment, Output};

    let element = match operand.format {
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
        Format::Half => return Ok(false),
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Predicate(operand.destination)],
        Environment::Exact,
    )?;
    let classification = prepare_classification(code, operand.format, CLASSIFICATION_MASKS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        Host::And.register(code, LEFT, ACTIVE, target);
        guard_normal_zero_or_infinity(
            code,
            classification,
            LEFT,
            CLASSIFICATION_SCRATCH,
            &mut failures,
            target,
        );
        if operand.right == Some(operand.left) {
            // The one classified source denotes identical non-NaN numbers.
            // Keep its exceptional-input and active-control guards above.
            if matches!(
                operand.kind,
                Kind::Equal | Kind::GreaterEqual | Kind::LessEqual | Kind::AbsoluteGreaterEqual
            ) {
                Host::ByteSignMask.register(code, EAX_REGISTER, ACTIVE, target);
                code.extend(AND_EAX_IMMEDIATE);
                code.extend(packed_leading_bits(element).to_le_bytes());
            } else {
                code.extend(XOR_EAX_EAX);
            }
        } else {
            if let Some(right) = operand.right {
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                Host::And.register(code, RIGHT, ACTIVE, target);
                guard_normal_zero_or_infinity(
                    code,
                    classification,
                    RIGHT,
                    CLASSIFICATION_SCRATCH,
                    &mut failures,
                    target,
                );
            } else {
                Host::Xor.register(code, RIGHT, RIGHT, target);
            }
            let result = compare_mask(code, operand.kind, operand.format, target);
            Host::And.register(code, result, ACTIVE, target);
            Host::ByteSignMask.register(code, EAX_REGISTER, result, target);
            code.extend(AND_EAX_IMMEDIATE);
            code.extend(packed_leading_bits(element).to_le_bytes());
        }
        numerical::stage_predicate_bits16(code, &frame, 0, chunk);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn half_refusal_emits_no_frame_or_guard() {
        let mut code = Code::from(vec![0x90]);
        let operand = Operand {
            kind: Kind::Equal,
            format: Format::Half,
            destination: 15,
            governing: 7,
            left: 31,
            right: Some(31),
        };
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
