//! SME2 FAMIN/FAMAX and FSCALE over whole staged groups.
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, features::NumericalFeatures},
        scalable::{VECTOR_REGISTER_COUNT, VectorLength},
        simd::arithmetic::Shape,
        sme::extrema_scale::{Kind, Operand},
    },
    x86_64::{
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        simd::{absolute_selection, exponent_scale},
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const SCRATCH: [u8; 4] = [2, 3, 4, 5];
const TEST_STATE_IMMEDIATE: &[u8] = &[0xf7, 0x87];
const JNZ: &[u8] = &[0x0f, 0x85];

/// Absolute extrema admit every numeric lane. FSCALE admits normal inputs and
/// normal results using the shared exact exponent-adjustment kernel. All other
/// lanes, and retained enables, exit once before any architectural group commit.
/// Integer operations preserve complete caller MXCSR.
/// Clobbers RAX/RCX/RDX, host flags, XMM0..5; preserves RDI/R15 and guest NZCV.
pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let count = operand.group.count();
    if !operand.destination.is_multiple_of(count)
        || usize::from(operand.destination) + usize::from(count)
            > usize::from(VECTOR_REGISTER_COUNT)
        || if operand.right_grouped {
            !operand.right.is_multiple_of(count)
                || usize::from(operand.right) + usize::from(count)
                    > usize::from(VECTOR_REGISTER_COUNT)
        } else {
            operand.kind != Kind::Scale || operand.right >= VECTOR_REGISTER_COUNT / 2
        }
    {
        return Ok(false);
    }
    let outputs: Vec<_> = (0..count)
        .map(|index| Output::Z(operand.destination + index))
        .collect();
    let frame = numerical::begin(code, length, &outputs, Environment::Exact)?;
    let mut failures = Vec::new();
    if features.full_a64() {
        code.extend(TEST_STATE_IMMEDIATE);
        code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
        code.extend(FPCR_EXCEPTION_ENABLE_MASK.to_le_bytes());
        code.extend(JNZ);
        failures.push(code.len());
        code.extend(0_i32.to_le_bytes());
    }
    for index in 0..count {
        for chunk in 0..length.chunks() {
            load_z_chunk(
                code,
                operand.destination + index,
                chunk,
                LEFT,
                length,
                target,
            );
            let right = if operand.right_grouped {
                operand.right + index
            } else {
                operand.right
            };
            load_z_chunk(code, right, chunk, RIGHT, length, target);
            match operand.kind {
                Kind::AbsoluteMinMax(operation) => {
                    absolute_selection::guard_and_magnitudes(
                        code,
                        operand.format,
                        LEFT,
                        RIGHT,
                        SCRATCH,
                        &mut failures,
                        target,
                    );
                    absolute_selection::emit(
                        code,
                        operand.format,
                        operation,
                        LEFT,
                        RIGHT,
                        SCRATCH,
                        target,
                    );
                }
                Kind::Scale => exponent_scale::emit(
                    code,
                    operand.format,
                    Shape::Vector128,
                    &mut failures,
                    target,
                ),
            }
            numerical::stage_vector_chunk(code, &frame, usize::from(index), chunk, LEFT, target);
        }
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
