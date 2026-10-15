//! Exact normal-domain reciprocal steps with transactional scalable staging.
//!
//! FRSQRTS scales a normal multiplicand exactly before its sole rounding.
//! Baseline multiplication is accepted only when its actual host status proves
//! the intermediate exact; checked FMA admits inexact products directly.
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, Format, features::NumericalFeatures},
        scalable::VectorLength,
        simd::{arithmetic::Shape, refinement::Kind as RefinementKind},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        simd::numerical::{
            ArithmeticOpcode, FusedOpcode, VZEROUPPER, emit_fma, emit_opcode_to,
            prepare_vector_input_range, prepare_vector_result_range, rounding_control,
            vector_exponent_range,
        },
    },
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ADDEND: u8 = 6;
const OUTPUT_SLOT: usize = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const GPR_RAX: u8 = 0;
const BROADCAST_LOW_DWORD: u8 = 0;
const MXCSR_STATUS_MASK: u32 = 0x3f;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const RECIPROCAL_ADDEND_EXPONENT: u32 = 1;
const RECIPROCAL_SQUARE_ROOT_FRACTION_SHIFT: u32 = 1;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const TEST_STATE_IMMEDIATE: &[u8] = &[0xf7, 0x87];
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const REL32_BYTES: usize = size_of::<i32>();

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn resolve(code: &mut [u8], displacement: usize, destination: usize) {
    let distance = i32::try_from(destination as i64 - (displacement + REL32_BYTES) as i64)
        .expect("bounded refinement branch");
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&distance.to_le_bytes());
}

fn test_control(code: &mut Vec<u8>, mask: u32) {
    code.extend(TEST_STATE_IMMEDIATE);
    code.extend((std::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(mask.to_le_bytes());
}

fn reject_status(code: &mut Vec<u8>, mask: u32, failures: &mut Vec<usize>) {
    code.extend(TEST_ECX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    failures.push(branch(code, JNZ_REL32));
}

fn broadcast(code: &mut Vec<u8>, format: Format, bits: u64, target: TargetCpu) {
    if format == Format::Single {
        code.push(MOV_EAX_IMMEDIATE);
        code.extend((bits as u32).to_le_bytes());
    } else {
        code.extend(MOV_RAX_IMMEDIATE);
        code.extend(bits.to_le_bytes());
    }
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (ADDEND << MODRM_REGISTER_SHIFT) | GPR_RAX);
    if format == Format::Single {
        Host::ShuffleDword.register(code, ADDEND, ADDEND, target);
        code.push(BROADCAST_LOW_DWORD);
    } else {
        Host::UnpackLowQword.register(code, ADDEND, ADDEND, target);
    }
}

fn addend_bits(format: Format, kind: RefinementKind) -> u64 {
    match kind {
        RefinementKind::Reciprocal => {
            u64::from(format.exponent_bias() + RECIPROCAL_ADDEND_EXPONENT) << format.fraction_bits()
        }
        RefinementKind::ReciprocalSquareRoot => {
            (u64::from(format.exponent_bias()) << format.fraction_bits())
                | (1 << (format.fraction_bits() - RECIPROCAL_SQUARE_ROOT_FRACTION_SHIFT))
        }
    }
}

/// Inputs already passed a normal-domain classifier. For FRSQRTS the left
/// exponent is >=2, so subtracting one exponent unit is exact and stays normal.
fn halve_left(code: &mut Vec<u8>, format: Format, target: TargetCpu) {
    broadcast(code, format, 1 << format.fraction_bits(), target);
    let opcode = if format == Format::Single {
        Host::SubDword
    } else {
        Host::SubQword
    };
    opcode.register(code, LEFT, ADDEND, target);
}

fn reject_non_normal(code: &mut Vec<u8>, format: Format, register: u8, failures: &mut Vec<usize>) {
    vector_exponent_range(code, format, Shape::Vector128, register);
    failures.push(branch(code, JNZ_REL32));
}

/// Owns only unpredicated vector FRECPS/FRSQRTS, without registration or feature
/// dispatch. Baseline requires an exact normal product, checked FMA does not.
/// NaN, zero, infinity, subnormal and Half inputs retain exact completion;
/// cancellation, tiny/overflowing results and nonprecision host status decline.
/// All chunks stage before one guest commit; every refusal restores MXCSR/RSP.
pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    if !matches!(operand.format, Format::Single | Format::Double)
        || operand.shape != ResultShape::Vector
        || operand.predicate.is_some()
    {
        return Ok(false);
    }
    let Kind::Refinement(kind) = operand.kind else {
        return Ok(false);
    };
    let Inputs::Binary {
        left: Source::Vector(left),
        right: Source::Vector(right),
    } = operand.inputs
    else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    let mut failures = Vec::new();
    if features.full_a64() {
        test_control(code, FPCR_AH);
        let suppressed = branch(code, JNZ_REL32);
        test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
        failures.push(branch(code, JNZ_REL32));
        let next = code.len();
        resolve(code, suppressed, next);
    }
    rounding_control(code);
    test_control(code, FPCR_AH);
    let ordinary = branch(code, JZ_REL32);
    code.extend(XOR_EAX_EAX);
    let next = code.len();
    resolve(code, ordinary, next);
    numerical::install_mxcsr(code, &frame);
    for chunk in 0..length.chunks() {
        numerical::clear_status(code, &frame);
        load_z_chunk(code, left, chunk, LEFT, length, target);
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        prepare_vector_input_range(code, operand.format);
        reject_non_normal(code, operand.format, RIGHT, &mut failures);
        if kind == RefinementKind::ReciprocalSquareRoot {
            prepare_vector_result_range(code);
        }
        reject_non_normal(code, operand.format, LEFT, &mut failures);
        if kind == RefinementKind::ReciprocalSquareRoot {
            halve_left(code, operand.format, target);
        }
        broadcast(
            code,
            operand.format,
            addend_bits(operand.format, kind),
            target,
        );
        if target.supports(TargetCpu::Fma) {
            emit_fma(
                code,
                operand.format,
                Shape::Vector128,
                FusedOpcode::NegativeMultiplyAdd,
                target,
            );
            code.extend(VZEROUPPER);
        } else {
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Multiply,
                LEFT,
                RIGHT,
            );
            numerical::capture_status(code, &frame);
            reject_status(code, MXCSR_STATUS_MASK, &mut failures);
            // Product is exact, but a tiny normal/subnormal could interact with
            // guest FZ/AH controls. Keep the common conservative normal range.
            prepare_vector_result_range(code);
            reject_non_normal(code, operand.format, LEFT, &mut failures);
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Subtract,
                ADDEND,
                LEFT,
            );
            Host::MoveAligned.register(code, LEFT, ADDEND, target);
        }
        prepare_vector_result_range(code);
        reject_non_normal(code, operand.format, LEFT, &mut failures);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
        numerical::capture_status(code, &frame);
        reject_status(code, MXCSR_OTHER_STATUS, &mut failures);
        test_control(code, FPCR_AH);
        let suppressed = branch(code, JNZ_REL32);
        code.extend(MOV_EAX_ECX);
        code.push(AND_EAX_IMMEDIATE);
        code.extend(MXCSR_INEXACT.to_le_bytes());
        code.extend(SHR_EAX_IMMEDIATE);
        code.push(MXCSR_TO_FPSR_INEXACT_SHIFT);
        numerical::add_fpsr(code, &frame);
        let next = code.len();
        resolve(code, suppressed, next);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addends_are_exact_two_and_one_point_five() {
        for (format, reciprocal, square_root) in [
            (Format::Single, 0x4000_0000, 0x3fc0_0000),
            (Format::Double, 0x4000_0000_0000_0000, 0x3ff8_0000_0000_0000),
        ] {
            assert_eq!(addend_bits(format, RefinementKind::Reciprocal), reciprocal);
            assert_eq!(
                addend_bits(format, RefinementKind::ReciprocalSquareRoot),
                square_root
            );
        }
    }

    #[test]
    fn unrelated_shapes_leave_output_untouched() {
        let length = VectorLength::from_bytes(16).unwrap();
        let base = Operand {
            kind: Kind::Refinement(RefinementKind::Reciprocal),
            format: Format::Single,
            destination: 0,
            predicate: None,
            inputs: Inputs::Binary {
                left: Source::Vector(1),
                right: Source::Vector(2),
            },
            shape: ResultShape::Vector,
        };
        for operand in [
            Operand {
                format: Format::Half,
                ..base
            },
            Operand {
                predicate: Some(0),
                ..base
            },
            Operand {
                shape: ResultShape::ScalarReduction,
                ..base
            },
            Operand {
                kind: Kind::SquareRoot,
                ..base
            },
            Operand {
                inputs: Inputs::Unary { source: 1 },
                ..base
            },
        ] {
            let mut code = vec![0xaa];
            assert!(
                !emit(
                    &mut code,
                    operand,
                    length,
                    NumericalFeatures::default(),
                    GuestAddress(0),
                    TargetCpu::Baseline
                )
                .unwrap()
            );
            assert_eq!(code, [0xaa]);
        }
    }
}
