//! SVE FRECPS/FRSQRTS on normal values. A baseline multiply is used only when the
//! host status shows it was exact.
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdi};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, Rm, ShiftOp, Size};
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
            ArithmeticOpcode, FusedOpcode, emit_fma, emit_opcode_to, prepare_vector_input_range,
            prepare_vector_result_range, rounding_control, vector_exponent_range,
        },
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ADDEND: u8 = 6;
const OUTPUT_SLOT: usize = 0;
const BROADCAST_LOW_DWORD: u8 = 0;
const MXCSR_STATUS_MASK: u32 = 0x3f;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const RECIPROCAL_ADDEND_EXPONENT: u32 = 1;
const RECIPROCAL_SQUARE_ROOT_FRACTION_SHIFT: u32 = 1;

fn test_control(code: &mut Code, mask: u32) {
    code.asm().test_imm(
        Size::Dword,
        Mem::base_disp32(Rdi, (core::mem::offset_of!(GuestState, fpcr)) as i32),
        mask as i32,
    );
}

fn reject_status(code: &mut Code, mask: u32, failures: &mut Vec<usize>) {
    code.asm().test_imm(Size::Dword, Rcx, mask as i32);
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

fn broadcast(code: &mut Code, format: Format, bits: u64, target: TargetCpu) {
    if format == Format::Single {
        code.asm().mov_imm32(Rax, bits as u32);
    } else {
        code.asm().mov_imm64(Rax, bits);
    }
    code.asm().simd(Host::MoveGprQword, ADDEND, Rax, target);
    if format == Format::Single {
        code.asm().simd_imm(
            Host::ShuffleDword,
            ADDEND,
            Rm::Xmm(ADDEND),
            BROADCAST_LOW_DWORD,
            target,
        );
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
fn halve_left(code: &mut Code, format: Format, target: TargetCpu) {
    broadcast(code, format, 1 << format.fraction_bits(), target);
    let opcode = if format == Format::Single {
        Host::SubDword
    } else {
        Host::SubQword
    };
    opcode.register(code, LEFT, ADDEND, target);
}

fn reject_non_normal(code: &mut Code, format: Format, register: u8, failures: &mut Vec<usize>) {
    vector_exponent_range(code, format, Shape::Vector128, register);
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

/// Owns only unpredicated vector FRECPS/FRSQRTS, without registration or feature
/// dispatch. Baseline requires an exact normal product, checked FMA does not.
/// NaN, zero, infinity, subnormal and Half inputs retain exact completion;
/// cancellation, tiny/overflowing results and nonprecision host status decline.
/// All chunks stage before one guest commit; every refusal restores MXCSR/RSP.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
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
        let suppressed = code.asm().jcc(Cond::Ne);
        test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
        failures.push(code.asm().jcc(Cond::Ne).offset());
        code.asm().bind(suppressed);
    }
    rounding_control(code);
    test_control(code, FPCR_AH);
    let ordinary = code.asm().jcc(Cond::E);
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    code.asm().bind(ordinary);
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
            code.asm().vzeroupper();
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
        let suppressed = code.asm().jcc(Cond::Ne);
        let mut asm = code.asm();
        asm.mov(Size::Dword, Rax, Rcx);
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_INEXACT as i32);
        asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_TO_FPSR_INEXACT_SHIFT);
        numerical::add_fpsr(code, &frame);
        code.asm().bind(suppressed);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
            let mut code = Code::from(vec![0xaa]);
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
