//! SVE FCADD (packed ADD) and FCMLA (FMA3, one rounding per component).
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, complex::Rotation, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        simd::arithmetic::Shape,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, FusedOpcode, emit_fma, emit_opcode_to, prepare_vector_input_range,
            prepare_vector_result_range, rounding_control, vector_exponent_range,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const MASK_SCRATCH: u8 = 2;
const CONSTANT_SCRATCH: u8 = 3;
const ADDEND: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const REPEAT_LOW_DWORD: u8 = 0;
const SWAP_SINGLE_COMPONENTS: u8 = 0xb1;
const SWAP_DOUBLE_COMPONENTS: u8 = 0x4e;
const DUPLICATE_SINGLE_REAL: u8 = 0xa0;
const DUPLICATE_SINGLE_IMAGINARY: u8 = 0xf5;
const DUPLICATE_LOW_PAIR: u8 = 0x44;
const DUPLICATE_HIGH_PAIR: u8 = 0xee;
const BENIGN_ADDEND_INCREMENT: u32 = 1;
const SINGLE_COMPONENT_SHIFT_BITS: u8 = u32::BITS as u8;
const DOUBLE_COMPONENT_BYTES: u8 = size_of::<u64>() as u8;
const MXCSR_PRECISION: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_PRECISION - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;

#[derive(Clone, Copy)]
enum Operation {
    Add {
        left: u8,
        right: u8,
        rotation: Rotation,
    },
    MultiplyAdd {
        addend: u8,
        left: u8,
        right: Source,
        rotation: Rotation,
    },
}

fn admitted(operand: Operand, target: TargetCpu) -> Option<Operation> {
    if operand.shape != ResultShape::Vector || operand.format == Format::Half {
        return None;
    }
    match (operand.kind, operand.inputs, operand.predicate) {
        (
            Kind::ComplexAdd(rotation @ (Rotation::Degrees90 | Rotation::Degrees270)),
            Inputs::Binary {
                left: Source::Vector(left),
                right: Source::Vector(right),
            },
            Some(_),
        ) if left == operand.destination => Some(Operation::Add {
            left,
            right,
            rotation,
        }),
        (
            Kind::ComplexMultiplyAdd(rotation),
            Inputs::Fused {
                addend,
                left,
                right,
            },
            predicate,
        ) if addend == operand.destination && target.supports(TargetCpu::Fma) => {
            let allocated = matches!((predicate, right), (Some(_), Source::Vector(_)))
                || predicate.is_none()
                    && operand.format == Format::Single
                    && matches!(right, Source::Indexed { index: 0..=1, .. });
            allocated.then_some(Operation::MultiplyAdd {
                addend,
                left,
                right,
                rotation,
            })
        }
        _ => None,
    }
}

fn reject(code: &mut Code, failures: &mut Vec<usize>) {
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

fn shuffle(code: &mut Code, register: u8, order: u8, target: TargetCpu) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        register,
        Rm::Xmm(register),
        order,
        target,
    );
}

/// Rotate M before active-lane masking; an active output may read an inactive
/// partner input. NaN sign rules remain with fallback because active NaNs fail
/// the following integer exponent guards before any architectural commit.
fn rotate_right(code: &mut Code, format: Format, rotation: Rotation, target: TargetCpu) {
    if matches!(rotation, Rotation::Degrees90 | Rotation::Degrees270) {
        shuffle(
            code,
            RIGHT,
            if format == Format::Single {
                SWAP_SINGLE_COMPONENTS
            } else {
                SWAP_DOUBLE_COMPONENTS
            },
            target,
        );
    }
    if rotation == Rotation::Degrees0 {
        return;
    }
    Host::EqualDword.register(code, MASK_SCRATCH, MASK_SCRATCH, target);
    let sign_shift = if format == Format::Single {
        ShiftOpcode::LeftDword
    } else {
        ShiftOpcode::LeftQword
    };
    sign_shift.emit(code, MASK_SCRATCH, (format.bits() - 1) as u8);
    match (format, rotation) {
        (Format::Single, Rotation::Degrees90) => {
            ShiftOpcode::RightQword.emit(code, MASK_SCRATCH, SINGLE_COMPONENT_SHIFT_BITS)
        }
        (Format::Single, Rotation::Degrees270) => {
            ShiftOpcode::LeftQword.emit(code, MASK_SCRATCH, SINGLE_COMPONENT_SHIFT_BITS)
        }
        (Format::Double, Rotation::Degrees90) => {
            ShiftOpcode::RightBytes.emit(code, MASK_SCRATCH, DOUBLE_COMPONENT_BYTES)
        }
        (Format::Double, Rotation::Degrees270) => {
            ShiftOpcode::LeftBytes.emit(code, MASK_SCRATCH, DOUBLE_COMPONENT_BYTES)
        }
        (_, Rotation::Degrees180) => {}
        _ => unreachable!("allocated complex rotation and format"),
    }
    Host::Xor.register(code, RIGHT, MASK_SCRATCH, target);
}

fn selected_left(code: &mut Code, format: Format, rotation: Rotation, target: TargetCpu) {
    let imaginary = matches!(rotation, Rotation::Degrees90 | Rotation::Degrees270);
    let order = match (format, imaginary) {
        (Format::Single, false) => DUPLICATE_SINGLE_REAL,
        (Format::Single, true) => DUPLICATE_SINGLE_IMAGINARY,
        (Format::Double, false) => DUPLICATE_LOW_PAIR,
        (Format::Double, true) => DUPLICATE_HIGH_PAIR,
        _ => unreachable!("Half uses exact completion"),
    };
    shuffle(code, LEFT, order, target);
}

fn load_right(
    code: &mut Code,
    source: Source,
    chunk: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    let register = match source {
        Source::Vector(register) | Source::Indexed { register, .. } => register,
        Source::ImmediateBits(_) => unreachable!("allocated complex source"),
    };
    load_z_chunk(code, register, chunk, RIGHT, length, target);
    if let Source::Indexed { index, .. } = source {
        shuffle(
            code,
            RIGHT,
            if index == 0 {
                DUPLICATE_LOW_PAIR
            } else {
                DUPLICATE_HIGH_PAIR
            },
            target,
        );
    }
}

/// Inactive FCADD uses1+1; inactive FCMLA uses2+1*1, both exact normals.
fn benign_inactive(code: &mut Code, format: Format, input: u8, target: TargetCpu) {
    let increment = if input == ADDEND {
        BENIGN_ADDEND_INCREMENT
    } else {
        0
    };
    let bits = u64::from(format.exponent_bias() + increment) << format.fraction_bits();
    if format == Format::Single {
        code.asm().mov_imm32(Rax, bits as u32);
    } else {
        code.asm().mov_imm64(Rax, bits);
    }
    code.asm()
        .simd(Host::MoveGprQword, CONSTANT_SCRATCH, Rax, target);
    if format == Format::Single {
        shuffle(code, CONSTANT_SCRATCH, REPEAT_LOW_DWORD, target);
    } else {
        Host::UnpackLowQword.register(code, CONSTANT_SCRATCH, CONSTANT_SCRATCH, target);
    }
    Host::MoveAligned.register(code, MASK_SCRATCH, ACTIVE, target);
    Host::AndNot.register(code, MASK_SCRATCH, CONSTANT_SCRATCH, target);
    Host::And.register(code, input, ACTIVE, target);
    Host::Or.register(code, input, MASK_SCRATCH, target);
}

/// The four complex forms. Active single/double operands and results must be
/// normal; indexed half precision and FCMLA without FMA return false without
/// emitting. RAX/RCX/RDX, flags and XMM0-7 are clobbered.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Some(operation) = admitted(operand, target) else {
        return Ok(false);
    };
    let element = if operand.format == Format::Single {
        ElementSize::Word
    } else {
        ElementSize::Doubleword
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                element,
                ACTIVE,
                MASK_SCRATCH,
                length,
                target,
            );
        } else if features.full_a64() {
            Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
        }
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        let fused = match operation {
            Operation::Add {
                left,
                right,
                rotation,
            } => {
                load_z_chunk(code, left, chunk, LEFT, length, target);
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                rotate_right(code, operand.format, rotation, target);
                false
            }
            Operation::MultiplyAdd {
                addend,
                left,
                right,
                rotation,
            } => {
                load_z_chunk(code, addend, chunk, ADDEND, length, target);
                load_z_chunk(code, left, chunk, LEFT, length, target);
                load_right(code, right, chunk, length, target);
                selected_left(code, operand.format, rotation, target);
                rotate_right(code, operand.format, rotation, target);
                true
            }
        };
        if operand.predicate.is_some() {
            for input in [LEFT, RIGHT] {
                benign_inactive(code, operand.format, input, target);
            }
            if fused {
                benign_inactive(code, operand.format, ADDEND, target);
            }
        }
        prepare_vector_input_range(code, operand.format);
        for input in [LEFT, RIGHT] {
            vector_exponent_range(code, operand.format, Shape::Vector128, input);
            reject(code, &mut failures);
        }
        if fused {
            vector_exponent_range(code, operand.format, Shape::Vector128, ADDEND);
            reject(code, &mut failures);
            emit_fma(
                code,
                operand.format,
                Shape::Vector128,
                FusedOpcode::MultiplyAdd,
                target,
            );
            code.asm().vzeroupper();
        } else {
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Add,
                LEFT,
                RIGHT,
            );
        }
        prepare_vector_result_range(code);
        vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
        reject(code, &mut failures);
        if operand.predicate.is_some() {
            load_z_chunk(code, operand.destination, chunk, ADDEND, length, target);
            Host::And.register(code, LEFT, ACTIVE, target);
            Host::AndNot.register(code, ACTIVE, ADDEND, target);
            Host::Or.register(code, LEFT, ACTIVE, target);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    numerical::capture_status(code, &frame);
    code.asm()
        .test_imm32(Size::Dword, Rcx, MXCSR_OTHER_STATUS as i32);
    reject(code, &mut failures);
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rax, Rcx);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_PRECISION as i32);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_TO_FPSR_INEXACT_SHIFT);
    numerical::add_fpsr(code, &frame);
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
