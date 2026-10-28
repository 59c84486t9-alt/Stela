//! SVE indexed half-precision arithmetic through exact double intermediates.
use crate::x86_64::asm::Code;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            BinaryOperation, Format, complex::Rotation, features::NumericalFeatures,
            fused::FusedOperation,
        },
        scalable::{VECTOR_CHUNK_BYTES, VectorLength},
        simd::arithmetic::Shape,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        simd::{
            half::{self, ResultSign, RoundingPolicy},
            numerical::{ArithmeticOpcode, Condition, VZEROUPPER, branch, emit_opcode_to, resolve},
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ADDEND: u8 = 2;
const ORIGINAL_ADDEND: u8 = 3;
const ORIGINAL_LEFT: u8 = 4;
const ORIGINAL_RIGHT: u8 = 5;
const RESULT: u8 = 6;
const ASSEMBLED: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const HALF_BYTES: usize = size_of::<u16>();
const HALF_LANES: usize = VECTOR_CHUNK_BYTES / HALF_BYTES;
const FIRST_HALF: u8 = 0;
const LAST_HALF: u8 = HALF_LANES as u8 - 1;
const REPEAT_LOW_WORD: u8 = 0;
const REPEAT_LOW_DWORD: u8 = 0;
const REPEAT_DWORD_SELECTOR: u8 = 0x55;
const DUPLICATE_REAL_WORDS: u8 = 0xa0;
const DUPLICATE_IMAGINARY_WORDS: u8 = 0xf5;
const SWAP_WORD_COMPONENTS: u8 = 0xb1;
const SIGN_MASK: u8 = ADDEND;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const XOR_R11D_R11D: &[u8] = &[0x45, 0x31, 0xdb];
const INC_R11D: &[u8] = &[0x41, 0xff, 0xc3];
const CMP_R11D_IMMEDIATE: &[u8] = &[0x41, 0x83, 0xfb];
const NORMAL_HALF_EXPONENT_COUNT: u32 =
    (Format::Half.exponent_mask() >> Format::Half.fraction_bits()) as u32 - 1;
const FIRST_NORMAL_HALF_EXPONENT: u32 = 1 << Format::Half.fraction_bits();
const HALF_TO_DOUBLE_BIAS: u64 = ((Format::Double.exponent_bias() - Format::Half.exponent_bias())
    as u64)
    << Format::Double.fraction_bits();
const MXCSR_STATUS_MASK: u32 = 0x3f;
const PEXTRW_EAX_XMM: &[u8] = &[0x66, 0x0f, 0xc5];
const PINSRW_XMM_EAX: &[u8] = &[0x66, 0x0f, 0xc4];
const MOV_EDX_EAX: &[u8] = &[0x89, 0xc2];
const AND_EDX_IMMEDIATE: &[u8] = &[0x81, 0xe2];
const SUB_EDX_IMMEDIATE: &[u8] = &[0x81, 0xea];
const CMP_EDX_IMMEDIATE: &[u8] = &[0x81, 0xfa];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const MOVABS_R9_IMMEDIATE: &[u8] = &[0x49, 0xb9];
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const MOV_EAX_R10D: &[u8] = &[0x44, 0x89, 0xd0];

#[derive(Debug, Clone, Copy, Default)]
pub(in crate::x86_64) enum Recipe {
    #[default]
    Baseline,
    CheckedWidening,
}

#[derive(Clone, Copy)]
struct Operation {
    left: u8,
    right: u8,
    index: u8,
    fused: bool,
    subtract: bool,
    rotation: Option<Rotation>,
}

fn admitted(operand: Operand) -> Option<Operation> {
    if operand.format != Format::Half
        || operand.predicate.is_some()
        || operand.shape != ResultShape::Vector
    {
        return None;
    }
    match (operand.kind, operand.inputs) {
        (
            Kind::Binary(BinaryOperation::Multiply),
            Inputs::Binary {
                left: Source::Vector(left),
                right:
                    Source::Indexed {
                        register: right,
                        index: index @ 0..=7,
                    },
            },
        ) => Some(Operation {
            left,
            right,
            index,
            fused: false,
            subtract: false,
            rotation: None,
        }),
        (
            Kind::Fused(kind @ (FusedOperation::Add | FusedOperation::Subtract)),
            Inputs::Fused {
                addend,
                left,
                right:
                    Source::Indexed {
                        register: right,
                        index: index @ 0..=7,
                    },
            },
        ) if addend == operand.destination => Some(Operation {
            left,
            right,
            index,
            fused: true,
            subtract: kind == FusedOperation::Subtract,
            rotation: None,
        }),
        (
            Kind::ComplexMultiplyAdd(rotation),
            Inputs::Fused {
                addend,
                left,
                right:
                    Source::Indexed {
                        register: right,
                        index: index @ 0..=3,
                    },
            },
        ) if addend == operand.destination => Some(Operation {
            left,
            right,
            index,
            fused: true,
            subtract: false,
            rotation: Some(rotation),
        }),
        _ => None,
    }
}

fn shuffle(code: &mut Code, opcode: Host, register: u8, order: u8, target: TargetCpu) {
    opcode.register(code, register, register, target);
    code.push(order);
}

/// Materialize the effective eight Half fields once per segment. Real and
/// imaginary selection occurs before any classification or FP conversion.
fn select_sources(code: &mut Code, operation: Operation, target: TargetCpu) {
    let sign = Format::Half.sign_mask() as u32;
    let sign_pair = if let Some(rotation) = operation.rotation {
        let imaginary = matches!(rotation, Rotation::Degrees90 | Rotation::Degrees270);
        let order = if imaginary {
            DUPLICATE_IMAGINARY_WORDS
        } else {
            DUPLICATE_REAL_WORDS
        };
        shuffle(code, Host::ShuffleLowWord, ORIGINAL_LEFT, order, target);
        shuffle(code, Host::ShuffleHighWord, ORIGINAL_LEFT, order, target);
        shuffle(
            code,
            Host::ShuffleDword,
            ORIGINAL_RIGHT,
            operation.index * REPEAT_DWORD_SELECTOR,
            target,
        );
        if imaginary {
            shuffle(
                code,
                Host::ShuffleLowWord,
                ORIGINAL_RIGHT,
                SWAP_WORD_COMPONENTS,
                target,
            );
            shuffle(
                code,
                Host::ShuffleHighWord,
                ORIGINAL_RIGHT,
                SWAP_WORD_COMPONENTS,
                target,
            );
        }
        match rotation {
            Rotation::Degrees0 => 0,
            Rotation::Degrees90 => sign,
            Rotation::Degrees180 => sign | sign << Format::Half.bits(),
            Rotation::Degrees270 => sign << Format::Half.bits(),
        }
    } else {
        if operation.index != FIRST_HALF {
            ShiftOpcode::RightBytes.emit(code, ORIGINAL_RIGHT, operation.index * HALF_BYTES as u8);
        }
        shuffle(
            code,
            Host::ShuffleLowWord,
            ORIGINAL_RIGHT,
            REPEAT_LOW_WORD,
            target,
        );
        shuffle(
            code,
            Host::ShuffleDword,
            ORIGINAL_RIGHT,
            REPEAT_LOW_DWORD,
            target,
        );
        if operation.subtract {
            sign | sign << Format::Half.bits()
        } else {
            0
        }
    };
    if sign_pair != 0 {
        code.push(MOV_EAX_IMMEDIATE);
        code.extend(sign_pair.to_le_bytes());
        Host::MoveGprQword.append(code, target);
        code.push(MODRM_REGISTER | (SIGN_MASK << MODRM_REGISTER_SHIFT) | GPR_RAX);
        shuffle(
            code,
            Host::ShuffleDword,
            SIGN_MASK,
            REPEAT_LOW_DWORD,
            target,
        );
        Host::Xor.register(code, ORIGINAL_RIGHT, SIGN_MASK, target);
    }
}

/// Extract only the effective source field: poisoned unselected components
/// never reach a hardware conversion. The unsigned interval admits exponents
/// 1..30, rejecting zeros, subnormals, infinities and every NaN payload.
fn widen_input(
    code: &mut Code,
    original: u8,
    output: u8,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    code.extend(PEXTRW_EAX_XMM);
    code.push(MODRM_REGISTER | (GPR_RAX << MODRM_REGISTER_SHIFT) | original);
    code.push(FIRST_HALF);
    code.extend(MOV_EDX_EAX);
    code.extend(AND_EDX_IMMEDIATE);
    code.extend((Format::Half.exponent_mask() as u32).to_le_bytes());
    code.extend(SUB_EDX_IMMEDIATE);
    code.extend(FIRST_NORMAL_HALF_EXPONENT.to_le_bytes());
    code.extend(CMP_EDX_IMMEDIATE);
    code.extend((NORMAL_HALF_EXPONENT_COUNT << Format::Half.fraction_bits()).to_le_bytes());
    failures.push(branch(code, Condition::AboveOrEqual));
    half::widen_normal(code, target);
    Host::MoveAligned.register(code, output, RESULT, target);
}

/// Optional selection changes only exact input widening. No feature is assumed
/// from the guest profile; unsupported checked selection declines untouched.
pub(in crate::x86_64) fn emit_candidate(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
    recipe: Recipe,
) -> Result<bool, CompileError> {
    let Some(operation) = admitted(operand) else {
        return Ok(false);
    };
    if matches!(recipe, Recipe::CheckedWidening) && !target.supports(TargetCpu::F16c) {
        return Ok(false);
    }
    let widening_target = if matches!(recipe, Recipe::CheckedWidening) {
        target
    } else {
        TargetCpu::Baseline
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    code.extend(XOR_EAX_EAX);
    numerical::install_mxcsr(code, &frame);
    code.extend(MOVABS_R9_IMMEDIATE);
    code.extend(HALF_TO_DOUBLE_BIAS.to_le_bytes());
    code.extend(XOR_R10D_R10D);
    let mut failures = Vec::new();
    Host::EqualDword.register(code, ASSEMBLED, ASSEMBLED, target);
    guard_active_exception_enables(code, ASSEMBLED, features, &mut failures, target);
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operation.left, chunk, ORIGINAL_LEFT, length, target);
        load_z_chunk(code, operation.right, chunk, ORIGINAL_RIGHT, length, target);
        if operation.fused {
            load_z_chunk(
                code,
                operand.destination,
                chunk,
                ORIGINAL_ADDEND,
                length,
                target,
            );
        }
        Host::Xor.register(code, ASSEMBLED, ASSEMBLED, target);
        select_sources(code, operation, target);
        code.extend(XOR_R11D_R11D);
        let repeat = code.len();

        widen_input(code, ORIGINAL_LEFT, LEFT, &mut failures, widening_target);
        widen_input(code, ORIGINAL_RIGHT, RIGHT, &mut failures, widening_target);
        if operation.fused {
            widen_input(
                code,
                ORIGINAL_ADDEND,
                ADDEND,
                &mut failures,
                widening_target,
            );
        }
        emit_opcode_to(
            code,
            Format::Double,
            Shape::Scalar,
            ArithmeticOpcode::Multiply,
            LEFT,
            RIGHT,
        );
        if operation.fused {
            emit_opcode_to(
                code,
                Format::Double,
                Shape::Scalar,
                ArithmeticOpcode::Add,
                LEFT,
                ADDEND,
            );
        }
        // Half multiplication is exact (at most 22 significant bits). Any
        // double-precision status event rejects the instruction before the
        // single half rounding, so no rounded intermediate or lost exception
        // reaches the packer.
        numerical::capture_status(code, &frame);
        code.extend(TEST_ECX_IMMEDIATE);
        code.extend(MXCSR_STATUS_MASK.to_le_bytes());
        failures.push(branch(code, Condition::NotZero));
        Host::MoveAligned.register(code, RESULT, LEFT, target);
        half::pack_normal(
            code,
            &mut failures,
            RoundingPolicy::Fpcr,
            ResultSign::Preserve,
        );
        ShiftOpcode::RightBytes.emit(code, ASSEMBLED, HALF_BYTES as u8);
        code.extend(PINSRW_XMM_EAX);
        code.push(MODRM_REGISTER | (ASSEMBLED << MODRM_REGISTER_SHIFT) | GPR_RAX);
        code.push(LAST_HALF);
        for input in [ORIGINAL_LEFT, ORIGINAL_RIGHT] {
            ShiftOpcode::RightBytes.emit(code, input, HALF_BYTES as u8);
        }
        if operation.fused {
            ShiftOpcode::RightBytes.emit(code, ORIGINAL_ADDEND, HALF_BYTES as u8);
        }
        code.extend(INC_R11D);
        code.extend(CMP_R11D_IMMEDIATE);
        code.push(HALF_LANES as u8);
        let more = branch(code, Condition::Below);
        resolve(code, more, repeat);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, ASSEMBLED, target);
    }
    if matches!(recipe, Recipe::CheckedWidening) {
        code.extend(VZEROUPPER);
    }
    code.extend(MOV_EAX_R10D);
    numerical::add_fpsr(code, &frame);
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let recipe = selected_recipe(operand, length, target);
    emit_candidate(code, operand, length, features, pc, target, recipe)
}

/// Paired CPU and wall measurements qualify these operation/length choices.
/// FCMLA at SVL16 was slower and FMUL at SVL16 tied; both keep the baseline.
/// Unmeasured lengths and unavailable F16C also retain the integer recipe.
fn selected_recipe(operand: Operand, length: VectorLength, target: TargetCpu) -> Recipe {
    if !target.supports(TargetCpu::F16c) {
        return Recipe::Baseline;
    }
    let qualified = matches!(
        (operand.kind, length.bytes()),
        (
            Kind::Fused(FusedOperation::Add | FusedOperation::Subtract),
            16 | 64
        ) | (
            Kind::Binary(BinaryOperation::Multiply) | Kind::ComplexMultiplyAdd(_),
            64
        )
    );
    if qualified {
        Recipe::CheckedWidening
    } else {
        Recipe::Baseline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::sve::floating::arithmetic;

    const INDEXED_FCMLA_HALF: u32 = 0x64a21020;
    const INDEXED_FMLA_HALF: u32 = 0x64220020;
    const INDEXED_FMLS_HALF: u32 = 0x64220420;
    const INDEXED_FMUL_HALF: u32 = 0x64222020;

    #[test]
    fn measured_selector_keeps_slow_tied_and_unmeasured_choices_on_baseline() {
        for word in [
            INDEXED_FCMLA_HALF,
            INDEXED_FMLA_HALF,
            INDEXED_FMLS_HALF,
            INDEXED_FMUL_HALF,
        ] {
            let operand = arithmetic::decode_numerical(word).unwrap().unwrap();
            for bytes in [16, 32, 64, 128, 256] {
                let length = VectorLength::from_bytes(bytes).unwrap();
                for target in [
                    TargetCpu::Baseline,
                    TargetCpu::Fma,
                    TargetCpu::F16c,
                    TargetCpu::Sse41.with_f16c().with_fma(),
                ] {
                    let checked = target.supports(TargetCpu::F16c)
                        && (bytes == 64
                            || bytes == 16
                                && matches!(word, INDEXED_FMLA_HALF | INDEXED_FMLS_HALF));
                    let recipe = selected_recipe(operand, length, target);
                    assert_eq!(matches!(recipe, Recipe::CheckedWidening), checked);
                    let mut selected = Code::new();
                    let mut explicit = Code::new();
                    let features = NumericalFeatures::new(false, true, true);
                    let pc = GuestAddress(0x123456789abcdef0);
                    assert!(emit(&mut selected, operand, length, features, pc, target).unwrap());
                    assert!(
                        emit_candidate(
                            &mut explicit,
                            operand,
                            length,
                            features,
                            pc,
                            target,
                            if checked {
                                Recipe::CheckedWidening
                            } else {
                                Recipe::Baseline
                            }
                        )
                        .unwrap()
                    );
                    assert_eq!(selected, explicit);
                }
            }
        }
    }
}
