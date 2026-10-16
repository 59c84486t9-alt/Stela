//! FCADD and FCMLA.
use alloc::vec::Vec;
mod half;

use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, FusedOpcode, VZEROUPPER, branch, commit_inexact, emit_fma,
    emit_opcode, environment, prepare_vector_input_range, prepare_vector_result_range,
    read_numerical_vector, reject_other_status, reject_product_status, resolve,
    restore_environment, restore_environment_with_product, save_product_status, test_control,
    vector_exponent_range,
};
use super::{Host, commit, packed, read_vector, shuffle};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            FPCR_EXCEPTION_ENABLE_MASK, Format,
            complex::{IMAGINARY, Rotation},
        },
        simd::{
            arithmetic::Shape,
            complex::{Kind, Operand, Source},
        },
    },
    block::ExitKind,
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const SIGN_MASK: u8 = 2;
const ADDEND: u8 = 6;
const FIRST_PAIR: u8 = 0;
const SIGN_BITS: u32 = 1;
const DUPLICATE_REAL: u8 = 0xa0; // Components [0, 0, 2, 2].
const DUPLICATE_IMAGINARY: u8 = 0xf5; // Components [1, 1, 3, 3].
const SWAP_ADJACENT_COMPONENTS: u8 = 0xb1; // Components [1, 0, 3, 2].
const SWAP_DOUBLE_COMPONENTS: u8 = 0x4e; // Dwords [2, 3, 0, 1].
const BROADCAST_LOW_SINGLE_PAIR: u8 = 0x44; // Dwords [0, 1, 0, 1].
const BROADCAST_HIGH_SINGLE_PAIR: u8 = 0xee; // Dwords [2, 3, 2, 3].
const BROADCAST_HALF_PAIR_STRIDE: u8 = 0x55; // Repeat one selected dword in all positions.

fn half_shuffle(code: &mut Vec<u8>, shape: Shape, vector: u8, control: u8) {
    packed(code, Host::ShuffleLowWord, vector, vector);
    code.push(control);
    if shape == Shape::Vector128 {
        packed(code, Host::ShuffleHighWord, vector, vector);
        code.push(control);
    }
}

fn duplicate_left_component(code: &mut Vec<u8>, operand: &Operand) {
    let imaginary = operand.rotation.left_component() == IMAGINARY;
    let control = if imaginary {
        DUPLICATE_IMAGINARY
    } else {
        DUPLICATE_REAL
    };
    match operand.format {
        Format::Half => half_shuffle(code, operand.shape, LEFT, control),
        Format::Single => shuffle(code, LEFT, LEFT, control),
        Format::Double => packed(
            code,
            if imaginary {
                Host::UnpackHighQword
            } else {
                Host::UnpackLowQword
            },
            LEFT,
            LEFT,
        ),
    }
}

fn prepare_right(code: &mut Vec<u8>, operand: &Operand) {
    match operand.right {
        Source::Vector(source) => {
            read_numerical_vector(code, operand.shape, source, RIGHT);
        }
        Source::Indexed { register, index } => {
            // Select the whole complex pair before classification; the other
            // indexed components are unused.
            read_vector(code, register, RIGHT);
            match operand.format {
                Format::Half => {
                    shuffle(code, RIGHT, RIGHT, index * BROADCAST_HALF_PAIR_STRIDE);
                }
                Format::Single => shuffle(
                    code,
                    RIGHT,
                    RIGHT,
                    if index == FIRST_PAIR {
                        BROADCAST_LOW_SINGLE_PAIR
                    } else {
                        BROADCAST_HIGH_SINGLE_PAIR
                    },
                ),
                Format::Double => unreachable!("indexed complex Double is unallocated"),
            }
        }
    }
    if matches!(operand.rotation, Rotation::Degrees90 | Rotation::Degrees270) {
        match operand.format {
            Format::Half => {
                half_shuffle(code, operand.shape, RIGHT, SWAP_ADJACENT_COMPONENTS);
            }
            Format::Single => shuffle(code, RIGHT, RIGHT, SWAP_ADJACENT_COMPONENTS),
            Format::Double => shuffle(code, RIGHT, RIGHT, SWAP_DOUBLE_COMPONENTS),
        }
    }
}

fn prepare_sources(code: &mut Vec<u8>, operand: &Operand) {
    read_numerical_vector(code, operand.shape, operand.left, LEFT);
    if operand.kind == Kind::MultiplyAdd {
        // Unselected N real/imaginary components, including signaling NaNs,
        // disappear before the active-input guards or any host FP operation.
        duplicate_left_component(code, operand);
    }
    prepare_right(code, operand);
}

/// Toggle only the architectural rotated M signs after normal-input guards.
/// XMM2 is scratch; staged XMM0/1 and the accumulator retain their source roles.
pub(super) fn rotate_right_sign(code: &mut Vec<u8>, format: Format, rotation: Rotation) {
    if rotation == Rotation::Degrees0 {
        return;
    }
    packed(code, Host::EqualDword, SIGN_MASK, SIGN_MASK);
    let lane_shift = match format {
        Format::Half => ShiftOpcode::LeftWord,
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
    };
    lane_shift.emit(code, SIGN_MASK, (format.bits() - SIGN_BITS) as u8);
    let real_only = rotation == Rotation::Degrees90;
    if rotation != Rotation::Degrees180 {
        let component_shift = match (format, real_only) {
            (Format::Half, true) => ShiftOpcode::RightDword,
            (Format::Half, false) => ShiftOpcode::LeftDword,
            (Format::Single, true) => ShiftOpcode::RightQword,
            (Format::Single, false) => ShiftOpcode::LeftQword,
            (Format::Double, true) => ShiftOpcode::RightBytes,
            (Format::Double, false) => ShiftOpcode::LeftBytes,
        };
        let amount = if format == Format::Double {
            format.bits() / u8::BITS
        } else {
            format.bits()
        };
        component_shift.emit(code, SIGN_MASK, amount as u8);
    }
    packed(code, Host::Xor, RIGHT, SIGN_MASK);
}

fn input_guard(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    prepare_vector_input_range(code, operand.format);
    vector_exponent_range(code, operand.format, operand.shape, LEFT);
    helper.push(branch(code, Condition::NotZero));
    vector_exponent_range(code, operand.format, operand.shape, RIGHT);
    if operand.kind == Kind::MultiplyAdd {
        helper.push(branch(code, Condition::NotZero));
        vector_exponent_range(code, operand.format, operand.shape, ADDEND);
    }
}

fn arithmetic(code: &mut Vec<u8>, operand: &Operand, native_fma: bool, target: TargetCpu) {
    let negative_product = native_fma && operand.rotation == Rotation::Degrees180;
    if !negative_product {
        rotate_right_sign(code, operand.format, operand.rotation);
    }
    environment(code);
    if native_fma {
        // Normal finite inputs make -(N*M)+A exactly equivalent to applying
        // FPNeg to M first. NaNs already took the unchanged architectural core.
        emit_fma(
            code,
            operand.format,
            operand.shape,
            if negative_product {
                FusedOpcode::NegativeMultiplyAdd
            } else {
                FusedOpcode::MultiplyAdd
            },
            target,
        );
        restore_environment(code);
    } else if operand.kind == Kind::MultiplyAdd {
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Multiply,
            RIGHT,
        );
        save_product_status(code);
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Add,
            ADDEND,
        );
        restore_environment_with_product(code);
    } else {
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Add,
            RIGHT,
        );
        restore_environment(code);
    }
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let native_fma = operand.format != Format::Half
        && operand.kind == Kind::MultiplyAdd
        && target.supports(TargetCpu::Fma);
    let native_f16c = operand.format == Format::Half && target.supports(TargetCpu::F16c);
    if native_fma || native_f16c {
        code.extend(VZEROUPPER);
    }
    prepare_sources(code, operand);
    if operand.format == Format::Half {
        // The half-precision path handles its own controls, guards, Vd
        // snapshot, rotation and commit.
        half::emit(code, operand, pc, target);
        return;
    }
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    if operand.kind == Kind::MultiplyAdd {
        read_numerical_vector(code, operand.shape, operand.destination, ADDEND);
    }
    input_guard(code, operand, &mut helper);
    // The last classifier's success skips a shared cold helper. Late failures
    // branch back only after restoring the complete caller environment/RSP.
    let accepted = branch(code, Condition::Zero);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let accepted_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, accepted, accepted_start);
    arithmetic(code, operand, native_fma, target);
    if operand.kind == Kind::MultiplyAdd && !native_fma {
        // Split arithmetic is fused only when its intermediate product is
        // exact and nonexceptional. Product overflow/underflow never succeeds.
        let product_failed = reject_product_status(code);
        resolve(code, product_failed, helper_start);
    }
    let status_failed = reject_other_status(code);
    resolve(code, status_failed, helper_start);
    // Tiny, zero and special outputs remain in the complete core, including
    // before/after-rounding tininess and AH-dependent flush/status behavior.
    prepare_vector_result_range(code);
    vector_exponent_range(code, operand.format, operand.shape, LEFT);
    let result_failed = branch(code, Condition::NotZero);
    resolve(code, result_failed, helper_start);
    commit_inexact(code);
    if operand.shape == Shape::Vector64 {
        packed(code, Host::MoveQword, LEFT, LEFT);
    }
    commit(code, operand.destination, LEFT);
}
