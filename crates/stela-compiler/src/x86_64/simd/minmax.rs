//! FP min/max: normal-or-zero S/D selection and normal H integer ordering.
use super::super::isa::ShiftOpcode;
use super::numerical::helper_section;
use super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, MOVQ_XMM0_XMM0, branch, clear_scalar, exponent_range, jump,
    prepare_vector_input_range, read_numerical_vector, resolve, test_control,
    vector_exponent_range, vector_normal_or_zero_range, zero_scalar,
};
use super::{Host, commit, packed, read_vector};
use crate::x86_64::asm::Code;
use crate::{
    GuestAddress,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, minmax::MinMaxOperation,
        },
        simd::{
            arithmetic::Shape,
            minmax::{BinaryMode, Operand},
        },
    },
};
use alloc::vec::Vec;

const RESULT_VECTOR: u8 = 0;
const RIGHT_VECTOR: u8 = 1;
const SIGN_VECTOR: u8 = 2;
const PAIR_VECTOR: u8 = 6;
const ORIGINAL_LEFT_VECTOR: u8 = 7;
// XMM3's input validity is dead after the guards. The right operand is consumed
// by selection; XMM6 may itself be that operand after pairwise staging.
const SELECTION_SCRATCH: u8 = 3;
const HALF_SIGN_SHIFT: u8 = u16::BITS as u8 - 1;
const SIGN_MASK_TO_MAGNITUDE_SHIFT: u8 = 1;
const BITS_PER_BYTE: u32 = u8::BITS;
const REGISTER_DIRECT: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const SSE_ESCAPE: u8 = 0x0f;
const SINGLE_SCALAR_PREFIX: u8 = 0xf3;
const DOUBLE_SCALAR_PREFIX: u8 = 0xf2;
const DOUBLE_PACKED_PREFIX: u8 = 0x66;
const SHUFFLE_SINGLE: u8 = 0xc6;
const UNPACK_LOW_SINGLE: u8 = 0x14;
const MOVE_HIGH_TO_LOW_SINGLE: u8 = 0x12;
const UNPACK_LOW_DOUBLE: u8 = 0x14;
const UNPACK_HIGH_DOUBLE: u8 = 0x15;
const EVEN_DWORDS: u8 = 0x88;
const ODD_DWORDS: u8 = 0xdd;
const SWAP_ADJACENT_WORDS: u8 = 0xb1;
const EVEN_WORDS: u8 = 0x88;
const TWO_HALF_BYTES: u8 = 2 * (u16::BITS / BITS_PER_BYTE) as u8;
const FOUR_HALF_BYTES: u8 = 4 * (u16::BITS / BITS_PER_BYTE) as u8;
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const PINSRW_XMM7_EAX_LOW: &[u8] = &[0x66, 0x0f, 0xc4, 0xf8, 0];

#[repr(u8)]
enum SelectionOpcode {
    Minimum = 0x5d,
    Maximum = 0x5f,
}

fn is_minimum(operation: MinMaxOperation) -> bool {
    matches!(
        operation,
        MinMaxOperation::Minimum | MinMaxOperation::MinimumNumber
    )
}

fn raw_selection(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    destination: u8,
    right: u8,
) {
    if format == Format::Half {
        packed(
            code,
            if is_minimum(operation) {
                Host::MinSignedWord
            } else {
                Host::MaxSignedWord
            },
            destination,
            right,
        );
        return;
    }
    match (format, shape) {
        (Format::Single, Shape::Scalar) => code.push(SINGLE_SCALAR_PREFIX),
        (Format::Double, Shape::Scalar) => code.push(DOUBLE_SCALAR_PREFIX),
        (Format::Double, _) => code.push(DOUBLE_PACKED_PREFIX),
        (Format::Single, _) => (),
        (Format::Half, _) => unreachable!("half selection is integer-only"),
    }
    let opcode = if is_minimum(operation) {
        SelectionOpcode::Minimum
    } else {
        SelectionOpcode::Maximum
    };
    code.extend([
        SSE_ESCAPE,
        opcode as u8,
        REGISTER_DIRECT | (destination << REGISTER_SHIFT) | right,
    ]);
}

/// Legacy SSE selects operand2 on a zero tie. Symmetric selection followed by
/// sign AND (maximum) or OR (minimum) gives Arm's standard zero sign. Plain
/// AH=1 retains operand2 instead. No inactive scalar lane undergoes FP work.
fn selection(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    destination: u8,
    right: u8,
) {
    if format == Format::Half {
        raw_selection(code, operation, format, shape, destination, right);
        return;
    }
    debug_assert!(destination != right);
    debug_assert!(destination != SELECTION_SCRATCH && right != SELECTION_SCRATCH);
    let alternative = if matches!(
        operation,
        MinMaxOperation::Minimum | MinMaxOperation::Maximum
    ) {
        test_control(code, FPCR_AH);
        Some(branch(code, Condition::NotZero))
    } else {
        None
    };
    let combine = if is_minimum(operation) {
        Host::Or
    } else {
        Host::And
    };
    if shape == Shape::Scalar {
        packed(code, Host::MoveAligned, SELECTION_SCRATCH, destination);
        raw_selection(code, operation, format, shape, SELECTION_SCRATCH, right);
        raw_selection(code, operation, format, shape, right, destination);
        packed(code, combine, SELECTION_SCRATCH, right);
        packed(
            code,
            if format == Format::Double {
                Host::MoveScalarDouble
            } else {
                Host::MoveScalarSingle
            },
            destination,
            SELECTION_SCRATCH,
        );
    } else {
        packed(code, Host::MoveAligned, SELECTION_SCRATCH, right);
        raw_selection(code, operation, format, shape, right, destination);
        raw_selection(
            code,
            operation,
            format,
            shape,
            destination,
            SELECTION_SCRATCH,
        );
        packed(code, combine, destination, right);
    }
    if let Some(alternative) = alternative {
        let done = jump(code);
        let alternative_start = code.len();
        resolve(code, alternative, alternative_start);
        raw_selection(code, operation, format, shape, destination, right);
        let end = code.len();
        resolve(code, done, end);
    }
}

/// Normal half-precision values map to a signed-word order key, and the same
/// transform restores the bit pattern after integer min/max.
fn half_order(code: &mut Code, vector: u8) {
    packed(code, Host::MoveAligned, SIGN_VECTOR, vector);
    ShiftOpcode::ArithmeticWord.emit(code, SIGN_VECTOR, HALF_SIGN_SHIFT);
    ShiftOpcode::RightWord.emit(code, SIGN_VECTOR, SIGN_MASK_TO_MAGNITUDE_SHIFT);
    packed(code, Host::Xor, vector, SIGN_VECTOR);
}

fn exception_guard(code: &mut Code, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
}

fn input_guard(code: &mut Code, format: Format, shape: Shape, source: u8, helper: &mut Vec<usize>) {
    if shape == Shape::Scalar {
        let zero = if format != Format::Half {
            zero_scalar(code, format, source);
            Some(branch(code, Condition::Zero))
        } else {
            None
        };
        exponent_range(code, format, source, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
        if let Some(zero) = zero {
            let end = code.len();
            resolve(code, zero, end);
        }
    } else {
        if format == Format::Half {
            vector_exponent_range(code, format, shape, source);
        } else {
            vector_normal_or_zero_range(code, format, shape, source, PAIR_VECTOR);
        }
        helper.push(branch(code, Condition::NotZero));
    }
}

fn shuffle(code: &mut Code, opcode: Host, destination: u8, source: u8, control: u8) {
    packed(code, opcode, destination, source);
    code.push(control);
}

fn shuffle_single(code: &mut Code, destination: u8, right: u8, control: u8) {
    code.extend([
        SSE_ESCAPE,
        SHUFFLE_SINGLE,
        REGISTER_DIRECT | (destination << REGISTER_SHIFT) | right,
        control,
    ]);
}

fn unpack_double(code: &mut Code, destination: u8, right: u8, high: bool) {
    code.extend([
        DOUBLE_PACKED_PREFIX,
        SSE_ESCAPE,
        if high {
            UNPACK_HIGH_DOUBLE
        } else {
            UNPACK_LOW_DOUBLE
        },
        REGISTER_DIRECT | (destination << REGISTER_SHIFT) | right,
    ]);
}

/// Pairwise results fill both words of each pair. Only integer operations run,
/// so inactive or duplicated lanes have no effect.
fn half_pairs(code: &mut Code, operation: MinMaxOperation, source: u8) {
    shuffle(
        code,
        Host::ShuffleLowWord,
        PAIR_VECTOR,
        source,
        SWAP_ADJACENT_WORDS,
    );
    shuffle(
        code,
        Host::ShuffleHighWord,
        PAIR_VECTOR,
        PAIR_VECTOR,
        SWAP_ADJACENT_WORDS,
    );
    selection(
        code,
        operation,
        Format::Half,
        Shape::Vector128,
        source,
        PAIR_VECTOR,
    );
}

fn compact_half_pairs(code: &mut Code, shape: Shape, source: u8) {
    shuffle(code, Host::ShuffleLowWord, source, source, EVEN_WORDS);
    if shape == Shape::Vector128 {
        shuffle(code, Host::ShuffleHighWord, source, source, EVEN_WORDS);
        shuffle(code, Host::ShuffleDword, source, source, EVEN_DWORDS);
    }
}

fn vector_pairs(code: &mut Code, operation: MinMaxOperation, format: Format, shape: Shape) {
    match format {
        Format::Half => {
            for source in [RESULT_VECTOR, RIGHT_VECTOR] {
                half_pairs(code, operation, source);
                compact_half_pairs(code, shape, source);
            }
            packed(
                code,
                if shape == Shape::Vector64 {
                    Host::UnpackLowDword
                } else {
                    Host::UnpackLowQword
                },
                RESULT_VECTOR,
                RIGHT_VECTOR,
            );
        }
        Format::Single if shape == Shape::Vector64 => {
            // Q0 loads zero both upper qwords. Gather [n0,m0,n1,m1], then
            // compare against [n1,m1,0,0]; only the low two results survive.
            code.extend([
                SSE_ESCAPE,
                UNPACK_LOW_SINGLE,
                REGISTER_DIRECT | (RESULT_VECTOR << REGISTER_SHIFT) | RIGHT_VECTOR,
            ]);
            code.extend([
                SSE_ESCAPE,
                MOVE_HIGH_TO_LOW_SINGLE,
                REGISTER_DIRECT | (RIGHT_VECTOR << REGISTER_SHIFT) | RESULT_VECTOR,
            ]);
            selection(code, operation, format, shape, RESULT_VECTOR, RIGHT_VECTOR);
        }
        Format::Single => {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            shuffle_single(code, RESULT_VECTOR, RIGHT_VECTOR, EVEN_DWORDS);
            shuffle_single(code, PAIR_VECTOR, RIGHT_VECTOR, ODD_DWORDS);
            selection(code, operation, format, shape, RESULT_VECTOR, PAIR_VECTOR);
        }
        Format::Double => {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            unpack_double(code, RESULT_VECTOR, RIGHT_VECTOR, false);
            unpack_double(code, PAIR_VECTOR, RIGHT_VECTOR, true);
            selection(code, operation, format, shape, RESULT_VECTOR, PAIR_VECTOR);
        }
    }
}

fn finish_binary(code: &mut Code, format: Format, shape: Shape, destination: u8) {
    if shape == Shape::Scalar {
        test_control(code, FPCR_NEP);
        let merge = branch(code, Condition::NotZero);
        if format == Format::Half {
            packed(code, Host::Xor, ORIGINAL_LEFT_VECTOR, ORIGINAL_LEFT_VECTOR);
        } else {
            clear_scalar(code, format, RESULT_VECTOR);
        }
        let merge_target = code.len();
        resolve(code, merge, merge_target);
        if format == Format::Half {
            code.extend(MOVD_EAX_XMM0);
            code.extend(PINSRW_XMM7_EAX_LOW);
            packed(code, Host::MoveAligned, RESULT_VECTOR, ORIGINAL_LEFT_VECTOR);
        }
    } else if shape == Shape::Vector64 {
        code.extend(MOVQ_XMM0_XMM0);
    }
    commit(code, destination, RESULT_VECTOR);
}

fn binary(code: &mut Code, operand: &Operand, pc: GuestAddress) {
    let Operand::Binary {
        operation,
        format,
        shape,
        mode,
        destination,
        left,
        right,
    } = *operand
    else {
        unreachable!("binary min/max operand")
    };
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, shape, left, RESULT_VECTOR);
    read_numerical_vector(code, shape, right, RIGHT_VECTOR);
    if shape != Shape::Scalar {
        prepare_vector_input_range(code, format);
    }
    input_guard(code, format, shape, RESULT_VECTOR, &mut helper);
    input_guard(code, format, shape, RIGHT_VECTOR, &mut helper);
    helper_section(code, &helper, pc);
    if format == Format::Half {
        if shape == Shape::Scalar {
            packed(code, Host::MoveAligned, ORIGINAL_LEFT_VECTOR, RESULT_VECTOR);
        }
        half_order(code, RESULT_VECTOR);
        half_order(code, RIGHT_VECTOR);
    }
    if mode == BinaryMode::Pairwise {
        vector_pairs(code, operation, format, shape);
    } else {
        selection(code, operation, format, shape, RESULT_VECTOR, RIGHT_VECTOR);
    }
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
    }
    finish_binary(code, format, shape, destination);
}

fn pairwise_scalar(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    destination: u8,
    source: u8,
    pc: GuestAddress,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, source, RESULT_VECTOR);
    packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
    ShiftOpcode::RightBytes.emit(code, RIGHT_VECTOR, (format.bits() / BITS_PER_BYTE) as u8);
    input_guard(code, format, Shape::Scalar, RESULT_VECTOR, &mut helper);
    input_guard(code, format, Shape::Scalar, RIGHT_VECTOR, &mut helper);
    helper_section(code, &helper, pc);
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
        half_order(code, RIGHT_VECTOR);
    }
    selection(
        code,
        operation,
        format,
        Shape::Scalar,
        RESULT_VECTOR,
        RIGHT_VECTOR,
    );
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
    }
    clear_scalar(code, format, RESULT_VECTOR);
    commit(code, destination, RESULT_VECTOR);
}

fn reduction(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    destination: u8,
    source: u8,
    pc: GuestAddress,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, shape, source, RESULT_VECTOR);
    prepare_vector_input_range(code, format);
    input_guard(code, format, shape, RESULT_VECTOR, &mut helper);
    helper_section(code, &helper, pc);
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
        half_pairs(code, operation, RESULT_VECTOR);
        // Balanced low/high subtrees match FPReduce: (0,1) with (2,3),
        // and for8H (4,5) with (6,7), followed by the two half results.
        let shifts: &[u8] = if shape == Shape::Vector64 {
            &[TWO_HALF_BYTES]
        } else {
            &[TWO_HALF_BYTES, FOUR_HALF_BYTES]
        };
        for &amount in shifts {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            ShiftOpcode::RightBytes.emit(code, PAIR_VECTOR, amount);
            selection(code, operation, format, shape, RESULT_VECTOR, PAIR_VECTOR);
        }
        half_order(code, RESULT_VECTOR);
    } else {
        debug_assert_eq!(format, Format::Single);
        packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
        shuffle(
            code,
            Host::ShuffleDword,
            RESULT_VECTOR,
            RESULT_VECTOR,
            EVEN_DWORDS,
        );
        shuffle(
            code,
            Host::ShuffleDword,
            RIGHT_VECTOR,
            RIGHT_VECTOR,
            ODD_DWORDS,
        );
        selection(code, operation, format, shape, RESULT_VECTOR, RIGHT_VECTOR);
        packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
        ShiftOpcode::RightBytes.emit(code, RIGHT_VECTOR, (format.bits() / BITS_PER_BYTE) as u8);
        selection(
            code,
            operation,
            format,
            Shape::Scalar,
            RESULT_VECTOR,
            RIGHT_VECTOR,
        );
    }
    clear_scalar(code, format, RESULT_VECTOR);
    commit(code, destination, RESULT_VECTOR);
}

pub(in crate::x86_64) fn emit(code: &mut Code, operand: &Operand, pc: GuestAddress) {
    match *operand {
        Operand::Binary { .. } => binary(code, operand, pc),
        Operand::PairwiseScalar {
            operation,
            format,
            destination,
            source,
        } => {
            pairwise_scalar(code, operation, format, destination, source, pc);
        }
        Operand::Reduction {
            operation,
            format,
            shape,
            destination,
            source,
        } => {
            reduction(code, operation, format, shape, destination, source, pc);
        }
    }
}
