//! FP min/max: ordered (normal, infinite, S/D zero) selection and Half integer ordering.
use super::super::isa::ShiftOpcode;
use super::encode::guest;
use super::numerical::helper_section;
use super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, branch, clear_high_qword, clear_scalar, exponent_range,
    infinity_scalar, jump, prepare_vector_input_range, read_numerical_vector, resolve,
    test_control, vector_ordered_range, zero_scalar,
};
use super::{Host, commit, packed, packed_imm, read_vector};
use crate::x86_64::asm::{Alu, Code, Gpr, Rm, Size, vector_extensions};
use crate::x86_64::asm::{FloatLanes, FloatOp};
use crate::{
    GuestAddress, TargetCpu,
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
const EVEN_DWORDS: u8 = 0x88;
const ODD_DWORDS: u8 = 0xdd;
const SWAP_ADJACENT_WORDS: u8 = 0xb1;
const EVEN_WORDS: u8 = 0x88;
const TWO_HALF_BYTES: u8 = 2 * (u16::BITS / BITS_PER_BYTE) as u8;
const FOUR_HALF_BYTES: u8 = 4 * (u16::BITS / BITS_PER_BYTE) as u8;

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
    let lanes = match (format, shape) {
        (Format::Single, Shape::Scalar) => FloatLanes::ScalarSingle,
        (Format::Double, Shape::Scalar) => FloatLanes::ScalarDouble,
        (Format::Double, _) => FloatLanes::PackedDouble,
        (Format::Single, _) => FloatLanes::PackedSingle,
        (Format::Half, _) => unreachable!("half selection is integer-only"),
    };
    let op = if is_minimum(operation) {
        FloatOp::Min
    } else {
        FloatOp::Max
    };
    code.asm().float(op, lanes, destination, Rm::Xmm(right));
}

/// Legacy SSE selects operand2 on a zero tie. Symmetric selection followed by
/// sign AND (maximum) or OR (minimum) gives Arm's standard zero sign, as
/// AVX10.2's VMINMAX does alone. Plain AH=1 keeps operand2 instead. No inactive
/// scalar lane undergoes FP work.
fn selection(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    destination: u8,
    right: u8,
    target: TargetCpu,
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
    if vector_extensions::extrema_supported(target) {
        vector_extensions::extrema(
            code,
            format,
            shape == Shape::Scalar,
            !is_minimum(operation),
            destination,
            right,
        );
    } else if shape == Shape::Scalar {
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

/// Infinities are ordinary ordered values for every selection here (and in
/// Half's order key), so only NaNs, subnormals and Half zeros exit.
fn input_guard(code: &mut Code, format: Format, shape: Shape, source: u8, helper: &mut Vec<usize>) {
    if shape == Shape::Scalar {
        let mut accepted = Vec::new();
        if format != Format::Half {
            zero_scalar(code, format, source);
            accepted.push(branch(code, Condition::Zero));
        }
        infinity_scalar(code, format, source);
        accepted.push(branch(code, Condition::Zero));
        exponent_range(code, format, source, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
        let end = code.len();
        for patch in accepted {
            resolve(code, patch, end);
        }
    } else {
        vector_ordered_range(code, format, shape, source, PAIR_VECTOR);
        helper.push(branch(code, Condition::NotZero));
    }
}

/// Whether [`quick_guard`] runs on `target`: PTEST (SSE4.1). The DIT
/// profile keeps its reviewed classification.
fn quick_guard_supported(target: TargetCpu) -> bool {
    super::three::test_zero_supported(target) && !target.data_independent_timing()
}

/// With AH clear the selection is exact for every ordered pair (subnormals
/// and infinities included, without status) once FZ or FIZ has flushed
/// subnormal inputs to their signed zeros (FZ raising IDC, FIZ nothing):
/// only a NaN in either operand needs the full Arm rules. One unordered
/// compare (UCOMIS for a scalar, CMPUNORD and PTEST over both whole
/// registers for a vector, whose 8-byte form has its high qword clear)
/// sends it to the helper. Returns the branch past the full classification
/// that follows, which handles AH set (AH=1 reports IDC for a subnormal).
fn quick_guard(
    code: &mut Code,
    shape: Shape,
    format: Format,
    helper: &mut Vec<usize>,
    target: TargetCpu,
) -> usize {
    use crate::aarch64::floating::{FPCR_FIZ, FPCR_FZ};
    const UNORDERED: u8 = 3;
    test_control(code, FPCR_AH);
    let flushing = branch(code, Condition::NotZero);
    let double = format == Format::Double;
    if shape == Shape::Scalar {
        let mut asm = code.asm();
        if double {
            asm.ucomisd(RESULT_VECTOR, Rm::Xmm(RIGHT_VECTOR));
        } else {
            asm.ucomiss(RESULT_VECTOR, Rm::Xmm(RIGHT_VECTOR));
        }
        helper.push(branch(code, Condition::Parity));
    } else {
        let lanes = if double {
            FloatLanes::PackedDouble
        } else {
            FloatLanes::PackedSingle
        };
        packed(code, Host::MoveAligned, SELECTION_SCRATCH, RESULT_VECTOR);
        code.asm()
            .float_compare(lanes, SELECTION_SCRATCH, Rm::Xmm(RIGHT_VECTOR), UNORDERED);
        super::three::test_zero(code, SELECTION_SCRATCH, target);
        helper.push(branch(code, Condition::NotZero));
    }
    // After the NaN check, which leaves for the helper with the state
    // untouched: FZ or FIZ flush a subnormal input to its signed zero, FZ
    // with IDC.
    test_control(code, FPCR_FZ | FPCR_FIZ);
    let plain = branch(code, Condition::Zero);
    for source in [RESULT_VECTOR, RIGHT_VECTOR] {
        flush_subnormal_lanes(code, format, shape, source);
    }
    let plain_start = code.len();
    resolve(code, plain, plain_start);
    let unflushed = jump(code);
    let end = code.len();
    resolve(code, flushing, end);
    unflushed
}

/// Replace each active subnormal S/D lane of `source` by its signed zero,
/// adding IDC to FPSR where FPCR.FZ is set (with AH clear). A scalar's
/// other lanes stay. Clobbers XMM2-5 and EAX.
fn flush_subnormal_lanes(code: &mut Code, format: Format, shape: Shape, source: u8) {
    use crate::aarch64::floating::{FPCR_FZ, INPUT_DENORMAL};
    const MAGNITUDE: u8 = SELECTION_SCRATCH;
    const SUBNORMAL: u8 = SIGN_VECTOR;
    const CONSTANT: u8 = 4;
    const ZERO: u8 = 5;
    let double = format == Format::Double;
    let constant = |code: &mut Code, xmm: u8, bits: u64| {
        if double {
            code.asm().mov_imm64(Gpr::Rax, bits);
            packed(code, Host::MoveGprQword, xmm, 0);
            packed(code, Host::UnpackLowQword, xmm, xmm);
        } else {
            let mut asm = code.asm();
            asm.mov_imm32(Gpr::Rax, bits as u32);
            asm.movd_to_xmm(xmm, Gpr::Rax);
            packed_imm(code, Host::ShuffleDword, xmm, xmm, 0);
        }
    };
    constant(code, CONSTANT, format.sign_mask() - 1);
    packed(code, Host::MoveAligned, MAGNITUDE, source);
    packed(code, Host::And, MAGNITUDE, CONSTANT);
    // Integer compares only, so that no lane (a scalar's poisoned upper
    // lanes included) raises host status: a zero exponent field and a
    // nonzero magnitude, each Double judged by its high dword's exponent
    // and both its dwords.
    constant(code, CONSTANT, format.exponent_mask());
    packed(code, Host::MoveAligned, SUBNORMAL, MAGNITUDE);
    packed(code, Host::And, SUBNORMAL, CONSTANT);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, SUBNORMAL, ZERO);
    packed(code, Host::EqualDword, MAGNITUDE, ZERO);
    if double {
        const HIGH_DWORDS: u8 = 0xf5;
        const SWAP_DWORDS: u8 = 0xb1;
        packed_imm(code, Host::ShuffleDword, SUBNORMAL, SUBNORMAL, HIGH_DWORDS);
        packed_imm(code, Host::ShuffleDword, CONSTANT, MAGNITUDE, SWAP_DWORDS);
        packed(code, Host::And, MAGNITUDE, CONSTANT);
    }
    packed(code, Host::AndNot, MAGNITUDE, SUBNORMAL);
    packed(code, Host::MoveAligned, SUBNORMAL, MAGNITUDE);
    if shape == Shape::Scalar {
        // Only the low element is an input.
        let spare = 16 - format.bits() as u8 / 8;
        ShiftOpcode::LeftBytes.emit(code, SUBNORMAL, spare);
        ShiftOpcode::RightBytes.emit(code, SUBNORMAL, spare);
    }
    // Keep the sign alone where subnormal.
    constant(code, CONSTANT, format.sign_mask() - 1);
    packed(code, Host::And, CONSTANT, SUBNORMAL);
    packed(code, Host::AndNot, CONSTANT, source);
    packed(code, Host::MoveAligned, source, CONSTANT);
    Host::ByteSignMask.register(code, 0, SUBNORMAL, TargetCpu::Baseline);
    code.asm().test(Size::Dword, Gpr::Rax, Gpr::Rax);
    let none = branch(code, Condition::Zero);
    test_control(code, FPCR_FZ);
    let quiet = branch(code, Condition::Zero);
    code.asm().alu_imm32(
        Alu::Or,
        Size::Dword,
        guest(core::mem::offset_of!(crate::GuestState, fpsr) as u32),
        INPUT_DENORMAL as i32,
    );
    let end = code.len();
    resolve(code, none, end);
    resolve(code, quiet, end);
}

/// Whether [`half_quick_guard`] runs on `target`; the DIT profile keeps its
/// reviewed classification.
fn half_quick_guard_supported(target: TargetCpu) -> bool {
    !target.data_independent_timing()
}

/// With AH clear every non-NaN Half (zeros, subnormals, infinities) is
/// ordered by the signed-word key ([`half_order`]), whose order gives Arm's
/// zero signs, and Half inputs raise no IDC: only a NaN needs the full
/// rules. FZ16 flushes subnormal inputs to their signed zeros first.
/// Returns the branch past the full classification, which handles AH.
fn half_quick_guard(code: &mut Code, shape: Shape, helper: &mut Vec<usize>) -> usize {
    use crate::aarch64::floating::FPCR_FZ16;
    const MAGNITUDE: u8 = SELECTION_SCRATCH;
    const CONSTANT: u8 = 4;
    const MASK: u8 = 5;
    test_control(code, FPCR_AH);
    let alternative = branch(code, Condition::NotZero);
    let active = match shape {
        Shape::Scalar => 0x3,
        Shape::Vector64 => 0xff,
        Shape::Vector128 => 0xffff,
    };
    let word_constant = |code: &mut Code, xmm: u8, bits: u16| {
        let mut asm = code.asm();
        asm.mov_imm32(Gpr::Rax, u32::from(bits) * 0x1_0001);
        asm.movd_to_xmm(xmm, Gpr::Rax);
        packed_imm(code, Host::ShuffleDword, xmm, xmm, 0);
    };
    let flush = |code: &mut Code, source: u8| {
        // Subnormal: 0 < magnitude < 0x400.
        word_constant(code, CONSTANT, 0x7fff);
        packed(code, Host::MoveAligned, MAGNITUDE, source);
        packed(code, Host::And, MAGNITUDE, CONSTANT);
        packed(code, Host::MoveAligned, SIGN_VECTOR, MAGNITUDE);
        packed(code, Host::Xor, MASK, MASK);
        packed(code, Host::GreaterWord, MAGNITUDE, MASK);
        word_constant(code, MASK, 0x0400);
        packed(code, Host::GreaterWord, MASK, SIGN_VECTOR);
        packed(code, Host::And, MASK, MAGNITUDE);
        if shape == Shape::Scalar {
            ShiftOpcode::LeftBytes.emit(code, MASK, 14);
            ShiftOpcode::RightBytes.emit(code, MASK, 14);
        }
        packed(code, Host::And, MASK, CONSTANT);
        packed(code, Host::AndNot, MASK, source);
        packed(code, Host::MoveAligned, source, MASK);
    };
    for source in [RESULT_VECTOR, RIGHT_VECTOR] {
        // NaN: magnitude above infinity's.
        word_constant(code, CONSTANT, 0x7fff);
        packed(code, Host::MoveAligned, MAGNITUDE, source);
        packed(code, Host::And, MAGNITUDE, CONSTANT);
        word_constant(code, CONSTANT, 0x7c00);
        packed(code, Host::GreaterWord, MAGNITUDE, CONSTANT);
        Host::ByteSignMask.register(code, 0, MAGNITUDE, TargetCpu::Baseline);
        code.asm().test_imm(Size::Dword, Gpr::Rax, active);
        helper.push(branch(code, Condition::NotZero));
    }
    test_control(code, FPCR_FZ16);
    let unflushed = branch(code, Condition::Zero);
    for source in [RESULT_VECTOR, RIGHT_VECTOR] {
        flush(code, source);
    }
    let unflushed_start = code.len();
    resolve(code, unflushed, unflushed_start);
    let done = jump(code);
    let alternative_start = code.len();
    resolve(code, alternative, alternative_start);
    done
}

fn shuffle(code: &mut Code, opcode: Host, destination: u8, source: u8, control: u8) {
    packed_imm(code, opcode, destination, source, control);
}

fn shuffle_single(code: &mut Code, destination: u8, right: u8, control: u8) {
    code.asm().shufps(destination, Rm::Xmm(right), control);
}

fn unpack_double(code: &mut Code, destination: u8, right: u8, high: bool) {
    if high {
        code.asm().unpckhpd(destination, Rm::Xmm(right));
    } else {
        code.asm().unpcklpd(destination, Rm::Xmm(right));
    }
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
    raw_selection(
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

fn vector_pairs(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    target: TargetCpu,
) {
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
            let mut asm = code.asm();
            asm.unpcklps(RESULT_VECTOR, Rm::Xmm(RIGHT_VECTOR));
            asm.movhlps(RIGHT_VECTOR, Rm::Xmm(RESULT_VECTOR));
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                RIGHT_VECTOR,
                target,
            );
        }
        Format::Single => {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            shuffle_single(code, RESULT_VECTOR, RIGHT_VECTOR, EVEN_DWORDS);
            shuffle_single(code, PAIR_VECTOR, RIGHT_VECTOR, ODD_DWORDS);
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                PAIR_VECTOR,
                target,
            );
        }
        Format::Double => {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            unpack_double(code, RESULT_VECTOR, RIGHT_VECTOR, false);
            unpack_double(code, PAIR_VECTOR, RIGHT_VECTOR, true);
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                PAIR_VECTOR,
                target,
            );
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
            let mut asm = code.asm();
            asm.movd_from_xmm(Gpr::Rax, RESULT_VECTOR);
            asm.pinsrw(ORIGINAL_LEFT_VECTOR, Gpr::Rax, 0);
            packed(code, Host::MoveAligned, RESULT_VECTOR, ORIGINAL_LEFT_VECTOR);
        }
    } else if shape == Shape::Vector64 {
        clear_high_qword(code, 0);
    }
    commit(code, destination, RESULT_VECTOR);
}

fn binary(code: &mut Code, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
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
    let unflushed = if format == Format::Half {
        half_quick_guard_supported(target).then(|| half_quick_guard(code, shape, &mut helper))
    } else {
        quick_guard_supported(target).then(|| quick_guard(code, shape, format, &mut helper, target))
    };
    if shape != Shape::Scalar {
        prepare_vector_input_range(code, format);
    }
    input_guard(code, format, shape, RESULT_VECTOR, &mut helper);
    input_guard(code, format, shape, RIGHT_VECTOR, &mut helper);
    if let Some(unflushed) = unflushed {
        let end = code.len();
        resolve(code, unflushed, end);
    }
    helper_section(code, &helper, pc);
    if format == Format::Half {
        if shape == Shape::Scalar {
            packed(code, Host::MoveAligned, ORIGINAL_LEFT_VECTOR, RESULT_VECTOR);
        }
        half_order(code, RESULT_VECTOR);
        half_order(code, RIGHT_VECTOR);
    }
    if mode == BinaryMode::Pairwise {
        vector_pairs(code, operation, format, shape, target);
    } else {
        selection(
            code,
            operation,
            format,
            shape,
            RESULT_VECTOR,
            RIGHT_VECTOR,
            target,
        );
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
    target: TargetCpu,
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
        target,
    );
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
    }
    clear_scalar(code, format, RESULT_VECTOR);
    commit(code, destination, RESULT_VECTOR);
}

fn reduction(code: &mut Code, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    let Operand::Reduction {
        operation,
        format,
        shape,
        destination,
        source,
    } = *operand
    else {
        unreachable!("reduction min/max operand")
    };
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
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                PAIR_VECTOR,
                target,
            );
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
        selection(
            code,
            operation,
            format,
            shape,
            RESULT_VECTOR,
            RIGHT_VECTOR,
            target,
        );
        packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
        ShiftOpcode::RightBytes.emit(code, RIGHT_VECTOR, (format.bits() / BITS_PER_BYTE) as u8);
        selection(
            code,
            operation,
            format,
            Shape::Scalar,
            RESULT_VECTOR,
            RIGHT_VECTOR,
            target,
        );
    }
    clear_scalar(code, format, RESULT_VECTOR);
    commit(code, destination, RESULT_VECTOR);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    match *operand {
        Operand::Binary { .. } => binary(code, operand, pc, target),
        Operand::PairwiseScalar {
            operation,
            format,
            destination,
            source,
        } => {
            pairwise_scalar(code, operation, format, destination, source, pc, target);
        }
        Operand::Reduction { .. } => reduction(code, operand, pc, target),
    }
}
