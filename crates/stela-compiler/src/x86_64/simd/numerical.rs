//! Shared FP emission: integer lane classification and a private MXCSR.
use alloc::vec;
use alloc::vec::Vec;
mod control;

use super::super::isa::ShiftOpcode;
use super::{Host, packed, read_vector, vector_offset};
use crate::{
    GuestState,
    aarch64::{floating::Format, simd::arithmetic::Shape},
};
pub(in crate::x86_64) use control::rounding_control;

const MXCSR_EXCEPTION_MASKS: u32 = 0x3f << 7;
pub(super) const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_POSITIVE_ROUNDING: u32 = 1 << 14;
const MXCSR_NEGATIVE_ROUNDING: u32 = 1 << 13;
const FPCR_POSITIVE_TO_MXCSR_SHIFT: u8 = 8;
const FPCR_NEGATIVE_TO_MXCSR_SHIFT: u8 = 10;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
pub(super) const INPUT_MINIMUM_EXPONENT: u8 = 1;
pub(super) const RESULT_MINIMUM_EXPONENT: u8 = 2;
/// Callers must prove usable AVX through their independent FMA/F16C capability.
pub(in crate::x86_64) const VZEROUPPER: &[u8] = &[0xc5, 0xf8, 0x77];
const SCALAR_SINGLE_PREFIX: u8 = 0xf3;
const SCALAR_DOUBLE_PREFIX: u8 = 0xf2;
const PACKED_DOUBLE_PREFIX: u8 = 0x66;
const SSE_ESCAPE: u8 = 0x0f;
pub(super) const LEFT_VECTOR: u8 = 0;
pub(super) const RIGHT_VECTOR: u8 = 1;
pub(super) const EXPONENT_VECTOR: u8 = 2;
const VALIDITY_VECTOR: u8 = 3;
const MAXIMUM_EXPONENT_VECTOR: u8 = 4;
pub(super) const MINIMUM_EXPONENT_VECTOR: u8 = 5;
const SINGLE_VECTOR_MASK: u8 = 0x0f;
const SINGLE_LOW_VECTOR_MASK: u8 = 0x03;
const DOUBLE_VECTOR_MASK: u8 = 0x05;
const SCALAR_VECTOR_MASK: u8 = 1;
const HALF_SCALAR_BYTE_MASK: u32 = 3;
const HALF_LOW_BYTE_MASK: u32 = 0xff;
const HALF_VECTOR_BYTE_MASK: u32 = 0xffff;
const SIGN_BITS: u8 = 1;
pub(super) const SINGLE_EXPONENT_BIAS_BITS: u8 = 7;
pub(super) const MOVLHPS_XMM1_XMM2: &[u8] = &[0x0f, 0x16, 0xca];
const TEST_STATE_IMM32: &[u8] = &[0xf7, 0x87];
const MOV_ECX_STATE: &[u8] = &[0x8b, 0x8f];
const OR_STATE_ECX: &[u8] = &[0x09, 0x8f];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const SHR_ECX_IMM8: &[u8] = &[0xc1, 0xe9];
const AND_EAX_IMM32: u8 = 0x25;
const OR_EAX_IMM32: u8 = 0x0d;
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const TEST_ECX_IMM32: &[u8] = &[0xf7, 0xc1];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const SUB_EAX_IMM8: &[u8] = &[0x83, 0xe8];
const CMP_EAX_IMM32: u8 = 0x3d;
const CMP_EAX_IMM8: &[u8] = &[0x83, 0xf8];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const MOVD_EAX_XMM6: &[u8] = &[0x66, 0x0f, 0x7e, 0xf0];
const MOVQ_RAX_XMM6: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xf0];
const MOVD_EAX_XMM1: &[u8] = &[0x66, 0x0f, 0x7e, 0xc8];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MOVQ_RAX_XMM1: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc8];
pub(super) const MOVQ_XMM0_XMM0: &[u8] = &[0xf3, 0x0f, 0x7e, 0xc0];
pub(super) const ENVIRONMENT_STACK_BYTES: u8 = 16;
const MXCSR_CONTROL_OFFSET: u8 = 4;
const MXCSR_STATUS_OFFSET: u8 = 8;
const SUB_RSP_ENVIRONMENT: &[u8] = &[0x48, 0x83, 0xec, ENVIRONMENT_STACK_BYTES];
const ADD_RSP_ENVIRONMENT: &[u8] = &[0x48, 0x83, 0xc4, ENVIRONMENT_STACK_BYTES];
const STMXCSR_SAVED: &[u8] = &[0x0f, 0xae, 0x1c, 0x24];
const MOV_CONTROL_EAX: &[u8] = &[0x89, 0x44, 0x24, MXCSR_CONTROL_OFFSET];
const LDMXCSR_CONTROL: &[u8] = &[0x0f, 0xae, 0x54, 0x24, MXCSR_CONTROL_OFFSET];
const STMXCSR_STATUS: &[u8] = &[0x0f, 0xae, 0x5c, 0x24, MXCSR_STATUS_OFFSET];
const LDMXCSR_SAVED: &[u8] = &[0x0f, 0xae, 0x14, 0x24];
const MOV_ECX_STATUS: &[u8] = &[0x8b, 0x4c, 0x24, MXCSR_STATUS_OFFSET];
const MOV_EAX_IMM32: u8 = 0xb8;

const FMA_VEX3: u8 = 0xc4;
const FMA_MAP_0F38: u8 = 0xe2;
const FMA_128_ADDEND_XMM6: u8 = 0x49;
const FMA_DOUBLE_W: u8 = 0x80;
const FMA_SCALAR_OPCODE_BIT: u8 = 1;

#[repr(u8)]
pub(in crate::x86_64) enum Condition {
    Below = 0x82,
    AboveOrEqual = 0x83,
    Zero = 0x84,
    NotZero = 0x85,
    Above = 0x87,
}

#[repr(u8)]
pub(in crate::x86_64) enum ArithmeticOpcode {
    Add = 0x58,
    Subtract = 0x5c,
    Multiply = 0x59,
    Divide = 0x5e,
}

#[repr(u8)]
pub(in crate::x86_64) enum FusedOpcode {
    MultiplyAdd = 0x98,
    MultiplySubtract = 0x9a,
    NegativeMultiplyAdd = 0x9c,
    NegativeMultiplySubtract = 0x9e,
}

#[derive(Clone, Copy)]
pub(super) enum Rounding {
    Fpcr,
    NearestEven,
    Positive,
    Negative,
    Zero,
}

mod bfloat16;
pub(in crate::x86_64) use bfloat16::{quantize_bfloat_packed, quantize_bfloat_scalar_bits};
mod quantization;

pub(in crate::x86_64) use quantization::{
    IntegerRoundingRegister, broadcast_integer_rounding, integer_rounding_policy,
};

/// Checked FMA132 with the shared numerical allocation: XMM0 is the product
/// destination, XMM1 the multiplier and XMM6 the addend. All are caller-volatile.
pub(in crate::x86_64) fn emit_fma(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    opcode: FusedOpcode,
    target: crate::TargetCpu,
) {
    const REGISTER_DIRECT: u8 = 0xc0;
    assert!(
        target.supports(crate::TargetCpu::Fma),
        "FMA3 requires usable AVX/FMA state"
    );
    // 132 order: XMM0 = XMM0 * XMM1 + XMM6, with the selected sign variant.
    code.extend([
        FMA_VEX3,
        FMA_MAP_0F38,
        FMA_128_ADDEND_XMM6
            | if format == Format::Double {
                FMA_DOUBLE_W
            } else {
                0
            },
        opcode as u8
            | if shape == Shape::Scalar {
                FMA_SCALAR_OPCODE_BIT
            } else {
                0
            },
        REGISTER_DIRECT | RIGHT_VECTOR,
    ]);
}

pub(in crate::x86_64) fn branch(code: &mut Vec<u8>, condition: Condition) -> usize {
    code.extend([SSE_ESCAPE, condition as u8]);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}
pub(in crate::x86_64) fn resolve(code: &mut [u8], patch: usize, target: usize) {
    let target = i64::try_from(target).expect("numerical branch target fits i64");
    let next = i64::try_from(patch + size_of::<i32>()).expect("numerical branch source fits i64");
    let distance = i32::try_from(target - next).expect("bounded numerical branch");
    code[patch..patch + size_of::<i32>()].copy_from_slice(&distance.to_le_bytes());
}
/// Refuse retained numerical enables unless AH suppresses exceptions.
pub(super) fn guard_ah0_exceptions(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    use crate::aarch64::floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK};
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    let enabled = code.len();
    resolve(code, suppressed, enabled);
}

/// Select guest RC for AH0 and mandatory nearest-even for AH1.
/// Inputs are already normal, so the forced AH1 flush controls are immaterial.
pub(super) fn environment_alternative_nearest(code: &mut Vec<u8>) {
    use crate::aarch64::floating::FPCR_AH;
    test_control(code, FPCR_AH);
    let nearest = branch(code, Condition::NotZero);
    environment(code);
    const JMP_REL32: u8 = 0xe9;
    code.push(JMP_REL32);
    let done = code.len();
    code.extend(0i32.to_le_bytes());
    let nearest_start = code.len();
    resolve(code, nearest, nearest_start);
    environment_round(code, Rounding::NearestEven);
    let end = code.len();
    resolve(code, done, end);
}

/// Commit the accepted host inexact status, only when FPCR.AH allows fresh
/// status.
pub(super) fn commit_ah0_inexact(code: &mut Vec<u8>) {
    use crate::aarch64::floating::FPCR_AH;
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    commit_inexact(code);
    let end = code.len();
    resolve(code, suppressed, end);
}

/// The FPCR fields outside whose defaults the sticky-inexact path
/// ([`sticky_inexact`]) declines: FIZ, AH, the exception enables, RMode
/// and FZ change some S/D result or its status that the path's result
/// classification cannot see, and NEP, which the path does not merge,
/// changes scalar upper bits. DN only selects a NaN result, which the
/// classification sends to the helper; FZ16 and AHP concern Half only.
pub(super) const FPCR_STICKY_MASK: u32 = {
    use crate::aarch64::floating::{
        FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_NEP, FPCR_ROUNDING_MASK,
        FPCR_ROUNDING_SHIFT,
    };
    FPCR_FIZ
        | FPCR_AH
        | FPCR_NEP
        | FPCR_EXCEPTION_ENABLE_MASK
        | FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT
        | FPCR_FZ
};
/// FPSR.IXC.
const FPSR_INEXACT: u8 = 1 << 4;
const TEST_STATE_BYTE_IMM8: &[u8] = &[0xf6, 0x87];
const JMP_REL32: u8 = 0xe9;

/// Enter the sticky-inexact path, or take one of the returned branches to
/// the full path. With FPCR at its defaults ([`FPCR_STICKY_MASK`]) and
/// FPSR.IXC already set, an S/D operation whose result its caller then
/// classifies needs neither its own MXCSR control nor its status. It runs
/// in the MXCSR native code is entered with: the block ABI's power-on
/// control (all exceptions masked, nearest rounding, no DAZ or FTZ), which
/// the SysV ABI preserves across calls and every environment sequence here
/// restores; its status flags are never read. Without DAZ, FZ and FIZ both
/// sides compute subnormal inputs exactly and without guest status, so no
/// input needs classifying. A fresh inexact result would only set IXC
/// again; every other status the guest would see needs a NaN or infinite
/// result, or, for an operation whose tiny results may be inexact, a result
/// below twice the minimum normal, which the caller's classification sends
/// to the exact helper.
///
/// Unless `entry.checked`, the caller knows the conditions hold
/// ([`Entry`]). There are then no branches.
pub(super) fn sticky_inexact(code: &mut Vec<u8>, entry: Entry) -> Vec<usize> {
    if !entry.checked {
        return vec![];
    }
    test_control(code, FPCR_STICKY_MASK);
    let control = branch(code, Condition::NotZero);
    code.extend(TEST_STATE_BYTE_IMM8);
    code.extend((core::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
    code.push(FPSR_INEXACT);
    let status = branch(code, Condition::Zero);
    vec![control, status]
}

/// What the block knows where a numerical instruction begins.
#[derive(Clone, Copy)]
pub(in crate::x86_64) struct Entry {
    /// Whether the sticky-inexact path checks its conditions
    /// ([`sticky_inexact`]). The block may omit the check where the
    /// previous instruction's sticky path falls through, if that
    /// instruction's full path continues in this one's ([`ColdSplit`]).
    pub(in crate::x86_64) checked: bool,
    /// The guest vector XMM0 holds whole, which the sticky path's inputs
    /// may take from there ([`read_inputs`]).
    pub(in crate::x86_64) xmm0: Option<u8>,
}

impl Entry {
    /// Nothing known.
    pub(in crate::x86_64) const UNKNOWN: Self = Self {
        checked: true,
        xmm0: None,
    };
}

/// An S/D emission with a sticky-inexact path ([`sticky_inexact`]), laid
/// out inline: the sticky path, a `jmp rel32` past the rest, then the rest
/// (zero-product check, full path, helper exit), which ends where the
/// emission ends. A block may move the rest out of line, re-resolving
/// `crossing` and ending the moved part with a jump to where the emission
/// ended. Neither part accesses guest memory.
pub(in crate::x86_64) struct ColdSplit {
    /// Start of the rest, just after the `jmp` past it.
    pub(in crate::x86_64) cold: usize,
    /// The full path's entry, correct in every FPCR and FPSR state.
    pub(in crate::x86_64) full: usize,
    /// Every rel32 branch field in one part that targets the other.
    pub(in crate::x86_64) crossing: Vec<usize>,
    /// The destination vector, which XMM0 holds whole wherever the
    /// emission ends: every path there ends with its commit from XMM0.
    pub(in crate::x86_64) result: u8,
}

/// An unconditional `jmp rel32` to resolve later.
pub(super) fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_REL32);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

/// Classify the active result lanes in `source` for the sticky-inexact
/// path and return the branch to the helper. Every NaN or infinite lane
/// takes it; unless `exact_tiny` (addition and subtraction, whose results
/// below the minimum normal are exact, and roots, which are never tiny),
/// so does every lane below twice the minimum normal, which may be tiny
/// before rounding, zero included.
pub(super) fn sticky_result_check(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    source: u8,
    exact_tiny: bool,
) -> usize {
    if shape == Shape::Scalar {
        let minimum = if exact_tiny {
            0
        } else {
            RESULT_MINIMUM_EXPONENT
        };
        if format == Format::Single {
            single_exponent_range(code, source, minimum);
        } else {
            exponent_range(code, format, source, minimum);
        }
        return branch(code, Condition::AboveOrEqual);
    }
    prepare_vector_maximum(code, format);
    if exact_tiny {
        vector_below_maximum(code, format, shape, source);
    } else {
        prepare_vector_result_range(code);
        vector_exponent_range(code, format, shape, source);
    }
    branch(code, Condition::NotZero)
}

/// [`exponent_range`] of a Single in `source` (XMM0 or XMM1) with one
/// instruction fewer: doubling its bits drops the sign and puts the
/// exponent field at the top, so the range bounds shift with it.
fn single_exponent_range(code: &mut Vec<u8>, source: u8, minimum: u8) {
    const SUB_EAX_IMM32: u8 = 0x2d;
    const FIELD_SHIFT: u32 = u32::BITS - 8;
    let maximum = (Format::Single.exponent_mask() >> Format::Single.fraction_bits()) as u32;
    code.extend(match source {
        0 => MOVD_EAX_XMM0,
        1 => MOVD_EAX_XMM1,
        _ => unreachable!("allocated numerical source register"),
    });
    code.extend(ADD_EAX_EAX);
    if minimum != 0 {
        code.push(SUB_EAX_IMM32);
        code.extend((u32::from(minimum) << FIELD_SHIFT).to_le_bytes());
    }
    code.push(CMP_EAX_IMM32);
    code.extend(((maximum - u32::from(minimum)) << FIELD_SHIFT).to_le_bytes());
}

/// Leave ZF set when every active S/D lane of `source` has an exponent
/// below all ones, with the maximum from [`prepare_vector_input_range`].
/// The high dwords of Double lanes hold zero, which is below it too.
fn vector_below_maximum(code: &mut Vec<u8>, format: Format, shape: Shape, source: u8) {
    vector_exponent_fields(code, format, source, false);
    packed(
        code,
        Host::MoveAligned,
        VALIDITY_VECTOR,
        MAXIMUM_EXPONENT_VECTOR,
    );
    packed(code, Host::GreaterDword, VALIDITY_VECTOR, EXPONENT_VECTOR);
    Host::DwordSignMask.register(code, 0, VALIDITY_VECTOR, crate::TargetCpu::Baseline);
    let mask = match (shape, format) {
        (Shape::Vector64, Format::Single) => {
            code.extend(AND_EAX_IMM8);
            code.push(SINGLE_LOW_VECTOR_MASK);
            SINGLE_LOW_VECTOR_MASK
        }
        (Shape::Vector128, Format::Single | Format::Double) => SINGLE_VECTOR_MASK,
        _ => unreachable!("allocated S/D vector shape"),
    };
    code.extend(CMP_EAX_IMM8);
    code.push(mask);
}

/// The operands of a product whose result the sticky classification
/// rejected, for [`zero_product_check`]: the result is in LEFT_VECTOR, the
/// right input in `right`, the left source (overwritten by the result)
/// still in guest vector `left` of the frame, and a fused addend in
/// `addend`.
pub(super) struct ZeroProduct {
    pub format: Format,
    pub shape: Shape,
    pub right: u8,
    pub left: u8,
    pub addend: Option<u8>,
}

/// Zero-product check registers; EXPONENT_VECTOR keeps the classifier's
/// lane validity, and the right input's register is reused for the left
/// once its own zeros are known.
const ZERO_RESULT: u8 = 3;
const ZERO_INPUT: u8 = 4;
const ZERO_PAIR: u8 = 5;
const ZERO_VECTOR: u8 = 7;
/// PSHUFD selector exchanging the two dwords of each qword.
const SWAP_DWORD_PAIRS: u8 = 0xb1;
/// MOVMSKPS lanes that are active: the low dword of each D lane holds its
/// classification.
const DOUBLE_LOW_DWORDS: u8 = 0b0101;
const MOV_RAX_STATE: &[u8] = &[0x48, 0x8b, 0x87];
const MOV_EAX_STATE: &[u8] = &[0x8b, 0x87];
const ADD_RAX_RAX: &[u8] = &[0x48, 0x01, 0xc0];
const ADD_EAX_EAX: &[u8] = &[0x01, 0xc0];
const MOVQ_RAX_XMM_PREFIX: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const MOVD_EAX_XMM_PREFIX: &[u8] = &[0x66, 0x0f, 0x7e];

/// Out of line after a sticky-inexact product (`sticky_inexact`): return
/// to `resume` when every active lane the classification rejected is a
/// zero whose product has a zero input, with a zero addend for a fused
/// product, which makes it exact and without status, and otherwise take
/// one of the returned branches to the helper; `resumes` receives the
/// branches to `resume`. Other zeros and tiny
/// results may have underflowed, and need the helper.
pub(super) fn zero_product_check(
    code: &mut Vec<u8>,
    product: &ZeroProduct,
    resume: usize,
    resumes: &mut Vec<usize>,
) -> Vec<usize> {
    let ZeroProduct {
        format,
        shape,
        right,
        left,
        addend,
    } = *product;
    if shape == Shape::Scalar {
        let mut helper = vec![];
        for source in core::iter::once(LEFT_VECTOR).chain(addend) {
            zero_scalar(code, format, source);
            helper.push(branch(code, Condition::NotZero));
        }
        zero_scalar(code, format, right);
        let right_zero = branch(code, Condition::Zero);
        resolve(code, right_zero, resume);
        resumes.push(right_zero);
        code.extend(if format == Format::Double {
            MOV_RAX_STATE
        } else {
            MOV_EAX_STATE
        });
        code.extend(vector_offset(left).to_le_bytes());
        code.extend(if format == Format::Double {
            ADD_RAX_RAX
        } else {
            ADD_EAX_EAX
        });
        let left_zero = branch(code, Condition::Zero);
        resolve(code, left_zero, resume);
        resumes.push(left_zero);
        helper.push(jump(code));
        return helper;
    }
    packed(code, Host::Xor, ZERO_VECTOR, ZERO_VECTOR);
    zero_lanes(code, format, ZERO_INPUT, right);
    read_vector(code, left, right);
    zero_lanes(code, format, right, right);
    packed(code, Host::Or, ZERO_INPUT, right);
    zero_lanes(code, format, ZERO_RESULT, LEFT_VECTOR);
    packed(code, Host::And, ZERO_INPUT, ZERO_RESULT);
    if let Some(addend) = addend {
        zero_lanes(code, format, addend, addend);
        packed(code, Host::And, ZERO_INPUT, addend);
    }
    packed(code, Host::Or, EXPONENT_VECTOR, ZERO_INPUT);
    Host::DwordSignMask.register(code, 0, EXPONENT_VECTOR, crate::TargetCpu::Baseline);
    let mask = match (shape, format) {
        (Shape::Vector64, Format::Single) => SINGLE_LOW_VECTOR_MASK,
        (Shape::Vector128, Format::Single) => SINGLE_VECTOR_MASK,
        (Shape::Vector128, Format::Double) => DOUBLE_LOW_DWORDS,
        _ => unreachable!("allocated S/D vector shape"),
    };
    code.extend(AND_EAX_IMM8);
    code.push(mask);
    code.extend(CMP_EAX_IMM8);
    code.push(mask);
    let passed = branch(code, Condition::Zero);
    resolve(code, passed, resume);
    resumes.push(passed);
    vec![jump(code)]
}

/// Leave ZF set when the low S/D lane of `xmm` is a zero of either sign.
fn zero_scalar(code: &mut Vec<u8>, format: Format, xmm: u8) {
    const REGISTER_DIRECT: u8 = 0xc0;
    const MODRM_REGISTER_SHIFT: u8 = 3;
    if format == Format::Double {
        code.extend(MOVQ_RAX_XMM_PREFIX);
        code.push(REGISTER_DIRECT | xmm << MODRM_REGISTER_SHIFT);
        code.extend(ADD_RAX_RAX);
    } else {
        code.extend(MOVD_EAX_XMM_PREFIX);
        code.push(REGISTER_DIRECT | xmm << MODRM_REGISTER_SHIFT);
        code.extend(ADD_EAX_EAX);
    }
}

/// Set every S lane, or both dwords of every D lane, of `destination` to
/// all ones where `source` holds a zero of either sign, using ZERO_VECTOR
/// and, for D, ZERO_PAIR.
fn zero_lanes(code: &mut Vec<u8>, format: Format, destination: u8, source: u8) {
    if destination != source {
        packed(code, Host::MoveAligned, destination, source);
    }
    if format == Format::Double {
        ShiftOpcode::LeftQword.emit(code, destination, SIGN_BITS);
    } else {
        ShiftOpcode::LeftDword.emit(code, destination, SIGN_BITS);
    }
    packed(code, Host::EqualDword, destination, ZERO_VECTOR);
    if format == Format::Double {
        packed(code, Host::ShuffleDword, ZERO_PAIR, destination);
        code.push(SWAP_DWORD_PAIRS);
        packed(code, Host::And, destination, ZERO_PAIR);
    }
}

pub(super) fn test_control(code: &mut Vec<u8>, mask: u32) {
    code.extend(TEST_STATE_IMM32);
    code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(mask.to_le_bytes());
}

/// Leave flags from (exponent-minimum) versus the exclusive range length.
/// Below is allocated normal; zero/all-ones exponents fail one unsigned test.
pub(super) fn exponent_range(code: &mut Vec<u8>, format: Format, source: u8, minimum: u8) {
    let maximum = (format.exponent_mask() >> format.fraction_bits()) as u32;
    exponent_range_impl(code, format, source, minimum, maximum, false);
}

/// A stricter exclusive upper exponent bounds finite arithmetic outputs too.
pub(super) fn exponent_range_below(
    code: &mut Vec<u8>,
    format: Format,
    source: u8,
    minimum: u8,
    maximum: u32,
) {
    exponent_range_impl(code, format, source, minimum, maximum, false);
}

/// Keep the sign alongside the exponent so every negative input also fails.
pub(super) fn positive_exponent_range(code: &mut Vec<u8>, format: Format, source: u8, minimum: u8) {
    let maximum = (format.exponent_mask() >> format.fraction_bits()) as u32;
    exponent_range_impl(code, format, source, minimum, maximum, true);
}

fn exponent_range_impl(
    code: &mut Vec<u8>,
    format: Format,
    source: u8,
    minimum: u8,
    maximum: u32,
    positive_only: bool,
) {
    code.extend(match (format, source) {
        (Format::Half | Format::Single, 0) => MOVD_EAX_XMM0,
        (Format::Half | Format::Single, 1) => MOVD_EAX_XMM1,
        (Format::Double, 0) => MOVQ_RAX_XMM0,
        (Format::Double, 1) => MOVQ_RAX_XMM1,
        (Format::Half | Format::Single, 6) => MOVD_EAX_XMM6,
        (Format::Double, 6) => MOVQ_RAX_XMM6,
        _ => unreachable!("allocated numerical source register"),
    });
    code.extend(if format == Format::Double {
        SHR_RAX_IMM8
    } else {
        SHR_EAX_IMM8
    });
    code.push(format.fraction_bits() as u8);
    let exponent_mask = (1u32 << (format.bits() - format.fraction_bits() - 1)) - 1;
    code.push(AND_EAX_IMM32);
    let field_mask = if positive_only {
        exponent_mask * 2 + 1
    } else {
        exponent_mask
    };
    code.extend(field_mask.to_le_bytes());
    if minimum != 0 {
        code.extend(SUB_EAX_IMM8);
        code.push(minimum);
    }
    code.push(CMP_EAX_IMM32);
    code.extend((maximum - u32::from(minimum)).to_le_bytes());
}

pub(super) fn environment(code: &mut Vec<u8>) {
    environment_round(code, Rounding::Fpcr);
}

/// Save the complete caller environment and install masked, nonflushing SSE
/// control. Conversion instructions may select rounding independently of FPCR.
pub(super) fn environment_round(code: &mut Vec<u8>, rounding: Rounding) {
    code.extend(SUB_RSP_ENVIRONMENT);
    code.extend(STMXCSR_SAVED);
    if matches!(rounding, Rounding::Fpcr) {
        code.extend(MOV_ECX_STATE);
        code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
        code.extend(MOV_EAX_ECX);
        code.extend(SHR_EAX_IMM8);
        code.push(FPCR_POSITIVE_TO_MXCSR_SHIFT);
        code.push(AND_EAX_IMM32);
        code.extend(MXCSR_POSITIVE_ROUNDING.to_le_bytes());
        code.extend(SHR_ECX_IMM8);
        code.push(FPCR_NEGATIVE_TO_MXCSR_SHIFT);
        code.extend(AND_ECX_IMM32);
        code.extend(MXCSR_NEGATIVE_ROUNDING.to_le_bytes());
        code.extend(OR_EAX_ECX);
        code.push(OR_EAX_IMM32);
        code.extend(MXCSR_EXCEPTION_MASKS.to_le_bytes());
    } else {
        let direction = match rounding {
            Rounding::NearestEven => 0,
            Rounding::Positive => MXCSR_POSITIVE_ROUNDING,
            Rounding::Negative => MXCSR_NEGATIVE_ROUNDING,
            Rounding::Zero => MXCSR_POSITIVE_ROUNDING | MXCSR_NEGATIVE_ROUNDING,
            Rounding::Fpcr => unreachable!("FPCR control emitted above"),
        };
        code.push(MOV_EAX_IMM32);
        code.extend((MXCSR_EXCEPTION_MASKS | direction).to_le_bytes());
    }
    code.extend(MOV_CONTROL_EAX);
    code.extend(LDMXCSR_CONTROL);
}

pub(super) fn restore_environment(code: &mut Vec<u8>) {
    code.extend(STMXCSR_STATUS);
    code.extend(LDMXCSR_SAVED);
    code.extend(MOV_ECX_STATUS);
    code.extend(ADD_RSP_ENVIRONMENT);
}

/// Observe a real arithmetic stage without leaving the private environment.
pub(super) fn capture_environment_status(code: &mut Vec<u8>) {
    code.extend(STMXCSR_STATUS);
    code.extend(MOV_ECX_STATUS);
}

/// Discard private scratch-operation status before the next arithmetic stage.
pub(super) fn clear_environment_status(code: &mut Vec<u8>) {
    code.extend(LDMXCSR_CONTROL);
}

/// Accumulate status and leave ECX holding only fresh guest IXC (zero or INEXACT).
pub(super) fn commit_inexact(code: &mut Vec<u8>) {
    code.extend(AND_ECX_IMM32);
    code.extend(MXCSR_INEXACT.to_le_bytes());
    code.extend(SHR_ECX_IMM8);
    code.push(MXCSR_TO_FPSR_INEXACT_SHIFT);
    code.extend(OR_STATE_ECX);
    code.extend((core::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
}

/// Extract exponent magnitudes into words/dwords and compare an open range.
/// Double exponents occupy the low dword of each qword; their high dwords and
/// inactive S lanes are excluded from the dword sign mask. No numerical FP runs here.
pub(in crate::x86_64) fn vector_exponent_range(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    source: u8,
) {
    vector_exponent_range_impl(code, format, shape, source, false);
}

/// Reject negative inputs as well as zero and all-ones exponents.
pub(super) fn vector_positive_exponent_range(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    source: u8,
) {
    vector_exponent_range_impl(code, format, shape, source, true);
}

/// Copy `source` to EXPONENT_VECTOR and reduce every lane to its exponent
/// field, with the sign above it if `positive_only`.
fn vector_exponent_fields(code: &mut Vec<u8>, format: Format, source: u8, positive_only: bool) {
    packed(code, Host::MoveAligned, EXPONENT_VECTOR, source);
    let (left, right) = match format {
        Format::Single => (ShiftOpcode::LeftDword, ShiftOpcode::RightDword),
        Format::Double => (ShiftOpcode::LeftQword, ShiftOpcode::RightQword),
        Format::Half => (ShiftOpcode::LeftWord, ShiftOpcode::RightWord),
    };
    if positive_only {
        right.emit(code, EXPONENT_VECTOR, format.fraction_bits() as u8);
    } else {
        left.emit(code, EXPONENT_VECTOR, SIGN_BITS);
        right.emit(
            code,
            EXPONENT_VECTOR,
            format.fraction_bits() as u8 + SIGN_BITS,
        );
    }
}

fn vector_exponent_validity(code: &mut Vec<u8>, format: Format, source: u8, positive_only: bool) {
    vector_exponent_fields(code, format, source, positive_only);
    packed(
        code,
        Host::MoveAligned,
        VALIDITY_VECTOR,
        MAXIMUM_EXPONENT_VECTOR,
    );
    let compare = if format == Format::Half {
        Host::GreaterWord
    } else {
        Host::GreaterDword
    };
    packed(code, compare, VALIDITY_VECTOR, EXPONENT_VECTOR);
    packed(code, compare, EXPONENT_VECTOR, MINIMUM_EXPONENT_VECTOR);
    packed(code, Host::And, EXPONENT_VECTOR, VALIDITY_VECTOR);
}

fn half_validity_mask(code: &mut Vec<u8>, byte_mask: u32) {
    Host::ByteSignMask.register(code, 0, EXPONENT_VECTOR, crate::TargetCpu::Baseline);
    code.push(AND_EAX_IMM32);
    code.extend(byte_mask.to_le_bytes());
    code.push(CMP_EAX_IMM32);
    code.extend(byte_mask.to_le_bytes());
}

/// Classify a caller-selected low Half lane span without inventing a vector shape.
pub(in crate::x86_64) fn vector_half_exponent_range(
    code: &mut Vec<u8>,
    source: u8,
    byte_mask: u32,
) {
    vector_exponent_validity(code, Format::Half, source, false);
    half_validity_mask(code, byte_mask);
}

fn vector_exponent_range_impl(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    source: u8,
    positive_only: bool,
) {
    vector_exponent_validity(code, format, source, positive_only);
    if format == Format::Half {
        let mask = match shape {
            Shape::Scalar => HALF_SCALAR_BYTE_MASK,
            Shape::Vector64 => HALF_LOW_BYTE_MASK,
            Shape::Vector128 => HALF_VECTOR_BYTE_MASK,
        };
        half_validity_mask(code, mask);
        return;
    }
    Host::DwordSignMask.register(code, 0, EXPONENT_VECTOR, crate::TargetCpu::Baseline);
    let mask = match (shape, format) {
        (Shape::Scalar, _) => {
            code.extend(AND_EAX_IMM8);
            code.push(SCALAR_VECTOR_MASK);
            SCALAR_VECTOR_MASK
        }
        (Shape::Vector64, Format::Single) => {
            code.extend(AND_EAX_IMM8);
            code.push(SINGLE_LOW_VECTOR_MASK);
            SINGLE_LOW_VECTOR_MASK
        }
        (Shape::Vector128, Format::Single) => SINGLE_VECTOR_MASK,
        (Shape::Vector128, Format::Double) => DOUBLE_VECTOR_MASK,
        _ => unreachable!("allocated vector shape"),
    };
    code.extend(CMP_EAX_IMM8);
    code.push(mask);
}

/// Widen four staged Half fields with integer operations. Callers guard active
/// inputs and supply zero and the broadcast Single-minus-Half exponent bias.
/// Inactive raw fields also become finite normal Single values without status.
pub(in crate::x86_64) fn widen_half_to_single(
    code: &mut Vec<u8>,
    destination: u8,
    source: u8,
    sign: u8,
    zero: u8,
    bias: u8,
) {
    const WIDTH_DIFFERENCE: u8 = (Format::Single.bits() - Format::Half.bits()) as u8;
    const SINGLE_SIGN_POSITION: u8 = (Format::Single.bits() - 1) as u8;
    const FRACTION_DIFFERENCE: u8 =
        (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
    if destination != source {
        packed(code, Host::MoveAligned, destination, source);
    }
    packed(code, Host::UnpackLowWord, destination, zero);
    packed(code, Host::MoveAligned, sign, destination);
    ShiftOpcode::LeftDword.emit(code, sign, WIDTH_DIFFERENCE);
    ShiftOpcode::RightDword.emit(code, sign, SINGLE_SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, sign, SINGLE_SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, destination, WIDTH_DIFFERENCE + SIGN_BITS);
    ShiftOpcode::RightDword.emit(
        code,
        destination,
        WIDTH_DIFFERENCE + SIGN_BITS - FRACTION_DIFFERENCE,
    );
    packed(code, Host::AddDword, destination, bias);
    packed(code, Host::Or, destination, sign);
}

pub(super) fn read_numerical_vector(code: &mut Vec<u8>, shape: Shape, source: u8, xmm: u8) {
    if shape == Shape::Vector64 {
        // MOVQ loads only active bits and clears the high qword, even for DIV.
        Host::MoveQword.append(code, crate::TargetCpu::Baseline);
        const STATE_MEMORY: u8 = 0x87;
        const MODRM_REGISTER_SHIFT: u8 = 3;
        code.push(STATE_MEMORY | (xmm << MODRM_REGISTER_SHIFT));
        code.extend(vector_offset(source).to_le_bytes());
    } else {
        read_vector(code, source, xmm);
    }
}

/// The low S or D element of guest vector `source` in `xmm`, the rest of
/// it clear (MOVSS or MOVSD from memory), so that a scalar operation with
/// `xmm` as its destination leaves the upper bits an Arm scalar write
/// clears already clear.
pub(super) fn read_numerical_scalar(code: &mut Vec<u8>, format: Format, source: u8, xmm: u8) {
    const STATE_MEMORY: u8 = 0x87;
    const MODRM_REGISTER_SHIFT: u8 = 3;
    match format {
        Format::Single => Host::MoveScalarSingle,
        Format::Double => Host::MoveScalarDouble,
        Format::Half => unreachable!("Half has its own mapping policy"),
    }
    .append(code, crate::TargetCpu::Baseline);
    code.push(STATE_MEMORY | (xmm << MODRM_REGISTER_SHIFT));
    code.extend(vector_offset(source).to_le_bytes());
}

/// How a sticky path reads one input from the frame: a zeroing scalar
/// load ([`read_numerical_scalar`]) or a vector one
/// ([`read_numerical_vector`]).
#[derive(Clone, Copy)]
pub(super) enum Input {
    Scalar(Format),
    Vector(Shape),
}

/// INSERTPS selector copying source lane 0 to destination lane 0 and
/// clearing lanes 1 to 3.
const INSERT_LOW_LANE_ALONE: u8 = 0b1110;

/// Read each `(input, source vector, xmm)`, taking a source that XMM0
/// holds whole (`xmm0`) from there rather than the frame, and producing
/// the bits a frame read would. Copies out of XMM0 come first, before a
/// read into XMM0 replaces it. A Single scalar copy needs SSE4.1's
/// INSERTPS; without it the frame provides the input.
pub(super) fn read_inputs(
    code: &mut Vec<u8>,
    xmm0: Option<u8>,
    target: crate::TargetCpu,
    inputs: &[(Input, u8, u8)],
) {
    let held = |input: Input, source: u8| {
        xmm0 == Some(source)
            && !matches!(input, Input::Scalar(Format::Single) if !target.supports(crate::TargetCpu::Sse41))
    };
    let copy = |code: &mut Vec<u8>, input: Input, xmm: u8| match input {
        Input::Scalar(Format::Single) => {
            Host::InsertSingle.register(code, xmm, LEFT_VECTOR, target);
            code.push(INSERT_LOW_LANE_ALONE);
        }
        Input::Scalar(Format::Double) | Input::Vector(Shape::Vector64) => {
            packed(code, Host::MoveQword, xmm, LEFT_VECTOR);
        }
        Input::Scalar(Format::Half) => unreachable!("Half has its own mapping policy"),
        Input::Vector(Shape::Vector128 | Shape::Scalar) => {
            if xmm != LEFT_VECTOR {
                packed(code, Host::MoveAligned, xmm, LEFT_VECTOR);
            }
        }
    };
    for &(input, source, xmm) in inputs {
        if held(input, source) && xmm != LEFT_VECTOR {
            copy(code, input, xmm);
        }
    }
    for &(input, source, xmm) in inputs {
        if !held(input, source) {
            match input {
                Input::Scalar(format) => read_numerical_scalar(code, format, source, xmm),
                Input::Vector(shape) => read_numerical_vector(code, shape, source, xmm),
            }
        } else if xmm == LEFT_VECTOR {
            copy(code, input, xmm);
        }
    }
}

/// Select from the whole indexed source before broadcasting. A 64-bit indexed
/// form may read a lane in the upper qword.
pub(super) fn read_numerical_right(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    source: u8,
    right_lane: Option<u8>,
) {
    const BROADCAST_LOW_LANE: u8 = 0;
    if let Some(lane) = right_lane {
        read_vector(code, source, RIGHT_VECTOR);
        ShiftOpcode::RightBytes.emit(
            code,
            RIGHT_VECTOR,
            (u32::from(lane) * format.bits() / u8::BITS) as u8,
        );
        if shape != Shape::Scalar {
            if format == Format::Half {
                packed(code, Host::ShuffleLowWord, RIGHT_VECTOR, RIGHT_VECTOR);
                code.push(BROADCAST_LOW_LANE);
            }
            if format != Format::Double {
                packed(code, Host::ShuffleDword, RIGHT_VECTOR, RIGHT_VECTOR);
                code.push(BROADCAST_LOW_LANE);
            } else {
                packed(code, Host::UnpackLowQword, RIGHT_VECTOR, RIGHT_VECTOR);
            }
        }
    } else {
        read_numerical_vector(code, shape, source, RIGHT_VECTOR);
    }
}

pub(in crate::x86_64) fn prepare_vector_input_range(code: &mut Vec<u8>, format: Format) {
    prepare_vector_maximum(code, format);
    packed(
        code,
        Host::Xor,
        MINIMUM_EXPONENT_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
    );
}

/// The all-ones exponent of `format` in every lane of
/// MAXIMUM_EXPONENT_VECTOR.
fn prepare_vector_maximum(code: &mut Vec<u8>, format: Format) {
    packed(
        code,
        Host::EqualDword,
        MAXIMUM_EXPONENT_VECTOR,
        MAXIMUM_EXPONENT_VECTOR,
    );
    let exponent_bits = format.bits() - format.fraction_bits() - u32::from(SIGN_BITS);
    let (shift, width) = if format == Format::Half {
        (ShiftOpcode::RightWord, u16::BITS)
    } else {
        (ShiftOpcode::RightDword, u32::BITS)
    };
    shift.emit(code, MAXIMUM_EXPONENT_VECTOR, (width - exponent_bits) as u8);
}
/// Set an exclusive upper bound, keeping the normal lower bound used by
/// `vector_exponent_range`. Half precision repeats the limit in both words.
pub(super) fn prepare_vector_input_range_below(code: &mut Vec<u8>, format: Format, maximum: u32) {
    const MOVD_MAXIMUM_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xe0];
    const BROADCAST_LOW_DWORD: u8 = 0;
    let limit = if format == Format::Half {
        maximum | maximum << u16::BITS
    } else {
        maximum
    };
    code.push(MOV_EAX_IMM32);
    code.extend(limit.to_le_bytes());
    code.extend(MOVD_MAXIMUM_EAX);
    packed(
        code,
        Host::ShuffleDword,
        MAXIMUM_EXPONENT_VECTOR,
        MAXIMUM_EXPONENT_VECTOR,
    );
    code.push(BROADCAST_LOW_DWORD);
    packed(
        code,
        Host::Xor,
        MINIMUM_EXPONENT_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
    );
}

pub(in crate::x86_64) fn prepare_vector_result_range(code: &mut Vec<u8>) {
    packed(
        code,
        Host::EqualDword,
        MINIMUM_EXPONENT_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
    );
    ShiftOpcode::RightDword.emit(code, MINIMUM_EXPONENT_VECTOR, u32::BITS as u8 - SIGN_BITS);
}
pub(super) fn emit_opcode(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    opcode: ArithmeticOpcode,
    right: u8,
) {
    emit_opcode_to(code, format, shape, opcode, LEFT_VECTOR, right);
}

/// Arithmetic encoding with an explicit destination register.
pub(in crate::x86_64) fn emit_opcode_to(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    opcode: ArithmeticOpcode,
    destination: u8,
    source: u8,
) {
    if shape == Shape::Scalar {
        code.push(if format == Format::Single {
            SCALAR_SINGLE_PREFIX
        } else {
            SCALAR_DOUBLE_PREFIX
        });
    } else if format == Format::Double {
        code.push(PACKED_DOUBLE_PREFIX);
    }
    const REGISTER_DIRECT: u8 = 0xc0;
    const MODRM_REGISTER_SHIFT: u8 = 3;
    code.extend([
        SSE_ESCAPE,
        opcode as u8,
        REGISTER_DIRECT | destination << MODRM_REGISTER_SHIFT | source,
    ]);
}
pub(super) fn reject_other_status(code: &mut Vec<u8>) -> usize {
    code.extend(TEST_ECX_IMM32);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    branch(code, Condition::NotZero)
}
pub(super) fn save_product_status(code: &mut Vec<u8>) {
    const STMXCSR_PRODUCT: &[u8] = &[0x0f, 0xae, 0x5c, 0x24, 12];
    code.extend(STMXCSR_PRODUCT);
}
pub(super) fn restore_environment_with_product(code: &mut Vec<u8>) {
    const MOV_EAX_PRODUCT: &[u8] = &[0x8b, 0x44, 0x24, 12];
    code.extend(STMXCSR_STATUS);
    code.extend(LDMXCSR_SAVED);
    code.extend(MOV_EAX_PRODUCT);
    code.extend(MOV_ECX_STATUS);
    code.extend(ADD_RSP_ENVIRONMENT);
}
pub(super) fn reject_product_status(code: &mut Vec<u8>) -> usize {
    const TEST_AL_STATUS: &[u8] = &[0xa8, 0x3f];
    code.extend(TEST_AL_STATUS);
    branch(code, Condition::NotZero)
}
pub(super) fn clear_scalar(code: &mut Vec<u8>, format: Format, xmm: u8) {
    const REGISTER_DIRECT: u8 = 0xc0;
    const MODRM_REGISTER_SHIFT: u8 = 3;
    if format == Format::Double {
        code.extend([
            0xf3,
            0x0f,
            0x7e,
            REGISTER_DIRECT | (xmm << MODRM_REGISTER_SHIFT) | xmm,
        ]);
    } else {
        code.extend([
            0x66,
            0x0f,
            0x7e,
            REGISTER_DIRECT | (xmm << MODRM_REGISTER_SHIFT),
        ]);
        if format == Format::Half {
            code.push(AND_EAX_IMM32);
            code.extend(u32::from(u16::MAX).to_le_bytes());
        }
        code.extend([
            0x66,
            0x0f,
            0x6e,
            REGISTER_DIRECT | (xmm << MODRM_REGISTER_SHIFT),
        ]);
    }
}
