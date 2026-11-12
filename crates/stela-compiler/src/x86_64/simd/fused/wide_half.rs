//! Vector Half FMLA/FMLS for every finite input on AVX2 hosts with F16C,
//! in Single lanes: the product of two Half values is exact in Single,
//! TwoSum gives the sum's exact error, and the sum rounded to odd (24 bits,
//! at least Half's 11 plus 2) rounds once more to Half exactly as the one
//! rounding Arm's FPMulAdd makes. Zeros and subnormal inputs need nothing
//! apart; a NaN or infinite input, FZ16, AH and enabled traps take the
//! caller's other path.
use super::super::numerical::{Condition, branch, jump, resolve};
use super::super::{commit, encode::guest};
use crate::x86_64::asm::{Alu, Code, Gpr, Map, Pp, Rm, ShiftOp, Size, Vex};
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FZ16, FPCR_ROUNDING_SHIFT, Format, INEXACT,
            OVERFLOW, UNDERFLOW,
        },
        simd::{arithmetic::Shape, fused::Operand},
    },
};
use alloc::{vec, vec::Vec};

const LEFT: u8 = 0;
/// Where [`super::prepare_right`] puts the (broadcast) right operand.
const RIGHT: u8 = super::RIGHT;
const ADDEND: u8 = 2;
const PRODUCT: u8 = 3;
const SUM: u8 = 4;
const SCRATCH: u8 = 5;
const ERROR: u8 = 6;
const RESULT: u8 = 7;

const EQUAL: u8 = 0;
const LESS: u8 = 1;
const UNORDERED: u8 = 3;
const NOT_EQUAL: u8 = 4;
const NOT_LESS: u8 = 5;

/// Single bits of Half's smallest normal, 2^-14.
const HALF_MINIMUM_NORMAL: u32 = 0x3880_0000;
/// Single bits of 2^16: a magnitude from which every rounding overflows Half.
const HALF_OVERFLOW: u32 = 0x4780_0000;
const SIGN_BITS: u8 = 31;

/// Whether this recipe serves `operand` on `target`.
pub(super) fn supported(operand: &Operand, target: TargetCpu) -> bool {
    operand.shape != Shape::Scalar
        && target.supports(TargetCpu::Avx2)
        && target.supports(TargetCpu::F16c)
        && !target.data_independent_timing()
}

struct Lanes {
    wide: bool,
    active: i32,
}

fn vex(
    code: &mut Code,
    lanes: &Lanes,
    (map, pp): (Map, Pp),
    opcode: u8,
    reg: u8,
    vvvv: u8,
    rm: Rm,
) {
    code.asm().vex(
        Vex {
            map,
            pp,
            w: false,
            l: lanes.wide,
        },
        opcode,
        reg,
        vvvv,
        rm,
    );
}

/// `destination = left op right` on packed Single (VEX.0F `opcode`).
fn single(code: &mut Code, lanes: &Lanes, opcode: u8, destination: u8, left: u8, right: u8) {
    vex(
        code,
        lanes,
        (Map::M0f, Pp::None),
        opcode,
        destination,
        left,
        Rm::Xmm(right),
    );
}

fn multiply(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8) {
    single(code, lanes, 0x59, destination, left, right);
}
fn add(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8) {
    single(code, lanes, 0x58, destination, left, right);
}
fn subtract(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8) {
    single(code, lanes, 0x5c, destination, left, right);
}
fn and(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8) {
    single(code, lanes, 0x54, destination, left, right);
}
fn or(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8) {
    single(code, lanes, 0x56, destination, left, right);
}
fn xor(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8) {
    single(code, lanes, 0x57, destination, left, right);
}

/// VCMPPS `predicate`: all ones where `left predicate right`. Its MXCSR
/// status is never guest state.
fn compare(code: &mut Code, lanes: &Lanes, destination: u8, left: u8, right: u8, predicate: u8) {
    single(code, lanes, 0xc2, destination, left, right);
    code.asm().data(&[predicate]);
}

/// VPCMPEQD `xmm`, `xmm`: all ones.
fn ones(code: &mut Code, lanes: &Lanes, xmm: u8) {
    vex(
        code,
        lanes,
        (Map::M0f, Pp::P66),
        0x76,
        xmm,
        xmm,
        Rm::Xmm(xmm),
    );
}

/// VPSRLD (`left` false: VPSLLD) `destination`, `source`, `count`.
fn shift(code: &mut Code, lanes: &Lanes, right: bool, destination: u8, source: u8, count: u8) {
    let extension = if right { 2 } else { 6 };
    vex(
        code,
        lanes,
        (Map::M0f, Pp::P66),
        0x72,
        extension,
        destination,
        Rm::Xmm(source),
    );
    code.asm().data(&[count]);
}

/// `bits` in every Single lane of `xmm` (VMOVD and VPBROADCASTD).
fn constant(code: &mut Code, lanes: &Lanes, xmm: u8, bits: u32) {
    code.asm().mov_imm32(Gpr::Rax, bits);
    let narrow = Lanes {
        wide: false,
        active: 0,
    };
    vex(
        code,
        &narrow,
        (Map::M0f, Pp::P66),
        0x6e,
        xmm,
        0,
        Rm::Reg(Gpr::Rax),
    );
    vex(
        code,
        lanes,
        (Map::M0f38, Pp::P66),
        0x58,
        xmm,
        0,
        Rm::Xmm(xmm),
    );
}

/// VCVTPH2PS `destination`, `source`: exact.
fn widen(code: &mut Code, lanes: &Lanes, destination: u8, source: u8) {
    vex(
        code,
        lanes,
        (Map::M0f38, Pp::P66),
        0x13,
        destination,
        0,
        Rm::Xmm(source),
    );
}

/// VCVTPS2PH `destination`, `source` under `rounding` (its immediate).
fn narrow(code: &mut Code, lanes: &Lanes, destination: u8, source: u8, rounding: u8) {
    vex(
        code,
        lanes,
        (Map::M0f3a, Pp::P66),
        0x1d,
        source,
        0,
        Rm::Xmm(destination),
    );
    code.asm().data(&[rounding]);
}

/// Branch taken when no active lane of the Single lane mask `xmm` is set
/// (VMOVMSKPS).
fn none_active(code: &mut Code, lanes: &Lanes, xmm: u8) -> usize {
    vex(code, lanes, (Map::M0f, Pp::None), 0x50, 0, 0, Rm::Xmm(xmm));
    code.asm().test_imm(Size::Dword, Gpr::Rax, lanes.active);
    branch(code, Condition::Zero)
}

/// Add `flag` to ECX where an active lane of `xmm` is set.
fn flag_if_active(code: &mut Code, lanes: &Lanes, xmm: u8, flag: u32) {
    let none = none_active(code, lanes, xmm);
    code.asm()
        .alu_imm32(Alu::Or, Size::Dword, Gpr::Rcx, flag as i32);
    let next = code.len();
    resolve(code, none, next);
}

/// Emit the recipe; returns the branches to the caller's other path, which
/// it enters with the state untouched, the inputs reread and no YMM upper
/// half in use.
pub(super) fn emit(code: &mut Code, operand: &Operand) -> Vec<usize> {
    let lanes = Lanes {
        wide: operand.shape == Shape::Vector128,
        active: if operand.shape == Shape::Vector128 {
            0xff
        } else {
            0xf
        },
    };
    let lanes = &lanes;
    let mut other = Vec::new();
    // ECX: FPCR's rounding mode.
    {
        let mut asm = code.asm();
        asm.mov_load(
            Size::Dword,
            Gpr::Rcx,
            guest(core::mem::offset_of!(GuestState, fpcr) as u32),
        );
        asm.test_imm(
            Size::Dword,
            Gpr::Rcx,
            (FPCR_EXCEPTION_ENABLE_MASK | FPCR_AH | FPCR_FZ16) as i32,
        );
    }
    other.push(branch(code, Condition::NotZero));
    {
        let mut asm = code.asm();
        asm.shift_imm(
            ShiftOp::Shr,
            Size::Dword,
            Gpr::Rcx,
            FPCR_ROUNDING_SHIFT as u8,
        );
        asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, 3);
    }
    super::prepare_right(code, operand);
    super::read_numerical_vector(code, operand.shape, operand.left, LEFT);
    super::read_numerical_vector(code, operand.shape, operand.addend, ADDEND);
    widen(code, lanes, LEFT, LEFT);
    widen(code, lanes, RIGHT, RIGHT);
    widen(code, lanes, ADDEND, ADDEND);
    if operand.operation.negate_left() || operand.operation.negate_addend() {
        ones(code, lanes, RESULT);
        shift(code, lanes, false, RESULT, RESULT, SIGN_BITS);
        if operand.operation.negate_left() {
            xor(code, lanes, LEFT, LEFT, RESULT);
        }
        if operand.operation.negate_addend() {
            xor(code, lanes, ADDEND, ADDEND, RESULT);
        }
    }
    // Exact product; rounded sum and its exact error (TwoSum).
    multiply(code, lanes, PRODUCT, LEFT, RIGHT);
    add(code, lanes, SUM, ADDEND, PRODUCT);
    subtract(code, lanes, SCRATCH, SUM, ADDEND);
    subtract(code, lanes, ERROR, SUM, SCRATCH);
    subtract(code, lanes, ERROR, ADDEND, ERROR);
    subtract(code, lanes, SCRATCH, PRODUCT, SCRATCH);
    add(code, lanes, ERROR, ERROR, SCRATCH);
    // A NaN or infinite input leaves a NaN or infinite product or sum.
    subtract(code, lanes, LEFT, SUM, SUM);
    subtract(code, lanes, RIGHT, PRODUCT, PRODUCT);
    add(code, lanes, LEFT, LEFT, RIGHT);
    compare(code, lanes, LEFT, LEFT, LEFT, UNORDERED);
    let finite = none_active(code, lanes, LEFT);
    code.asm().vzeroupper();
    other.push(jump(code));
    let finite_start = code.len();
    resolve(code, finite, finite_start);
    // An exact zero sum is -0 rounding toward minus infinity unless both
    // terms are +0; the host's rounding to nearest gave +0 there.
    const TOWARD_MINUS: i32 = 2;
    code.asm()
        .alu_imm8(Alu::Cmp, Size::Dword, Gpr::Rcx, TOWARD_MINUS as i8);
    let not_minus = branch(code, Condition::NotZero);
    xor(code, lanes, LEFT, LEFT, LEFT);
    compare(code, lanes, SCRATCH, SUM, LEFT, EQUAL);
    or(code, lanes, RIGHT, ADDEND, PRODUCT);
    ones(code, lanes, RESULT);
    shift(code, lanes, false, RESULT, RESULT, SIGN_BITS);
    and(code, lanes, RIGHT, RIGHT, RESULT);
    and(code, lanes, RIGHT, RIGHT, SCRATCH);
    or(code, lanes, SUM, SUM, RIGHT);
    let after_minus = code.len();
    resolve(code, not_minus, after_minus);
    // Round to odd: an inexact sum moves toward zero where the error has
    // the other sign, and gets its lowest bit set.
    xor(code, lanes, LEFT, LEFT, LEFT);
    compare(code, lanes, SCRATCH, ERROR, LEFT, NOT_EQUAL);
    xor(code, lanes, ERROR, ERROR, SUM);
    and(code, lanes, ERROR, ERROR, SCRATCH);
    ones(code, lanes, RIGHT);
    vex(
        code,
        lanes,
        (Map::M0f, Pp::P66),
        0xfe,
        PRODUCT,
        SUM,
        Rm::Xmm(RIGHT),
    );
    // VBLENDVPS SUM, SUM, PRODUCT, ERROR.
    vex(
        code,
        lanes,
        (Map::M0f3a, Pp::P66),
        0x4a,
        SUM,
        SUM,
        Rm::Xmm(PRODUCT),
    );
    code.asm().data(&[ERROR << 4]);
    shift(code, lanes, true, RIGHT, RIGHT, SIGN_BITS);
    and(code, lanes, RIGHT, RIGHT, SCRATCH);
    or(code, lanes, SUM, SUM, RIGHT);
    // One rounding to Half in FPCR's mode: Arm's RN, RP, RM, RZ are the
    // host immediates 0, 2, 1, 3.
    code.asm().test_imm(Size::Dword, Gpr::Rcx, 3);
    let directed = branch(code, Condition::NotZero);
    narrow(code, lanes, RESULT, SUM, 0);
    let mut rounded = vec![jump(code)];
    let directed_start = code.len();
    resolve(code, directed, directed_start);
    for (mode, immediate) in [(1, 2), (2, 1)] {
        code.asm().alu_imm8(Alu::Cmp, Size::Dword, Gpr::Rcx, mode);
        let next = branch(code, Condition::NotZero);
        narrow(code, lanes, RESULT, SUM, immediate);
        rounded.push(jump(code));
        let next_start = code.len();
        resolve(code, next, next_start);
    }
    narrow(code, lanes, RESULT, SUM, 3);
    let rounded_start = code.len();
    for patch in rounded {
        resolve(code, patch, rounded_start);
    }
    // Flags per lane: inexact where the Half differs from the odd sum, UFC
    // where such a lane is below Half's normal range before rounding (Arm's
    // rule; the odd sum is as tiny as the exact one), OFC where the Half
    // is infinite or every rounding overflows.
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rcx, Gpr::Rcx);
    widen(code, lanes, LEFT, RESULT);
    compare(code, lanes, SCRATCH, LEFT, SUM, NOT_EQUAL);
    flag_if_active(code, lanes, SCRATCH, INEXACT);
    ones(code, lanes, ERROR);
    shift(code, lanes, true, ERROR, ERROR, 1);
    and(code, lanes, SUM, SUM, ERROR);
    and(code, lanes, LEFT, LEFT, ERROR);
    constant(code, lanes, RIGHT, HALF_MINIMUM_NORMAL);
    compare(code, lanes, PRODUCT, SUM, RIGHT, LESS);
    and(code, lanes, PRODUCT, PRODUCT, SCRATCH);
    flag_if_active(code, lanes, PRODUCT, UNDERFLOW);
    constant(code, lanes, RIGHT, HALF_OVERFLOW);
    compare(code, lanes, PRODUCT, SUM, RIGHT, NOT_LESS);
    // Infinite Half: the magnitude compares equal to infinity's.
    constant(code, lanes, RIGHT, Format::Single.exponent_mask() as u32);
    compare(code, lanes, SCRATCH, LEFT, RIGHT, EQUAL);
    or(code, lanes, PRODUCT, PRODUCT, SCRATCH);
    flag_if_active(code, lanes, PRODUCT, OVERFLOW | INEXACT);
    code.asm().vzeroupper();
    code.asm().alu(
        Alu::Or,
        Size::Dword,
        guest(core::mem::offset_of!(GuestState, fpsr) as u32),
        Gpr::Rcx,
    );
    commit(code, operand.destination, RESULT);
    other
}
