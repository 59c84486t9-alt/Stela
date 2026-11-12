//! Vector Half FMLA/FMLS and scalar FMADD, FMSUB, FNMADD, FNMSUB and FMLA
//! by element on AVX2 hosts with F16C, in Single lanes (a scalar form's
//! status from lane 0 alone): the product of two Half values is exact in
//! Single, TwoSum gives the sum's exact error, and the sum rounded to odd
//! (24 bits, at least Half's 11 plus 2) rounds once more to Half exactly as
//! the one rounding Arm's FPMulAdd makes. Zeros and subnormal inputs need
//! nothing apart. Lanes with a NaN or infinite input take Arm's result from
//! [`special_lanes`] and rerun as zeros. FZ16 flushes subnormal inputs
//! inline; a result it may flush, a quiet NaN addend with a NaN product, AH
//! and enabled traps take the caller's other path.
use super::super::numerical::{Condition, branch, jump, resolve, test_control};
use super::super::{Host, commit, encode::guest, half as lanes, packed};
use crate::x86_64::asm::{Alu, Code, Gpr, Map, Mem, Pp, Rm, ShiftOp, Size, Vex};
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FZ16, FPCR_ROUNDING_SHIFT, Format,
            INEXACT, INVALID, OVERFLOW, UNDERFLOW,
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
const LESS_EQUAL: u8 = 2;
const UNORDERED: u8 = 3;
const NOT_EQUAL: u8 = 4;
const NOT_LESS: u8 = 5;

/// Single bits of Half's smallest normal, 2^-14.
const HALF_MINIMUM_NORMAL: u32 = 0x3880_0000;
/// Single bits of 2^16: a magnitude from which every rounding overflows Half.
const HALF_OVERFLOW: u32 = 0x4780_0000;
const SIGN_BITS: u8 = 31;

/// Whether this recipe serves `operand` on `target`.
pub(super) fn supported(target: TargetCpu) -> bool {
    target.supports(TargetCpu::Avx2)
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

/// The Half inputs: Vn in LEFT, Vm (or its broadcast element) in RIGHT and
/// the addend in ADDEND, each subnormal lane flushed to its signed zero
/// under FZ16 (which raises no IDC for Half). Clobbers XMM3 to XMM5, XMM7
/// and EAX.
fn read_inputs(code: &mut Code, operand: &Operand) {
    super::prepare_right(code, operand);
    super::read_numerical_vector(code, operand.shape, operand.left, LEFT);
    super::read_numerical_vector(code, operand.shape, operand.addend, ADDEND);
    test_control(code, FPCR_FZ16);
    let kept = branch(code, Condition::Zero);
    let words = &Lanes {
        wide: false,
        active: 0,
    };
    constant(code, words, PRODUCT, HALF_INFINITY);
    constant(code, words, SUM, HALF_MAGNITUDE);
    word(code, PXOR, RESULT, RESULT, RESULT);
    for input in [LEFT, RIGHT, ADDEND] {
        // The magnitude of a lane whose exponent field is zero.
        word(code, PAND, SCRATCH, input, PRODUCT);
        word(code, PCMPEQW, SCRATCH, SCRATCH, RESULT);
        word(code, PAND, SCRATCH, SCRATCH, SUM);
        word(code, PANDN, input, SCRATCH, input);
    }
    let end = code.len();
    resolve(code, kept, end);
}

const PAND: u8 = 0xdb;
const PANDN: u8 = 0xdf;
const POR: u8 = 0xeb;
const PXOR: u8 = 0xef;
const PCMPEQW: u8 = 0x75;
const PCMPGTW: u8 = 0x65;

const WORDS: Vex = Vex {
    map: Map::M0f,
    pp: Pp::P66,
    w: false,
    l: false,
};

/// `destination = left op right` on the eight words of XMM registers
/// (VEX.128.66.0F `opcode`; PANDN is `!left & right`).
fn word(code: &mut Code, opcode: u8, destination: u8, left: u8, right: u8) {
    code.asm()
        .vex(WORDS, opcode, destination, left, Rm::Xmm(right));
}

/// VPSRLW (`extension` 2), VPSRAW (4) or VPSLLW (6) by `count`.
fn word_shift(code: &mut Code, extension: u8, destination: u8, source: u8, count: u8) {
    code.asm()
        .vex(WORDS, 0x71, extension, destination, Rm::Xmm(source));
    code.asm().data(&[count]);
}

/// `destination = mask ? right : left` per byte (VPBLENDVB).
fn word_blend(code: &mut Code, destination: u8, left: u8, right: u8, mask: u8) {
    code.asm().vex(
        Vex {
            map: Map::M0f3a,
            ..WORDS
        },
        0x4c,
        destination,
        left,
        Rm::Xmm(right),
    );
    code.asm().data(&[mask << 4]);
}

/// `destination` = the words of `source` that are NaN, against the
/// infinity words in `infinity`.
fn word_nan(code: &mut Code, destination: u8, source: u8, infinity: u8) {
    word_shift(code, 6, destination, source, 1);
    word_shift(code, 2, destination, destination, 1);
    word(code, PCMPGTW, destination, destination, infinity);
}

/// ZF clear when the word mask `xmm` has an active lane (VPMOVMSKB into
/// EAX).
fn test_active_words(code: &mut Code, lanes: &Lanes, xmm: u8) {
    code.asm().vex(WORDS, 0xd7, 0, 0, Rm::Xmm(xmm));
    // Two mask bits per word.
    let bytes = match lanes.active {
        0xff => 0xffff,
        0xf => 0xff,
        _ => 0x3,
    };
    code.asm().test_imm(Size::Dword, Gpr::Rax, bytes);
}

/// R8D's mark that the special lanes' Half results are on the stack.
const SPECIAL_SAVED: u32 = 1 << 8;
/// The stack frame holding the special results and a spilled mask.
const SPECIAL_FRAME_BYTES: i8 = 32;
const SPILL: i32 = 16;
const HALF_INFINITY: u32 = 0x7c00_7c00;
const HALF_QUIET: u32 = 0x0200_0200;
const HALF_DEFAULT_NAN: u32 = 0x7e00_7e00;
const HALF_MAGNITUDE: u32 = 0x7fff_7fff;
const SIGN_WORD: u8 = 15;
const QUIET_TO_SIGN: u8 = 6;

/// Lanes with an infinite or NaN input: Arm's FPMulAdd results go on the
/// stack (zero in the other lanes) and their IOC into R8D, and their inputs
/// become zeros whose negated product and sum are +0 with no status, so the
/// caller reruns the finite recipe and ORs the results in. A NaN input
/// gives the first signaling NaN of the addend, the (negated) Vn and Vm,
/// else the first quiet one, quieted (the default NaN under DN), with IOC
/// for a signaling one; infinities give the infinity, or the default NaN
/// with IOC for infinity times zero or opposite infinities. A quiet NaN
/// addend with a NaN product (Arm's default NaN for infinity times zero)
/// takes `other`. Clobbers XMM0 to XMM7 and EAX.
fn special_lanes(code: &mut Code, operand: &Operand, lanes: &Lanes, other: &mut Vec<usize>) {
    let words = &Lanes {
        wide: false,
        active: lanes.active,
    };
    const INFINITY: u8 = PRODUCT;
    const ANY_NAN: u8 = SUM;
    const SIGNALING: u8 = SCRATCH;
    const MASK: u8 = ERROR;
    const SELECTED: u8 = RESULT;
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SPECIAL_FRAME_BYTES);
    read_inputs(code, operand);
    let negate = |code: &mut Code| {
        if operand.operation.negate_left() || operand.operation.negate_addend() {
            ones(code, words, MASK);
            word_shift(code, 6, MASK, MASK, SIGN_WORD);
            if operand.operation.negate_left() {
                word(code, PXOR, LEFT, LEFT, MASK);
            }
            if operand.operation.negate_addend() {
                word(code, PXOR, ADDEND, ADDEND, MASK);
            }
        }
    };
    negate(code);
    constant(code, words, INFINITY, HALF_INFINITY);
    // Quiet NaNs in reverse order of priority, then signaling ones.
    packed(code, Host::MoveAligned, SELECTED, RIGHT);
    word_nan(code, ANY_NAN, RIGHT, INFINITY);
    for input in [LEFT, ADDEND] {
        word_nan(code, MASK, input, INFINITY);
        word(code, POR, ANY_NAN, ANY_NAN, MASK);
        word_blend(code, SELECTED, SELECTED, input, MASK);
    }
    Host::StoreUnaligned.emit(
        code,
        ANY_NAN,
        Mem::base(Gpr::Rsp, SPILL),
        TargetCpu::Baseline,
    );
    word(code, PXOR, SIGNALING, SIGNALING, SIGNALING);
    for input in [RIGHT, LEFT, ADDEND] {
        word_nan(code, MASK, input, INFINITY);
        // ANY_NAN = the quiet bit, as a mask.
        word_shift(code, 6, ANY_NAN, input, QUIET_TO_SIGN);
        word_shift(code, 4, ANY_NAN, ANY_NAN, SIGN_WORD);
        word(code, PANDN, MASK, ANY_NAN, MASK);
        word(code, POR, SIGNALING, SIGNALING, MASK);
        word_blend(code, SELECTED, SELECTED, input, MASK);
    }
    constant(code, words, MASK, HALF_QUIET);
    word(code, POR, SELECTED, SELECTED, MASK);
    test_control(code, FPCR_DN);
    let propagate = branch(code, Condition::Zero);
    constant(code, words, SELECTED, HALF_DEFAULT_NAN);
    let after_default = code.len();
    resolve(code, propagate, after_default);
    test_active_words(code, lanes, SIGNALING);
    let quiet = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Or, Size::Dword, Gpr::R8, INVALID as i8);
    let after_signaling = code.len();
    resolve(code, quiet, after_signaling);
    // A quiet NaN addend with a NaN product takes `other`.
    widen(code, lanes, ANY_NAN, LEFT);
    widen(code, lanes, MASK, RIGHT);
    multiply(code, lanes, ANY_NAN, ANY_NAN, MASK);
    narrow(code, lanes, ANY_NAN, ANY_NAN, 0);
    word_nan(code, MASK, ANY_NAN, INFINITY);
    word_nan(code, SIGNALING, ADDEND, INFINITY);
    word(code, PAND, MASK, MASK, SIGNALING);
    word_shift(code, 6, SIGNALING, ADDEND, QUIET_TO_SIGN);
    word_shift(code, 4, SIGNALING, SIGNALING, SIGN_WORD);
    word(code, PAND, MASK, MASK, SIGNALING);
    test_active_words(code, lanes, MASK);
    let ordinary = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SPECIAL_FRAME_BYTES);
    code.asm().vzeroupper();
    other.push(jump(code));
    let ordinary_start = code.len();
    resolve(code, ordinary, ordinary_start);
    // Without a NaN input: the infinity, or a host NaN (invalid).
    widen(code, lanes, ANY_NAN, LEFT);
    widen(code, lanes, MASK, RIGHT);
    multiply(code, lanes, ANY_NAN, ANY_NAN, MASK);
    widen(code, lanes, MASK, ADDEND);
    add(code, lanes, ANY_NAN, MASK, ANY_NAN);
    narrow(code, lanes, ANY_NAN, ANY_NAN, 0);
    word_nan(code, SIGNALING, ANY_NAN, INFINITY);
    Host::LoadUnaligned.emit(code, MASK, Mem::base(Gpr::Rsp, SPILL), TargetCpu::Baseline);
    word(code, PANDN, SIGNALING, MASK, SIGNALING);
    test_active_words(code, lanes, SIGNALING);
    let valid = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Or, Size::Dword, Gpr::R8, INVALID as i8);
    let after_invalid = code.len();
    resolve(code, valid, after_invalid);
    word_blend(code, SELECTED, ANY_NAN, SELECTED, MASK);
    constant(code, words, ANY_NAN, HALF_DEFAULT_NAN);
    word_blend(code, SELECTED, SELECTED, ANY_NAN, SIGNALING);
    // MASK = the special lanes: an input exponent field all ones.
    word(code, PXOR, MASK, MASK, MASK);
    for input in [LEFT, RIGHT, ADDEND] {
        word(code, PAND, SIGNALING, input, INFINITY);
        word(code, PCMPEQW, SIGNALING, SIGNALING, INFINITY);
        word(code, POR, MASK, MASK, SIGNALING);
    }
    word(code, PAND, SELECTED, SELECTED, MASK);
    Host::StoreUnaligned.emit(code, SELECTED, Mem::base(Gpr::Rsp, 0), TargetCpu::Baseline);
    code.asm()
        .alu_imm32(Alu::Or, Size::Dword, Gpr::R8, SPECIAL_SAVED as i32);
    // Zeros in the special lanes, negated back to the inputs.
    for input in [LEFT, RIGHT, ADDEND] {
        word(code, PANDN, input, MASK, input);
    }
    negate(code);
}

/// Emit the recipe; returns the branches to the caller's other path, which
/// it enters with the state untouched, the inputs reread and no YMM upper
/// half in use.
pub(super) fn emit(code: &mut Code, operand: &Operand) -> Vec<usize> {
    let lanes = Lanes {
        wide: operand.shape == Shape::Vector128,
        active: match operand.shape {
            Shape::Vector128 => 0xff,
            Shape::Vector64 => 0xf,
            Shape::Scalar => 0x1,
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
            (FPCR_EXCEPTION_ENABLE_MASK | FPCR_AH) as i32,
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
    // R8D: the special lanes' IOC, and SPECIAL_SAVED once their results
    // are on the stack.
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::R8, Gpr::R8);
    read_inputs(code, operand);
    let arithmetic = code.len();
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
    special_lanes(code, operand, lanes, &mut other);
    let again = jump(code);
    resolve(code, again, arithmetic);
    let finite_start = code.len();
    resolve(code, finite, finite_start);
    // Under FZ16 a lane Arm may flush (a nonzero sum at most 2^-14, the
    // exact one being tiny only then) takes `other`.
    test_control(code, FPCR_FZ16);
    let unflushed = branch(code, Condition::Zero);
    ones(code, lanes, RESULT);
    shift(code, lanes, true, RESULT, RESULT, 1);
    and(code, lanes, LEFT, SUM, RESULT);
    constant(code, lanes, RIGHT, HALF_MINIMUM_NORMAL);
    compare(code, lanes, SCRATCH, LEFT, RIGHT, LESS_EQUAL);
    xor(code, lanes, RIGHT, RIGHT, RIGHT);
    compare(code, lanes, LEFT, LEFT, RIGHT, NOT_EQUAL);
    and(code, lanes, SCRATCH, SCRATCH, LEFT);
    let none = none_active(code, lanes, SCRATCH);
    code.asm()
        .test_imm(Size::Dword, Gpr::R8, SPECIAL_SAVED as i32);
    let unsaved = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SPECIAL_FRAME_BYTES);
    let unsaved_start = code.len();
    resolve(code, unsaved, unsaved_start);
    code.asm().vzeroupper();
    other.push(jump(code));
    let ordinary = code.len();
    resolve(code, unflushed, ordinary);
    resolve(code, none, ordinary);
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
    // The special lanes' results (their computed lanes are +0) and IOC.
    code.asm()
        .test_imm(Size::Dword, Gpr::R8, SPECIAL_SAVED as i32);
    let ordinary = branch(code, Condition::Zero);
    Host::LoadUnaligned.emit(code, SCRATCH, Mem::base(Gpr::Rsp, 0), TargetCpu::Baseline);
    word(code, POR, RESULT, RESULT, SCRATCH);
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SPECIAL_FRAME_BYTES);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::R8, INVALID as i8);
    asm.alu(Alu::Or, Size::Dword, Gpr::Rcx, Gpr::R8);
    let after_special = code.len();
    resolve(code, ordinary, after_special);
    code.asm().vzeroupper();
    code.asm().alu(
        Alu::Or,
        Size::Dword,
        guest(core::mem::offset_of!(GuestState, fpsr) as u32),
        Gpr::Rcx,
    );
    if operand.shape == Shape::Scalar {
        // Lane 0 alone, or under FPCR.NEP in the unnegated Va's other bits.
        let mut asm = code.asm();
        asm.movd_from_xmm(Gpr::Rax, RESULT);
        asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rax, 0xffff);
        asm.movq_to_xmm(lanes::LEFT, Gpr::Rax);
        super::super::read_vector(code, operand.addend, lanes::ORIGINAL_LEFT);
        lanes::merge_scalar(code);
        commit(code, operand.destination, lanes::LEFT);
    } else {
        commit(code, operand.destination, RESULT);
    }
    other
}
