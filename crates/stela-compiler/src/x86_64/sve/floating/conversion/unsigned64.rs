//! SSE2 conversions between single/double and unsigned 64-bit integers. The
//! caller owns the MXCSR frame, lane guards and staging.
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::FloatOp;
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};

use crate::aarch64::floating::Format;
use alloc::vec::Vec;

const SCALAR: u8 = 0;
const TEMPORARY: u8 = 7;
const INTEGER_HIGH_BIT: u8 = u64::BITS as u8 - 1;
const SINGLE_EXPONENT_BIAS: u64 = 127;
const DOUBLE_EXPONENT_BIAS: u64 = 1023;

fn check(format: Format) {
    assert!(
        matches!(format, Format::Single | Format::Double),
        "unsigned64 candidate admits only S/D"
    );
}

/// CVTSI2SS/CVTSI2SD XMM0 from RAX.
fn convert_from_integer(code: &mut Code, format: Format) {
    let mut asm = code.asm();
    if format == Format::Single {
        asm.cvtsi2float(FloatLanes::ScalarSingle, Size::Qword, SCALAR, Rax);
    } else {
        asm.cvtsi2float(FloatLanes::ScalarDouble, Size::Qword, SCALAR, Rax);
    }
}

/// CVTTSS2SI/CVTTSD2SI RAX from XMM0.
fn convert_to_integer(code: &mut Code, format: Format) {
    let mut asm = code.asm();
    if format == Format::Single {
        asm.cvtfloat2si(
            FloatLanes::ScalarSingle,
            true,
            Size::Qword,
            Rax,
            Rm::Xmm(SCALAR),
        );
    } else {
        asm.cvtfloat2si(
            FloatLanes::ScalarDouble,
            true,
            Size::Qword,
            Rax,
            Rm::Xmm(SCALAR),
        );
    }
}

fn unsigned_split_constant(code: &mut Code, format: Format) {
    let bias = match format {
        Format::Single => SINGLE_EXPONENT_BIAS,
        Format::Double => DOUBLE_EXPONENT_BIAS,
        Format::Half => unreachable!("unsigned64 candidate admits only S/D"),
    };
    let bits = (bias + u64::from(INTEGER_HIGH_BIT)) << format.fraction_bits();
    let mut asm = code.asm();
    asm.mov_imm64(Rdx, bits);
    asm.movq_to_xmm(TEMPORARY, Rdx);
}

/// Consume unsigned RAX, produce low S/D in XMM0. Upper XMM0 must start zero.
/// Scratch RAX/RCX and flags; preserves XMM1..7, RDX and all caller pointers.
/// Private MXCSR must contain effective guest RC, clear status and masked traps.
pub(crate) fn from_integer(code: &mut Code, format: Format) {
    check(format);
    let mut asm = code.asm();
    asm.test(Size::Qword, Rax, Rax);
    let low = asm.jcc(Cond::Ns);
    // For n >= 2^63, n/2 fits signed X. OR the discarded low bit into the
    // quotient: it retains sticky information for all four IEEE rounding modes.
    asm.mov(Size::Qword, Rcx, Rax);
    asm.alu_imm8(Alu::And, Size::Dword, Rcx, 1);
    asm.shift_one(ShiftOp::Shr, Size::Qword, Rax);
    asm.alu(Alu::Or, Size::Qword, Rax, Rcx);
    convert_from_integer(code, format);
    // The rounded quotient is normal and finite; doubling is exact, including
    // the rounded-up 2^63 quotient. Only the CVTSI can contribute host PE.
    let mut asm = code.asm();
    if format == Format::Single {
        asm.float(
            FloatOp::Add,
            FloatLanes::ScalarSingle,
            SCALAR,
            Rm::Xmm(SCALAR),
        );
    } else {
        asm.float(
            FloatOp::Add,
            FloatLanes::ScalarDouble,
            SCALAR,
            Rm::Xmm(SCALAR),
        );
    }
    let done = asm.jmp();
    asm.bind(low);
    convert_from_integer(code, format);
    code.asm().bind(done);
}

/// Consume low S/D XMM0, produce unsigned RAX. Scratch XMM0/XMM7/RDX/flags.
/// Caller must reject NaNs/subnormals, then reject all private status except PE.
/// This appends a negative-result failure to the shared transactional rollback.
pub(crate) fn to_integer(code: &mut Code, format: Format, failures: &mut Vec<usize>) {
    check(format);
    unsigned_split_constant(code, format);
    let mut asm = code.asm();
    if format == Format::Double {
        asm.ucomisd(SCALAR, Rm::Xmm(TEMPORARY));
    } else {
        asm.ucomiss(SCALAR, Rm::Xmm(TEMPORARY));
    }
    let low = asm.jcc(Cond::B);
    // Subtraction is exact on [2^63, 2^64) by Sterbenz. The remainder fits
    // signed X; restoring bit63 reconstructs the unsigned integer exactly.
    // >=2^64 and infinities instead raise private invalid and must roll back.
    if format == Format::Single {
        asm.float(
            FloatOp::Sub,
            FloatLanes::ScalarSingle,
            SCALAR,
            Rm::Xmm(TEMPORARY),
        );
    } else {
        asm.float(
            FloatOp::Sub,
            FloatLanes::ScalarDouble,
            SCALAR,
            Rm::Xmm(TEMPORARY),
        );
    }
    convert_to_integer(code, format);
    let mut asm = code.asm();
    asm.bit_imm(BitTest::Bts, Size::Qword, Rax, INTEGER_HIGH_BIT);
    let done = asm.jmp();
    asm.bind(low);
    convert_to_integer(code, format);
    // Negative fractions truncating to zero (and -0) are valid. Reject the
    // negative integer result, not the input sign. Private invalid catches the
    // signed sentinel too; the bit test alone never establishes success.
    let mut asm = code.asm();
    asm.bit_imm(BitTest::Bt, Size::Qword, Rax, INTEGER_HIGH_BIT);
    failures.push(asm.jcc(Cond::B).offset());
    asm.bind(done);
}
