//! SSE2 conversions between single/double and unsigned 64-bit integers. The
//! caller owns the MXCSR frame, lane guards and staging.

use crate::aarch64::floating::Format;
use alloc::vec::Vec;

const SCALAR: u8 = 0;
const TEMPORARY: u8 = 7;
const DATA_GPR: u8 = 2;
const INTEGER_HIGH_BIT: u8 = u64::BITS as u8 - 1;
const SINGLE_EXPONENT_BIAS: u64 = 127;
const DOUBLE_EXPONENT_BIAS: u64 = 1023;
const SINGLE_PREFIX: u8 = 0xf3;
const DOUBLE_PREFIX: u8 = 0xf2;
const SSE_ESCAPE: u8 = 0x0f;
const REX_W: u8 = 0x48;
const REGISTER_DIRECT: u8 = 0xc0;
const REGISTER_FIELD_SHIFT: u8 = 3;
const CVTSI_TO_FLOAT: u8 = 0x2a;
const CVTT_TO_INTEGER: u8 = 0x2c;
const ADD_SCALAR: u8 = 0x58;
const SUBTRACT_SCALAR: u8 = 0x5c;
const UCOMIS: u8 = 0x2e;
const DOUBLE_COMPARE_PREFIX: u8 = 0x66;
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const AND_ECX_ONE: &[u8] = &[0x83, 0xe1, 1];
const SHR_RAX_ONE: &[u8] = &[0x48, 0xd1, 0xe8];
const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
const MOVABS_RDX: &[u8] = &[0x48, 0xba];
const MOVQ_XMM_RDX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e];
const BT_RAX_IMMEDIATE: &[u8] = &[0x48, 0x0f, 0xba, 0xe0];
const BTS_RAX_IMMEDIATE: &[u8] = &[0x48, 0x0f, 0xba, 0xe8];
const JNS_REL32: &[u8] = &[0x0f, 0x89];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const JMP_REL32: &[u8] = &[0xe9];

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn resolve(code: &mut [u8], displacement: usize, destination: usize) {
    let next = displacement + size_of::<i32>();
    let relative = i32::try_from(destination as isize - next as isize)
        .expect("conversion lane branch fits rel32");
    code[displacement..next].copy_from_slice(&relative.to_le_bytes());
}

fn prefix(format: Format) -> u8 {
    match format {
        Format::Single => SINGLE_PREFIX,
        Format::Double => DOUBLE_PREFIX,
        Format::Half => unreachable!("unsigned64 candidate admits only S/D"),
    }
}

fn convert(code: &mut Vec<u8>, format: Format, opcode: u8) {
    // Both directions use RAX and XMM0; the opcode assigns their roles.
    code.extend([prefix(format), REX_W, SSE_ESCAPE, opcode, REGISTER_DIRECT]);
}

fn scalar(code: &mut Vec<u8>, format: Format, opcode: u8, source: u8) {
    code.extend([
        prefix(format),
        SSE_ESCAPE,
        opcode,
        REGISTER_DIRECT | (SCALAR << REGISTER_FIELD_SHIFT) | source,
    ]);
}

fn unsigned_split_constant(code: &mut Vec<u8>, format: Format) {
    let bias = match format {
        Format::Single => SINGLE_EXPONENT_BIAS,
        Format::Double => DOUBLE_EXPONENT_BIAS,
        Format::Half => unreachable!("unsigned64 candidate admits only S/D"),
    };
    let bits = (bias + u64::from(INTEGER_HIGH_BIT)) << format.fraction_bits();
    code.extend(MOVABS_RDX);
    code.extend(bits.to_le_bytes());
    code.extend(MOVQ_XMM_RDX);
    code.push(REGISTER_DIRECT | (TEMPORARY << REGISTER_FIELD_SHIFT) | DATA_GPR);
}

/// Consume unsigned RAX, produce low S/D in XMM0. Upper XMM0 must start zero.
/// Scratch RAX/RCX and flags; preserves XMM1..7, RDX and all caller pointers.
/// Private MXCSR must contain effective guest RC, clear status and masked traps.
pub(crate) fn from_integer(code: &mut Vec<u8>, format: Format) {
    let _ = prefix(format); // Reject a violated S/D contract before emitting bytes.
    code.extend(TEST_RAX_RAX);
    let low = branch(code, JNS_REL32);
    // For n >= 2^63, n/2 fits signed X. OR the discarded low bit into the
    // quotient: it retains sticky information for all four IEEE rounding modes.
    code.extend(MOV_RCX_RAX);
    code.extend(AND_ECX_ONE);
    code.extend(SHR_RAX_ONE);
    code.extend(OR_RAX_RCX);
    convert(code, format, CVTSI_TO_FLOAT);
    // The rounded quotient is normal and finite; doubling is exact, including
    // the rounded-up 2^63 quotient. Only the CVTSI can contribute host PE.
    scalar(code, format, ADD_SCALAR, SCALAR);
    let done = branch(code, JMP_REL32);
    let low_start = code.len();
    resolve(code, low, low_start);
    convert(code, format, CVTSI_TO_FLOAT);
    let end = code.len();
    resolve(code, done, end);
}

/// Consume low S/D XMM0, produce unsigned RAX. Scratch XMM0/XMM7/RDX/flags.
/// Caller must reject NaNs/subnormals, then reject all private status except PE.
/// This appends a negative-result failure to the shared transactional rollback.
pub(crate) fn to_integer(code: &mut Vec<u8>, format: Format, failures: &mut Vec<usize>) {
    let _ = prefix(format);
    unsigned_split_constant(code, format);
    if format == Format::Double {
        code.push(DOUBLE_COMPARE_PREFIX);
    }
    code.extend([
        SSE_ESCAPE,
        UCOMIS,
        REGISTER_DIRECT | (SCALAR << REGISTER_FIELD_SHIFT) | TEMPORARY,
    ]);
    let low = branch(code, JB_REL32);
    // Subtraction is exact on [2^63, 2^64) by Sterbenz. The remainder fits
    // signed X; restoring bit63 reconstructs the unsigned integer exactly.
    // >=2^64 and infinities instead raise private invalid and must roll back.
    scalar(code, format, SUBTRACT_SCALAR, TEMPORARY);
    convert(code, format, CVTT_TO_INTEGER);
    code.extend(BTS_RAX_IMMEDIATE);
    code.push(INTEGER_HIGH_BIT);
    let done = branch(code, JMP_REL32);
    let low_start = code.len();
    resolve(code, low, low_start);
    convert(code, format, CVTT_TO_INTEGER);
    // Negative fractions truncating to zero (and -0) are valid. Reject the
    // negative integer result, not the input sign. Private invalid catches the
    // signed sentinel too; the bit test alone never establishes success.
    code.extend(BT_RAX_IMMEDIATE);
    code.push(INTEGER_HIGH_BIT);
    failures.push(branch(code, JB_REL32));
    let end = code.len();
    resolve(code, done, end);
}
