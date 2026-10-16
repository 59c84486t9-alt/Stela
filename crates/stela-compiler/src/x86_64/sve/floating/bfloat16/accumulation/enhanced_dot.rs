//! Guarded SSE2 enhanced BFDOT over one 128-bit architectural chunk.
//!
//! Caller owns the shared PrivateMxcsr frame, installs the guest rounding mode
//! with DAZ/FTZ clear, and stages XMM0 only after this function. This function
//! performs no calls, frame allocation, state writes, or architectural commits.
//! Inputs XMM0/XMM1 are eight BF16 values; XMM6 is four Single accumulators.
//! Output XMM0 is four Singles. XMM1/XMM6 and RDI/R15/callee-saved GPRs survive.
//! XMM2/3/4/5/7, RAX/RCX and flags are clobbered; RDX survives. Host status is
//! discarded; caller must not add it to FPSR and must restore original MXCSR.

use crate::x86_64::scalable::numerical;
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const WORK_LEFT: u8 = 2;
const WORK_RIGHT: u8 = 3;
const WORK_PAIR: u8 = 4;
const OUTPUT: u8 = 5;
const ACCUMULATOR: u8 = 6;
const WORK_MASK: u8 = 7;
const EAX: u8 = 0;
const SIGN_DISCARD_SHIFT: u8 = 1;
const DOUBLE_SIGN_BIT: u8 = 63;
const DWORD_BITS: u8 = 32;
const REGISTER_MODRM: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const REL32_BYTES: usize = core::mem::size_of::<i32>();
const CONDITIONAL_ESCAPE: u8 = 0x0f;
const EQUAL: u8 = 0x84;
const NOT_EQUAL: u8 = 0x85;
const BELOW: u8 = 0x82;
const BELOW_OR_EQUAL: u8 = 0x86;
const BFLOAT_EXPONENT_PAIR: u32 = 0x7f80_7f80;
const SINGLE_EXPONENT: u32 = 0x7f80_0000;
const SINGLE_MAGNITUDE: u32 = 0x7fff_ffff;
const SINGLE_MINIMUM_NORMAL: u32 = 0x0080_0000;
const SINGLE_MINIMUM_NORMAL_AS_DOUBLE: u64 = 0x3810_0000_0000_0000;
const BFLOAT_TO_SINGLE_SHIFT: u8 = 16;
const HALF_CHUNK_BYTES: u8 = 8;
const UPPER_TWO_SINGLES: u8 = 0xee;
const SPLAT_LOW_DWORD: u8 = 0;

const MOVDQA: &[u8] = &[0x66, 0x0f, 0x6f];
const MOVQ_XMM: &[u8] = &[0xf3, 0x0f, 0x7e];
const PXOR: &[u8] = &[0x66, 0x0f, 0xef];
const PAND: &[u8] = &[0x66, 0x0f, 0xdb];
const PANDN: &[u8] = &[0x66, 0x0f, 0xdf];
const POR: &[u8] = &[0x66, 0x0f, 0xeb];
const PCMPEQW: &[u8] = &[0x66, 0x0f, 0x75];
const PCMPEQD: &[u8] = &[0x66, 0x0f, 0x76];
const PUNPCKLWD: &[u8] = &[0x66, 0x0f, 0x61];
const PSHUFD: &[u8] = &[0x66, 0x0f, 0x70];
const PSLLW_IMM: &[u8] = &[0x66, 0x0f, 0x71];
const PSLLD_IMM: &[u8] = &[0x66, 0x0f, 0x72];
const PSRLDQ_IMM: &[u8] = &[0x66, 0x0f, 0x73];
const SHIFT_LEFT_GROUP: u8 = 6;
const SHIFT_RIGHT_BYTES_GROUP: u8 = 3;
const CVTPS2PD: &[u8] = &[0x0f, 0x5a];
const CVTPD2PS: &[u8] = &[0x66, 0x0f, 0x5a];
const MULPD: &[u8] = &[0x66, 0x0f, 0x59];
const ADDPD: &[u8] = &[0x66, 0x0f, 0x58];
const ADDPS: &[u8] = &[0x0f, 0x58];
const UNPCKLPD: &[u8] = &[0x66, 0x0f, 0x14];
const UNPCKHPD: &[u8] = &[0x66, 0x0f, 0x15];
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const PMOVMSKB_EAX_XMM: &[u8] = &[0x66, 0x0f, 0xd7];
const MOV_EAX_IMM32: u8 = 0xb8;
const MOV_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const CMP_ECX_IMM32: &[u8] = &[0x81, 0xf9];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const CMP_RAX_RCX: &[u8] = &[0x48, 0x39, 0xc8];
const BTR_RAX_SIGN: &[u8] = &[0x48, 0x0f, 0xba, 0xf0, DOUBLE_SIGN_BIT];
const SHR_RAX_DWORD: &[u8] = &[0x48, 0xc1, 0xe8, DWORD_BITS];

fn vector(code: &mut Vec<u8>, opcode: &[u8], destination: u8, source: u8) {
    code.extend(opcode);
    code.push(REGISTER_MODRM | destination << MODRM_REGISTER_SHIFT | source);
}

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, lanes: u8) {
    vector(code, PSHUFD, destination, source);
    code.push(lanes);
}

fn shift(code: &mut Vec<u8>, opcode: &[u8], group: u8, register: u8, amount: u8) {
    code.extend(opcode);
    code.extend([
        REGISTER_MODRM | group << MODRM_REGISTER_SHIFT | register,
        amount,
    ]);
}

fn branch(code: &mut Vec<u8>, condition: u8) -> usize {
    code.extend([CONDITIONAL_ESCAPE, condition]);
    let displacement = code.len();
    code.extend([0; REL32_BYTES]);
    displacement
}

fn skip_to_here(code: &mut [u8], displacement: usize) {
    let relative = i32::try_from(code.len() - displacement - REL32_BYTES)
        .expect("bounded enhanced BFDOT chunk");
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&relative.to_le_bytes());
}

fn mask(code: &mut Vec<u8>, value: u32) {
    code.push(MOV_EAX_IMM32);
    code.extend(value.to_le_bytes());
    vector(code, MOVD_XMM_EAX, WORK_MASK, EAX);
    shuffle(code, WORK_MASK, WORK_MASK, SPLAT_LOW_DWORD);
}

fn reject_mask(code: &mut Vec<u8>, register: u8, failures: &mut Vec<usize>) {
    vector(code, PMOVMSKB_EAX_XMM, EAX, register);
    code.extend(TEST_EAX_EAX);
    failures.push(branch(code, NOT_EQUAL));
}

fn guard_bfloat(code: &mut Vec<u8>, source: u8, failures: &mut Vec<usize>) {
    vector(code, MOVDQA, WORK_LEFT, source);
    vector(code, PAND, WORK_LEFT, WORK_MASK);
    vector(code, MOVDQA, WORK_RIGHT, WORK_LEFT);
    vector(code, PCMPEQW, WORK_RIGHT, WORK_MASK);
    vector(code, PCMPEQW, WORK_LEFT, OUTPUT);
    vector(code, MOVDQA, WORK_PAIR, source);
    shift(
        code,
        PSLLW_IMM,
        SHIFT_LEFT_GROUP,
        WORK_PAIR,
        SIGN_DISCARD_SHIFT,
    );
    vector(code, PCMPEQW, WORK_PAIR, OUTPUT);
    vector(code, PANDN, WORK_PAIR, WORK_LEFT);
    vector(code, POR, WORK_RIGHT, WORK_PAIR);
    reject_mask(code, WORK_RIGHT, failures);
}

fn guard_accumulator(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    vector(code, MOVDQA, WORK_LEFT, ACCUMULATOR);
    shift(
        code,
        PSLLD_IMM,
        SHIFT_LEFT_GROUP,
        WORK_LEFT,
        SIGN_DISCARD_SHIFT,
    );
    vector(code, PCMPEQD, WORK_LEFT, OUTPUT);
    vector(code, MOVDQA, WORK_RIGHT, ACCUMULATOR);
    vector(code, PAND, WORK_RIGHT, WORK_MASK);
    vector(code, MOVDQA, WORK_PAIR, WORK_RIGHT);
    vector(code, PCMPEQD, WORK_RIGHT, OUTPUT);
    vector(code, PANDN, WORK_LEFT, WORK_RIGHT);
    vector(code, PCMPEQD, WORK_PAIR, WORK_MASK);
    vector(code, POR, WORK_LEFT, WORK_PAIR);
    reject_mask(code, WORK_LEFT, failures);
}

fn guard_double(code: &mut Vec<u8>, register: u8, failures: &mut Vec<usize>) {
    // All inputs/products/sums are finite Double. Unsigned magnitude bits sort
    // numerically. Strict > excludes pre-round tininess obscured by directed
    // rounding up to min-normal; exact signed zero is admitted separately.
    vector(code, MOVQ_RAX_XMM, register, EAX);
    code.extend(BTR_RAX_SIGN);
    code.extend(TEST_RAX_RAX);
    let zero = branch(code, EQUAL);
    code.extend(MOV_RCX_IMM64);
    code.extend(SINGLE_MINIMUM_NORMAL_AS_DOUBLE.to_le_bytes());
    code.extend(CMP_RAX_RCX);
    failures.push(branch(code, BELOW_OR_EQUAL));
    skip_to_here(code, zero);
}

fn guard_single(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(MOV_ECX_EAX);
    code.extend(AND_ECX_IMM32);
    code.extend(SINGLE_MAGNITUDE.to_le_bytes());
    code.extend(TEST_ECX_ECX);
    let zero = branch(code, EQUAL);
    code.extend(CMP_ECX_IMM32);
    code.extend(SINGLE_MINIMUM_NORMAL.to_le_bytes());
    failures.push(branch(code, BELOW));
    skip_to_here(code, zero);
}

fn product_pair(code: &mut Vec<u8>, upper: bool) {
    vector(code, PXOR, WORK_MASK, WORK_MASK);
    vector(code, MOVDQA, WORK_LEFT, LEFT);
    vector(code, MOVDQA, WORK_RIGHT, RIGHT);
    if upper {
        shift(
            code,
            PSRLDQ_IMM,
            SHIFT_RIGHT_BYTES_GROUP,
            WORK_LEFT,
            HALF_CHUNK_BYTES,
        );
        shift(
            code,
            PSRLDQ_IMM,
            SHIFT_RIGHT_BYTES_GROUP,
            WORK_RIGHT,
            HALF_CHUNK_BYTES,
        );
    }
    for register in [WORK_LEFT, WORK_RIGHT] {
        vector(code, PUNPCKLWD, register, WORK_MASK);
        shift(
            code,
            PSLLD_IMM,
            SHIFT_LEFT_GROUP,
            register,
            BFLOAT_TO_SINGLE_SHIFT,
        );
    }
    vector(code, CVTPS2PD, WORK_PAIR, WORK_LEFT);
    vector(code, CVTPS2PD, WORK_MASK, WORK_RIGHT);
    vector(code, MULPD, WORK_PAIR, WORK_MASK);
    shuffle(code, WORK_LEFT, WORK_LEFT, UPPER_TWO_SINGLES);
    shuffle(code, WORK_RIGHT, WORK_RIGHT, UPPER_TWO_SINGLES);
    vector(code, CVTPS2PD, WORK_LEFT, WORK_LEFT);
    vector(code, CVTPS2PD, WORK_RIGHT, WORK_RIGHT);
    vector(code, MULPD, WORK_LEFT, WORK_RIGHT);
    vector(code, MOVDQA, WORK_RIGHT, WORK_PAIR);
    vector(code, UNPCKLPD, WORK_RIGHT, WORK_LEFT);
    vector(code, UNPCKHPD, WORK_PAIR, WORK_LEFT);
    vector(code, ADDPD, WORK_RIGHT, WORK_PAIR);
}

/// Shared-frame guarded enhanced branch. Failures target the outer frame's
/// common cleanup; pending guest FPSR must remain zero throughout this branch.
pub(super) fn emit_chunk(code: &mut Vec<u8>, _frame: &numerical::Frame, failures: &mut Vec<usize>) {
    vector(code, PXOR, OUTPUT, OUTPUT);
    mask(code, BFLOAT_EXPONENT_PAIR);
    guard_bfloat(code, LEFT, failures);
    guard_bfloat(code, RIGHT, failures);
    mask(code, SINGLE_EXPONENT);
    guard_accumulator(code, failures);
    for upper in [false, true] {
        product_pair(code, upper);
        guard_double(code, WORK_RIGHT, failures);
        vector(code, MOVDQA, WORK_PAIR, WORK_RIGHT);
        vector(code, UNPCKHPD, WORK_PAIR, WORK_PAIR);
        guard_double(code, WORK_PAIR, failures);
        vector(code, CVTPD2PS, WORK_RIGHT, WORK_RIGHT);
        if upper {
            shuffle(code, WORK_PAIR, ACCUMULATOR, UPPER_TWO_SINGLES);
            vector(code, ADDPS, WORK_RIGHT, WORK_PAIR);
        } else {
            vector(code, ADDPS, WORK_RIGHT, ACCUMULATOR);
        }
        vector(code, MOVQ_RAX_XMM, WORK_RIGHT, EAX);
        guard_single(code, failures);
        code.extend(SHR_RAX_DWORD);
        guard_single(code, failures);
        if upper {
            vector(code, UNPCKLPD, OUTPUT, WORK_RIGHT);
        } else {
            vector(code, MOVQ_XMM, OUTPUT, WORK_RIGHT);
        }
    }
    vector(code, MOVDQA, LEFT, OUTPUT);
}
