//! Exact-Double BF16 fused arithmetic with transactional exceptional fallback.
//!
//! Nearby operand exponents make the BF16 product and sum exact in Double.
//! Integer round-to-odd compression supplies a Single-shaped representation to
//! the shared BF16 rounding selectors, without a host Double-to-Single rounding.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, INEXACT, features::NumericalFeatures},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::{
            dot::RightOperand,
            floating::bfloat16::{Kind, Operand},
        },
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            Condition, branch, integer_rounding_policy, quantize_bfloat_scalar_bits, resolve,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};

const RESULT: u8 = 0;
const GPR_RAX: u8 = 0;
const ACCUMULATOR: u8 = 1;
const LEFT: u8 = 2;
const RIGHT: u8 = 3;
const DOUBLE_ACCUMULATOR: u8 = 4;
const ACTIVE: u8 = 5;
const DOUBLE_LEFT: u8 = 6;
const DOUBLE_RIGHT: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const BFLOAT_BYTES: usize = size_of::<u16>();
const CHUNK_LANES: usize = VECTOR_CHUNK_BYTES / BFLOAT_BYTES;
const BFLOAT_FRACTION_BITS: u8 = 7;
const BFLOAT_EXPONENT_MASK: u32 = 255;
const BFLOAT_EXPONENT_BIAS: u32 = 127;
const BFLOAT_SIGN_MASK: u32 = 1 << 15;
const SINGLE_TO_BFLOAT_SHIFT: u8 = 16;
const DOUBLE_TO_SINGLE_SHIFT: u8 = 29;
const STICKY_MASK: u32 = (1 << DOUBLE_TO_SINGLE_SHIFT) - 1;
const SINGLE_SIGN_MASK: u32 = 1 << 31;
const SINGLE_EXPONENT_MASK: u32 = 255 << 23;
const EXPONENT_REBIAS: u64 = (1023 - 127) << 23;
const MINIMUM_DOUBLE_EXPONENT: u32 = 1023 - 127 + 1;
const NORMAL_EXPONENT_INTERVAL: u32 = 253;
const EXACT_EXPONENT_DISTANCE: u8 = 32;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const PEXTRW: &[u8] = &[0x66, 0x0f, 0xc5];
const PINSRW: &[u8] = &[0x66, 0x0f, 0xc4];
const MOVD: &[u8] = &[0x66, 0x0f, 0x6e];
const CVTSS2SD: &[u8] = &[0xf3, 0x0f, 0x5a];
const MULSD: &[u8] = &[0xf2, 0x0f, 0x59];
const ADDSD: &[u8] = &[0xf2, 0x0f, 0x58];
const MOVQ_RAX_XMM6: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xf0];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const MOV_EDX_ECX: &[u8] = &[0x89, 0xca];
const MOV_R10D_ECX: &[u8] = &[0x41, 0x89, 0xca];
const NEG_R10D: &[u8] = &[0x41, 0xf7, 0xda];
const ADD_R10D_ECX: &[u8] = &[0x41, 0x01, 0xca];
const SUB_R10D_IMM8: &[u8] = &[0x41, 0x83, 0xea];
const ADD_R10D_IMM8: &[u8] = &[0x41, 0x83, 0xc2];
const CMP_R10D_IMM8: &[u8] = &[0x41, 0x83, 0xfa];
const SHR_ECX_IMM8: &[u8] = &[0xc1, 0xe9];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const SUB_EDX_ONE: &[u8] = &[0x83, 0xea, 1];
const CMP_EDX_IMM32: &[u8] = &[0x81, 0xfa];
const XOR_EAX_IMM32: u8 = 0x35;
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const TEST_EAX_IMM32: u8 = 0xa9;
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const SHR_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe9];
const SUB_ECX_IMM32: &[u8] = &[0x81, 0xe9];
const CMP_ECX_IMM32: &[u8] = &[0x81, 0xf9];
const SETNZ_CL: &[u8] = &[0x0f, 0x95, 0xc1];
const MOVZX_R10D_CL: &[u8] = &[0x44, 0x0f, 0xb6, 0xd1];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const SHR_RDX_IMM8: &[u8] = &[0x48, 0xc1, 0xea];
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const MOV_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const SUB_RAX_RCX: &[u8] = &[0x48, 0x29, 0xc8];
const OR_EAX_R10D: &[u8] = &[0x44, 0x09, 0xd0];
const OR_EAX_EDX: &[u8] = &[0x09, 0xd0];
const TEST_R10D_R10D: &[u8] = &[0x45, 0x85, 0xd2];
const MOV_R10D_EAX: &[u8] = &[0x41, 0x89, 0xc2];
const MOV_EAX_R10D: &[u8] = &[0x44, 0x89, 0xd0];
const MOV_EAX_IMM32: u8 = 0xb8;

fn scalar(code: &mut Vec<u8>, opcode: &[u8], destination: u8, source: u8) {
    code.extend(opcode);
    code.push(MODRM_REGISTER | destination << MODRM_REGISTER_SHIFT | source);
}

fn extract(code: &mut Vec<u8>, source: u8, lane: usize) {
    scalar(code, PEXTRW, GPR_RAX, source);
    code.push(lane as u8);
}

/// Preserve raw BF16 in EAX and its biased exponent in ECX. Reject zeros,
/// subnormals and nonfinite values before any host floating-point instruction.
fn normal_input(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(MOV_ECX_EAX);
    code.extend(SHR_ECX_IMM8);
    code.push(BFLOAT_FRACTION_BITS);
    code.extend(AND_ECX_IMM32);
    code.extend(BFLOAT_EXPONENT_MASK.to_le_bytes());
    code.extend(MOV_EDX_ECX);
    code.extend(SUB_EDX_ONE);
    code.extend(CMP_EDX_IMM32);
    code.extend(NORMAL_EXPONENT_INTERVAL.to_le_bytes());
    failures.push(branch(code, Condition::Above));
}

fn widen(code: &mut Vec<u8>, destination: u8) {
    code.extend(SHL_EAX_IMM8);
    code.push(SINGLE_TO_BFLOAT_SHIFT);
    scalar(code, MOVD, destination, GPR_RAX);
    scalar(code, CVTSS2SD, destination, destination);
}

/// Product precision is at most16 bits. With |eL+eR-eA| <=32, aligning the
/// accumulator and product requires at most48 significant bits plus one carry,
/// fitting Double53 even before cancellation. Both Double operations are exact.
fn exact_exponent_guard(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(SUB_R10D_IMM8);
    code.push(BFLOAT_EXPONENT_BIAS as u8);
    code.extend(ADD_R10D_IMM8);
    code.push(EXACT_EXPONENT_DISTANCE);
    code.extend(CMP_R10D_IMM8);
    code.push(EXACT_EXPONENT_DISTANCE * 2);
    failures.push(branch(code, Condition::Above));
}

/// Compress an exact Double to a rebased Single-shaped integer representation.
/// The low29 discarded bits become one sticky bit. Sixteen retained guard bits
/// remain below BF precision, so every final BF rounding mode sees the same
/// below-half/equal-half/above-half and nonzero-remainder classification.
fn compress(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(MOVQ_RAX_XMM6);
    code.extend(MOV_RCX_RAX);
    code.extend(SHR_RCX_IMM8);
    code.push(Format::Double.fraction_bits() as u8);
    code.extend(AND_ECX_IMM32);
    code.extend(0x7ff_u32.to_le_bytes());
    code.extend(SUB_ECX_IMM32);
    code.extend(MINIMUM_DOUBLE_EXPONENT.to_le_bytes());
    code.extend(CMP_ECX_IMM32);
    code.extend(NORMAL_EXPONENT_INTERVAL.to_le_bytes());
    failures.push(branch(code, Condition::Above));
    code.push(TEST_EAX_IMM32);
    code.extend(STICKY_MASK.to_le_bytes());
    code.extend(SETNZ_CL);
    code.extend(MOVZX_R10D_CL);
    code.extend(MOV_RDX_RAX);
    code.extend(SHR_RDX_IMM8);
    code.push(u32::BITS as u8);
    code.extend(AND_EDX_IMM32);
    code.extend(SINGLE_SIGN_MASK.to_le_bytes());
    code.extend(SHR_RAX_IMM8);
    code.push(DOUBLE_TO_SINGLE_SHIFT);
    code.extend(MOV_RCX_IMM64);
    code.extend(EXPONENT_REBIAS.to_le_bytes());
    code.extend(SUB_RAX_RCX);
    code.extend(OR_EAX_R10D);
    code.extend(OR_EAX_EDX);
}

/// Shared R8D/R9D/R11D selectors own RC and nearest-even parity. Every discarded
/// bit records true-BF IXC, including AH1. Pending status commits only at finish.
fn quantize(code: &mut Vec<u8>, frame: &numerical::Frame, failures: &mut Vec<usize>) {
    // R10D holds the compression sticky bit, which is already part of EAX.
    // The shared helper's OR-accumulation therefore records exactly low16.
    quantize_bfloat_scalar_bits(code);
    code.extend(TEST_R10D_R10D);
    let exact = branch(code, Condition::Zero);
    code.extend(MOV_R10D_EAX);
    code.push(MOV_EAX_IMM32);
    code.extend(INEXACT.to_le_bytes());
    numerical::add_fpsr(code, frame);
    code.extend(MOV_EAX_R10D);
    let destination = code.len();
    resolve(code, exact, destination);
    code.extend(MOV_ECX_EAX);
    code.extend(AND_ECX_IMM32);
    code.extend(SINGLE_EXPONENT_MASK.to_le_bytes());
    code.extend(CMP_ECX_IMM32);
    code.extend(SINGLE_EXPONENT_MASK.to_le_bytes());
    failures.push(branch(code, Condition::Zero));
    code.extend(SHR_EAX_IMM8);
    code.push(SINGLE_TO_BFLOAT_SHIFT);
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::MultiplyAdd { subtract } = operand.kind else {
        return Ok(false);
    };
    let (right, index) = match operand.right {
        RightOperand::Vector(register) => (register, None),
        RightOperand::Indexed { register, index } if index < CHUNK_LANES as u8 => {
            (register, Some(index))
        }
        RightOperand::Indexed { .. } => return Ok(false),
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    let mut failures = Vec::new();
    // Exact admitted arithmetic is independent of host RC. Fixed RN also makes
    // the private environment auditable; final BF RC remains the shared policy.
    code.extend(XOR_EAX_EAX);
    numerical::install_mxcsr(code, &frame);
    integer_rounding_policy(code, SINGLE_TO_BFLOAT_SHIFT, false);
    for chunk in 0..length.chunks() {
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                ElementSize::Halfword,
                ACTIVE,
                RESULT,
                length,
                target,
            );
        } else {
            Host::EqualWord.register(code, ACTIVE, ACTIVE, target);
        }
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            ACCUMULATOR,
            length,
            target,
        );
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        Host::MoveAligned.register(code, RESULT, ACCUMULATOR, target);
        for lane in 0..CHUNK_LANES {
            extract(code, ACTIVE, lane);
            code.extend(TEST_EAX_EAX);
            let inactive = branch(code, Condition::Zero);
            extract(code, ACCUMULATOR, lane);
            normal_input(code, &mut failures);
            code.extend(MOV_R10D_ECX);
            code.extend(NEG_R10D);
            widen(code, DOUBLE_ACCUMULATOR);
            extract(code, LEFT, lane);
            normal_input(code, &mut failures);
            code.extend(ADD_R10D_ECX);
            if subtract {
                code.push(XOR_EAX_IMM32);
                code.extend(BFLOAT_SIGN_MASK.to_le_bytes());
            }
            widen(code, DOUBLE_LEFT);
            extract(code, RIGHT, index.map_or(lane, usize::from));
            normal_input(code, &mut failures);
            code.extend(ADD_R10D_ECX);
            exact_exponent_guard(code, &mut failures);
            widen(code, DOUBLE_RIGHT);
            scalar(code, MULSD, DOUBLE_LEFT, DOUBLE_RIGHT);
            scalar(code, ADDSD, DOUBLE_LEFT, DOUBLE_ACCUMULATOR);
            compress(code, &mut failures);
            quantize(code, &frame, &mut failures);
            scalar(code, PINSRW, RESULT, GPR_RAX);
            code.push(lane as u8);
            let destination = code.len();
            resolve(code, inactive, destination);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
