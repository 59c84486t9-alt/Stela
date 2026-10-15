//! Private proposal: guarded normal Double-to-Single precision and odd narrowing.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, INEXACT, features::NumericalFeatures, precision::PrecisionRounding},
        scalable::{ElementSize, VectorLength},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::{numerical::rounding_control, precision::jam_odd_pair},
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const ACTIVE: u8 = 2;
const SCRATCH: u8 = 3;
const CLASSIFICATION_CONSTANTS: [u8; 2] = [4, 5];
const CLASSIFICATION_SCRATCH: [u8; 3] = [SCRATCH, 6, 7];
const MAXIMUM_EXPONENT: u8 = 6;
const ONE_VECTOR: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const GPR_RCX: u8 = 1;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOV_RCX_IMMEDIATE: &[u8] = &[0x48, 0xb9];
const MOV_EAX_IMMEDIATE: &[u8] = &[0xb8];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const AND_EAX_IMMEDIATE: &[u8] = &[0x25];
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const CMP_EAX_IMMEDIATE8: &[u8] = &[0x83, 0xf8];
const SHR_EAX_IMMEDIATE8: &[u8] = &[0xc1, 0xe8];
const JNE_REL32: &[u8] = &[0x0f, 0x85];
const CVTPD2PS_XMM0_XMM1: &[u8] = &[0x66, 0x0f, 0x5a, 0xc1];
const DOUBLE_ONE: u64 = (Format::Double.exponent_bias() as u64) << Format::Double.fraction_bits();
const SIGN_BITS: u8 = 1;
const SINGLE_EXPONENT_BITS: u8 =
    (Format::Single.bits() - Format::Single.fraction_bits() - SIGN_BITS as u32) as u8;
const SINGLE_EXPONENT_TO_BOTTOM: u8 = u32::BITS as u8 - SINGLE_EXPONENT_BITS;
const RESULT_LANES: u32 = u128::BITS / u64::BITS;
const LOW_TWO_DWORD_MASK: u8 = (1 << RESULT_LANES) - 1;
const MXCSR_PRECISION: u32 = 1 << 5;
const MXCSR_STATUS: u32 = (1 << 6) - 1;
const MXCSR_REJECTED_STATUS: u32 = MXCSR_STATUS & !MXCSR_PRECISION;
const MXCSR_ROUNDING_SHIFT: u32 = 13;
const MXCSR_TOWARD_ZERO: u32 = 3 << MXCSR_ROUNDING_SHIFT;
const HOST_TO_GUEST_INEXACT_SHIFT: u8 =
    (MXCSR_PRECISION.trailing_zeros() - INEXACT.trailing_zeros()) as u8;
const LOW_SINGLE_IN_QWORDS: u8 = 0xd8; // dword [0,2,1,3], with original upper64 zero.
const TOP_SINGLE_IN_QWORDS: u8 = 0x72; // dword [2,0,3,1].

fn failure(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(JNE_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

fn neutralize_inactive(code: &mut Vec<u8>, target: TargetCpu) {
    code.extend(MOV_RCX_IMMEDIATE);
    code.extend(DOUBLE_ONE.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (RESULT << MODRM_REGISTER_SHIFT) | GPR_RCX);
    Host::UnpackLowQword.register(code, RESULT, RESULT, target);
    Host::MoveAligned.register(code, SCRATCH, ACTIVE, target);
    Host::AndNot.register(code, SCRATCH, RESULT, target);
    Host::And.register(code, SOURCE, ACTIVE, target);
    Host::Or.register(code, SOURCE, SCRATCH, target);
}

/// The mature conservative result range is exponent2..254. This excludes the
/// minimum-normal binade as well as zero/tiny/Inf/NaN, preventing before/after
/// rounding tininess differences from being hidden by host status alone.
fn guard_result(code: &mut Vec<u8>, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::MoveAligned.register(code, SCRATCH, RESULT, target);
    ShiftOpcode::LeftDword.emit(code, SCRATCH, SIGN_BITS);
    ShiftOpcode::RightDword.emit(code, SCRATCH, SINGLE_EXPONENT_TO_BOTTOM);
    Host::EqualDword.register(code, MAXIMUM_EXPONENT, MAXIMUM_EXPONENT, target);
    ShiftOpcode::RightDword.emit(code, MAXIMUM_EXPONENT, SINGLE_EXPONENT_TO_BOTTOM);
    Host::GreaterDword.register(code, MAXIMUM_EXPONENT, SCRATCH, target);
    Host::EqualDword.register(code, ONE_VECTOR, ONE_VECTOR, target);
    ShiftOpcode::RightDword.emit(code, ONE_VECTOR, u32::BITS as u8 - SIGN_BITS);
    Host::GreaterDword.register(code, SCRATCH, ONE_VECTOR, target);
    Host::And.register(code, SCRATCH, MAXIMUM_EXPONENT, target);
    Host::DwordSignMask.register(code, GPR_RAX, SCRATCH, target);
    // CVTPD2PS sets the upper64 bits to zero. Only its two converted lanes count.
    code.extend(AND_EAX_IMMEDIATE);
    code.extend(u32::from(LOW_TWO_DWORD_MASK).to_le_bytes());
    code.extend(CMP_EAX_IMMEDIATE8);
    code.push(LOW_TWO_DWORD_MASK);
    failure(code, failures);
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::Precision {
        source: Format::Double,
        destination: Format::Single,
        rounding,
        placement: placement @ (Placement::Low | Placement::UpperDestination),
    } = operand.kind
    else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    if rounding == PrecisionRounding::ToOdd {
        code.extend(MOV_EAX_IMMEDIATE);
        code.extend(MXCSR_TOWARD_ZERO.to_le_bytes());
    } else {
        rounding_control(code);
    }
    numerical::install_mxcsr(code, &frame);
    let classification =
        prepare_classification(code, Format::Double, CLASSIFICATION_CONSTANTS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            ElementSize::Doubleword,
            ACTIVE,
            SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        neutralize_inactive(code, target);
        guard_normal_zero_or_infinity(
            code,
            classification,
            SOURCE,
            CLASSIFICATION_SCRATCH,
            &mut failures,
            target,
        );
        numerical::clear_status(code, &frame);
        code.extend(CVTPD2PS_XMM0_XMM1);
        numerical::capture_status(code, &frame);
        code.extend(TEST_ECX_IMMEDIATE);
        code.extend(MXCSR_REJECTED_STATUS.to_le_bytes());
        failure(code, &mut failures);
        code.extend(MOV_EAX_ECX);
        code.extend(AND_EAX_IMMEDIATE);
        code.extend(MXCSR_PRECISION.to_le_bytes());
        code.extend(SHR_EAX_IMMEDIATE8);
        code.push(HOST_TO_GUEST_INEXACT_SHIFT);
        numerical::add_fpsr(code, &frame);
        guard_result(code, &mut failures, target);
        if rounding == PrecisionRounding::ToOdd {
            jam_odd_pair(code, ONE_VECTOR);
        }
        Host::ShuffleDword.register(code, RESULT, RESULT, target);
        code.push(if placement == Placement::UpperDestination {
            TOP_SINGLE_IN_QWORDS
        } else {
            LOW_SINGLE_IN_QWORDS
        });
        // Neutral inactive one results are removed before top-slot mask shaping.
        Host::And.register(code, RESULT, ACTIVE, target);
        if placement == Placement::UpperDestination {
            ShiftOpcode::LeftQword.emit(code, ACTIVE, Format::Single.bits() as u8);
        }
        load_z_chunk(code, operand.destination, chunk, SCRATCH, length, target);
        Host::AndNot.register(code, ACTIVE, SCRATCH, target);
        Host::Or.register(code, RESULT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
