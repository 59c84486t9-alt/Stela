//! SVE FRECPE/FRSQRTE tables on normal values. Host RCP/RSQRT approximations
//! are never used; integer DIV and a masked SQRTSD compute the exact table values.
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, Format, features::NumericalFeatures},
        scalable::{VECTOR_CHUNK_BYTES, VectorLength},
        simd::estimate::Kind as EstimateKind,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const SOURCE: u8 = 0;
const RESULT: u8 = 1;
const ROOT: u8 = 2;
const INSERT: u8 = 3;
const NUMERATOR: u8 = 4;
const INPUT_UNIT: u8 = 5;
const RESULT_UNIT: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_BITS: u32 = u64::BITS;
const STANDARD_INPUT_BITS: u32 = 8;
const STANDARD_RESULT_BITS: u32 = 8;
const ENHANCED_INPUT_BITS: u32 = 11;
const ENHANCED_RESULT_BITS: u32 = 12;
const RECIPROCAL_NUMERATOR_BITS: u32 = 19;
const ENHANCED_RECIPROCAL_NUMERATOR_BITS: u32 = 26;
const ROOT_NUMERATOR_BITS: u32 = 28;
const ENHANCED_ROOT_NUMERATOR_BITS: u32 = 39;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const GPR_RAX: u8 = 0;
const GPR_RCX: u8 = 1;
const GPR_RDX: u8 = 2;
const REL32_BYTES: usize = size_of::<i32>();
const TEST_STATE_IMMEDIATE: &[u8] = &[0xf7, 0x87];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const JAE_REL32: &[u8] = &[0x0f, 0x83];
const JC_REL32: &[u8] = &[0x0f, 0x82];
const JMP_REL32: &[u8] = &[0xe9];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const XOR_EDX_EDX: &[u8] = &[0x31, 0xd2];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const MOV_R8_RAX: &[u8] = &[0x49, 0x89, 0xc0];
const SHR_R8_IMMEDIATE: &[u8] = &[0x49, 0xc1, 0xe8];
const AND_R8D_IMMEDIATE: &[u8] = &[0x41, 0x81, 0xe0];
const TEST_R8D_R8D: &[u8] = &[0x45, 0x85, 0xc0];
const CMP_R8D_IMMEDIATE: &[u8] = &[0x41, 0x81, 0xf8];
const TEST_R8B_PARITY: &[u8] = &[0x41, 0xf6, 0xc0, 1];
const BT_RAX_IMMEDIATE: &[u8] = &[0x48, 0x0f, 0xba, 0xe0];
const MOV_ECX_IMMEDIATE: u8 = 0xb9;
const SUB_ECX_R8D: &[u8] = &[0x44, 0x29, 0xc1];
const SHR_ECX_ONE: &[u8] = &[0xd1, 0xe9];
const SHL_RCX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xe1];
const MOV_R9_RAX: &[u8] = &[0x49, 0x89, 0xc1];
const SHR_R9_IMMEDIATE: &[u8] = &[0x49, 0xc1, 0xe9];
const SHL_R9_IMMEDIATE: &[u8] = &[0x49, 0xc1, 0xe1];
const OR_R9_RCX: &[u8] = &[0x49, 0x09, 0xc9];
const MOV_R9_RCX: &[u8] = &[0x49, 0x89, 0xc9];
const SHL_RAX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xe0];
const SHR_RAX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xe8];
const SHL_RAX_CL: &[u8] = &[0x48, 0xd3, 0xe0];
const SHR_RAX_CL: &[u8] = &[0x48, 0xd3, 0xe8];
const MOV_ECX_R10D: &[u8] = &[0x44, 0x89, 0xd1];
const MOV_ECX_R11D: &[u8] = &[0x44, 0x89, 0xd9];
const MOV_R10D_IMMEDIATE: &[u8] = &[0x41, 0xba];
const MOV_R11D_IMMEDIATE: &[u8] = &[0x41, 0xbb];
const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const OR_EAX_IMMEDIATE: u8 = 0x0d;
const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
const AND_EAX_EVEN: &[u8] = &[0x83, 0xe0, 0xfe];
const LEA_ECX_TWICE_RAX_PLUS_ONE: &[u8] = &[0x8d, 0x4c, 0x00, 1];
const LEA_ECX_TWICE_RAX_PLUS_TWO: &[u8] = &[0x8d, 0x4c, 0x00, 2];
const SHR_EAX_ONE: &[u8] = &[0xd1, 0xe8];
const DIV_RCX: &[u8] = &[0x48, 0xf7, 0xf1];
const DIV_ECX: &[u8] = &[0xf7, 0xf1];
const ADD_EAX_ONE: &[u8] = &[0x83, 0xc0, 1];
const SUB_EAX_IMMEDIATE: u8 = 0x2d;
const SUB_EAX_EDX: &[u8] = &[0x29, 0xd0];
const OR_RAX_R9: &[u8] = &[0x4c, 0x09, 0xc8];
const MOVQ_GPR_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const CVTSI2SD_XMM2_RAX: &[u8] = &[0xf2, 0x48, 0x0f, 0x2a, 0xd0];
const CVTTSD2SI_RAX_XMM2: &[u8] = &[0xf2, 0x48, 0x0f, 0x2c, 0xc2];
const PINSRW_XMM1_EAX: &[u8] = &[0x66, 0x0f, 0xc4, 0xc8];
const PINSRD_XMM1_EAX: &[u8] = &[0x66, 0x0f, 0x3a, 0x22, 0xc8];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Reciprocal,
    ReciprocalSquareRoot,
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn resolve(code: &mut [u8], displacement: usize, destination: usize) {
    let next = displacement + REL32_BYTES;
    let relative = i32::try_from(destination as i64 - next as i64)
        .expect("bounded estimate branch fits rel32");
    code[displacement..next].copy_from_slice(&relative.to_le_bytes());
}

fn immediate(code: &mut Vec<u8>, opcode: &[u8], value: u32) {
    code.extend(opcode);
    code.extend(value.to_le_bytes());
}

fn test_ah(code: &mut Vec<u8>) {
    code.extend(TEST_STATE_IMMEDIATE);
    code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(FPCR_AH.to_le_bytes());
}

fn xmm_to_gpr(code: &mut Vec<u8>, source: u8, destination: u8) {
    code.extend(MOVQ_GPR_XMM);
    code.push(MODRM_REGISTER | (source << MODRM_REGISTER_SHIFT) | destination);
}

fn xmm_constant(code: &mut Vec<u8>, destination: u8, bits: u64, target: TargetCpu) {
    code.extend(MOV_RAX_IMMEDIATE);
    code.extend(bits.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (destination << MODRM_REGISTER_SHIFT) | GPR_RAX);
}

fn numerator(operation: Operation, enhanced: bool) -> u64 {
    match (operation, enhanced) {
        (Operation::Reciprocal, false) => 1 << RECIPROCAL_NUMERATOR_BITS,
        (Operation::Reciprocal, true) => 1 << ENHANCED_RECIPROCAL_NUMERATOR_BITS,
        (Operation::ReciprocalSquareRoot, false) => (1 << ROOT_NUMERATOR_BITS) - 1,
        (Operation::ReciprocalSquareRoot, true) => (1 << ENHANCED_ROOT_NUMERATOR_BITS) - 1,
    }
}

fn constants(
    code: &mut Vec<u8>,
    operation: Operation,
    format: Format,
    enhanced: bool,
    target: TargetCpu,
) {
    let input_bits = if enhanced {
        ENHANCED_INPUT_BITS
    } else {
        STANDARD_INPUT_BITS
    };
    let result_bits = if enhanced {
        ENHANCED_RESULT_BITS
    } else {
        STANDARD_RESULT_BITS
    };
    immediate(code, MOV_R10D_IMMEDIATE, GPR_BITS - input_bits);
    immediate(
        code,
        MOV_R11D_IMMEDIATE,
        format.fraction_bits() - result_bits,
    );
    xmm_constant(code, NUMERATOR, numerator(operation, enhanced), target);
    xmm_constant(code, INPUT_UNIT, 1 << input_bits, target);
    xmm_constant(code, RESULT_UNIT, 1 << result_bits, target);
}

fn guard_normal(
    code: &mut Vec<u8>,
    operation: Operation,
    format: Format,
    failures: &mut Vec<usize>,
) {
    code.extend(MOV_R8_RAX);
    code.extend(SHR_R8_IMMEDIATE);
    code.push(format.fraction_bits() as u8);
    immediate(
        code,
        AND_R8D_IMMEDIATE,
        (format.exponent_mask() >> format.fraction_bits()) as u32,
    );
    code.extend(TEST_R8D_R8D);
    failures.push(branch(code, JZ_REL32));
    let ceiling = match operation {
        Operation::Reciprocal => format.exponent_bias() * 2 - 1,
        Operation::ReciprocalSquareRoot => {
            (format.exponent_mask() >> format.fraction_bits()) as u32
        }
    };
    immediate(code, CMP_R8D_IMMEDIATE, ceiling);
    failures.push(branch(code, JAE_REL32));
    if operation == Operation::ReciprocalSquareRoot {
        code.extend(BT_RAX_IMMEDIATE);
        code.push((format.bits() - 1) as u8);
        failures.push(branch(code, JC_REL32));
    }
}

fn result_exponent(code: &mut Vec<u8>, operation: Operation, format: Format) {
    let exponent_base = match operation {
        Operation::Reciprocal => format.exponent_bias() * 2 - 1,
        Operation::ReciprocalSquareRoot => format.exponent_bias() * 3 - 1,
    };
    immediate(code, &[MOV_ECX_IMMEDIATE], exponent_base);
    code.extend(SUB_ECX_R8D);
    if operation == Operation::ReciprocalSquareRoot {
        code.extend(SHR_ECX_ONE);
    }
    code.extend(SHL_RCX_IMMEDIATE);
    code.push(format.fraction_bits() as u8);
    if operation == Operation::Reciprocal {
        code.extend(MOV_R9_RAX);
        code.extend(SHR_R9_IMMEDIATE);
        code.push((format.bits() - 1) as u8);
        code.extend(SHL_R9_IMMEDIATE);
        code.push((format.bits() - 1) as u8);
        code.extend(OR_R9_RCX);
    } else {
        code.extend(MOV_R9_RCX);
    }
}

fn midpoint(code: &mut Vec<u8>, operation: Operation, format: Format, dynamic: bool) {
    // Strip sign/exponent first. The second shift selects only the top fixed
    // fraction bits, including the enhanced Single table's eleven-bit input.
    code.extend(SHL_RAX_IMMEDIATE);
    code.push((GPR_BITS - format.fraction_bits()) as u8);
    if dynamic {
        code.extend(MOV_ECX_R10D);
        code.extend(SHR_RAX_CL);
        xmm_to_gpr(code, INPUT_UNIT, GPR_RCX);
        code.extend(OR_RAX_RCX);
    } else {
        code.extend(SHR_RAX_IMMEDIATE);
        code.push((GPR_BITS - STANDARD_INPUT_BITS) as u8);
        immediate(code, &[OR_EAX_IMMEDIATE], 1 << STANDARD_INPUT_BITS);
    }
    if operation == Operation::Reciprocal {
        code.extend(LEA_ECX_TWICE_RAX_PLUS_ONE);
    } else {
        code.extend(TEST_R8B_PARITY);
        let odd = branch(code, JNZ_REL32);
        code.extend(AND_EAX_EVEN);
        code.extend(LEA_ECX_TWICE_RAX_PLUS_TWO);
        let ready = branch(code, JMP_REL32);
        let odd_start = code.len();
        resolve(code, odd, odd_start);
        code.extend(SHR_EAX_ONE);
        code.extend(LEA_ECX_TWICE_RAX_PLUS_ONE);
        let end = code.len();
        resolve(code, ready, end);
    }
}

fn estimate(
    code: &mut Vec<u8>,
    operation: Operation,
    format: Format,
    dynamic: bool,
    target: TargetCpu,
) {
    if dynamic {
        xmm_to_gpr(code, NUMERATOR, GPR_RAX);
    } else {
        immediate(
            code,
            &[MOV_EAX_IMMEDIATE],
            numerator(operation, false) as u32,
        );
    }
    if dynamic && operation == Operation::ReciprocalSquareRoot {
        code.extend(XOR_EDX_EDX);
        code.extend(DIV_RCX);
    } else {
        code.extend(XOR_EDX_EDX);
        code.extend(DIV_ECX);
    }
    if operation == Operation::ReciprocalSquareRoot {
        // q=floor((2^n-1)/midpoint) is a positive integer below 2^28 in
        // both precision profiles. CVTSI2SD is therefore exact. Its square
        // root is below 2^14; for nonsquares distance to either neighboring
        // integer exceeds 2^-15, while RNE error is at most 2^-40. An exact
        // square rounds exactly. Truncating SQRTSD is consequently isqrt(q).
        code.extend(CVTSI2SD_XMM2_RAX);
        Host::SquareRootScalarDouble.register(code, ROOT, ROOT, target);
        code.extend(CVTTSD2SI_RAX_XMM2);
    }
    code.extend(ADD_EAX_ONE);
    code.extend(SHR_EAX_ONE);
    if dynamic {
        xmm_to_gpr(code, RESULT_UNIT, GPR_RDX);
        code.extend(SUB_EAX_EDX);
        code.extend(MOV_ECX_R11D);
        code.extend(SHL_RAX_CL);
    } else {
        immediate(code, &[SUB_EAX_IMMEDIATE], 1 << STANDARD_RESULT_BITS);
        code.extend(SHL_RAX_IMMEDIATE);
        code.push((format.fraction_bits() - STANDARD_RESULT_BITS) as u8);
    }
    code.extend(OR_RAX_R9);
}

fn insert(code: &mut Vec<u8>, format: Format, lane: usize, checked: bool, target: TargetCpu) {
    match format {
        Format::Half => {
            code.extend(PINSRW_XMM1_EAX);
            code.push(lane as u8);
        }

        Format::Single if checked => {
            assert!(target.supports(TargetCpu::Sse41));
            code.extend(PINSRD_XMM1_EAX);
            code.push(lane as u8);
        }
        Format::Single | Format::Double => {
            // The unpredicated first lane initializes the complete chunk:
            // MOVQ clears its high64 bits. Later lanes only OR fresh disjoint
            // bits; no initial PXOR or first-lane temporary/OR is needed.
            let destination = if lane == 0 { RESULT } else { INSERT };
            Host::MoveGprQword.append(code, target);
            code.push(MODRM_REGISTER | (destination << MODRM_REGISTER_SHIFT) | GPR_RAX);
            if lane != 0 {
                ShiftOpcode::LeftBytes.emit(
                    code,
                    INSERT,
                    (lane * format.bits() as usize / u8::BITS as usize) as u8,
                );
                Host::Or.register(code, RESULT, INSERT, target);
            }
        }
    }
}

/// Normal-value kernel for the two estimate forms. Special values, subnormal
/// inputs, subnormal or overflowing reciprocals and negative RSQRT inputs leave
/// the instruction to software completion. Normal half precision ignores AHP
/// and FZ16. FPCR.AH suppresses enabled-trap rejection; FEAT_RPRES with
/// single-precision AH selects the enhanced constants. No new FPSR bits are
/// raised. Clobbers RAX/RCX/RDX/R8-R11, flags and XMM0-7; preserves the
/// callee-saved GPRs, RDI/R15, the sources and the caller's MXCSR.
pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let operation = match operand.kind {
        Kind::Estimate(EstimateKind::Reciprocal) => Operation::Reciprocal,
        Kind::Estimate(EstimateKind::ReciprocalSquareRoot) => Operation::ReciprocalSquareRoot,
        _ => return Ok(false),
    };
    let Inputs::Unary { source } = operand.inputs else {
        return Ok(false);
    };
    if operand.shape != ResultShape::Vector || operand.predicate.is_some() {
        return Ok(false);
    }

    // Measured SSE4.1 insertion applies only to one Single chunk with RPRES
    // and no full-A64 enable guard. FRECPE benefits on a true RAW recurrence;
    // FRSQRTE benefits with either alias. Other lengths/profiles keep baseline.
    let checked = operand.format == Format::Single
        && length.bytes() == VECTOR_CHUNK_BYTES
        && target.supports(TargetCpu::Sse41)
        && !features.full_a64()
        && features.rpres()
        && (operation == Operation::ReciprocalSquareRoot || source == operand.destination);

    let environment = if operation == Operation::ReciprocalSquareRoot {
        Environment::PrivateMxcsr
    } else {
        Environment::Exact
    };
    let frame = numerical::begin(code, length, &[Output::Z(operand.destination)], environment)?;
    if environment == Environment::PrivateMxcsr {
        code.extend(XOR_EAX_EAX);
        numerical::install_mxcsr(code, &frame);
    }
    let mut failures = Vec::new();
    if features.full_a64() {
        test_ah(code);
        let suppressed = branch(code, JNZ_REL32);
        Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        let next = code.len();
        resolve(code, suppressed, next);
    }
    let dynamic = operand.format == Format::Single && features.rpres();
    if dynamic {
        test_ah(code);
        let standard = branch(code, JZ_REL32);
        constants(code, operation, operand.format, true, target);
        let ready = branch(code, JMP_REL32);
        let standard_start = code.len();
        resolve(code, standard, standard_start);
        constants(code, operation, operand.format, false, target);
        let next = code.len();
        resolve(code, ready, next);
    }
    let element_bytes = operand.format.bits() as usize / u8::BITS as usize;
    for chunk in 0..length.chunks() {
        load_z_chunk(code, source, chunk, SOURCE, length, target);
        for lane in 0..VECTOR_CHUNK_BYTES / element_bytes {
            xmm_to_gpr(code, SOURCE, GPR_RAX);
            match operand.format {
                Format::Half => code.extend(MOVZX_EAX_AX),
                Format::Single => code.extend(MOV_EAX_EAX),
                Format::Double => (),
            }
            guard_normal(code, operation, operand.format, &mut failures);
            result_exponent(code, operation, operand.format);
            midpoint(code, operation, operand.format, dynamic);
            estimate(code, operation, operand.format, dynamic, target);
            insert(code, operand.format, lane, checked, target);
            if lane + 1 != VECTOR_CHUNK_BYTES / element_bytes {
                ShiftOpcode::RightBytes.emit(code, SOURCE, element_bytes as u8);
            }
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
