//! Exact unsigned estimate lookup; no FP environment is consulted.
//! Literal lookup data is shared by every chunk of one emitted instruction.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        simd::estimate::Kind as EstimateKind,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
    },
};
use alloc::vec::Vec;

const SOURCE: u8 = 0;
const ACTIVE: u8 = 1;
const MERGE: u8 = 2;
const RESULT: u8 = 3;
const CANDIDATE: u8 = 4;
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const DWORD_BYTES: usize = core::mem::size_of::<u32>();
const REL32_BYTES: usize = core::mem::size_of::<i32>();
const ESTIMATE_FRACTION_BITS: u32 = 8;
const ESTIMATE_UNIT: u32 = 1 << ESTIMATE_FRACTION_BITS;
const ESTIMATE_INPUT_SHIFT: u8 = (u32::BITS - ESTIMATE_FRACTION_BITS - 1) as u8;
const RECIPROCAL_FIRST_BIN: u32 = ESTIMATE_UNIT;
const RSQRT_FIRST_BIN: u32 = ESTIMATE_UNIT / 2;
const LAST_BIN_EXCLUSIVE: u32 = ESTIMATE_UNIT * 2;

const MOVD_GPR_XMM: &[u8] = &[0x66, 0x0f, 0x7e];
const MOV_EAX_IMM32: u8 = 0xb8;
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const CMP_EAX_IMM32: u8 = 0x3d;
const OR_EAX_IMM32: u8 = 0x0d;
const LEA_RDX_RIP_REL32: &[u8] = &[0x48, 0x8d, 0x15];
const MOVZX_EAX_BYTE_RDX_RAX_DISP32: &[u8] = &[0x0f, 0xb6, 0x84, 0x02];
const PEXTRD_EAX_XMM: &[u8] = &[0x66, 0x0f, 0x3a, 0x16];
const PINSRD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x3a, 0x22];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const JMP_REL32: u8 = 0xe9;

fn patch(code: &mut [u8], displacement: usize, destination: usize) {
    let relative = i32::try_from(destination as i64 - (displacement + REL32_BYTES) as i64)
        .expect("unsigned estimate body exceeds rel32 range");
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&relative.to_le_bytes());
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn movd_from_xmm(code: &mut Vec<u8>, xmm: u8, gpr: u8) {
    code.extend(MOVD_GPR_XMM);
    code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) | gpr);
}

fn movq_to_xmm(code: &mut Vec<u8>, xmm: u8, gpr: u8, target: TargetCpu) {
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) | gpr);
}

fn first_bin(kind: EstimateKind) -> u32 {
    match kind {
        EstimateKind::UnsignedReciprocal => RECIPROCAL_FIRST_BIN,
        EstimateKind::UnsignedReciprocalSquareRoot => RSQRT_FIRST_BIN,
        _ => unreachable!("validated unsigned estimate kind"),
    }
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    _features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::Estimate(
        kind @ (EstimateKind::UnsignedReciprocal | EstimateKind::UnsignedReciprocalSquareRoot),
    ) = operand.kind
    else {
        return Ok(false);
    };
    let (Inputs::Unary { source }, Some(predicate)) = (operand.inputs, operand.predicate) else {
        return Ok(false);
    };
    if operand.format != Format::Single || operand.shape != ResultShape::Vector {
        return Ok(false);
    }
    // The checked lookup wins on the measured one-chunk RAW recurrence.
    // Unsigned estimates ignore numerical features and every FP control.
    // Preserve the lookup recipe for distinct source/destination registers.
    let checked = length.bytes() == VECTOR_CHUNK_BYTES
        && source == operand.destination
        && target.supports(TargetCpu::Sse41);
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let mut table_addresses = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            ElementSize::Word,
            ACTIVE,
            MERGE,
            length,
            target,
        );
        load_z_chunk(code, source, chunk, SOURCE, length, target);

        code.extend(LEA_RDX_RIP_REL32);
        table_addresses.push(code.len());
        code.extend(0_i32.to_le_bytes());

        for lane in 0..VECTOR_CHUNK_BYTES / DWORD_BYTES {
            if checked {
                code.extend(PEXTRD_EAX_XMM);
                code.push(MODRM_REGISTER | (SOURCE << MODRM_REGISTER_SHIFT) | GPR_RAX);
                code.push(lane as u8);
            } else {
                movd_from_xmm(code, SOURCE, GPR_RAX);
            }

            code.extend(SHR_EAX_IMM8);
            code.push(ESTIMATE_INPUT_SHIFT);
            code.push(CMP_EAX_IMM32);
            code.extend(first_bin(kind).to_le_bytes());
            let below = branch(code, JB_REL32);

            code.extend(MOVZX_EAX_BYTE_RDX_RAX_DISP32);
            code.extend((-(first_bin(kind) as i32)).to_le_bytes());
            code.push(OR_EAX_IMM32);
            code.extend(ESTIMATE_UNIT.to_le_bytes());

            code.extend(SHL_EAX_IMM8);
            code.push(ESTIMATE_INPUT_SHIFT);
            let valid = branch(code, &[JMP_REL32]);
            let below_start = code.len();
            patch(code, below, below_start);
            code.push(MOV_EAX_IMM32);
            code.extend(u32::MAX.to_le_bytes());
            let value_done = code.len();
            patch(code, valid, value_done);

            if checked {
                code.extend(PINSRD_XMM_EAX);
                code.push(MODRM_REGISTER | (RESULT << MODRM_REGISTER_SHIFT) | GPR_RAX);
                code.push(lane as u8);
            } else {
                if lane == 0 {
                    // MOVQ writes the first dword and clears every upper byte.
                    movq_to_xmm(code, RESULT, GPR_RAX, target);
                } else {
                    movq_to_xmm(code, CANDIDATE, GPR_RAX, target);
                    ShiftOpcode::LeftBytes.emit(code, CANDIDATE, (lane * DWORD_BYTES) as u8);
                    Host::Or.register(code, RESULT, CANDIDATE, target);
                }
                if lane + 1 != VECTOR_CHUNK_BYTES / DWORD_BYTES {
                    ShiftOpcode::RightBytes.emit(code, SOURCE, DWORD_BYTES as u8);
                }
            }
        }
        load_z_chunk(code, operand.destination, chunk, MERGE, length, target);
        Host::And.register(code, RESULT, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, MERGE, target);
        Host::Or.register(code, RESULT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &[], pc, target);

    let skip = branch(code, &[JMP_REL32]);
    let table_start = code.len();
    for scaled in first_bin(kind)..LAST_BIN_EXCLUSIVE {
        // Compile-time only: compact exact architectural table; no host
        // address, CALL, mutable storage or runtime FP operation is emitted.
        let result = crate::aarch64::floating::estimate::evaluate(
            kind,
            Format::Single,
            0,
            u64::from(scaled) << ESTIMATE_INPUT_SHIFT,
        )
        .expect("unsigned estimate ignores every control");
        let estimate = (result.bits >> ESTIMATE_INPUT_SHIFT) as u32;
        code.push(u8::try_from(estimate - ESTIMATE_UNIT).expect("estimate table byte"));
    }
    let table_end = code.len();
    patch(code, skip, table_end);
    for displacement in table_addresses {
        patch(code, displacement, table_start);
    }

    Ok(true)
}
