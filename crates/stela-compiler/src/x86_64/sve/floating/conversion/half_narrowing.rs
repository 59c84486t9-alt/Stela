//! SVE conversions narrowing to half precision.
use crate::x86_64::asm::Code;
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, precision::PrecisionRounding},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::{half::emit_normal_or_zero, numerical::rounding_control},
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const SCRATCH: u8 = 2;
const PACK_INPUT: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const GPR_RCX: u8 = 1;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOVD_EAX_XMM2: &[u8] = &[0x66, 0x0f, 0x7e, 0xd0];
const MOV_EAX_R10D: &[u8] = &[0x44, 0x89, 0xd0];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const XOR_ECX_ECX: &[u8] = &[0x31, 0xc9];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const PINSRW: &[u8] = &[0x66, 0x0f, 0xc4];
const CVTSS2SD_XMM6_XMM6: &[u8] = &[0xf3, 0x0f, 0x5a, 0xf6];
const HALF_BYTES: usize = size_of::<u16>();
const BITS_PER_BYTE: u32 = u8::BITS;

fn branch(code: &mut Code, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn resolve(code: &mut [u8], displacement: usize, end: usize) {
    let next = displacement + size_of::<i32>();
    let relative = i64::try_from(end).expect("bounded Half instruction")
        - i64::try_from(next).expect("bounded Half instruction");
    code[displacement..next].copy_from_slice(
        &i32::try_from(relative)
            .expect("bounded Half branch")
            .to_le_bytes(),
    );
}

fn insert_half(code: &mut Code, gpr: u8, byte_offset: usize) {
    assert!(byte_offset < VECTOR_CHUNK_BYTES && byte_offset.is_multiple_of(HALF_BYTES));
    code.extend(PINSRW);
    code.push(MODRM_REGISTER | (RESULT << MODRM_REGISTER_SHIFT) | gpr);
    code.push((byte_offset / HALF_BYTES) as u8);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let (source, placement) = match operand.kind {
        Kind::Precision {
            source: Format::Single,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: placement @ (Placement::Low | Placement::UpperDestination),
        } => (Format::Single, placement),
        Kind::Precision {
            source: Format::Double,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        } => (Format::Double, Placement::Low),
        _ => return Ok(false),
    };
    let slot_bytes = (source.bits() / BITS_PER_BYTE) as usize;
    let element = ElementSize::from_bytes(slot_bytes).expect("typed precision source size");
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element,
            ACTIVE,
            SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        load_z_chunk(code, operand.destination, chunk, RESULT, length, target);
        code.extend(XOR_R10D_R10D);
        for slot in (0..VECTOR_CHUNK_BYTES).step_by(slot_bytes) {
            Host::MoveAligned.register(code, SCRATCH, ACTIVE, target);
            if slot != 0 {
                ShiftOpcode::RightBytes.emit(code, SCRATCH, slot as u8);
            }
            code.extend(MOVD_EAX_XMM2);
            code.extend(TEST_EAX_EAX);
            let inactive = branch(code, JZ_REL32);
            Host::MoveAligned.register(code, PACK_INPUT, SOURCE, target);
            if slot != 0 {
                ShiftOpcode::RightBytes.emit(code, PACK_INPUT, slot as u8);
            }
            if source == Format::Single {
                // Private masks prevent host traps on exceptional temporary
                // inputs. Any widening status takes whole completion before
                // packing; no intermediate status is mapped to guest FPSR.
                numerical::clear_status(code, &frame);
                code.extend(CVTSS2SD_XMM6_XMM6);
                numerical::capture_status(code, &frame);
                code.extend(TEST_ECX_ECX);
                failures.push(branch(code, JNZ_REL32));
            }
            emit_normal_or_zero(code, &mut failures);
            let destination_offset = if placement == Placement::UpperDestination {
                HALF_BYTES
            } else {
                0
            };
            insert_half(code, GPR_RAX, slot + destination_offset);
            if placement == Placement::Low {
                // Ordinary precision narrowing zero-extends the whole source
                // slot. Top narrowing replaces exactly its high Half instead.
                code.extend(XOR_ECX_ECX);
                for upper in (slot + HALF_BYTES..slot + slot_bytes).step_by(HALF_BYTES) {
                    insert_half(code, GPR_RCX, upper);
                }
            }
            let end = code.len();
            resolve(code, inactive, end);
        }
        // Consume private IXC before the next predicate/access helper reload.
        code.extend(MOV_EAX_R10D);
        numerical::add_fpsr(code, &frame);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
