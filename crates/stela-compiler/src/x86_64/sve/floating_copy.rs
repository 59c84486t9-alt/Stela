//! SVE floating immediates are bitwise construction, independent of FP controls.
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VectorLength},
        sve::floating_copy::Operand,
    },
    x86_64::{
        isa::SimdOpcode,
        scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
    },
};

const IMMEDIATE: u8 = 0;
const ACTIVE: u8 = 1;
const PREDICATE_SCRATCH: u8 = 2;
const OLD_DESTINATION: u8 = 3;
const SELECTED: u8 = 4;
const RCX_REGISTER: u8 = 1;
const REGISTER_DIRECT: u8 = 0xc0;
const REGISTER_FIELD_SHIFT: u8 = 3;
const MOV_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const MOV_ECX_IMM32: &[u8] = &[0xb9];
const REPEAT_LOW_DWORD: u8 = 0;
// Only this H/S vector shape has a measured ComplementXor win. Other lengths
// and Double retain AndSelect; this is an empirical shape, not a threshold.
const COMPLEMENT_XOR_MEASURED_VECTOR_BYTES: usize = 64;

/// Fill active SVE lanes with the already expanded VFP immediate. All inactive
/// lanes preserve their old destination; FDUP supplies no governing predicate.
/// Full SVE writes cover current VL and do not clear any other Z register tail.
pub(crate) fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let bits = operand.format.bits();
    let complement_xor =
        bits != u64::BITS && length.bytes() == COMPLEMENT_XOR_MEASURED_VECTOR_BYTES;
    let element = ElementSize::from_bytes((bits / u8::BITS) as usize)
        .expect("decoded FP immediate has a defined element size");
    let mut qword = 0;
    for shift in (0..u64::BITS).step_by(bits as usize) {
        qword |= operand.value << shift;
    }
    if bits == u64::BITS {
        code.extend(MOV_RCX_IMM64);
        code.extend(qword.to_le_bytes());
    } else {
        code.extend(MOV_ECX_IMM32);
        code.extend((qword as u32).to_le_bytes());
    }
    SimdOpcode::MoveGprQword.append(code, target);
    code.push(REGISTER_DIRECT | (IMMEDIATE << REGISTER_FIELD_SHIFT) | RCX_REGISTER);
    if bits == u64::BITS {
        SimdOpcode::UnpackLowQword.register(code, IMMEDIATE, IMMEDIATE, target);
    } else {
        SimdOpcode::ShuffleDword.register(code, IMMEDIATE, IMMEDIATE, target);
        code.push(REPEAT_LOW_DWORD);
    }
    for chunk in 0..length.chunks() {
        let output = if let Some(governing) = operand.governing {
            read_predicate_mask(
                code,
                governing,
                chunk,
                element,
                ACTIVE,
                PREDICATE_SCRATCH,
                length,
                target,
            );
            load_z_chunk(
                code,
                operand.destination,
                chunk,
                OLD_DESTINATION,
                length,
                target,
            );
            if complement_xor {
                SimdOpcode::Xor.register(code, OLD_DESTINATION, IMMEDIATE, target);
                SimdOpcode::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
                SimdOpcode::Xor.register(code, ACTIVE, IMMEDIATE, target);
            } else {
                SimdOpcode::MoveAligned.register(code, SELECTED, IMMEDIATE, target);
                SimdOpcode::And.register(code, SELECTED, ACTIVE, target);
                SimdOpcode::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
                SimdOpcode::Or.register(code, ACTIVE, SELECTED, target);
            }
            ACTIVE
        } else {
            IMMEDIATE
        };
        store_z_chunk(code, operand.destination, chunk, output, length, target);
    }
}
