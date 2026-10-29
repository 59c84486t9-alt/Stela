//! SVE FCPY and FDUP.
use crate::x86_64::asm::Gpr::Rcx;
use crate::x86_64::asm::{Code, Rm};
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
const REPEAT_LOW_DWORD: u8 = 0;
// Only this H/S vector shape has a measured ComplementXor win. Other lengths
// and Double keep AndSelect; this is an empirical shape, not a threshold.
const COMPLEMENT_XOR_MEASURED_VECTOR_BYTES: usize = 64;

/// Fill active SVE lanes with the already expanded VFP immediate. All inactive
/// lanes preserve their old destination; FDUP supplies no governing predicate.
/// Full SVE writes cover current VL and do not clear any other Z register tail.
pub(crate) fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
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
        code.asm().mov_imm64(Rcx, qword);
    } else {
        code.asm().mov_imm32(Rcx, qword as u32);
    }
    code.asm()
        .simd(SimdOpcode::MoveGprQword, IMMEDIATE, Rcx, target);
    if bits == u64::BITS {
        SimdOpcode::UnpackLowQword.register(code, IMMEDIATE, IMMEDIATE, target);
    } else {
        code.asm().simd_imm(
            SimdOpcode::ShuffleDword,
            IMMEDIATE,
            Rm::Xmm(IMMEDIATE),
            REPEAT_LOW_DWORD,
            target,
        );
    }
    for chunk in 0..length.chunks() {
        let output = if let Some(governing) = operand.governing {
            read_predicate_mask(
                code,
                governing,
                chunk,
                element,
                crate::x86_64::scalable::MaskRegisters::new(ACTIVE, PREDICATE_SCRATCH),
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
