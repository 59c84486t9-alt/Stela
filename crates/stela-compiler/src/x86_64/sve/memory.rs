//! Address computation and fault exits shared by the SVE memory families.

use super::super::{load, scalable::memory as service};
use crate::aarch64::{
    Register,
    scalable::VectorLength,
    sve::memory::{Address, Offset, Scale},
};
use crate::context::memory::MemoryStatus;
use alloc::vec::Vec;

const ADD_RAX_IMM8: &[u8] = &[0x48, 0x83, 0xc0];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const SHIFT_RAX_LEFT_IMM8: &[u8] = &[0x48, 0xc1, 0xe0];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const ADD_RAX_RCX: &[u8] = &[0x48, 0x01, 0xc8];
const TEST_AL_IMM8: u8 = 0xa8;
const JE_REL32: &[u8] = &[0x0f, 0x84];
const JMP_REL32: u8 = 0xe9;
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JE_REL8: u8 = 0x74;
const RET: u8 = 0xc3;
const RET_BYTES: u8 = 1;
const STACK_ALIGNMENT_BYTES: u8 = 16;
const STACK_ALIGNMENT_MASK: u8 = STACK_ALIGNMENT_BYTES - 1;

fn scale_bytes(scale: Scale, length: VectorLength) -> usize {
    match scale {
        Scale::Bytes => 1,
        Scale::PredicateBytes => length.predicate_bytes(),
        Scale::VectorBytes { multiply, divide } => {
            assert!(
                multiply != 0 && divide != 0,
                "allocated vector scale is nonzero"
            );
            let bytes = length.bytes() * usize::from(multiply);
            assert_eq!(
                bytes % usize::from(divide),
                0,
                "vector scale must be integral"
            );
            bytes / usize::from(divide)
        }
    }
}

/// Return the effective guest address in RAX, with 64-bit wrapping arithmetic.
/// CPA2 is disabled; translation owns TBI handling. Clobbers RCX; RDI/R15 survive.
pub(crate) fn address(code: &mut Vec<u8>, operand: Address, length: VectorLength) {
    match operand.offset {
        Offset::Immediate { value, scale } => {
            load(code, operand.base);
            let displacement = i32::from(value)
                * i32::try_from(scale_bytes(scale, length)).expect("allocated scale fits i32");
            if displacement == 0 {
                return;
            }
            if let Ok(short) = i8::try_from(displacement) {
                code.extend(ADD_RAX_IMM8);
                code.push(short as u8);
            } else {
                code.extend(ADD_RAX_IMM32);
                code.extend(displacement.to_le_bytes());
            }
        }
        Offset::Register {
            index: Register::Zero,
            ..
        } => load(code, operand.base),
        Offset::Register { index, shift } => {
            load(code, index);
            if shift != 0 {
                code.extend(SHIFT_RAX_LEFT_IMM8);
                code.push(shift);
            }
            code.extend(MOV_RCX_RAX);
            load(code, operand.base);
            code.extend(ADD_RAX_RCX);
        }
    }
}

/// Check SP before applying the displacement. Requires SA/SA0 enabled, with
/// CHECKSPNONEACTIVE true. Prefetches must not call this. The caller patches
/// the fault site to its cleanup.
pub(crate) fn check_sp(code: &mut Vec<u8>, base: Register, pc: u64) -> Option<usize> {
    if base != Register::Sp {
        return None;
    }
    load(code, Register::Sp);
    code.push(TEST_AL_IMM8);
    code.push(STACK_ALIGNMENT_MASK);
    code.extend(JE_REL32);
    let aligned = code.len();
    code.extend(0_i32.to_le_bytes());
    service::fault(code, MemoryStatus::StackAlignment, pc);
    code.push(JMP_REL32);
    let failed = code.len();
    code.extend(0_i32.to_le_bytes());
    let destination = code.len();
    service::patch_branch(code, aligned, destination);
    Some(failed)
}

/// After family scratch cleanup, return a failed inner body to its outer entry.
/// The outer entry CALLs the body and owns POP_R15; this RET cannot bypass it.
/// Success (EAX=0) falls through to the next translated guest instruction.
pub(crate) fn return_if_failed(code: &mut Vec<u8>) {
    code.extend(TEST_EAX_EAX);
    code.push(JE_REL8);
    code.push(RET_BYTES);
    code.push(RET);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_lengths_keep_every_allocated_address_scale_integral() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for memory in [1, 2, 4, 8, 16] {
                for element in [1, 2, 4, 8, 16] {
                    let scale = Scale::VectorBytes {
                        multiply: memory,
                        divide: element,
                    };
                    assert_eq!(
                        scale_bytes(scale, length) * usize::from(element),
                        bytes * usize::from(memory)
                    );
                }
            }
        }
    }
}
