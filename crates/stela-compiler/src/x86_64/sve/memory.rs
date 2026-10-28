//! Address computation and fault exits shared by the SVE memory families.
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, ShiftOp, Size};

use super::super::{load, scalable::memory as service};
use crate::aarch64::{
    Register,
    scalable::VectorLength,
    sve::memory::{Address, Offset, Scale},
};
use crate::context::memory::MemoryStatus;

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
pub(crate) fn address(code: &mut Code, operand: Address, length: VectorLength) {
    match operand.offset {
        Offset::Immediate { value, scale } => {
            load(code, operand.base);
            let displacement = i32::from(value)
                * i32::try_from(scale_bytes(scale, length)).expect("allocated scale fits i32");
            if displacement == 0 {
                return;
            }
            if let Ok(short) = i8::try_from(displacement) {
                code.asm().alu_imm8(Alu::Add, Size::Qword, Rax, short);
            } else {
                code.asm()
                    .alu_accumulator_imm32(Alu::Add, Size::Qword, displacement);
            }
        }
        Offset::Register {
            index: Register::Zero,
            ..
        } => load(code, operand.base),
        Offset::Register { index, shift } => {
            load(code, index);
            if shift != 0 {
                code.asm().shift_imm(ShiftOp::Shl, Size::Qword, Rax, shift);
            }
            code.asm().mov(Size::Qword, Rcx, Rax);
            load(code, operand.base);
            code.asm().alu(Alu::Add, Size::Qword, Rax, Rcx);
        }
    }
}

/// Check SP before applying the displacement. Requires SA/SA0 enabled, with
/// CHECKSPNONEACTIVE true. Prefetches must not call this. The caller patches
/// the fault site to its cleanup.
pub(crate) fn check_sp(code: &mut Code, base: Register, pc: u64) -> Option<usize> {
    if base != Register::Sp {
        return None;
    }
    load(code, Register::Sp);
    let mut asm = code.asm();
    asm.test_al_imm8(STACK_ALIGNMENT_MASK);
    let aligned = asm.jcc(Cond::E);
    service::fault(code, MemoryStatus::StackAlignment, pc);
    let mut asm = code.asm();
    let failed = asm.jmp();
    asm.bind(aligned);
    Some(failed.offset())
}

/// After family scratch cleanup, return a failed inner body to its outer entry.
/// The outer entry CALLs the body and owns POP_R15; this RET cannot bypass it.
/// Success (EAX=0) falls through to the next translated guest instruction.
pub(crate) fn return_if_failed(code: &mut Code) {
    let mut asm = code.asm();
    asm.test(Size::Dword, Rax, Rax);
    let succeeded = asm.jcc8(Cond::E);
    asm.ret();
    asm.bind(succeeded);
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
