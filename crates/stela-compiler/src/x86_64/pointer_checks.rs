//! Result marking shared by the checked pointer arithmetic forms.
use crate::x86_64::asm::{Alu, BitTest, Code, Cond, Gpr, ShiftOp, Size};

const TOP_BYTE_SHIFT: u8 = 56;
const POINTER_SIGN_BIT: u8 = 55;
const DETECTION_BIT: u8 = 54;
const LOW_RESULT_MASK: u64 = (1 << DETECTION_BIT) - 1;
const ONE_BIT_SHIFT: u8 = 1;
const ONE_BIT_MASK: i8 = 1;

/// RAX is the result and RDX the base; R8 holds the normalized multiplication
/// predicate when requested. RCX/R9/R10/R11 are scratch. No branch depends on
/// guest data.
pub(super) fn emit(code: &mut Code, multiplication: bool) {
    use Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx};
    use Size::{Dword, Qword};
    let mut asm = code.asm();
    asm.mov(Qword, R9, Rax);
    asm.alu(Alu::Xor, Qword, R9, Rdx);
    asm.shift_imm(ShiftOp::Shr, Qword, R9, TOP_BYTE_SHIFT);
    asm.mov(Qword, Rcx, Rdx);
    asm.shift_imm(ShiftOp::Shr, Qword, Rcx, DETECTION_BIT);
    asm.mov(Qword, R10, Rcx);
    asm.shift_imm(ShiftOp::Shr, Qword, R10, ONE_BIT_SHIFT);
    asm.alu(Alu::Xor, Qword, Rcx, R10);
    asm.alu_imm8(Alu::And, Dword, Rcx, ONE_BIT_MASK);
    asm.alu(Alu::Or, Qword, R9, Rcx);
    if multiplication {
        asm.alu(Alu::Or, Qword, R9, R8);
    }

    // Preserve result[53:0] and base[63:55], then set bit54 to NOT base[55].
    asm.mov(Qword, Rcx, Rax);
    asm.mov_imm64(R10, LOW_RESULT_MASK);
    asm.alu(Alu::And, Qword, Rcx, R10);
    asm.unary(crate::x86_64::asm::Unary::Not, Qword, R10);
    asm.alu(Alu::And, Qword, R10, Rdx);
    asm.bit_imm(BitTest::Btr, Qword, R10, DETECTION_BIT);
    asm.bit_imm(BitTest::Bt, Qword, Rdx, POINTER_SIGN_BIT);
    asm.setcc(Cond::Ae, R11);
    asm.movzx(Dword, R11, Size::Byte, R11);
    asm.shift_imm(ShiftOp::Shl, Qword, R11, DETECTION_BIT);
    asm.alu(Alu::Or, Qword, Rcx, R10);
    asm.alu(Alu::Or, Qword, Rcx, R11);
    asm.test(Qword, R9, R9);
    asm.cmov(Cond::Ne, Qword, Rax, Rcx);
}
