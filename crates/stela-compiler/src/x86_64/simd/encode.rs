//! Operands the SIMD, SME and AMX lowerings name by number or by frame.
use crate::x86_64::asm::{Gpr, Mem};

/// The general-purpose register numbered `number`.
pub(in crate::x86_64) const fn gpr(number: u8) -> Gpr {
    use Gpr::*;
    const REGISTERS: [Gpr; 16] = [
        Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15,
    ];
    REGISTERS[number as usize]
}

/// `[rsp + offset]` with a 32-bit displacement: a private stack slot.
pub(in crate::x86_64) const fn stack(offset: usize) -> Mem {
    Mem::base_disp32(Gpr::Rsp, offset as i32)
}

/// `[rdi + offset]` in GuestState, with a 32-bit displacement.
pub(in crate::x86_64) const fn guest(offset: u32) -> Mem {
    Mem::base_disp32(Gpr::Rdi, offset as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_number_as_encoded() {
        assert_eq!(gpr(0), Gpr::Rax);
        assert_eq!(gpr(9), Gpr::R9);
    }
}
