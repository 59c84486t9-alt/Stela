//! FPCR/FPSR reads and writes, using integer instructions only.
use super::{load, store};
use crate::x86_64::asm::{Alu, Code, Gpr::Rax, Size};
use crate::{
    GuestState,
    aarch64::{
        Register,
        fp_register::{Operand, SystemRegister},
    },
};

const FPCR_OFFSET: u32 = core::mem::offset_of!(GuestState, fpcr) as u32;
const FPSR_OFFSET: u32 = core::mem::offset_of!(GuestState, fpsr) as u32;

/// The register's field of the guest frame.
fn field(register: SystemRegister) -> crate::x86_64::asm::Mem {
    super::frame(match register {
        SystemRegister::Fpcr => FPCR_OFFSET,
        SystemRegister::Fpsr => FPSR_OFFSET,
    })
}

fn mask(code: &mut Code, register: SystemRegister) {
    code.asm()
        .alu_accumulator_imm32(Alu::And, Size::Dword, register.mask() as i32);
}

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    match *operand {
        Operand::Read {
            register,
            destination,
        } => {
            if destination == Register::Zero {
                // Access is enabled by this profile. Keep a distinct native
                // interval for the discarded read under strict source maps.
                code.asm().nop();
                return;
            }
            // The u32 load never reads the adjacent field. AND EAX masks raw
            // imported storage and zero-extends before the full Xt store.
            code.asm().mov_load(Size::Dword, Rax, field(register));
            mask(code, register);
            store(code, destination);
        }
        Operand::Write { register, source } => {
            load(code, source);
            if source != Register::Zero {
                // Only the low source word participates; the EAX result also
                // clears unsupported storage bits rather than retaining them.
                mask(code, register);
            }
            // A four-byte replacement cannot corrupt the other FP field.
            // The common XZR load supplies XOR EAX,EAX for a zero write.
            code.asm().mov_store(Size::Dword, field(register), Rax);
        }
    }
}
