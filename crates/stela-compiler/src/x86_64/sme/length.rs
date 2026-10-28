//! ADDSVL/ADDSPL/RDSVL with the streaming vector length as a constant.
use crate::aarch64::Register;
use crate::aarch64::scalable::VectorLength;
use crate::aarch64::sme::length::{Kind, Operand, Scale};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};
use crate::x86_64::simd::encode::guest;
use crate::x86_64::{load, offset, store};

pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength) {
    // The caller must check SME access before entering this emitter, including
    // discarded results and identity operations. SM and ZA need not be enabled.
    if operand.destination == Register::Zero {
        code.asm().nop();
        return;
    }
    let scale = match operand.kind {
        Kind::Add {
            scale: Scale::Predicate,
            ..
        } => length.predicate_bytes(),
        Kind::Add {
            scale: Scale::Vector,
            ..
        }
        | Kind::Read => length.bytes(),
    };
    let displacement = i32::from(operand.immediate) * scale as i32;
    match operand.kind {
        Kind::Add { source, .. } => {
            if displacement == 0 && source == operand.destination {
                code.asm().nop();
                return;
            }
            if source == operand.destination {
                let state = guest(offset(source).expect("length add source is GPR or SP"));
                code.asm()
                    .alu_imm(Alu::Add, Size::Qword, state, displacement);
                return;
            }
            load(code, source);
            if displacement != 0 {
                if let Ok(displacement) = i8::try_from(displacement) {
                    code.asm().lea(
                        Size::Qword,
                        Gpr::Rax,
                        Mem::base_disp8(Gpr::Rax, displacement),
                    );
                } else {
                    code.asm()
                        .alu_accumulator_imm32(Alu::Add, Size::Qword, displacement);
                }
            }
            store(code, operand.destination);
        }
        Kind::Read => {
            if displacement == 0 {
                code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
                store(code, operand.destination);
            } else {
                let state = guest(offset(operand.destination).expect("RDSVL destination is a GPR"));
                code.asm().mov_rm_imm32(Size::Qword, state, displacement);
            }
        }
    }
}
