//! SME length arithmetic specialized to the cache-bound streaming vector length.
use crate::aarch64::Register;
use crate::aarch64::scalable::VectorLength;
use crate::aarch64::sme::length::{Kind, Operand, Scale};
use crate::x86_64::{load, offset, store};
use alloc::vec::Vec;

const NOP: u8 = 0x90;
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const LEA_RAX_RAX_DISP8: &[u8] = &[0x48, 0x8d, 0x40];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const ADD_STATE_IMM8: &[u8] = &[0x48, 0x83, 0x87];
const ADD_STATE_IMM32: &[u8] = &[0x48, 0x81, 0x87];
const MOV_STATE_IMM32_SIGNED: &[u8] = &[0x48, 0xc7, 0x87];

pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, length: VectorLength) {
    // The caller must check SME access before entering this emitter, including
    // discarded results and identity operations. SM and ZA need not be enabled.
    if operand.destination == Register::Zero {
        code.push(NOP);
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
                code.push(NOP);
                return;
            }
            if source == operand.destination {
                let short = i8::try_from(displacement).ok();
                code.extend(if short.is_some() {
                    ADD_STATE_IMM8
                } else {
                    ADD_STATE_IMM32
                });
                code.extend(
                    offset(source)
                        .expect("length add source is GPR or SP")
                        .to_le_bytes(),
                );
                if let Some(displacement) = short {
                    code.push(displacement as u8);
                } else {
                    code.extend(displacement.to_le_bytes());
                }
                return;
            }
            load(code, source);
            if displacement != 0 {
                if let Ok(displacement) = i8::try_from(displacement) {
                    code.extend(LEA_RAX_RAX_DISP8);
                    code.extend(displacement.to_le_bytes());
                } else {
                    code.extend(ADD_RAX_IMM32);
                    code.extend(displacement.to_le_bytes());
                }
            }
            store(code, operand.destination);
        }
        Kind::Read => {
            if displacement == 0 {
                code.extend(XOR_EAX_EAX);
                store(code, operand.destination);
            } else {
                code.extend(MOV_STATE_IMM32_SIGNED);
                code.extend(
                    offset(operand.destination)
                        .expect("RDSVL destination is a GPR")
                        .to_le_bytes(),
                );
                code.extend(displacement.to_le_bytes());
            }
        }
    }
}
