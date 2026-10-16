//! FPCR/FPSR reads and writes, using integer instructions only.
use super::{load, store};
use crate::{
    GuestState,
    aarch64::{
        Register,
        fp_register::{Operand, SystemRegister},
    },
};
use alloc::vec::Vec;

const FPCR_OFFSET: u32 = core::mem::offset_of!(GuestState, fpcr) as u32;
const FPSR_OFFSET: u32 = core::mem::offset_of!(GuestState, fpsr) as u32;
const MOV_EAX_STATE_DISP32: &[u8] = &[0x8b, 0x87];
const MOV_STATE_DISP32_EAX: &[u8] = &[0x89, 0x87];
const AND_EAX_IMM32: u8 = 0x25;
const NOP: u8 = 0x90;

fn field_offset(register: SystemRegister) -> u32 {
    match register {
        SystemRegister::Fpcr => FPCR_OFFSET,
        SystemRegister::Fpsr => FPSR_OFFSET,
    }
}

fn mask(code: &mut Vec<u8>, register: SystemRegister) {
    code.push(AND_EAX_IMM32);
    code.extend(register.mask().to_le_bytes());
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    match *operand {
        Operand::Read {
            register,
            destination,
        } => {
            if destination == Register::Zero {
                // Access is enabled by this profile. Keep a distinct native
                // interval for the discarded read under strict source maps.
                code.push(NOP);
                return;
            }
            // The u32 load never reads the adjacent field. AND EAX masks raw
            // imported storage and zero-extends before the full Xt store.
            code.extend(MOV_EAX_STATE_DISP32);
            code.extend(field_offset(register).to_le_bytes());
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
            code.extend(MOV_STATE_DISP32_EAX);
            code.extend(field_offset(register).to_le_bytes());
        }
    }
}
