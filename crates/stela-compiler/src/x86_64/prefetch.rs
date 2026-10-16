//! PRFM as SSE PREFETCH hints.
use super::{load, offset};
use crate::aarch64::{
    prefetch::{Address, Hint, Operand},
    register_offset::IndexExtend,
};
use alloc::vec::Vec;

const NOP: u8 = 0x90;
const MOVABS_RAX: &[u8] = &[0x48, 0xb8];
const MOV_ECX_STATE: &[u8] = &[0x8b, 0x8f];
const MOVSXD_RCX_STATE: &[u8] = &[0x48, 0x63, 0x8f];
const MOV_RCX_STATE: &[u8] = &[0x48, 0x8b, 0x8f];
const PREFETCH: &[u8] = &[0x0f, 0x18];
const MOD_DISP8: u8 = 0x40;
const MOD_DISP32: u8 = 0x80;
const SIB_ADDRESS: u8 = 4;
const SIB_RAX_RCX: u8 = 1 << 3;
const SIB_SCALE_SHIFT: u8 = 6;

#[derive(Clone, Copy)]
enum Locality {
    NonTemporal = 0,
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
}

impl Locality {
    const fn modrm(self) -> u8 {
        (self as u8) << 3
    }
}

fn locality(hint: Hint) -> Option<Locality> {
    const STORE_HINT: u8 = 0b10000;
    const TYPE_MASK: u8 = 0b11000;
    const TARGET_MASK: u8 = 0b00110;
    const SYSTEM_CACHE: u8 = 0b00110;
    const STREAMING: u8 = 1;
    let raw = hint.encoding();
    if !matches!(raw & TYPE_MASK, 0 | STORE_HINT) || raw & TARGET_MASK == SYSTEM_CACHE {
        // Arm allows any prefetch hint to be a NOP. PLI needs translated
        // instruction addresses, and SLC, intent-to-read-on-update and
        // unallocated hints have no host equivalent.
        return None;
    }
    Some(if raw & STREAMING != 0 {
        Locality::NonTemporal
    } else {
        match (raw & TARGET_MASK) >> 1 {
            0 => Locality::Level1,
            1 => Locality::Level2,
            2 => Locality::Level3,
            _ => unreachable!("system cache hints use the explicit NOP policy"),
        }
    })
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    let Some(locality) = locality(operand.hint) else {
        // One byte preserves strict source-map intervals for the no-action hint.
        code.push(NOP);
        return;
    };
    match operand.address {
        Address::Immediate { base, displacement } => {
            load(code, base); // SP is an ordinary source here; no CheckSPAlignment.
            immediate(code, locality, displacement);
        }
        Address::Register {
            base,
            index,
            extend,
            shift,
        } => {
            load(code, base);
            if let Some(displacement) = offset(index) {
                // Read precisely the bits used by ExtendReg. W forms avoid an
                // unnecessary 64-bit load followed by a separate conversion.
                code.extend(match extend {
                    IndexExtend::Uxtw => MOV_ECX_STATE,
                    IndexExtend::Sxtw => MOVSXD_RCX_STATE,
                    IndexExtend::Lsl | IndexExtend::Sxtx => MOV_RCX_STATE,
                });
                code.extend(displacement.to_le_bytes());
                code.extend(PREFETCH);
                code.push(locality.modrm() | SIB_ADDRESS);
                // Decoder restricts shift to 0 or 3. SIB performs the shift and
                // modulo-64 addition without an extra SHL/LEA instruction.
                code.push((shift << SIB_SCALE_SHIFT) | SIB_RAX_RCX);
            } else {
                immediate(code, locality, 0); // XZR index contributes zero.
            }
        }
        Address::Literal(address) => {
            code.extend(MOVABS_RAX);
            code.extend(address.to_le_bytes());
            immediate(code, locality, 0);
        }
    }
}

fn immediate(code: &mut Vec<u8>, locality: Locality, displacement: i32) {
    code.extend(PREFETCH);
    if displacement == 0 {
        code.push(locality.modrm()); // [rax]
    } else if let Ok(short) = i8::try_from(displacement) {
        code.push(locality.modrm() | MOD_DISP8);
        code.extend(short.to_le_bytes());
    } else {
        code.push(locality.modrm() | MOD_DISP32);
        code.extend(displacement.to_le_bytes());
    }
}

#[cfg(test)]
mod tests;
