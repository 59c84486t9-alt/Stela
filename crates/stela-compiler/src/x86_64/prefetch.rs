//! PRFM as SSE PREFETCH hints.
use super::{load, offset};
use crate::aarch64::{
    prefetch::{Address, Hint, Operand},
    register_offset::IndexExtend,
};
use crate::x86_64::asm::{Code, Gpr, Mem, Size, memory::Prefetch};

fn locality(hint: Hint) -> Option<Prefetch> {
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
        Prefetch::Nta
    } else {
        match (raw & TARGET_MASK) >> 1 {
            0 => Prefetch::T0,
            1 => Prefetch::T1,
            2 => Prefetch::T2,
            _ => unreachable!("system cache hints use the explicit NOP policy"),
        }
    })
}

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    let Some(locality) = locality(operand.hint) else {
        // One byte preserves strict source-map intervals for the no-action hint.
        code.asm().nop();
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
                let state = Mem::base_disp32(Gpr::Rdi, displacement as i32);
                let mut asm = code.asm();
                match extend {
                    IndexExtend::Uxtw => asm.mov_load(Size::Dword, Gpr::Rcx, state),
                    IndexExtend::Sxtw => asm.movsxd(Gpr::Rcx, state),
                    IndexExtend::Lsl | IndexExtend::Sxtx => {
                        asm.mov_load(Size::Qword, Gpr::Rcx, state);
                    }
                }
                // Decoder restricts shift to 0 or 3. SIB performs the shift and
                // modulo-64 addition without an extra SHL/LEA instruction.
                asm.prefetch(locality, Mem::indexed(Gpr::Rax, Gpr::Rcx, 1 << shift, 0));
            } else {
                immediate(code, locality, 0); // XZR index contributes zero.
            }
        }
        Address::Literal(address) => {
            code.asm().mov_imm64(Gpr::Rax, address);
            immediate(code, locality, 0);
        }
    }
}

/// Prefetch [RAX + displacement], in its shortest form.
fn immediate(code: &mut Code, locality: Prefetch, displacement: i32) {
    code.asm()
        .prefetch(locality, Mem::base(Gpr::Rax, displacement));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, aarch64::prefetch};

    use alloc::vec::Vec;

    fn emitted(word: u32) -> Vec<u8> {
        let operand = prefetch::decode(GuestAddress(0), word).unwrap().unwrap();
        let mut code = Code::new();
        emit(&mut code, &operand);
        code.into_bytes()
    }

    #[test]
    fn advisory_hints_select_baseline_data_prefetch_or_explicit_nop() {
        for hint in 0..32 {
            let code = emitted(0xf9800000 | hint);
            if matches!(hint, 0..=5 | 16..=21) {
                let modrm = if hint & 1 != 0 {
                    0
                } else {
                    (((hint >> 1) & 3) + 1) << 3
                };
                assert_eq!(&code[7..], &[0x0f, 0x18, modrm as u8]);
            } else {
                assert_eq!(code, [0x90]);
            }
        }
    }

    #[test]
    fn sp_sources_never_add_the_transfer_alignment_trap() {
        for word in [0xf98003e0, 0xf88003e0, 0xf8bf6be0] {
            let code = emitted(word);
            assert_eq!(&code[..7], &[0x48, 0x8b, 0x87, 248, 0, 0, 0]);
            assert!(!code.windows(2).any(|bytes| bytes == [0x0f, 0x0b]));
        }
    }
}
