//! Direct private-RAM register-offset accesses; guest NZCV is unchanged.
use super::{
    AddressMode, MemoryTransfer, Register, Shift, Width, memory_address, offset, right_operand,
};
use crate::aarch64::register_offset::{IndexExtend, Operand};

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    // Validate incoming SP before offset addition, even if the effective
    // address would be aligned. No guest register is committed before access.
    memory_address(code, operand.base, 0, AddressMode::Offset);
    right_operand(code, operand.index, Width::X64, Shift::Lsl, 0);
    match operand.extend {
        IndexExtend::Uxtw => code.extend([0x89, 0xc9]), // mov ecx,ecx
        IndexExtend::Sxtw => code.extend([0x48, 0x63, 0xc9]), // movsxd rcx,ecx
        IndexExtend::Lsl | IndexExtend::Sxtx => {}
    }
    if operand.shift != 0 {
        code.extend([0x48, 0xc1, 0xe1, operand.shift]);
    }
    code.extend([0x48, 0x8d, 0x04, 0x08]); // lea rax,[rax+rcx], modulo 2^64
    match operand.transfer {
        MemoryTransfer::Store => {
            right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
            match operand.bytes {
                1 => code.extend([0x88, 0x08]),
                2 => code.extend([0x66, 0x89, 0x08]),
                4 => code.extend([0x89, 0x08]),
                8 => code.extend([0x48, 0x89, 0x08]),
                _ => unreachable!("decoder validates register-offset size"),
            }
        }
        MemoryTransfer::Load { signed, width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            match (operand.bytes, signed) {
                (1, false) => code.extend([0x0f, 0xb6, 0x08]),
                (2, false) => code.extend([0x0f, 0xb7, 0x08]),
                (1, true) => code.extend([0x0f, 0xbe, 0x08]),
                (2, true) => code.extend([0x0f, 0xbf, 0x08]),
                (4, true) => code.extend([0x63, 0x08]),
                (4 | 8, false) => code.extend([0x8b, 0x08]),
                _ => unreachable!("decoder validates signed register-offset size"),
            }
            // A load to ZR still accesses memory and can fault.
            if let Some(displacement) = offset(operand.data) {
                code.extend([0x48, 0x89, 0x8f]);
                code.extend(displacement.to_le_bytes());
            }
        }
    }
    // This addressing class never performs base writeback.
    debug_assert!(operand.base != Register::Zero);
}
