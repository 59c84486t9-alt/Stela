//! Scalar bitfield operations using baseline x86-64 shifts and Boolean logic.
//! Guest NZCV remains memory-backed and untouched by incidental host flags.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::aarch64::bitfield::{Kind, Operand};
use alloc::vec::Vec;

fn shift(code: &mut Vec<u8>, width: Width, opcode: u8, amount: u8) {
    if amount != 0 {
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([0xc1, opcode, amount]);
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    if operand.destination == Register::Zero {
        // Discarding a result must still own a nonempty source-map interval.
        code.push(0x90);
        return;
    }
    let bits = match operand.width {
        Width::W32 => 32,
        Width::X64 => 64,
    };
    debug_assert!(operand.rotation < bits && operand.mask_end < bits);
    let (source_shift, destination_shift, field_width) = if operand.rotation <= operand.mask_end {
        (operand.rotation, 0, operand.mask_end - operand.rotation + 1)
    } else {
        (0, bits - operand.rotation, operand.mask_end + 1)
    };

    load(code, operand.source);
    if operand.width == Width::W32 {
        // Required even when both shifts are absent (the full-width MOV alias).
        code.extend([0x89, 0xc0]); // mov eax,eax
    }
    // Move the source field to the operand's MSB, then extract it. Arithmetic
    // extraction replicates source[imms], including wrapping SBFIZ aliases.
    // Zero shifts are omitted; emitted amounts are 1 through bits-1 because
    // x86 masks a shift by bits to zero.
    shift(
        code,
        operand.width,
        0xe0, // shl (e/r)ax,imm8
        bits - source_shift - field_width,
    );
    shift(
        code,
        operand.width,
        if operand.kind == Kind::Signed {
            0xf8 // sar (e/r)ax,imm8
        } else {
            0xe8 // shr (e/r)ax,imm8
        },
        bits - field_width,
    );
    shift(code, operand.width, 0xe0, destination_shift);

    if operand.kind == Kind::Insert {
        let field_mask = (u64::MAX >> (64 - field_width)) << destination_shift;
        // No guest destination has been committed: source and destination may
        // alias. RCX receives the original destination after staging the source.
        right_operand(code, operand.destination, Width::X64, Shift::Lsl, 0);
        if operand.width == Width::X64 {
            code.extend([0x48, 0xba]); // movabs rdx,~field_mask
            code.extend((!field_mask).to_le_bytes());
            code.extend([0x48, 0x21, 0xd1]); // and rcx,rdx
            code.push(0x48);
        } else {
            code.extend([0x81, 0xe1]); // and ecx,imm32
            code.extend((!(field_mask as u32)).to_le_bytes());
        }
        code.extend([0x09, 0xc8]); // or (e/r)ax,(e/r)cx
    }
    store(code, operand.destination);
}

#[cfg(test)]
mod tests;
