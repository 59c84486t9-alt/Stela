//! Constant-time packed-index table lookup shared by the LUTI forms.
use crate::{
    TargetCpu,
    aarch64::scalable::{ElementSize, VECTOR_CHUNK_BYTES},
    x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host},
};
use alloc::vec::Vec;
const MOV_EAX: u8 = 0xb8;
const MOVD: &[u8] = &[0x66, 0x0f, 0x6e];
const REGISTER: u8 = 0xc0;
const XMM_SHIFT: u8 = 3;
const REPEAT_LOW: u8 = 0;
const LOW_TABLE: u8 = 4;
const HIGH_TABLE: u8 = 5;
const OUTPUT: u8 = 6;
const MASK: u8 = 7;
const BYTE_INDEX_MASK2: u32 = 0x0303_0303;
const BYTE_INDEX_MASK4: u32 = 0x0f0f_0f0f;
const HALFWORD_OFFSETS: u32 = 0x0100_0100;
const SHUFFLE_DISABLE: u32 = 0x8080_8080;
const TABLE_BANK_TO_DISABLE_SHIFT: u8 = 3;

fn splat(code: &mut Vec<u8>, xmm: u8, value: u32, target: TargetCpu) {
    code.push(MOV_EAX);
    code.extend(value.to_le_bytes());
    code.extend(MOVD);
    code.push(REGISTER | (xmm << XMM_SHIFT));
    Host::ShuffleDword.register(code, xmm, xmm, target);
    code.push(REPEAT_LOW);
}
fn expand(code: &mut Vec<u8>, index_bits: u8, target: TargetCpu) {
    splat(
        code,
        MASK,
        if index_bits == 2 {
            BYTE_INDEX_MASK2
        } else {
            BYTE_INDEX_MASK4
        },
        target,
    );
    Host::MoveAligned.register(code, 1, 0, target);
    Shift::RightWord.emit(code, 1, index_bits);
    if index_bits == 2 {
        Host::MoveAligned.register(code, 2, 0, target);
        Shift::RightWord.emit(code, 2, 4);
        Host::MoveAligned.register(code, 3, 0, target);
        Shift::RightWord.emit(code, 3, 6);
        Host::And.register(code, 2, MASK, target);
        Host::And.register(code, 3, MASK, target);
        Host::UnpackLowByte.register(code, 2, 3, target);
    }
    Host::And.register(code, 0, MASK, target);
    Host::And.register(code, 1, MASK, target);
    Host::UnpackLowByte.register(code, 0, 1, target);
    if index_bits == 2 {
        Host::UnpackLowWord.register(code, 0, 2, target);
    }
}
fn boolean(code: &mut Vec<u8>, element: ElementSize, index_bits: u8, target: TargetCpu) {
    if element == ElementSize::Halfword {
        Host::UnpackLowByte.register(code, 0, 0, target);
    }
    Host::Xor.register(code, OUTPUT, OUTPUT, target);
    for entry in 0..(1u8 << index_bits) {
        splat(code, 1, u32::from(entry) * 0x0101_0101, target);
        Host::EqualByte.register(code, 1, 0, target);
        let offset = usize::from(entry) * element.bytes();
        Host::MoveAligned.register(
            code,
            2,
            if offset < VECTOR_CHUNK_BYTES {
                LOW_TABLE
            } else {
                HIGH_TABLE
            },
            target,
        );
        if !offset.is_multiple_of(VECTOR_CHUNK_BYTES) {
            Shift::RightBytes.emit(code, 2, (offset % VECTOR_CHUNK_BYTES) as u8);
        }
        if element == ElementSize::Byte {
            Host::UnpackLowByte.register(code, 2, 2, target);
        }
        Host::ShuffleLowWord.register(code, 2, 2, target);
        code.push(REPEAT_LOW);
        Host::ShuffleDword.register(code, 2, 2, target);
        code.push(REPEAT_LOW);
        Host::And.register(code, 1, 2, target);
        Host::Or.register(code, OUTPUT, 1, target);
    }
}
fn shuffle(code: &mut Vec<u8>, element: ElementSize, index_bits: u8, target: TargetCpu) {
    if element == ElementSize::Halfword {
        Host::UnpackLowByte.register(code, 0, 0, target);
        Shift::LeftWord.emit(code, 0, 1);
        splat(code, MASK, HALFWORD_OFFSETS, target);
        Host::Or.register(code, 0, MASK, target);
    }
    Host::MoveAligned.register(code, OUTPUT, LOW_TABLE, target);
    if element == ElementSize::Halfword && index_bits == 4 {
        Host::MoveAligned.register(code, 2, 0, target);
        Shift::LeftWord.emit(code, 2, TABLE_BANK_TO_DISABLE_SHIFT);
        splat(code, MASK, SHUFFLE_DISABLE, target);
        Host::And.register(code, 2, MASK, target);
        Host::MoveAligned.register(code, 3, 0, target);
        Host::Or.register(code, 3, 2, target);
        Host::ByteShuffle.register(code, OUTPUT, 3, target);
        Host::Xor.register(code, 2, MASK, target);
        Host::Or.register(code, 0, 2, target);
        Host::MoveAligned.register(code, 1, HIGH_TABLE, target);
        Host::ByteShuffle.register(code, 1, 0, target);
        Host::Or.register(code, OUTPUT, 1, target);
    } else {
        Host::ByteShuffle.register(code, OUTPUT, 0, target);
    }
}
/// XMM0 holds packed indices; XMM4/5 hold the low/high 16-byte table.
/// Returns XMM6, preserves XMM4/5, clobbers XMM0..3,7 and RAX.
/// Four-bit halfword lookup requires both table chunks. No indexed memory.
pub(crate) fn emit_chunk(
    code: &mut Vec<u8>,
    index_bits: u8,
    element: ElementSize,
    target: TargetCpu,
) {
    assert!(
        matches!(index_bits, 2 | 4) && matches!(element, ElementSize::Byte | ElementSize::Halfword)
    );
    expand(code, index_bits, target);
    if target.supports(TargetCpu::Ssse3) {
        shuffle(code, element, index_bits, target);
    } else {
        boolean(code, element, index_bits, target);
    }
}
