//! Scalable register access for the extended native ABI.
//!
//! RDI holds GuestState and R15 the ExecutionContext. The low 128 bits of each Z
//! register live in `GuestState::v`; the upper bytes and packed predicates live
//! in the scalable view. Helpers clobber only RAX/RCX/RDX and XMM0-7.

pub(crate) use super::memory_context as memory;
use alloc::vec::Vec;

pub(crate) mod lut;
pub(crate) mod numerical;
pub(crate) mod routing;
mod z_upper;
pub(crate) use z_upper::clear_z_upper;

mod predicate;
pub(crate) use predicate::{write_predicate_chunk, zero_predicate};

use super::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::{
    GuestState, TargetCpu,
    aarch64::scalable::{
        BITS_PER_BYTE, ElementSize, VECTOR_CHUNK_BYTES, VectorLength, is_predicate_register,
        is_z_register,
    },
    context::{
        EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_PREDICATES_OFFSET, SCALABLE_Z_UPPER_OFFSET,
    },
};

const XMM_REGISTER_COUNT: u8 = 8;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_DISP32: u8 = 0x80;
const REGISTER_SHIFT: u8 = 3;
const STATE_RDI: u8 = 7;
const ADDRESS_RDX: u8 = 2;
const HALFWORD_BYTES: usize = core::mem::size_of::<u16>();
const DWORD_BYTES: usize = core::mem::size_of::<u32>();
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const PREDICATE_CHUNK_BYTES: usize = QWORD_BYTES;
const PREDICATE_MASK_BYTES: usize = VECTOR_CHUNK_BYTES / BITS_PER_BYTE;
const MOV_RDX_CONTEXT_DISP8: &[u8] = &[0x49, 0x8b, 0x57];
const MOV_RDX_RDX_DISP8: &[u8] = &[0x48, 0x8b, 0x52];
const MOVZX_EAX_WORD_RDX_DISP32: &[u8] = &[0x0f, 0xb7, 0x82];
const MOV_EAX_RDX_DISP32: &[u8] = &[0x8b, 0x82];
const MOV_RAX_RDX_DISP32: &[u8] = &[0x48, 0x8b, 0x82];
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const MOVABS_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const MOVQ_XMM_RCX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const NEG_EAX: &[u8] = &[0xf7, 0xd8];
const DWORD_SIGN_BIT: u8 = (u32::BITS - 1) as u8;
const RCX_REGISTER: u8 = 1;
const REPEAT_LOW_DWORD: u8 = 0;
const REPEAT_LOW_TWO_DWORDS: u8 = 0x50;
const FIRST_PREDICATE_BIT: u8 = 1;

fn xmm(register: u8) {
    assert!(
        register < XMM_REGISTER_COUNT,
        "scalable helper requires XMM0..7"
    );
}

fn storage_pointer(code: &mut Vec<u8>, field: u32) {
    // Both fields fit positive signed disp8 in the versioned shared ABI.
    debug_assert!(EXECUTION_CONTEXT_SCALABLE_OFFSET <= i8::MAX as u32);
    debug_assert!(field <= i8::MAX as u32);
    code.extend(MOV_RDX_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_SCALABLE_OFFSET as u8);
    code.extend(MOV_RDX_RDX_DISP8);
    code.push(field as u8);
}

fn vector_offset(register: u8) -> u32 {
    assert!(is_z_register(register));
    (core::mem::offset_of!(GuestState, v) + usize::from(register) * VECTOR_CHUNK_BYTES) as u32
}

fn upper_offset(register: u8, chunk: usize, length: VectorLength) -> u32 {
    assert!(is_z_register(register));
    assert!(chunk > 0 && chunk < length.chunks());
    (usize::from(register) * (length.bytes() - VECTOR_CHUNK_BYTES)
        + (chunk - 1) * VECTOR_CHUNK_BYTES) as u32
}

fn vector_memory(
    code: &mut Vec<u8>,
    opcode: Host,
    register: u8,
    base: u8,
    displacement: u32,
    target: TargetCpu,
) {
    xmm(register);
    opcode.append(code, target);
    code.push(MODRM_DISP32 | (register << REGISTER_SHIFT) | base);
    code.extend(displacement.to_le_bytes());
}

/// Read one 16-byte Z segment into XMM0..7. Upper chunks clobber RDX only.
pub(crate) fn load_z_chunk(
    code: &mut Vec<u8>,
    register: u8,
    chunk: usize,
    destination: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(chunk < length.chunks());
    let (base, displacement) = if chunk == 0 {
        (STATE_RDI, vector_offset(register))
    } else {
        storage_pointer(code, SCALABLE_Z_UPPER_OFFSET);
        (ADDRESS_RDX, upper_offset(register, chunk, length))
    };
    vector_memory(
        code,
        Host::LoadUnaligned,
        destination,
        base,
        displacement,
        target,
    );
}

/// Commit one 16-byte Z segment from XMM0..7. Upper chunks clobber RDX only.
pub(crate) fn store_z_chunk(
    code: &mut Vec<u8>,
    register: u8,
    chunk: usize,
    source: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(chunk < length.chunks());
    let (base, displacement) = if chunk == 0 {
        (STATE_RDI, vector_offset(register))
    } else {
        storage_pointer(code, SCALABLE_Z_UPPER_OFFSET);
        (ADDRESS_RDX, upper_offset(register, chunk, length))
    };
    vector_memory(
        code,
        Host::StoreUnaligned,
        source,
        base,
        displacement,
        target,
    );
}

fn predicate_offset(predicate: u8, byte_offset: usize, length: VectorLength) -> u32 {
    assert!(is_predicate_register(predicate));
    assert!(byte_offset < length.predicate_bytes());
    (usize::from(predicate) * length.predicate_bytes() + byte_offset) as u32
}

fn read_predicate_at(code: &mut Vec<u8>, displacement: u32, bytes: usize) {
    code.extend(match bytes {
        HALFWORD_BYTES => MOVZX_EAX_WORD_RDX_DISP32,
        DWORD_BYTES => MOV_EAX_RDX_DISP32,
        QWORD_BYTES => MOV_RAX_RDX_DISP32,
        _ => unreachable!("validated streaming length has 2/4/8-byte predicate chunks"),
    });
    code.extend(displacement.to_le_bytes());
}

fn predicate_bit_pattern(element: ElementSize) -> u64 {
    // Each byte selects the first predicate bit of its architectural element.
    let mut pattern = 0;
    for byte in 0..QWORD_BYTES {
        let bit = (byte / element.bytes()) * element.bytes();
        pattern |= 1u64 << (byte * BITS_PER_BYTE + bit);
    }
    pattern
}

/// Expand packed P bits into a 16-byte FF/00 element mask. Only each element's
/// first predicate bit selects the lane. Destination/scratch must be distinct.
/// Clobbers RAX/RCX/RDX and those two XMMs; preserves other XMMs, RDI and R15.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_predicate_mask(
    code: &mut Vec<u8>,
    predicate: u8,
    chunk: usize,
    element: ElementSize,
    destination: u8,
    scratch: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(chunk < length.chunks());
    xmm(destination);
    xmm(scratch);
    assert_ne!(destination, scratch);
    storage_pointer(code, SCALABLE_PREDICATES_OFFSET);
    read_predicate_at(
        code,
        predicate_offset(predicate, chunk * PREDICATE_MASK_BYTES, length),
        PREDICATE_MASK_BYTES,
    );
    expand_predicate_mask(code, element, destination, scratch, target);
}

/// Expand low16 RAX predicate bits without accessing state storage. Upper RAX
/// bits are ignored. Used by packed P and compressed-counter predicate readers.
/// Clobbers RAX/RCX and destination/scratch XMMs; leaves RDX and other XMMs live.
pub(crate) fn expand_predicate_mask(
    code: &mut Vec<u8>,
    element: ElementSize,
    destination: u8,
    scratch: u8,
    target: TargetCpu,
) {
    xmm(destination);
    xmm(scratch);
    assert_ne!(destination, scratch);
    if element == ElementSize::Quadword {
        code.extend(AND_EAX_IMM8);
        code.push(FIRST_PREDICATE_BIT);
        code.extend(NEG_EAX);
        code.extend(MOVD_XMM_EAX);
        code.push(MODRM_REGISTER | (destination << REGISTER_SHIFT));
        Host::ShuffleDword.register(code, destination, destination, target);
        code.push(REPEAT_LOW_DWORD);
        return;
    }
    code.extend(MOVD_XMM_EAX);
    code.push(MODRM_REGISTER | (destination << REGISTER_SHIFT));
    Host::UnpackLowByte.register(code, destination, destination, target);
    Host::UnpackLowWord.register(code, destination, destination, target);
    if element == ElementSize::Doubleword {
        // Dwords hold the low/high predicate bytes. Their bit0 selects each
        // 8-byte element; arithmetic shifts replicate exactly that bit.
        ShiftOpcode::LeftDword.emit(code, destination, DWORD_SIGN_BIT);
        ShiftOpcode::ArithmeticDword.emit(code, destination, DWORD_SIGN_BIT);
        Host::ShuffleDword.register(code, destination, destination, target);
        code.push(REPEAT_LOW_TWO_DWORDS);
        return;
    }
    Host::ShuffleDword.register(code, destination, destination, target);
    code.push(REPEAT_LOW_TWO_DWORDS);
    code.extend(MOVABS_RCX_IMM64);
    code.extend(predicate_bit_pattern(element).to_le_bytes());
    code.extend(MOVQ_XMM_RCX);
    code.push(MODRM_REGISTER | (scratch << REGISTER_SHIFT) | RCX_REGISTER);
    Host::UnpackLowQword.register(code, scratch, scratch, target);
    Host::And.register(code, destination, scratch, target);
    Host::EqualByte.register(code, destination, scratch, target);
}

fn predicate_chunk(chunk: usize, length: VectorLength) -> (usize, usize) {
    assert!(chunk < length.predicate_bytes().div_ceil(PREDICATE_CHUNK_BYTES));
    let offset = chunk * PREDICATE_CHUNK_BYTES;
    let bytes = (length.predicate_bytes() - offset).min(PREDICATE_CHUNK_BYTES);
    (offset, bytes)
}

/// Read an 8-byte packed-P chunk into RAX, zero-extending a final 2/4-byte chunk.
/// The chunk index addresses packed bytes, not Z chunks. Clobbers RDX only.
pub(crate) fn read_predicate_chunk(
    code: &mut Vec<u8>,
    predicate: u8,
    chunk: usize,
    length: VectorLength,
) {
    let (offset, bytes) = predicate_chunk(chunk, length);
    storage_pointer(code, SCALABLE_PREDICATES_OFFSET);
    read_predicate_at(code, predicate_offset(predicate, offset, length), bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

    #[test]
    fn z_storage_segments_cover_each_register_without_overlap() {
        assert_eq!(core::mem::offset_of!(GuestState, v), 264);
        for bytes in LENGTHS {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for register in 0..32 {
                assert_eq!(vector_offset(register), 264 + u32::from(register) * 16);
                for chunk in 1..length.chunks() {
                    assert_eq!(
                        upper_offset(register, chunk, length) as usize,
                        usize::from(register) * (bytes - 16) + (chunk - 1) * 16
                    );
                }
            }
        }
    }

    #[test]
    fn mask_patterns_select_first_bit_of_each_element() {
        assert_eq!(
            predicate_bit_pattern(ElementSize::Byte),
            0x8040_2010_0804_0201
        );
        assert_eq!(
            predicate_bit_pattern(ElementSize::Halfword),
            0x4040_1010_0404_0101
        );
        assert_eq!(
            predicate_bit_pattern(ElementSize::Word),
            0x1010_1010_0101_0101
        );
        assert_eq!(
            predicate_bit_pattern(ElementSize::Doubleword),
            0x0101_0101_0101_0101
        );
    }
}
