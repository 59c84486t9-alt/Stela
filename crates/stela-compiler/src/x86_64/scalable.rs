//! Scalable register access for the extended native ABI.
//!
//! RDI holds GuestState and R15 the ExecutionContext. The low 128 bits of each Z
//! register live in `GuestState::v`; the upper bytes and packed predicates live
//! in the scalable view. Helpers clobber only RAX/RCX/RDX and XMM0-7.
use crate::x86_64::asm::Gpr::{R15, Rax, Rcx, Rdi, Rdx};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Rm, Size, Unary};

pub(crate) use super::memory_context as memory;

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
const HALFWORD_BYTES: usize = core::mem::size_of::<u16>();
const DWORD_BYTES: usize = core::mem::size_of::<u32>();
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const PREDICATE_CHUNK_BYTES: usize = QWORD_BYTES;
const PREDICATE_MASK_BYTES: usize = VECTOR_CHUNK_BYTES / BITS_PER_BYTE;
const DWORD_SIGN_BIT: u8 = (u32::BITS - 1) as u8;
const REPEAT_LOW_DWORD: u8 = 0;
const REPEAT_LOW_TWO_DWORDS: u8 = 0x50;
const FIRST_PREDICATE_BIT: u8 = 1;

fn xmm(register: u8) {
    assert!(
        register < XMM_REGISTER_COUNT,
        "scalable helper requires XMM0..7"
    );
}

fn storage_pointer(code: &mut Code, field: u32) {
    // Both fields fit positive signed disp8 in the versioned shared ABI.
    debug_assert!(EXECUTION_CONTEXT_SCALABLE_OFFSET <= i8::MAX as u32);
    debug_assert!(field <= i8::MAX as u32);
    let mut asm = code.asm();
    asm.mov_load(
        Size::Qword,
        Rdx,
        Mem::base_disp8(R15, EXECUTION_CONTEXT_SCALABLE_OFFSET as i8),
    );
    asm.mov_load(Size::Qword, Rdx, Mem::base_disp8(Rdx, field as i8));
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
    code: &mut Code,
    opcode: Host,
    register: u8,
    base: Gpr,
    displacement: u32,
    target: TargetCpu,
) {
    xmm(register);
    code.asm().simd(
        opcode,
        register,
        Mem::base_disp32(base, displacement as i32),
        target,
    );
}

/// Read one 16-byte Z segment into XMM0..7. Upper chunks clobber RDX only.
pub(crate) fn load_z_chunk(
    code: &mut Code,
    register: u8,
    chunk: usize,
    destination: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(chunk < length.chunks());
    let (base, displacement) = if chunk == 0 {
        (Rdi, vector_offset(register))
    } else {
        storage_pointer(code, SCALABLE_Z_UPPER_OFFSET);
        (Rdx, upper_offset(register, chunk, length))
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
    code: &mut Code,
    register: u8,
    chunk: usize,
    source: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(chunk < length.chunks());
    let (base, displacement) = if chunk == 0 {
        (Rdi, vector_offset(register))
    } else {
        storage_pointer(code, SCALABLE_Z_UPPER_OFFSET);
        (Rdx, upper_offset(register, chunk, length))
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

fn read_predicate_at(code: &mut Code, displacement: u32, bytes: usize) {
    let source = Mem::base_disp32(Rdx, displacement as i32);
    let mut asm = code.asm();
    match bytes {
        HALFWORD_BYTES => asm.movzx(Size::Dword, Rax, Size::Word, source),
        DWORD_BYTES => asm.mov_load(Size::Dword, Rax, source),
        QWORD_BYTES => asm.mov_load(Size::Qword, Rax, source),
        _ => unreachable!("validated streaming length has 2/4/8-byte predicate chunks"),
    }
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

/// The distinct destination and scratch XMMs used to expand a predicate.
#[derive(Clone, Copy)]
pub(crate) struct MaskRegisters {
    destination: u8,
    scratch: u8,
}

impl MaskRegisters {
    pub(crate) fn new(destination: u8, scratch: u8) -> Self {
        xmm(destination);
        xmm(scratch);
        assert_ne!(destination, scratch);
        Self {
            destination,
            scratch,
        }
    }

    pub(crate) fn expand(self, code: &mut Code, element: ElementSize, target: TargetCpu) {
        expand_predicate_mask(code, element, self.destination, self.scratch, target);
    }
}

/// Expand packed P bits into a 16-byte FF/00 element mask. Only each element's
/// first predicate bit selects the lane.
/// Clobbers RAX/RCX/RDX and the mask XMMs; preserves other XMMs, RDI and R15.
pub(crate) fn read_predicate_mask(
    code: &mut Code,
    predicate: u8,
    chunk: usize,
    element: ElementSize,
    registers: MaskRegisters,
    length: VectorLength,
    target: TargetCpu,
) {
    assert!(chunk < length.chunks());
    storage_pointer(code, SCALABLE_PREDICATES_OFFSET);
    read_predicate_at(
        code,
        predicate_offset(predicate, chunk * PREDICATE_MASK_BYTES, length),
        PREDICATE_MASK_BYTES,
    );
    registers.expand(code, element, target);
}

/// Expand low16 RAX predicate bits without accessing state storage. Upper RAX
/// bits are ignored. Used by packed P and compressed-counter predicate readers.
/// Clobbers RAX/RCX and destination/scratch XMMs; leaves RDX and other XMMs live.
pub(crate) fn expand_predicate_mask(
    code: &mut Code,
    element: ElementSize,
    destination: u8,
    scratch: u8,
    target: TargetCpu,
) {
    xmm(destination);
    xmm(scratch);
    assert_ne!(destination, scratch);
    if element == ElementSize::Quadword {
        let mut asm = code.asm();
        asm.alu_imm8(Alu::And, Size::Dword, Rax, FIRST_PREDICATE_BIT as i8);
        asm.unary(Unary::Neg, Size::Dword, Rax);
        code.asm().movd_to_xmm(destination, Rax);
        code.asm().simd_imm(
            Host::ShuffleDword,
            destination,
            Rm::Xmm(destination),
            REPEAT_LOW_DWORD,
            target,
        );
        return;
    }
    code.asm().movd_to_xmm(destination, Rax);
    Host::UnpackLowByte.register(code, destination, destination, target);
    Host::UnpackLowWord.register(code, destination, destination, target);
    if element == ElementSize::Doubleword {
        // Dwords hold the low/high predicate bytes. Their bit0 selects each
        // 8-byte element; arithmetic shifts replicate exactly that bit.
        ShiftOpcode::LeftDword.emit(code, destination, DWORD_SIGN_BIT);
        ShiftOpcode::ArithmeticDword.emit(code, destination, DWORD_SIGN_BIT);
        code.asm().simd_imm(
            Host::ShuffleDword,
            destination,
            Rm::Xmm(destination),
            REPEAT_LOW_TWO_DWORDS,
            target,
        );
        return;
    }
    code.asm().simd_imm(
        Host::ShuffleDword,
        destination,
        Rm::Xmm(destination),
        REPEAT_LOW_TWO_DWORDS,
        target,
    );
    code.asm().mov_imm64(Rcx, predicate_bit_pattern(element));
    code.asm().movq_to_xmm(scratch, Rcx);
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
    code: &mut Code,
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
