//! Fixed-SVL rearrangement recipes using baseline SSE2 and checked SSSE3.
//! Source snapshots are needed only for aliased permutations crossing chunks.
use alloc::vec::Vec;
mod dynamic;

use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sve::rearrange::{InterleaveKind, Operand};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_mask, store_z_chunk};

const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const MOVABS_RAX_IMM64: &[u8] = &[0x48, 0xb8];
const MODRM_STACK_DISP32: u8 = 0x84;
const STACK_SIB: u8 = 0x24;
const XMM_FIELD_SHIFT: u8 = 3;
const MODRM_REGISTER: u8 = 0xc0;
const FIRST: u8 = 0;
const SECOND: u8 = 1;
const REVERSE_SCRATCH: u8 = 2;
const MASK: u8 = 6;
const SCRATCH: u8 = 7;
const BITS_PER_BYTE: u8 = 8;
const WORD_BITS: u8 = 16;
const QWORD_BYTES: u8 = 8;
const SELECT_EVEN_DWORDS: u8 = 0x88;
const SELECT_ODD_DWORDS: u8 = 0xdd;
const REVERSE_FOUR: u8 = 0x1b;
const SWAP_QWORDS: u8 = 0x4e;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_LOW_DWORD: u8 = 0;
const LOW_BYTE_EACH_WORD: u64 = 0x00ff_00ff_00ff_00ff;
const BYTE_REVERSE_LOW: u64 = 0x0809_0a0b_0c0d_0e0f;
const BYTE_REVERSE_HIGH: u64 = 0x0001_0203_0405_0607;

fn stack_memory(code: &mut Vec<u8>, opcode: Host, xmm: u8, offset: usize, target: TargetCpu) {
    opcode.append(code, target);
    code.push(MODRM_STACK_DISP32 | (xmm << XMM_FIELD_SHIFT));
    code.push(STACK_SIB);
    code.extend((offset as u32).to_le_bytes());
}

fn constant(code: &mut Vec<u8>, value: u64, xmm: u8, target: TargetCpu) {
    code.extend(MOVABS_RAX_IMM64);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (xmm << XMM_FIELD_SHIFT));
}

fn shuffle(code: &mut Vec<u8>, opcode: Host, xmm: u8, control: u8, target: TargetCpu) {
    opcode.register(code, xmm, xmm, target);
    code.push(control);
}

struct Snapshot {
    register: Option<u8>,
    length: VectorLength,
}

impl Snapshot {
    fn new(
        code: &mut Vec<u8>,
        destination: u8,
        sources: &[u8],
        crossing: bool,
        length: VectorLength,
        target: TargetCpu,
    ) -> Self {
        let register = (crossing && length.chunks() > 1 && sources.contains(&destination))
            .then_some(destination);
        if register.is_some() {
            code.extend(SUB_RSP_IMM32);
            code.extend((length.bytes() as u32).to_le_bytes());
            for chunk in 0..length.chunks() {
                load_z_chunk(code, destination, chunk, FIRST, length, target);
                stack_memory(
                    code,
                    Host::StoreUnaligned,
                    FIRST,
                    chunk * VECTOR_CHUNK_BYTES,
                    target,
                );
            }
        }
        Self { register, length }
    }

    fn load(&self, code: &mut Vec<u8>, register: u8, chunk: usize, xmm: u8, target: TargetCpu) {
        if self.register == Some(register) {
            stack_memory(
                code,
                Host::LoadUnaligned,
                xmm,
                chunk * VECTOR_CHUNK_BYTES,
                target,
            );
        } else {
            load_z_chunk(code, register, chunk, xmm, self.length, target);
        }
    }

    fn finish(self, code: &mut Vec<u8>) {
        if self.register.is_some() {
            code.extend(ADD_RSP_IMM32);
            code.extend((self.length.bytes() as u32).to_le_bytes());
        }
    }
}

fn unpack(element: ElementSize, high: bool) -> Host {
    match (element, high) {
        (ElementSize::Byte, false) => Host::UnpackLowByte,
        (ElementSize::Byte, true) => Host::UnpackHighByte,
        (ElementSize::Halfword, false) => Host::UnpackLowWord,
        (ElementSize::Halfword, true) => Host::UnpackHighWord,
        (ElementSize::Word, false) => Host::UnpackLowDword,
        (ElementSize::Word, true) => Host::UnpackHighDword,
        (ElementSize::Doubleword, false) => Host::UnpackLowQword,
        (ElementSize::Doubleword, true) => Host::UnpackHighQword,
        _ => unreachable!("ordinary interleaving excludes quadwords"),
    }
}

/// Compact selected odd/even elements into the low qword without saturation loss.
fn compact(code: &mut Vec<u8>, xmm: u8, element: ElementSize, part: u8, target: TargetCpu) {
    match element {
        ElementSize::Byte => {
            if part == 0 {
                Host::And.register(code, xmm, MASK, target);
            } else {
                Shift::RightWord.emit(code, xmm, BITS_PER_BYTE);
            }
            Host::PackUnsignedWordToByte.register(code, xmm, xmm, target);
        }
        ElementSize::Halfword => {
            if part == 0 {
                Shift::LeftDword.emit(code, xmm, WORD_BITS);
            }
            Shift::ArithmeticDword.emit(code, xmm, WORD_BITS);
            Host::PackSignedDwordToWord.register(code, xmm, xmm, target);
        }
        ElementSize::Word => shuffle(
            code,
            Host::ShuffleDword,
            xmm,
            if part == 0 {
                SELECT_EVEN_DWORDS
            } else {
                SELECT_ODD_DWORDS
            },
            target,
        ),
        ElementSize::Doubleword => {
            if part != 0 {
                Shift::RightBytes.emit(code, xmm, QWORD_BYTES);
            }
        }
        _ => unreachable!("ordinary compaction excludes quadwords"),
    }
}

fn interleave(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let Operand::Interleave {
        kind,
        part,
        segment,
        element_size: element,
        destination,
        source,
        second,
    } = operand
    else {
        unreachable!("interleave allocation");
    };
    let snapshot = Snapshot::new(
        code,
        destination,
        &[source, second],
        !segment && kind != InterleaveKind::Transpose,
        length,
        target,
    );
    if element == ElementSize::Byte && kind != InterleaveKind::Zip && part == 0 {
        constant(code, LOW_BYTE_EACH_WORD, MASK, target);
        Host::UnpackLowQword.register(code, MASK, MASK, target);
    }
    for chunk in 0..length.chunks() {
        match kind {
            InterleaveKind::Zip => {
                let position = if segment {
                    usize::from(part)
                } else {
                    usize::from(part) * length.chunks() + chunk
                };
                let source_chunk = if segment { chunk } else { position / 2 };
                snapshot.load(code, source, source_chunk, FIRST, target);
                snapshot.load(code, second, source_chunk, SECOND, target);
                unpack(element, !position.is_multiple_of(2)).register(code, FIRST, SECOND, target);
            }
            InterleaveKind::Transpose => {
                snapshot.load(code, source, chunk, FIRST, target);
                snapshot.load(code, second, chunk, SECOND, target);
                if element == ElementSize::Doubleword {
                    unpack(element, part != 0).register(code, FIRST, SECOND, target);
                } else {
                    compact(code, FIRST, element, part, target);
                    compact(code, SECOND, element, part, target);
                    unpack(element, false).register(code, FIRST, SECOND, target);
                }
            }
            InterleaveKind::Unzip => {
                if segment || length.chunks() == 1 {
                    snapshot.load(code, source, chunk, FIRST, target);
                    snapshot.load(code, second, chunk, SECOND, target);
                } else {
                    let half = length.chunks() / 2;
                    let selected = if chunk < half { source } else { second };
                    let source_chunk = (chunk % half) * 2;
                    snapshot.load(code, selected, source_chunk, FIRST, target);
                    snapshot.load(code, selected, source_chunk + 1, SECOND, target);
                }
                compact(code, FIRST, element, part, target);
                compact(code, SECOND, element, part, target);
                Host::UnpackLowQword.register(code, FIRST, SECOND, target);
            }
        }
        store_z_chunk(code, destination, chunk, FIRST, length, target);
    }
    snapshot.finish(code);
}

fn extract(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let Operand::Extract {
        destination,
        source,
        second,
        byte_offset: offset,
        segment,
    } = operand
    else {
        unreachable!("extract allocation");
    };
    let offset = if !segment && usize::from(offset) >= length.bytes() {
        0
    } else {
        usize::from(offset)
    };
    let snapshot = Snapshot::new(
        code,
        destination,
        &[source, second],
        !segment,
        length,
        target,
    );
    for chunk in 0..length.chunks() {
        let position = if segment {
            offset
        } else {
            chunk * VECTOR_CHUNK_BYTES + offset
        };
        let first_register = if position < length.bytes() {
            source
        } else {
            second
        };
        let first_chunk = if segment {
            chunk
        } else {
            (position % length.bytes()) / VECTOR_CHUNK_BYTES
        };
        let shift = (position % VECTOR_CHUNK_BYTES) as u8;
        snapshot.load(code, first_register, first_chunk, FIRST, target);
        if shift != 0 {
            let (next_register, next_chunk) = if segment {
                (second, chunk)
            } else if first_chunk + 1 < length.chunks() {
                (first_register, first_chunk + 1)
            } else {
                (second, 0)
            };
            snapshot.load(code, next_register, next_chunk, SECOND, target);
            if target.supports(TargetCpu::Ssse3) {
                Host::AlignBytes.register(code, SECOND, FIRST, target);
                code.push(shift);
                Host::MoveAligned.register(code, FIRST, SECOND, target);
            } else {
                Shift::RightBytes.emit(code, FIRST, shift);
                Shift::LeftBytes.emit(code, SECOND, VECTOR_CHUNK_BYTES as u8 - shift);
                Host::Or.register(code, FIRST, SECOND, target);
            }
        }
        store_z_chunk(code, destination, chunk, FIRST, length, target);
    }
    snapshot.finish(code);
}

fn reverse_chunk(
    code: &mut Vec<u8>,
    xmm: u8,
    scratch: u8,
    element: ElementSize,
    target: TargetCpu,
) {
    if element == ElementSize::Byte && target.supports(TargetCpu::Ssse3) {
        Host::ByteShuffle.register(code, xmm, MASK, target);
        return;
    }
    if element == ElementSize::Byte {
        Host::MoveAligned.register(code, scratch, xmm, target);
        Shift::LeftWord.emit(code, xmm, BITS_PER_BYTE);
        Shift::RightWord.emit(code, scratch, BITS_PER_BYTE);
        Host::Or.register(code, xmm, scratch, target);
    }
    if matches!(element, ElementSize::Byte | ElementSize::Halfword) {
        shuffle(code, Host::ShuffleLowWord, xmm, REVERSE_FOUR, target);
        shuffle(code, Host::ShuffleHighWord, xmm, REVERSE_FOUR, target);
        shuffle(code, Host::ShuffleDword, xmm, SWAP_QWORDS, target);
    } else {
        shuffle(
            code,
            Host::ShuffleDword,
            xmm,
            if element == ElementSize::Word {
                REVERSE_FOUR
            } else {
                SWAP_QWORDS
            },
            target,
        );
    }
}

fn reverse(
    code: &mut Vec<u8>,
    destination: u8,
    source: u8,
    element: ElementSize,
    length: VectorLength,
    target: TargetCpu,
) {
    if element == ElementSize::Byte && target.supports(TargetCpu::Ssse3) {
        constant(code, BYTE_REVERSE_LOW, MASK, target);
        constant(code, BYTE_REVERSE_HIGH, SCRATCH, target);
        Host::UnpackLowQword.register(code, MASK, SCRATCH, target);
    }
    if destination == source {
        // Capture both ends before either commit; no full-vector stack mirror.
        for chunk in 0..length.chunks().div_ceil(2) {
            let opposite = length.chunks() - 1 - chunk;
            load_z_chunk(code, source, opposite, FIRST, length, target);
            if opposite != chunk {
                load_z_chunk(code, source, chunk, SECOND, length, target);
            }
            reverse_chunk(code, FIRST, REVERSE_SCRATCH, element, target);
            if opposite != chunk {
                reverse_chunk(code, SECOND, REVERSE_SCRATCH, element, target);
            }
            store_z_chunk(code, destination, chunk, FIRST, length, target);
            if opposite != chunk {
                store_z_chunk(code, destination, opposite, SECOND, length, target);
            }
        }
    } else {
        for chunk in 0..length.chunks() {
            load_z_chunk(
                code,
                source,
                length.chunks() - 1 - chunk,
                FIRST,
                length,
                target,
            );
            reverse_chunk(code, FIRST, REVERSE_SCRATCH, element, target);
            store_z_chunk(code, destination, chunk, FIRST, length, target);
        }
    }
}

/// Profile requirement for the actual selected instruction recipe.
pub(crate) fn requires_explicit_dit_zero(
    operand: Operand,
    length: VectorLength,
    target: TargetCpu,
) -> bool {
    dynamic::requires_explicit_dit_zero(operand, length, target)
}

/// Emit a fully decoded operand under the validated scalable execution profile.
pub(crate) fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    match operand {
        operand @ Operand::Interleave { .. } => interleave(code, operand, length, target),
        operand @ Operand::Extract { .. } => extract(code, operand, length, target),
        Operand::Reverse {
            destination,
            source,
            element_size,
        } => reverse(code, destination, source, element_size, length, target),
        Operand::ReverseDouble {
            destination,
            source,
            governing,
        } => {
            for chunk in 0..length.chunks() {
                load_z_chunk(code, source, chunk, FIRST, length, target);
                shuffle(code, Host::ShuffleDword, FIRST, SWAP_QWORDS, target);
                read_predicate_mask(
                    code,
                    governing,
                    chunk,
                    ElementSize::Quadword,
                    MASK,
                    SCRATCH,
                    length,
                    target,
                );
                Host::And.register(code, FIRST, MASK, target);
                load_z_chunk(code, destination, chunk, SECOND, length, target);
                Host::AndNot.register(code, MASK, SECOND, target);
                Host::Or.register(code, FIRST, MASK, target);
                store_z_chunk(code, destination, chunk, FIRST, length, target);
            }
        }
        Operand::DuplicateSegment {
            destination,
            source,
            index,
            element_size,
        } => {
            for chunk in 0..length.chunks() {
                load_z_chunk(code, source, chunk, FIRST, length, target);
                Shift::RightBytes.emit(
                    code,
                    FIRST,
                    (usize::from(index) * element_size.bytes()) as u8,
                );
                match element_size {
                    ElementSize::Byte => {
                        Host::UnpackLowByte.register(code, FIRST, FIRST, target);
                        Host::UnpackLowWord.register(code, FIRST, FIRST, target);
                        shuffle(code, Host::ShuffleDword, FIRST, REPEAT_LOW_DWORD, target);
                    }
                    ElementSize::Halfword => {
                        Host::UnpackLowWord.register(code, FIRST, FIRST, target);
                        shuffle(code, Host::ShuffleDword, FIRST, REPEAT_LOW_DWORD, target);
                    }
                    ElementSize::Word => {
                        shuffle(code, Host::ShuffleDword, FIRST, REPEAT_LOW_DWORD, target)
                    }
                    ElementSize::Doubleword => {
                        shuffle(code, Host::ShuffleDword, FIRST, REPEAT_LOW_QWORD, target)
                    }
                    _ => unreachable!("DUPQ excludes quadword elements"),
                }
                store_z_chunk(code, destination, chunk, FIRST, length, target);
            }
        }
        Operand::DuplicateMask { destination, mask } => {
            constant(code, mask, FIRST, target);
            Host::UnpackLowQword.register(code, FIRST, FIRST, target);
            for chunk in 0..length.chunks() {
                store_z_chunk(code, destination, chunk, FIRST, length, target);
            }
        }
        operand @ (Operand::Table { .. } | Operand::Splice { .. } | Operand::Index { .. }) => {
            dynamic::emit(code, operand, length, target);
        }
    }
}
