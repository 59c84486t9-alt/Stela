//! Exact packed predicate writes and chunk access for registered consumers.
//! This child is enabled only when an instruction family needs these helpers.

use super::{
    DWORD_BYTES, HALFWORD_BYTES, PREDICATE_CHUNK_BYTES, QWORD_BYTES, predicate_chunk,
    predicate_offset, storage_pointer,
};
use crate::{aarch64::scalable::VectorLength, context::SCALABLE_PREDICATES_OFFSET};
use alloc::vec::Vec;

const MOV_RDX_DISP32_AX: &[u8] = &[0x66, 0x89, 0x82];
const MOV_RDX_DISP32_EAX: &[u8] = &[0x89, 0x82];
const MOV_RDX_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x82];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

pub(super) fn write_predicate_at(code: &mut Vec<u8>, displacement: u32, bytes: usize) {
    code.extend(match bytes {
        HALFWORD_BYTES => MOV_RDX_DISP32_AX,
        DWORD_BYTES => MOV_RDX_DISP32_EAX,
        QWORD_BYTES => MOV_RDX_DISP32_RAX,
        _ => unreachable!("validated streaming length has 2/4/8-byte predicate chunks"),
    });
    code.extend(displacement.to_le_bytes());
}

/// Write low RAX bytes to one packed-P chunk without touching adjacent P slots.
/// Final 2/4-byte chunks use that exact width. RAX is preserved; RDX is scratch.
pub(crate) fn write_predicate_chunk(
    code: &mut Vec<u8>,
    predicate: u8,
    chunk: usize,
    length: VectorLength,
) {
    let (offset, bytes) = predicate_chunk(chunk, length);
    storage_pointer(code, SCALABLE_PREDICATES_OFFSET);
    write_predicate_at(code, predicate_offset(predicate, offset, length), bytes);
}

/// Clear a complete packed P register. Clobbers RAX/RDX; all XMMs survive.
pub(crate) fn zero_predicate(code: &mut Vec<u8>, predicate: u8, length: VectorLength) {
    storage_pointer(code, SCALABLE_PREDICATES_OFFSET);
    code.extend(XOR_EAX_EAX);
    for offset in (0..length.predicate_bytes()).step_by(PREDICATE_CHUNK_BYTES) {
        let bytes = (length.predicate_bytes() - offset).min(PREDICATE_CHUNK_BYTES);
        write_predicate_at(code, predicate_offset(predicate, offset, length), bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

    #[test]
    fn predicate_chunks_cover_exact_slot_widths() {
        for bytes in LENGTHS {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let mut covered = 0;
            for chunk in 0..length.predicate_bytes().div_ceil(PREDICATE_CHUNK_BYTES) {
                let (offset, width) = predicate_chunk(chunk, length);
                assert_eq!(offset, covered);
                assert!(matches!(width, 2 | 4 | 8));
                covered += width;
                for predicate in 0..16 {
                    assert_eq!(
                        predicate_offset(predicate, offset, length) as usize,
                        usize::from(predicate) * length.predicate_bytes() + covered - width
                    );
                }
            }
            assert_eq!(covered, length.predicate_bytes());
        }
    }
}
