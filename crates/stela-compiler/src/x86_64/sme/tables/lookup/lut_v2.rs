//! SME_LUTv2: LUTI4 with two index vectors, and MOVT to ZT0.
use crate::x86_64::asm::{Code, Mem};

use super::super::{allocate_frame, release_frame, stage};
use super::{TABLE, XMM0, load_packed_indexes, prepare_planes, table_pointer};
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, LOOKUP_TABLE_BYTES, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sme::lut_v2::Operand;
use crate::x86_64::isa::SimdOpcode as Host;
use crate::x86_64::scalable::{load_z_chunk, lut, store_z_chunk};

const INDEX_BITS: u8 = 4;
const RESULT_XMM: u8 = 6;
const ZERO_XMM: u8 = 1;

fn store_table_chunk(code: &mut Code, xmm: u8, offset: usize, target: TargetCpu) {
    Host::StoreUnaligned.emit(code, xmm, Mem::base_disp32(TABLE, offset as i32), target);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
) {
    match *operand {
        Operand::LookupPair {
            destination,
            source,
        } => {
            let frame_bytes = 2 * length.bytes();
            allocate_frame(code, frame_bytes);
            stage(code, &[source, source + 1], length, target);
            table_pointer(code);
            // Compact low bytes from sixteen 32-bit ZT0 entries into XMM4.
            // This Byte specialization uses SSE2 fixed loads and PACK only.
            prepare_planes(code, ElementSize::Byte, target);
            for register in 0..destination.count {
                for chunk in 0..length.chunks() {
                    let output_byte =
                        usize::from(register) * length.bytes() + chunk * VECTOR_CHUNK_BYTES;
                    load_packed_indexes(code, VECTOR_CHUNK_BYTES / 2, output_byte / 2);
                    lut::emit_chunk(code, INDEX_BITS, ElementSize::Byte, target);
                    store_z_chunk(
                        code,
                        destination.register(register),
                        chunk,
                        RESULT_XMM,
                        length,
                        target,
                    );
                }
            }
            release_frame(code, frame_bytes);
        }
        Operand::MoveToTable { source, .. } => {
            let (offset, bytes, clear_tail) = operand.table_transfer(length).unwrap();
            table_pointer(code);
            for chunk in 0..bytes / VECTOR_CHUNK_BYTES {
                load_z_chunk(code, source, chunk, XMM0, length, target);
                store_table_chunk(code, XMM0, offset + chunk * VECTOR_CHUNK_BYTES, target);
            }
            if clear_tail && bytes < LOOKUP_TABLE_BYTES {
                Host::Xor.register(code, ZERO_XMM, ZERO_XMM, target);
                for chunk in bytes / VECTOR_CHUNK_BYTES..LOOKUP_TABLE_BYTES / VECTOR_CHUNK_BYTES {
                    store_table_chunk(code, ZERO_XMM, chunk * VECTOR_CHUNK_BYTES, target);
                }
            }
        }
    }
}
