//! LUTv2 adds two protected index vectors and streaming vector-to-table moves.
//! Index vectors are staged before any destination commit. All table accesses
//! have fixed addresses; lookup uses the shared constant-time SSE2/SSSE3 core.

use super::super::{allocate_frame, release_frame, stage};
use super::{MOV_R8_CONTEXT_DISP8, MOV_R8_R8_DISP8, XMM0, load_packed_indexes, prepare_planes};
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, LOOKUP_TABLE_BYTES, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sme::lut_v2::Operand;
use crate::context::{EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_ZT0_OFFSET};
use crate::x86_64::isa::SimdOpcode as Host;
use crate::x86_64::scalable::{load_z_chunk, lut, store_z_chunk};
use alloc::vec::Vec;

const INDEX_BITS: u8 = 4;
const RESULT_XMM: u8 = 6;
const ZERO_XMM: u8 = 1;
const MODRM_DISP32_R8: u8 = 0x80;
const REGISTER_SHIFT: u8 = 3;
const REX_R8_BASE: u8 = 0x41;

fn table_pointer(code: &mut Vec<u8>) {
    code.extend(MOV_R8_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_SCALABLE_OFFSET as u8);
    code.extend(MOV_R8_R8_DISP8);
    code.push(SCALABLE_ZT0_OFFSET as u8);
}

fn store_table_chunk(code: &mut Vec<u8>, xmm: u8, offset: usize, target: TargetCpu) {
    assert!(target.supports(Host::StoreUnaligned.requires()));
    let opcode = Host::StoreUnaligned.encoding();
    // REX.B selects R8 after the mandatory REP prefix and before the opcode.
    code.push(opcode[0]);
    code.push(REX_R8_BASE);
    code.extend(&opcode[1..]);
    code.push(MODRM_DISP32_R8 | (xmm << REGISTER_SHIFT));
    code.extend((offset as u32).to_le_bytes());
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
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
