//! Shared packed-predicate helpers, grouped by architectural responsibility.
use alloc::vec::Vec;
mod counter;
mod counter_mask;
mod flags;

pub(crate) use counter::{emit_counter_chunk, emit_prepared_counter_chunk, prepare_counter};
pub(crate) use counter_mask::emit_prepared_counter_mask;
pub(crate) use flags::{accumulate_predtest, begin_predtest, finish_predtest, leading_bits};

const CHUNK_BITS: usize = 64;
const REL32_BYTES: usize = 4;

fn jump(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend([0; REL32_BYTES]);
    displacement
}

fn bind(code: &mut [u8], displacement: usize) {
    let relative = i32::try_from(code.len() - displacement - REL32_BYTES).unwrap();
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&relative.to_le_bytes());
}
