//! Packed predicate helpers.
mod counter;
mod counter_mask;
mod flags;

pub(crate) use counter::{emit_counter_chunk, emit_prepared_counter_chunk, prepare_counter};
pub(crate) use counter_mask::emit_prepared_counter_mask;
pub(crate) use flags::{accumulate_predtest, begin_predtest, finish_predtest, leading_bits};

const CHUNK_BITS: usize = 64;
