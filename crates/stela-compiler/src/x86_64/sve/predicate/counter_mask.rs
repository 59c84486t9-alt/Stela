//! Vector expansion of predicate-as-counter masks.
use super::{CHUNK_BITS, emit_prepared_counter_chunk};
use crate::aarch64::scalable::VectorLength;
use crate::x86_64::asm::Code;

const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const VECTOR_MASK_BYTES: usize = 16;

/// Expand one16-byte counter segment from prepare_counter state. Preserves
/// R8/R9/R10/RDX/RDI/R15 and other XMMs; clobbers RAX/RCX/R11 and both mask XMMs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_prepared_counter_mask(
    code: &mut Code,
    group: usize,
    chunk: usize,
    element: crate::aarch64::scalable::ElementSize,
    destination: u8,
    scratch: u8,
    length: VectorLength,
    target: crate::TargetCpu,
) {
    assert!(group < 4 && chunk < length.chunks());
    let bit_offset = group * length.bytes() + chunk * VECTOR_MASK_BYTES;
    emit_prepared_counter_chunk(code, bit_offset / CHUNK_BITS, length);
    let shift = bit_offset % CHUNK_BITS;
    if shift != 0 {
        code.extend(SHR_RAX_IMM8);
        code.push(shift as u8);
    }
    crate::x86_64::scalable::expand_predicate_mask(code, element, destination, scratch, target);
}
