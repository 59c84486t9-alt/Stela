use super::*;
use alloc::vec::Vec;

#[test]
fn every_streaming_length_emits_bounded_chunks_without_optional_instructions() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for chunk in 0..bytes * 4 / CHUNK_BITS {
            let mut code = Vec::new();
            emit_counter_chunk(&mut code, chunk, length);
            assert!(code.starts_with(MOVZX_R8D_AX));
            assert!(code.ends_with(AND_RAX_R10));
            assert!(code.len() < 256);
        }
    }
}
