use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn invalid_layout_does_not_emit() {
    let length = VectorLength::from_bytes(256).unwrap();
    for outputs in [
        vec![],
        vec![Output::Z(32)],
        vec![Output::Predicate(16)],
        vec![Output::V(32)],
        vec![Output::Z(0), Output::V(0)],
        vec![Output::Predicate(1); 2],
        vec![Output::Z(0); 5],
    ] {
        let mut code = vec![0xaa];
        assert!(begin(&mut code, length, &outputs, Environment::Exact).is_err());
        assert_eq!(code, [0xaa]);
    }
}

#[test]
fn bounded_call_aligned_layout() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for environment in [Environment::Exact, Environment::PrivateMxcsr] {
            for outputs in [
                vec![Output::Predicate(0)],
                vec![Output::V(0)],
                vec![Output::Z(0)],
                vec![Output::Z(0), Output::Z(1), Output::Z(2), Output::Z(3)],
            ] {
                let frame = begin(&mut Vec::new(), length, &outputs, environment).unwrap();
                assert_eq!(
                    frame.bytes as usize % VECTOR_CHUNK_BYTES,
                    CALL_ALIGNMENT_PAD
                );
                assert!(frame.bytes as usize <= MAX_FRAME_BYTES);
                for slot in frame.slots {
                    assert_eq!(slot.offset as usize % VECTOR_CHUNK_BYTES, 0);
                }
            }
        }
    }
}
