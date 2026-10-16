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
