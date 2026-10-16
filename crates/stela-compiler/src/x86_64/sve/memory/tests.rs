use super::*;

#[test]
fn declared_lengths_keep_every_allocated_address_scale_integral() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for memory in [1, 2, 4, 8, 16] {
            for element in [1, 2, 4, 8, 16] {
                let scale = Scale::VectorBytes {
                    multiply: memory,
                    divide: element,
                };
                assert_eq!(
                    scale_bytes(scale, length) * usize::from(element),
                    bytes * usize::from(memory)
                );
            }
        }
    }
}
