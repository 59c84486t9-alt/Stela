use super::*;
use alloc::vec::Vec;

#[test]
fn numerical_instructions_require_the_block_exit_protocol() {
    const FADD_S: u32 = 0x1e222820;
    const FADD_H: u32 = 0x1ee22820;
    const FADD_2S: u32 = 0x0e22d420;
    const FADD_4H: u32 = 0x0e421420;
    const RET: u32 = 0xd65f03c0;
    for word in [FADD_S, FADD_H, FADD_2S, FADD_4H] {
        let bytes: Vec<u8> = [word, RET]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert!(
            crate::compile(&bytes, GuestAddress(0x1000))
                .unwrap_err()
                .0
                .contains("NumericalRuntimeRequired")
        );
        let block = crate::block::compile(&bytes, GuestAddress(0x1000)).unwrap();
        if [FADD_H, FADD_4H].contains(&word) {
            assert_eq!(block.source_bytes, size_of::<u32>());
            assert_eq!(block.native.source_map, [(GuestAddress(0x1000), 0)]);
        } else {
            assert_eq!(block.native.source_map.len(), 2);
            assert_eq!(block.native.source_map[1].0, GuestAddress(0x1004));
        }
    }
}
