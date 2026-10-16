use crate::{GuestAddress, block};
use alloc::vec::Vec;

const FCVT_H_S: u32 = 0x1e23c020;
const SCVTF_H_W: u32 = 0x1ee20020;
const FCVTAS_W_S: u32 = 0x1e240020;
const FJCVTZS_W_D: u32 = 0x1e7e0020;
const FCVT_S_H: u32 = 0x1ee24020;
const SCVTF_S_W: u32 = 0x1e220020;
const FCVTL_4S_4H: u32 = 0x0e217820;
const UNSUPPORTED_SUFFIX: u32 = u32::MAX;

#[test]
fn terminal_conversions_do_not_consume_or_validate_an_unreached_suffix() {
    for word in [FCVT_H_S, SCVTF_H_W, FCVTAS_W_S] {
        let bytes: Vec<u8> = [word, UNSUPPORTED_SUFFIX]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let compiled = block::compile(&bytes, GuestAddress(0x1000)).unwrap();
        assert_eq!(compiled.source_bytes, size_of::<u32>());
        assert_eq!(compiled.native.source_map, [(GuestAddress(0x1000), 0)]);
    }
    for word in [FCVT_S_H, SCVTF_S_W, FCVTL_4S_4H, FJCVTZS_W_D] {
        let bytes: Vec<u8> = [word, UNSUPPORTED_SUFFIX]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert!(block::compile(&bytes, GuestAddress(0x1000)).is_err());
    }
}
