use super::*;
use crate::{GuestAddress, aarch64::prefetch};
use alloc::vec;
use alloc::vec::Vec;

fn emitted(word: u32) -> Vec<u8> {
    let operand = prefetch::decode(GuestAddress(0), word).unwrap().unwrap();
    let mut code = vec![];
    emit(&mut code, &operand);
    code
}

#[test]
fn advisory_hints_select_baseline_data_prefetch_or_explicit_nop() {
    for hint in 0..32 {
        let code = emitted(0xf9800000 | hint);
        if matches!(hint, 0..=5 | 16..=21) {
            let modrm = if hint & 1 != 0 {
                0
            } else {
                (((hint >> 1) & 3) + 1) << 3
            };
            assert_eq!(&code[7..], &[0x0f, 0x18, modrm as u8]);
        } else {
            assert_eq!(code, [NOP]);
        }
    }
}

#[test]
fn sp_sources_never_add_the_transfer_alignment_trap() {
    for word in [0xf98003e0, 0xf88003e0, 0xf8bf6be0] {
        let code = emitted(word);
        assert_eq!(&code[..7], &[0x48, 0x8b, 0x87, 248, 0, 0, 0]);
        assert!(!code.windows(2).any(|bytes| bytes == [0x0f, 0x0b]));
    }
}
