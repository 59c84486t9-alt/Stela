use super::*;
use crate::aarch64::sme::movement::decode;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn rejected_debug_and_short_length_emit_nothing() {
    let length = VectorLength::from_bytes(16).unwrap();
    for word in [
        0xc04c_03e0,
        0xc04e_03e0,
        0xc0c6_0400,
        0xc0c6_0600,
        0xc0c4_0400,
    ] {
        let operand = decode(word).unwrap();
        let mut code = vec![0x90];
        assert!(emit(&mut code, &operand, length, TargetCpu::Baseline).is_err());
        assert_eq!(code, [0x90]);
    }
}

#[test]
fn empty_tile_mask_has_no_output_and_full_mask_is_bounded() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let mut code = Vec::new();
        emit(
            &mut code,
            &decode(0xc008_0000).unwrap(),
            length,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert!(code.is_empty());
        emit(
            &mut code,
            &decode(0xc008_00ff).unwrap(),
            length,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert!(code.len() < 256);
    }
}

#[test]
fn only_vertical_doubleword_scatter_uses_checked_extension() {
    let length = VectorLength::from_bytes(64).unwrap();
    for word in [
        0xc000_8000,
        0xc040_8000,
        0xc080_8000,
        0xc0c0_0000,
        0xc0c2_8000,
    ] {
        let operand = decode(word).unwrap();
        let mut baseline = Vec::new();
        let mut checked = Vec::new();
        emit(&mut baseline, &operand, length, TargetCpu::Baseline).unwrap();
        emit(&mut checked, &operand, length, TargetCpu::Sse41).unwrap();
        assert_eq!(baseline, checked);
    }
    let operand = decode(0xc0c0_8000).unwrap();
    let mut baseline = Vec::new();
    let mut checked = Vec::new();
    emit(&mut baseline, &operand, length, TargetCpu::Baseline).unwrap();
    emit(&mut checked, &operand, length, TargetCpu::Sse41).unwrap();
    assert!(checked.len() < baseline.len());
}
