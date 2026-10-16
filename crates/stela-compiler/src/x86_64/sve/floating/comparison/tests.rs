use super::*;
use alloc::vec;

#[test]
fn half_refusal_emits_no_frame_or_guard() {
    let mut code = vec![0x90];
    let operand = Operand {
        kind: Kind::Equal,
        format: Format::Half,
        destination: 15,
        governing: 7,
        left: 31,
        right: Some(31),
    };
    assert!(
        !emit(
            &mut code,
            operand,
            VectorLength::from_bytes(256).unwrap(),
            NumericalFeatures::new(true, true, true),
            GuestAddress(0x1000),
            TargetCpu::Baseline,
        )
        .unwrap()
    );
    assert_eq!(code, [0x90]);
}
