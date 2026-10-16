use super::*;

#[test]
fn sign_operations_require_streaming_without_za() {
    const FABS_HALF: u32 = 0x045c_a020;
    const FNEG_DOUBLE: u32 = 0x04dd_bfff;
    const RESERVED_SIGN_SIZE: u32 = 0x041c_a020;
    for bytes in [16, 32, 64, 128, 256] {
        for svcr in 0..=3 {
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::from_svcr(svcr).unwrap(),
            );
            let source = words(&[FABS_HALF, FNEG_DOUBLE, RET_X30]);
            let result =
                compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
            if profile.mode().streaming() {
                let native = result.unwrap();
                assert_eq!(
                    native.source_map[0],
                    (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                );
                assert_eq!(native.source_map[1].0, GuestAddress(4));
                assert!(native.source_map[1].1 > native.source_map[0].1);
            } else {
                assert!(result.unwrap_err().0.contains("streaming mode required"));
            }
        }
    }
    assert!(crate::compile(&words(&[FABS_HALF, RET_X30]), GuestAddress(0)).is_err());
    assert!(
        compile_for_profile(
            &words(&[RESERVED_SIGN_SIZE, RET_X30]),
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .0
        .contains("reserved streaming sign")
    );
}
