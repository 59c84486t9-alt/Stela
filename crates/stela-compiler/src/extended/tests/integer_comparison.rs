use super::*;

#[test]
fn integer_comparison_preflight_rejects_non_streaming_reserved_and_prefix_inputs() {
    const CMPEQ_BYTE: u32 = 0x2400_2020;
    const CMPEQ_WIDE_RESERVED_DOUBLEWORD: u32 = 0x24c0_2020;
    const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
    for (input, streaming, reason) in [
        (vec![CMPEQ_BYTE, RET_X30], false, "streaming mode required"),
        (
            vec![CMPEQ_WIDE_RESERVED_DOUBLEWORD, RET_X30],
            true,
            "reserved streaming integer comparison",
        ),
        (vec![MOVPRFX_Z0_Z1, CMPEQ_BYTE, RET_X30], true, "MOVPRFX"),
    ] {
        let error = compile_for_profile(
            &words(&input),
            GuestAddress(0),
            profile(32, streaming),
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.0.contains(reason), "{error:?}");
    }
}

#[test]
fn integer_comparison_accepts_declared_sme_without_sme2() {
    const CMPEQ_BYTE: u32 = 0x2400_2020;
    let length = VectorLength::from_bytes(32).unwrap();
    let mode = ScalableMode::new(true, true);
    let declared = ScalableProfile::new_with_features(
        length,
        mode,
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(length, false),
    )
    .unwrap();
    let source = words(&[CMPEQ_BYTE, RET_X30]);
    let fixed = compile_for_profile(
        &source,
        GuestAddress(0),
        ScalableProfile::new(length, mode),
        TargetCpu::Baseline,
    )
    .unwrap();
    let explicit =
        compile_for_profile(&source, GuestAddress(0), declared, TargetCpu::Baseline).unwrap();
    assert_eq!(fixed.x86_64_code, explicit.x86_64_code);
    assert_eq!(fixed.source_map, explicit.source_map);
}
