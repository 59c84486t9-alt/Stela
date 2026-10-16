use super::*;

#[test]
fn multi_vector_integer_access_and_legacy_abi_boundaries() {
    const ADD_PAIR: u32 = 0xc120_a300;
    const SQCVT_PAIR: u32 = 0xc123_e000;
    const SVE_SQCVTN_PAIR: u32 = 0x4531_4000;
    const SRSHL_PAIR: u32 = 0xc120_a220;
    const RESERVED_QUARTET_SHIFT: u32 = 0xc120_d800;
    let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    let declared = |bytes, streaming| {
        let length = VectorLength::from_bytes(bytes).unwrap();
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(streaming, false),
            features,
            ScalableControls::new(length, false),
        )
        .unwrap()
    };
    for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
        let source = words(&[word, RET_X30]);
        assert!(crate::compile(&source, GuestAddress(0)).is_err());
        let compatible = compile_for_profile(
            &source,
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(
            compatible.source_map[0],
            (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
        );
        for bytes in [16, 32, 64, 128, 256] {
            for streaming in [false, true] {
                let result = compile_for_profile(
                    &source,
                    GuestAddress(0),
                    declared(bytes, streaming),
                    TargetCpu::Baseline,
                );
                if streaming {
                    let native = result.unwrap();
                    assert_eq!(
                        native.source_map[0],
                        (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                    );
                    assert_eq!(native.source_map[1].0, GuestAddress(4));
                } else {
                    assert!(result.unwrap_err().0.contains("streaming mode required"));
                }
            }
        }
    }
    assert!(
        compile_for_profile(
            &words(&[RESERVED_QUARTET_SHIFT, RET_X30]),
            GuestAddress(0),
            declared(16, true),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("reserved multi-vector integer")
    );
    let sme_only = ScalableProfile::new_with_features(
        VectorLength::from_bytes(16).unwrap(),
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(VectorLength::from_bytes(16).unwrap(), false),
    )
    .unwrap();
    for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
        assert!(
            compile_for_profile(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                sme_only,
                TargetCpu::Baseline,
            )
            .is_err()
        );
    }
}
