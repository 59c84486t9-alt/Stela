use super::*;

#[test]
fn address_counts_require_streaming_but_sme_length_does_not() {
    const ADDVL_X0_ONE: u32 = 0x0420_5020;
    const RDVL_X0_ONE: u32 = 0x04bf_5020;
    const CNTP_X0_P0: u32 = 0x2520_8000;
    const CNTP_X0_PN0: u32 = 0x2520_8200;
    const SQINCW_X0_W0: u32 = 0x04a0_f000;
    const UQDECW_Z0: u32 = 0x04a0_cc00;
    for bytes in [16, 32, 64, 128, 256] {
        for word in [
            ADDVL_X0_ONE,
            RDVL_X0_ONE,
            CNTP_X0_P0,
            CNTP_X0_PN0,
            SQINCW_X0_W0,
            UQDECW_Z0,
        ] {
            for za in [false, true] {
                let selected = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::new(true, za),
                );
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        selected,
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
                let inactive = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::new(false, za),
                );
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        inactive,
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("streaming mode required")
                );
            }
            assert!(crate::compile(&words(&[word, RET_X30]), GuestAddress(0)).is_err());
        }
        assert!(
            compile_for_profile(
                &words(&[RDSVL_X0_ONE, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .is_ok()
        );
    }
}

#[test]
fn address_vector_reserved_width_declines_before_mode_checks() {
    const RESERVED_BYTE_VECTOR_WORDS: [u32; 12] = [
        0x0430_c000,
        0x0430_c400,
        0x0420_c000,
        0x0420_c400,
        0x0420_c800,
        0x0420_cc00,
        0x252c_8000,
        0x252d_8000,
        0x2528_8000,
        0x2529_8000,
        0x252a_8000,
        0x252b_8000,
    ];
    for word in RESERVED_BYTE_VECTOR_WORDS {
        for streaming in [false, true] {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    profile(16, streaming),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved")
            );
        }
    }
}

#[test]
fn address_counter_requires_declared_sme2() {
    const ADDVL_X0_ONE: u32 = 0x0420_5020;
    const CNTP_X0_PN0: u32 = 0x2520_8200;
    let length = VectorLength::from_bytes(16).unwrap();
    let selected = ScalableProfile::new_with_features(
        length,
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(length, false),
    )
    .unwrap();
    assert!(
        compile_for_profile(
            &words(&[ADDVL_X0_ONE, RET_X30]),
            GuestAddress(0),
            selected,
            TargetCpu::Baseline
        )
        .is_ok()
    );
    assert!(
        compile_for_profile(
            &words(&[CNTP_X0_PN0, RET_X30]),
            GuestAddress(0),
            selected,
            TargetCpu::Baseline
        )
        .unwrap_err()
        .0
        .contains("FEAT_SME2")
    );
}
