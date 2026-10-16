use super::*;
use crate::aarch64::sve::integer_products;

#[test]
fn integer_products_maps_every_form_to_exact_body_boundaries() {
    const CANONICAL_WORDS: [u32; 101] = [
        0x4403_20bf, // cmla_z_zzz_
        0x44a3_60bf, // cmla_z_zzzi_h
        0x44e3_60bf, // cmla_z_zzzi_s
        0x0403_de7f, // mad_z_p_zzz_
        0x0403_5cbf, // mla_z_p_zzz_
        0x44e3_08bf, // mla_z_zzzi_d
        0x4423_08bf, // mla_z_zzzi_h
        0x44a3_08bf, // mla_z_zzzi_s
        0x0403_7cbf, // mls_z_p_zzz_
        0x44e3_0cbf, // mls_z_zzzi_d
        0x4423_0cbf, // mls_z_zzzi_h
        0x44a3_0cbf, // mls_z_zzzi_s
        0x0403_fe7f, // msb_z_p_zzz_
        0x0410_1c7f, // mul_z_p_zz_
        0x2530_d01f, // mul_z_zi_
        0x0423_60bf, // mul_z_zz_
        0x44e3_f8bf, // mul_z_zzi_d
        0x4423_f8bf, // mul_z_zzi_h
        0x44a3_f8bf, // mul_z_zzi_s
        0x0423_64bf, // pmul_z_zz_
        0x4543_68bf, // pmullb_z_zz_
        0x4543_6cbf, // pmullt_z_zz_
        0x4443_40bf, // smlalb_z_zzz_
        0x44e3_80bf, // smlalb_z_zzzi_d
        0x44a3_80bf, // smlalb_z_zzzi_s
        0x4443_44bf, // smlalt_z_zzz_
        0x44e3_84bf, // smlalt_z_zzzi_d
        0x44a3_84bf, // smlalt_z_zzzi_s
        0x4443_50bf, // smlslb_z_zzz_
        0x44e3_a0bf, // smlslb_z_zzzi_d
        0x44a3_a0bf, // smlslb_z_zzzi_s
        0x4443_54bf, // smlslt_z_zzz_
        0x44e3_a4bf, // smlslt_z_zzzi_d
        0x44a3_a4bf, // smlslt_z_zzzi_s
        0x0412_1c7f, // smulh_z_p_zz_
        0x0423_68bf, // smulh_z_zz_
        0x4543_70bf, // smullb_z_zz_
        0x44e3_c0bf, // smullb_z_zzi_d
        0x44a3_c0bf, // smullb_z_zzi_s
        0x4543_74bf, // smullt_z_zz_
        0x44e3_c4bf, // smullt_z_zzi_d
        0x44a3_c4bf, // smullt_z_zzi_s
        0x4443_60bf, // sqdmlalb_z_zzz_
        0x44e3_20bf, // sqdmlalb_z_zzzi_d
        0x44a3_20bf, // sqdmlalb_z_zzzi_s
        0x4443_08bf, // sqdmlalbt_z_zzz_
        0x4443_64bf, // sqdmlalt_z_zzz_
        0x44e3_24bf, // sqdmlalt_z_zzzi_d
        0x44a3_24bf, // sqdmlalt_z_zzzi_s
        0x4443_68bf, // sqdmlslb_z_zzz_
        0x44e3_30bf, // sqdmlslb_z_zzzi_d
        0x44a3_30bf, // sqdmlslb_z_zzzi_s
        0x4443_0cbf, // sqdmlslbt_z_zzz_
        0x4443_6cbf, // sqdmlslt_z_zzz_
        0x44e3_34bf, // sqdmlslt_z_zzzi_d
        0x44a3_34bf, // sqdmlslt_z_zzzi_s
        0x0423_70bf, // sqdmulh_z_zz_
        0x44e3_f0bf, // sqdmulh_z_zzi_d
        0x4423_f0bf, // sqdmulh_z_zzi_h
        0x44a3_f0bf, // sqdmulh_z_zzi_s
        0x4543_60bf, // sqdmullb_z_zz_
        0x44e3_e0bf, // sqdmullb_z_zzi_d
        0x44a3_e0bf, // sqdmullb_z_zzi_s
        0x4543_64bf, // sqdmullt_z_zz_
        0x44e3_e4bf, // sqdmullt_z_zzi_d
        0x44a3_e4bf, // sqdmullt_z_zzi_s
        0x4403_30bf, // sqrdcmlah_z_zzz_
        0x44a3_70bf, // sqrdcmlah_z_zzzi_h
        0x44e3_70bf, // sqrdcmlah_z_zzzi_s
        0x4403_70bf, // sqrdmlah_z_zzz_
        0x44e3_10bf, // sqrdmlah_z_zzzi_d
        0x4423_10bf, // sqrdmlah_z_zzzi_h
        0x44a3_10bf, // sqrdmlah_z_zzzi_s
        0x4403_74bf, // sqrdmlsh_z_zzz_
        0x44e3_14bf, // sqrdmlsh_z_zzzi_d
        0x4423_14bf, // sqrdmlsh_z_zzzi_h
        0x44a3_14bf, // sqrdmlsh_z_zzzi_s
        0x0423_74bf, // sqrdmulh_z_zz_
        0x44e3_f4bf, // sqrdmulh_z_zzi_d
        0x4423_f4bf, // sqrdmulh_z_zzi_h
        0x44a3_f4bf, // sqrdmulh_z_zzi_s
        0x4443_48bf, // umlalb_z_zzz_
        0x44e3_90bf, // umlalb_z_zzzi_d
        0x44a3_90bf, // umlalb_z_zzzi_s
        0x4443_4cbf, // umlalt_z_zzz_
        0x44e3_94bf, // umlalt_z_zzzi_d
        0x44a3_94bf, // umlalt_z_zzzi_s
        0x4443_58bf, // umlslb_z_zzz_
        0x44e3_b0bf, // umlslb_z_zzzi_d
        0x44a3_b0bf, // umlslb_z_zzzi_s
        0x4443_5cbf, // umlslt_z_zzz_
        0x44e3_b4bf, // umlslt_z_zzzi_d
        0x44a3_b4bf, // umlslt_z_zzzi_s
        0x0413_1c7f, // umulh_z_p_zz_
        0x0423_6cbf, // umulh_z_zz_
        0x4543_78bf, // umullb_z_zz_
        0x44e3_d0bf, // umullb_z_zzi_d
        0x44a3_d0bf, // umullb_z_zzi_s
        0x4543_7cbf, // umullt_z_zz_
        0x44e3_d4bf, // umullt_z_zzi_d
        0x44a3_d4bf, // umullt_z_zzi_s
    ];
    for word in CANONICAL_WORDS {
        let operand = integer_products::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::IntegerProducts(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for (target, declared) in [
                (TargetCpu::Baseline, false),
                (TargetCpu::Sse42, false),
                (TargetCpu::Baseline, true),
                (TargetCpu::Sse42, true),
            ] {
                let selected_profile = if declared {
                    ScalableProfile::new_with_features(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::new(true, false),
                        ScalableFeatures::of(ScalableFeature::Sme),
                        ScalableControls::new(VectorLength::from_bytes(bytes).unwrap(), false),
                    )
                    .unwrap()
                } else {
                    profile(bytes, true)
                };
                let native = compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    selected_profile,
                    target,
                )
                .unwrap();
                let mut expected = Vec::new();
                x86_64::sve::integer_products::emit(
                    &mut expected,
                    operand,
                    VectorLength::from_bytes(bytes).unwrap(),
                    target,
                );
                assert_eq!(
                    native.source_map,
                    [
                        (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                        (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                    ]
                );
                assert_eq!(
                    &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                    context_wrapper()
                );
                assert_eq!(
                    &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                    expected
                );
                assert_eq!(&native.x86_64_code[native.source_map[1].1..], &[RET]);
            }
        }
    }
}

#[test]
fn integer_products_preflight_rejects_reserved_modes_and_prefix_pairs() {
    const MUL_Z0_Z1_Z2: u32 = 0x0422_6020;
    const SMULLB_RESERVED_BYTE: u32 = 0x4500_7000;
    const PMULLB_RESERVED_WORD: u32 = 0x4580_6800;
    for word in [SMULLB_RESERVED_BYTE, PMULLB_RESERVED_WORD] {
        assert!(
            compile_for_profile(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("reserved streaming integer product")
        );
    }
    assert!(
        compile_for_profile(
            &words(&[MUL_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, false),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("streaming mode required")
    );
    assert!(
        compile_for_profile(
            &words(&[MOVPRFX_Z0_Z1, MUL_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("MOVPRFX pair validation")
    );
}
