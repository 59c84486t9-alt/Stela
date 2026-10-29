use super::*;

#[test]
fn out_of_range_tnsz_is_forced_into_the_architectural_range() {
    // TTBR1 walks disabled with T1SZ=0, as a TTBR0-only EL1 leaves it.
    let tcr = 25 | 1 << 23;
    let context = Context::new(1, all_keys()).with_translation_regime(tcr);
    let upper = context.layout(policy::Domain::Data, 0xffff_0000_0000_1000, false);
    assert_eq!(upper.address_bits, 64 - MIN_TNSZ as u32);
    assert_eq!(
        context
            .layout(policy::Domain::Data, 0x1000, false)
            .address_bits,
        39
    );
    let wide = Context::new(1, all_keys()).with_translation_regime(48);
    assert_eq!(
        wide.layout(policy::Domain::Data, 0x1000, false)
            .address_bits,
        64 - MAX_TNSZ as u32
    );
    // Signing an upper pointer no longer overflows.
    assert!(context.sign(Key::Da, 0xffff_0000_0000_1000, 0).is_ok());
}

// PACIBSP/AUTIBSP vectors recorded from Unicorn 2.1.4 (CPU max, QARMA5, PAuth1,
// VA47, instruction TBI off) with public test keys.
const POINTERS: [u64; 4] = [0x0, 0x1400, 0x7fffffffffff, 0x123456789abc];
const MODIFIERS: [u64; 4] = [0x0, 0x2000, 0xffffffffffffffff, 0x123456789abcdef];
const IB_VECTORS: [([u64; 2], [u64; 16]); 4] = [
    (
        [0x1122334455667788, 0x99aabbccddeeff00],
        [
            0xf90e800000000000,
            0xcd1f800000000000,
            0xf911000000000000,
            0x3041800000000000,
            0x6709800000001400,
            0xce76000000001400,
            0xc405800000001400,
            0xfe1d000000001400,
            0xfd717fffffffffff,
            0xdc587fffffffffff,
            0x7564ffffffffffff,
            0xa1457fffffffffff,
            0xa630923456789abc,
            0xb00e923456789abc,
            0xa248123456789abc,
            0x9f09923456789abc,
        ],
    ),
    (
        [0x0, 0x0],
        [
            0x7624000000000000,
            0xb51800000000000,
            0x7c16000000000000,
            0x1c15000000000000,
            0x603d000000001400,
            0xff3a000000001400,
            0x983c800000001400,
            0xb67e800000001400,
            0x75affffffffffff,
            0x8b39ffffffffffff,
            0x6d56ffffffffffff,
            0xc102ffffffffffff,
            0x757b123456789abc,
            0xdd1e123456789abc,
            0xc15c923456789abc,
            0xbd0c123456789abc,
        ],
    ),
    (
        [0xffffffffffffffff, 0xffffffffffffffff],
        [
            0xdd57000000000000,
            0x1a0d800000000000,
            0x4855800000000000,
            0x852e000000000000,
            0x8160000000001400,
            0x6419000000001400,
            0x2d50000000001400,
            0xb354000000001400,
            0xa620ffffffffffff,
            0xdb7b7fffffffffff,
            0xf43dffffffffffff,
            0x32347fffffffffff,
            0xd615923456789abc,
            0x9c7a123456789abc,
            0x3f66923456789abc,
            0xa109923456789abc,
        ],
    ),
    (
        [0x1, 0x2],
        [
            0xc56e800000000000,
            0x3c40000000000000,
            0x825c800000000000,
            0x2f70000000000000,
            0xac7f000000001400,
            0x4071800000001400,
            0xe407800000001400,
            0x714b800000001400,
            0x751b7fffffffffff,
            0xe0397fffffffffff,
            0xe6767fffffffffff,
            0xff62ffffffffffff,
            0xb04123456789abc,
            0x253a123456789abc,
            0x5c4c123456789abc,
            0x2968923456789abc,
        ],
    ),
];
#[test]
fn original_enabled_arm_ib_vectors_match_and_round_trip() -> Result<()> {
    for (words, signed) in IB_VECTORS {
        let context = Context::new(73, Keys::from_ib_words(words[0], words[1]));
        for (pointer_index, pointer) in POINTERS.into_iter().enumerate() {
            for (modifier_index, modifier) in MODIFIERS.into_iter().enumerate() {
                let encoded = signed[pointer_index * 4 + modifier_index];
                assert_eq!(context.sign_ib(pointer, modifier)?, encoded);
                assert_eq!(
                    context.authenticate_ib(encoded, modifier)?,
                    AuthResult {
                        pointer,
                        authenticated: true,
                    }
                );
            }
        }
    }
    Ok(())
}

// Independent nibble-array implementation of the Arm pseudocode; the upper 32
// bits were also checked against original PACGA.
#[test]
fn full64_qarma5_matches_independent_nibble_asl_vectors() {
    let vectors = [
        (
            0x0,
            0x0,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xf98eebd04f80fec6,
        ),
        (
            0x3c810c2558894393,
            0x33a14317477358e7,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x7cec813deab63a55,
        ),
        (
            0xdb75f319b483fcd5,
            0xdd1af32ab32cfb22,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xa5f20d0d7776814,
        ),
        (
            0x2524e003c1432543,
            0xcfe77676c7b84f90,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xdb69675548508432,
        ),
        (
            0x2ed789064fa6bbcc,
            0x6e54c8b49abb51bc,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xe61fc538e854699f,
        ),
        (
            0xc1c675b87fc42511,
            0x7e206026f6549718,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x4fbdd31c41849186,
        ),
        (
            0xa4601de012b07be3,
            0xb9577bd89b48ee52,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xd06fb2fcb27e5d50,
        ),
        (
            0x291e514e4fd5e8d3,
            0x6f9d0c33b844f4c4,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xe68256a379ad2504,
        ),
        (
            0xa9de99224d3581bf,
            0xaf2fb1590a2fc6bd,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x3beaabf4a9184e65,
        ),
        (
            0x23e3647c64a0f3a2,
            0xc6b21be5b51aaccf,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x48f9fe3106eb6ae3,
        ),
        (
            0x53471cc4cd40c33c,
            0x6c90e18ec551138a,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0xd3f029020f7b0356,
        ),
        (
            0x965121dfe4b238ca,
            0x60c2b6f7672b9a4e,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x3fe103f2b39dc30,
        ),
        (
            0x907fa48493109c21,
            0x66dd128e6f419835,
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x8251a27e4a52ba06,
        ),
        (
            0xdef475e27b35192d,
            0x8e8c0dd51c21f2b3,
            0x842fa07b630a8282,
            0x37fdc673abbf343f,
            0x5779db86552f2e3a,
        ),
        (
            0x83c0808da71ed9e2,
            0xa57f47a258ed2136,
            0x7acc0887b148a07d,
            0xe0d85e13ee6a7663,
            0x74ebc6ad8e41fc56,
        ),
        (
            0x29cf741c9173ab3d,
            0x33d9b70ddf7b9df9,
            0xf28c190a408ce61c,
            0x219d7e95e231c536,
            0x93f53a7591dfb34b,
        ),
    ];
    for (data, modifier, low, high, expected) in vectors {
        assert_eq!(qarma5(data, modifier, &[low, high]), expected);
    }
}

#[test]
fn every_pac_bit_corruption_produces_ib_poison_without_stripping() -> Result<()> {
    let context = Context::new(
        7,
        Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
    );
    let signed = context.sign_ib(0x1400, 0x2000)?;
    assert_eq!(signed, 0xce76000000001400);
    for bit in 0..64 {
        if PAC_MASK & (1 << bit) != 0 {
            assert_eq!(
                context.authenticate_ib(signed ^ (1 << bit), 0x2000)?,
                AuthResult {
                    pointer: 0x4000000000001400,
                    authenticated: false,
                }
            );
        }
    }
    assert_eq!(
        context.authenticate_ib(signed, 0x2010)?,
        AuthResult {
            pointer: 0x4000000000001400,
            authenticated: false,
        }
    );
    let other = Context::new(
        7,
        Keys::from_ib_words(0x1122334455667789, 0x99aabbccddeeff00),
    );
    assert!(!other.authenticate_ib(signed, 0x2000)?.authenticated);
    assert!(!context.authenticate_ib(signed ^ 4, 0x2000)?.authenticated);
    Ok(())
}

#[test]
fn null_upper_region_and_invalid_extensions_follow_classic_math() -> Result<()> {
    let context = Context::new(
        7,
        Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
    );
    assert_ne!(context.sign_ib(0, 0x2000)?, 0);
    for pointer in [0, ADDRESS_MASK, !ADDRESS_MASK, u64::MAX] {
        let encoded = context.sign_ib(pointer, 0x2000)?;
        assert_eq!(encoded & REGION_BIT, pointer & REGION_BIT);
        assert_eq!(
            context.authenticate_ib(encoded, 0x2000)?,
            AuthResult {
                pointer,
                authenticated: true,
            }
        );
    }
    // The Arm pseudocode corrupts PAC bit 62 for an invalid extension;
    // Unicorn's older helper flips bit 63 instead. The vectors above agree;
    // these cases follow the pseudocode.
    for bit in 47..64 {
        for pointer in [(1u64 << bit) | 0x1400, !(1u64 << bit) & !0x1234] {
            let extension = pointer >> 47;
            if extension == 0 || extension == u64::MAX >> 47 {
                continue;
            }
            let canonical =
                (pointer & ADDRESS_MASK) | if pointer >> 63 != 0 { !ADDRESS_MASK } else { 0 };
            let encoded = context.sign_ib(pointer, 0x2000)?;
            assert_eq!(encoded, context.sign_ib(canonical, 0x2000)? ^ (1 << 62));
            let failed = context.authenticate_ib(encoded, 0x2000)?;
            assert!(!failed.authenticated);
            assert_eq!(failed.pointer, (canonical & !POISON_MASK) | IB_POISON);
        }
    }
    Ok(())
}

#[test]
fn context_metadata_and_debug_never_include_secret_key_words() {
    let context = Context::new(
        73,
        Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
    );
    assert_eq!(context.address_space(), 73);
    assert_eq!(context.profile_id(), PROFILE_ID);
    assert_eq!(
        format!("{context:?}"),
        format!("Context {{ address_space: 73, profile: {PROFILE_ID:?}, .. }}")
    );
}
fn all_keys() -> Keys {
    let words = [0x1122334455667788, 0x99aabbccddeeff00];
    Keys::from_words(words, words, words, words)
}

#[test]
fn generic_domains_match_original_canonical_sign_auth_and_xpac_vectors() -> Result<()> {
    // Original enabled Unicorn2.1.4 MAX, QARMA5/VA47/iTBIoff/dTBIon.
    // oracle-receipt.json SHA256:
    // 2b0bb3e6c7c7cf9bb3958745ec00c2accda46e114cce9f19940895a18ac0b91e
    let context = Context::new(73, all_keys());
    let vectors = [
        (
            0x0000000000000000,
            0x0000000000000000,
            0xf90e800000000000,
            0x000e800000000000,
        ),
        (
            0x0000000000000000,
            0x0000000000002000,
            0xcd1f800000000000,
            0x001f800000000000,
        ),
        (
            0x0000000000000000,
            0xffffffffffffffff,
            0xf911000000000000,
            0x0011000000000000,
        ),
        (
            0x0000000000001400,
            0x0000000000000000,
            0x6709800000001400,
            0x0009800000001400,
        ),
        (
            0x0000000000001400,
            0x0000000000002000,
            0xce76000000001400,
            0x0076000000001400,
        ),
        (
            0x0000000000001400,
            0xffffffffffffffff,
            0xc405800000001400,
            0x0005800000001400,
        ),
        (
            0x00007fffffffffff,
            0x0000000000000000,
            0xfd717fffffffffff,
            0x00717fffffffffff,
        ),
        (
            0x00007fffffffffff,
            0x0000000000002000,
            0xdc587fffffffffff,
            0x00587fffffffffff,
        ),
        (
            0x00007fffffffffff,
            0xffffffffffffffff,
            0x7564ffffffffffff,
            0x0064ffffffffffff,
        ),
        (
            0xffff800000001400,
            0x0000000000000000,
            0x3cc4800000001400,
            0xffc4800000001400,
        ),
        (
            0xffff800000001400,
            0x0000000000002000,
            0xf8a9800000001400,
            0xffa9800000001400,
        ),
        (
            0xffff800000001400,
            0xffffffffffffffff,
            0xb598800000001400,
            0xff98800000001400,
        ),
    ];
    for (pointer, modifier, instruction, data) in vectors {
        for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
            let signed = if key.is_data() { data } else { instruction };
            assert_eq!(context.sign(key, pointer, modifier)?, signed);
            assert_eq!(
                context.authenticate(key, signed, modifier)?,
                AuthResult {
                    pointer,
                    authenticated: true,
                }
            );
            assert_eq!(context.strip(key, signed)?, pointer);
        }
    }
    Ok(())
}

#[test]
fn tagged_data_matches_original_and_keeps_tag_on_auth_and_strip() -> Result<()> {
    let context = Context::new(73, all_keys());
    let vectors = [
        (0x8000000000001400, 0x0000000000000000, 0x805d800000001400),
        (0x8000000000001400, 0x0000000000002000, 0x8026800000001400),
        (0x8000000000001400, 0xffffffffffffffff, 0x807a800000001400),
        (0x7aff800000001400, 0x0000000000000000, 0x7abe000000001400),
        (0x7aff800000001400, 0x0000000000002000, 0x7acb000000001400),
        (0x7aff800000001400, 0xffffffffffffffff, 0x7ad1000000001400),
    ];
    for (pointer, modifier, signed) in vectors {
        for key in [Key::Da, Key::Db] {
            assert_eq!(context.sign(key, pointer, modifier)?, signed);
            assert_eq!(signed >> 56, pointer >> 56);
            assert_eq!(
                context.authenticate(key, signed, modifier)?,
                AuthResult {
                    pointer,
                    authenticated: true,
                }
            );
            assert_eq!(context.strip(key, signed)?, pointer);
            for bit in 47..55 {
                let failed = context.authenticate(key, signed ^ (1 << bit), modifier)?;
                assert!(!failed.authenticated);
                assert_eq!(failed.pointer >> 56, pointer >> 56);
                assert_eq!(failed.pointer & REGION_BIT, pointer & REGION_BIT);
                let poison = if key == Key::Db { 2u64 } else { 1 };
                assert_eq!(failed.pointer, (pointer & !(3 << 53)) | (poison << 53));
            }
        }
    }
    Ok(())
}

#[test]
fn all_domains_poison_every_corrupted_pac_bit_and_key_selection_is_explicit() -> Result<()> {
    let context = Context::new(73, all_keys());
    for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
        let signed = context.sign(key, 0x1400, 0x2000)?;
        let shift = if key.is_data() { 53 } else { 61 };
        let poison = if key.is_b() { 2u64 } else { 1 };
        for bit in 0..64 {
            if key_pac_mask(key) & (1 << bit) != 0 {
                assert_eq!(
                    context.authenticate(key, signed ^ (1 << bit), 0x2000)?,
                    AuthResult {
                        pointer: 0x1400 | (poison << shift),
                        authenticated: false,
                    }
                );
            }
        }
    }
    // Distinct domain keys use the same verified QARMA
    // primitive; no artificial IA/IB/DA/DB domain tag is added to the MAC.
    let context = Context::new(
        73,
        Keys::from_words(
            [0, 0],
            [u64::MAX, u64::MAX],
            [1, 2],
            [0x1122334455667788, 0x99aabbccddeeff00],
        ),
    );
    for (key, expected) in [
        (Key::Ia, 0xff3a000000001400),
        (Key::Ib, 0x6419000000001400),
        (Key::Da, 0x0071800000001400),
        (Key::Db, 0x0076000000001400),
    ] {
        assert_eq!(context.sign(key, 0x1400, 0x2000)?, expected);
        assert!(context.authenticate(key, expected, 0x2000)?.authenticated);
    }
    Ok(())
}

#[test]
fn data_invalid_extension_corruption_follows_june_asl_not_old_emulator() -> Result<()> {
    let context = Context::new(73, all_keys());
    for key in [Key::Da, Key::Db] {
        for tag in [0u64, 0x80, 0x7a, 0xff] {
            for bit in 47..56 {
                for pointer in [
                    (tag << 56) | (1 << bit) | 0x1400,
                    (tag << 56) | (DATA_EXTENSION_MASK & !(1 << bit)) | 0x1400,
                ] {
                    let canonical = policy::authentication_input(key_domain(key).layout(), pointer);
                    let signed = context.sign(key, pointer, 0x2000)?;
                    assert_eq!(signed, context.sign(key, canonical, 0x2000)? ^ (1 << 54));
                    let failed = context.authenticate(key, signed, 0x2000)?;
                    assert!(!failed.authenticated);
                    let poison = if key.is_b() { 2u64 } else { 1 };
                    assert_eq!(failed.pointer, (canonical & !(3 << 53)) | (poison << 53));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn missing_keys_decline_sign_and_auth_but_xpac_is_keyless() -> Result<()> {
    let ib = Context::new(
        73,
        Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
    );
    assert_eq!(ib.profile_id(), PROFILE_ID);
    assert!(ib.has_key(Key::Ib));
    for key in [Key::Ia, Key::Da, Key::Db] {
        assert!(!ib.has_key(key));
        assert!(ib.sign(key, 0x1400, 0x2000).is_err());
        assert!(ib.authenticate(key, 0x1400, 0x2000).is_err());
        assert_eq!(ib.strip(key, 0x1400)?, 0x1400);
    }
    assert_eq!(ib.sign_ib(0x1400, 0x2000)?, 0xce76000000001400);
    let full = Context::new(73, all_keys());
    assert_eq!(full.profile_id(), FULL_PROFILE_ID);
    assert_eq!(
        format!("{full:?}"),
        format!("Context {{ address_space: 73, profile: {FULL_PROFILE_ID:?}, .. }}")
    );
    for (key, name) in [
        (Key::Ia, "ia"),
        (Key::Ib, "ib"),
        (Key::Da, "da"),
        (Key::Db, "db"),
    ] {
        assert!(full.has_key(key));
        assert_eq!(serde_json::to_value(key)?, serde_json::json!(name));
    }
    Ok(())
}
#[test]
fn generic_key_is_independent_and_pacga_zeros_its_lower_half() -> Result<()> {
    let key = [0x1122334455667788, 0x99aabbccddeeff00];
    let context = Context::new(73, all_keys().with_generic_words(key));
    assert!(context.has_generic_key());
    assert_eq!(context.profile_id(), GENERIC_PROFILE_ID);
    assert_eq!(context.generic_code(0, 0)?, 0xf98e_ebd0_0000_0000);
    assert_eq!(
        context.generic_code(0x3c810c2558894393, 0x33a14317477358e7)?,
        0x7cec_813d_0000_0000
    );
    let old = Context::new(73, all_keys());
    assert!(!old.has_generic_key());
    assert!(old.generic_code(0, 0).is_err());
    for domain in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
        assert_eq!(
            context.sign(domain, 0x1400, 0x2000)?,
            old.sign(domain, 0x1400, 0x2000)?
        );
    }
    assert!(!format!("{context:?}").contains("1122334455667788"));
    Ok(())
}

#[test]
fn modern_versions_keep_key_and_faulting_policies_explicit() -> Result<()> {
    for (version, profile) in [
        (Version::Enhanced, ENHANCED_PROFILE_ID),
        (Version::Faulting, FAULTING_PROFILE_ID),
        (Version::FaultingCombined, COMBINED_PROFILE_ID),
    ] {
        let context = Context::new_with_version(73, all_keys(), version);
        assert_eq!(context.version(), version);
        assert_eq!(context.profile_id(), profile);
        for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
            for pointer in [0x1400, !0xfu64] {
                let signed = context.sign(key, pointer, 0x2000)?;
                for combined in [false, true] {
                    assert_eq!(
                        context.authenticate_operation(key, signed, 0x2000, combined)?,
                        AuthResult {
                            pointer,
                            authenticated: true
                        }
                    );
                    let result =
                        context.authenticate_operation(key, signed ^ (1 << 47), 0x2000, combined);
                    if version == Version::FaultingCombined
                        || (version == Version::Faulting && !combined)
                    {
                        assert_eq!(
                            result,
                            Err(AuthenticationError::Failure {
                                code: (u8::from(key.is_data()) << 1) | u8::from(key.is_b())
                            })
                        );
                    } else {
                        assert_eq!(result?.pointer, pointer ^ (1 << 47));
                    }
                }
            }
        }
        let missing = Context::new_with_version(73, Keys::from_ib_words(1, 2), version);
        assert_eq!(
            missing.authenticate_operation(Key::Da, 0, 0, true),
            Err(AuthenticationError::KeyUnavailable { key: Key::Da })
        );
    }
    Ok(())
}

/// XNU's user TCR_EL1: T0SZ 17, T1SZ 0 (EPD1), TBI0 with TBID0, so an
/// instruction pointer's PAC reaches bit 63. Authentication must still
/// take its field from T0SZ when that PAC bit is set.
#[test]
fn a_set_pac_bit_63_does_not_move_the_field_to_the_upper_range() -> Result<()> {
    const TCR: u64 = 17 | 1 << 23 | 5 << 32 | 1 << 37 | 1 << 51;
    let keys = Keys::from_words(
        [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210],
        [0x1111_2222_3333_4444, 0x5555_6666_7777_8888],
        [0x9999_aaaa_bbbb_cccc, 0xdddd_eeee_ffff_0001],
        [0x0f0f_0f0f_f0f0_f0f0, 0x3c3c_3c3c_c3c3_c3c3],
    );
    let context = Context::new_with_version(0, keys, Version::Classic).with_translation_regime(TCR);
    let (mut upper, mut lower) = (0, 0);
    for index in 0..256u64 {
        let pointer = 0x3_40ee_0000 + index * 4;
        let modifier = 0x16fd_fe850;
        for key in [Key::Ib, Key::Da] {
            let signed = context.sign(key, pointer, modifier)?;
            if signed >> 63 == 1 {
                upper += 1;
            } else {
                lower += 1;
            }
            let result = context.authenticate_operation(key, signed, modifier, true);
            assert!(
                matches!(result, Ok(AuthResult { pointer: p, authenticated: true }) if p == pointer),
                "{key:?} {pointer:#x} signed {signed:#x}: {result:?}"
            );
            assert_eq!(context.strip(key, signed)?, pointer);
        }
    }
    assert!(upper > 0 && lower > 0, "both PAC bit-63 values occur");
    Ok(())
}
