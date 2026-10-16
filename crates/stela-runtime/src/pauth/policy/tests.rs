use super::*;

#[test]
fn enhanced_sign_xors_existing_noncanonical_fields_without_corrupting_pac() {
    for domain in [Domain::Instruction, Domain::Data] {
        for pointer in [0, ADDRESS_MASK, u64::MAX, REGION_BIT, 1 << ADDRESS_BITS] {
            let pac = 0x1234_5678_9abc_def0;
            let signed = sign(Version::Enhanced, domain, pointer, pac);
            assert_eq!(
                signed & !domain.extension_mask(),
                pointer & !domain.extension_mask()
            );
            assert_eq!(
                signed & domain.pac_mask(),
                (pointer ^ pac) & domain.pac_mask()
            );
            assert_eq!(
                signed & REGION_BIT,
                signing_input(domain, pointer) & REGION_BIT
            );
        }
    }
}

#[test]
fn canonical_roundtrips_and_failure_policies_are_distinct() {
    for domain in [Domain::Instruction, Domain::Data] {
        for side in [Side::A, Side::B] {
            for canonical in [0x1234, !0xfu64] {
                for version in [
                    Version::Classic,
                    Version::Enhanced,
                    Version::Faulting,
                    Version::FaultingCombined,
                ] {
                    let pac = 0x5a5a_a5a5_1234_9876;
                    let signed = sign(version, domain, canonical, pac);
                    assert_eq!(
                        authenticate(version, domain, side, true, signed, pac),
                        Ok(Authentication {
                            pointer: canonical,
                            authenticated: true
                        })
                    );
                    for bit in ADDRESS_BITS..u64::BITS {
                        if domain.pac_mask() & (1 << bit) == 0 {
                            continue;
                        }
                        for combined in [false, true] {
                            let result = authenticate(
                                version,
                                domain,
                                side,
                                combined,
                                signed ^ (1 << bit),
                                pac,
                            );
                            let faulting = version == Version::FaultingCombined
                                || (version == Version::Faulting && !combined);
                            if faulting {
                                assert_eq!(
                                    result,
                                    Err(Failure {
                                        code: (u8::from(domain == Domain::Data) << 1)
                                            | u8::from(side == Side::B)
                                    })
                                );
                            } else {
                                assert!(!result.unwrap().authenticated);
                            }
                        }
                    }
                }
            }
        }
    }
}
