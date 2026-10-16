//! Two-modifier signing and authentication.
use super::*;
use crate::pauth::{Keys, TwoModifierError};

const ADDRESS_SPACE: u64 = 7;
const IA_KEY: [u64; 2] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
const IB_KEY: [u64; 2] = [0x1020_3040_5060_7080, 0x8877_6655_4433_2211];
const FIRST_MODIFIER: u64 = 0x1234_5678_9abc_def0;
const SECOND_MODIFIER: u64 = 0xfedc_ba98_7654_3210;
const TARGET: u64 = 0x1234;
const CORRUPT_PAC_BIT: u64 = 1 << 47;
const FIRST_RELEVANT_MASK: u64 = (u32::MAX as u64) << 4;
const SECOND_RELEVANT_MASK: u64 = (u32::MAX as u64) << 5;

fn context(version: Version) -> Context {
    Context::new_with_version(
        ADDRESS_SPACE,
        Keys::from_words(IA_KEY, IB_KEY, [0; 2], [0; 2]),
        version,
    )
}

#[test]
fn both_instruction_keys_preserve_complete_canonical_pointer_results() {
    let context = context(Version::FaultingCombined);
    for key in [Key::Ia, Key::Ib] {
        for pointer in [
            0,
            TARGET,
            0x0000_7fff_ffff_ffff,
            0xffff_8000_0000_1234,
            u64::MAX,
        ] {
            let signed = context
                .sign_two_modifiers(key, pointer, FIRST_MODIFIER, SECOND_MODIFIER)
                .unwrap();
            // Separate source-slice construction validates the complete crypto
            // and pointer-policy delegation rather than only an upper PAC field.
            let packed = ((SECOND_MODIFIER & SECOND_RELEVANT_MASK) << 27)
                | ((FIRST_MODIFIER & FIRST_RELEVANT_MASK) >> 4);
            assert_eq!(signed, context.sign(key, pointer, packed).unwrap());
            for combined in [false, true] {
                assert_eq!(
                    context.authenticate_two_modifiers(
                        key,
                        signed,
                        FIRST_MODIFIER,
                        SECOND_MODIFIER,
                        combined
                    ),
                    Ok(Ok(AuthResult {
                        pointer,
                        authenticated: true
                    }))
                );
            }
        }
    }
}

#[test]
fn corrupt_authentication_retains_exact_standalone_and_combined_faults() {
    let context = context(Version::FaultingCombined);
    for key in [Key::Ia, Key::Ib] {
        let signed = context
            .sign_two_modifiers(key, TARGET, FIRST_MODIFIER, SECOND_MODIFIER)
            .unwrap();
        for combined in [false, true] {
            let corrupt = signed ^ CORRUPT_PAC_BIT;
            let expected = context.authenticate_operation(
                key,
                corrupt,
                pack_modifiers(FIRST_MODIFIER, SECOND_MODIFIER),
                combined,
            );
            assert_eq!(
                expected,
                Err(AuthenticationError::Failure {
                    code: u8::from(key == Key::Ib)
                })
            );
            assert_eq!(
                context.authenticate_two_modifiers(
                    key,
                    corrupt,
                    FIRST_MODIFIER,
                    SECOND_MODIFIER,
                    combined
                ),
                Ok(expected)
            );
        }
    }
}

#[test]
fn exact_modifier_bit_dependence_and_ignored_bits_reuse_one_pack_owner() {
    for bit in 0..u64::BITS {
        let first = if (4..=35).contains(&bit) {
            1 << (bit - 4)
        } else {
            0
        };
        let second = if (5..=36).contains(&bit) {
            1 << (bit - 5 + u32::BITS)
        } else {
            0
        };
        assert_eq!(pack_modifiers(1 << bit, 0), first);
        assert_eq!(pack_modifiers(0, 1 << bit), second);
    }
    let context = context(Version::FaultingCombined);
    for key in [Key::Ia, Key::Ib] {
        let signed = context
            .sign_two_modifiers(key, TARGET, FIRST_MODIFIER, SECOND_MODIFIER)
            .unwrap();
        for (first, second) in [
            (FIRST_MODIFIER ^ !FIRST_RELEVANT_MASK, SECOND_MODIFIER),
            (FIRST_MODIFIER, SECOND_MODIFIER ^ !SECOND_RELEVANT_MASK),
        ] {
            assert_eq!(
                context.sign_two_modifiers(key, TARGET, first, second),
                Ok(signed)
            );
            assert_eq!(
                context.authenticate_two_modifiers(key, signed, first, second, true),
                Ok(Ok(AuthResult {
                    pointer: TARGET,
                    authenticated: true
                }))
            );
        }
    }
}

#[test]
fn configuration_errors_do_not_become_authentication_failures_or_zero_keys() {
    let context = context(Version::FaultingCombined);
    for key in [Key::Da, Key::Db] {
        assert_eq!(
            context.sign_two_modifiers(key, TARGET, FIRST_MODIFIER, SECOND_MODIFIER),
            Err(TwoModifierError::DataKey { key })
        );
        assert_eq!(
            context.authenticate_two_modifiers(key, TARGET, FIRST_MODIFIER, SECOND_MODIFIER, true),
            Err(TwoModifierError::DataKey { key })
        );
    }
    for version in [Version::Classic, Version::Enhanced, Version::Faulting] {
        let context = self::context(version);
        assert_eq!(
            context.sign_two_modifiers(Key::Ia, TARGET, FIRST_MODIFIER, SECOND_MODIFIER),
            Err(TwoModifierError::UnsupportedVersion { version })
        );
        assert_eq!(
            context.authenticate_two_modifiers(
                Key::Ia,
                TARGET,
                FIRST_MODIFIER,
                SECOND_MODIFIER,
                true
            ),
            Err(TwoModifierError::UnsupportedVersion { version })
        );
    }
    let missing = Context::new_with_version(
        ADDRESS_SPACE,
        Keys::from_ib_words(IB_KEY[0], IB_KEY[1]),
        Version::FaultingCombined,
    );
    assert_eq!(
        missing.sign_two_modifiers(Key::Ia, TARGET, FIRST_MODIFIER, SECOND_MODIFIER),
        Err(TwoModifierError::KeyUnavailable { key: Key::Ia })
    );
    assert_eq!(
        missing.authenticate_two_modifiers(Key::Ia, TARGET, FIRST_MODIFIER, SECOND_MODIFIER, true),
        Err(TwoModifierError::KeyUnavailable { key: Key::Ia })
    );
    assert!(
        missing
            .sign_two_modifiers(Key::Ib, TARGET, FIRST_MODIFIER, SECOND_MODIFIER)
            .is_ok()
    );
}
