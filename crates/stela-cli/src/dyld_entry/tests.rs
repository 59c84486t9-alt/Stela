use super::*;
#[test]
fn startup_whitelist_recovers_signed_branch_and_declines_changed_effects() {
    let mut words = [0x910003e0, 0x927cec1f, 0xd280001d, 0xd280001e, 0x1400ae18];
    assert_eq!(startup_target(words, 0x4bf0).unwrap(), 0x30460);
    assert_eq!(startup_target(words, 0x40000004bf0).unwrap(), 0x40000030460);
    for index in 0..4 {
        let mut changed = words;
        changed[index] ^= 1;
        assert!(startup_target(changed, 0x4bf0).is_err());
    }
    words[4] = 0x17ffffff;
    assert_eq!(startup_target(words, 0x1000).unwrap(), 0x100c);
    words[4] = 0x97ffffff; // BL is not this reviewed prefix.
    assert!(startup_target(words, 0x1000).is_err());
    words[4] = 0x17fffffb; // -20 from entry+16 underflows entry zero.
    assert!(startup_target(words, 0).is_err());
    assert!(startup_target(words, u64::MAX - 15).is_err());
}
