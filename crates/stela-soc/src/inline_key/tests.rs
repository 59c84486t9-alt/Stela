use super::*;
use alloc::vec::Vec;

fn key() -> InlineKey {
    InlineKey(Zeroizing::new(core::array::from_fn(|n| n as u8)))
}

fn engine() -> Engine {
    let engine = Engine::default();
    engine.provision(Zeroizing::new([7; 32]));
    engine
}

fn unit_bytes(seed: usize) -> Vec<u8> {
    (0..DATA_UNIT_BYTES)
        .map(|i| (i * 71 + seed) as u8)
        .collect()
}

#[test]
fn xts_batches_match_scalar_block_transforms() {
    let data_cipher = Aes128::new_from_slice(&[0x51; 16]).unwrap();
    let tweak_cipher = Aes128::new_from_slice(&[0xc3; 16]).unwrap();
    for unit in [0u64, 1, u64::MAX] {
        let plain = unit_bytes(3);
        let mut scalar = plain.clone();
        let mut tweak = [0; BLOCK];
        tweak[..8].copy_from_slice(&unit.to_le_bytes());
        tweak_cipher.encrypt_block(GenericArray::from_mut_slice(&mut tweak));
        for chunk in scalar.as_chunks_mut::<BLOCK>().0 {
            for (byte, mask) in chunk.iter_mut().zip(tweak) {
                *byte ^= mask;
            }
            data_cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
            for (byte, mask) in chunk.iter_mut().zip(tweak) {
                *byte ^= mask;
            }
            tweak = double_tweak(u128::from_le_bytes(tweak)).to_le_bytes();
        }
        let mut batched = plain.clone();
        xts(&data_cipher, &tweak_cipher, unit, &mut batched, true);
        assert_eq!(batched, scalar, "unit={unit}");
        xts(&data_cipher, &tweak_cipher, unit, &mut batched, false);
        assert_eq!(batched, plain);
    }
}

#[test]
fn aes_128_xts_matches_the_openssl_known_answer() {
    // Independent OpenSSL `enc -aes-128-xts` vector: key1 = 00..0f,
    // key2 = 10..1f, data unit 1; a data unit's first two blocks.
    let plaintext =
        hex::decode("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f").unwrap();
    let expected =
        hex::decode("ac0f5a931d555f32c189b35891efcc1cc2d233fcd8fd7993beaf5fa1f05885bb").unwrap();
    let mut data = unit_bytes(0);
    data[..32].copy_from_slice(&plaintext);
    key().transform(1, &mut data, true).unwrap();
    assert_eq!(data[..32], expected);
    key().transform(1, &mut data, false).unwrap();
    assert_eq!(data[..32], plaintext);
}

#[test]
fn consecutive_units_take_consecutive_numbers_and_partial_units_refuse() {
    let mut whole = [unit_bytes(1), unit_bytes(2)].concat();
    let (mut first, mut second) = (unit_bytes(1), unit_bytes(2));
    key().transform(40, &mut whole, true).unwrap();
    key().transform(40, &mut first, true).unwrap();
    key().transform(41, &mut second, true).unwrap();
    assert_eq!(whole, [first, second].concat());
    assert_ne!(whole[..DATA_UNIT_BYTES], whole[DATA_UNIT_BYTES..]);
    assert!(key().transform(0, &mut [0; 512], true).is_err());
    assert!(key().transform(0, &mut [], true).is_err());
}

#[test]
fn a_wrapped_key_unwraps_to_the_same_cipher_only_under_its_boot_key() {
    let volume = [0x3c; KEY_BYTES];
    let area = engine().wrap(&volume).unwrap();
    // The AP carries only the first word and bytes 16..64.
    assert_eq!(area[..4], HEADER);
    assert!(area[4..16].iter().all(|&b| b == 0));
    let mut plain = unit_bytes(5);
    let mut expected = plain.clone();
    InlineKey(Zeroizing::new(volume))
        .transform(9, &mut expected, true)
        .unwrap();
    engine()
        .unwrap(&area)
        .unwrap()
        .transform(9, &mut plain, true)
        .unwrap();
    assert_eq!(plain, expected);

    let next_boot = Engine::default();
    next_boot.provision(Zeroizing::new([8; 32]));
    assert!(next_boot.unwrap(&area).is_err());
    assert!(Engine::default().unwrap(&area).is_err());
    assert!(Engine::default().wrap(&volume).is_err());
    for index in [0, 5, 16, 40, 63] {
        let mut bad = area;
        bad[index] ^= 1;
        assert!(engine().unwrap(&bad).is_err(), "byte {index}");
    }
}

#[test]
fn a_raw_key_area_carries_its_key_after_zeros() {
    let mut area = [0; KEY_AREA_BYTES];
    area[32..].copy_from_slice(&[0x3c; KEY_BYTES]);
    let mut raw = unit_bytes(6);
    let mut expected = raw.clone();
    InlineKey::raw(&area)
        .unwrap()
        .transform(2, &mut raw, true)
        .unwrap();
    InlineKey(Zeroizing::new([0x3c; KEY_BYTES]))
        .transform(2, &mut expected, true)
        .unwrap();
    assert_eq!(raw, expected);
    area[31] = 1;
    assert!(InlineKey::raw(&area).is_err());
}

#[test]
fn sealing_binds_its_domain_and_associated_data() {
    let secret = [0x11; KEY_BYTES];
    let sealed = seal(&[1; 32], b"a", b"aad", &secret);
    assert_eq!(sealed, seal(&[1; 32], b"a", b"aad", &secret));
    assert_eq!(*open(&[1; 32], b"a", b"aad", &sealed).unwrap(), secret);
    assert!(open(&[2; 32], b"a", b"aad", &sealed).is_err());
    assert!(open(&[1; 32], b"b", b"aad", &sealed).is_err());
    assert!(open(&[1; 32], b"a", b"aae", &sealed).is_err());
    // Domain and associated data are length-delimited.
    assert_ne!(sealed, seal(&[1; 32], b"aa", b"ad", &secret));
}

#[test]
fn compact_sealing_keeps_an_eight_byte_tag_with_the_same_binding() {
    let secret = [0x11; KEY_BYTES];
    let sealed = seal_compact(&[1; 32], b"a", b"aad", &secret);
    assert_eq!(sealed.len(), 40);
    assert_eq!(sealed[..8], seal(&[1; 32], b"a", b"aad", &secret)[..8]);
    assert_eq!(
        *open_compact(&[1; 32], b"a", b"aad", &sealed).unwrap(),
        secret
    );
    assert!(open_compact(&[1; 32], b"a", b"aae", &sealed).is_err());
    for index in [0, 7, 8, 39] {
        let mut bad = sealed;
        bad[index] ^= 1;
        assert!(
            open_compact(&[1; 32], b"a", b"aad", &bad).is_err(),
            "byte {index}"
        );
    }
}
