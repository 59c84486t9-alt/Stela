//! Differential vectors for the host crypto facade.
use super::*;
use ::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use sha2::Digest;

#[test]
fn sha_vectors_and_stream_boundaries() {
    assert_eq!(
        hex::encode(Sha256::digest(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex::encode(Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let data: alloc::vec::Vec<u8> = (0..8193usize)
        .map(|i| (i.wrapping_mul(71) ^ (i >> 3)) as u8)
        .collect();
    for length in [
        0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4095, 4096, 4097, 8193,
    ] {
        let expected = sha2::Sha256::digest(&data[..length]);
        for chunk in [1, 7, 63, 64, 65, 511, 4096] {
            let mut actual = Sha256::new();
            for part in data[..length].chunks(chunk) {
                actual.update(part);
            }
            assert_eq!(actual.finalize(), expected, "length={length} chunk={chunk}");
        }
    }
    let mut reset = Sha256::new();
    reset.update(b"abc");
    assert_eq!(reset.finalize_reset(), sha2::Sha256::digest(b"abc"));
    assert_eq!(reset.finalize(), sha2::Sha256::digest(b""));
}

macro_rules! aes_vectors {
    ($name:ident, $cipher:ty, $reference:ty, $length:expr, $expected:literal) => {
        #[test]
        fn $name() {
            let key: alloc::vec::Vec<u8> = (0..$length).map(|v| v as u8).collect();
            let cipher = <$cipher>::new_from_slice(&key).unwrap();
            let reference = <$reference>::new_from_slice(&key).unwrap();
            let plain = hex::decode("00112233445566778899aabbccddeeff").unwrap();
            let mut block = GenericArray::clone_from_slice(&plain);
            cipher.encrypt_block(&mut block);
            assert_eq!(hex::encode(block), $expected);
            cipher.decrypt_block(&mut block);
            assert_eq!(block.as_slice(), plain);
            for count in [0, 1, 7, 8, 9, 16, 17, 256] {
                let mut actual = alloc::vec![GenericArray::default(); count];
                for (i, block) in actual.iter_mut().enumerate() {
                    for (j, b) in block.iter_mut().enumerate() { *b = (i * 7 + j) as u8; }
                }
                let plain = actual.clone();
                let mut expected = actual.clone();
                cipher.encrypt_blocks(&mut actual);
                reference.encrypt_blocks(&mut expected);
                assert_eq!(actual, expected, "count={count}");
                cipher.decrypt_blocks(&mut actual);
                assert_eq!(actual, plain, "count={count}");
            }
        }
    };
}
aes_vectors!(
    aes128_vectors_and_batches,
    Aes128,
    ::aes::Aes128,
    16,
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
aes_vectors!(
    aes192_vectors_and_batches,
    Aes192,
    ::aes::Aes192,
    24,
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
aes_vectors!(
    aes256_vectors_and_batches,
    Aes256,
    ::aes::Aes256,
    32,
    "8ea2b7ca516745bfeafc49904b496089"
);

#[test]
fn sha1_vectors_and_stream_boundaries() {
    assert_eq!(
        hex::encode(Sha1::digest(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    let data: alloc::vec::Vec<u8> = (0..8193usize).map(|i| i.wrapping_mul(71) as u8).collect();
    for length in [
        0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4095, 4096, 4097, 8193,
    ] {
        let expected = ::sha1::Sha1::digest(&data[..length]);
        for chunk in [1, 7, 63, 64, 65, 511, 4096] {
            let mut actual = Sha1::new();
            for part in data[..length].chunks(chunk) {
                actual.update(part);
            }
            assert_eq!(actual.finalize(), expected, "length={length} chunk={chunk}");
        }
    }
}
