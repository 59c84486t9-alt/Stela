//! Maverick native-service image ABI and the source's configuration-tag check.
//!
//! Original image1 518..5d2 hashes 1dfc..2268 from the four retained initial
//! words at 1d68, then compares the eight bytes at 2268. Helpers 418..4ec
//! implement two compression/four final SipHash rounds. This is the firmware's
//! integrity check, not a certificate, silicon identity or execution receipt.

const INITIAL: core::ops::Range<usize> = 0x1d68..0x1d88;
const CONFIGURATION: usize = 0x1d88;
const VERSION: usize = 0x1da8;
const METADATA: usize = 0x1df4;
const COVERED: core::ops::Range<usize> = 0x1dfc..0x2268;
const TAG: usize = 0x2268;
const BYTES: usize = TAG + 8;

/// The caller selects a recovered native PMIC service ABI explicitly. No
/// digest chooses a model and no uploaded instructions are executed. The fixed
/// source load-map extents prevent a structural short upload from gaining the
/// native ABI's missing trailing bytes or implicit zero storage.
pub(super) fn verify(
    bytes: &[u8],
    configuration: usize,
    version: usize,
    metadata: u16,
) -> Result<(), &'static str> {
    if bytes.len() != BYTES
        || configuration != CONFIGURATION
        || version != VERSION
        || usize::from(metadata) != METADATA
    {
        return Err(
            "native Maverick firmware requires its complete source-qualified image ABI/load map",
        );
    }
    let initial = core::array::from_fn(|i| {
        u64::from_le_bytes(
            bytes[INITIAL.start + 8 * i..INITIAL.start + 8 * i + 8]
                .try_into()
                .expect("initial tag word"),
        )
    });
    let expected = u64::from_le_bytes(bytes[TAG..BYTES].try_into().expect("image tag"));
    if configuration_tag(initial, &bytes[COVERED]) != expected {
        return Err("native Maverick firmware configuration integrity tag mismatch");
    }
    Ok(())
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}
fn compress(v: &mut [u64; 4], word: u64) {
    v[3] ^= word;
    round(v);
    round(v);
    v[0] ^= word;
}
fn configuration_tag(mut v: [u64; 4], bytes: &[u8]) -> u64 {
    let (words, tail) = bytes.as_chunks::<8>();
    for word in words {
        compress(&mut v, u64::from_le_bytes(*word));
    }
    let mut last = (bytes.len() as u64) << 56;
    for (i, byte) in tail.iter().enumerate() {
        last |= u64::from(*byte) << (8 * i);
    }
    compress(&mut v, last);
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v.into_iter().fold(0, |a, b| a ^ b)
}

#[cfg(test)]
pub(super) fn test_image() -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0x5a; BYTES];
    bytes[super::HEADER..super::HEADER + super::HEADER_BYTES].fill(0);
    bytes[super::HEADER..super::HEADER + 4].copy_from_slice(b"uuid");
    for (at, value) in [(8, CONFIGURATION), (12, VERSION), (0x30, METADATA)] {
        bytes[super::HEADER + at..super::HEADER + at + 4]
            .copy_from_slice(&(value as u32).to_le_bytes());
    }
    let initial = [0; 4];
    bytes[INITIAL].fill(0);
    let tag = configuration_tag(initial, &bytes[COVERED]);
    bytes[TAG..BYTES].copy_from_slice(&tag.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)] // The independent std owner is specifically SipHash-2-4.
    fn independent_std_hasher_compares_all_tails_blocks_and_long_lengths() {
        use std::hash::{Hasher, SipHasher};
        for (k0, k1) in [
            (0, 0),
            (0x0706050403020100, 0x0f0e0d0c0b0a0908),
            (u64::MAX, u64::MAX),
            (17, 0x5a5a5a5a),
        ] {
            let initial = [
                0x736f6d6570736575 ^ k0,
                0x646f72616e646f6d ^ k1,
                0x6c7967656e657261 ^ k0,
                0x7465646279746573 ^ k1,
            ];
            let message: alloc::vec::Vec<_> = (0..1300).map(|i| (i * 31 + 7) as u8).collect();
            for len in 0..=message.len() {
                let mut independent = SipHasher::new_with_keys(k0, k1);
                independent.write(&message[..len]);
                assert_eq!(
                    configuration_tag(initial, &message[..len]),
                    independent.finish(),
                    "length {len}"
                );
            }
        }
    }
    #[test]
    fn exact_native_extent_and_every_covered_byte_require_actual_integrity() {
        let mut bytes = test_image();
        assert_eq!(
            verify(&bytes, CONFIGURATION, VERSION, METADATA as u16),
            Ok(())
        );
        for at in COVERED.chain(TAG..BYTES).chain(INITIAL) {
            bytes[at] ^= 1;
            assert!(
                verify(&bytes, CONFIGURATION, VERSION, METADATA as u16).is_err(),
                "modified byte {at:x}"
            );
            bytes[at] ^= 1;
        }
        for len in [0, 0xc0, 0x1df4, 0x2268, BYTES - 1] {
            assert!(verify(&bytes[..len], CONFIGURATION, VERSION, METADATA as u16).is_err());
        }
        for (configuration, version, metadata) in [
            (0, VERSION, METADATA),
            (CONFIGURATION, 0, METADATA),
            (CONFIGURATION, VERSION, 0),
        ] {
            assert!(verify(&bytes, configuration, version, metadata as u16).is_err());
        }
        bytes.push(0);
        assert!(verify(&bytes, CONFIGURATION, VERSION, METADATA as u16).is_err());
    }
    #[test]
    #[ignore = "requires original pinned J314s LLB via STELA_TEST_CRAM_J314S_LLB"]
    fn original_maverick_tag_matches_all_1132_actual_covered_bytes() {
        let llb = std::fs::read(std::env::var("STELA_TEST_CRAM_J314S_LLB").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&llb),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        let bytes = &llb[0x1f9b20..0x1fbd90];
        assert_eq!(
            verify(bytes, CONFIGURATION, VERSION, METADATA as u16),
            Ok(())
        );
        assert_eq!(
            u64::from_le_bytes(bytes[TAG..BYTES].try_into().unwrap()),
            0x3b11b044f826ed2c
        );
        for (range, hash) in [
            (
                0x418..0x4ec,
                "b0b5269a57f1b353dbea7942d0e8d0fe83846d8cb15273b4df405046baba4ee7",
            ),
            (
                0x518..0x5d2,
                "79c85be1994e8260bde5248ee0968858bb839a510ef27977c3e259c209e4072c",
            ),
        ] {
            assert_eq!(stela_formats::sha256(&bytes[range]), hash);
        }
    }
}
