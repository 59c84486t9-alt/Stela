//! Stela's machine-bound P-256 reference keys, not Apple's private blob/KDF.
//!
//! The AP's `oc` constructor returns a dictionary with `rk` metadata. Its
//! public reader expects `kt` and a compact `pub` inside that dictionary.
//! The later operation sends the entire returned blob as its `rk` value.
//! We retain a fresh public seed plus an authenticated policy/point, deriving
//! the private scalar only from the provisioned machine root and that seed.
//! Thus the exported reference contains no private scalar, survives reopen,
//! and cannot authorize a key belonging to another machine or policy.
//!
//! Only the source-observed standalone class 13 / option 1 profile and P-256
//! types 4/5 are admitted. Credential bags, deletion/revocation, attestation,
//! private export and unsupported key classes remain separate operations.
use super::super::{
    Entropy,
    der::{self, Cursor},
};
use alloc::{vec, vec::Vec};
use hmac::{Hmac, Mac};
use p256::{
    SecretKey,
    elliptic_curve::{
        bigint::U256,
        ff::PrimeField,
        sec1::ToEncodedPoint,
        subtle::{Choice, ConditionallySelectable},
    },
};
use sha2::Sha256;
use zeroize::Zeroizing;

pub(super) const CLASS: u32 = 13;
pub(super) const OPTIONS: u32 = 1;
const VERSION: u8 = 1;
const SEED_BYTES: usize = 32;
const SCALAR_DOMAIN: &[u8] = b"Stela SEP reference P-256 scalar v1\0";
const MAC_DOMAIN: &[u8] = b"Stela SEP reference descriptor MAC v1\0";
const MAX_ATTEMPTS: u32 = 256;
const PRIME: U256 =
    U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

pub(super) struct ReferenceKey {
    secret: SecretKey,
}

impl ReferenceKey {
    pub(super) fn create(
        root: &[u8; 32],
        kind: u32,
        entropy: &mut dyn Entropy,
    ) -> Result<Vec<u8>, &'static str> {
        if !matches!(kind, 4 | 5) {
            return Err("SEP reference-key type is not implemented");
        }
        let mut seed = [0; SEED_BYTES];
        entropy.fill(&mut seed)?;
        let key = Self {
            secret: derive(root, kind, &seed)?,
        };
        let public = key.compact_public();
        let metadata = metadata(kind, &seed, &public);
        let mac = authenticator(root, &metadata).finalize().into_bytes();
        let descriptor = dictionary(&[
            (b"bc", number(CLASS as u8)),
            (b"kt", number(kind as u8)),
            (b"mac", tagged(4, &mac)),
            (b"pub", tagged(4, &public)),
            (b"rko", number(OPTIONS as u8)),
            (b"salt", tagged(4, &seed)),
            (b"v", number(VERSION)),
        ]);
        Ok(dictionary(&[(b"rk", descriptor)]))
    }

    /// Open the complete constructor reply, as `aks_sik_attest` submits it.
    /// Validate its MAC before deriving any private scalar or permitting use.
    pub(super) fn open(root: &[u8; 32], bytes: &[u8]) -> Result<Self, &'static str> {
        let mut outer = Cursor(bytes);
        let mut fields = Cursor(outer.take(17)?.value);
        outer.end()?;
        let descriptor = field(&mut fields, b"rk", 17)?;
        fields.end()?;
        let mut fields = Cursor(descriptor);
        if der::unsigned(field(&mut fields, b"bc", 2)?)? != [CLASS as u8] {
            return Err("SEP reference-key class is not implemented");
        }
        let kind = match der::unsigned(field(&mut fields, b"kt", 2)?)? {
            [4] => 4,
            [5] => 5,
            _ => return Err("SEP reference-key type is not implemented"),
        };
        let mac = field(&mut fields, b"mac", 4)?;
        let public = field(&mut fields, b"pub", 4)?;
        if der::unsigned(field(&mut fields, b"rko", 2)?)? != [OPTIONS as u8] {
            return Err("SEP reference-key options are not implemented");
        }
        let seed: [u8; SEED_BYTES] = field(&mut fields, b"salt", 4)?
            .try_into()
            .map_err(|_| "SEP reference-key seed has the wrong length")?;
        if der::unsigned(field(&mut fields, b"v", 2)?)? != [VERSION] {
            return Err("SEP reference-key version is not implemented");
        }
        fields.end()?;
        if public.len() != 32 || mac.len() != 32 {
            return Err("SEP reference-key point or MAC has the wrong length");
        }
        authenticator(root, &metadata(kind, &seed, public))
            .verify_slice(mac)
            .map_err(|_| "SEP reference-key authentication failed")?;
        let key = Self {
            secret: derive(root, kind, &seed)?,
        };
        if key.compact_public() != public {
            return Err("SEP reference-key point does not match its sealed scalar");
        }
        Ok(key)
    }

    pub(super) fn public(&self) -> [u8; 65] {
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    /// The AP has already SHA-256-hashed the CSR input. Return the original
    /// AKS operation's DER OCTET STRING holding a DER ECDSA signature.
    pub(super) fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signing = p256::ecdsa::SigningKey::from(&self.secret);
        let signature: p256::ecdsa::Signature = signing
            .sign_prehash(digest)
            .map_err(|_| "SEP reference-key digest signing failed")?;
        Ok(tagged(4, signature.to_der().as_bytes()))
    }

    fn compact_public(&self) -> [u8; 32] {
        self.secret.public_key().to_encoded_point(false).as_bytes()[1..33]
            .try_into()
            .unwrap()
    }
}

fn derive(root: &[u8; 32], kind: u32, seed: &[u8; SEED_BYTES]) -> Result<SecretKey, &'static str> {
    for counter in 0..MAX_ATTEMPTS {
        let mut mac = Hmac::<Sha256>::new_from_slice(root).expect("HMAC accepts 256-bit roots");
        mac.update(SCALAR_DOMAIN);
        mac.update(&CLASS.to_be_bytes());
        mac.update(&kind.to_be_bytes());
        mac.update(&OPTIONS.to_be_bytes());
        mac.update(seed);
        mac.update(&counter.to_be_bytes());
        let candidate = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        if let Ok(secret) = SecretKey::from_slice(candidate.as_ref()) {
            // Apple's compact convention is min(y, p-y), not SEC1 parity.
            // Select the corresponding scalar (d or n-d), preserving the
            // private/public pair. The compared coordinates are public.
            let point = secret.public_key().to_encoded_point(false);
            let y = U256::from_be_slice(point.y().unwrap());
            let negate = Choice::from(u8::from(PRIME.wrapping_sub(&y) < y));
            let scalar = Zeroizing::new(secret.to_nonzero_scalar());
            let negated = Zeroizing::new(-*scalar);
            let normalized = Zeroizing::new(p256::NonZeroScalar::conditional_select(
                &scalar, &negated, negate,
            ));
            let bytes = Zeroizing::new(normalized.to_repr());
            return SecretKey::from_bytes(&bytes).map_err(|_| "SEP compact scalar is invalid");
        }
    }
    Err("SEP reference-key scalar derivation exhausted")
}

fn authenticator(root: &[u8; 32], metadata: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(root).expect("HMAC accepts 256-bit roots");
    mac.update(MAC_DOMAIN);
    mac.update(metadata);
    mac
}

fn metadata(kind: u32, seed: &[u8; SEED_BYTES], public: &[u8]) -> Vec<u8> {
    dictionary(&[
        (b"bc", number(CLASS as u8)),
        (b"kt", number(kind as u8)),
        (b"pub", tagged(4, public)),
        (b"rko", number(OPTIONS as u8)),
        (b"salt", tagged(4, seed)),
        (b"v", number(VERSION)),
    ])
}

fn field<'a>(fields: &mut Cursor<'a>, name: &[u8], tag: u32) -> Result<&'a [u8], &'static str> {
    let mut pair = Cursor(fields.take(16)?.value);
    if pair.take(12)?.value != name {
        return Err("SEP reference-key dictionary has missing, repeated or unordered fields");
    }
    let value = pair.take(tag)?.value;
    pair.end()?;
    Ok(value)
}

fn number(value: u8) -> Vec<u8> {
    if value < 128 {
        tagged(2, &[value])
    } else {
        tagged(2, &[0, value])
    }
}

/// Only fixed-size, internally authored fields reach this encoder.
fn tagged(tag: u8, bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 256);
    let mut result = vec![tag];
    if bytes.len() >= 128 {
        result.push(0x81);
    }
    result.push(bytes.len() as u8);
    result.extend_from_slice(bytes);
    result
}

fn dictionary(fields: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    debug_assert!(fields.windows(2).all(|f| f[0].0 < f[1].0));
    let mut bytes = Vec::new();
    for (key, value) in fields {
        let mut pair = tagged(12, key);
        pair.extend_from_slice(value);
        bytes.extend(tagged(0x30, &pair));
    }
    tagged(0x31, &bytes)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn attestation_parameters(blob: &[u8]) -> Vec<u8> {
        dictionary(&[
            (b"o", tagged(12, b"osa")),
            (b"rk", blob.to_vec()),
            (b"rko", number(1)),
        ])
    }

    pub(crate) fn signing_parameters(blob: &[u8], digest: &[u8]) -> Vec<u8> {
        dictionary(&[
            (b"d", tagged(4, digest)),
            (b"o", tagged(12, b"osgn")),
            (b"rk", blob.to_vec()),
        ])
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_LIBFDR_ARM64E"]
    fn original_libfdr_reference_contract_binds_builder_reader_and_attestation_order() {
        use sha2::Digest;
        let path = std::env::var("STELA_TEST_LIBFDR_ARM64E").unwrap();
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "80ed05a609977db0495fb2506d8a1717128f9f8867356126236b407fa7a97faa"
        );
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let branch = |pc: usize| {
            let instruction = word(pc);
            assert_eq!(instruction >> 26, 0b100101);
            let delta = ((instruction << 6) as i32 >> 6) as i64 * 4;
            (pc as i64 + delta) as usize
        };
        // Actual argument constants, not an application-dependent runtime path.
        assert_eq!(word(0x1730), 0x1280_0000); // mov w0, #-1
        assert_eq!(word(0x1734), 0x5280_01a1); // mov w1, #13
        assert_eq!(branch(0x173c), 0x8ae18); // constructor
        assert_eq!(branch(0x8aec0), 0x5c694); // class key helper
        assert_eq!(branch(0x8aed4), 0x5c7bc); // type key helper
        for (slot, key) in [
            (0xd0048, b"bc".as_slice()),
            (0xd0088, b"kt"),
            (0xd0098, b"oc"),
            (0xd0090, b"rk"),
            (0xd0080, b"pub"),
            (0xd0128, b"rko"),
        ] {
            let pointer =
                u64::from_le_bytes(bytes[slot..slot + 8].try_into().unwrap()) as u32 as usize;
            assert_eq!(bytes[pointer], 12);
            assert_eq!(usize::from(bytes[pointer + 1]), key.len());
            assert_eq!(&bytes[pointer + 2..pointer + 2 + key.len()], key);
        }
        assert_eq!(branch(0x5c32c), 0xb3c20); // ccec_cp_256 stub
        assert_eq!(branch(0x5c3c0), 0xb3c10); // compact import stub
        assert_eq!(branch(0x1758), 0x5c468); // mandatory SIK attestation
        assert_eq!(branch(0x1788), 0x5c284); // public extraction only afterward
        assert_eq!(branch(0x8b5ec), 0x5c61c);
        assert_eq!(word(0x5c61c), 0xf940_02e2); // rk argument is full blob, [x23]
        assert_eq!(branch(0x1a1c), 0xb3d20); // SHA-256 descriptor
        assert_eq!(branch(0x1a2c), 0xb3c00); // hash caller data
        assert_eq!(word(0x1a48), 0x5280_0404); // digest length: 32
        assert_eq!(branch(0x1a4c), 0x8b4a8); // AKS reference signing
        assert_eq!(word(0x1a6c), 0x5280_0080); // DER OCTET STRING tag
        assert_eq!(branch(0x1a70), 0xb3be0); // unwrap DER result
        assert_eq!(branch(0x8b50c), 0x5c51c); // full constructor reply
        for (slot, key) in [(0xd0050, b"d".as_slice()), (0xd00a0, b"osgn")] {
            let pointer =
                u64::from_le_bytes(bytes[slot..slot + 8].try_into().unwrap()) as u32 as usize;
            assert_eq!(bytes[pointer], 12);
            assert_eq!(usize::from(bytes[pointer + 1]), key.len());
            assert_eq!(&bytes[pointer + 2..pointer + 2 + key.len()], key);
        }
    }

    #[test]
    fn compact_key_matches_independent_openssl_and_survives_authenticated_reopen() {
        let root = [1; 32];
        let encoded = ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
            bytes.fill(2);
            Ok(())
        })
        .unwrap();
        let key = ReferenceKey::open(&root, &encoded).unwrap();
        // Independent Python HMAC-SHA256 plus OpenSSL EC public derivation
        // and scalar negation, retained in the r2 evidence vector receipt.
        assert_eq!(
            hex::encode(key.secret.to_bytes()),
            "84641805873d19004fe67ed956aff5ddfe2163da2a67baa0397dc7bb171f7a90"
        );
        assert_eq!(
            hex::encode(key.secret.public_key().to_encoded_point(false).as_bytes()),
            "0443658ba6913576edf77f94f53448373f63763627e7c922a2b7b672dfd8f7b506286720afdd19c28248338e96fd849231ea20e76cd54b340cd337f74f318717a5"
        );
        let point = key.secret.public_key().to_encoded_point(false);
        let y = U256::from_be_slice(point.y().unwrap());
        assert!(y < PRIME.wrapping_sub(&y));
        assert!(
            !encoded
                .windows(32)
                .any(|w| w == key.secret.to_bytes().as_slice())
        );
        assert!(ReferenceKey::open(&[2; 32], &encoded).is_err());
        let another = ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
            bytes.fill(3);
            Ok(())
        })
        .unwrap();
        assert_ne!(encoded, another);
        assert_ne!(
            key.compact_public(),
            ReferenceKey::open(&root, &another)
                .unwrap()
                .compact_public()
        );
    }

    #[test]
    fn all_descriptor_bytes_are_bound_and_truncation_or_other_metadata_cannot_reopen() {
        let root = [1; 32];
        let encoded = ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
            bytes.fill(2);
            Ok(())
        })
        .unwrap();
        for index in 0..encoded.len() {
            let mut bad = encoded.clone();
            bad[index] ^= 1;
            assert!(
                ReferenceKey::open(&root, &bad).is_err(),
                "changed byte {index}"
            );
            assert!(ReferenceKey::open(&root, &encoded[..index]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(ReferenceKey::open(&root, &trailing).is_err());
        let kind4 = ReferenceKey::create(&root, 4, &mut |bytes: &mut [u8]| {
            bytes.fill(2);
            Ok(())
        })
        .unwrap();
        assert_ne!(
            ReferenceKey::open(&root, &kind4).unwrap().compact_public(),
            ReferenceKey::open(&root, &encoded)
                .unwrap()
                .compact_public()
        );
    }

    #[test]
    fn reference_signature_verifies_only_the_supplied_prehash() {
        use p256::ecdsa::signature::{Verifier, hazmat::PrehashVerifier};
        use sha2::Digest;
        let root = [1; 32];
        let blob = ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
            bytes.fill(2);
            Ok(())
        })
        .unwrap();
        let key = ReferenceKey::open(&root, &blob).unwrap();
        let digest: [u8; 32] = Sha256::digest(b"original CSR input").into();
        let result = key.sign_digest(&digest).unwrap();
        let mut wrapped = Cursor(&result);
        let signature = p256::ecdsa::Signature::from_der(wrapped.take(4).unwrap().value).unwrap();
        wrapped.end().unwrap();
        let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public()).unwrap();
        verifier.verify_prehash(&digest, &signature).unwrap();
        assert!(verifier.verify(&digest, &signature).is_err()); // no second SHA-256
        let mut wrong = digest;
        wrong[0] ^= 1;
        assert!(verifier.verify_prehash(&wrong, &signature).is_err());
        assert_eq!(
            result,
            ReferenceKey::open(&root, &blob)
                .unwrap()
                .sign_digest(&digest)
                .unwrap()
        );
        assert!(ReferenceKey::open(&[2; 32], &blob).is_err());
    }

    #[test]
    #[ignore = "oracle: program:/usr/bin/openssl"]
    fn reference_signature_verifies_with_openssl() {
        use sha2::Digest;
        let root = [1; 32];
        let blob = ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
            bytes.fill(2);
            Ok(())
        })
        .unwrap();
        let key = ReferenceKey::open(&root, &blob).unwrap();
        let message = b"original CSR input";
        let digest: [u8; 32] = Sha256::digest(message).into();
        let reply = key.sign_digest(&digest).unwrap();
        let mut wrapped = Cursor(&reply);
        let signature = wrapped.take(4).unwrap().value;
        wrapped.end().unwrap();
        let mut spki = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        spki.extend_from_slice(&key.public());
        let dir =
            std::env::temp_dir().join(format!("stela-refsign-openssl-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let pubkey = dir.join("pub.der");
        let sig = dir.join("sig.der");
        let input = dir.join("message.bin");
        std::fs::write(&pubkey, spki).unwrap();
        std::fs::write(&sig, signature).unwrap();
        std::fs::write(&input, message).unwrap();
        let verify = || {
            std::process::Command::new("/usr/bin/openssl")
                .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
                .arg(&pubkey)
                .args(["-keyform", "DER", "-sigfile"])
                .arg(&sig)
                .args(["-rawin", "-digest", "sha256", "-in"])
                .arg(&input)
                .output()
                .unwrap()
        };
        let result = verify();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::write(&input, b"wrong CSR input").unwrap();
        assert!(!verify().status.success());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsupported_type_and_entropy_failures_cannot_publish_a_reference() {
        let mut calls = 0;
        let mut entropy = |bytes: &mut [u8]| {
            calls += 1;
            bytes.fill(7);
            Err("injected entropy failure")
        };
        assert!(ReferenceKey::create(&[1; 32], 7, &mut entropy).is_err());
        assert_eq!(
            ReferenceKey::create(&[1; 32], 5, &mut entropy).unwrap_err(),
            "injected entropy failure"
        );
        assert_eq!(calls, 1);
    }
}
