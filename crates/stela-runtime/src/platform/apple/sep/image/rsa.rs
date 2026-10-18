//! Public RSA PKCS#1 v1.5 verification (RFC 8017 §§5.2.2, 8.2, 9.2).
//! Bounded to 2048..4096-bit, whole-octet moduli and exponent 65537.
//! No private keys, signing, padding recovery or permissive ASN.1 decoding.
use super::der::{sequence, unsigned};
use crypto_bigint::{
    Encoding, U4096,
    modular::runtime_mod::{DynResidue, DynResidueParams},
};
use sha2::{Digest, Sha256, Sha384};

const MAX_BYTES: usize = 512;
const MIN_BYTES: usize = 256;
const PUBLIC_EXPONENT: &[u8] = &[1, 0, 1];
const SHA256_INFO: &[u8] =
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\0\x04\x20";
const SHA384_INFO: &[u8] =
    b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\0\x04\x30";

#[derive(Clone, Copy)]
pub(super) enum Hash {
    Sha256,
    Sha384,
}

pub(super) struct Key {
    modulus: U4096,
    bytes: usize,
}

impl Key {
    /// The DER RSAPublicKey inside SubjectPublicKeyInfo's BIT STRING.
    pub fn parse(der: &[u8]) -> Result<Self, &'static str> {
        let mut fields = sequence(der)?;
        let n = fields.take(2)?;
        let modulus = unsigned(n.value)?;
        if !(MIN_BYTES..=MAX_BYTES).contains(&modulus.len())
            || modulus[0] & 128 == 0
            || modulus[modulus.len() - 1] & 1 == 0
        {
            return Err("SEP RSA modulus size or parity is unsupported");
        }
        let exponent = fields.take(2)?;
        if unsigned(exponent.value)? != PUBLIC_EXPONENT {
            return Err("SEP RSA exponent is unsupported");
        }
        fields.end()?;
        let mut padded = [0; MAX_BYTES];
        padded[MAX_BYTES - modulus.len()..].copy_from_slice(modulus);
        Ok(Self {
            modulus: U4096::from_be_bytes(padded),
            bytes: modulus.len(),
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8], hash: Hash) -> Result<(), &'static str> {
        if signature.len() != self.bytes {
            return Err("SEP RSA signature has the wrong length");
        }
        let mut padded = [0; MAX_BYTES];
        padded[MAX_BYTES - self.bytes..].copy_from_slice(signature);
        let s = U4096::from_be_bytes(padded);
        if s >= self.modulus {
            return Err("SEP RSA signature representative is out of range");
        }
        let params = DynResidueParams::new(&self.modulus);
        let recovered = DynResidue::new(&s, params)
            .pow_bounded_exp(&U4096::from_u64(65537), 17)
            .retrieve()
            .to_be_bytes();
        let mut expected = [0xff; MAX_BYTES];
        let (prefix, digest) = match hash {
            Hash::Sha256 => (SHA256_INFO, Sha256::digest(message).to_vec()),
            Hash::Sha384 => (SHA384_INFO, Sha384::digest(message).to_vec()),
        };
        let start = MAX_BYTES - self.bytes;
        expected[..start].fill(0);
        expected[start] = 0;
        expected[start + 1] = 1;
        let separator = MAX_BYTES - prefix.len() - digest.len() - 1;
        expected[separator] = 0;
        expected[separator + 1..separator + 1 + prefix.len()].copy_from_slice(prefix);
        expected[MAX_BYTES - digest.len()..].copy_from_slice(&digest);
        if recovered != expected {
            return Err("SEP RSA PKCS1 signature verification failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independently_signed_vector_rejects_corruption_wrong_hash_and_representatives() {
        // Generated solely for Stela with OpenSSL RSA-2048/SHA-384. Public
        // key and signature only; no Apple data or private key in this fixture.
        let public = hex::decode("3082010a0282010100ab6a5a81c1a2b0afdd4e24b554773cb83c418a9594bdc84f2e4045d690a63615fce9c9714f435419009c32feec337d472cd0a13ea6278c8a669abca6606789f3f33513d095d92a1e3df2ea12e3b2052d1ef0309e6e85858f80b501f82e84f5e303b206582e5a78832653ccb28542711a1b60af67fb5b8f13ca7a42d2acd2090c2deac96f1d3f1c33460b6d42261132bcb86a75069eb44abb156ca52c7e486a944b689b6a1aaf23403d6f2ae0427115e8a978d6a24a9c72023c6bc88a8f3d8a48d87a2a451b0cc664e868bbad175b40a329e36cc8bd5ce1c0a23c9bcb0050e69e100efb6047d2df38782c449725f64735214f1da788728f73caa01238494b97cf0203010001").unwrap();
        let signature = hex::decode("0fff416582ce163cac6e609896d5f856330f734b93b6109cb3d9ac6e5d2fc8fdf14bc7abf7faa10cf1d629de7cf654cbd8e7696b5cd0c7b121284b09c8362141abfb92738b175abb7256864cfd5dbc8c82ab9c3d0a7ac9b55fff32f8c636fd836f6ee446f76c01a027ea0c7c901c7f79e381f3b27cd956413f284c81fc2e97fd1cb3610f549e7b2fdecdba5f208756d8bdb0a347ac535fa1d5b5c3a6b8f1b5422729b216eaf9b79cc1e9706f2d6b6bbe9d0ec82d227b195b443a1e66d59bddfa652cd13450d7adc61cc1dbf55912fca28b32d4c1d031209ac34adc6c74f0cd566107b3bbc9b559d8c66e2d370a766d4985abd83130980b60188d5ed74b369853").unwrap();
        let key = Key::parse(&public).unwrap();
        let message = b"Stela synthetic RSA verification vector";
        key.verify(message, &signature, Hash::Sha384).unwrap();
        assert!(key.verify(b"modified", &signature, Hash::Sha384).is_err());
        assert!(key.verify(message, &signature, Hash::Sha256).is_err());
        assert!(key.verify(message, &signature[1..], Hash::Sha384).is_err());
        assert!(key.verify(message, &[0xff; 256], Hash::Sha384).is_err());
        assert!(key.verify(message, &[0; 256], Hash::Sha384).is_err());
        let mut wrong_exponent = public.clone();
        *wrong_exponent.last_mut().unwrap() = 3;
        assert!(Key::parse(&wrong_exponent).is_err());
        for end in 0..public.len() {
            assert!(Key::parse(&public[..end]).is_err());
        }
    }
}
