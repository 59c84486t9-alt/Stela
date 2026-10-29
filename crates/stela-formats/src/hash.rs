//! SHA-256 hex digests, shared by hosted and freestanding code.
use alloc::string::String;
use sha2::Digest;
use stela_crypto::Sha256;

pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
