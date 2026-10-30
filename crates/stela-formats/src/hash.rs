//! SHA-256 hex digests, shared by hosted and freestanding code.
use alloc::string::String;
use stela_crypto::Sha256;
use stela_crypto::digest::Digest;

pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
