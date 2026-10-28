//! Host SHA-1, SHA-256 and AES with a software fallback and preserving x86 kernels.
//!
//! The digest and cipher interfaces are RustCrypto's. The x86 kernels take
//! pointers and integers, so the UEFI soft-float ABI does not need vector
//! arguments or LLVM intrinsics. Every kernel restores the XMM registers it
//! uses; legacy SSE encodings leave upper vector state and MXCSR unchanged.
#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod aes;
mod sha1;
mod sha256;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub use ::sha2::digest;
pub use aes::{Aes128, Aes192, Aes256};
pub use sha1::Sha1;
pub use sha256::Sha256;

#[cfg(test)]
mod tests;
