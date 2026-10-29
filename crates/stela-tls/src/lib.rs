//! Native client TLS over an owned entropy/time provider and bounded record pump.
#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;
mod aead;
mod allocator;
mod backend;
pub mod channel;
mod provider;
pub mod time;
mod verification;
use backend::{Digest, Entropy, Error, Group, Key};
pub use provider::{EntropySource, PolicyError, ProviderOwner, client_config};

// The configuration and peer name use the same pinned Rustls owner as Channel.
pub use rustls::crypto::GetRandomFailed as RandomUnavailable;
pub use rustls::{ClientConfig, pki_types::ServerName};
