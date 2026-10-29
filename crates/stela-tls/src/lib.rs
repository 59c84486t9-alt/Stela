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
mod verification;
use backend::{Digest, Entropy, Error, Group, Key};
pub use provider::{EntropySource, PolicyError, ProviderOwner, client_config};
