pub use core::hash::*;

/// `std`'s default build hasher. A boot image has no secret to seed it with and
/// no untrusted keys to defend from, so it hashes like `FxBuildHasher`.
pub type RandomState = upstream_hash::FxBuildHasher;
pub type DefaultHasher = upstream_hash::FxHasher;
