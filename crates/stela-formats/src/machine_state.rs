//! Wire geometry of Stela's machine-state partition records.
/// Reserved SEP roots/store area following the NOR image.
pub const SEP_BYTES: u64 = 0x10000;
/// Roots record reservation at the beginning of the SEP area.
pub const SEP_ROOTS_BYTES: usize = 0x1000;
/// One durable nonce-store bank; two alternating banks follow the roots.
pub const SEP_BANK_BYTES: usize = 0x2000;
