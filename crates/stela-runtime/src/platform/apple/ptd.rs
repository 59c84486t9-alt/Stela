//! Owned PMP PTD transport. Service-level power acknowledgements and cache
//! grants are not transport effects. See `docs/research/apple-mcc.md` for the
//! original T6000 producer/consumer contract and the remaining MMIO read seam.
use alloc::string::String;

pub mod transport;
pub use transport::Ptd;

/// The shared publication bank and its AP/PMP update alias.
pub const PTD_BYTES: u64 = 0x20000;
pub const UPDATE_OFFSET: u64 = 0x10000;

/// A source-qualified `ptd-range` identity. The fourth DT word (the interrupt
/// resource) must also be retained by the mount; it is not an AIC input number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub id: u32,
    pub start: u32,
    pub count: u32,
    pub name: String,
}
