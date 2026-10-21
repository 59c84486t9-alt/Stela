//! Shared native 802.11 frame and security boundaries.
//!
//! Vendor transports supply normalized MPDUs, preserving the actual Protected
//! bit and removing FCS and vendor alignment padding. Decryption observations
//! never imply association, authentication, replay validation or Ethernet
//! carrier. Station management and software cryptography are separate work.

pub mod frame;
pub mod intel;
pub mod mediatek;
pub mod security;
pub mod station;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub band: Band,
    pub number: u16,
    pub frequency_mhz: u16,
}

/// On-air band, independent of a driver's raw channel encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz2,
    Ghz5,
    Ghz6,
}

/// Actual received radio information. This is not regulatory permission to TX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadioStatus {
    pub band: Band,
    pub channel: u16,
    pub frequency_mhz: u16,
    /// `None` when the device did not measure a usable value.
    pub signal_dbm: Option<i8>,
    pub chain_signal_dbm: [Option<i8>; 4],
    /// Vendor rate/vector encoding with its negotiated layout version.
    pub rate: RawRate,
    pub tsf: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawRate {
    pub layout: u16,
    pub words: [u32; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timestamp {
    Low32(u32),
    Full64(u64),
}

/// Retained aggregation observations. The first security path explicitly
/// refuses aggregates until reordering and shared-PN subframes are supported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregation {
    pub ampdu: Option<u32>,
    pub reorder: Option<Reorder>,
    pub amsdu: Option<Amsdu>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reorder {
    pub ba_id: u16,
    pub next_sequence: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Amsdu {
    pub index: u16,
    pub first: bool,
    pub last: bool,
}

/// A transport completion must distinguish reclaiming DMA from an on-air ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxStatus {
    pub cookie: u64,
    pub queue: u16,
    pub descriptor: u16,
    pub dma_released: bool,
    pub air: AirStatus,
    /// Actual attempts when available; not synthesized for aggregate responses.
    pub attempts: Option<u16>,
    pub rate: Option<RawRate>,
    pub raw_status: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AirStatus {
    /// Includes aggregate TX responses awaiting a matching block ACK.
    Pending,
    Acknowledged,
    Failed,
    Flushed,
}
