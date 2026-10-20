//! Network adapters as raw Ethernet II links ([`Link`]): Intel I225/I226
//! ([`igc`]) and virtio-net ([`virtio`]). USB Ethernet adapters are in
//! [`usb::cdc`](crate::usb::cdc).
use alloc::{string::String, vec::Vec};
use core::fmt;

pub mod igc;
pub mod virtio;

/// The shortest frame without FCS; shorter frames are padded (IEEE 802.3).
pub const MIN_FRAME: usize = 60;
pub const MAX_FRAME: usize = 1514;

/// An Ethernet MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 != 0
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Why a link did not take or give a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The adapter failed or refused a frame.
    Adapter(String),
    /// A frame no Ethernet link carries.
    Invalid(&'static str),
}

/// A raw Ethernet II link: whole frames without the FCS.
pub trait Link {
    /// The adapter's station address, which the stack sends from.
    fn mac(&self) -> Mac;
    /// Whether the adapter reports carrier; `true` when it cannot tell.
    fn carrier(&mut self) -> bool {
        true
    }
    /// Queues one frame (14-byte header and payload, at most 1514 bytes).
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError>;
    /// One frame the adapter received, if any, without blocking.
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError>;
}
