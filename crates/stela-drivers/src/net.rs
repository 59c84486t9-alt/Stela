//! Network adapters as raw Ethernet II links ([`Link`]): Intel 82574L and
//! PCH (I217–I219) [`e1000e`], discrete Intel Gigabit [`igb`], I225/I226
//! [`igc`], Realtek RTL8169/8168/8125/8126 [`realtek`] and [`virtio`]-net.
//! USB Ethernet adapters are in [`usb::cdc`](crate::usb::cdc) and
//! [`usb::ethernet`](crate::usb::ethernet). [`wifi`] holds the Wi-Fi
//! libraries, which no adapter attaches through yet.
use alloc::{string::String, vec::Vec};
use core::fmt;

mod advanced;
pub mod aqtion;
pub mod e1000e;
pub mod igb;
pub mod igc;
pub mod realtek;
mod ring;
pub mod tg3;
pub mod virtio;
pub mod wifi;

/// The shortest frame without FCS; shorter frames are padded (IEEE 802.3).
pub const MIN_FRAME: usize = 60;
pub const MAX_FRAME: usize = 1514;
/// Destination, source and EtherType.
pub const HEADER: usize = 14;

/// Refuse what no Ethernet link carries: a frame without its header or
/// longer than the maximum.
pub fn check_frame(frame: &[u8]) -> Result<(), LinkError> {
    match frame.len() {
        length if length < HEADER => Err(LinkError::Invalid("frame shorter than its header")),
        length if length > MAX_FRAME => {
            Err(LinkError::Invalid("frame exceeds the Ethernet maximum"))
        }
        _ => Ok(()),
    }
}

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
    /// The link is down: no frame can leave until it comes back. Frames the
    /// adapter held when it went down are discarded, as Linux does.
    NoCarrier,
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
