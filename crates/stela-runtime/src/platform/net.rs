//! Stela's own IPv4 client network over raw Ethernet frames: the restore
//! client's signing-server POST and its ranged downloads from Apple's CDN.
//!
//! The protocols are smoltcp's (ARP, IPv4, DHCPv4 with lease renewal, DNS,
//! and TCP with window scaling, reassembly and Reno congestion control);
//! [`Stack`] adapts it to any [`Link`](stela_drivers::net::Link), so it is
//! independent of the adapter: one of the mount's own drivers after
//! ExitBootServices (`stela_drivers::net`, or a USB CDC Ethernet adapter on
//! the host xHCI), or a test peer. Every wait has an explicit deadline from
//! a [`Clock`]; nothing is retried without bound. [`http`] frames the
//! requests and responses (RFC 9112), with httparse reading the heads.
//! Absent, and refused explicitly: IPv6, TLS and HTTP redirects.
use alloc::string::String;
use core::fmt;
use stela_drivers::net::LinkError;

pub mod http;
pub mod stack;

pub use smoltcp::wire::Ipv4Address as Ipv4;
pub use stack::{Config, Stack, Transfer};

/// Why a network operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    /// The link adapter failed or refused a frame.
    Link(String),
    /// The link reports no carrier.
    NoCarrier,
    /// No DHCP server answered.
    Dhcp(&'static str),
    /// The resolver failed: no server, no answer, or an error code.
    Dns(String),
    /// The peer refused or reset the connection.
    Reset,
    /// Something did not finish before its deadline.
    Timeout(&'static str),
    /// The HTTP response was malformed or not one this client accepts.
    Http(String),
    /// The server answered with a non-success HTTP status.
    Status(u16),
    /// A request the stack cannot express (bad URL, oversized message).
    Invalid(&'static str),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(why) => write!(f, "network link: {why}"),
            Self::NoCarrier => f.write_str("network link has no carrier"),
            Self::Dhcp(why) => write!(f, "DHCP: {why}"),
            Self::Dns(why) => write!(f, "DNS: {why}"),
            Self::Reset => f.write_str("connection refused or reset by peer"),
            Self::Timeout(what) => write!(f, "timed out: {what}"),
            Self::Http(why) => write!(f, "HTTP: {why}"),
            Self::Status(code) => write!(f, "HTTP status {code}"),
            Self::Invalid(why) => write!(f, "invalid request: {why}"),
        }
    }
}

impl From<LinkError> for NetError {
    fn from(error: LinkError) -> Self {
        match error {
            LinkError::Adapter(why) => Self::Link(why),
            LinkError::Invalid(why) => Self::Invalid(why),
            LinkError::NoCarrier => Self::NoCarrier,
        }
    }
}

/// Microseconds from an arbitrary origin, monotonic.
pub trait Clock {
    fn now_us(&self) -> u64;
    /// Sleep until an interrupt or the clock reads `until_us`, whichever is
    /// first; the stack calls it only for a link that signals arrivals. A
    /// clock that cannot sleep returns at once, and the stack polls.
    fn sleep(&self, until_us: u64) {
        let _ = until_us;
    }
}

impl Clock for stela_drivers::Clock {
    fn now_us(&self) -> u64 {
        self.now_us()
    }
}
