//! Dual-stack HTTP and TLS transport over retained native Ethernet adapters.
//!
//! smoltcp owns ARP, IPv4/IPv6, DHCPv4, DNS and TCP. SLAAC/RDNSS admission
//! includes duplicate-address detection; the URL-aware request layer retains
//! redirect policy and range validators. TLS uses the shared protocol provider
//! and requires actual owned entropy and a UTC-correlated continuous clock.
//! Missing native capabilities refuse HTTPS; they cannot select plaintext.
//! Stateful DHCPv6 is unsupported. Raw guest relay bytes stay opaque.
use alloc::string::String;
use core::fmt;
use stela_drivers::net::LinkError;

pub mod http;
pub mod stack;
pub mod tls;

pub use smoltcp::wire::Ipv4Address as Ipv4;
pub use stack::{
    Config, HttpRequest, HttpTransfer, SecureTransfer, Stack, TlsUnavailable, Transfer,
};

/// Why a network operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    /// The link adapter failed or refused a frame.
    Link(String),
    /// The link reports no carrier.
    NoCarrier,
    /// IPv6 duplicate-address detection found another owner.
    DuplicateAddress(core::net::Ipv6Addr),
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
    /// The TLS engine refused the peer, record or required time/entropy input.
    Tls(String),
    /// A connection ended inside an otherwise valid framed body or record.
    Truncated(&'static str),
    TlsUnavailable(TlsUnavailable),
    Url(http::UrlError),
    Redirect(http::RedirectError),
    ProxyAuthentication,
    NetworkAuthentication,
    /// The server answered with a non-success HTTP status.
    Status(u16),
    /// A request the stack cannot express (bad URL, oversized message).
    Invalid(&'static str),
}

impl NetError {
    /// Retry only a transient transport/server failure. Identity, certificate,
    /// capability, framing and redirect policy failures need a changed input.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Link(_)
                | Self::NoCarrier
                | Self::Dhcp(_)
                | Self::Dns(_)
                | Self::Reset
                | Self::Timeout(_)
                | Self::Truncated(_)
                | Self::Status(408 | 429 | 500 | 502 | 503 | 504)
        )
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(why) => write!(f, "network link: {why}"),
            Self::NoCarrier => f.write_str("network link has no carrier"),
            Self::DuplicateAddress(address) => {
                write!(f, "IPv6 address {address} is already in use")
            }
            Self::Dhcp(why) => write!(f, "DHCP: {why}"),
            Self::Dns(why) => write!(f, "DNS: {why}"),
            Self::Reset => f.write_str("connection refused or reset by peer"),
            Self::Timeout(what) => write!(f, "timed out: {what}"),
            Self::Http(why) => write!(f, "HTTP: {why}"),
            Self::Tls(why) => write!(f, "TLS: {why}"),
            Self::Truncated(what)=>write!(f,"connection ended inside {what}"),
            Self::TlsUnavailable(why)=>write!(f,"TLS unavailable: {why}"),
            Self::Url(why)=>write!(f,"URL: {why}"),
            Self::Redirect(why)=>write!(f,"redirect: {why}"),
            Self::ProxyAuthentication=>f.write_str("the network requires proxy authentication (HTTP 407); no proxy credentials are configured"),
            Self::NetworkAuthentication=>f.write_str("the network requires authentication (HTTP 511); complete network login before installing"),
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
