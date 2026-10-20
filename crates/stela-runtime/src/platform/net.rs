//! A small IPv4 client stack over raw Ethernet frames, for Stela's own
//! outbound requests (the restore client's signing-server POST): DHCPv4,
//! DNS A lookups, TCP client connections and an HTTP/1.1 POST.
//!
//! It runs on any [`Link`](stela_drivers::net::Link), so it is independent
//! of the adapter: one of the mount's own drivers after ExitBootServices
//! (`stela_drivers::net`, or a USB CDC Ethernet adapter on the host xHCI),
//! or a test peer. Everything blocks with explicit deadlines from a
//! [`Clock`]; nothing is retried without bound.
//!
//! Evidence: RFC 826 (ARP), RFC 791 (IPv4), RFC 768 (UDP), RFC 9293 (TCP),
//! RFC 2131 and 2132 (DHCP and its options), RFC 1035 (DNS) and RFC 9112
//! (HTTP/1.1 message syntax). Deliberately absent, and refused or dropped
//! explicitly: IPv6, IP fragments (sent with DF; received fragments are
//! dropped), TCP options other than MSS, out-of-order TCP reassembly (the
//! peer retransmits), TLS, and HTTP redirects.
use alloc::string::String;
use core::fmt;
use stela_drivers::net::LinkError;

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod stack;
pub mod tcp;
pub mod wire;

pub use stack::Stack;

/// An IPv4 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Ipv4(pub [u8; 4]);

impl Ipv4 {
    pub const UNSPECIFIED: Self = Self([0; 4]);
    pub const BROADCAST: Self = Self([0xff; 4]);

    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn from_u32(value: u32) -> Self {
        Self(value.to_be_bytes())
    }

    /// A dotted-quad literal, as a URL host may be.
    pub fn parse(text: &str) -> Option<Self> {
        let mut octets = [0u8; 4];
        let mut parts = text.split('.');
        for octet in &mut octets {
            let part = parts.next()?;
            if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *octet = part.parse().ok()?;
        }
        parts.next().is_none().then_some(Self(octets))
    }
}

impl fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// Why a network operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    /// The link adapter failed or refused a frame.
    Link(String),
    /// The link reports no carrier.
    NoCarrier,
    /// No DHCP server answered, or it offered nothing usable.
    Dhcp(&'static str),
    /// The resolver failed: no server, no answer, or an error code.
    Dns(String),
    /// No ARP reply for this next hop.
    Unreachable(Ipv4),
    /// The peer refused the connection with a reset.
    Refused,
    /// The peer reset an established connection.
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
            Self::Unreachable(ip) => write!(f, "no ARP reply from {ip}"),
            Self::Refused => f.write_str("connection refused"),
            Self::Reset => f.write_str("connection reset by peer"),
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
        }
    }
}

/// Microseconds from an arbitrary origin, monotonic.
pub trait Clock {
    fn now_us(&self) -> u64;
}

impl Clock for stela_drivers::Clock {
    fn now_us(&self) -> u64 {
        self.now_us()
    }
}

/// The Internet checksum (RFC 1071) of `parts` concatenated, folded.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &byte in *part {
            match odd.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => odd = Some(byte),
            }
        }
    }
    if let Some(high) = odd {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::net::Mac;

    #[test]
    fn addresses_parse_and_print() {
        assert_eq!(Ipv4::parse("10.0.2.15"), Some(Ipv4([10, 0, 2, 15])));
        for bad in [
            "10.0.2",
            "10.0.2.15.1",
            "256.0.0.1",
            "a.b.c.d",
            "1..2.3",
            "",
        ] {
            assert_eq!(Ipv4::parse(bad), None, "{bad}");
        }
        assert_eq!(format!("{}", Ipv4([192, 168, 1, 2])), "192.168.1.2");
        assert_eq!(
            format!("{}", Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56])),
            "52:54:00:12:34:56"
        );
        assert!(Mac::BROADCAST.is_multicast());
    }

    #[test]
    fn checksums_follow_rfc_1071() {
        // RFC 1071 section 3's example words sum to ddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&[&data]), !0xddf2);
        // Split parts and an odd length give the same result as one buffer.
        assert_eq!(checksum(&[&data[..3], &data[3..]]), checksum(&[&data]));
        let odd = [0x45, 0x00, 0x01];
        assert_eq!(checksum(&[&odd]), !0x4600);
        // A buffer with its own checksum folded in sums to zero.
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&[&header]), 0);
    }
}
