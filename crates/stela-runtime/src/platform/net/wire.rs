//! Frame and header encodings: Ethernet II, ARP for IPv4 over Ethernet,
//! IPv4, UDP and TCP. Parsers check lengths and checksums and return
//! `None` for anything malformed; builders produce complete frames.
use super::{Ipv4, checksum};
use alloc::vec::Vec;
use stela_drivers::net::{MAX_FRAME, MIN_FRAME, Mac};

pub const ETHERNET_HEADER: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const IPV4_HEADER: usize = 20;
pub const UDP_HEADER: usize = 8;
pub const TCP_HEADER: usize = 20;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
/// The largest IPv4 payload one frame carries.
pub const MTU: usize = MAX_FRAME - ETHERNET_HEADER;
const DONT_FRAGMENT: u16 = 0x4000;
const TTL: u8 = 64;

const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// A received Ethernet II frame.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub destination: Mac,
    pub source: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < ETHERNET_HEADER {
            return None;
        }
        let mac = |at: usize| Mac(bytes[at..at + 6].try_into().unwrap());
        Some(Self {
            destination: mac(0),
            source: mac(6),
            ethertype: be16(bytes, 12),
            payload: &bytes[ETHERNET_HEADER..],
        })
    }
}

/// An Ethernet frame of `ethertype` carrying `payload`, padded to the
/// minimum length.
pub fn frame(destination: Mac, source: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((ETHERNET_HEADER + payload.len()).max(MIN_FRAME));
    bytes.extend_from_slice(&destination.0);
    bytes.extend_from_slice(&source.0);
    bytes.extend_from_slice(&ethertype.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().max(MIN_FRAME), 0);
    bytes
}

/// An ARP packet for IPv4 over Ethernet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub reply: bool,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4,
    pub target_mac: Mac,
    pub target_ip: Ipv4,
}

impl Arp {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 || be16(bytes, 0) != 1 || be16(bytes, 2) != ETHERTYPE_IPV4 {
            return None;
        }
        if bytes[4] != 6 || bytes[5] != 4 {
            return None;
        }
        let reply = match be16(bytes, 6) {
            ARP_REQUEST => false,
            ARP_REPLY => true,
            _ => return None,
        };
        let mac = |at: usize| Mac(bytes[at..at + 6].try_into().unwrap());
        let ip = |at: usize| Ipv4(bytes[at..at + 4].try_into().unwrap());
        Some(Self {
            reply,
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }

    pub fn emit(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        bytes.extend_from_slice(&[6, 4]);
        let operation = if self.reply { ARP_REPLY } else { ARP_REQUEST };
        bytes.extend_from_slice(&operation.to_be_bytes());
        bytes.extend_from_slice(&self.sender_mac.0);
        bytes.extend_from_slice(&self.sender_ip.0);
        bytes.extend_from_slice(&self.target_mac.0);
        bytes.extend_from_slice(&self.target_ip.0);
        bytes
    }
}

/// A received, unfragmented IPv4 datagram.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    pub source: Ipv4,
    pub destination: Ipv4,
    pub protocol: u8,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// `None` for a malformed header, a bad checksum or a fragment.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < IPV4_HEADER || bytes[0] >> 4 != 4 {
            return None;
        }
        let header = usize::from(bytes[0] & 0xf) * 4;
        let total = usize::from(be16(bytes, 2));
        if header < IPV4_HEADER || total < header || total > bytes.len() {
            return None;
        }
        if checksum(&[&bytes[..header]]) != 0 {
            return None;
        }
        // More Fragments, or a nonzero offset: a fragment this stack drops.
        if be16(bytes, 6) & 0x3fff != 0 {
            return None;
        }
        let ip = |at: usize| Ipv4(bytes[at..at + 4].try_into().unwrap());
        Some(Self {
            source: ip(12),
            destination: ip(16),
            protocol: bytes[9],
            payload: &bytes[header..total],
        })
    }
}

/// An IPv4 header of `protocol` with DF set, followed by `payload`.
pub fn ipv4(source: Ipv4, destination: Ipv4, protocol: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let total = (IPV4_HEADER + payload.len()) as u16;
    let mut bytes = Vec::with_capacity(usize::from(total));
    bytes.extend_from_slice(&[0x45, 0]);
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&DONT_FRAGMENT.to_be_bytes());
    bytes.extend_from_slice(&[TTL, protocol, 0, 0]);
    bytes.extend_from_slice(&source.0);
    bytes.extend_from_slice(&destination.0);
    let sum = checksum(&[&bytes]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn pseudo_header(source: Ipv4, destination: Ipv4, protocol: u8, length: usize) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(&source.0);
    bytes[4..8].copy_from_slice(&destination.0);
    bytes[9] = protocol;
    bytes[10..12].copy_from_slice(&(length as u16).to_be_bytes());
    bytes
}

/// A received UDP datagram.
#[derive(Debug, Clone, Copy)]
pub struct Udp<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    pub fn parse(source: Ipv4, destination: Ipv4, bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < UDP_HEADER {
            return None;
        }
        let length = usize::from(be16(bytes, 4));
        if length < UDP_HEADER || length > bytes.len() {
            return None;
        }
        let bytes = &bytes[..length];
        // A zero checksum means the sender computed none (RFC 768).
        if be16(bytes, 6) != 0 {
            let pseudo = pseudo_header(source, destination, PROTOCOL_UDP, length);
            if checksum(&[&pseudo, bytes]) != 0 {
                return None;
            }
        }
        Some(Self {
            source_port: be16(bytes, 0),
            destination_port: be16(bytes, 2),
            payload: &bytes[UDP_HEADER..],
        })
    }
}

pub fn udp(
    source: Ipv4,
    destination: Ipv4,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = UDP_HEADER + payload.len();
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&destination_port.to_be_bytes());
    bytes.extend_from_slice(&(length as u16).to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    let pseudo = pseudo_header(source, destination, PROTOCOL_UDP, length);
    let sum = match checksum(&[&pseudo, &bytes]) {
        0 => 0xffff,
        sum => sum,
    };
    bytes[6..8].copy_from_slice(&sum.to_be_bytes());
    bytes
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
const MSS_OPTION: u8 = 2;

/// A received TCP segment.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    /// The peer's maximum segment size option, on a SYN.
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    pub fn parse(source: Ipv4, destination: Ipv4, bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < TCP_HEADER {
            return None;
        }
        let offset = usize::from(bytes[12] >> 4) * 4;
        if offset < TCP_HEADER || offset > bytes.len() {
            return None;
        }
        let pseudo = pseudo_header(source, destination, PROTOCOL_TCP, bytes.len());
        if checksum(&[&pseudo, bytes]) != 0 {
            return None;
        }
        let mut mss = None;
        let mut options = &bytes[TCP_HEADER..offset];
        while let Some(&kind) = options.first() {
            match kind {
                0 => break,
                1 => options = &options[1..],
                _ => {
                    let length = usize::from(*options.get(1)?);
                    if length < 2 || length > options.len() {
                        return None;
                    }
                    if kind == MSS_OPTION && length == 4 {
                        mss = Some(be16(options, 2));
                    }
                    options = &options[length..];
                }
            }
        }
        Some(Self {
            source_port: be16(bytes, 0),
            destination_port: be16(bytes, 2),
            sequence: be32(bytes, 4),
            acknowledgment: be32(bytes, 8),
            flags: bytes[13] & 0x3f,
            window: be16(bytes, 14),
            mss,
            payload: &bytes[offset..],
        })
    }
}

/// The fields of one outgoing TCP segment.
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

pub fn tcp(source: Ipv4, destination: Ipv4, segment: &Outgoing<'_>) -> Vec<u8> {
    let options = if segment.mss.is_some() { 4 } else { 0 };
    let length = TCP_HEADER + options + segment.payload.len();
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&segment.source_port.to_be_bytes());
    bytes.extend_from_slice(&segment.destination_port.to_be_bytes());
    bytes.extend_from_slice(&segment.sequence.to_be_bytes());
    bytes.extend_from_slice(&segment.acknowledgment.to_be_bytes());
    bytes.push((((TCP_HEADER + options) / 4) as u8) << 4);
    bytes.push(segment.flags);
    bytes.extend_from_slice(&segment.window.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(mss) = segment.mss {
        bytes.extend_from_slice(&[MSS_OPTION, 4]);
        bytes.extend_from_slice(&mss.to_be_bytes());
    }
    bytes.extend_from_slice(segment.payload);
    let pseudo = pseudo_header(source, destination, PROTOCOL_TCP, length);
    let sum = checksum(&[&pseudo, &bytes]);
    bytes[16..18].copy_from_slice(&sum.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4 = Ipv4([10, 0, 2, 15]);
    const B: Ipv4 = Ipv4([10, 0, 2, 2]);

    #[test]
    fn frames_pad_and_parse() {
        let frame = frame(Mac::BROADCAST, Mac([2; 6]), ETHERTYPE_ARP, &[1, 2, 3]);
        assert_eq!(frame.len(), MIN_FRAME);
        let parsed = Frame::parse(&frame).unwrap();
        assert_eq!(parsed.destination, Mac::BROADCAST);
        assert_eq!(parsed.source, Mac([2; 6]));
        assert_eq!(parsed.ethertype, ETHERTYPE_ARP);
        assert_eq!(&parsed.payload[..3], &[1, 2, 3]);
        assert!(Frame::parse(&frame[..13]).is_none());
    }

    #[test]
    fn arp_round_trips_and_rejects_other_protocols() {
        let arp = Arp {
            reply: true,
            sender_mac: Mac([1; 6]),
            sender_ip: A,
            target_mac: Mac([2; 6]),
            target_ip: B,
        };
        let bytes = arp.emit();
        assert_eq!(Arp::parse(&bytes), Some(arp));
        let mut other = bytes.clone();
        other[3] = 0xdd; // IPv6 protocol type
        assert_eq!(Arp::parse(&other), None);
        other = bytes;
        other[7] = 3; // RARP
        assert_eq!(Arp::parse(&other), None);
    }

    #[test]
    fn ipv4_checks_its_header_and_drops_fragments() {
        let packet = ipv4(A, B, PROTOCOL_UDP, 7, b"data");
        let parsed = Ipv4Packet::parse(&packet).unwrap();
        assert_eq!((parsed.source, parsed.destination), (A, B));
        assert_eq!(parsed.protocol, PROTOCOL_UDP);
        assert_eq!(parsed.payload, b"data");
        // Ethernet padding after the datagram is not payload.
        let mut padded = packet.clone();
        padded.extend_from_slice(&[0; 20]);
        assert_eq!(Ipv4Packet::parse(&padded).unwrap().payload, b"data");
        let mut corrupt = packet.clone();
        corrupt[8] = 1;
        assert!(Ipv4Packet::parse(&corrupt).is_none());
        let mut fragment = packet;
        fragment[6] = 0x20; // More Fragments
        fragment[10..12].fill(0);
        let sum = checksum(&[&fragment[..20]]);
        fragment[10..12].copy_from_slice(&sum.to_be_bytes());
        assert!(Ipv4Packet::parse(&fragment).is_none());
    }

    #[test]
    fn udp_checksums_cover_the_pseudo_header() {
        let datagram = udp(A, B, 68, 67, b"hello");
        let parsed = Udp::parse(A, B, &datagram).unwrap();
        assert_eq!((parsed.source_port, parsed.destination_port), (68, 67));
        assert_eq!(parsed.payload, b"hello");
        // The sum is symmetric in the addresses; another address fails it.
        assert!(Udp::parse(B, A, &datagram).is_some());
        assert!(Udp::parse(A, Ipv4([10, 0, 2, 3]), &datagram).is_none());
        let mut unchecked = datagram;
        unchecked[6..8].fill(0);
        unchecked[8] ^= 1;
        assert!(Udp::parse(A, Ipv4([1, 1, 1, 1]), &unchecked).is_some());
    }

    #[test]
    fn tcp_segments_carry_mss_and_reject_bad_sums() {
        let out = Outgoing {
            source_port: 49152,
            destination_port: 80,
            sequence: 0x1234_5678,
            acknowledgment: 0,
            flags: SYN,
            window: 65535,
            mss: Some(1460),
            payload: &[],
        };
        let bytes = tcp(A, B, &out);
        let parsed = Segment::parse(A, B, &bytes).unwrap();
        assert_eq!(parsed.sequence, 0x1234_5678);
        assert_eq!(parsed.flags, SYN);
        assert_eq!(parsed.mss, Some(1460));
        assert!(parsed.payload.is_empty());
        let data = tcp(
            A,
            B,
            &Outgoing {
                flags: ACK | PSH,
                mss: None,
                payload: b"GET",
                ..out
            },
        );
        assert_eq!(Segment::parse(A, B, &data).unwrap().payload, b"GET");
        assert!(Segment::parse(B, A, &data).is_some());
        assert!(Segment::parse(A, Ipv4([9; 4]), &data).is_none());
    }
}
