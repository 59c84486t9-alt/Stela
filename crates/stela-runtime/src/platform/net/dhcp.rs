//! DHCPv4 client messages (RFC 2131 sections 2, 3.1 and 4.4; option codes
//! of RFC 2132). The client broadcasts DISCOVER and REQUEST with the
//! broadcast flag set, so it needs no address to hear OFFER and ACK.
use super::Ipv4;
use alloc::vec::Vec;
use stela_drivers::net::Mac;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
const BOOT_REQUEST: u8 = 1;
const BOOT_REPLY: u8 = 2;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
const BROADCAST_FLAG: u16 = 0x8000;
/// The fixed BOOTP fields before the options.
const FIXED: usize = 236;

const PAD: u8 = 0;
const SUBNET_MASK: u8 = 1;
const ROUTER: u8 = 3;
const DNS_SERVERS: u8 = 6;
const REQUESTED_ADDRESS: u8 = 50;
const LEASE_TIME: u8 = 51;
const MESSAGE_TYPE: u8 = 53;
const SERVER_IDENTIFIER: u8 = 54;
const PARAMETERS: u8 = 55;
const MAXIMUM_SIZE: u8 = 57;
const CLIENT_IDENTIFIER: u8 = 61;
const END: u8 = 255;

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;

/// A client message: DISCOVER, or REQUEST of an offered address.
pub fn request(
    kind: u8,
    xid: u32,
    mac: Mac,
    offered: Option<(Ipv4, Ipv4)>,
    seconds: u16,
) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; FIXED];
    bytes[0] = BOOT_REQUEST;
    bytes[1] = 1; // Ethernet
    bytes[2] = 6;
    bytes[4..8].copy_from_slice(&xid.to_be_bytes());
    bytes[8..10].copy_from_slice(&seconds.to_be_bytes());
    bytes[10..12].copy_from_slice(&BROADCAST_FLAG.to_be_bytes());
    bytes[28..34].copy_from_slice(&mac.0);
    bytes.extend_from_slice(&COOKIE);
    bytes.extend_from_slice(&[MESSAGE_TYPE, 1, kind]);
    bytes.extend_from_slice(&[CLIENT_IDENTIFIER, 7, 1]);
    bytes.extend_from_slice(&mac.0);
    if let Some((address, server)) = offered {
        bytes.extend_from_slice(&[REQUESTED_ADDRESS, 4]);
        bytes.extend_from_slice(&address.0);
        bytes.extend_from_slice(&[SERVER_IDENTIFIER, 4]);
        bytes.extend_from_slice(&server.0);
    }
    bytes.extend_from_slice(&[MAXIMUM_SIZE, 2]);
    bytes.extend_from_slice(&1500u16.to_be_bytes());
    bytes.extend_from_slice(&[PARAMETERS, 4, SUBNET_MASK, ROUTER, DNS_SERVERS, LEASE_TIME]);
    bytes.push(END);
    // RFC 2131 4.1: a 300-byte minimum, as BOOTP relays expect.
    bytes.resize(bytes.len().max(300), PAD);
    bytes
}

/// A server reply's address assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub kind: u8,
    pub xid: u32,
    pub address: Ipv4,
    pub server: Option<Ipv4>,
    pub mask: Option<Ipv4>,
    pub router: Option<Ipv4>,
    pub dns: Vec<Ipv4>,
    pub lease_seconds: Option<u32>,
}

impl Reply {
    /// `None` unless this is a well-formed BOOTREPLY for `mac`.
    pub fn parse(bytes: &[u8], mac: Mac) -> Option<Self> {
        if bytes.len() < FIXED + 4 || bytes[0] != BOOT_REPLY || bytes[1] != 1 || bytes[2] != 6 {
            return None;
        }
        if bytes[28..34] != mac.0 || bytes[FIXED..FIXED + 4] != COOKIE {
            return None;
        }
        let ip = |b: &[u8]| Ipv4(b[..4].try_into().unwrap());
        let mut reply = Self {
            kind: 0,
            xid: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            address: ip(&bytes[16..20]),
            server: None,
            mask: None,
            router: None,
            dns: Vec::new(),
            lease_seconds: None,
        };
        let mut options = &bytes[FIXED + 4..];
        loop {
            let (&code, rest) = options.split_first()?;
            match code {
                PAD => {
                    options = rest;
                    continue;
                }
                END => break,
                _ => {}
            }
            let (&length, rest) = rest.split_first()?;
            let length = usize::from(length);
            if rest.len() < length {
                return None;
            }
            let (value, rest) = rest.split_at(length);
            options = rest;
            match code {
                MESSAGE_TYPE if length == 1 => reply.kind = value[0],
                SERVER_IDENTIFIER if length == 4 => reply.server = Some(ip(value)),
                SUBNET_MASK if length == 4 => reply.mask = Some(ip(value)),
                ROUTER if length >= 4 => reply.router = Some(ip(value)),
                DNS_SERVERS if length >= 4 && length % 4 == 0 => {
                    reply.dns = value.chunks(4).map(ip).collect();
                }
                LEASE_TIME if length == 4 => {
                    reply.lease_seconds = Some(u32::from_be_bytes(value.try_into().unwrap()))
                }
                _ => {}
            }
        }
        (reply.kind != 0).then_some(reply)
    }
}

/// A server's reply, as the tests' DHCP server sends it.
#[cfg(test)]
pub(crate) fn reply(kind: u8, xid: u32, mac: Mac, lease: &Reply) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; FIXED];
    bytes[0] = BOOT_REPLY;
    bytes[1] = 1;
    bytes[2] = 6;
    bytes[4..8].copy_from_slice(&xid.to_be_bytes());
    bytes[16..20].copy_from_slice(&lease.address.0);
    bytes[28..34].copy_from_slice(&mac.0);
    bytes.extend_from_slice(&COOKIE);
    bytes.extend_from_slice(&[MESSAGE_TYPE, 1, kind]);
    let mut option = |code: u8, value: &[u8]| {
        bytes.extend_from_slice(&[code, value.len() as u8]);
        bytes.extend_from_slice(value);
    };
    if let Some(server) = lease.server {
        option(SERVER_IDENTIFIER, &server.0);
    }
    if let Some(mask) = lease.mask {
        option(SUBNET_MASK, &mask.0);
    }
    if let Some(router) = lease.router {
        option(ROUTER, &router.0);
    }
    let dns: Vec<u8> = lease.dns.iter().flat_map(|ip| ip.0).collect();
    if !dns.is_empty() {
        option(DNS_SERVERS, &dns);
    }
    if let Some(lease) = lease.lease_seconds {
        option(LEASE_TIME, &lease.to_be_bytes());
    }
    bytes.push(END);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_carry_the_client_and_its_choice() {
        let mac = Mac([2, 0, 0, 0, 0, 1]);
        let discover = request(DISCOVER, 0x1234, mac, None, 3);
        assert_eq!(discover.len(), 300);
        assert_eq!(discover[0], BOOT_REQUEST);
        assert_eq!(&discover[4..8], &0x1234u32.to_be_bytes());
        assert_eq!(&discover[8..10], &3u16.to_be_bytes());
        assert_eq!(&discover[10..12], &BROADCAST_FLAG.to_be_bytes());
        assert_eq!(&discover[28..34], &mac.0);
        assert_eq!(
            &discover[FIXED..FIXED + 7],
            &[99, 130, 83, 99, 53, 1, DISCOVER]
        );
        let offered = (Ipv4([10, 0, 2, 15]), Ipv4([10, 0, 2, 2]));
        let req = request(REQUEST, 0x1234, mac, Some(offered), 0);
        let window = |code: u8| {
            req.windows(6)
                .find(|w| w[0] == code && w[1] == 4)
                .map(|w| Ipv4(w[2..6].try_into().unwrap()))
        };
        assert_eq!(window(REQUESTED_ADDRESS), Some(offered.0));
        assert_eq!(window(SERVER_IDENTIFIER), Some(offered.1));
    }

    #[test]
    fn replies_parse_their_options_and_reject_strangers() {
        let mac = Mac([2, 0, 0, 0, 0, 1]);
        let lease = Reply {
            kind: OFFER,
            xid: 9,
            address: Ipv4([10, 0, 2, 15]),
            server: Some(Ipv4([10, 0, 2, 2])),
            mask: Some(Ipv4([255, 255, 255, 0])),
            router: Some(Ipv4([10, 0, 2, 2])),
            dns: alloc::vec![Ipv4([10, 0, 2, 3]), Ipv4([1, 1, 1, 1])],
            lease_seconds: Some(86400),
        };
        let bytes = reply(OFFER, 9, mac, &lease);
        assert_eq!(Reply::parse(&bytes, mac), Some(lease));
        assert_eq!(Reply::parse(&bytes, Mac([2, 0, 0, 0, 0, 2])), None);
        assert_eq!(Reply::parse(&bytes[..FIXED + 6], mac), None);
        let mut request = bytes;
        request[0] = BOOT_REQUEST;
        assert_eq!(Reply::parse(&request, mac), None);
    }
}
