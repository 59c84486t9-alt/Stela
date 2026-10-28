//! Duplicate-address probes before publishing automatically-derived IPv6 addresses.
use super::rdnss::checksum;
use alloc::{vec, vec::Vec};
use core::net::Ipv6Addr;

pub(super) struct Probe {
    pub(super) address: Ipv6Addr,
    pub(super) nonce: [u8; 6],
    pub(super) until: u64,
    pub(super) duplicate: bool,
}

pub(super) fn solicitation(mac: [u8; 6], target: Ipv6Addr, nonce: [u8; 6]) -> Vec<u8> {
    let raw = target.octets();
    let destination = solicited_node(target);
    let mut frame = vec![0; 14 + 40 + 32];
    frame[..6].copy_from_slice(&[0x33, 0x33, 0xff, raw[13], raw[14], raw[15]]);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    let ip = &mut frame[14..];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&32u16.to_be_bytes());
    ip[6] = 58;
    ip[7] = 255;
    ip[24..40].copy_from_slice(&destination.octets());
    let icmp = &mut ip[40..];
    icmp[0] = 135;
    icmp[8..24].copy_from_slice(&raw);
    // RFC 7527's nonce distinguishes a reflected probe from a peer using the
    // same MAC/IID; a source-MAC comparison alone would miss that collision.
    icmp[24] = 14;
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(&nonce);
    let sum = checksum(Ipv6Addr::UNSPECIFIED, destination, icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    frame
}

pub(super) fn conflicts(frame: &[u8], target: Ipv6Addr, nonce: [u8; 6]) -> bool {
    let Some((source, destination, icmp)) = message(frame) else {
        return false;
    };
    if icmp.len() < 24 || target.is_multicast() || icmp[8..24] != target.octets() {
        return false;
    }
    match icmp[0] {
        136 => {
            // RFC 4861 7.1.2: an NA cannot originate from the unspecified
            // address or set Solicited while addressed to multicast.
            !source.is_unspecified()
                && !source.is_multicast()
                && (destination == target
                    || destination == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))
                && !(destination.is_multicast() && icmp[4] & 0x40 != 0)
                && valid_options(&icmp[24..], false, nonce).is_some()
        }
        135 if source.is_unspecified() && destination == solicited_node(target) => {
            // A DAD NS must use the solicited-node destination and omit the
            // source link-layer option. Validate the whole option tail before
            // trusting a matching nonce (not merely its first option).
            matches!(valid_options(&icmp[24..], true, nonce), Some(false))
        }
        _ => false,
    }
}
fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
    let raw = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(raw[13]),
        u16::from_be_bytes([raw[14], raw[15]]),
    )
}
fn valid_options(mut options: &[u8], dad: bool, nonce: [u8; 6]) -> Option<bool> {
    let mut reflected = false;
    while !options.is_empty() {
        let size = usize::from(*options.get(1)?) * 8;
        let option = options.get(..size).filter(|_| size != 0)?;
        if dad && option[0] == 1 {
            return None;
        }
        if option[0] == 14 && size == 8 && option[2..] == nonce {
            reflected = true;
        }
        options = &options[size..];
    }
    Some(reflected)
}

fn message(frame: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr, &[u8])> {
    if frame.len() < 78 || frame[12..14] != [0x86, 0xdd] {
        return None;
    }
    let ip = &frame[14..];
    if ip[0] >> 4 != 6 || ip[6] != 58 || ip[7] != 255 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?);
    let length = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let icmp = ip.get(40..40 + length)?;
    if icmp.get(1) != Some(&0) || checksum(source, destination, icmp) != 0 {
        return None;
    }
    Some((source, destination, icmp))
}

#[cfg(test)]
mod tests {
    use super::*;
    const TARGET: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    #[test]
    fn nonce_identifies_loopback_without_hiding_a_duplicate_mac_peer() {
        let own = solicitation([2, 0, 0, 0, 0, 2], TARGET, [1; 6]);
        assert!(!conflicts(&own, TARGET, [1; 6]));
        let peer = solicitation([2, 0, 0, 0, 0, 2], TARGET, [2; 6]);
        assert!(conflicts(&peer, TARGET, [1; 6]));
        assert!(!conflicts(&peer, Ipv6Addr::LOCALHOST, [1; 6]));
    }
    #[test]
    fn invalid_checksum_or_hop_limit_is_not_duplicate_evidence() {
        let peer = solicitation([2; 6], TARGET, [2; 6]);
        for offset in [21usize, 54, 55, 56] {
            let mut packet = peer.clone();
            packet[offset] ^= 1;
            assert!(!conflicts(&packet, TARGET, [1; 6]));
        }
    }
    fn resign(frame: &mut [u8]) {
        let ip = &mut frame[14..];
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap());
        ip[42..44].fill(0);
        let sum = checksum(source, destination, &ip[40..]);
        ip[42..44].copy_from_slice(&sum.to_be_bytes());
    }
    #[test]
    fn dad_rejects_wrong_destination_and_source_link_layer_option() {
        let mut frame = solicitation([2; 6], TARGET, [2; 6]);
        frame[38..54].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        resign(&mut frame);
        assert!(!conflicts(&frame, TARGET, [1; 6]));
        let mut frame = solicitation([2; 6], TARGET, [2; 6]);
        frame[78] = 1;
        resign(&mut frame);
        assert!(!conflicts(&frame, TARGET, [1; 6]));
        let mut frame = solicitation([2; 6], TARGET, [2; 6]);
        frame[79] = 0;
        resign(&mut frame);
        assert!(!conflicts(&frame, TARGET, [1; 6]));
    }
    #[test]
    fn advertisement_requires_a_real_source_and_valid_multicast_flags() {
        let mut frame = solicitation([2; 6], TARGET, [2; 6]);
        frame[54] = 136;
        frame[38..54].copy_from_slice(&TARGET.octets());
        resign(&mut frame);
        assert!(!conflicts(&frame, TARGET, [1; 6]));
        frame[22..38].copy_from_slice(&"fe80::3".parse::<Ipv6Addr>().unwrap().octets());
        resign(&mut frame);
        assert!(conflicts(&frame, TARGET, [1; 6]));
        frame[38..54].copy_from_slice(&"ff02::1".parse::<Ipv6Addr>().unwrap().octets());
        frame[58] = 0x40;
        resign(&mut frame);
        assert!(!conflicts(&frame, TARGET, [1; 6]));
        frame[58] = 0;
        resign(&mut frame);
        assert!(conflicts(&frame, TARGET, [1; 6]));
    }
}
