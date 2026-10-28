//! Router-advertised DNS lifetimes (RFC 8106 sections 5.1 and 6.1).
use alloc::vec::Vec;
use core::net::Ipv6Addr;

const MAX_RECORDS: usize = 8;
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
struct Server {
    router: Ipv6Addr,
    address: Ipv6Addr,
    until: u64,
}
#[derive(Default)]
pub(super) struct Rdnss {
    servers: Vec<Server>,
}
impl Rdnss {
    /// Consume only complete, checksummed link-local RAs addressed to this
    /// interface or all nodes. A malformed option leaves the repository intact.
    pub(super) fn observe(&mut self, frame: &[u8], local: Ipv6Addr, now: u64) {
        let Some((router, updates)) = parse(frame, local) else {
            return;
        };
        self.servers.retain(|server| server.until > now);
        for (address, lifetime) in updates {
            let existing = self
                .servers
                .iter()
                .position(|server| server.router == router && server.address == address);
            if lifetime == 0 {
                if let Some(index) = existing {
                    self.servers.remove(index);
                }
                continue;
            }
            let until = if lifetime == u32::MAX {
                u64::MAX
            } else {
                now.saturating_add(u64::from(lifetime) * 1_000_000)
            };
            if let Some(index) = existing {
                self.servers[index].until = until;
            } else if self.servers.len() < MAX_RECORDS {
                self.servers.push(Server {
                    router,
                    address,
                    until,
                });
            }
        }
    }
    pub(super) fn servers(&mut self, now: u64) -> Vec<Ipv6Addr> {
        self.servers.retain(|server| server.until > now);
        let mut result = Vec::new();
        for server in &self.servers {
            if !result.contains(&server.address) {
                result.push(server.address);
            }
        }
        result
    }
}

fn address(bytes: &[u8]) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))
}
fn parse(frame: &[u8], local: Ipv6Addr) -> Option<(Ipv6Addr, Vec<(Ipv6Addr, u32)>)> {
    if frame.len() < 70 || frame[12..14] != [0x86, 0xdd] {
        return None;
    }
    let ipv6 = &frame[14..];
    if ipv6[0] >> 4 != 6 || ipv6[6] != 58 || ipv6[7] != 255 {
        return None;
    }
    let source = address(&ipv6[8..24])?;
    let destination = address(&ipv6[24..40])?;
    if !source.is_unicast_link_local() || (destination != local && destination != ALL_NODES) {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    let icmp = ipv6.get(40..40usize.checked_add(length)?)?;
    if icmp.len() < 16 || icmp[0] != 134 || icmp[1] != 0 || checksum(source, destination, icmp) != 0
    {
        return None;
    }
    let mut updates = Vec::new();
    let mut options = &icmp[16..];
    while !options.is_empty() {
        let length = usize::from(*options.get(1)?) * 8;
        if length == 0 {
            return None;
        }
        let option = options.get(..length)?;
        if option[0] == 25 {
            if length < 24 || (length - 8) % 16 != 0 {
                return None;
            }
            let lifetime = u32::from_be_bytes(option[4..8].try_into().ok()?);
            for bytes in option[8..].as_chunks::<16>().0 {
                let server = address(bytes)?;
                if server.is_unspecified()
                    || server.is_multicast()
                    || server.to_ipv4_mapped().is_some()
                {
                    return None;
                }
                updates.push((server, lifetime));
            }
        }
        options = &options[length..];
    }
    Some((source, updates))
}

pub(super) fn checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum = 0u64;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            sum += u64::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    };
    add(&source.octets());
    add(&destination.octets());
    add(&(icmp.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 58]);
    add(icmp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    const LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const DNS: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53);
    fn advertisement(source: Ipv6Addr, lifetime: u32, dns: Ipv6Addr) -> Vec<u8> {
        let mut frame = vec![0; 14 + 40 + 40];
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&40u16.to_be_bytes());
        ip[6] = 58;
        ip[7] = 255;
        ip[8..24].copy_from_slice(&source.octets());
        ip[24..40].copy_from_slice(&ALL_NODES.octets());
        let icmp = &mut ip[40..];
        icmp[0] = 134;
        icmp[16] = 25;
        icmp[17] = 3;
        icmp[20..24].copy_from_slice(&lifetime.to_be_bytes());
        icmp[24..40].copy_from_slice(&dns.octets());
        seal(&mut frame);
        frame
    }
    fn seal(frame: &mut [u8]) {
        let source = address(&frame[22..38]).unwrap();
        let dest = address(&frame[38..54]).unwrap();
        frame[56..58].fill(0);
        let sum = checksum(source, dest, &frame[54..]);
        frame[56..58].copy_from_slice(&sum.to_be_bytes());
    }
    #[test]
    fn lifetimes_refresh_expire_and_withdraw_per_router() {
        let mut dns = Rdnss::default();
        dns.observe(&advertisement(ROUTER, 10, DNS), LOCAL, 0);
        dns.observe(&advertisement(LOCAL, 20, DNS), LOCAL, 0);
        assert_eq!(dns.servers(9_000_000), [DNS]);
        dns.observe(&advertisement(ROUTER, 0, DNS), LOCAL, 9_000_000);
        assert_eq!(dns.servers(19_000_000), [DNS]);
        assert!(dns.servers(20_000_000).is_empty());
        dns.observe(&advertisement(ROUTER, u32::MAX, DNS), LOCAL, 0);
        assert_eq!(dns.servers(u64::MAX - 1), [DNS]);
    }
    #[test]
    fn rejects_bad_sources_checksum_hop_limit_and_truncated_options() {
        let valid = advertisement(ROUTER, 10, DNS);
        for field in [14usize, 20, 21, 22, 38, 54, 55, 56, 71] {
            let mut frame = valid.clone();
            frame[field] ^= 0x80;
            let mut dns = Rdnss::default();
            dns.observe(&frame, LOCAL, 0);
            assert!(dns.servers(0).is_empty(), "field={field}");
        }
        for width in 0..valid.len() {
            let mut dns = Rdnss::default();
            dns.observe(&valid[..width], LOCAL, 0);
            assert!(dns.servers(0).is_empty(), "width={width}");
        }
    }
    #[test]
    fn invalid_tail_does_not_publish_an_earlier_option() {
        let mut frame = advertisement(ROUTER, 10, DNS);
        frame.extend_from_slice(&[25, 0, 0, 0, 0, 0, 0, 0]);
        frame[18..20].copy_from_slice(&48u16.to_be_bytes());
        seal(&mut frame);
        let mut dns = Rdnss::default();
        dns.observe(&frame, LOCAL, 0);
        assert!(dns.servers(0).is_empty());
    }
}
