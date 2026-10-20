//! The interface: address configuration by DHCP, ARP, IPv4 routing to the
//! on-link network or the router, UDP for DHCP and DNS, and blocking TCP
//! exchanges. One operation runs at a time; while it waits, the stack
//! answers ARP requests for its address and drops traffic for no waiter.
use super::{
    Clock, Ipv4, Link, Mac, NetError, dhcp, dns, http,
    tcp::{self, Connection, Emit, Incoming},
    wire::{self, Arp, Frame, Ipv4Packet, Segment, Udp},
};
use alloc::{string::String, vec::Vec};

/// An interface's IPv4 configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub address: Ipv4,
    pub mask: Ipv4,
    pub router: Option<Ipv4>,
    pub dns: Vec<Ipv4>,
}

impl Config {
    fn on_link(&self, ip: Ipv4) -> bool {
        let mask = self.mask.to_u32();
        ip.to_u32() & mask == self.address.to_u32() & mask
    }

    fn directed_broadcast(&self) -> Ipv4 {
        Ipv4::from_u32(self.address.to_u32() | !self.mask.to_u32())
    }
}

/// Autonegotiation after an adapter reset: about 3 s for 2.5GBASE-T,
/// doubled.
const CARRIER_WAIT_US: u64 = 6_000_000;
const DHCP_ATTEMPTS: u32 = 4;
const DHCP_FIRST_WAIT_US: u64 = 4_000_000;
const ARP_ATTEMPTS: u32 = 3;
const ARP_WAIT_US: u64 = 1_000_000;
const ARP_CACHE: usize = 16;
const DNS_ATTEMPTS: u32 = 3;
const DNS_WAIT_US: u64 = 2_000_000;
/// From connection to the response's end.
const EXCHANGE_US: u64 = 120_000_000;
const CLOSE_US: u64 = 2_000_000;
const FIRST_EPHEMERAL: u16 = 49152;

/// A received datagram or segment for a waiting operation.
enum Inbound {
    Udp {
        source: Ipv4,
        source_port: u16,
        port: u16,
        payload: Vec<u8>,
    },
    Tcp {
        source: Ipv4,
        source_port: u16,
        port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        window: u16,
        mss: Option<u16>,
        payload: Vec<u8>,
    },
}

pub struct Stack<L: Link, C: Clock> {
    link: L,
    clock: C,
    mac: Mac,
    config: Option<Config>,
    arp: Vec<(Ipv4, Mac)>,
    ip_id: u16,
    seed: u64,
    next_port: u16,
    /// Frames dropped as malformed or for nobody, for diagnostics.
    pub dropped: u64,
}

impl<L: Link, C: Clock> Stack<L, C> {
    pub fn new(link: L, clock: C) -> Self {
        let mac = link.mac();
        let seed = clock.now_us()
            ^ u64::from_be_bytes([
                0, 0, mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
            ])
            ^ 0x9e37_79b9_7f4a_7c15;
        let mut stack = Self {
            link,
            clock,
            mac,
            config: None,
            arp: Vec::new(),
            ip_id: 0,
            seed: seed | 1,
            next_port: 0,
            dropped: 0,
        };
        stack.next_port = FIRST_EPHEMERAL + (stack.random() as u16 & 0x3fff);
        stack.ip_id = stack.random() as u16;
        stack
    }

    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }

    /// Uses `config` instead of asking a DHCP server.
    pub fn set_config(&mut self, config: Config) {
        self.config = Some(config);
        self.arp.clear();
    }

    /// Identifiers that need only be unpredictable to an off-path guesser
    /// across boots: DHCP and DNS transaction IDs, initial sequence numbers
    /// and the first ephemeral port (xorshift64* over the clock and MAC).
    fn random(&mut self) -> u32 {
        self.seed ^= self.clock.now_us();
        self.seed ^= self.seed >> 12;
        self.seed ^= self.seed << 25;
        self.seed ^= self.seed >> 27;
        (self.seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    fn port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = match port {
            u16::MAX => FIRST_EPHEMERAL,
            _ => port + 1,
        };
        port
    }

    fn address(&self) -> Ipv4 {
        self.config
            .as_ref()
            .map_or(Ipv4::UNSPECIFIED, |c| c.address)
    }

    fn learn(&mut self, ip: Ipv4, mac: Mac) {
        if let Some(entry) = self.arp.iter_mut().find(|(known, _)| *known == ip) {
            entry.1 = mac;
            return;
        }
        if self.arp.len() == ARP_CACHE {
            self.arp.remove(0);
        }
        self.arp.push((ip, mac));
    }

    /// One frame from the link, handled: ARP is answered here; a datagram
    /// or segment for this address comes back.
    fn poll(&mut self) -> Result<Option<Inbound>, NetError> {
        let Some(bytes) = self.link.receive()? else {
            return Ok(None);
        };
        let Some(frame) = Frame::parse(&bytes) else {
            self.dropped += 1;
            return Ok(None);
        };
        if frame.destination != self.mac && frame.destination != Mac::BROADCAST {
            self.dropped += 1;
            return Ok(None);
        }
        match frame.ethertype {
            wire::ETHERTYPE_ARP => {
                self.arp_packet(frame)?;
                Ok(None)
            }
            wire::ETHERTYPE_IPV4 => Ok(self.ipv4_packet(frame.payload)),
            _ => {
                self.dropped += 1;
                Ok(None)
            }
        }
    }

    fn arp_packet(&mut self, frame: Frame<'_>) -> Result<(), NetError> {
        let Some(arp) = Arp::parse(frame.payload) else {
            self.dropped += 1;
            return Ok(());
        };
        let ours = self.config.is_some() && arp.target_ip == self.address();
        if arp.reply || ours {
            self.learn(arp.sender_ip, arp.sender_mac);
        }
        if !arp.reply && ours {
            let reply = Arp {
                reply: true,
                sender_mac: self.mac,
                sender_ip: self.address(),
                target_mac: arp.sender_mac,
                target_ip: arp.sender_ip,
            };
            let bytes = wire::frame(arp.sender_mac, self.mac, wire::ETHERTYPE_ARP, &reply.emit());
            self.link.transmit(&bytes)?;
        }
        Ok(())
    }

    fn ipv4_packet(&mut self, bytes: &[u8]) -> Option<Inbound> {
        let Some(packet) = Ipv4Packet::parse(bytes) else {
            self.dropped += 1;
            return None;
        };
        let accepted = match &self.config {
            // Before configuration only DHCP replies arrive, to any address.
            None => true,
            Some(config) => {
                packet.destination == config.address
                    || packet.destination == Ipv4::BROADCAST
                    || packet.destination == config.directed_broadcast()
            }
        };
        if !accepted {
            self.dropped += 1;
            return None;
        }
        let inbound = match packet.protocol {
            wire::PROTOCOL_UDP => Udp::parse(packet.source, packet.destination, packet.payload)
                .map(|udp| Inbound::Udp {
                    source: packet.source,
                    source_port: udp.source_port,
                    port: udp.destination_port,
                    payload: udp.payload.to_vec(),
                }),
            wire::PROTOCOL_TCP => Segment::parse(packet.source, packet.destination, packet.payload)
                .map(|s| Inbound::Tcp {
                    source: packet.source,
                    source_port: s.source_port,
                    port: s.destination_port,
                    sequence: s.sequence,
                    acknowledgment: s.acknowledgment,
                    flags: s.flags,
                    window: s.window,
                    mss: s.mss,
                    payload: s.payload.to_vec(),
                }),
            _ => None,
        };
        if inbound.is_none() {
            self.dropped += 1;
        }
        inbound
    }

    /// The MAC address of `ip`'s next hop.
    fn next_hop(&mut self, ip: Ipv4) -> Result<Mac, NetError> {
        let Some(config) = &self.config else {
            return match ip {
                Ipv4::BROADCAST => Ok(Mac::BROADCAST),
                _ => Err(NetError::Invalid("unicast before address configuration")),
            };
        };
        if ip == Ipv4::BROADCAST || ip == config.directed_broadcast() {
            return Ok(Mac::BROADCAST);
        }
        let hop = if config.on_link(ip) {
            ip
        } else {
            config.router.ok_or(NetError::Unreachable(ip))?
        };
        if let Some(&(_, mac)) = self.arp.iter().find(|(known, _)| *known == hop) {
            return Ok(mac);
        }
        let request = Arp {
            reply: false,
            sender_mac: self.mac,
            sender_ip: config.address,
            target_mac: Mac::default(),
            target_ip: hop,
        };
        let frame = wire::frame(
            Mac::BROADCAST,
            self.mac,
            wire::ETHERTYPE_ARP,
            &request.emit(),
        );
        for _ in 0..ARP_ATTEMPTS {
            self.link.transmit(&frame)?;
            let deadline = self.clock.now_us() + ARP_WAIT_US;
            while self.clock.now_us() < deadline {
                self.poll()?;
                if let Some(&(_, mac)) = self.arp.iter().find(|(known, _)| *known == hop) {
                    return Ok(mac);
                }
            }
        }
        Err(NetError::Unreachable(hop))
    }

    fn send_ipv4(
        &mut self,
        destination: Ipv4,
        protocol: u8,
        payload: &[u8],
    ) -> Result<(), NetError> {
        if wire::IPV4_HEADER + payload.len() > wire::MTU {
            return Err(NetError::Invalid("datagram exceeds the link MTU"));
        }
        let mac = self.next_hop(destination)?;
        self.ip_id = self.ip_id.wrapping_add(1);
        let packet = wire::ipv4(self.address(), destination, protocol, self.ip_id, payload);
        let frame = wire::frame(mac, self.mac, wire::ETHERTYPE_IPV4, &packet);
        self.link.transmit(&frame)
    }

    fn send_udp(
        &mut self,
        destination: Ipv4,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<(), NetError> {
        let datagram = wire::udp(
            self.address(),
            destination,
            source_port,
            destination_port,
            payload,
        );
        self.send_ipv4(destination, wire::PROTOCOL_UDP, &datagram)
    }

    /// Waits until `deadline` for a UDP datagram to `port` that `accept`
    /// takes.
    fn wait_udp<T>(
        &mut self,
        port: u16,
        deadline: u64,
        mut accept: impl FnMut(Ipv4, u16, &[u8]) -> Option<T>,
    ) -> Result<Option<T>, NetError> {
        while self.clock.now_us() < deadline {
            if let Some(Inbound::Udp {
                source,
                source_port,
                port: to,
                payload,
            }) = self.poll()?
                && to == port
                && let Some(value) = accept(source, source_port, &payload)
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    /// Configures the interface from a DHCP server (RFC 2131 3.1).
    pub fn dhcp(&mut self) -> Result<&Config, NetError> {
        let deadline = self.clock.now_us().saturating_add(CARRIER_WAIT_US);
        while !self.link.carrier() {
            if self.clock.now_us() >= deadline {
                return Err(NetError::NoCarrier);
            }
        }
        self.config = None;
        let xid = self.random();
        let started = self.clock.now_us();
        let mut wait = DHCP_FIRST_WAIT_US;
        let mac = self.mac;
        let seconds = |clock: &C| ((clock.now_us() - started) / 1_000_000).min(0xffff) as u16;
        for _ in 0..DHCP_ATTEMPTS {
            let discover = dhcp::request(dhcp::DISCOVER, xid, mac, None, seconds(&self.clock));
            self.send_udp(
                Ipv4::BROADCAST,
                dhcp::CLIENT_PORT,
                dhcp::SERVER_PORT,
                &discover,
            )?;
            let deadline = self.clock.now_us() + wait;
            wait *= 2;
            let offer = self.wait_udp(dhcp::CLIENT_PORT, deadline, |_, from, payload| {
                (from == dhcp::SERVER_PORT)
                    .then(|| dhcp::Reply::parse(payload, mac))
                    .flatten()
                    .filter(|r| r.xid == xid && r.kind == dhcp::OFFER)
            })?;
            let Some(offer) = offer else { continue };
            let server = offer
                .server
                .ok_or(NetError::Dhcp("offer without a server"))?;
            let request = dhcp::request(
                dhcp::REQUEST,
                xid,
                mac,
                Some((offer.address, server)),
                seconds(&self.clock),
            );
            self.send_udp(
                Ipv4::BROADCAST,
                dhcp::CLIENT_PORT,
                dhcp::SERVER_PORT,
                &request,
            )?;
            let deadline = self.clock.now_us() + wait;
            let reply = self.wait_udp(dhcp::CLIENT_PORT, deadline, |_, from, payload| {
                (from == dhcp::SERVER_PORT)
                    .then(|| dhcp::Reply::parse(payload, mac))
                    .flatten()
                    .filter(|r| {
                        r.xid == xid
                            && matches!(r.kind, dhcp::ACK | dhcp::NAK)
                            && r.server.is_none_or(|s| s == server)
                    })
            })?;
            match reply {
                Some(ack) if ack.kind == dhcp::ACK => {
                    if ack.address == Ipv4::UNSPECIFIED {
                        return Err(NetError::Dhcp("acknowledged no address"));
                    }
                    self.arp.clear();
                    self.config = Some(Config {
                        address: ack.address,
                        // RFC 2132 3.3 requires the mask; a missing one is
                        // taken as the whole address (no on-link peers).
                        mask: ack.mask.or(offer.mask).unwrap_or(Ipv4::BROADCAST),
                        router: ack.router.or(offer.router),
                        dns: if ack.dns.is_empty() {
                            offer.dns
                        } else {
                            ack.dns
                        },
                    });
                    return Ok(self.config.as_ref().unwrap());
                }
                Some(_) => return Err(NetError::Dhcp("server refused the request (NAK)")),
                None => continue,
            }
        }
        Err(NetError::Dhcp("no server answered"))
    }

    /// `host`'s address: a dotted-quad literal, or a DNS A lookup through
    /// the configured servers.
    pub fn resolve(&mut self, host: &str) -> Result<Ipv4, NetError> {
        if let Some(ip) = Ipv4::parse(host) {
            return Ok(ip);
        }
        let servers = match &self.config {
            Some(config) if !config.dns.is_empty() => config.dns.clone(),
            Some(_) => return Err(NetError::Dns(String::from("no DNS server configured"))),
            None => return Err(NetError::Invalid("resolve before address configuration")),
        };
        let mut last = NetError::Timeout("DNS");
        for server in servers {
            for _ in 0..DNS_ATTEMPTS {
                let id = self.random() as u16;
                let port = self.port();
                let query = dns::query(id, host)?;
                if let Err(error) = self.send_udp(server, port, dns::PORT, &query) {
                    last = error;
                    break;
                }
                let deadline = self.clock.now_us() + DNS_WAIT_US;
                let reply = self.wait_udp(port, deadline, |from, from_port, payload| {
                    (from == server && from_port == dns::PORT)
                        .then(|| dns::answer(payload, id, host))
                })?;
                match reply {
                    Some(Ok(addresses)) => return Ok(addresses[0]),
                    // An authoritative failure is not retried.
                    Some(Err(error)) => return Err(error),
                    None => last = NetError::Timeout("DNS"),
                }
            }
        }
        Err(last)
    }

    fn send_segment(
        &mut self,
        remote: (Ipv4, u16),
        local: u16,
        emit: &Emit,
    ) -> Result<(), NetError> {
        let segment = wire::tcp(
            self.address(),
            remote.0,
            &wire::Outgoing {
                source_port: local,
                destination_port: remote.1,
                sequence: emit.sequence,
                acknowledgment: emit.acknowledgment,
                flags: emit.flags,
                window: emit.window,
                mss: emit.mss,
                payload: &emit.payload,
            },
        );
        self.send_ipv4(remote.0, wire::PROTOCOL_TCP, &segment)
    }

    /// Opens a connection to `remote`, sends `request`, and collects what
    /// the peer sends until `complete` (given the bytes so far and whether
    /// the peer has closed) says the reply is whole. Then closes.
    pub fn exchange(
        &mut self,
        remote: (Ipv4, u16),
        request: &[u8],
        mut complete: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<Vec<u8>, NetError> {
        if self.config.is_none() {
            return Err(NetError::Invalid("connect before address configuration"));
        }
        // ARP before the SYN, so the connection's timers start on the wire.
        self.next_hop(remote.0)?;
        let local = self.port();
        let iss = self.random();
        let now = self.clock.now_us();
        let (mut connection, syn) = Connection::open(iss, now);
        self.send_segment(remote, local, &syn)?;
        connection.send(request)?;
        let deadline = now + EXCHANGE_US;
        let mut checked = None;
        loop {
            let now = self.clock.now_us();
            if now >= deadline {
                return Err(NetError::Timeout("TCP exchange"));
            }
            let progress = (connection.received.len(), connection.peer_closed);
            if connection.state != tcp::State::SynSent && checked != Some(progress) {
                checked = Some(progress);
                if complete(&connection.received, connection.peer_closed)? {
                    break;
                }
                if connection.peer_closed {
                    return Err(NetError::Http(String::from(
                        "connection closed before the reply was complete",
                    )));
                }
            }
            if connection.state == tcp::State::Closed {
                return Err(NetError::Reset);
            }
            self.step(&mut connection, remote, local)?;
        }
        let received = core::mem::take(&mut connection.received);
        // A graceful close; its failure does not lose the reply.
        connection.close();
        let deadline = self.clock.now_us() + CLOSE_US;
        while !connection.drained()
            && connection.state != tcp::State::Closed
            && self.clock.now_us() < deadline
        {
            if self.step(&mut connection, remote, local).is_err() {
                break;
            }
        }
        Ok(received)
    }

    /// One round of timer work and at most one received segment.
    fn step(
        &mut self,
        connection: &mut Connection,
        remote: (Ipv4, u16),
        local: u16,
    ) -> Result<(), NetError> {
        let now = self.clock.now_us();
        for emit in connection.poll(now)? {
            self.send_segment(remote, local, &emit)?;
        }
        if let Some(Inbound::Tcp {
            source,
            source_port,
            port,
            sequence,
            acknowledgment,
            flags,
            window,
            mss,
            payload,
        }) = self.poll()?
        {
            if (source, source_port, port) != (remote.0, remote.1, local) {
                self.dropped += 1;
                return Ok(());
            }
            let segment = Incoming {
                sequence,
                acknowledgment,
                flags,
                window,
                mss,
                payload: &payload,
            };
            for emit in connection.receive(segment, self.clock.now_us())? {
                self.send_segment(remote, local, &emit)?;
            }
        }
        Ok(())
    }

    /// One HTTP/1.1 POST to `host` on port 80, configuring the interface
    /// by DHCP first if it has no address. Returns the response body.
    pub fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) => (
                name,
                port.parse::<u16>()
                    .map_err(|_| NetError::Invalid("HTTP port"))?,
            ),
            None => (host, 80),
        };
        let request = http::post(host, path, headers, content_type, body)?;
        if self.config.is_none() {
            self.dhcp()?;
        }
        let ip = self.resolve(name)?;
        let reply = self.exchange((ip, port), &request, |bytes, closed| {
            http::response(bytes, closed).map(|r| r.is_some())
        })?;
        // `exchange` returned because the response is complete.
        let closed = true;
        http::response(&reply, closed)?
            .map(|response| response.body)
            .ok_or_else(|| NetError::Http(String::from("incomplete response")))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::net::wire::{ACK, FIN, PSH, RST, SYN};
    use alloc::collections::VecDeque;
    use core::cell::Cell;

    pub(crate) struct TestClock(pub Cell<u64>);
    impl Clock for TestClock {
        /// Each reading advances 100 us, so waits end without real time.
        fn now_us(&self) -> u64 {
            let now = self.0.get() + 100;
            self.0.set(now);
            now
        }
    }

    const CLIENT: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    const ROUTER_MAC: Mac = Mac([0x52, 0x55, 10, 0, 2, 2]);
    const ROUTER: Ipv4 = Ipv4([10, 0, 2, 2]);
    const RESOLVER: Ipv4 = Ipv4([10, 0, 2, 3]);
    const LEASE: Ipv4 = Ipv4([10, 0, 2, 15]);
    const SERVER: Ipv4 = Ipv4([17, 1, 2, 3]);

    /// QEMU user networking in miniature: a DHCP server and router, a
    /// resolver and one HTTP server beyond the router.
    pub(crate) struct Lan {
        rx: VecDeque<Vec<u8>>,
        pub sent: Vec<Vec<u8>>,
        pub drop_syns: usize,
        pub drop_response_segments: usize,
        pub refuse: bool,
        pub dhcp_silent: bool,
        /// Carrier polls that report no link before the link comes up.
        pub carrier_after: usize,
        pub response: Vec<u8>,
        request: Vec<u8>,
        server_next: u32,
        client_next: u32,
        responded: bool,
        response_start: u32,
        /// The highest acknowledgment seen, and the one last answered by a
        /// retransmission.
        acked: u32,
        resent_for: Option<u32>,
        pub received_request: Option<Vec<u8>>,
    }

    impl Lan {
        pub(crate) fn new(response: &[u8]) -> Self {
            Self {
                rx: VecDeque::new(),
                sent: Vec::new(),
                drop_syns: 0,
                drop_response_segments: 0,
                refuse: false,
                dhcp_silent: false,
                carrier_after: 0,
                response: response.to_vec(),
                request: Vec::new(),
                server_next: 7000,
                client_next: 0,
                responded: false,
                response_start: 0,
                acked: 0,
                resent_for: None,
                received_request: None,
            }
        }

        fn deliver_ip(&mut self, source: Ipv4, destination: Ipv4, protocol: u8, payload: &[u8]) {
            let packet = wire::ipv4(source, destination, protocol, 1, payload);
            let to = if destination == Ipv4::BROADCAST {
                Mac::BROADCAST
            } else {
                CLIENT
            };
            self.rx
                .push_back(wire::frame(to, ROUTER_MAC, wire::ETHERTYPE_IPV4, &packet));
        }

        fn tcp_reply(&mut self, port: u16, flags: u8, payload: &[u8], mss: Option<u16>) {
            let segment = wire::tcp(
                SERVER,
                LEASE,
                &wire::Outgoing {
                    source_port: 80,
                    destination_port: port,
                    sequence: self.server_next,
                    acknowledgment: self.client_next,
                    flags,
                    window: 8192,
                    mss,
                    payload,
                },
            );
            self.deliver_ip(SERVER, LEASE, wire::PROTOCOL_TCP, &segment);
        }

        fn handle(&mut self, frame: &[u8]) {
            let frame = Frame::parse(frame).unwrap();
            assert_eq!(frame.source, CLIENT);
            if frame.ethertype == wire::ETHERTYPE_ARP {
                let arp = Arp::parse(frame.payload).unwrap();
                if !arp.reply && (arp.target_ip == ROUTER || arp.target_ip == RESOLVER) {
                    let reply = Arp {
                        reply: true,
                        sender_mac: ROUTER_MAC,
                        sender_ip: arp.target_ip,
                        target_mac: CLIENT,
                        target_ip: arp.sender_ip,
                    };
                    self.rx.push_back(wire::frame(
                        CLIENT,
                        ROUTER_MAC,
                        wire::ETHERTYPE_ARP,
                        &reply.emit(),
                    ));
                }
                return;
            }
            let ip = Ipv4Packet::parse(frame.payload).expect("client sends valid IPv4");
            match ip.protocol {
                wire::PROTOCOL_UDP => self.udp(ip),
                wire::PROTOCOL_TCP => {
                    assert_eq!(frame.destination, ROUTER_MAC, "off-link goes to the router");
                    self.tcp(ip)
                }
                other => panic!("unexpected protocol {other}"),
            }
        }

        fn udp(&mut self, ip: Ipv4Packet<'_>) {
            let udp = Udp::parse(ip.source, ip.destination, ip.payload).unwrap();
            if udp.destination_port == dhcp::SERVER_PORT {
                if self.dhcp_silent {
                    return;
                }
                let kind = udp.payload[FIXED_KIND];
                let xid = u32::from_be_bytes(udp.payload[4..8].try_into().unwrap());
                let reply_kind = match kind {
                    dhcp::DISCOVER => dhcp::OFFER,
                    dhcp::REQUEST => dhcp::ACK,
                    _ => return,
                };
                let lease = dhcp::Reply {
                    kind: reply_kind,
                    xid,
                    address: LEASE,
                    server: Some(ROUTER),
                    mask: Some(Ipv4([255, 255, 255, 0])),
                    router: Some(ROUTER),
                    dns: alloc::vec![RESOLVER],
                    lease_seconds: Some(86400),
                };
                let message = dhcp::reply(reply_kind, xid, CLIENT, &lease);
                let datagram = wire::udp(ROUTER, Ipv4::BROADCAST, 67, 68, &message);
                self.deliver_ip(ROUTER, Ipv4::BROADCAST, wire::PROTOCOL_UDP, &datagram);
            } else if udp.destination_port == dns::PORT {
                assert_eq!(ip.destination, RESOLVER);
                let id = u16::from_be_bytes([udp.payload[0], udp.payload[1]]);
                let message = dns::response(
                    id,
                    "gs.apple.com",
                    &[
                        ("gs.apple.com", Err("gs.cdn.test")),
                        ("gs.cdn.test", Ok(SERVER)),
                    ],
                );
                let datagram = wire::udp(RESOLVER, LEASE, 53, udp.source_port, &message);
                self.deliver_ip(RESOLVER, LEASE, wire::PROTOCOL_UDP, &datagram);
            }
        }

        fn tcp(&mut self, ip: Ipv4Packet<'_>) {
            assert_eq!(ip.destination, SERVER);
            let s = Segment::parse(ip.source, ip.destination, ip.payload).unwrap();
            assert_eq!(s.destination_port, 80);
            if s.flags & SYN != 0 {
                if self.drop_syns > 0 {
                    self.drop_syns -= 1;
                    return;
                }
                self.client_next = s.sequence.wrapping_add(1);
                if self.refuse {
                    self.tcp_reply(s.source_port, RST | ACK, &[], None);
                    return;
                }
                self.tcp_reply(s.source_port, SYN | ACK, &[], Some(1460));
                self.server_next += 1;
                return;
            }
            if s.sequence == self.client_next && !s.payload.is_empty() {
                self.request.extend_from_slice(s.payload);
                self.client_next = self.client_next.wrapping_add(s.payload.len() as u32);
            }
            if s.flags & FIN != 0 && s.sequence == self.client_next {
                self.client_next = self.client_next.wrapping_add(1);
                self.tcp_reply(s.source_port, ACK, &[], None);
                return;
            }
            let complete = self
                .request
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .is_some_and(|end| {
                    let head = core::str::from_utf8(&self.request[..end]).unwrap();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    self.request.len() >= end + 4 + length
                });
            if !complete {
                self.tcp_reply(s.source_port, ACK, &[], None);
                return;
            }
            if self.responded {
                // A duplicate acknowledgment asks once for the lost part,
                // go-back-N from it.
                let ack = s.acknowledgment;
                if before_server(self.acked, ack) {
                    self.acked = ack;
                } else if ack == self.acked
                    && before_server(ack, self.server_next)
                    && self.resent_for != Some(ack)
                {
                    self.resent_for = Some(ack);
                    self.server_next = ack;
                    self.respond_from(s.source_port);
                }
                return;
            }
            self.received_request = Some(self.request.clone());
            self.responded = true;
            self.response_start = self.server_next;
            self.acked = self.server_next;
            self.respond_from(s.source_port);
        }

        fn respond_from(&mut self, port: u16) {
            let offset = self.server_next.wrapping_sub(self.response_start) as usize;
            let response = self.response.clone();
            for chunk in response[offset.min(response.len())..].chunks(100) {
                if self.drop_response_segments > 0 {
                    self.drop_response_segments -= 1;
                    self.server_next = self.server_next.wrapping_add(chunk.len() as u32);
                    continue;
                }
                self.tcp_reply(port, ACK | PSH, chunk, None);
                self.server_next = self.server_next.wrapping_add(chunk.len() as u32);
            }
            self.tcp_reply(port, FIN | ACK, &[], None);
            self.server_next = self.server_next.wrapping_add(1);
        }
    }

    fn before_server(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) < 0
    }

    /// The DHCP message-type value's offset: the fixed fields, the cookie
    /// and option 53's code and length.
    const FIXED_KIND: usize = 236 + 4 + 2;

    impl Link for Lan {
        fn mac(&self) -> Mac {
            CLIENT
        }
        fn carrier(&mut self) -> bool {
            self.carrier_after = self.carrier_after.saturating_sub(1);
            self.carrier_after == 0
        }
        fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
            assert!(frame.len() >= wire::MIN_FRAME && frame.len() <= wire::MAX_FRAME);
            self.sent.push(frame.to_vec());
            self.handle(frame);
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
            Ok(self.rx.pop_front())
        }
    }

    fn stack(lan: Lan) -> Stack<Lan, TestClock> {
        Stack::new(lan, TestClock(Cell::new(0)))
    }

    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n";

    fn ticket_response() -> Vec<u8> {
        let body = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".repeat(10);
        let mut response = RESPONSE.to_vec();
        response.extend_from_slice(&body);
        response
    }

    #[test]
    fn dhcp_configures_and_dns_follows_aliases() {
        let mut s = stack(Lan::new(b""));
        let config = s.dhcp().unwrap().clone();
        assert_eq!(config.address, LEASE);
        assert_eq!(config.router, Some(ROUTER));
        assert_eq!(config.dns, [RESOLVER]);
        assert_eq!(s.resolve("gs.apple.com").unwrap(), SERVER);
        assert_eq!(s.resolve("1.2.3.4").unwrap(), Ipv4([1, 2, 3, 4]));
    }

    #[test]
    fn dhcp_waits_a_bounded_time_for_carrier() {
        let mut lan = Lan::new(b"");
        lan.carrier_after = 1000;
        assert_eq!(stack(lan).dhcp().unwrap().address, LEASE);
        let mut lan = Lan::new(b"");
        lan.carrier_after = usize::MAX;
        let mut s = stack(lan);
        assert_eq!(s.dhcp().unwrap_err(), NetError::NoCarrier);
        assert!(s.link.sent.is_empty());
    }

    #[test]
    fn a_post_returns_the_body_through_loss_and_reordering() {
        let mut lan = Lan::new(&ticket_response());
        lan.drop_syns = 1;
        lan.drop_response_segments = 1;
        let mut s = stack(lan);
        let body = s
            .post(
                "gs.apple.com",
                "/TSS/controller?action=2",
                &[],
                "text/xml",
                &[b'x'; 3000],
            )
            .unwrap();
        assert_eq!(body, b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".repeat(10));
        let request = s.link_mut().received_request.clone().unwrap();
        let text = core::str::from_utf8(&request[..request.len() - 3000]).unwrap();
        assert!(
            text.starts_with("POST /TSS/controller?action=2 HTTP/1.1\r\nHost: gs.apple.com\r\n")
        );
        assert!(request.ends_with(&[b'x'; 3000]));
        // The client closed gracefully after the response.
        let fins = s
            .link_mut()
            .sent
            .iter()
            .filter_map(|f| {
                let frame = Frame::parse(f)?;
                let ip = Ipv4Packet::parse(frame.payload)?;
                let seg = Segment::parse(ip.source, ip.destination, ip.payload)?;
                (seg.flags & FIN != 0).then_some(())
            })
            .count();
        assert_eq!(fins, 1);
    }

    #[test]
    fn refusals_and_silence_are_explicit_errors() {
        let mut lan = Lan::new(&ticket_response());
        lan.refuse = true;
        let mut s = stack(lan);
        assert_eq!(
            s.post("gs.apple.com", "/", &[], "text/xml", b""),
            Err(NetError::Refused)
        );
        let lan = Lan::new(b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n");
        let mut s = stack(lan);
        assert_eq!(
            s.post("gs.apple.com", "/", &[], "text/xml", b""),
            Err(NetError::Status(500))
        );
        let mut lan = Lan::new(b"");
        lan.dhcp_silent = true;
        let mut s = stack(lan);
        assert_eq!(s.dhcp(), Err(NetError::Dhcp("no server answered")));
        let mut lan = Lan::new(b"");
        lan.drop_syns = usize::MAX;
        let mut s = stack(lan);
        s.dhcp().unwrap();
        assert_eq!(
            s.post("17.1.2.3", "/", &[], "text/xml", b""),
            Err(NetError::Timeout("TCP connection"))
        );
    }

    #[test]
    fn arp_requests_for_the_lease_are_answered() {
        let mut s = stack(Lan::new(b""));
        s.dhcp().unwrap();
        let who_has = Arp {
            reply: false,
            sender_mac: ROUTER_MAC,
            sender_ip: ROUTER,
            target_mac: Mac::default(),
            target_ip: LEASE,
        };
        s.link.rx.push_back(wire::frame(
            Mac::BROADCAST,
            ROUTER_MAC,
            wire::ETHERTYPE_ARP,
            &who_has.emit(),
        ));
        s.poll().unwrap();
        let reply = Arp::parse(Frame::parse(s.link.sent.last().unwrap()).unwrap().payload).unwrap();
        assert!(reply.reply);
        assert_eq!((reply.sender_ip, reply.sender_mac), (LEASE, CLIENT));
        assert_eq!(reply.target_mac, ROUTER_MAC);
    }
}
