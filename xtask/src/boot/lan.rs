//! The LAN behind `boot run --network`: a user-space peer for QEMU's NIC
//! that gives the guest real internet reach without QEMU's slirp backend.
//!
//! QEMU connects its `stream` netdev to a TCP listener this process owns
//! and exchanges Ethernet frames with it, each after a 4-byte big-endian
//! length. The peer plays the gateway 10.0.2.2: it answers ARP for that
//! address, leases 10.0.2.15 by DHCP (RFC 2131/2132) with 10.0.2.2 as the
//! router and DNS server, answers DNS A queries (RFC 1035) from the host's
//! resolver, and terminates every TCP connection the guest opens to any
//! address (RFC 9293), relaying its bytes over a host TCP connection to the
//! same address and port: connect, data both ways, FIN and RST. Anything
//! else (other protocols, other UDP ports, IP options it cannot route) is
//! dropped and logged. Each lease, query and connection is logged to the
//! run directory. Dev-only: one guest, IPv4, no fragments. The guest's
//! window scale (RFC 7323) is honored; the peer's own window is unscaled.
mod wire;

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender, channel},
    },
    thread,
    time::{Duration, Instant},
};
use stela_drivers::net::Mac;
use wire::{ACK, Arp, FIN, Frame, Ipv4Packet, Outgoing, PSH, RST, SYN, Segment, Udp};

type Ipv4 = Ipv4Addr;
pub const GATEWAY: Ipv4 = Ipv4::new(10, 0, 2, 2);
pub const GUEST: Ipv4 = Ipv4::new(10, 0, 2, 15);
const MASK: Ipv4 = Ipv4::new(255, 255, 255, 0);
const GATEWAY_MAC: Mac = Mac([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
const LEASE_SECONDS: u32 = 24 * 60 * 60;
const DNS_TTL: u32 = 60;
const WINDOW: u16 = 65535;
const MSS: usize = 1460;
const RETRANSMIT: Duration = Duration::from_secs(1);
const IDLE: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TICK: Duration = Duration::from_millis(50);
/// Host bytes a connection queues for the guest before its host read
/// waits, so an open-ended download streams at the guest's pace instead
/// of piling up here.
const HOST_BUFFER: usize = 4 << 20;

const DHCP_SERVER: u16 = 67;
const DHCP_CLIENT: u16 = 68;
const DNS: u16 = 53;
const DHCP_FIXED: usize = 236;
const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Connections by the guest's port and the remote address and port.
type Key = (u16, [u8; 4], u16);

/// What the peer reacts to: a frame from the guest, or host-side work its
/// threads finished.
pub enum Event {
    Frame(Vec<u8>),
    Connected(Key, io::Result<TcpStream>),
    Data(Key, Vec<u8>),
    /// The host side's end of stream (`Ok`) or failure.
    Closed(Key, io::Result<()>),
    /// A DNS reply to send from the gateway to `port` on the guest.
    Resolved {
        port: u16,
        reply: Vec<u8>,
    },
    /// QEMU closed the link.
    Quit,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Waiting for the host connection; the guest's SYN is not answered.
    Connecting,
    /// SYN-ACK sent, waiting for the guest's ACK of it.
    Accepted,
    Established,
}

struct Connection {
    state: State,
    writer: Option<TcpStream>,
    iss: u32,
    /// Next sequence number the guest sends.
    receive_next: u32,
    send_unacknowledged: u32,
    send_next: u32,
    window: u32,
    /// The guest's window scale shift, when its SYN offered scaling.
    scale: Option<u8>,
    mss: usize,
    /// Host bytes sent and not yet acknowledged, from `send_unacknowledged`.
    flight: Vec<u8>,
    /// Host bytes not yet sent.
    unsent: VecDeque<u8>,
    /// Host bytes read and not yet sent, shared with the host reader,
    /// which waits while it reaches [`HOST_BUFFER`].
    queued: Arc<AtomicUsize>,
    host_closed: bool,
    fin_sent: bool,
    fin_acknowledged: bool,
    guest_closed: bool,
    last_sent: Instant,
    last_activity: Instant,
    to_guest: u64,
    to_host: u64,
}

fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Resolves a name to its IPv4 addresses.
pub type Resolver = fn(&str) -> io::Result<Vec<Ipv4>>;

pub fn host_resolver(name: &str) -> io::Result<Vec<Ipv4>> {
    Ok((name, 0)
        .to_socket_addrs()?
        .filter_map(|address| match address {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .collect())
}

pub struct Lan {
    events: Sender<Event>,
    log: Box<dyn Write + Send>,
    resolver: Resolver,
    guest_mac: Option<Mac>,
    connections: HashMap<Key, Connection>,
    iss: u32,
    out: Vec<Vec<u8>>,
}

impl Lan {
    pub fn new(events: Sender<Event>, log: Box<dyn Write + Send>, resolver: Resolver) -> Self {
        let iss = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos())
            ^ 0x5a17_c3e1;
        Self {
            events,
            log,
            resolver,
            guest_mac: None,
            connections: HashMap::new(),
            iss,
            out: Vec::new(),
        }
    }

    fn note(&mut self, line: std::fmt::Arguments<'_>) {
        // The log is diagnostics; losing a line does not stop the LAN.
        let _ = writeln!(self.log, "{line}");
        let _ = self.log.flush();
    }

    /// Frames for the guest, in order.
    pub fn take_frames(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    pub fn handle(&mut self, event: Event) {
        match event {
            Event::Frame(bytes) => self.frame(&bytes),
            Event::Connected(key, result) => self.connected(key, result),
            Event::Data(key, bytes) => {
                if let Some(c) = self.connections.get_mut(&key) {
                    c.unsent.extend(bytes);
                    c.last_activity = Instant::now();
                    self.push(key);
                }
            }
            Event::Closed(key, result) => {
                let Some(c) = self.connections.get_mut(&key) else {
                    return;
                };
                match result {
                    Ok(()) => {
                        c.host_closed = true;
                        self.push(key);
                    }
                    Err(error) => {
                        self.note(format_args!("TCP {} host error: {error}", show(key)));
                        self.reset(key);
                    }
                }
            }
            Event::Resolved { port, reply } => self.udp(GATEWAY, GUEST, DNS, port, &reply),
            Event::Quit => {}
        }
    }

    /// Retransmissions and idle connections.
    pub fn tick(&mut self, now: Instant) {
        let keys: Vec<Key> = self.connections.keys().copied().collect();
        for key in keys {
            let Some(c) = self.connections.get(&key) else {
                continue;
            };
            if now.duration_since(c.last_activity) > IDLE {
                self.note(format_args!("TCP {} idle", show(key)));
                self.reset(key);
                continue;
            }
            let waiting = c.state == State::Accepted
                || !c.flight.is_empty()
                || (c.fin_sent && !c.fin_acknowledged)
                || (c.window == 0 && !c.unsent.is_empty());
            if waiting && now.duration_since(c.last_sent) >= RETRANSMIT {
                self.retransmit(key);
            }
        }
    }

    fn frame(&mut self, bytes: &[u8]) {
        let Some(frame) = Frame::parse(bytes) else {
            return;
        };
        if !frame.source.is_multicast() {
            self.guest_mac = Some(frame.source);
        }
        match frame.ethertype {
            wire::ETHERTYPE_ARP => {
                if let Some(arp) = Arp::parse(frame.payload)
                    && !arp.reply
                    && arp.target_ip == GATEWAY
                {
                    let reply = Arp {
                        reply: true,
                        sender_mac: GATEWAY_MAC,
                        sender_ip: GATEWAY,
                        target_mac: arp.sender_mac,
                        target_ip: arp.sender_ip,
                    };
                    let reply = wire::frame(
                        arp.sender_mac,
                        GATEWAY_MAC,
                        wire::ETHERTYPE_ARP,
                        &reply.emit(),
                    );
                    self.out.push(reply);
                }
            }
            wire::ETHERTYPE_IPV4 => {
                let Some(packet) = Ipv4Packet::parse(frame.payload) else {
                    return;
                };
                match packet.protocol {
                    wire::PROTOCOL_UDP => {
                        if let Some(udp) =
                            Udp::parse(packet.source, packet.destination, packet.payload)
                        {
                            match udp.destination_port {
                                DHCP_SERVER => self.dhcp(udp.payload),
                                DNS if packet.destination == GATEWAY => {
                                    self.dns(udp.source_port, udp.payload)
                                }
                                port => self.note(format_args!(
                                    "UDP to {}:{port} dropped",
                                    packet.destination
                                )),
                            }
                        }
                    }
                    wire::PROTOCOL_TCP => {
                        if let Some(segment) =
                            Segment::parse(packet.source, packet.destination, packet.payload)
                        {
                            self.segment(packet.source, packet.destination, &segment);
                        }
                    }
                    protocol => self.note(format_args!(
                        "IP protocol {protocol} to {} dropped",
                        packet.destination
                    )),
                }
            }
            _ => {}
        }
    }

    fn ip(&mut self, source: Ipv4, destination: Ipv4, protocol: u8, payload: &[u8]) {
        let packet = wire::ipv4(source, destination, protocol, payload);
        let mac = match destination {
            Ipv4::BROADCAST => Mac::BROADCAST,
            _ => self.guest_mac.unwrap_or(Mac::BROADCAST),
        };
        self.out
            .push(wire::frame(mac, GATEWAY_MAC, wire::ETHERTYPE_IPV4, &packet));
    }

    fn udp(&mut self, source: Ipv4, destination: Ipv4, from: u16, to: u16, payload: &[u8]) {
        let datagram = wire::udp(source, destination, from, to, payload);
        self.ip(source, destination, wire::PROTOCOL_UDP, &datagram);
    }

    fn dhcp(&mut self, request: &[u8]) {
        if request.len() < DHCP_FIXED + 4
            || request[0] != 1
            || request[1] != 1
            || request[2] != 6
            || request[DHCP_FIXED..DHCP_FIXED + 4] != DHCP_COOKIE
        {
            return;
        }
        let mut kind = None;
        let mut requested = None;
        let mut options = &request[DHCP_FIXED + 4..];
        while let Some((&code, rest)) = options.split_first() {
            match code {
                0 => {
                    options = rest;
                    continue;
                }
                255 => break,
                _ => {}
            }
            let Some((&length, rest)) = rest.split_first() else {
                return;
            };
            let length = usize::from(length);
            if rest.len() < length {
                return;
            }
            let (value, rest) = rest.split_at(length);
            match (code, length) {
                (53, 1) => kind = Some(value[0]),
                (50, 4) => requested = Some(Ipv4::from(<[u8; 4]>::try_from(value).unwrap())),
                _ => {}
            }
            options = rest;
        }
        let client = Ipv4::from(<[u8; 4]>::try_from(&request[12..16]).unwrap());
        let mac = Mac(request[28..34].try_into().unwrap());
        let reply = match kind {
            Some(1) => 2,                                         // DISCOVER: OFFER
            Some(3) if requested.unwrap_or(client) == GUEST => 5, // REQUEST: ACK
            Some(3) => 6,                                         // NAK
            _ => return,
        };
        let mut bytes = vec![0u8; DHCP_FIXED];
        bytes[..4].copy_from_slice(&[2, 1, 6, 0]);
        bytes[4..8].copy_from_slice(&request[4..8]);
        bytes[10..12].copy_from_slice(&request[10..12]);
        if reply != 6 {
            bytes[16..20].copy_from_slice(&GUEST.octets());
            bytes[20..24].copy_from_slice(&GATEWAY.octets());
        }
        bytes[28..44].copy_from_slice(&request[28..44]);
        bytes.extend_from_slice(&DHCP_COOKIE);
        bytes.extend_from_slice(&[53, 1, reply, 54, 4]);
        bytes.extend_from_slice(&GATEWAY.octets());
        if reply != 6 {
            bytes.extend_from_slice(&[51, 4]);
            bytes.extend_from_slice(&LEASE_SECONDS.to_be_bytes());
            for code in [1u8, 3, 6] {
                bytes.extend_from_slice(&[code, 4]);
                let value = if code == 1 { MASK } else { GATEWAY };
                bytes.extend_from_slice(&value.octets());
            }
        }
        bytes.push(255);
        let name = match reply {
            2 => "OFFER",
            5 => "ACK",
            _ => "NAK",
        };
        self.note(format_args!("DHCP {name} {GUEST} to {mac}"));
        self.udp(GATEWAY, Ipv4::BROADCAST, DHCP_SERVER, DHCP_CLIENT, &bytes);
    }

    fn dns(&mut self, port: u16, query: &[u8]) {
        // One standard query, one question, no compression in it.
        if query.len() < 12 || query[2] & 0xf8 != 0 || query[4..6] != [0, 1] {
            return;
        }
        let mut at = 12;
        let mut labels = Vec::new();
        loop {
            let Some(&length) = query.get(at) else {
                return;
            };
            at += 1;
            if length == 0 {
                break;
            }
            if length & 0xc0 != 0 || at + usize::from(length) > query.len() {
                return;
            }
            labels.push(String::from_utf8_lossy(&query[at..at + usize::from(length)]).into_owned());
            at += usize::from(length);
        }
        let Some(fixed) = query.get(at..at + 4) else {
            return;
        };
        let (kind, class) = (
            u16::from_be_bytes([fixed[0], fixed[1]]),
            u16::from_be_bytes([fixed[2], fixed[3]]),
        );
        let question = query[12..at + 4].to_vec();
        let header = [query[0], query[1], 0x80 | (query[2] & 0x01), 0x80];
        let name = labels.join(".");
        let events = self.events.clone();
        let resolver = self.resolver;
        self.note(format_args!("DNS query {name} type {kind}"));
        // The host resolver blocks; its reply comes back as an event.
        thread::spawn(move || {
            let (code, answers) = if kind == 1 && class == 1 {
                match resolver(&name) {
                    Ok(answers) => (0, answers),
                    Err(_) => (3, Vec::new()),
                }
            } else {
                // Other types: an empty answer, so the client moves on.
                (0, Vec::new())
            };
            let mut reply = header.to_vec();
            reply[3] |= code;
            reply.extend_from_slice(&[0, 1]);
            reply.extend_from_slice(&(answers.len() as u16).to_be_bytes());
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&question);
            for address in &answers {
                reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
                reply.extend_from_slice(&DNS_TTL.to_be_bytes());
                reply.extend_from_slice(&[0, 4]);
                reply.extend_from_slice(&address.octets());
            }
            let _ = events.send(Event::Resolved { port, reply });
        });
    }

    fn send(&mut self, key: Key, sequence: u32, flags: u8, payload: &[u8], mss: bool) {
        let (port, remote, remote_port) = key;
        let connection = self.connections.get(&key);
        let acknowledgment = connection.map_or(0, |c| c.receive_next);
        // A SYN-ACK answers the guest's scaling offer with shift 0.
        let scale = connection.and_then(|c| c.scale).and(mss.then_some(0));
        let remote = Ipv4::from(remote);
        let segment = wire::tcp(
            remote,
            GUEST,
            &Outgoing {
                source_port: remote_port,
                destination_port: port,
                sequence,
                acknowledgment,
                flags,
                window: WINDOW,
                mss: mss.then_some(MSS as u16),
                scale,
                payload,
            },
        );
        self.ip(remote, GUEST, wire::PROTOCOL_TCP, &segment);
        if let Some(c) = self.connections.get_mut(&key) {
            c.last_sent = Instant::now();
        }
    }

    /// A reset for a segment that belongs to no connection (RFC 9293 3.10.7.1).
    fn refuse(&mut self, source: Ipv4, destination: Ipv4, segment: &Segment<'_>) {
        if segment.flags & RST != 0 {
            return;
        }
        let length = segment.payload.len() as u32
            + u32::from(segment.flags & SYN != 0)
            + u32::from(segment.flags & FIN != 0);
        let (sequence, acknowledgment, flags) = if segment.flags & ACK != 0 {
            (segment.acknowledgment, 0, RST)
        } else {
            (0, segment.sequence.wrapping_add(length), RST | ACK)
        };
        let reply = wire::tcp(
            destination,
            source,
            &Outgoing {
                source_port: segment.destination_port,
                destination_port: segment.source_port,
                sequence,
                acknowledgment,
                flags,
                window: 0,
                mss: None,
                scale: None,
                payload: &[],
            },
        );
        self.ip(destination, source, wire::PROTOCOL_TCP, &reply);
    }

    fn reset(&mut self, key: Key) {
        if let Some(c) = self.connections.get(&key) {
            let sequence = c.send_next;
            self.send(key, sequence, RST | ACK, &[], false);
        }
        self.drop_connection(key, "reset");
    }

    fn drop_connection(&mut self, key: Key, why: &str) {
        if let Some(c) = self.connections.remove(&key) {
            if let Some(writer) = c.writer {
                let _ = writer.shutdown(Shutdown::Both);
            }
            self.note(format_args!(
                "TCP {} {why}: to_guest={} to_host={}",
                show(key),
                c.to_guest,
                c.to_host
            ));
        }
    }

    fn segment(&mut self, source: Ipv4, destination: Ipv4, segment: &Segment<'_>) {
        if source != GUEST {
            return;
        }
        let key = (
            segment.source_port,
            destination.octets(),
            segment.destination_port,
        );
        let now = Instant::now();
        let Some(c) = self.connections.get_mut(&key) else {
            if segment.flags & (SYN | ACK | RST) != SYN {
                return self.refuse(source, destination, segment);
            }
            self.iss = self.iss.wrapping_add(64_000);
            let connection_queued = Arc::new(AtomicUsize::new(0));
            let connection = Connection {
                state: State::Connecting,
                writer: None,
                iss: self.iss,
                receive_next: segment.sequence.wrapping_add(1),
                send_unacknowledged: self.iss,
                send_next: self.iss.wrapping_add(1),
                window: u32::from(segment.window),
                scale: segment.scale,
                mss: segment.mss.map_or(536, usize::from).min(MSS),
                flight: Vec::new(),
                unsent: VecDeque::new(),
                queued: Arc::clone(&connection_queued),
                host_closed: false,
                fin_sent: false,
                fin_acknowledged: false,
                guest_closed: false,
                last_sent: now,
                last_activity: now,
                to_guest: 0,
                to_host: 0,
            };
            self.connections.insert(key, connection);
            self.note(format_args!("TCP {} connecting", show(key)));
            let events = self.events.clone();
            let queued = Arc::clone(&connection_queued);
            thread::spawn(move || {
                let address = SocketAddr::from((Ipv4Addr::from(key.1), key.2));
                let result = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT);
                let reader = result.as_ref().ok().and_then(|s| s.try_clone().ok());
                let _ = events.send(Event::Connected(key, result));
                if let Some(mut reader) = reader {
                    let mut buffer = vec![0u8; 16 * 1024];
                    loop {
                        // The connection is gone once only this thread
                        // holds the count.
                        while queued.load(Ordering::Acquire) >= HOST_BUFFER {
                            if Arc::strong_count(&queued) == 1 {
                                return;
                            }
                            thread::sleep(TICK);
                        }
                        match reader.read(&mut buffer) {
                            Ok(0) => {
                                let _ = events.send(Event::Closed(key, Ok(())));
                                break;
                            }
                            Ok(n) => {
                                queued.fetch_add(n, Ordering::AcqRel);
                                if events.send(Event::Data(key, buffer[..n].to_vec())).is_err() {
                                    break;
                                }
                            }
                            Err(error) => {
                                let _ = events.send(Event::Closed(key, Err(error)));
                                break;
                            }
                        }
                    }
                }
            });
            return;
        };
        c.last_activity = now;
        if segment.flags & RST != 0 {
            return self.drop_connection(key, "reset by the guest");
        }
        if segment.flags & SYN != 0 {
            // A retransmitted SYN: answer again once the SYN-ACK is out.
            if c.state == State::Accepted {
                let iss = c.iss;
                self.send(key, iss, SYN | ACK, &[], true);
            }
            return;
        }
        if c.state == State::Connecting {
            return;
        }
        if segment.flags & ACK != 0 {
            let ack = segment.acknowledgment;
            if after(ack, c.send_unacknowledged) && !after(ack, c.send_next) {
                let mut advanced = ack.wrapping_sub(c.send_unacknowledged) as usize;
                if c.state == State::Accepted {
                    c.state = State::Established;
                    advanced -= 1;
                }
                let data = advanced.min(c.flight.len());
                c.flight.drain(..data);
                if advanced > data && c.fin_sent {
                    c.fin_acknowledged = true;
                }
                c.send_unacknowledged = ack;
            }
            c.window = u32::from(segment.window) << c.scale.unwrap_or(0);
        }
        let mut acknowledge = false;
        if !segment.payload.is_empty() || segment.flags & FIN != 0 {
            acknowledge = true;
            if segment.sequence == c.receive_next && !c.guest_closed {
                if !segment.payload.is_empty() {
                    let written = c
                        .writer
                        .as_mut()
                        .map(|writer| writer.write_all(segment.payload));
                    if !matches!(written, Some(Ok(()))) {
                        self.note(format_args!("TCP {} host write failed", show(key)));
                        return self.reset(key);
                    }
                    c.receive_next = c.receive_next.wrapping_add(segment.payload.len() as u32);
                    c.to_host += segment.payload.len() as u64;
                }
                if segment.flags & FIN != 0 {
                    c.receive_next = c.receive_next.wrapping_add(1);
                    c.guest_closed = true;
                    if let Some(writer) = &c.writer {
                        let _ = writer.shutdown(Shutdown::Write);
                    }
                }
            }
        }
        if acknowledge {
            let sequence = c.send_next;
            self.send(key, sequence, ACK, &[], false);
        }
        self.push(key);
    }

    fn connected(&mut self, key: Key, result: io::Result<TcpStream>) {
        let Some(c) = self.connections.get_mut(&key) else {
            return;
        };
        match result {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                c.writer = Some(stream);
                c.state = State::Accepted;
                let iss = c.iss;
                self.note(format_args!("TCP {} open", show(key)));
                self.send(key, iss, SYN | ACK, &[], true);
            }
            Err(error) => {
                self.note(format_args!("TCP {} refused: {error}", show(key)));
                let sequence = 0;
                self.send(key, sequence, RST | ACK, &[], false);
                self.connections.remove(&key);
            }
        }
    }

    /// Sends what the guest's window takes, then the FIN once the host has
    /// closed and everything is out; closes a finished connection.
    fn push(&mut self, key: Key) {
        let mut segments = Vec::new();
        let Some(c) = self.connections.get_mut(&key) else {
            return;
        };
        if c.state != State::Established {
            return;
        }
        while !c.unsent.is_empty() && (c.flight.len() as u32) < c.window {
            let room = (c.window as usize - c.flight.len()).min(c.mss);
            let bytes: Vec<u8> = c.unsent.drain(..room.min(c.unsent.len())).collect();
            c.queued.fetch_sub(bytes.len(), Ordering::AcqRel);
            segments.push((c.send_next, ACK | PSH, bytes.clone()));
            c.send_next = c.send_next.wrapping_add(bytes.len() as u32);
            c.to_guest += bytes.len() as u64;
            c.flight.extend_from_slice(&bytes);
        }
        if c.host_closed && c.unsent.is_empty() && !c.fin_sent {
            segments.push((c.send_next, FIN | ACK, Vec::new()));
            c.send_next = c.send_next.wrapping_add(1);
            c.fin_sent = true;
        }
        let finished = c.guest_closed && c.fin_acknowledged;
        for (sequence, flags, bytes) in segments {
            self.send(key, sequence, flags, &bytes, false);
        }
        if finished {
            self.drop_connection(key, "closed");
        }
    }

    fn retransmit(&mut self, key: Key) {
        let Some(c) = self.connections.get(&key) else {
            return;
        };
        if c.state == State::Accepted {
            let iss = c.iss;
            return self.send(key, iss, SYN | ACK, &[], true);
        }
        let mut segments = Vec::new();
        let mut sequence = c.send_unacknowledged;
        if c.flight.is_empty() && c.window == 0 && !c.unsent.is_empty() {
            // A zero window probe: one byte past the window (RFC 9293 3.8.6.1).
            segments.push((sequence, ACK, vec![c.unsent[0]]));
        }
        let window = (c.window as usize).max(1);
        for chunk in c.flight[..c.flight.len().min(window)].chunks(c.mss) {
            segments.push((sequence, ACK | PSH, chunk.to_vec()));
            sequence = sequence.wrapping_add(chunk.len() as u32);
        }
        if c.fin_sent && !c.fin_acknowledged && c.unsent.is_empty() {
            segments.push((c.send_next.wrapping_sub(1), FIN | ACK, Vec::new()));
        }
        for (sequence, flags, bytes) in segments {
            self.send(key, sequence, flags, &bytes, false);
        }
    }
}

fn show((port, remote, remote_port): Key) -> String {
    format!("{GUEST}:{port} -> {}:{remote_port}", Ipv4::from(remote))
}

/// Runs the LAN over QEMU's stream connection until QEMU closes it.
pub fn serve(socket: TcpStream, log: Box<dyn Write + Send>) -> io::Result<()> {
    let (events, inbox) = channel();
    let mut reader = socket.try_clone()?;
    let frames = events.clone();
    thread::spawn(move || {
        loop {
            let mut length = [0u8; 4];
            if reader.read_exact(&mut length).is_err() {
                break;
            }
            let mut frame = vec![0u8; u32::from_be_bytes(length) as usize];
            if reader.read_exact(&mut frame).is_err() || frames.send(Event::Frame(frame)).is_err() {
                break;
            }
        }
        let _ = frames.send(Event::Quit);
    });
    let mut lan = Lan::new(events, log, host_resolver);
    let mut writer = socket;
    run(&mut lan, &inbox, |frame| {
        writer.write_all(&(frame.len() as u32).to_be_bytes())?;
        writer.write_all(frame)
    })
}

fn run(
    lan: &mut Lan,
    inbox: &Receiver<Event>,
    mut deliver: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        match inbox.recv_timeout(TICK) {
            Ok(Event::Quit) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Ok(event) => lan.handle(event),
            Err(RecvTimeoutError::Timeout) => {}
        }
        lan.tick(Instant::now());
        for frame in lan.take_frames() {
            deliver(&frame)?;
        }
    }
}

/// A listener for QEMU's `-netdev stream` client on a free loopback port,
/// and a thread that serves the first connection, logging to `log`.
pub fn listen(log: std::path::PathBuf) -> io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        let Ok(file) = std::fs::File::create(&log) else {
            return;
        };
        let _ = socket.set_nodelay(true);
        if let Err(error) = serve(socket, Box::new(file)) {
            eprintln!("network peer: {error}");
        }
    });
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    use stela_drivers::net::{Link, LinkError};
    use stela_runtime::net::{Clock, NetError, Stack};

    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<u8>>>);
    impl Write for Log {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The runtime's own stack, its link wired straight into the peer.
    struct Wire {
        lan: Lan,
        inbox: Receiver<Event>,
        frames: VecDeque<Vec<u8>>,
    }
    impl Link for Wire {
        fn mac(&self) -> Mac {
            Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56])
        }
        fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
            self.lan.handle(Event::Frame(frame.to_vec()));
            self.frames.extend(self.lan.take_frames());
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
            if self.frames.is_empty() {
                if let Ok(event) = self.inbox.recv_timeout(Duration::from_millis(1)) {
                    self.lan.handle(event);
                }
                self.lan.tick(Instant::now());
                self.frames.extend(self.lan.take_frames());
            }
            Ok(self.frames.pop_front())
        }
    }

    struct Wall(Instant);
    impl Clock for Wall {
        fn now_us(&self) -> u64 {
            self.0.elapsed().as_micros() as u64
        }
    }

    fn stack(log: &Log) -> Stack<Wire, Wall> {
        let (events, inbox) = channel();
        let lan = Lan::new(events, Box::new(log.clone()), host_resolver);
        Stack::new(
            Wire {
                lan,
                inbox,
                frames: VecDeque::new(),
            },
            Wall(Instant::now()),
        )
    }

    #[test]
    fn the_runtime_stack_leases_resolves_and_posts_through_the_peer_to_a_host_server() {
        let server = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = server.local_addr().unwrap().port();
        let served = thread::spawn(move || {
            let (mut socket, _) = server.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request.ends_with(b"ping") {
                let n = socket.read(&mut buffer).unwrap();
                assert_ne!(n, 0, "request ended early");
                request.extend_from_slice(&buffer[..n]);
            }
            // A body larger than the guest's window and several segments.
            let body = vec![b'x'; 200_000];
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(head.as_bytes()).unwrap();
            socket.write_all(&body).unwrap();
            request
        });
        let log = Log::default();
        let mut stack = stack(&log);
        let config = stack.dhcp().unwrap();
        assert_eq!(
            (config.address.address(), config.router),
            (GUEST, Some(GATEWAY))
        );
        assert_eq!(config.dns, [GATEWAY]);
        let host = format!("localhost:{port}");
        let body = stack
            .post(&host, "/check", &[], "text/plain", b"ping")
            .unwrap();
        assert_eq!(body.len(), 200_000);
        let request = String::from_utf8(served.join().unwrap()).unwrap();
        assert!(request.starts_with("POST /check HTTP/1.1\r\n"), "{request}");
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        for line in [
            "DHCP OFFER 10.0.2.15",
            "DHCP ACK 10.0.2.15",
            "DNS query localhost type 1",
            "TCP 10.0.2.15:",
            format!("127.0.0.1:{port} open").as_str(),
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
    }

    #[test]
    fn a_closed_host_port_resets_the_guest_connection() {
        let closed = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let log = Log::default();
        let mut stack = stack(&log);
        let result = stack.post(&format!("127.0.0.1:{port}"), "/", &[], "text/plain", b"");
        assert!(matches!(result, Err(NetError::Reset)), "{result:?}");
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("refused"), "{text}");
    }
}
