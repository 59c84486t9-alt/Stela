//! UDP and ICMP echo through the gateway: user-mode NAT with ordinary host
//! sockets. Each guest UDP port gets one host UDP socket (an endpoint-
//! independent mapping, RFC 4787 4.1), so every remote the guest sends from
//! that port sees one host address and port, and replies from any remote
//! come back to that guest port with their real source. Each guest echo
//! identifier gets one unprivileged ICMP ping socket on Linux, whose kernel
//! picks the host identifier; replies are given back the guest's. Mappings
//! end after [`UDP_IDLE`] or [`ECHO_IDLE`] without traffic either way, and
//! at [`FLOWS`] the one idle longest makes room.
//!
//! Like any NAT gateway on a LAN with no other hosts, the peer keeps
//! multicast and broadcast on the link (nothing else is there to answer),
//! answers echo requests to itself, and serves only DHCP and DNS on UDP.
//! Fragments from the guest are counted and dropped: the peer does not
//! reassemble. ICMP errors the host's sockets receive are not relayed.
use super::{Event, GATEWAY, GUEST, Lan, MASK, wire};
use std::{
    io,
    net::{Ipv4Addr as Ipv4, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    thread,
    time::{Duration, Instant},
};

/// RFC 4787 REQ-5: at least two minutes; five or more recommended.
pub const UDP_IDLE: Duration = Duration::from_secs(300);
/// RFC 5508 REQ-1: at least 60 seconds for ICMP query mappings.
pub const ECHO_IDLE: Duration = Duration::from_secs(60);
pub const FLOWS: usize = 256;
/// How often a mapping's reader looks whether its mapping is gone.
const POLL: Duration = Duration::from_millis(250);
/// Largest datagram a host socket receives (the IPv4 maximum).
const LARGEST: usize = 65_535;
/// How often the totals line is written while it changes.
pub const TOTALS_EVERY: Duration = Duration::from_secs(60);

/// A mapping's guest side: the guest's UDP port or echo identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flow {
    Udp(u16),
    Echo(u16),
}

impl Flow {
    fn idle(&self) -> Duration {
        match self {
            Flow::Udp(_) => UDP_IDLE,
            Flow::Echo(_) => ECHO_IDLE,
        }
    }
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Flow::Udp(port) => write!(f, "UDP {GUEST}:{port}"),
            Flow::Echo(ident) => write!(f, "ICMP echo {GUEST} id {ident}"),
        }
    }
}

/// One mapping's host socket and traffic. Dropping it stops its reader.
pub struct Mapping {
    socket: Arc<UdpSocket>,
    open: Arc<AtomicBool>,
    /// The host side's port or, for echo, the kernel's identifier.
    host_port: u16,
    to_host: u64,
    to_guest: u64,
    send_failed: bool,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        self.open.store(false, Ordering::Release);
    }
}

/// Datagram counts for the totals line.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct Totals {
    pub opened: u64,
    pub evicted: u64,
    pub expired: u64,
    pub udp_to_host: u64,
    pub udp_to_guest: u64,
    pub echo_to_host: u64,
    pub echo_to_guest: u64,
    pub echo_answered: u64,
    /// Datagrams to the guest sent as IPv4 fragments.
    pub fragmented: u64,
    /// Multicast and broadcast kept on the link.
    pub local: u64,
    /// UDP to the gateway on a port it does not serve.
    pub gateway: u64,
    pub fragments: u64,
    pub send_failed: u64,
    pub unsupported: u64,
    /// Anything else not forwarded: other sources, other ICMP types,
    /// mappings that could not open.
    pub other: u64,
}

impl std::fmt::Display for Totals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP totals: flows opened={} evicted={} expired={} udp to_host={} to_guest={} \
             echo to_host={} to_guest={} answered={} fragmented_to_guest={} \
             not forwarded: local={} gateway={} fragments={} send_failed={} unsupported={} \
             other={}",
            self.opened,
            self.evicted,
            self.expired,
            self.udp_to_host,
            self.udp_to_guest,
            self.echo_to_host,
            self.echo_to_guest,
            self.echo_answered,
            self.fragmented,
            self.local,
            self.gateway,
            self.fragments,
            self.send_failed,
            self.unsupported,
            self.other,
        )
    }
}

/// Destinations that stay on this link: multicast, the limited broadcast
/// and the subnet's broadcast.
fn on_link(destination: Ipv4) -> bool {
    let subnet_broadcast = u32::from(GATEWAY) | !u32::from(MASK);
    destination.is_multicast()
        || destination.is_broadcast()
        || u32::from(destination) == subnet_broadcast
}

/// An unprivileged ICMP echo socket (Linux `net.ipv4.ping_group_range`).
#[cfg(target_os = "linux")]
fn ping_socket() -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    // SAFETY: socket(2) takes no pointers and returns a new descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a datagram socket this process just opened and that
    // nothing else owns; the `UdpSocket` closes it.
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn ping_socket() -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ping sockets are implemented for Linux hosts only",
    ))
}

/// Relays what a mapping's socket receives as events until the mapping is
/// dropped or the peer stops.
fn read(socket: Arc<UdpSocket>, open: Arc<AtomicBool>, flow: Flow, events: Sender<Event>) {
    let mut buffer = vec![0u8; LARGEST];
    while open.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((n, SocketAddr::V4(from))) => {
                let payload = buffer[..n].to_vec();
                if events
                    .send(Event::Datagram {
                        flow,
                        from,
                        payload,
                    })
                    .is_err()
                {
                    return;
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            // A queued ICMP error (Linux reports some on the next call):
            // the socket stays usable.
            Err(_) => thread::sleep(POLL),
        }
    }
}

impl Lan {
    /// A guest UDP datagram for anything but the gateway's DHCP and DNS.
    pub(super) fn forward_udp(
        &mut self,
        source: Ipv4,
        destination: Ipv4,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) {
        if source != GUEST {
            self.totals.other += 1;
            return self.note(format_args!(
                "UDP from {source}:{source_port} to {destination}:{destination_port} dropped: \
                 not the guest's address"
            ));
        }
        if on_link(destination) {
            self.totals.local += 1;
            if self.local_reported.insert((destination, destination_port)) {
                self.note(format_args!(
                    "UDP to {destination}:{destination_port} stays on the link, which has no \
                     other hosts (reported once)"
                ));
            }
            return;
        }
        if destination == GATEWAY || destination.is_unspecified() {
            self.totals.gateway += 1;
            if self.local_reported.insert((destination, destination_port)) {
                self.note(format_args!(
                    "UDP to {destination}:{destination_port} dropped: the gateway serves only \
                     DHCP and DNS (reported once)"
                ));
            }
            return;
        }
        let flow = Flow::Udp(source_port);
        let remote = SocketAddrV4::new(destination, destination_port);
        if !self.open_flow(flow, remote) {
            return;
        }
        self.totals.udp_to_host += 1;
        self.send_to_host(flow, remote, payload);
    }

    /// A guest ICMP message.
    pub(super) fn forward_icmp(&mut self, source: Ipv4, destination: Ipv4, message: &[u8]) {
        let Some(ident) = wire::echo_request(message) else {
            self.totals.other += 1;
            let (kind, code) = wire::icmp_kind(message).unwrap_or_default();
            return self.note(format_args!(
                "ICMP type {kind} code {code} to {destination} dropped"
            ));
        };
        if source != GUEST {
            self.totals.other += 1;
            return;
        }
        if destination == GATEWAY {
            self.totals.echo_answered += 1;
            let reply = wire::echo_answer(message);
            return self.ip(GATEWAY, GUEST, wire::PROTOCOL_ICMP, &reply);
        }
        if on_link(destination) || destination.is_unspecified() {
            self.totals.local += 1;
            return;
        }
        let flow = Flow::Echo(ident);
        let remote = SocketAddrV4::new(destination, 0);
        if !self.open_flow(flow, remote) {
            return;
        }
        self.totals.echo_to_host += 1;
        self.send_to_host(flow, remote, message);
    }

    /// Makes sure `flow` has a mapping, opening one for its first datagram
    /// (to `remote`); `false` when none could open.
    fn open_flow(&mut self, flow: Flow, remote: SocketAddrV4) -> bool {
        let now = Instant::now();
        if self.flows.touch(&flow, now).is_some() {
            return true;
        }
        let socket = match flow {
            Flow::Udp(_) => UdpSocket::bind((Ipv4::UNSPECIFIED, 0)),
            Flow::Echo(_) => ping_socket(),
        };
        let socket = match socket.and_then(|socket| {
            socket.set_read_timeout(Some(POLL))?;
            Ok(socket)
        }) {
            Ok(socket) => socket,
            Err(error) => {
                if matches!(flow, Flow::Echo(_)) {
                    self.totals.unsupported += 1;
                    if !self.echo_unsupported {
                        self.echo_unsupported = true;
                        self.note(format_args!(
                            "ICMP echo unsupported: no unprivileged ping socket ({error}); echo \
                             requests beyond the gateway are dropped (reported once)"
                        ));
                    }
                } else {
                    self.totals.other += 1;
                    self.note(format_args!("{flow} -> {remote} could not open: {error}"));
                }
                return false;
            }
        };
        // Before the first send, a ping socket has no identifier yet; its
        // port is read again after the send.
        let host_port = socket.local_addr().map_or(0, |address| address.port());
        let socket = Arc::new(socket);
        let open = Arc::new(AtomicBool::new(true));
        let mapping = Mapping {
            socket: Arc::clone(&socket),
            open: Arc::clone(&open),
            host_port,
            to_host: 0,
            to_guest: 0,
            send_failed: false,
        };
        let events = self.events.clone();
        thread::spawn(move || read(socket, open, flow, events));
        self.totals.opened += 1;
        if let Some((evicted, mapping)) = self.flows.insert(flow, mapping, now) {
            self.totals.evicted += 1;
            self.close(evicted, mapping, "evicted");
        }
        if matches!(flow, Flow::Udp(_)) {
            self.note(format_args!(
                "{flow} -> {remote} open via host port {host_port}"
            ));
        }
        true
    }

    fn send_to_host(&mut self, flow: Flow, remote: SocketAddrV4, payload: &[u8]) {
        let Some(mapping) = self.flows.touch(&flow, Instant::now()) else {
            return;
        };
        match mapping.socket.send_to(payload, remote) {
            Ok(_) => {
                mapping.to_host += 1;
                if mapping.to_host == 1 && matches!(flow, Flow::Echo(_)) {
                    let ident = mapping
                        .socket
                        .local_addr()
                        .map_or(0, |address| address.port());
                    mapping.host_port = ident;
                    self.note(format_args!(
                        "{flow} -> {} open via host id {ident}",
                        remote.ip()
                    ));
                }
            }
            Err(error) => {
                self.totals.send_failed += 1;
                if !mapping.send_failed {
                    mapping.send_failed = true;
                    self.note(format_args!(
                        "{flow} -> {remote} send failed: {error} (reported once per mapping)"
                    ));
                }
            }
        }
    }

    /// A datagram a mapping's host socket received.
    pub(super) fn host_datagram(&mut self, flow: Flow, from: SocketAddrV4, mut payload: Vec<u8>) {
        let Some(mapping) = self.flows.touch(&flow, Instant::now()) else {
            // Its mapping ended while the datagram was on its way.
            return;
        };
        mapping.to_guest += 1;
        match flow {
            Flow::Udp(port) => {
                self.totals.udp_to_guest += 1;
                self.udp(*from.ip(), GUEST, from.port(), port, &payload);
            }
            Flow::Echo(ident) => {
                if wire::echo_reply_for(&mut payload, ident) {
                    self.totals.echo_to_guest += 1;
                    self.ip(*from.ip(), GUEST, wire::PROTOCOL_ICMP, &payload);
                }
            }
        }
    }

    /// A guest datagram that is a fragment of a larger one.
    pub(super) fn fragment_dropped(&mut self, bytes: &[u8]) {
        self.totals.fragments += 1;
        if self.totals.fragments == 1 {
            let destination = bytes
                .get(16..20)
                .and_then(|octets| <[u8; 4]>::try_from(octets).ok())
                .map_or(Ipv4::UNSPECIFIED, Ipv4::from);
            self.note(format_args!(
                "IPv4 fragment to {destination} dropped: the peer does not reassemble \
                 (reported once; counted in UDP totals)"
            ));
        }
    }

    /// Ends idle mappings and writes the totals while they change.
    pub(super) fn tick_flows(&mut self, now: Instant) {
        for (flow, mapping) in self.flows.expire(now, Flow::idle) {
            self.totals.expired += 1;
            self.close(flow, mapping, "idle");
        }
        if now.saturating_duration_since(self.totals_written) >= TOTALS_EVERY {
            self.write_totals(now);
        }
    }

    pub(super) fn write_totals(&mut self, now: Instant) {
        self.totals_written = now;
        if self.totals != self.totals_noted {
            self.totals_noted = self.totals.clone();
            let line = self.totals.to_string();
            self.note(format_args!("{line}"));
        }
    }

    /// Closes every mapping and writes the final totals.
    pub(super) fn finish(&mut self) {
        for (flow, mapping) in self.flows.drain() {
            self.close(flow, mapping, "closed");
        }
        self.write_totals(Instant::now());
    }

    fn close(&mut self, flow: Flow, mapping: Mapping, why: &str) {
        self.note(format_args!(
            "{flow} {why}: host port {} to_host={} to_guest={}",
            mapping.host_port, mapping.to_host, mapping.to_guest
        ));
    }
}

#[cfg(test)]
mod tests;
