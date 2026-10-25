//! The interface: smoltcp over a [`Link`], configured by DHCP (renewed as
//! the lease runs) or statically, with blocking DNS lookups and HTTP
//! requests, and non-blocking [`Transfer`]s that several connections can
//! run at once.
use super::{Clock, Ipv4, NetError, http};
use alloc::{vec, vec::Vec};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::{dhcpv4, dns, tcp},
    time::{Duration, Instant},
    wire::{DnsQueryType, EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Cidr},
};
use stela_drivers::net::{Link, LinkError, MAX_FRAME};

/// An interface's IPv4 configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub address: Ipv4Cidr,
    pub router: Option<Ipv4>,
    pub dns: Vec<Ipv4>,
}

/// Autonegotiation after an adapter reset: about 3 s for 2.5GBASE-T,
/// doubled.
const CARRIER_WAIT_US: u64 = 6_000_000;
/// smoltcp's DHCP client retries within this.
const DHCP_WAIT_US: u64 = 30_000_000;
/// smoltcp's resolver retries each server within this.
const DNS_WAIT_US: u64 = 15_000_000;
/// A POST, from connection to the response's end.
const POST_WAIT_US: u64 = 120_000_000;
/// A transfer that receives nothing for this long has failed.
const IDLE_US: u64 = 30_000_000;
const FIRST_EPHEMERAL: u16 = 49152;
/// A POST's receive buffer, and a download's: the latter bounds the TCP
/// window, so a 30 ms path carries 4 MiB / 30 ms, about 140 MB/s, per
/// connection.
const POST_BUFFER: usize = 256 * 1024;
pub const DOWNLOAD_BUFFER: usize = 4 << 20;
const SEND_BUFFER: usize = 64 * 1024;

/// The link as smoltcp's device. A link refusal is kept, and the operation
/// polling the interface reports it.
struct Phy<L> {
    link: L,
    fault: Option<LinkError>,
}

struct Rx(Vec<u8>);
struct Tx<'a, L>(&'a mut Phy<L>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<L: Link> phy::TxToken for Tx<'_, L> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        let mut frame = vec![0; length];
        let result = f(&mut frame);
        if let Err(error) = self.0.link.transmit(&frame) {
            self.0.fault.get_or_insert(error);
        }
        result
    }
}

impl<L: Link> Device for Phy<L> {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a, L>
    where
        Self: 'a;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_, L>)> {
        match self.link.receive() {
            Ok(Some(frame)) => Some((Rx(frame), Tx(self))),
            Ok(None) => None,
            Err(error) => {
                self.fault.get_or_insert(error);
                None
            }
        }
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_, L>> {
        Some(Tx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        // smoltcp counts the Ethernet header in an Ethernet MTU.
        capabilities.max_transmission_unit = MAX_FRAME;
        capabilities
    }
}

/// One TCP connection carrying one request and its response.
pub struct Transfer {
    socket: SocketHandle,
    request: Vec<u8>,
    sent: usize,
    /// When the transfer fails unless something arrives first.
    idle_at: u64,
}

pub struct Stack<L: Link, C: Clock> {
    phy: Phy<L>,
    clock: C,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Absent once a configuration is set by hand.
    dhcp: Option<SocketHandle>,
    dns: SocketHandle,
    config: Option<Config>,
    next_port: u16,
}

impl<L: Link, C: Clock> Stack<L, C> {
    pub fn new(link: L, clock: C) -> Self {
        let mac = link.mac();
        let seed = clock.now_us()
            ^ u64::from_be_bytes([
                0, 0, mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
            ]);
        let mut config = InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac.0)));
        config.random_seed = seed;
        let mut phy = Phy { link, fault: None };
        let now = Instant::from_micros(clock.now_us() as i64);
        let iface = Interface::new(config, &mut phy, now);
        let mut sockets = SocketSet::new(Vec::new());
        let dhcp = Some(sockets.add(dhcpv4::Socket::new()));
        let dns = sockets.add(dns::Socket::new(&[], Vec::new()));
        Self {
            phy,
            clock,
            iface,
            sockets,
            dhcp,
            dns,
            config: None,
            next_port: FIRST_EPHEMERAL + (seed % 8192) as u16,
        }
    }

    pub fn link_mut(&mut self) -> &mut L {
        &mut self.phy.link
    }

    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }

    /// Configures the interface by hand instead of by DHCP.
    pub fn set_config(&mut self, config: Config) {
        if let Some(dhcp) = self.dhcp.take() {
            self.sockets.remove(dhcp);
        }
        self.apply(Some(config));
    }

    fn apply(&mut self, config: Option<Config>) {
        self.iface.update_ip_addrs(|addresses| {
            addresses.clear();
            if let Some(config) = &config {
                addresses.push(IpCidr::Ipv4(config.address)).unwrap();
            }
        });
        let routes = self.iface.routes_mut();
        match config.as_ref().and_then(|config| config.router) {
            Some(router) => {
                routes.add_default_ipv4_route(router).unwrap();
            }
            None => {
                routes.remove_default_ipv4_route();
            }
        }
        let servers: Vec<IpAddress> = config
            .iter()
            .flat_map(|config| config.dns.iter().copied().map(IpAddress::Ipv4))
            .collect();
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .update_servers(&servers);
        self.config = config;
    }

    fn now(&self) -> u64 {
        self.clock.now_us()
    }

    /// Moves every frame the link holds through the interface, then takes
    /// DHCP's news. A link refusal since the last poll is the error.
    pub fn poll(&mut self) -> Result<(), NetError> {
        let now = Instant::from_micros(self.now() as i64);
        self.iface.poll(now, &mut self.phy, &mut self.sockets);
        if let Some(dhcp) = self.dhcp {
            let news = match self.sockets.get_mut::<dhcpv4::Socket>(dhcp).poll() {
                Some(dhcpv4::Event::Configured(lease)) => Some(Some(Config {
                    address: lease.address,
                    router: lease.router,
                    dns: lease.dns_servers.iter().copied().collect(),
                })),
                Some(dhcpv4::Event::Deconfigured) => Some(None),
                None => None,
            };
            if let Some(config) = news {
                self.apply(config);
            }
        }
        match self.phy.fault.take() {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    /// Waits for carrier and a DHCP lease.
    pub fn dhcp(&mut self) -> Result<&Config, NetError> {
        let start = self.now();
        while !self.phy.link.carrier() {
            if self.now() >= start + CARRIER_WAIT_US {
                return Err(NetError::NoCarrier);
            }
        }
        let deadline = self.now() + DHCP_WAIT_US;
        while self.config.is_none() {
            if self.dhcp.is_none() {
                return Err(NetError::Invalid("DHCP after a configuration by hand"));
            }
            if self.now() >= deadline {
                return Err(NetError::Dhcp("no server answered"));
            }
            self.poll()?;
        }
        Ok(self.config.as_ref().unwrap())
    }

    /// The first IPv4 address of `host`, or `host` itself as a literal.
    fn resolve(&mut self, host: &str) -> Result<Ipv4, NetError> {
        if let Ok(address) = host.parse() {
            return Ok(address);
        }
        let query = self
            .sockets
            .get_mut::<dns::Socket>(self.dns)
            .start_query(self.iface.context(), host, DnsQueryType::A)
            .map_err(|error| NetError::Dns(alloc::format!("{host}: {error:?}")))?;
        let deadline = self.now() + DNS_WAIT_US;
        loop {
            self.poll()?;
            let now = self.now();
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
            match socket.get_query_result(query) {
                Ok(addresses) => {
                    return addresses
                        .iter()
                        .map(|&IpAddress::Ipv4(address)| address)
                        .next()
                        .ok_or_else(|| NetError::Dns(alloc::format!("{host}: no address")));
                }
                Err(dns::GetQueryResultError::Pending) if now < deadline => {}
                Err(dns::GetQueryResultError::Pending) => {
                    socket.cancel_query(query);
                    return Err(NetError::Timeout("DNS"));
                }
                Err(error) => return Err(NetError::Dns(alloc::format!("{host}: {error:?}"))),
            }
        }
    }

    /// Connects to `host` (`name` or `name:port`, port 80 by default) and
    /// queues `request`, configuring the interface by DHCP first if it has
    /// no address. `buffer` bounds the receive window.
    pub fn open(
        &mut self,
        host: &str,
        request: Vec<u8>,
        buffer: usize,
    ) -> Result<Transfer, NetError> {
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) => (
                name,
                port.parse::<u16>()
                    .map_err(|_| NetError::Invalid("HTTP port"))?,
            ),
            None => (host, 80),
        };
        if self.config.is_none() {
            self.dhcp()?;
        }
        let address = self.resolve(name)?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; buffer]),
            tcp::SocketBuffer::new(vec![0; SEND_BUFFER]),
        );
        socket.set_congestion_control(tcp::CongestionControl::Reno);
        socket.set_timeout(Some(Duration::from_micros(IDLE_US)));
        let local = self.next_port;
        self.next_port = local.checked_add(1).unwrap_or(FIRST_EPHEMERAL);
        socket
            .connect(
                self.iface.context(),
                (IpAddress::Ipv4(address), port),
                local,
            )
            .map_err(|_| NetError::Invalid("TCP connect"))?;
        Ok(Transfer {
            socket: self.sockets.add(socket),
            request,
            sent: 0,
            idle_at: self.now() + IDLE_US,
        })
    }

    /// Without waiting: polls the interface, sends what is left of the
    /// request, and hands what has arrived to `take` with whether the peer
    /// has closed. Returns `take`'s verdict that the response is complete.
    pub fn read(
        &mut self,
        transfer: &mut Transfer,
        mut take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        self.poll()?;
        let now = self.now();
        let socket = self.sockets.get_mut::<tcp::Socket>(transfer.socket);
        if socket.can_send() && transfer.sent < transfer.request.len() {
            transfer.sent += socket
                .send_slice(&transfer.request[transfer.sent..])
                .map_err(|_| NetError::Reset)?;
        }
        let mut done = false;
        while socket.can_recv() && !done {
            done = socket
                .recv(|bytes| (bytes.len(), take(bytes, false)))
                .map_err(|_| NetError::Reset)??;
            transfer.idle_at = now + IDLE_US;
        }
        if done {
            return Ok(true);
        }
        match socket.state() {
            tcp::State::Closed if transfer.sent == 0 => Err(NetError::Reset),
            tcp::State::SynSent | tcp::State::SynReceived => self.waiting(transfer, now),
            _ if !socket.may_recv() => take(&[], true),
            _ => self.waiting(transfer, now),
        }
    }

    fn waiting(&self, transfer: &Transfer, now: u64) -> Result<bool, NetError> {
        if now >= transfer.idle_at {
            return Err(NetError::Timeout("TCP transfer"));
        }
        Ok(false)
    }

    /// Ends `transfer`, gracefully if it completed, and frees its socket.
    pub fn close(&mut self, transfer: Transfer) {
        self.sockets.get_mut::<tcp::Socket>(transfer.socket).abort();
        // The RST leaves on this poll; its failure loses nothing.
        let _ = self.poll();
        self.sockets.remove(transfer.socket);
    }

    /// Reads `transfer` until `take` says its response is complete.
    fn finish(
        &mut self,
        mut transfer: Transfer,
        deadline: u64,
        mut take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<(), NetError> {
        let result = loop {
            match self.read(&mut transfer, &mut take) {
                Ok(true) => break Ok(()),
                Ok(false) if self.now() >= deadline => break Err(NetError::Timeout("HTTP")),
                Ok(false) => {}
                Err(error) => break Err(error),
            }
        };
        self.close(transfer);
        result
    }

    /// One HTTP/1.1 POST; the response body on a 2xx status.
    pub fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        let request = http::post(host, path, headers, content_type, body)?;
        let transfer = self.open(host, request, POST_BUFFER)?;
        let mut reply = Vec::new();
        let mut response = None;
        self.finish(transfer, self.now() + POST_WAIT_US, |bytes, closed| {
            reply.extend_from_slice(bytes);
            response = http::response(&reply, closed)?;
            Ok(response.is_some())
        })?;
        Ok(response.unwrap().body)
    }

    /// Bytes `start..=end` of `http://host/path`, handed to `body` in order
    /// as they arrive. Returns the resource's whole size.
    pub fn get_range(
        &mut self,
        host: &str,
        path: &str,
        start: u64,
        end: u64,
        mut body: impl FnMut(&[u8]),
    ) -> Result<u64, NetError> {
        let request = http::get_range(host, path, start, end, None)?;
        let transfer = self.open(host, request, DOWNLOAD_BUFFER)?;
        let mut ranged = http::Ranged::new(start, end);
        self.finish(transfer, u64::MAX, |bytes, closed| {
            ranged.feed(bytes, closed, &mut body)
        })?;
        Ok(ranged.size.unwrap())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::{collections::VecDeque, rc::Rc};
    use core::cell::{Cell, RefCell};
    use stela_drivers::net::Mac;

    const CLIENT: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const CLIENT_IP: Ipv4 = Ipv4::new(10, 0, 2, 15);
    const SERVER_IP: Ipv4 = Ipv4::new(10, 0, 2, 2);

    /// Each reading advances 20 µs, so waits end.
    #[derive(Clone, Default)]
    pub(crate) struct TestClock(Rc<Cell<u64>>);

    impl Clock for TestClock {
        fn now_us(&self) -> u64 {
            self.0.set(self.0.get() + 20);
            self.0.get()
        }
    }

    /// Frames from one end to the other.
    #[derive(Default)]
    struct Queue(VecDeque<Vec<u8>>);

    struct End {
        mac: Mac,
        out: Rc<RefCell<Queue>>,
        into: Rc<RefCell<Queue>>,
    }

    impl Link for End {
        fn mac(&self) -> Mac {
            self.mac
        }
        fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
            self.out.borrow_mut().0.push_back(frame.to_vec());
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
            Ok(self.into.borrow_mut().0.pop_front())
        }
    }

    /// A smoltcp HTTP server serving `pattern(offset)` for ranges of a
    /// `size`-byte resource, stepped whenever the client reads its link;
    /// every `drop_every`th frame to the client is lost and every
    /// `swap_every`th pair swapped.
    struct Lan {
        client: End,
        server: Phy<End>,
        iface: Interface,
        sockets: SocketSet<'static>,
        listener: SocketHandle,
        clock: TestClock,
        size: u64,
        request: Vec<u8>,
        reply: Option<(Vec<u8>, u64, u64)>,
        sent: u64,
        frames: usize,
        drop_every: usize,
        swap_every: usize,
    }

    fn pattern(offset: u64) -> u8 {
        (offset.wrapping_mul(0x9e37_79b9) >> 13) as u8
    }

    impl Lan {
        fn new(size: u64, clock: TestClock) -> Self {
            let (a, b) = (Rc::default(), Rc::default());
            let client = End {
                mac: CLIENT,
                out: Rc::clone(&a),
                into: Rc::clone(&b),
            };
            let mut server = Phy {
                link: End {
                    mac: Mac(SERVER),
                    out: b,
                    into: a,
                },
                fault: None,
            };
            let config = InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(SERVER)));
            let mut iface = Interface::new(config, &mut server, Instant::ZERO);
            iface.update_ip_addrs(|a| a.push(IpCidr::new(SERVER_IP.into(), 24)).unwrap());
            let mut sockets = SocketSet::new(Vec::new());
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 1 << 20]),
                tcp::SocketBuffer::new(vec![0; 1 << 20]),
            );
            socket.listen(80).unwrap();
            let listener = sockets.add(socket);
            Self {
                client,
                server,
                iface,
                sockets,
                listener,
                clock,
                size,
                request: Vec::new(),
                reply: None,
                sent: 0,
                frames: 0,
                drop_every: 0,
                swap_every: 0,
            }
        }

        fn step(&mut self) {
            let now = Instant::from_micros(self.clock.0.get() as i64);
            self.iface.poll(now, &mut self.server, &mut self.sockets);
            let socket = self.sockets.get_mut::<tcp::Socket>(self.listener);
            while socket.can_recv() {
                socket
                    .recv(|bytes| {
                        self.request.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if self.reply.is_none() && self.request.windows(4).any(|w| w == b"\r\n\r\n") {
                let text = core::str::from_utf8(&self.request).unwrap();
                let range = text.split("Range: bytes=").nth(1).unwrap();
                let range = range.split("\r\n").next().unwrap();
                let (first, last) = range.split_once('-').unwrap();
                let (first, last): (u64, u64) = (first.parse().unwrap(), last.parse().unwrap());
                let head = alloc::format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {first}-{last}/{}\r\nContent-Length: {}\r\n\r\n",
                    self.size,
                    last - first + 1
                );
                self.reply = Some((head.into_bytes(), first, last + 1));
            }
            if let Some((head, first, end)) = &mut self.reply {
                if !head.is_empty() {
                    let n = socket.send_slice(head).unwrap();
                    head.drain(..n);
                }
                while head.is_empty() && *first + self.sent < *end && socket.can_send() {
                    let at = *first + self.sent;
                    let chunk: Vec<u8> = (at..(*end).min(at + 4096)).map(pattern).collect();
                    self.sent += socket.send_slice(&chunk).unwrap() as u64;
                }
                if *first + self.sent == *end {
                    socket.close();
                }
            }
            self.iface.poll(now, &mut self.server, &mut self.sockets);
            // Impair what the server sent.
            let mut queue = self.client.into.borrow_mut();
            let mut kept = VecDeque::new();
            while let Some(frame) = queue.0.pop_front() {
                self.frames += 1;
                if self.drop_every != 0 && self.frames.is_multiple_of(self.drop_every) {
                    continue;
                }
                kept.push_back(frame);
                if self.swap_every != 0 && self.frames.is_multiple_of(self.swap_every) {
                    let n = kept.len();
                    if n >= 2 {
                        kept.swap(n - 1, n - 2);
                    }
                }
            }
            queue.0 = kept;
        }
    }

    impl Link for Lan {
        fn mac(&self) -> Mac {
            CLIENT
        }
        fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
            self.client.transmit(frame)
        }
        fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
            if self.client.into.borrow().0.is_empty() {
                self.step();
            }
            self.client.receive()
        }
    }

    fn stack(lan: Lan, clock: TestClock) -> Stack<Lan, TestClock> {
        let mut s = Stack::new(lan, clock);
        s.set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        });
        s
    }

    #[test]
    fn a_range_arrives_whole_and_in_order_through_loss_and_reordering() {
        let clock = TestClock::default();
        let mut lan = Lan::new(1 << 40, clock.clone());
        lan.drop_every = 97;
        lan.swap_every = 13;
        let mut s = stack(lan, clock);
        let start = 3 << 30;
        let length = 3 << 20;
        let mut body = Vec::new();
        let size = s
            .get_range("10.0.2.2", "/a.ipsw", start, start + length - 1, |b| {
                body.extend_from_slice(b)
            })
            .unwrap();
        assert_eq!(size, 1 << 40);
        assert_eq!(body.len() as u64, length);
        assert!(body.iter().zip(start..).all(|(&b, at)| b == pattern(at)));
        let request = core::str::from_utf8(&s.link_mut().request).unwrap();
        assert!(request.starts_with("GET /a.ipsw HTTP/1.1\r\nHost: 10.0.2.2\r\n"));
    }

    #[test]
    fn a_silent_or_absent_peer_times_out() {
        let clock = TestClock::default();
        let mut lan = Lan::new(100, clock.clone());
        lan.drop_every = 1;
        let mut s = stack(lan, clock);
        assert_eq!(
            s.get_range("10.0.2.2", "/", 0, 9, |_| ()),
            Err(NetError::Timeout("TCP transfer"))
        );
        let clock = TestClock::default();
        let mut s = stack(Lan::new(100, clock.clone()), clock);
        // Port 81 has no listener: smoltcp answers with a reset.
        assert_eq!(
            s.get_range("10.0.2.2:81", "/", 0, 9, |_| ()),
            Err(NetError::Reset)
        );
    }
}
