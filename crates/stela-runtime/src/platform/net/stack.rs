//! The interface: smoltcp over a [`Link`], configured by DHCPv4 and IPv6
//! autoconfiguration (or an authored fixture), with blocking DNS lookups and HTTP
//! requests, and non-blocking [`Transfer`]s that several connections can
//! run at once.
mod automatic;
mod dad;
mod rdnss;
use super::{Clock, Ipv4, NetError, http};
use alloc::{string::String, vec, vec::Vec};
pub use automatic::Automatic;
use core::net::Ipv6Addr;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::{dhcpv4, dns, tcp},
    time::{Duration, Instant},
    wire::{DnsQueryType, EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Cidr, Ipv6Cidr},
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
/// How long a name's address is used before it is looked up again.
const RESOLVED_US: u64 = 300_000_000;
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
    /// Whether the last poll took a frame from the link.
    received: bool,
    probes: Vec<dad::Probe>,
    local_ipv6: Ipv6Addr,
    approved_ipv6: Vec<Ipv6Addr>,
    rdnss: rdnss::Rdnss,
    manage_ipv6: bool,
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
        // Tentative addresses stay off the wire until their DAD probe ends.
        if self.0.manage_ipv6 && frame.len() >= 54 && frame[12..14] == [0x86, 0xdd] {
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[22..38]).unwrap());
            if !source.is_unspecified() && !self.0.approved_ipv6.contains(&source) {
                return result;
            }
        }
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

    fn receive(&mut self, now: Instant) -> Option<(Rx, Tx<'_, L>)> {
        match self.link.receive() {
            Ok(Some(frame)) => {
                self.received = true;
                for probe in &mut self.probes {
                    probe.duplicate |= dad::conflicts(&frame, probe.address, probe.nonce);
                }
                self.rdnss
                    .observe(&frame, self.local_ipv6, now.total_micros().max(0) as u64);
                Some((Rx(frame), Tx(self)))
            }
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
    /// Names looked up, their first address and when it was found.
    resolved: Vec<(String, IpAddress, u64)>,
    dns_servers: Vec<IpAddress>,
    conflicts: Vec<Ipv6Addr>,
    probe_nonce: u64,
}

impl<L: Link, C: Clock> Stack<L, C> {
    /// Seed TCP sequence/port choices from host cryptographic entropy.
    pub fn new(link: L, clock: C, seed: u64) -> Self {
        let mac = link.mac();
        let local_ipv6 = automatic::link_local(mac.0);
        let mut config = InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac.0)));
        config.random_seed = seed;
        config.slaac = true;
        let mut phy = Phy {
            link,
            fault: None,
            received: false,
            probes: Vec::new(),
            local_ipv6,
            approved_ipv6: Vec::new(),
            rdnss: Default::default(),
            manage_ipv6: true,
        };
        let now = Instant::from_micros(clock.now_us() as i64);
        let mut iface = Interface::new(config, &mut phy, now);
        iface.update_ip_addrs(|a| a.push(IpCidr::Ipv6(Ipv6Cidr::new(local_ipv6, 64))).unwrap());
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
            resolved: Vec::new(),
            dns_servers: Vec::new(),
            conflicts: Vec::new(),
            probe_nonce: seed,
        }
    }

    pub fn link_mut(&mut self) -> &mut L {
        &mut self.phy.link
    }

    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }

    /// Configures the interface by hand instead of by DHCP.
    pub fn set_config(&mut self, config: Config) -> Result<(), NetError> {
        if let Some(dhcp) = self.dhcp.take() {
            self.sockets.remove(dhcp);
        }
        self.apply(Some(config))
    }

    fn apply(&mut self, config: Option<Config>) -> Result<(), NetError> {
        let mut fit = true;
        self.iface.update_ip_addrs(|addresses| {
            addresses.retain(|a| matches!(a, IpCidr::Ipv6(_)));
            if let Some(config) = &config {
                // Reserve one slot for the lease without disturbing the
                // first link-local IPv6 address required by router discovery.
                while addresses.is_full() && addresses.len() > 1 {
                    addresses.pop();
                }
                fit = addresses.push(IpCidr::Ipv4(config.address)).is_ok();
            }
        });
        if !fit {
            return Err(NetError::Invalid("interface address capacity"));
        }
        let routes = self.iface.routes_mut();
        match config.as_ref().and_then(|config| config.router) {
            Some(router) => {
                routes
                    .add_default_ipv4_route(router)
                    .map_err(|_| NetError::Invalid("interface route capacity"))?;
            }
            None => {
                routes.remove_default_ipv4_route();
            }
        }
        self.config = config;
        self.update_dns();
        Ok(())
    }

    fn now(&self) -> u64 {
        self.clock.now_us()
    }

    /// Moves every frame the link holds through the interface, then takes
    /// DHCP's news. A link refusal since the last poll is the error.
    pub fn poll(&mut self) -> Result<(), NetError> {
        let now = Instant::from_micros(self.now() as i64);
        self.phy.received = false;
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
                self.apply(config)?;
            }
        }
        self.probe_ipv6()?;
        self.update_dns();
        match self.phy.fault.take() {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    /// Waits up to `micros` for the link's next frame, when the link signals
    /// arrivals and the last poll took none: until its signal, smoltcp's next
    /// timer or the bound, whichever is first. A link that does not signal
    /// returns at once, and its caller polls.
    pub fn wait(&mut self, micros: u64) {
        let deadline = self.now().saturating_add(micros);
        self.wait_until(deadline);
    }

    fn wait_until(&mut self, deadline: u64) {
        if !self.phy.link.signals() || self.phy.received {
            return;
        }
        let now = self.now();
        let timer = self
            .iface
            .poll_delay(Instant::from_micros(now as i64), &self.sockets)
            .map_or(u64::MAX, |delay| now.saturating_add(delay.total_micros()));
        let dad = self
            .phy
            .probes
            .iter()
            .map(|probe| probe.until)
            .min()
            .unwrap_or(u64::MAX);
        let until = deadline.min(timer).min(dad);
        if until > now {
            self.clock.sleep(until);
        }
    }

    /// Waits for carrier and, without a configuration by hand, a DHCP
    /// lease.
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
                return Err(NetError::Dhcp(
                    "no IPv4 lease: no DHCP server answered within 30 seconds",
                ));
            }
            self.poll()?;
            if self.config.is_none() {
                self.wait_until(deadline);
            }
        }
        Ok(self.config.as_ref().unwrap())
    }

    /// The first IPv4 address of `host`, or `host` itself as a literal.
    /// An address found in the last [`RESOLVED_US`] is used again, and a
    /// lookup that fails falls back to the last address the name had, so
    /// one lost reply does not end a long download.
    fn resolve(&mut self, host: &str) -> Result<IpAddress, NetError> {
        if let Ok(address) = host.parse() {
            return Ok(address);
        }
        let now = self.now();
        let known = self.resolved.iter().position(|(name, ..)| name == host);
        if let Some(index) = known
            && self.address_usable(self.resolved[index].1)
            && now.wrapping_sub(self.resolved[index].2) < RESOLVED_US
        {
            return Ok(self.resolved[index].1);
        }
        match (self.lookup(host), known) {
            (Ok(address), Some(index)) => {
                self.resolved[index] = (String::from(host), address, now);
                Ok(address)
            }
            (Ok(address), None) => {
                self.resolved.push((String::from(host), address, now));
                Ok(address)
            }
            (Err(error), Some(index)) => {
                if self.address_usable(self.resolved[index].1) {
                    Ok(self.resolved[index].1)
                } else {
                    Err(error)
                }
            }
            (Err(error), None) => Err(error),
        }
    }

    fn lookup(&mut self, host: &str) -> Result<IpAddress, NetError> {
        if self.ipv6_ready()
            && let Ok(address) = self.lookup_type(host, DnsQueryType::Aaaa)
        {
            return Ok(address);
        }
        if self.config.is_some() {
            self.lookup_type(host, DnsQueryType::A)
        } else {
            Err(NetError::Dns(alloc::format!(
                "{host}: no reachable address family"
            )))
        }
    }
    fn lookup_type(&mut self, host: &str, kind: DnsQueryType) -> Result<IpAddress, NetError> {
        let dns_deadline = self.now().saturating_add(DNS_WAIT_US);
        while self.dns_servers.is_empty() {
            self.poll()?;
            if self.now() >= dns_deadline {
                return Err(NetError::Dns(String::from(
                    "no DNS server from DHCPv4 or IPv6 router advertisements",
                )));
            }
            if self.dns_servers.is_empty() {
                self.wait_until(dns_deadline);
            }
        }
        let query = self
            .sockets
            .get_mut::<dns::Socket>(self.dns)
            .start_query(self.iface.context(), host, kind)
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
                        .copied()
                        .next()
                        .ok_or_else(|| NetError::Dns(alloc::format!("{host}: no address")));
                }
                Err(dns::GetQueryResultError::Pending) if now < deadline => {
                    self.wait_until(deadline)
                }
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
        let (name, port) = automatic::authority(host)?;
        if self.config.is_none() && !self.ipv6_ready() {
            self.automatic()?;
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
            .connect(self.iface.context(), (address, port), local)
            .map_err(|_| NetError::Invalid("TCP connect"))?;
        Ok(Transfer {
            socket: self.sockets.add(socket),
            request,
            sent: 0,
            idle_at: self.now() + IDLE_US,
        })
    }

    /// Opens an unframed TCP stream. The caller supplies every application
    /// byte later through [`Self::write`] and decides when an idle connection
    /// ends. This is the transport boundary for protocols whose TLS and
    /// request framing belong to the peer rather than Stela.
    pub fn open_raw(&mut self, host: &str, port: u16, buffer: usize) -> Result<Transfer, NetError> {
        if port == 0 {
            return Err(NetError::Invalid("TCP destination port zero"));
        }
        let destination = if host.parse::<Ipv6Addr>().is_ok() {
            alloc::format!("[{host}]:{port}")
        } else {
            alloc::format!("{host}:{port}")
        };
        let mut transfer = self.open(&destination, Vec::new(), buffer)?;
        self.sockets
            .get_mut::<tcp::Socket>(transfer.socket)
            .set_timeout(None);
        transfer.idle_at = u64::MAX;
        Ok(transfer)
    }

    /// Sends as much of one caller-retained raw payload as the stream accepts.
    /// Zero is backpressure while the connection is opening or its send window
    /// is full; the caller must retry the unchanged bytes.
    pub fn write(&mut self, transfer: &mut Transfer, bytes: &[u8]) -> Result<usize, NetError> {
        self.poll()?;
        if transfer.sent != transfer.request.len() {
            return Err(NetError::Invalid("raw write before the fixed request"));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let now = self.now();
        let socket = self.sockets.get_mut::<tcp::Socket>(transfer.socket);
        if socket.can_send() {
            let sent = socket.send_slice(bytes).map_err(|_| NetError::Reset)?;
            if sent != 0 {
                transfer.idle_at = now.saturating_add(IDLE_US);
            }
            return Ok(sent);
        }
        match socket.state() {
            tcp::State::Closed | tcp::State::CloseWait | tcp::State::LastAck => {
                Err(NetError::Reset)
            }
            _ => Ok(0),
        }
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
        if now >= transfer.idle_at {
            return Err(NetError::Timeout("TCP transfer"));
        }
        match socket.state() {
            tcp::State::Closed if !transfer.request.is_empty() && transfer.sent == 0 => {
                Err(NetError::Reset)
            }
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
                Ok(false) => self.wait_until(deadline.min(transfer.idle_at)),
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
        raw: bool,
        raw_sent: usize,
        frames: usize,
        drop_every: usize,
        swap_every: usize,
        ipv6: bool,
        dns_listener: Option<SocketHandle>,
        dns_queries: Vec<u16>,
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
                received: false,
                probes: Vec::new(),
                local_ipv6: Ipv6Addr::UNSPECIFIED,
                approved_ipv6: Vec::new(),
                rdnss: Default::default(),
                manage_ipv6: false,
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
                raw: false,
                raw_sent: 0,
                frames: 0,
                drop_every: 0,
                swap_every: 0,
                ipv6: false,
                dns_listener: None,
                dns_queries: Vec::new(),
            }
        }

        fn ipv6(size: u64, clock: TestClock) -> Self {
            use smoltcp::socket::udp;
            let mut lan = Self::new(size, clock);
            lan.ipv6 = true;
            lan.iface.update_ip_addrs(|addresses| {
                addresses.clear();
                for address in ["fe80::1", "2001:db8:1234::53"] {
                    addresses
                        .push(IpCidr::new(address.parse::<Ipv6Addr>().unwrap().into(), 64))
                        .unwrap();
                }
            });
            let mut dns = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
            );
            dns.bind(53).unwrap();
            lan.dns_listener = Some(lan.sockets.add(dns));
            lan
        }

        fn step(&mut self) {
            let now = Instant::from_micros(self.clock.0.get() as i64);
            self.iface.poll(now, &mut self.server, &mut self.sockets);
            if let Some(handle) = self.dns_listener {
                let dns = self.sockets.get_mut::<smoltcp::socket::udp::Socket>(handle);
                while dns.can_recv() {
                    let (query, endpoint) = dns.recv().unwrap();
                    assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
                    let mut end = 12;
                    while query[end] != 0 {
                        end += usize::from(query[end]) + 1;
                    }
                    end += 1;
                    let kind = u16::from_be_bytes([query[end], query[end + 1]]);
                    self.dns_queries.push(kind);
                    let mut reply = query[..end + 4].to_vec();
                    reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                    reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                    reply[8..12].fill(0);
                    reply.extend_from_slice(&[0xc0, 0x0c]);
                    reply.extend_from_slice(&kind.to_be_bytes());
                    reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                    assert_eq!(kind, 28, "IPv6-only link must query AAAA");
                    reply.extend_from_slice(&16u16.to_be_bytes());
                    reply.extend_from_slice(
                        &"2001:db8:1234::53".parse::<Ipv6Addr>().unwrap().octets(),
                    );
                    dns.send_slice(&reply, endpoint).unwrap();
                }
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(self.listener);
            while socket.can_recv() {
                socket
                    .recv(|bytes| {
                        self.request.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if self.raw {
                while self.raw_sent < self.request.len() && socket.can_send() {
                    let n = socket.send_slice(&self.request[self.raw_sent..]).unwrap();
                    self.raw_sent += n;
                }
            } else if self.reply.is_none() && self.request.windows(4).any(|w| w == b"\r\n\r\n") {
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
            if self.ipv6
                && frame.len() >= 62
                && frame[12..14] == [0x86, 0xdd]
                && frame[20] == 58
                && frame[54] == 133
            {
                self.client
                    .into
                    .borrow_mut()
                    .0
                    .push_back(automatic::tests::advertisement());
            }
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
        let mut s = Stack::new(lan, clock, 7);
        s.set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        })
        .unwrap();
        s
    }

    #[test]
    fn slaac_deadline_remains_visible_without_a_socket_deadline() {
        let clock = TestClock::default();
        let mut stack = Stack::new(Lan::ipv6(8192, clock.clone()), clock.clone(), 7);
        stack
            .set_config(Config {
                address: Ipv4Cidr::new(CLIENT_IP, 24),
                router: None,
                dns: Vec::new(),
            })
            .unwrap();
        stack.poll().unwrap();
        // The only socket is an idle DNS client. The emitted first RS still
        // owns a future retry timer even when no socket has a deadline.
        let delay = stack
            .iface
            .poll_delay(Instant::from_micros(clock.now_us() as i64), &stack.sockets)
            .expect("router discovery retry remains scheduled");
        assert!(delay > Duration::ZERO && delay <= Duration::from_secs(4));
    }

    #[test]
    fn an_existing_ipv4_default_route_does_not_block_ipv6_router_admission() {
        let clock = TestClock::default();
        let mut stack = Stack::new(Lan::ipv6(8192, clock.clone()), clock.clone(), 7);
        // An authored already-configured IPv4 interface must not be erased
        // by the DHCP socket's legitimate initial Deconfigured event.
        stack
            .set_config(Config {
                address: Ipv4Cidr::new(CLIENT_IP, 24),
                router: Some(SERVER_IP),
                dns: Vec::new(),
            })
            .unwrap();
        for _ in 0..1000 {
            stack.poll().unwrap();
            if stack.ipv6_ready() {
                break;
            }
            clock.0.set(clock.0.get() + 10_000);
        }
        assert!(stack.ipv6_ready());
        assert!(stack.iface.routes().get_default_ipv4_route().is_some());
        assert!(stack.iface.routes().get_default_ipv6_route().is_some());
        assert_eq!(stack.config().unwrap().router, Some(SERVER_IP));
    }

    #[test]
    fn ipv6_only_ra_rdnss_aaaa_and_tcp_range_are_usable_without_ipv4() {
        let clock = TestClock::default();
        let lan = Lan::ipv6(8192, clock.clone());
        let mut stack = Stack::new(lan, clock, 7);
        let configuration = stack.automatic().unwrap();
        assert!(stack.config().is_none());
        assert!(!configuration.dns.is_empty());
        let mut bytes = Vec::new();
        assert_eq!(
            stack
                .get_range("restore.test", "/source", 7, 4102, |chunk| bytes
                    .extend_from_slice(chunk))
                .unwrap(),
            8192
        );
        assert_eq!(bytes, (7..4103).map(pattern).collect::<Vec<_>>());
        assert_eq!(stack.phy.link.dns_queries, vec![28]);
        assert!(
            stack
                .iface
                .ip_addrs()
                .iter()
                .all(|address| matches!(address, IpCidr::Ipv6(_)))
        );
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
            .unwrap_or_else(|error| {
                panic!(
                    "{error:?}; received={} server_sent={} frames={} clock={}",
                    body.len(),
                    s.phy.link.sent,
                    s.phy.link.frames,
                    s.phy.link.clock.0.get()
                )
            });
        assert_eq!(size, 1 << 40);
        assert_eq!(body.len() as u64, length);
        assert!(body.iter().zip(start..).all(|(&b, at)| b == pattern(at)));
        let request = core::str::from_utf8(&s.link_mut().request).unwrap();
        assert!(request.starts_with("GET /a.ipsw HTTP/1.1\r\nHost: 10.0.2.2\r\n"));
    }

    #[test]
    fn a_network_without_dhcp_reports_no_ipv4_lease() {
        /// Each reading advances 100 ms.
        struct Coarse(Cell<u64>);
        impl Clock for Coarse {
            fn now_us(&self) -> u64 {
                self.0.set(self.0.get() + 100_000);
                self.0.get()
            }
        }
        let silent = End {
            mac: CLIENT,
            out: Rc::default(),
            into: Rc::default(),
        };
        let mut stack = Stack::new(silent, Coarse(Cell::new(0)), 7);
        match stack.dhcp() {
            Err(NetError::Dhcp(why)) => assert!(why.starts_with("no IPv4 lease"), "{why}"),
            other => panic!("{other:?}"),
        }
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

    #[test]
    fn a_signalling_link_sleeps_until_the_deadline_when_nothing_arrives() {
        /// A clock whose sleeps jump to the time asked for.
        #[derive(Clone, Default)]
        struct Sleeping(Rc<Cell<u64>>, Rc<Cell<usize>>);
        impl Clock for Sleeping {
            fn now_us(&self) -> u64 {
                self.0.get()
            }
            fn sleep(&self, until_us: u64) {
                self.1.set(self.1.get() + 1);
                self.0.set(until_us.max(self.0.get()));
            }
        }
        struct Signalling(End);
        impl Link for Signalling {
            fn mac(&self) -> Mac {
                self.0.mac
            }
            fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
                self.0.transmit(frame)
            }
            fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
                self.0.receive()
            }
            fn signals(&self) -> bool {
                true
            }
        }
        let clock = Sleeping::default();
        let silent = Signalling(End {
            mac: CLIENT,
            out: Rc::default(),
            into: Rc::default(),
        });
        let mut stack = Stack::new(silent, clock.clone(), 7);
        match stack.dhcp() {
            Err(NetError::Dhcp(why)) => assert!(why.starts_with("no IPv4 lease"), "{why}"),
            other => panic!("{other:?}"),
        }
        // DHCP's retransmissions bound each sleep, so the 30 s wait takes a
        // handful of sleeps rather than a poll per clock reading.
        assert!((1..64).contains(&clock.1.get()), "{}", clock.1.get());
        assert!(clock.0.get() >= DHCP_WAIT_US);
    }

    #[test]
    fn a_name_keeps_its_address_and_falls_back_to_it_when_a_lookup_fails() {
        let clock = TestClock::default();
        // No DNS server is configured, so every lookup fails.
        let mut s = stack(Lan::new(100, clock.clone()), clock);
        assert!(matches!(s.resolve("cdn.example"), Err(NetError::Dns(_))));
        let now = s.now();
        s.resolved
            .push((String::from("cdn.example"), SERVER_IP.into(), now));
        assert_eq!(s.resolve("cdn.example"), Ok(SERVER_IP.into()));
        s.resolved[0].2 = now.wrapping_sub(RESOLVED_US);
        assert_eq!(s.resolve("cdn.example"), Ok(SERVER_IP.into()));
        assert_eq!(s.resolve("10.0.2.2"), Ok(SERVER_IP.into()));
    }

    #[test]
    fn raw_stream_retains_partial_dynamic_writes_and_opaque_replies() {
        let clock = TestClock::default();
        let mut lan = Lan::new(0, clock.clone());
        lan.raw = true;
        let mut s = stack(lan, clock);
        let payload: Vec<u8> = (0..200_000).map(|n| (n * 37) as u8).collect();
        let mut transfer = s.open_raw("10.0.2.2", 80, 1 << 20).unwrap();
        let (mut sent, mut received) = (0, Vec::new());
        for _ in 0..1_000_000 {
            if sent < payload.len() {
                sent += s.write(&mut transfer, &payload[sent..]).unwrap();
            }
            let done = s
                .read(&mut transfer, |bytes, _| {
                    received.extend_from_slice(bytes);
                    Ok(received.len() == payload.len())
                })
                .unwrap();
            if done {
                break;
            }
        }
        assert_eq!(sent, payload.len());
        assert_eq!(received, payload);
        s.close(transfer);
    }
}
