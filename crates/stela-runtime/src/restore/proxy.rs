//! PurpleReverseProxy control/connection peer. Evidence: pinned
//! libimobiledevice reverse_proxy.c, not usbmux wire framing. Binary plists
//! have LE lengths. Destination requests are returned only after the original
//! acknowledgement and command echo have reached the guest; the caller owns
//! DNS, TCP and the subsequent opaque byte relay.
use super::{
    Error, Result,
    driver::Ports,
    plist::{Limits, Value},
    stream::{ByteStream, Endian, Framed, Input, Output},
};
use alloc::{string::String, vec::Vec};
use core::task::Poll;
pub const CONTROL_PORT: u16 = 1082;
const BEGIN: &[u8] = b"BeginCtrl\0";
const LEGACY: &[u8] = b"HelloCtrl\0";
const HELLO: &[u8] = b"HelloConn\0";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Two,
    One,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Connection { port: u16, version: Version },
    Shutdown,
}
#[derive(Clone, Copy)]
#[repr(u8)]
enum Phase {
    Connect,
    Hello,
    Offer,
    Reply,
    LegacyPort,
    Commands,
    FallbackClose,
    ShutdownClose,
    Done,
    Failed,
}
struct PortStream<'a, P: Ports> {
    ports: &'a mut P,
    handle: P::Handle,
}
impl<P: Ports> ByteStream for PortStream<'_, P> {
    fn read(&mut self, bytes: &mut [u8]) -> Poll<Result<usize>> {
        self.ports.read(self.handle, bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Poll<Result<usize>> {
        self.ports.write(self.handle, bytes)
    }
}
pub struct Control<H> {
    stream: Option<H>,
    phase: Phase,
    version: Version,
    port: u16,
    output: Output,
    input: Input,
    frame: Framed,
    pub v2_failure: Option<Error>,
}
impl<H: Copy + Eq> Default for Control<H> {
    fn default() -> Self {
        Self::new()
    }
}
impl<H: Copy + Eq> Control<H> {
    pub fn new() -> Self {
        Self {
            stream: None,
            phase: Phase::Connect,
            version: Version::Two,
            port: 0,
            output: Output::default(),
            input: Input::default(),
            frame: Framed::new(Endian::Little, Limits::default()),
            v2_failure: None,
        }
    }
    pub fn poll(&mut self, ports: &mut impl Ports<Handle = H>) -> Poll<Result<Event>> {
        if matches!(self.phase, Phase::FallbackClose) {
            if let Some(handle) = self.stream {
                match ports.close(handle) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.phase = Phase::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => self.stream = None,
                }
            }
            self.phase = Phase::Connect;
        }
        if matches!(self.phase, Phase::ShutdownClose) {
            if let Some(handle) = self.stream {
                match ports.close(handle) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.phase = Phase::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => self.stream = None,
                }
            }
            self.phase = Phase::Done;
            return Poll::Ready(Ok(Event::Shutdown));
        }
        let r = self.step(ports);
        if let Poll::Ready(Err(e)) = r {
            if self.version == Version::Two
                && matches!(
                    self.phase,
                    Phase::Connect | Phase::Hello | Phase::Offer | Phase::Reply
                )
            {
                self.v2_failure = Some(e);
                self.version = Version::One;
                self.phase = Phase::FallbackClose;
                self.output = Output::default();
                self.input = Input::default();
                self.frame = Framed::new(Endian::Little, Limits::default());
                return Poll::Pending;
            }
            self.phase = Phase::Failed;
            return Poll::Ready(Err(e));
        }
        r
    }

    /// Retire any control stream and return to a fresh v2 negotiation. The
    /// guest advertises PurpleReverseProxy late in restore, so an earlier mux
    /// refusal is service-discovery state rather than a permanent session
    /// failure. The caller supplies its own bounded retry cadence.
    pub fn restart(&mut self, ports: &mut impl Ports<Handle = H>) -> Poll<Result<()>> {
        if let Some(handle) = self.stream {
            match ports.close(handle) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        *self = Self::new();
        Poll::Ready(Ok(()))
    }

    /// The control handshake has supplied the separate connection port and
    /// is now waiting for commands. A scheduler may time out only earlier
    /// phases; an established control is long-lived and idle.
    pub fn ready(&self) -> bool {
        matches!(
            self.phase,
            Phase::Commands | Phase::ShutdownClose | Phase::Done
        )
    }

    /// Opaque monotonic-work marker for a scheduler's stalled-handshake
    /// deadline. Values changing means protocol bytes or phases advanced;
    /// their representation is not a wire or persistence contract.
    pub fn progress(&self) -> (Version, u8, u64, u64) {
        (
            self.version,
            self.phase as u8,
            self.output.written(),
            self.frame.written(),
        )
    }
    fn step(&mut self, ports: &mut impl Ports<Handle = H>) -> Poll<Result<Event>> {
        if matches!(self.phase, Phase::Failed) {
            return Poll::Ready(Err(Error::Invalid("proxy control failed")));
        }
        if matches!(self.phase, Phase::Done) {
            return Poll::Pending;
        }
        if matches!(self.phase, Phase::Connect) {
            self.stream = Some(match ports.open(CONTROL_PORT) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            });
            self.output.queue(
                if self.version == Version::Two {
                    BEGIN
                } else {
                    LEGACY
                }
                .to_vec(),
                32,
            )?;
            self.phase = Phase::Hello;
            return Poll::Pending;
        }
        let s = self
            .stream
            .as_ref()
            .copied()
            .ok_or(Error::Invalid("proxy stream absent"))?;
        let mut s = PortStream { ports, handle: s };
        if self.output.is_pending() {
            return match self.output.poll(&mut s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }
        if self.frame.sending() {
            return match self.frame.poll_send(&mut s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }
        match self.phase {
            Phase::Hello => {
                if self.version == Version::Two {
                    self.frame.queue(
                        &Value::dict([
                            ("Command", Value::from("BeginCtrl")),
                            ("CtrlProtoVersion", Value::Integer(2)),
                        ]),
                        true,
                    )?;
                    self.phase = Phase::Offer;
                } else {
                    let b = match self.input.poll(&mut s, LEGACY.len() - 1) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(v) => v?,
                    };
                    if b != LEGACY[..LEGACY.len() - 1] {
                        return Poll::Ready(Err(Error::Invalid("proxy HelloCtrl reply")));
                    }
                    self.phase = Phase::LegacyPort;
                }
            }
            Phase::Offer => self.phase = Phase::Reply,
            Phase::Reply => {
                let v = match self.frame.poll_receive(&mut s) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                self.port = port(v.required("ConnPort")?.uint()?)?;
                self.phase = Phase::Commands;
            }
            Phase::LegacyPort => {
                let b = match self.input.poll(&mut s, 2) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                self.port = port(u16::from_le_bytes(b.try_into().unwrap()) as u64)?;
                self.phase = Phase::Commands;
            }
            Phase::Commands => {
                let b = match self.input.poll(&mut s, 4) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                match u32::from_le_bytes(b.try_into().unwrap()) {
                    1 => {
                        return Poll::Ready(Ok(Event::Connection {
                            port: self.port,
                            version: self.version,
                        }));
                    }
                    2 => {
                        self.phase = Phase::ShutdownClose;
                        return Poll::Pending;
                    }
                    _ => {
                        return Poll::Ready(Err(Error::Invalid(
                            "unsupported proxy control command",
                        )));
                    }
                }
            }
            Phase::Connect
            | Phase::FallbackClose
            | Phase::ShutdownClose
            | Phase::Done
            | Phase::Failed => {}
        }
        Poll::Pending
    }
}
fn port(n: u64) -> Result<u16> {
    u16::try_from(n)
        .ok()
        .filter(|n| *n != 0)
        .ok_or(Error::Invalid("proxy port outside 1..=65535"))
}
#[derive(Clone, Copy)]
#[repr(u8)]
enum PeerPhase {
    Hello,
    Command,
    Plist,
    ConnectAck,
    ConnectHeader,
    SocksRequest,
    ConnectDestination,
    ConnectReply,
    Relaying,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}
pub struct Peer {
    version: Version,
    phase: PeerPhase,
    output: Output,
    input: Input,
    frame: Framed,
    host_bytes: usize,
    destination: Option<Destination>,
    ping_seen: bool,
    socks5: bool,
    observed_header: Option<[u8; 3]>,
}
impl Peer {
    pub fn new(version: Version) -> Self {
        let mut output = Output::default();
        output.queue(HELLO.to_vec(), 32).unwrap();
        Self {
            version,
            phase: PeerPhase::Hello,
            output,
            input: Input::default(),
            frame: Framed::new(Endian::Little, Limits::default()),
            host_bytes: 0,
            destination: None,
            ping_seen: false,
            socks5: false,
            observed_header: None,
        }
    }
    /// Protocol-only state for bounded scheduler diagnostics. No peer payload
    /// or destination bytes are exposed here.
    pub fn state(&self) -> &'static str {
        match self.phase {
            PeerPhase::Hello => "hello",
            PeerPhase::Command => "command",
            PeerPhase::Plist => "plist",
            PeerPhase::ConnectAck => "connect-ack",
            PeerPhase::ConnectHeader => "connect-header",
            PeerPhase::SocksRequest => "socks-request",
            PeerPhase::ConnectDestination => "connect-destination",
            PeerPhase::ConnectReply => "connect-reply",
            PeerPhase::Relaying => "relaying",
            PeerPhase::Failed => "failed",
        }
    }
    /// A Ping's Pong frame has completely left the host. The reference peer
    /// closes this connection after Pong, so the following EOF is success.
    pub fn ping_answered(&self) -> bool {
        self.ping_seen && !self.frame.sending()
    }
    /// First post-command protocol bytes, for bounded framing diagnostics.
    /// These bytes contain only the SOCKS version, command, and reserved or
    /// address-type fields; destination and application payload stay private.
    pub fn observed_header(&self) -> Option<[u8; 3]> {
        self.observed_header
    }
    pub fn poll(&mut self, s: &mut impl ByteStream) -> Poll<Result<Destination>> {
        let r = self.step(s);
        if matches!(r, Poll::Ready(Err(_))) {
            self.phase = PeerPhase::Failed;
        }
        r
    }
    fn step(&mut self, s: &mut impl ByteStream) -> Poll<Result<Destination>> {
        if matches!(self.phase, PeerPhase::Failed) {
            return Poll::Ready(Err(Error::Invalid("proxy peer failed")));
        }
        if self.output.is_pending() {
            return match self.output.poll(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }
        if self.frame.sending() {
            return match self.frame.poll_send(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }
        match self.phase {
            PeerPhase::Hello => {
                if self.version == Version::Two {
                    let v = match self.frame.poll_receive(s) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(v) => v?,
                    };
                    if v.required("Command")?.string()? != "HelloConn" {
                        return Poll::Ready(Err(super::refuse("unexpected proxy HelloConn", &v)));
                    }
                } else {
                    let b = match self.input.poll(s, HELLO.len()) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(v) => v?,
                    };
                    if b != HELLO {
                        return Poll::Ready(Err(Error::Invalid("proxy HelloConn reply")));
                    }
                }
                self.phase = PeerPhase::Command;
            }
            PeerPhase::Command => {
                let b = match self.input.poll(s, 2) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                self.phase = match u16::from_le_bytes(b.try_into().unwrap()) {
                    0xbbaa => PeerPhase::Plist,
                    0x105 => {
                        // Purple gates the proxied SOCKS bytes on this command
                        // success. It is distinct from the subsequent SOCKS5
                        // method and CONNECT replies.
                        self.output.queue(5u16.to_le_bytes().to_vec(), 2)?;
                        PeerPhase::ConnectAck
                    }
                    _ => {
                        return Poll::Ready(Err(Error::Invalid(
                            "unsupported proxy connection command",
                        )));
                    }
                };
            }
            PeerPhase::Plist => {
                let v = match self.frame.poll_receive(s) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                if v.required("Command")?.string()? != "Ping" {
                    return Poll::Ready(Err(super::refuse("unsupported proxy plist command", &v)));
                }
                self.frame
                    .queue(&Value::dict([("Pong", Value::Boolean(true))]), true)?;
                self.ping_seen = true;
                self.phase = PeerPhase::Command;
            }
            PeerPhase::ConnectAck => self.phase = PeerPhase::ConnectHeader,
            PeerPhase::ConnectHeader => {
                let b = match self.input.poll(s, 3) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                self.observed_header = Some([b[0], b[1], b[2]]);
                if b[0] == 5 && b[1] == 1 && b[2] == 0 {
                    // Modern Purple forwards the SOCKS5 method exchange. The
                    // little-endian protocol success word is also the SOCKS5
                    // no-auth selection. Purple then forwards CONNECT whole.
                    self.output.queue(5u16.to_le_bytes().to_vec(), 2)?;
                    self.socks5 = true;
                    self.phase = PeerPhase::SocksRequest;
                } else if b[0] == 0 && b[1] == 5 && b[2] == 1 {
                    // On current Purple, the first two bytes of each SOCKS5
                    // message are the little-endian 0x105 command itself.
                    // This is the one-byte method tail immediately followed
                    // by the next CONNECT command. The zero is the method
                    // list's tail, not part of either SOCKS5 reply, so consume
                    // it without echoing it. The second command
                    // acknowledgement is prepended to the destination echo.
                    self.socks5 = true;
                    self.phase = PeerPhase::ConnectHeader;
                } else if b[0] == 0 && b[1] == 3 && b[2] != 0 {
                    // Older Purple strips SOCKS5's version and command, and
                    // uses the command success already sent before the
                    // destination is echoed back.
                    self.host_bytes = b[2] as usize;
                    self.phase = PeerPhase::ConnectDestination;
                } else {
                    return Poll::Ready(Err(Error::Invalid(
                        "unsupported proxy destination encoding",
                    )));
                }
            }
            PeerPhase::SocksRequest => {
                let b = match self.input.poll(s, 5) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                if b[0] != 5 || b[1] != 1 || b[2] != 0 || b[3] != 3 || b[4] == 0 {
                    return Poll::Ready(Err(Error::Invalid(
                        "unsupported SOCKS5 destination encoding",
                    )));
                }
                self.host_bytes = b[4] as usize;
                self.phase = PeerPhase::ConnectDestination;
            }
            PeerPhase::ConnectDestination => {
                let b = match self.input.poll(s, self.host_bytes + 2) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                let host = core::str::from_utf8(&b[..self.host_bytes])
                    .map_err(|_| Error::Invalid("proxy host UTF-8"))?;
                if host.contains('\0') {
                    return Poll::Ready(Err(Error::Invalid("proxy host NUL")));
                }
                let port = u16::from_be_bytes(b[self.host_bytes..].try_into().unwrap());
                if port == 0 {
                    return Poll::Ready(Err(Error::Invalid("proxy destination port zero")));
                }
                let mut reply = Vec::with_capacity(self.host_bytes + 7);
                if self.socks5 {
                    reply.extend_from_slice(&5u16.to_le_bytes());
                }
                reply.extend_from_slice(&[0, 3, self.host_bytes as u8]);
                reply.extend_from_slice(host.as_bytes());
                reply.extend_from_slice(&port.to_be_bytes());
                self.output.queue(reply, 264)?;
                self.destination = Some(Destination {
                    host: String::from(host),
                    port,
                });
                self.phase = PeerPhase::ConnectReply;
            }
            PeerPhase::ConnectReply => {
                self.phase = PeerPhase::Relaying;
                return Poll::Ready(Ok(self.destination.take().expect("destination parsed")));
            }
            PeerPhase::Relaying => return Poll::Pending,
            PeerPhase::Failed => unreachable!(),
        }
        Poll::Pending
    }
}
#[cfg(test)]
mod tests {
    use super::super::stream::tests::Memory;
    use super::*;
    struct FakePorts {
        streams: alloc::vec::Vec<Memory>,
        next: usize,
        connects: usize,
        closed: alloc::vec::Vec<usize>,
    }
    impl Ports for FakePorts {
        type Handle = usize;
        fn open(&mut self, p: u16) -> Poll<Result<usize>> {
            assert_eq!(p, CONTROL_PORT);
            self.connects += 1;
            if self.next == self.streams.len() {
                return Poll::Ready(Err(Error::Invalid("no stream")));
            }
            let handle = self.next;
            self.next += 1;
            Poll::Ready(Ok(handle))
        }
        fn read(&mut self, handle: usize, bytes: &mut [u8]) -> Poll<Result<usize>> {
            self.streams[handle].read(bytes)
        }
        fn write(&mut self, handle: usize, bytes: &[u8]) -> Poll<Result<usize>> {
            self.streams[handle].write(bytes)
        }
        fn close(&mut self, handle: usize) -> Poll<Result<()>> {
            self.closed.push(handle);
            Poll::Ready(Ok(()))
        }
    }
    fn frame(v: Value) -> alloc::vec::Vec<u8> {
        let b = super::super::plist::encode_binary(&v, Limits::default()).unwrap();
        [&(b.len() as u32).to_le_bytes()[..], &b].concat()
    }
    #[test]
    fn protocol_two_and_fresh_legacy_fallback_preserve_short_fields() {
        for fallback in [false, true] {
            let mut input = if fallback {
                [b"HelloCtrl".as_slice(), &4321u16.to_le_bytes()].concat()
            } else {
                frame(Value::dict([("ConnPort", Value::Integer(4321))]))
            };
            input.extend(1u32.to_le_bytes());
            input.extend(2u32.to_le_bytes());
            let mut streams = alloc::vec::Vec::new();
            if fallback {
                streams.push(Memory::new(vec![], 1));
            }
            streams.push(Memory::new(input, 1));
            let mut ports = FakePorts {
                streams,
                next: 0,
                connects: 0,
                closed: alloc::vec::Vec::new(),
            };
            let mut c = Control::<usize>::new();
            let mut events = alloc::vec::Vec::new();
            for _ in 0..5000 {
                if let Poll::Ready(v) = c.poll(&mut ports) {
                    events.push(v.unwrap());
                    if events.len() == 2 {
                        break;
                    }
                }
            }
            assert_eq!(
                events,
                vec![
                    Event::Connection {
                        port: 4321,
                        version: if fallback { Version::One } else { Version::Two }
                    },
                    Event::Shutdown
                ]
            );
            assert_eq!(ports.connects, if fallback { 2 } else { 1 });
            assert_eq!(ports.closed.len(), if fallback { 2 } else { 1 });
            assert_eq!(c.v2_failure.is_some(), fallback);
            assert!(c.ready());
        }
    }
    #[test]
    fn peer_answers_ping_acknowledges_and_echoes_destination_before_relay() {
        let mut input = HELLO.to_vec();
        input.extend(0xbbaau16.to_le_bytes());
        input.extend(frame(Value::dict([("Command", Value::from("Ping"))])));
        input.extend(0x105u16.to_le_bytes());
        input.extend([0, 3, 4]);
        input.extend(b"test");
        input.extend(443u16.to_be_bytes());
        let mut s = Memory::new(input, 1);
        let mut p = Peer::new(Version::One);
        let mut destination = None;
        for _ in 0..5000 {
            if let Poll::Ready(result) = p.poll(&mut s) {
                destination = Some(result.unwrap());
                break;
            }
        }
        assert_eq!(
            destination,
            Some(Destination {
                host: String::from("test"),
                port: 443,
            })
        );
        assert!(s.output.starts_with(HELLO));
        let mut echoed = 5u16.to_le_bytes().to_vec();
        echoed.extend([0, 3, 4]);
        echoed.extend(b"test");
        echoed.extend(443u16.to_be_bytes());
        assert!(s.output.ends_with(&echoed));
    }

    #[test]
    fn peer_answers_socks5_method_before_connect_request_arrives() {
        let mut input = HELLO.to_vec();
        input.extend(0x105u16.to_le_bytes());
        input.extend([5, 1, 0]);
        let mut stream = Memory::new(input, 1);
        let mut peer = Peer::new(Version::One);
        for _ in 0..5000 {
            assert!(matches!(peer.poll(&mut stream), Poll::Pending));
            if peer.state() == "socks-request" && stream.output.len() == HELLO.len() + 4 {
                break;
            }
        }
        assert_eq!(peer.state(), "socks-request");
        let mut expected = HELLO.to_vec();
        expected.extend([5, 0, 5, 0]);
        assert_eq!(stream.output, expected);
    }

    #[test]
    fn peer_accepts_full_socks5_destination_and_returns_success() {
        let mut input = HELLO.to_vec();
        input.extend(0x105u16.to_le_bytes());
        input.extend([5, 1, 0]);
        input.extend([5, 1, 0, 3, 4]);
        input.extend(b"test");
        input.extend(443u16.to_be_bytes());
        let mut stream = Memory::new(input, 1);
        let mut peer = Peer::new(Version::One);
        let destination = (0..5000).find_map(|_| match peer.poll(&mut stream) {
            Poll::Ready(result) => Some(result.unwrap()),
            Poll::Pending => None,
        });
        assert_eq!(
            destination,
            Some(Destination {
                host: String::from("test"),
                port: 443,
            })
        );
        let mut expected = HELLO.to_vec();
        expected.extend([5, 0, 5, 0, 5, 0, 0, 3, 4]);
        expected.extend(b"test");
        expected.extend(443u16.to_be_bytes());
        assert_eq!(stream.output, expected);
    }

    #[test]
    fn peer_accepts_split_command_socks5_exchange_used_by_current_purple() {
        let mut input = HELLO.to_vec();
        input.extend(0x105u16.to_le_bytes());
        input.extend([0, 5, 1]);
        input.extend([0, 3, 4]);
        input.extend(b"test");
        input.extend(443u16.to_be_bytes());
        let mut stream = Memory::new(input, 1);
        let mut peer = Peer::new(Version::One);
        let destination = (0..5000).find_map(|_| match peer.poll(&mut stream) {
            Poll::Ready(result) => Some(result.unwrap()),
            Poll::Pending => None,
        });
        assert_eq!(
            destination,
            Some(Destination {
                host: String::from("test"),
                port: 443,
            })
        );
        let mut expected = HELLO.to_vec();
        expected.extend([5, 0, 5, 0, 0, 3, 4]);
        expected.extend(b"test");
        expected.extend(443u16.to_be_bytes());
        assert_eq!(stream.output, expected);
    }

    #[test]
    fn refused_control_can_retire_and_restart_when_the_service_appears_late() {
        let mut input = frame(Value::dict([("ConnPort", Value::Integer(4321))]));
        input.extend(1u32.to_le_bytes());
        let mut ports = FakePorts {
            // Both protocol attempts are refused before a later v2 service
            // accepts the control negotiation.
            streams: vec![
                Memory::new(vec![], 1),
                Memory::new(vec![], 1),
                Memory::new(input, 1),
            ],
            next: 0,
            connects: 0,
            closed: vec![],
        };
        let mut control = Control::<usize>::new();
        assert!(!control.ready());
        let failure = (0..5000).find_map(|_| match control.poll(&mut ports) {
            Poll::Ready(Err(error)) => Some(error),
            _ => None,
        });
        assert!(failure.is_some());
        assert_eq!(ports.connects, 2);
        assert_eq!(control.restart(&mut ports), Poll::Ready(Ok(())));
        assert_eq!(ports.closed, vec![0, 1]);

        let event = (0..5000).find_map(|_| match control.poll(&mut ports) {
            Poll::Ready(Ok(event)) => Some(event),
            Poll::Ready(Err(error)) => panic!("late service refused: {error}"),
            Poll::Pending => None,
        });
        assert_eq!(
            event,
            Some(Event::Connection {
                port: 4321,
                version: Version::Two,
            })
        );
        assert!(control.ready());
        assert_eq!(ports.connects, 3);
    }
}
