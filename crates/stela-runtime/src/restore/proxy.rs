//! PurpleReverseProxy control/connection peer. Evidence: pinned
//! libimobiledevice reverse_proxy.c, not usbmux wire framing. Binary plists
//! have LE lengths. Offline connection requests fail with destination context;
//! no unconditional success acknowledgement or Apple network access.
use super::{
    Error, Result,
    plist::{Limits, Value},
    stream::{ByteStream, Endian, Framed, Input, Mux, Output},
};
use alloc::{format, string::ToString};
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
enum Phase {
    Connect,
    Hello,
    Offer,
    Reply,
    LegacyPort,
    Commands,
    Done,
    Failed,
}
pub struct Control<M: Mux> {
    stream: Option<M::Stream>,
    phase: Phase,
    version: Version,
    port: u16,
    output: Output,
    input: Input,
    frame: Framed,
    pub v2_failure: Option<Error>,
}
impl<M: Mux> Default for Control<M> {
    fn default() -> Self {
        Self::new()
    }
}
impl<M: Mux> Control<M> {
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
    pub fn poll(&mut self, mux: &mut M) -> Poll<Result<Event>> {
        let r = self.step(mux);
        if let Poll::Ready(Err(e)) = r {
            if self.version == Version::Two
                && matches!(
                    self.phase,
                    Phase::Connect | Phase::Hello | Phase::Offer | Phase::Reply
                )
            {
                self.v2_failure = Some(e);
                self.version = Version::One;
                self.stream = None;
                self.phase = Phase::Connect;
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
    fn step(&mut self, mux: &mut M) -> Poll<Result<Event>> {
        if matches!(self.phase, Phase::Failed) {
            return Poll::Ready(Err(Error::Invalid("proxy control failed")));
        }
        if matches!(self.phase, Phase::Done) {
            return Poll::Pending;
        }
        if matches!(self.phase, Phase::Connect) {
            self.stream = Some(match mux.connect(CONTROL_PORT) {
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
            .as_mut()
            .ok_or(Error::Invalid("proxy stream absent"))?;
        if self.output.is_pending() {
            return match self.output.poll(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }
        if self.frame.sending() {
            return match self.frame.poll_send(s) {
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
                    let b = match self.input.poll(s, LEGACY.len() - 1) {
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
                let v = match self.frame.poll_receive(s) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                self.port = port(v.required("ConnPort")?.uint()?)?;
                self.phase = Phase::Commands;
            }
            Phase::LegacyPort => {
                let b = match self.input.poll(s, 2) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                self.port = port(u16::from_le_bytes(b.try_into().unwrap()) as u64)?;
                self.phase = Phase::Commands;
            }
            Phase::Commands => {
                let b = match self.input.poll(s, 4) {
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
                        self.phase = Phase::Done;
                        return Poll::Ready(Ok(Event::Shutdown));
                    }
                    _ => {
                        return Poll::Ready(Err(Error::Invalid(
                            "unsupported proxy control command",
                        )));
                    }
                }
            }
            _ => {}
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
enum PeerPhase {
    Hello,
    Command,
    Plist,
    ConnectHeader,
    ConnectDestination,
    Failed,
}
pub struct Peer {
    version: Version,
    phase: PeerPhase,
    output: Output,
    input: Input,
    frame: Framed,
    host_bytes: usize,
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
        }
    }
    pub fn poll(&mut self, s: &mut impl ByteStream) -> Poll<Result<()>> {
        let r = self.step(s);
        if matches!(r, Poll::Ready(Err(_))) {
            self.phase = PeerPhase::Failed;
        }
        r
    }
    fn step(&mut self, s: &mut impl ByteStream) -> Poll<Result<()>> {
        if matches!(self.phase, PeerPhase::Failed) {
            return Poll::Ready(Err(Error::Invalid("proxy peer failed")));
        }
        if self.output.is_pending() {
            return match self.output.poll(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                r => r,
            };
        }
        if self.frame.sending() {
            return match self.frame.poll_send(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                r => r,
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
                    0x105 => PeerPhase::ConnectHeader,
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
                self.phase = PeerPhase::Command;
            }
            PeerPhase::ConnectHeader => {
                let b = match self.input.poll(s, 3) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                if b[0] != 0 || b[1] != 3 || b[2] == 0 {
                    return Poll::Ready(Err(Error::Invalid(
                        "unsupported proxy destination encoding",
                    )));
                }
                self.host_bytes = b[2] as usize;
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
                return Poll::Ready(Err(super::refuse(
                    format!("offline proxy destination unavailable: {host}:{port}"),
                    &Value::dict([
                        ("Host", Value::String(host.to_string())),
                        ("Port", Value::Integer(port as u64)),
                    ]),
                )));
            }
            PeerPhase::Failed => unreachable!(),
        }
        Poll::Pending
    }
}
#[cfg(test)]
mod tests {
    use super::super::stream::tests::Memory;
    use super::*;
    struct FakeMux {
        inputs: alloc::collections::VecDeque<Memory>,
        connects: usize,
    }
    impl Mux for FakeMux {
        type Stream = Memory;
        fn connect(&mut self, p: u16) -> Poll<Result<Memory>> {
            assert_eq!(p, CONTROL_PORT);
            self.connects += 1;
            Poll::Ready(self.inputs.pop_front().ok_or(Error::Invalid("no stream")))
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
            let mut inputs = alloc::collections::VecDeque::new();
            if fallback {
                inputs.push_back(Memory::new(vec![], 1));
            }
            inputs.push_back(Memory::new(input, 1));
            let mut mux = FakeMux {
                inputs,
                connects: 0,
            };
            let mut c = Control::new();
            let mut events = alloc::vec::Vec::new();
            for _ in 0..5000 {
                if let Poll::Ready(v) = c.poll(&mut mux) {
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
            assert_eq!(mux.connects, if fallback { 2 } else { 1 });
            assert_eq!(c.v2_failure.is_some(), fallback);
        }
    }
    #[test]
    fn peer_answers_ping_and_refuses_remote_destination_without_success_ack() {
        let mut input = HELLO.to_vec();
        input.extend(0xbbaau16.to_le_bytes());
        input.extend(frame(Value::dict([("Command", Value::from("Ping"))])));
        input.extend(0x105u16.to_le_bytes());
        input.extend([0, 3, 4]);
        input.extend(b"test");
        input.extend(443u16.to_be_bytes());
        let mut s = Memory::new(input, 1);
        let mut p = Peer::new(Version::One);
        let mut error = None;
        for _ in 0..5000 {
            if let Poll::Ready(Err(e)) = p.poll(&mut s) {
                error = Some(e);
                break;
            }
        }
        let Error::Refused { reason, .. } = error.unwrap() else {
            panic!("destination context missing")
        };
        assert!(reason.contains("test:443"));
        assert!(s.output.starts_with(HELLO));
        assert!(!s.output.ends_with(&5u16.to_le_bytes()));
    }
}
