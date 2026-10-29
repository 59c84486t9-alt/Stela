//! Control-channel dispatch to a router configuration owner.
//!
//! This is the raw control transport, not a capability/register template.
//! Every configuration access, error, timestamp, notification and reset comes
//! from the required backend. No backend or machine admission is supplied.
use super::control::{Address, Body, Header, Packet};
use super::{Accepted, Consumer, Direction, Frame, Options, Transmit};
use crate::Result;
use alloc::{boxed::Box, vec::Vec};
use stela_contracts::Refusal;
use stela_contracts::refuse;

pub mod cio;

/// A real routed hardware error, distinct from a missing model requirement.
pub struct Failure {
    pub route: u64,
    pub port: u8,
    pub code: u8,
}
/// Native completion time and the outcome of a configuration access.
/// The backend owns timestamp encoding; it must not substitute scheduled time.
/// `Ok(None)` means accepted without a reply (for example a router reset that
/// destroys its return route). It never means successful configuration data.
pub struct Completion<T> {
    pub timestamp: u32,
    pub result: Result<Option<T>, Failure>,
}
pub struct Read {
    pub upstream_port: u8,
    pub data: Vec<u32>,
}
pub struct Notification {
    pub timestamp: u32,
    pub packet: Packet,
}

/// Required hardware configuration/reset owner. Outer errors mean an explicit
/// model requirement, with no committed effects. Inner failures are real wire
/// errors returned by the router. A successful read must return exactly the
/// requested word count and an upstream adapter. No sparse-zero bank,
/// always-success writes or implied reset completion is supplied here.
pub trait Configuration {
    fn read(&mut self, route: u64, address: Address, now: u64) -> Result<Completion<Read>>;
    fn write(
        &mut self,
        route: u64,
        address: Address,
        data: &[u32],
        now: u64,
    ) -> Result<Completion<u8>>;
    fn reset_router(&mut self, route: u64, now: u64) -> Result<Completion<()>>;
    /// PDF3/4 acknowledgments have no automatic response. Validate the
    /// event/ack lifecycle before applying it or returning a completion time.
    fn acknowledge(&mut self, route: u64, body: &Body, now: u64) -> Result<u32>;
    /// Return only real events, at most `credits` packets. Keep events while
    /// the AP has no receive descriptors, without acknowledging them early.
    fn notifications(
        &mut self,
        now: u64,
        credits: usize,
    ) -> Result<(Vec<Notification>, Option<u64>)>;
    /// Physical transport loss/reset, distinct from a routed PDF9 request.
    fn reset_transport(&mut self) -> Result<()>;
}

pub struct Router {
    backend: Box<dyn Configuration>,
    tx: Option<Options>,
    rx: Option<Options>,
    terminal: Option<Refusal>,
    response: Option<Frame>,
}
impl Router {
    pub fn new(backend: Box<dyn Configuration>) -> Self {
        Self {
            backend,
            tx: None,
            rx: None,
            terminal: None,
            response: None,
        }
    }
    fn frame(packet: Packet, timestamp: u32) -> Result<Frame> {
        if !packet.header.reply {
            return Err(refuse!(
                "router backend returned a request as an incoming event"
            ));
        }
        let encoded = packet
            .encode(0)
            .map_err(|_| refuse!("router backend returned an invalid control packet"))?;
        Frame::new(0, encoded.bytes, encoded.sof, encoded.eof, timestamp, false)
    }
    fn complete(
        &mut self,
        packet: Option<Packet>,
        timestamp: u32,
        credits: &[usize],
    ) -> Result<Option<Accepted>> {
        if let Some(packet) = packet {
            match Self::frame(packet, timestamp) {
                Ok(frame) => self.response = Some(frame),
                Err(reason) => {
                    // The backend may have committed read-clear/write/reset
                    // effects. Block retry until a real transport reset.
                    self.terminal = Some(reason.clone());
                    return Err(reason);
                }
            }
        }
        let incoming = if self.rx.is_some() && credits.first().copied().unwrap_or(0) != 0 {
            self.response.take().into_iter().collect()
        } else {
            Vec::new()
        };
        Ok(Some(Accepted {
            timestamp,
            incoming,
        }))
    }
    fn failure(error: Failure) -> Packet {
        Packet {
            header: Header {
                route: error.route,
                reply: true,
            },
            body: Body::Error {
                code: error.code,
                port: error.port,
                acknowledgement: 0,
            },
        }
    }
}
impl Consumer for Router {
    fn configure(
        &mut self,
        hop: usize,
        direction: Direction,
        options: Option<Options>,
    ) -> Result<()> {
        if hop != 0 {
            return if options.is_none() {
                Ok(())
            } else {
                Err(refuse!(
                    "NHI data-plane HopID requires its real adapter consumer"
                ))
            };
        }
        if let Some(options) = options {
            if options.e2e {
                return Err(refuse!(
                    "NHI E2E flow-control packets require their real adapter consumer"
                ));
            }
            if !options.raw || options.no_snoop || options.isochronous {
                return Err(refuse!(
                    "NHI control consumer requires raw asynchronous coherent framing"
                ));
            }
            if direction == Direction::Receive && options.receive_capacity < 256 {
                return Err(refuse!(
                    "NHI control receive buffer cannot hold a full control frame"
                ));
            }
        }
        match direction {
            Direction::Transmit => self.tx = options,
            Direction::Receive => self.rx = options,
        }
        Ok(())
    }
    fn transmit(&mut self, frame: Transmit<'_>) -> Result<Option<Accepted>> {
        if let Some(reason) = self.terminal.clone() {
            return Err(reason);
        }
        if frame.hop != 0 || self.tx != Some(frame.options) || frame.isochronous {
            return Err(refuse!(
                "NHI control transmit is outside its configured channel"
            ));
        }
        let packet = Packet::decode(frame.bytes, frame.sof, frame.eof).map_err(|_| {
            refuse!("NHI malformed control-frame policy requires a hardware contract")
        })?;
        if packet.header.reply {
            return Err(refuse!(
                "AP sent a response on the router control-request channel"
            ));
        }
        let route = packet.header.route;
        if matches!(packet.body, Body::NotificationAck | Body::Error { .. }) {
            let timestamp = self.backend.acknowledge(route, &packet.body, frame.now)?;
            return Ok(Some(Accepted {
                timestamp,
                incoming: Vec::new(),
            }));
        }
        if !matches!(
            packet.body,
            Body::Read { .. } | Body::Write { .. } | Body::Reset
        ) {
            return Err(refuse!(
                "AP control packet requires an additional router protocol"
            ));
        }
        if self.response.is_some() {
            // One kept control response is the explicit native queue
            // budget. Full means no backend effects and no TX completion.
            // Acknowledgments above remain possible to avoid event deadlock.
            return Ok(None);
        }
        let header = Header { route, reply: true };
        let (timestamp, response) = match packet.body {
            Body::Read { mut address, .. } => {
                let completion = self.backend.read(route, address, frame.now)?;
                let response = match completion.result {
                    Ok(Some(read)) => {
                        address.port = read.upstream_port;
                        Some(Packet {
                            header,
                            body: Body::Read {
                                address,
                                data: read.data,
                            },
                        })
                    }
                    Ok(None) => None,
                    Err(error) => Some(Self::failure(error)),
                };
                (completion.timestamp, response)
            }
            Body::Write { mut address, data } => {
                let completion = self.backend.write(route, address, &data, frame.now)?;
                let response = match completion.result {
                    Ok(Some(port)) => {
                        address.port = port;
                        Some(Packet {
                            header,
                            body: Body::Write {
                                address,
                                data: Vec::new(),
                            },
                        })
                    }
                    Ok(None) => None,
                    Err(error) => Some(Self::failure(error)),
                };
                (completion.timestamp, response)
            }
            Body::Reset => {
                let completion = self.backend.reset_router(route, frame.now)?;
                let response = match completion.result {
                    Ok(Some(())) => Some(Packet {
                        header,
                        body: Body::Reset,
                    }),
                    Ok(None) => None,
                    Err(error) => Some(Self::failure(error)),
                };
                (completion.timestamp, response)
            }
            _ => unreachable!(),
        };
        self.complete(response, timestamp, frame.receive_credits)
    }
    fn poll(&mut self, now: u64, receive_credits: &[usize]) -> Result<(Vec<Frame>, Option<u64>)> {
        if let Some(reason) = self.terminal.clone() {
            return Err(reason);
        }
        let credits = if self.rx.is_some() {
            receive_credits.first().copied().unwrap_or(0)
        } else {
            0
        };
        let response_credit = usize::from(credits != 0 && self.response.is_some());
        let event_credits = credits - response_credit;
        let (notifications, deadline) = self.backend.notifications(now, event_credits)?;
        if notifications.len() > event_credits {
            let reason = "router backend returned more notifications than posted receive credit";
            self.terminal = Some(reason.into());
            return Err(reason.into());
        }
        let mut frames = Vec::with_capacity(notifications.len());
        for event in notifications {
            if !matches!(event.packet.body, Body::Plug { .. } | Body::Error { .. }) {
                let reason = "router backend returned a non-notification event";
                self.terminal = Some(reason.into());
                return Err(reason.into());
            }
            match Self::frame(event.packet, event.timestamp) {
                Ok(frame) => frames.push(frame),
                Err(reason) => {
                    self.terminal = Some(reason.clone());
                    return Err(reason);
                }
            }
        }
        if response_credit != 0 {
            frames.insert(0, self.response.take().unwrap());
        }
        Ok((frames, deadline))
    }
    fn reset(&mut self) -> Result<()> {
        self.backend.reset_transport()?;
        self.tx = None;
        self.rx = None;
        self.terminal = None;
        self.response = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
