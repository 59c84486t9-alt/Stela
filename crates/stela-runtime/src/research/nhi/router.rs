//! Control-channel dispatch to an actual router configuration owner.
//!
//! This is the raw control transport, not a capability/register template.
//! Every configuration access, error, timestamp, notification and reset comes
//! from the required backend. No backend or machine admission is supplied.
use super::control::{Address, Body, Header, Packet};
use super::{Accepted, Consumer, Direction, Frame, Options, Transmit};
use alloc::{boxed::Box, vec::Vec};

pub mod cio;

/// A real routed hardware error, distinct from a missing model requirement.
pub struct Failure {
    pub route: u64,
    pub port: u8,
    pub code: u8,
}
/// Native completion time and the actual outcome of a configuration access.
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
/// requested word count and an actual upstream adapter. No sparse-zero bank,
/// always-success writes or implied reset completion is supplied here.
pub trait Configuration {
    fn read(
        &mut self,
        route: u64,
        address: Address,
        now: u64,
    ) -> Result<Completion<Read>, &'static str>;
    fn write(
        &mut self,
        route: u64,
        address: Address,
        data: &[u32],
        now: u64,
    ) -> Result<Completion<u8>, &'static str>;
    fn reset_router(&mut self, route: u64, now: u64) -> Result<Completion<()>, &'static str>;
    /// PDF3/4 acknowledgments have no automatic response. Validate the actual
    /// event/ack lifecycle before applying it or returning a completion time.
    fn acknowledge(&mut self, route: u64, body: &Body, now: u64) -> Result<u32, &'static str>;
    /// Return only real events, at most `credits` packets. Retain events while
    /// the AP has no receive descriptors, without acknowledging them early.
    fn notifications(
        &mut self,
        now: u64,
        credits: usize,
    ) -> Result<(Vec<Notification>, Option<u64>), &'static str>;
    /// Physical transport loss/reset, distinct from a routed PDF9 request.
    fn reset_transport(&mut self) -> Result<(), &'static str>;
}

pub struct Router {
    backend: Box<dyn Configuration>,
    tx: Option<Options>,
    rx: Option<Options>,
    terminal: Option<&'static str>,
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
    fn frame(packet: Packet, timestamp: u32) -> Result<Frame, &'static str> {
        if !packet.header.reply {
            return Err("router backend returned a request as an incoming event");
        }
        let encoded = packet
            .encode(0)
            .map_err(|_| "router backend returned an invalid control packet")?;
        Frame::new(0, encoded.bytes, encoded.sof, encoded.eof, timestamp, false)
    }
    fn complete(
        &mut self,
        packet: Option<Packet>,
        timestamp: u32,
        credits: &[usize],
    ) -> Result<Option<Accepted>, &'static str> {
        if let Some(packet) = packet {
            match Self::frame(packet, timestamp) {
                Ok(frame) => self.response = Some(frame),
                Err(reason) => {
                    // The backend may have committed read-clear/write/reset
                    // effects. Block retry until a real transport reset.
                    self.terminal = Some(reason);
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
    ) -> Result<(), &'static str> {
        if hop != 0 {
            return if options.is_none() {
                Ok(())
            } else {
                Err("NHI data-plane HopID requires its real adapter consumer")
            };
        }
        if let Some(options) = options {
            if options.e2e {
                return Err("NHI E2E flow-control packets require their real adapter consumer");
            }
            if !options.raw || options.no_snoop || options.isochronous {
                return Err("NHI control consumer requires raw asynchronous coherent framing");
            }
            if direction == Direction::Receive && options.receive_capacity < 256 {
                return Err("NHI control receive buffer cannot hold a full control frame");
            }
        }
        match direction {
            Direction::Transmit => self.tx = options,
            Direction::Receive => self.rx = options,
        }
        Ok(())
    }
    fn transmit(&mut self, frame: Transmit<'_>) -> Result<Option<Accepted>, &'static str> {
        if let Some(reason) = self.terminal {
            return Err(reason);
        }
        if frame.hop != 0 || self.tx != Some(frame.options) || frame.isochronous {
            return Err("NHI control transmit is outside its configured channel");
        }
        let packet = Packet::decode(frame.bytes, frame.sof, frame.eof)
            .map_err(|_| "NHI malformed control-frame policy requires a hardware contract")?;
        if packet.header.reply {
            return Err("AP sent a response on the router control-request channel");
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
            return Err("AP control packet requires an additional router protocol");
        }
        if self.response.is_some() {
            // One retained control response is the explicit native queue
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
    fn poll(
        &mut self,
        now: u64,
        receive_credits: &[usize],
    ) -> Result<(Vec<Frame>, Option<u64>), &'static str> {
        if let Some(reason) = self.terminal {
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
            self.terminal = Some(reason);
            return Err(reason);
        }
        let mut frames = Vec::with_capacity(notifications.len());
        for event in notifications {
            if !matches!(event.packet.body, Body::Plug { .. } | Body::Error { .. }) {
                let reason = "router backend returned a non-notification event";
                self.terminal = Some(reason);
                return Err(reason);
            }
            match Self::frame(event.packet, event.timestamp) {
                Ok(frame) => frames.push(frame),
                Err(reason) => {
                    self.terminal = Some(reason);
                    return Err(reason);
                }
            }
        }
        if response_credit != 0 {
            frames.insert(0, self.response.take().unwrap());
        }
        Ok((frames, deadline))
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        self.backend.reset_transport()?;
        self.tx = None;
        self.rx = None;
        self.terminal = None;
        self.response = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::control::Space;
    use super::*;
    use alloc::rc::Rc;
    use core::cell::RefCell;

    #[derive(Default)]
    struct Registers {
        value: u32,
        writes: usize,
        resets: usize,
        acknowledgments: usize,
        calls: usize,
        invalid_reply: bool,
        refuse: bool,
        events: Vec<Notification>,
        silent_reset: bool,
        refuse_poll: bool,
        excess_events: bool,
    }
    struct Backend(Rc<RefCell<Registers>>);
    impl Configuration for Backend {
        fn read(
            &mut self,
            route: u64,
            address: Address,
            now: u64,
        ) -> Result<Completion<Read>, &'static str> {
            let mut registers = self.0.borrow_mut();
            if registers.refuse {
                return Err("fixture requirement unavailable");
            }
            registers.calls += 1;
            let result = if route != 0 {
                Err(Failure {
                    route: 0,
                    port: 0,
                    code: 0,
                })
            } else if address.offset != 0 || address.length != 1 || address.space != Space::Router {
                Err(Failure {
                    route: 0,
                    port: 0,
                    code: 2,
                })
            } else {
                Ok(Some(Read {
                    upstream_port: 6,
                    data: if registers.invalid_reply {
                        vec![]
                    } else {
                        vec![registers.value]
                    },
                }))
            };
            Ok(Completion {
                timestamp: now as u32,
                result,
            })
        }
        fn write(
            &mut self,
            route: u64,
            address: Address,
            data: &[u32],
            now: u64,
        ) -> Result<Completion<u8>, &'static str> {
            let mut registers = self.0.borrow_mut();
            if registers.refuse {
                return Err("fixture requirement unavailable");
            }
            registers.calls += 1;
            let result = if route != 0
                || address.offset != 0
                || address.length != 1
                || address.space != Space::Router
            {
                Err(Failure {
                    route: 0,
                    port: 0,
                    code: 2,
                })
            } else {
                registers.value = registers.value & !0xff | data[0] & 0xff;
                registers.writes += 1;
                Ok(Some(6))
            };
            Ok(Completion {
                timestamp: now as u32,
                result,
            })
        }
        fn reset_router(&mut self, route: u64, now: u64) -> Result<Completion<()>, &'static str> {
            let mut registers = self.0.borrow_mut();
            if registers.refuse {
                return Err("fixture requirement unavailable");
            }
            registers.calls += 1;
            let result = if route == 0 {
                registers.value = 0;
                registers.resets += 1;
                Ok(if registers.silent_reset {
                    None
                } else {
                    Some(())
                })
            } else {
                Err(Failure {
                    route: 0,
                    port: 0,
                    code: 0,
                })
            };
            Ok(Completion {
                timestamp: now as u32,
                result,
            })
        }
        fn acknowledge(&mut self, _: u64, _: &Body, now: u64) -> Result<u32, &'static str> {
            let mut registers = self.0.borrow_mut();
            if registers.refuse {
                return Err("fixture requirement unavailable");
            }
            registers.acknowledgments += 1;
            Ok(now as u32)
        }
        fn notifications(
            &mut self,
            _: u64,
            credits: usize,
        ) -> Result<(Vec<Notification>, Option<u64>), &'static str> {
            let mut registers = self.0.borrow_mut();
            if registers.refuse_poll {
                return Err("fixture notification requirement unavailable");
            }
            let count = if registers.excess_events {
                registers.events.len()
            } else {
                credits.min(registers.events.len())
            };
            Ok((registers.events.drain(..count).collect(), None))
        }
        fn reset_transport(&mut self) -> Result<(), &'static str> {
            let mut registers = self.0.borrow_mut();
            if registers.refuse {
                return Err("fixture requirement unavailable");
            }
            registers.events.clear();
            Ok(())
        }
    }
    fn options() -> Options {
        Options {
            raw: true,
            no_snoop: false,
            e2e: false,
            isochronous: false,
            e2e_tx_hop: 0,
            parameter: 2,
            pdf: 0,
            receive_capacity: 256,
        }
    }
    fn setup() -> (Router, Rc<RefCell<Registers>>) {
        let registers = Rc::new(RefCell::new(Registers::default()));
        let mut router = Router::new(Box::new(Backend(registers.clone())));
        router
            .configure(0, Direction::Transmit, Some(options()))
            .unwrap();
        router
            .configure(0, Direction::Receive, Some(options()))
            .unwrap();
        (router, registers)
    }
    fn request(body: Body) -> Packet {
        Packet {
            header: Header {
                route: 0,
                reply: false,
            },
            body,
        }
    }
    fn address() -> Address {
        Address {
            offset: 0,
            length: 1,
            port: 0,
            space: Space::Router,
            sequence: 3,
        }
    }
    fn send(
        router: &mut Router,
        packet: &Packet,
        credits: usize,
    ) -> Result<Option<Accepted>, &'static str> {
        let wire = packet.encode(packet.body.pdf()).unwrap();
        router.transmit(Transmit {
            hop: 0,
            bytes: &wire.bytes,
            sof: wire.sof,
            eof: wire.eof,
            isochronous: false,
            scheduled_time: 0,
            now: 0x1234,
            options: options(),
            receive_credits: &[credits],
        })
    }
    fn response(accepted: Accepted) -> Packet {
        assert_eq!(accepted.timestamp, 0x1234);
        assert_eq!(accepted.incoming.len(), 1);
        let frame = &accepted.incoming[0];
        assert_eq!(frame.timestamp, 0x1234);
        Packet::decode(&frame.bytes, frame.sof, frame.eof).unwrap()
    }
    #[test]
    fn real_configuration_dispatch_preserves_sequence_and_commits_once() {
        let (mut router, registers) = setup();
        registers.borrow_mut().value = 0xaabbccdd;
        let read = request(Body::Read {
            address: address(),
            data: vec![],
        });
        let accepted = send(&mut router, &read, 0).unwrap().unwrap();
        assert!(accepted.incoming.is_empty());
        assert_eq!(registers.borrow().calls, 1);
        assert!(send(&mut router, &read, 1).unwrap().is_none());
        assert_eq!(registers.borrow().calls, 1);
        let (incoming, _) = router.poll(0, &[1]).unwrap();
        let reply = response(Accepted {
            timestamp: 0x1234,
            incoming,
        });
        let mut addr = address();
        addr.port = 6;
        assert_eq!(
            reply,
            Packet {
                header: Header {
                    route: 0,
                    reply: true
                },
                body: Body::Read {
                    address: addr,
                    data: vec![0xaabbccdd]
                }
            }
        );
        let write = request(Body::Write {
            address: address(),
            data: vec![0x11223344],
        });
        let accepted = send(&mut router, &write, 0).unwrap().unwrap();
        assert!(accepted.incoming.is_empty());
        assert_eq!(registers.borrow().writes, 1);
        assert!(send(&mut router, &write, 1).unwrap().is_none());
        assert_eq!(registers.borrow().writes, 1);
        let (incoming, _) = router.poll(0, &[1]).unwrap();
        let reply = response(Accepted {
            timestamp: 0x1234,
            incoming,
        });
        assert_eq!(
            reply.body,
            Body::Write {
                address: addr,
                data: vec![]
            }
        );
        assert_eq!(registers.borrow().value, 0xaabbcc44);
        assert_eq!(registers.borrow().writes, 1);
        let reply = response(
            send(&mut router, &request(Body::Reset), 1)
                .unwrap()
                .unwrap(),
        );
        assert_eq!(reply.body, Body::Reset);
        assert_eq!(registers.borrow().resets, 1);
        assert_eq!(registers.borrow().value, 0);
    }
    #[test]
    fn hardware_errors_and_model_refusals_have_different_effects() {
        let (mut router, registers) = setup();
        let mut addr = address();
        addr.offset = 1;
        let read = request(Body::Read {
            address: addr,
            data: vec![],
        });
        let reply = response(send(&mut router, &read, 1).unwrap().unwrap());
        assert_eq!(
            reply.body,
            Body::Error {
                code: 2,
                port: 0,
                acknowledgement: 0
            }
        );
        registers.borrow_mut().refuse = true;
        assert!(send(&mut router, &read, 1).is_err());
        assert_eq!(registers.borrow().calls, 1);
        assert!(router.reset().is_err());
        assert!(router.tx.is_some());
        registers.borrow_mut().refuse = false;
        router.reset().unwrap();
        assert!(router.tx.is_none());
        assert!(router.rx.is_none());
    }
    #[test]
    fn invalid_backend_reply_is_terminal_and_cannot_repeat_effectful_reads() {
        let (mut router, registers) = setup();
        registers.borrow_mut().invalid_reply = true;
        let read = request(Body::Read {
            address: address(),
            data: vec![],
        });
        assert!(send(&mut router, &read, 1).is_err());
        assert_eq!(registers.borrow().calls, 1);
        registers.borrow_mut().invalid_reply = false;
        assert!(send(&mut router, &read, 1).is_err());
        assert_eq!(registers.borrow().calls, 1);
        router.reset().unwrap();
        router
            .configure(0, Direction::Transmit, Some(options()))
            .unwrap();
        router
            .configure(0, Direction::Receive, Some(options()))
            .unwrap();
        assert!(send(&mut router, &read, 1).unwrap().is_some());
        assert_eq!(registers.borrow().calls, 2);
    }
    #[test]
    fn notifications_wait_for_credit_and_acknowledgments_do_not_ack_themselves() {
        let (mut router, registers) = setup();
        registers.borrow_mut().events.push(Notification {
            timestamp: 42,
            packet: Packet {
                header: Header {
                    route: 0,
                    reply: true,
                },
                body: Body::Plug {
                    port: 1,
                    unplug: false,
                },
            },
        });
        assert!(router.poll(0, &[0]).unwrap().0.is_empty());
        assert_eq!(registers.borrow().events.len(), 1);
        let (frames, _) = router.poll(0, &[1]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].timestamp, 42);
        assert_eq!(registers.borrow().acknowledgments, 0);
        let accepted = send(
            &mut router,
            &request(Body::Error {
                code: 7,
                port: 1,
                acknowledgement: 2,
            }),
            0,
        )
        .unwrap()
        .unwrap();
        assert!(accepted.incoming.is_empty());
        assert_eq!(registers.borrow().acknowledgments, 1);
        assert!(
            router
                .configure(1, Direction::Transmit, Some(options()))
                .is_err()
        );
        assert!(
            router
                .configure(
                    0,
                    Direction::Transmit,
                    Some(Options {
                        e2e: true,
                        ..options()
                    })
                )
                .is_err()
        );
    }
    fn plug() -> Notification {
        Notification {
            timestamp: 42,
            packet: Packet {
                header: Header {
                    route: 0,
                    reply: true,
                },
                body: Body::Plug {
                    port: 1,
                    unplug: false,
                },
            },
        }
    }
    #[test]
    fn queued_reply_survives_receive_stop_poll_refusal_and_refused_reset() {
        let (mut router, registers) = setup();
        let read = request(Body::Read {
            address: address(),
            data: vec![],
        });
        router.configure(0, Direction::Receive, None).unwrap();
        assert!(
            send(&mut router, &read, 10)
                .unwrap()
                .unwrap()
                .incoming
                .is_empty()
        );
        assert!(router.response.is_some());
        registers.borrow_mut().events.push(plug());
        assert!(router.poll(0, &[10]).unwrap().0.is_empty());
        assert_eq!(registers.borrow().events.len(), 1);
        registers.borrow_mut().refuse = true;
        assert!(router.reset().is_err());
        assert!(router.response.is_some());
        registers.borrow_mut().refuse = false;
        router
            .configure(0, Direction::Receive, Some(options()))
            .unwrap();
        registers.borrow_mut().refuse_poll = true;
        assert!(router.poll(0, &[1]).is_err());
        assert!(router.response.is_some());
        registers.borrow_mut().refuse_poll = false;
        let (frames, _) = router.poll(0, &[1]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].eof, 1);
        assert_eq!(registers.borrow().events.len(), 1);
        let (frames, _) = router.poll(0, &[1]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].eof, 5);
        assert_eq!(registers.borrow().calls, 1);
        assert!(router.poll(0, &[1]).unwrap().0.is_empty());
    }
    #[test]
    fn routed_reset_can_commit_without_reply_and_transport_reset_discards_queue() {
        let (mut router, registers) = setup();
        registers.borrow_mut().value = 42;
        registers.borrow_mut().silent_reset = true;
        let accepted = send(&mut router, &request(Body::Reset), 0)
            .unwrap()
            .unwrap();
        assert!(accepted.incoming.is_empty());
        assert_eq!(registers.borrow().value, 0);
        assert_eq!(registers.borrow().resets, 1);
        assert!(router.response.is_none());
        registers.borrow_mut().silent_reset = false;
        send(&mut router, &request(Body::Reset), 0)
            .unwrap()
            .unwrap();
        assert!(router.response.is_some());
        router.reset().unwrap();
        assert!(router.response.is_none());
        assert!(router.tx.is_none());
        assert!(router.rx.is_none());
        assert_eq!(registers.borrow().resets, 2);
    }
    #[test]
    fn full_response_queue_still_allows_real_event_acknowledgments() {
        let (mut router, registers) = setup();
        send(&mut router, &request(Body::Reset), 0)
            .unwrap()
            .unwrap();
        let ack = request(Body::NotificationAck);
        assert!(
            send(&mut router, &ack, 0)
                .unwrap()
                .unwrap()
                .incoming
                .is_empty()
        );
        assert_eq!(registers.borrow().acknowledgments, 1);
        assert!(router.response.is_some());
        assert!(
            send(&mut router, &request(Body::Reset), 0)
                .unwrap()
                .is_none()
        );
        assert_eq!(registers.borrow().resets, 1);
    }
    #[test]
    fn backend_event_contract_violations_stop_retries_until_transport_reset() {
        for bad in [false, true] {
            let (mut router, registers) = setup();
            if bad {
                registers.borrow_mut().events.push(Notification {
                    timestamp: 1,
                    packet: request(Body::Reset),
                });
            } else {
                registers.borrow_mut().events.push(plug());
                registers.borrow_mut().excess_events = true;
            }
            assert!(router.poll(0, &[usize::from(bad)]).is_err());
            assert!(send(&mut router, &request(Body::Reset), 1).is_err());
            assert_eq!(registers.borrow().resets, 0);
            router.reset().unwrap();
            assert!(router.terminal.is_none());
        }
    }
    #[test]
    fn e2e_and_unimplemented_modes_refuse_atomically_but_unused_rings_can_stop() {
        let (mut router, _) = setup();
        for direction in [Direction::Receive, Direction::Transmit] {
            assert!(
                router
                    .configure(
                        0,
                        direction,
                        Some(Options {
                            e2e: true,
                            ..options()
                        })
                    )
                    .is_err()
            );
            assert_eq!(router.tx, Some(options()));
            assert_eq!(router.rx, Some(options()));
        }
        assert!(
            router
                .configure(
                    0,
                    Direction::Receive,
                    Some(Options {
                        receive_capacity: 255,
                        ..options()
                    })
                )
                .is_err()
        );
        assert!(router.configure(1, Direction::Transmit, None).is_ok());
        assert_eq!(router.tx, Some(options()));
        let mut malformed = request(Body::Reset).encode(9).unwrap();
        malformed.bytes[0] ^= 1;
        assert!(
            router
                .transmit(Transmit {
                    hop: 0,
                    bytes: &malformed.bytes,
                    sof: 9,
                    eof: 9,
                    isochronous: false,
                    scheduled_time: 0,
                    now: 1,
                    options: options(),
                    receive_credits: &[1],
                })
                .is_err()
        );
        assert!(router.terminal.is_none());
    }

    #[test]
    fn programmed_control_dma_retains_queued_replies_and_effects_across_faults() {
        use super::super::{Error as NhiError, Layout, Nhi, Profile};
        use {
            stela_contracts::bus::Access, stela_contracts::bus::MmioDevice,
            stela_contracts::bus::Width,
        };
        use {
            stela_contracts::dma::DmaError, stela_contracts::dma::Iommu,
            stela_contracts::dma::Memory, stela_contracts::dma::Port,
            stela_contracts::dma::test_support::Ram,
        };
        use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::InterruptLatch};
        struct Fault(Option<u64>);
        impl Iommu for Fault {
            fn page(&self) -> u64 {
                16
            }
            fn translate(
                &mut self,
                _: &mut dyn Memory,
                _: usize,
                iova: u64,
                last: u64,
                write: bool,
                _: &mut Access<'_>,
            ) -> Result<u64, DmaError> {
                if write && self.0.is_some_and(|at| (iova..=last).contains(&at)) {
                    Err(DmaError::Fault(0x80))
                } else {
                    Ok(iova)
                }
            }
        }
        fn word(ram: &Ram, at: usize) -> u32 {
            u32::from_le_bytes(ram.bytes[at..at + 4].try_into().unwrap())
        }
        fn service(
            nhi: &mut Nhi,
            ram: &mut Ram,
            iommu: &mut Fault,
            access: &mut Access<'_>,
        ) -> Result<(), NhiError> {
            nhi.service_dma(&mut Port {
                memory: ram,
                iommu,
                stream: 0,
                access,
            })
        }
        let registers = Rc::new(RefCell::new(Registers::default()));
        let router = Router::new(Box::new(Backend(registers.clone())));
        let mut nhi = Nhi::new(
            Profile {
                layout: Layout::ACIO,
                capability_words: [1, 0x12345678],
                shared_tx_buffers: 2,
            },
            vec![AicInput::new(0, 0)],
            vec![AicInput::new(0, 1)],
            Box::new(router),
        )
        .unwrap();
        let mut interrupts = InterruptLatch::new();
        let mut access = Access::new(0, 100, &mut interrupts);
        let mut ram = Ram::new(0, 0x10000);
        let mut iommu = Fault(Some(0x1008));
        nhi.set_powered(true, &mut access).unwrap();
        for (base, descriptors, count, parameter) in
            [(0x10000, 0x1000, 4, 2), (0x80000, 0x2000, 4 | 256 << 16, 0)]
        {
            nhi.write(base, Width::Double, descriptors, &mut access)
                .unwrap();
            nhi.write(base + 12, Width::Word, count, &mut access)
                .unwrap();
            nhi.write(base + 20, Width::Word, parameter, &mut access)
                .unwrap();
            nhi.write(base + 16, Width::Word, 0xc0000000, &mut access)
                .unwrap();
        }
        for slot in 0..2 {
            let mut address = address();
            address.sequence -= slot as u8;
            let wire = request(Body::Write {
                address,
                data: vec![0x11 + slot as u32 * 0x11],
            })
            .encode(2)
            .unwrap();
            let payload = 0x3000 + slot * 0x100;
            assert!(ram.write(payload, &wire.bytes));
            ram.put_u64(0x1000 + slot * 16, payload);
            ram.put_u64(0x1008 + slot * 16, 0xc22000 | wire.bytes.len() as u64);
            ram.put_u64(0x2000 + slot * 16, 0x4000 + slot * 0x100);
            ram.put_u64(0x2008 + slot * 16, 0xc00000);
        }
        nhi.write(0x1000a, Width::Half, 2, &mut access).unwrap();
        assert_eq!(
            service(&mut nhi, &mut ram, &mut iommu, &mut access),
            Err(NhiError::Dma(DmaError::Fault(0x80)))
        );
        assert_eq!(registers.borrow().writes, 1);
        assert_eq!(word(&ram, 0x1008), 0xc22014);
        iommu.0 = None;
        service(&mut nhi, &mut ram, &mut iommu, &mut access).unwrap();
        assert_eq!(registers.borrow().writes, 1);
        assert_eq!(word(&ram, 0x1008), 0xa22014);
        assert_eq!(word(&ram, 0x1018), 0xc22014);
        assert!(nhi.dma_pending());
        nhi.write(0x80008, Width::Half, 1, &mut access).unwrap();
        access.now = 200;
        nhi.advance(&mut access).unwrap();
        iommu.0 = Some(0x4000);
        assert_eq!(
            service(&mut nhi, &mut ram, &mut iommu, &mut access),
            Err(NhiError::Dma(DmaError::Fault(0x80)))
        );
        assert_eq!(registers.borrow().writes, 1);
        assert_eq!(word(&ram, 0x2008), 0xc00000);
        iommu.0 = None;
        service(&mut nhi, &mut ram, &mut iommu, &mut access).unwrap();
        assert_eq!(registers.borrow().writes, 2);
        assert_eq!(word(&ram, 0x200c), 100);
        nhi.write(0x80008, Width::Half, 2, &mut access).unwrap();
        nhi.advance(&mut access).unwrap();
        service(&mut nhi, &mut ram, &mut iommu, &mut access).unwrap();
        assert_eq!(registers.borrow().writes, 2);
        assert_eq!(registers.borrow().value, 0x22);
        for (slot, sequence, time) in [(0, 3, 100), (1, 2, 200)] {
            assert_eq!(word(&ram, 0x2008 + slot * 16), 0xa02010);
            assert_eq!(word(&ram, 0x200c + slot * 16), time);
            let response = Packet::decode(
                &ram.bytes[0x4000 + slot * 0x100..0x4010 + slot * 0x100],
                0,
                2,
            )
            .unwrap();
            assert_eq!(
                response.body,
                Body::Write {
                    address: Address {
                        port: 6,
                        sequence,
                        ..address()
                    },
                    data: vec![],
                }
            );
        }
        assert!(!nhi.dma_pending());
    }
}
