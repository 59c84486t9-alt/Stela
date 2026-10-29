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
fn programmed_control_dma_keeps_queued_replies_and_effects_across_faults() {
    use super::super::{Error as NhiError, Layout, Nhi, Profile};
    use {
        stela_contracts::bus::Access, stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
    };
    use {
        stela_contracts::dma::DmaError, stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
        stela_contracts::dma::Port, stela_contracts::dma::test_support::Ram,
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
