use super::*;
use crate::Result;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;

#[test]
fn physical_retention_freezes_work_and_preserves_mailbox_irq_ownership() {
    struct Active {
        polls: u32,
        resets: u32,
    }
    impl Firmware for Active {
        fn check_reset(&self) -> Result<()> {
            Ok(())
        }
        fn reset(&mut self) -> Result<()> {
            self.resets += 1;
            Ok(())
        }
        fn start(&mut self, _: &mut Vec<Message>) -> Result<()> {
            Ok(())
        }
        fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<()> {
            Ok(())
        }
        fn dma_pending(&self) -> bool {
            true
        }
        fn poll(&mut self, out: &mut Vec<Message>) -> Result<()> {
            self.polls += 1;
            out.push(Message {
                endpoint: 0x20,
                payload: u64::from(self.polls),
            });
            Ok(())
        }
    }
    let mut asc = Asc::booted(
        Box::new(Active {
            polls: 0,
            resets: 0,
        }),
        Lines::from_interrupts(LINES),
    )
    .unwrap();
    let active = asc.lifecycle;
    let mut latch = InterruptLatch::new();
    {
        let mut access = Access::new(0, 0, &mut latch);
        asc.advance(&mut access).unwrap();
        asc.write(A2I_SEND0, Width::Double, 0x123, &mut access)
            .unwrap();
    }
    assert!(latch.is_asserted(Wire::Aic(LINES[2])));
    for gated in [
        LifecycleState {
            clocked: false,
            ..active
        },
        LifecycleState {
            quiesced: true,
            ..active
        },
        LifecycleState {
            powered: false,
            clocked: false,
            retention: true,
            ..active
        },
    ] {
        let mut access = Access::new(0, 1, &mut latch);
        asc.check_lifecycle(gated).unwrap();
        asc.set_lifecycle(gated, &mut access);
        asc.advance(&mut access).unwrap();
        assert!(!asc.dma_pending());
        assert_eq!(asc.send0, Some(0x123));
        assert_eq!(asc.outbox.len(), 1);
        assert_eq!(asc.firmware::<Active>().unwrap().polls, 1);
        assert!(
            asc.check_lifecycle(LifecycleState {
                reset: true,
                ..active
            })
            .is_err()
        );
        asc.set_lifecycle(active, &mut access);
        assert!(asc.dma_pending());
    }
    assert!(latch.is_asserted(Wire::Aic(LINES[2])));
    let mut access = Access::new(0, 2, &mut latch);
    assert_eq!(receive(&mut asc, &mut access).0, 1);
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    let reset = LifecycleState {
        reset: true,
        ..active
    };
    asc.check_lifecycle(reset).unwrap();
    asc.set_lifecycle(reset, &mut access);
    assert!(!asc.running && !asc.halted && asc.outbox.is_empty());
    assert_eq!(asc.firmware::<Active>().unwrap().resets, 1);
    assert!(asc.read(CPU_CONTROL, Width::Word, &mut access).is_err());
    asc.set_lifecycle(active, &mut access);
    assert_eq!(asc.read(CPU_CONTROL, Width::Word, &mut access), Ok(0));
    assert!(!asc.execution_enabled());
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    assert!(asc.execution_enabled());
    assert_eq!(asc.firmware::<Active>().unwrap().resets, 1);
}

/// Echoes every message back on endpoint + 1 and says hello at start.
struct Echo;
impl Firmware for Echo {
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<()> {
        outbox.push(Message {
            endpoint: 0,
            payload: 0x11,
        });
        Ok(())
    }
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<()> {
        if message.endpoint == 0xff {
            return Err(if message.payload == 0 {
                refuse!("refused without a reply")
            } else {
                refuse!("refused")
            });
        }
        outbox.push(Message {
            endpoint: message.endpoint + 1,
            payload: message.payload,
        });
        Ok(())
    }
    /// A refused request with a nonzero payload has an error reply.
    fn error_reply(&mut self, message: Message, _: &Refusal) -> Option<Vec<Message>> {
        (message.payload != 0).then(|| {
            alloc::vec![Message {
                endpoint: message.endpoint,
                payload: !message.payload,
            }]
        })
    }
}

#[test]
fn unimplemented_requests_get_the_error_reply_or_none_and_report_once() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut asc = Asc::booted(Box::new(Echo), Lines::from_interrupts(LINES)).unwrap();
    asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
    assert_eq!(receive(&mut asc, &mut access).0, 0x11);
    let send = |asc: &mut Asc, payload, access: &mut Access<'_>| {
        asc.write(A2I_SEND0, Width::Double, payload, access)
            .unwrap();
        asc.write(A2I_SEND1, Width::Double, 0xff, access)
    };
    for _ in 0..2 {
        send(&mut asc, 5, &mut access).unwrap();
        assert_eq!(receive(&mut asc, &mut access).0, !5);
    }
    let reports = asc.take_unmodeled();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].contains("refused"), "{}", reports[0]);
    // Without an error reply in its protocol the request is left
    // unanswered, so the client's timeout runs.
    for _ in 0..2 {
        send(&mut asc, 0, &mut access).unwrap();
        assert!(asc.outbox.is_empty());
    }
    let reports = asc.take_unmodeled();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].contains("left unanswered"), "{}", reports[0]);
}

const LINES: [AicInput; 4] = [
    AicInput::new(0, 0x275),
    AicInput::new(0, 0x274),
    AicInput::new(0, 0x277),
    AicInput::new(0, 0x276),
];

fn receive(asc: &mut Asc, access: &mut Access<'_>) -> (u64, u64) {
    let payload = asc.read(I2A_RECV0, Width::Double, access).unwrap();
    (payload, asc.read(I2A_RECV1, Width::Double, access).unwrap())
}

#[test]
fn boot_handoff_delivers_hello_without_an_ap_mailbox_enable() {
    let mut latch = InterruptLatch::new();
    let mut asc = Asc::booted(Box::new(Echo), Lines::from_interrupts(LINES)).unwrap();
    {
        let mut access = Access::new(0, 0, &mut latch);
        asc.advance(&mut access).unwrap();
    }
    assert!(latch.is_asserted(Wire::Aic(LINES[2])));
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(asc.read(IDLE_STATUS, Width::Word, &mut access), Ok(0));
    assert_eq!(
        asc.read(A2I_CONTROL, Width::Word, &mut access),
        Ok(CONTROL_ENABLE | CONTROL_EMPTY)
    );
    let control = asc.read(I2A_CONTROL, Width::Word, &mut access).unwrap();
    asc.write(I2A_CONTROL, Width::Word, control, &mut access)
        .unwrap();
    assert_eq!(receive(&mut asc, &mut access), (0x11, 1 << 52));
    assert_eq!(asc.read(IDLE_STATUS, Width::Word, &mut access), Ok(1));
    assert!(!latch.is_asserted(Wire::Aic(LINES[2])));
    let mut access = Access::new(0, 0, &mut latch);
    asc.write(A2I_SEND0, Width::Double, 0x123, &mut access)
        .unwrap();
    assert_eq!(asc.read(IDLE_STATUS, Width::Word, &mut access), Ok(0));
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    asc.write(A2I_SEND0, Width::Double, 0x456, &mut access)
        .unwrap();
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    assert_eq!(receive(&mut asc, &mut access), (0x123, 0x21 | 2 << 52));
    assert_eq!(receive(&mut asc, &mut access), (0x456, 0x21 | 1 << 52));
    assert!(asc.read(I2A_RECV0, Width::Double, &mut access).is_err());
}

#[test]
fn a_started_coprocessor_answers_through_the_enabled_outbox() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let lines = Lines::from_interrupts(LINES);
    let mut asc = Asc::new(Box::new(Echo), false, lines).unwrap();
    assert_eq!(asc.read(CPU_CONTROL, Width::Word, &mut access), Ok(0));
    // A stopped coprocessor cannot take a message.
    asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
    assert!(
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .is_err()
    );
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    // Its hello waits in the disabled outbox.
    assert_eq!(
        asc.read(I2A_CONTROL, Width::Word, &mut access),
        Ok(CONTROL_EMPTY)
    );
    assert!(asc.read(I2A_RECV0, Width::Double, &mut access).is_err());
    asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
    assert!(latch.is_asserted(Wire::Aic(LINES[2])));
    assert!(!latch.is_asserted(Wire::Aic(LINES[3])));
    assert!(latch.is_asserted(Wire::Aic(LINES[1])));
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(
        asc.read(I2A_CONTROL, Width::Word, &mut access),
        Ok(1 | 1 << OCCUPANCY_SHIFT)
    );
    assert_eq!(receive(&mut asc, &mut access), (0x11, 1 << 52));
    assert_eq!(
        asc.read(I2A_CONTROL, Width::Word, &mut access),
        Ok(1 | CONTROL_EMPTY)
    );
    // A message is sent by its second word and answered at once.
    asc.write(A2I_SEND0, Width::Double, 0xabc, &mut access)
        .unwrap();
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    assert_eq!(
        asc.read(A2I_CONTROL, Width::Word, &mut access),
        Ok(CONTROL_EMPTY)
    );
    assert_eq!(receive(&mut asc, &mut access), (0xabc, 0x21 | 1 << 52));
    assert!(!latch.is_asserted(Wire::Aic(LINES[2])));
    assert!(latch.is_asserted(Wire::Aic(LINES[3])));
}

#[test]
fn refusals_stay_explicit() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut asc = Asc::new(Box::new(Echo), true, Lines::default()).unwrap();
    assert_eq!(asc.read(CPU_CONTROL, Width::Word, &mut access), Ok(RUN));
    assert!(asc.write(CPU_CONTROL, Width::Word, 0, &mut access).is_err());
    asc.write(
        CPU_CONTROL,
        Width::Word,
        RUN | CPU_CONTROL_HELD,
        &mut access,
    )
    .unwrap();
    assert!(
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .is_err()
    );
    asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
    assert!(
        asc.write(A2I_SEND1, Width::Double, 0x120, &mut access)
            .is_err()
    );
    // A request the firmware refuses is answered degraded, reported once.
    asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
    asc.write(A2I_SEND1, Width::Double, 0xff, &mut access)
        .unwrap();
    assert_eq!(asc.take_unmodeled().len(), 1);
    assert!(
        asc.write(I2A_CONTROL, Width::Word, 1 << 7, &mut access)
            .is_err()
    );
    assert!(asc.read(0x8004, Width::Word, &mut access).is_err());
    assert!(asc.read(I2A_RECV0, Width::Word, &mut access).is_err());
}

#[derive(Default)]
struct Retained {
    starts: u32,
    stops: u32,
    resumes: u32,
    polls: u32,
    value: u64,
    refuse_stop: bool,
    refuse_resume: bool,
}

impl Firmware for Retained {
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<()> {
        self.starts += 1;
        outbox.push(Message {
            endpoint: 0,
            payload: 0x1234,
        });
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        if self.refuse_stop {
            return Err(refuse!("stop refused"));
        }
        self.stops += 1;
        Ok(())
    }
    fn resume(&mut self, _: &mut Vec<Message>) -> Result<()> {
        if self.refuse_resume {
            return Err(refuse!("resume refused"));
        }
        self.resumes += 1;
        Ok(())
    }
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<()> {
        self.value += message.payload;
        outbox.push(Message {
            endpoint: message.endpoint,
            payload: self.value,
        });
        Ok(())
    }
    fn poll(&mut self, _: &mut Vec<Message>) -> Result<()> {
        self.polls += 1;
        Ok(())
    }
    fn dma_pending(&self) -> bool {
        true
    }
}

#[test]
fn kept_halt_keeps_mailboxes_state_and_cpu_work_until_resume() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut asc = Asc::new(
        Box::new(Retained::default()),
        false,
        Lines::from_interrupts(LINES),
    )
    .unwrap();
    asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
    assert_eq!(asc.firmware::<Retained>().unwrap().stops, 0);
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    asc.write(
        CPU_CONTROL,
        Width::Word,
        RUN | CPU_CONTROL_HELD,
        &mut access,
    )
    .unwrap();
    asc.write(A2I_CONTROL, Width::Word, 1, &mut access).unwrap();
    asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
    asc.write(A2I_SEND0, Width::Double, 5, &mut access).unwrap();
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    asc.write(A2I_SEND0, Width::Double, 7, &mut access).unwrap();
    asc.advance(&mut access).unwrap();
    assert!(asc.dma_pending());
    // Clearing RUN and the held bit are separate AP stores. Neither
    // flushes a response or the first word of an AP message.
    asc.write(CPU_CONTROL, Width::Word, CPU_CONTROL_HELD, &mut access)
        .unwrap();
    asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
    asc.advance(&mut access).unwrap();
    assert!(!asc.dma_pending());
    assert_eq!(asc.levels[2], Some(true)); // Outbox IRQ survives CPU halt.
    assert_eq!(asc.firmware::<Retained>().unwrap().polls, 1);
    assert_eq!(
        asc.read(A2I_CONTROL, Width::Word, &mut access),
        Ok(CONTROL_ENABLE | CONTROL_EMPTY)
    );
    assert_eq!(receive(&mut asc, &mut access), (0x1234, 2 << 52));
    assert_eq!(asc.levels[2], Some(true));
    assert_eq!(receive(&mut asc, &mut access), (5, 0x20 | 1 << 52));
    assert_eq!(asc.levels[2], Some(false));
    assert_eq!(asc.levels[3], Some(true));
    assert!(
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .is_err()
    );
    assert_eq!(asc.send0, Some(7));
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    assert!(asc.dma_pending());
    assert!(asc.outbox.is_empty()); // Resume did not emit another cold Hello.
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    assert_eq!(receive(&mut asc, &mut access), (12, 0x20 | 1 << 52));
    let firmware = asc.firmware::<Retained>().unwrap();
    assert_eq!(
        (firmware.starts, firmware.stops, firmware.resumes),
        (1, 1, 1)
    );
    assert_eq!(firmware.value, 12);
}

#[test]
fn refused_power_changes_leave_state_unchanged() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut asc = Asc::new(
        Box::new(Retained {
            refuse_stop: true,
            ..Retained::default()
        }),
        true,
        Lines::default(),
    )
    .unwrap();
    asc.write(A2I_SEND0, Width::Double, 9, &mut access).unwrap();
    assert!(asc.write(CPU_CONTROL, Width::Word, 0, &mut access).is_err());
    assert!(asc.running && !asc.halted);
    assert_eq!(asc.cpu_control, RUN);
    assert_eq!(asc.send0, Some(9));
    assert_eq!(asc.outbox.len(), 1);
    asc.firmware_mut::<Retained>().unwrap().refuse_stop = false;
    asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
    asc.firmware_mut::<Retained>().unwrap().refuse_resume = true;
    assert!(
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .is_err()
    );
    assert!(!asc.running && asc.halted);
    assert_eq!(asc.cpu_control, 0);
    assert_eq!(asc.send0, Some(9));
    assert_eq!(asc.outbox.len(), 1);
    assert!(
        asc.write(CPU_CONTROL, Width::Word, RUN | 1, &mut access)
            .is_err()
    );
    assert!(
        asc.write(CPU_CONTROL, Width::Double, RUN, &mut access)
            .is_err()
    );
    assert_eq!(asc.firmware::<Retained>().unwrap().resumes, 0);
}

struct AtomicCommand {
    refuse_start: bool,
    refuse_resume: bool,
    refuse_receive: bool,
    value: u64,
}
impl Firmware for AtomicCommand {
    fn start(&mut self, out: &mut Vec<Message>) -> Result<()> {
        out.push(Message {
            endpoint: 0,
            payload: 0x11,
        });
        if self.refuse_start {
            return Err(refuse!("start refused"));
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
    fn resume(&mut self, out: &mut Vec<Message>) -> Result<()> {
        out.push(Message {
            endpoint: 0,
            payload: 7 << 52 | 0x20,
        });
        if self.refuse_resume {
            return Err(refuse!("resume refused"));
        }
        Ok(())
    }
    fn receive(&mut self, message: Message, out: &mut Vec<Message>) -> Result<()> {
        out.push(Message {
            endpoint: message.endpoint,
            payload: self.value + message.payload,
        });
        if self.refuse_receive {
            return Err(refuse!("command refused"));
        }
        self.value += message.payload;
        Ok(())
    }
}

#[test]
fn atomic_refusals_discard_tentative_acks() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut asc = Asc::new(
        Box::new(AtomicCommand {
            refuse_start: true,
            refuse_resume: true,
            refuse_receive: true,
            value: 0,
        }),
        false,
        Lines::from_interrupts(LINES),
    )
    .unwrap();
    asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
    assert!(
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .is_err()
    );
    assert!(!asc.running && !asc.halted && asc.cpu_control == 0);
    assert!(asc.outbox.is_empty());
    assert_eq!(asc.levels[2], Some(false));
    asc.firmware_mut::<AtomicCommand>().unwrap().refuse_start = false;
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    assert_eq!(receive(&mut asc, &mut access).0, 0x11);
    // A refused command publishes no tentative ack: it is left
    // unanswered and reported once.
    asc.write(A2I_SEND0, Width::Double, 5, &mut access).unwrap();
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    assert_eq!(asc.send0, None);
    assert_eq!(asc.firmware::<AtomicCommand>().unwrap().value, 0);
    assert!(asc.outbox.is_empty());
    assert_eq!(asc.levels[2], Some(false));
    assert_eq!(asc.take_unmodeled().len(), 1);
    asc.firmware_mut::<AtomicCommand>().unwrap().refuse_receive = false;
    asc.write(A2I_SEND0, Width::Double, 5, &mut access).unwrap();
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    assert_eq!(asc.send0, None);
    assert_eq!(asc.firmware::<AtomicCommand>().unwrap().value, 5);
    assert_eq!(receive(&mut asc, &mut access).0, 5);
    asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
    assert!(
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .is_err()
    );
    assert!(!asc.running && asc.halted && asc.cpu_control == 0);
    assert!(asc.outbox.is_empty());
    asc.firmware_mut::<AtomicCommand>().unwrap().refuse_resume = false;
    asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
        .unwrap();
    assert_eq!(receive(&mut asc, &mut access).0, 7 << 52 | 0x20);
    assert!(asc.outbox.is_empty());
}

struct AsyncEndpoint {
    value: u64,
    issued: bool,
    fail: bool,
    polls: u32,
}
impl super::super::rtkit::Endpoint for AsyncEndpoint {
    fn start(&mut self, _: &mut Vec<u64>) -> Result<()> {
        Ok(())
    }
    fn receive(&mut self, _: u64, _: &mut Vec<u64>) -> Result<()> {
        Err(refuse!("no command contract"))
    }
    fn poll(&mut self, out: &mut Vec<u64>) -> Result<()> {
        self.polls += 1;
        if !self.issued {
            self.issued = true;
            out.push(self.value);
        }
        if self.fail {
            return Err(refuse!("later async operation failed"));
        }
        Ok(())
    }
}

#[test]
fn rtkit_poll_keeps_prior_and_failing_events() {
    use super::super::rtkit::{Endpoint, RtKit};
    let endpoints = (0x20..=0x22)
        .map(|number| {
            (
                number,
                Box::new(AsyncEndpoint {
                    value: u64::from(number) + 100,
                    issued: false,
                    fail: number == 0x21,
                    polls: 0,
                }) as Box<dyn Endpoint>,
            )
        })
        .collect();
    let rtkit = RtKit::new(endpoints, stela_formats::builds::DEFAULT.rtkit_version).unwrap();
    let mut asc = Asc::booted(Box::new(rtkit), Lines::from_interrupts(LINES)).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let send = |asc: &mut Asc, payload, access: &mut Access<'_>| {
        asc.write(A2I_SEND0, Width::Double, payload, access)
            .unwrap();
        asc.write(A2I_SEND1, Width::Double, 0, access).unwrap();
    };
    receive(&mut asc, &mut access); // Hello.
    send(&mut asc, 2 << 52 | 12 | 12 << 16, &mut access);
    receive(&mut asc, &mut access); // Roll call0.
    send(&mut asc, 8 << 52 | 1, &mut access);
    receive(&mut asc, &mut access); // Roll call1.
    send(&mut asc, 8 << 52 | 1 << 51 | 1 << 32, &mut access);
    assert_eq!(receive(&mut asc, &mut access).0, 7 << 52 | 0x20);
    for number in 0x20..=0x22 {
        send(&mut asc, 5 << 52 | number << 32 | 2, &mut access);
    }
    asc.write(I2A_CONTROL, Width::Word, 0, &mut access).unwrap();
    assert!(asc.advance(&mut access).is_err());
    assert_eq!(asc.outbox.len(), 2);
    assert_eq!(asc.levels[2], Some(false)); // Delivery gated, events kept.
    assert!(asc.read(I2A_RECV0, Width::Double, &mut access).is_err());
    asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
    assert_eq!(asc.levels[2], Some(true));
    assert_eq!(receive(&mut asc, &mut access).0, 132);
    assert_eq!(asc.levels[2], Some(true));
    assert_eq!(receive(&mut asc, &mut access).0, 133);
    assert_eq!(asc.levels[2], Some(false));
    let rtkit = asc.firmware_mut::<RtKit>().unwrap();
    assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x22).unwrap().polls, 0);
    rtkit.endpoint_mut::<AsyncEndpoint>(0x21).unwrap().fail = false;
    asc.advance(&mut access).unwrap();
    assert_eq!(asc.outbox.len(), 1); // Committed events were not replayed.
    assert_eq!(receive(&mut asc, &mut access).0, 134);
    let rtkit = asc.firmware_mut::<RtKit>().unwrap();
    assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x20).unwrap().polls, 2);
    assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x21).unwrap().polls, 2);
    assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x22).unwrap().polls, 1);
    assert!(asc.outbox.is_empty());
}

struct PartialDma(bool);
impl Firmware for PartialDma {
    fn start(&mut self, _: &mut Vec<Message>) -> Result<()> {
        Ok(())
    }
    fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<()> {
        Ok(())
    }
    fn dma(&mut self, port: &mut Port<'_, '_>, out: &mut Vec<Message>) -> Result<()> {
        if !self.0 {
            port.write(0, b"done")
                .map_err(|_| refuse!("first DMA failed"))?;
            out.push(Message {
                endpoint: 0x24,
                payload: 0x85 << 48,
            });
            self.0 = true;
        }
        port.read(0x1000, &mut [0])
            .map_err(|_| refuse!("later DMA failed"))
    }
}

#[test]
fn an_earlier_dma_notification_survives_a_later_transfer_fault() {
    use {stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram};
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut memory = Ram::new(0, 8);
    let mut asc = Asc::booted(Box::new(PartialDma(false)), Lines::from_interrupts(LINES)).unwrap();
    asc.write(I2A_CONTROL, Width::Word, CONTROL_ENABLE, &mut access)
        .unwrap();
    for _ in 0..2 {
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        assert_eq!(asc.service_dma(&mut port), Err(refuse!("later DMA failed")));
    }
    assert_eq!(&memory.bytes[..4], b"done");
    assert_eq!(asc.outbox.len(), 1);
    assert_eq!(asc.levels[2], Some(true));
    assert_eq!(receive(&mut asc, &mut access), (0x85 << 48, 0x24 | 1 << 52));
    assert_eq!(asc.levels[2], Some(false));
}

/// Powers the machine off for any message and reports one event of
/// its own per poll.
struct Standby {
    events: u64,
    requested: bool,
}
impl Firmware for Standby {
    fn start(&mut self, _outbox: &mut Vec<Message>) -> Result<()> {
        Ok(())
    }
    fn receive(&mut self, _message: Message, _outbox: &mut Vec<Message>) -> Result<()> {
        self.requested = true;
        Ok(())
    }
    fn poll(&mut self, outbox: &mut Vec<Message>) -> Result<()> {
        self.events += 1;
        outbox.push(Message {
            endpoint: 0x20,
            payload: self.events,
        });
        Ok(())
    }
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        core::mem::take(&mut self.requested).then_some(TransitionRequest {
            device: "standby",
            transition: Transition::PowerOff,
            reason: "test",
        })
    }
}

#[test]
fn firmware_events_leave_at_advance_and_transitions_reach_the_machine() {
    let mut latch = InterruptLatch::new();
    let firmware = Standby {
        events: 0,
        requested: false,
    };
    let mut asc = Asc::booted(Box::new(firmware), Lines::from_interrupts(LINES)).unwrap();
    let mut access = Access::new(0, 7, &mut latch);
    asc.advance(&mut access).unwrap();
    assert!(latch.is_asserted(Wire::Aic(LINES[2])));
    let mut access = Access::new(0, 7, &mut latch);
    assert_eq!(receive(&mut asc, &mut access), (1, 0x20 | 1 << 52));
    assert_eq!(asc.firmware_mut::<Standby>().unwrap().events, 1);
    assert!(asc.firmware_mut::<Echo>().is_none());
    asc.write(A2I_SEND0, Width::Double, 0, &mut access).unwrap();
    assert!(access.reset_request().is_none());
    asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
        .unwrap();
    let request = access.reset_request().unwrap();
    assert_eq!(
        (request.device, request.transition, request.at),
        ("standby", Transition::PowerOff, 7)
    );
}
