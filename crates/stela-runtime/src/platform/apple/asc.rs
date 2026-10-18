//! The ASC coprocessor wrapper (`iop,ascwrap-v4`; ADT `/arm-io/<iop>` `reg[0]`):
//! the CPU control of an RTKit coprocessor and its AP mailbox.
//!
//! The coprocessor's own software is emulated natively behind [`Firmware`]
//! (docs/target.md: RTKit coprocessors are emulated at their AP-facing
//! protocols); the wrapper only carries 128-bit messages and starts it.
//!
//! Documented by Linux `drivers/soc/apple/rtkit-helper.c` (`APPLE_ASC_CPU_CONTROL`
//! 0x44, `RUN` bit 4) and `drivers/mailbox/apple-mailbox.c` (the `asc` variant,
//! 0x8000 into the wrapper): A2I (AP to coprocessor) control 0x110, send
//! 0x800 and 0x808; I2A control 0x114, receive 0x830 and 0x838; control bit 16
//! FULL and bit 17 EMPTY; a message is two 64-bit words, the payload and the
//! endpoint in the low byte of the second, sent by the store of 0x808 and
//! consumed by the load of 0x838. The 26A434 J473AP `AppleASCWrapV4` accesses
//! exactly these registers (`_inbox` stores 0x8800 and 0x8808, `_outbox` loads
//! 0x8830 and 0x8838, `_getInboxEmpty`/`_getInboxFull` read 0x8110 bits 17/16,
//! `_runCPU` sets or clears 0x44 bit 4 and on stop also clears bit 5).
//! `getMailboxBulk` takes the number of waiting messages from I2A control
//! bits 23:20, and the full and empty queries treat bits 19:18 as errors,
//! which the model never raises.
//!
//! The ADT lists four interrupts in the order of their AIC numbers rotated by
//! one pair (J473AP PMP: 0x275, 0x274, 0x277, 0x276); `AppleA7IOP` takes
//! index 1 as inbox empty and index 2 as outbox not empty. With Linux's order
//! of a wrapper's four consecutive lines (send empty, send not empty, receive
//! empty, receive not empty), index 0 is inbox not empty and index 3 outbox
//! empty. Every line is a level.
//!
//! Inferred, not documented:
//! - the native firmware takes each message as it is sent, so the inbox is
//!   always empty, which is the fastest permitted completion; a message sent
//!   while the coprocessor is stopped is refused, since nothing would drain it;
//! - `AppleASCWrapV4::_enableOutbox` sets 0x8114 bit 0 and leaves interrupt
//!   enables to its no-op `_enableOutboxInterrupt`, so bit 0 enables the
//!   outbox itself: the coprocessor's messages wait in it, invisible, until
//!   the AP enables it. 0x8110 bit 0 (`_getKICInboxEnabled`) is held;
//! - a load of an empty outbox is refused (the hardware underflows, which
//!   `AppleA7IOP::_outboxUnderflowCheck` treats as an error);
//! - stopping a running coprocessor is refused until a firmware models what
//!   a restart loses.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::interrupt::{AicInput, Wire};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::any::Any;

const NAME: &str = "asc";

const CPU_CONTROL: u64 = 0x44;
const RUN: u64 = 1 << 4;
/// Cleared with RUN on stop; its meaning is not documented, so it is held.
const CPU_CONTROL_HELD: u64 = 1 << 5;
const A2I_CONTROL: u64 = 0x8110;
const I2A_CONTROL: u64 = 0x8114;
const A2I_SEND0: u64 = 0x8800;
const A2I_SEND1: u64 = 0x8808;
const I2A_RECV0: u64 = 0x8830;
const I2A_RECV1: u64 = 0x8838;
const CONTROL_ENABLE: u64 = 1;
const CONTROL_FULL: u64 = 1 << 16;
const CONTROL_EMPTY: u64 = 1 << 17;
/// The I2A control's count of waiting messages, bits 23:20.
const OCCUPANCY_SHIFT: u32 = 20;
const OCCUPANCY_MAX: usize = 0xf;
/// The second message word holds the endpoint in its low byte.
const ENDPOINT: u64 = 0xff;

/// The wrapper's register span, through the mailbox.
pub const WRAPPER_BYTES: u64 = 0x8840;

/// One mailbox message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub endpoint: u8,
    pub payload: u64,
}

/// The coprocessor's software, emulated natively.
pub trait Firmware: Any {
    /// The coprocessor starts running; messages it sends go to `outbox`.
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str>;
    /// The AP sent `message`.
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str>;
}

/// The wrapper's interrupt lines, in ADT `interrupts` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lines {
    pub inbox_not_empty: Option<AicInput>,
    pub inbox_empty: Option<AicInput>,
    pub outbox_not_empty: Option<AicInput>,
    pub outbox_empty: Option<AicInput>,
}

impl Lines {
    /// The lines of an ADT `interrupts` list of four AIC inputs.
    pub fn from_interrupts(irqs: [AicInput; 4]) -> Self {
        Self {
            inbox_not_empty: Some(irqs[0]),
            inbox_empty: Some(irqs[1]),
            outbox_not_empty: Some(irqs[2]),
            outbox_empty: Some(irqs[3]),
        }
    }
}

pub struct Asc {
    firmware: Box<dyn Firmware>,
    running: bool,
    cpu_control: u64,
    a2i_control: u64,
    outbox_enabled: bool,
    send0: Option<u64>,
    /// The coprocessor's messages; the head is visible while the outbox is
    /// enabled.
    outbox: VecDeque<Message>,
    lines: Lines,
    /// Levels last reported, in [`Lines`] order.
    levels: [Option<bool>; 4],
}

impl Asc {
    /// A wrapper whose coprocessor `running` already (started by the boot
    /// firmware) or waits for the AP to set RUN.
    pub fn new(
        mut firmware: Box<dyn Firmware>,
        running: bool,
        lines: Lines,
    ) -> Result<Self, &'static str> {
        let mut outbox = Vec::new();
        if running {
            firmware.start(&mut outbox)?;
        }
        Ok(Self {
            firmware,
            running,
            cpu_control: if running { RUN } else { 0 },
            a2i_control: 0,
            outbox_enabled: false,
            send0: None,
            outbox: outbox.into(),
            lines,
            levels: [None; 4],
        })
    }

    /// A native coprocessor's typed state, for its DMA boundary. The wrapper
    /// still owns all mailbox and interrupt effects; firmware cannot replace it.
    pub fn firmware<F: Firmware>(&self) -> Option<&F> {
        (&*self.firmware as &dyn Any).downcast_ref()
    }

    fn visible(&self) -> bool {
        self.outbox_enabled && !self.outbox.is_empty()
    }

    fn update_lines(&mut self, access: &mut Access<'_>) {
        let visible = self.visible();
        let wanted = [
            (self.lines.inbox_not_empty, false),
            (self.lines.inbox_empty, true),
            (self.lines.outbox_not_empty, visible),
            (self.lines.outbox_empty, !visible),
        ];
        for (index, (line, level)) in wanted.into_iter().enumerate() {
            if self.levels[index] != Some(level) {
                self.levels[index] = Some(level);
                if let Some(irq) = line {
                    access.interrupts.set_level(Wire::Aic(irq), level);
                }
            }
        }
    }

    fn deliver(&mut self, result: Result<Vec<Message>, &'static str>) -> Result<(), &'static str> {
        self.outbox.extend(result?);
        Ok(())
    }

    fn send(&mut self, endpoint_word: u64) -> Result<(), &'static str> {
        if !self.running {
            return Err("mailbox send to a stopped coprocessor");
        }
        if endpoint_word & !ENDPOINT != 0 {
            return Err("mailbox message bits above the endpoint are not modeled");
        }
        let payload = self
            .send0
            .take()
            .ok_or("mailbox send without its payload word")?;
        let message = Message {
            endpoint: endpoint_word as u8,
            payload,
        };
        let mut replies = Vec::new();
        let result = self
            .firmware
            .receive(message, &mut replies)
            .map(|()| replies);
        self.deliver(result)
    }

    fn write_cpu_control(&mut self, value: u64) -> Result<(), &'static str> {
        if value & !(RUN | CPU_CONTROL_HELD) != 0 {
            return Err("ASC CPU control bit is not modeled");
        }
        let run = value & RUN != 0;
        if self.running && !run {
            return Err("stopping a running coprocessor is not modeled");
        }
        if run && !self.running {
            let mut started = Vec::new();
            let result = self.firmware.start(&mut started).map(|()| started);
            self.deliver(result)?;
            self.running = true;
        }
        self.cpu_control = value;
        Ok(())
    }
}

impl MmioDevice for Asc {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        let value = match (offset, width) {
            (CPU_CONTROL, Width::Word) => self.cpu_control,
            (A2I_CONTROL, Width::Word) => self.a2i_control | CONTROL_EMPTY,
            (I2A_CONTROL, Width::Word) => {
                let waiting = if self.visible() { self.outbox.len() } else { 0 };
                u64::from(self.outbox_enabled)
                    | (waiting.min(OCCUPANCY_MAX) as u64) << OCCUPANCY_SHIFT
                    | if waiting == 0 { CONTROL_EMPTY } else { 0 }
            }
            (I2A_RECV0, Width::Double) => self
                .visible()
                .then(|| self.outbox[0].payload)
                .ok_or_else(|| fail("load of an empty outbox"))?,
            (I2A_RECV1, Width::Double) => {
                if !self.visible() {
                    return Err(fail("load of an empty outbox"));
                }
                let message = self.outbox.pop_front().expect("visible outbox has a head");
                self.update_lines(access);
                u64::from(message.endpoint)
            }
            _ => return Err(fail("ASC register without a model")),
        };
        Ok(value)
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        match (offset, width) {
            (CPU_CONTROL, Width::Word) => self.write_cpu_control(value).map_err(fail)?,
            (A2I_CONTROL, Width::Word) if value & !CONTROL_ENABLE == 0 => self.a2i_control = value,
            (I2A_CONTROL, Width::Word) if value & !CONTROL_ENABLE == 0 => {
                self.outbox_enabled = value & CONTROL_ENABLE != 0;
            }
            (A2I_CONTROL | I2A_CONTROL, Width::Word) => {
                return Err(fail("mailbox control bits other than enable are status"));
            }
            (A2I_SEND0, Width::Double) => self.send0 = Some(value),
            (A2I_SEND1, Width::Double) => self.send(value).map_err(fail)?,
            _ => return Err(fail("ASC register without a model")),
        }
        self.update_lines(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    /// Echoes every message back on endpoint + 1 and says hello at start.
    struct Echo;
    impl Firmware for Echo {
        fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
            outbox.push(Message {
                endpoint: 0,
                payload: 0x11,
            });
            Ok(())
        }
        fn receive(
            &mut self,
            message: Message,
            outbox: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            if message.endpoint == 0xff {
                return Err("refused");
            }
            outbox.push(Message {
                endpoint: message.endpoint + 1,
                payload: message.payload,
            });
            Ok(())
        }
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
        assert_eq!(receive(&mut asc, &mut access), (0x11, 0));
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
        assert_eq!(receive(&mut asc, &mut access), (0xabc, 0x21));
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
        asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
        assert!(
            asc.write(A2I_SEND1, Width::Double, 0xff, &mut access)
                .is_err()
        );
        assert!(
            asc.write(I2A_CONTROL, Width::Word, CONTROL_EMPTY, &mut access)
                .is_err()
        );
        assert!(asc.read(0x8000, Width::Word, &mut access).is_err());
        assert!(asc.read(I2A_RECV0, Width::Word, &mut access).is_err());
    }
}
