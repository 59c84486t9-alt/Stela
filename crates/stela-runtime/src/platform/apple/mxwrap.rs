//! MxWrap's AP mailbox transport, used by `iop,mxwrap-acio`.
//!
//! The original 26A434 `AppleMxWrap` methods establish the register offsets,
//! eight-entry FIFO pointer encoding and pre-pop receive snapshot; see
//! `docs/research/usb4-acio.md` for the complete evidence and requirement matrix.
//! [`Firmware`] is the same native AP-facing protocol boundary as ASC v4.
//! This module does not implement CIO firmware, NHI or a tunnel manager, and
//! does not cause the loader to admit an ACIO controller.
//!
//! Native sends drain synchronously. Native replies wait behind the physical
//! eight-slot FIFO when full; the backlog is not hardware occupancy. As with
//! ASC, outbox enable gates AP visibility and its interrupt. A2I enable is
//! retained readback state; the running native receiver accepts sends even
//! when that bit is clear. The AP send path checks FIFO status; the electrical
//! meaning of a cleared enable bit is not established. These are stated
//! emulation choices, not proof of disabled hardware FIFO behavior. Empty
//! reads, unknown fields and unimplemented firmware requests refuse. Retained
//! CPU halt/resume requires the firmware's explicit lifecycle hooks; it never
//! repeats cold start or resets the mailboxes. CPU idle remains unsupported,
//! never inferred from FIFO emptiness.
use super::asc::{Firmware, Lines, Message};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::any::Any;
use stela_contracts::dma::Port;
use stela_contracts::interrupt::Wire;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "mxwrap";
/// Logical offset for ADT `reg[0]`, the AP mailbox view.
pub const MAILBOX: u64 = 0;
/// Logical offset for ADT `reg[1]`, the coprocessor-control view.
pub const CPU: u64 = 0x1_0000;
/// Size of each separately mapped DeviceTree view.
pub const VIEW_BYTES: u64 = 0x4000;
const CPU_RUN: u64 = CPU + 0x28;
const CPU_IDLE: u64 = CPU + 0x44;
const RUN: u64 = 0x10;
const STOP: u64 = 0xffff_ffef;
const A2I_CONTROL: u64 = 0x110;
const I2A_CONTROL: u64 = 0x114;
const A2I_SEND0: u64 = 0x800;
const A2I_SEND1: u64 = 0x808;
const I2A_RECV0: u64 = 0x830;
const I2A_RECV1: u64 = 0x838;
const ENABLE: u64 = 1;
const FULL: u64 = 1 << 16;
const EMPTY: u64 = 1 << 17;
const WRITE_SHIFT: u32 = 8;
const READ_SHIFT: u32 = 12;
const INDEX_MASK: u8 = 7;
const SLOTS: usize = 8;
const STATUS: u64 = (7 << WRITE_SHIFT) | (7 << READ_SHIFT) | FULL | EMPTY;
const ENDPOINT: u64 = 0xff;

pub struct MxWrap {
    firmware: Box<dyn Firmware>,
    running: bool,
    halted: bool,
    a2i_enabled: bool,
    i2a_enabled: bool,
    staged: Option<u64>,
    /// Physical FIFO; only these messages contribute to control status.
    outbox: VecDeque<Message>,
    /// Native transmitter backlog, waiting for physical FIFO space.
    pending: VecDeque<Message>,
    rx_write: u8,
    rx_read: u8,
    tx_index: u8,
    lines: Lines,
    levels: [Option<bool>; 4],
}

impl MxWrap {
    /// A stopped coprocessor, with both mailbox enables clear. Starting it
    /// requires the original CPU run write or a separately modeled power path.
    pub fn new(firmware: Box<dyn Firmware>, lines: Lines) -> Self {
        Self {
            firmware,
            running: false,
            halted: false,
            a2i_enabled: false,
            i2a_enabled: false,
            staged: None,
            outbox: VecDeque::new(),
            pending: VecDeque::new(),
            rx_write: 0,
            rx_read: 0,
            tx_index: 0,
            lines,
            levels: [None; 4],
        }
    }

    /// Explicit previous-stage handoff: firmware running, mailboxes enabled.
    /// This does not manufacture the firmware's HELLO or any endpoint reply.
    pub fn booted(firmware: Box<dyn Firmware>, lines: Lines) -> Result<Self, &'static str> {
        let mut wrapper = Self::new(firmware, lines);
        wrapper.start()?;
        wrapper.a2i_enabled = true;
        wrapper.i2a_enabled = true;
        Ok(wrapper)
    }

    pub fn firmware<F: Firmware>(&self) -> Option<&F> {
        (&*self.firmware as &dyn Any).downcast_ref()
    }

    pub fn firmware_mut<F: Firmware>(&mut self) -> Option<&mut F> {
        (&mut *self.firmware as &mut dyn Any).downcast_mut()
    }

    pub fn dma_pending(&self) -> bool {
        self.running && self.firmware.dma_pending()
    }

    pub fn service_dma(&mut self, port: &mut Port<'_, '_>) -> Result<(), &'static str> {
        if !self.running {
            return Err("MxWrap DMA on a stopped coprocessor");
        }
        let mut produced = Vec::new();
        let result = self.firmware.dma(port, &mut produced);
        // Earlier DMA writes and their emitted notifications can already be
        // committed when a later transfer faults. Retain those messages in
        // FIFO/backlog order and publish their actual visibility before the
        // error reaches the AP; repairing DMA must not replay or erase them.
        self.deliver(produced);
        self.update_lines(port.access);
        result
    }

    fn start(&mut self) -> Result<(), &'static str> {
        if !self.running {
            let mut produced = Vec::new();
            if self.halted {
                self.firmware.resume(&mut produced)?;
            } else {
                self.firmware.start(&mut produced)?;
            }
            self.deliver(produced);
            self.running = true;
            self.halted = false;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), &'static str> {
        if self.running {
            self.firmware.stop()?;
            self.running = false;
            self.halted = true;
        }
        Ok(())
    }

    fn deliver(&mut self, produced: Vec<Message>) {
        self.pending.extend(produced);
        while self.outbox.len() < SLOTS {
            let Some(message) = self.pending.pop_front() else {
                break;
            };
            self.outbox.push_back(message);
            self.rx_write = (self.rx_write + 1) & INDEX_MASK;
        }
    }

    fn visible(&self) -> bool {
        self.i2a_enabled && !self.outbox.is_empty()
    }

    fn receive_status(&self) -> u64 {
        if !self.i2a_enabled {
            return EMPTY;
        }
        ENABLE
            | (u64::from(self.rx_write) << WRITE_SHIFT)
            | (u64::from(self.rx_read) << READ_SHIFT)
            | match self.outbox.len() {
                0 => EMPTY,
                SLOTS => FULL,
                _ => 0,
            }
    }

    fn update_lines(&mut self, access: &mut Access<'_>) {
        let visible = self.visible();
        for (index, (line, level)) in [
            (self.lines.inbox_not_empty, false),
            (self.lines.inbox_empty, true),
            (self.lines.outbox_not_empty, visible),
            (self.lines.outbox_empty, !visible),
        ]
        .into_iter()
        .enumerate()
        {
            if self.levels[index] != Some(level) {
                self.levels[index] = Some(level);
                if let Some(irq) = line {
                    access.interrupts.set_level(Wire::Aic(irq), level);
                }
            }
        }
    }

    fn send(&mut self, endpoint: u64) -> Result<(), &'static str> {
        if !self.running {
            return Err("MxWrap send to a stopped coprocessor");
        }
        if endpoint & !ENDPOINT != 0 {
            return Err("MxWrap message bits above the endpoint are not modeled");
        }
        let payload = self.staged.ok_or("MxWrap send without its payload word")?;
        let mut produced = Vec::new();
        self.firmware.receive(
            Message {
                endpoint: endpoint as u8,
                payload,
            },
            &mut produced,
        )?;
        self.staged = None;
        self.tx_index = (self.tx_index + 1) & INDEX_MASK;
        self.deliver(produced);
        Ok(())
    }
}

impl MmioDevice for MxWrap {
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
            (A2I_CONTROL, Width::Word) => {
                u64::from(self.a2i_enabled)
                    | EMPTY
                    | (u64::from(self.tx_index) << WRITE_SHIFT)
                    | (u64::from(self.tx_index) << READ_SHIFT)
            }
            (I2A_CONTROL, Width::Word) => self.receive_status(),
            (I2A_RECV0, Width::Double) if self.visible() => self.outbox[0].payload,
            (I2A_RECV1, Width::Double) if self.visible() => {
                let snapshot = self.receive_status();
                let message = self.outbox.pop_front().expect("visible FIFO has a head");
                self.rx_read = (self.rx_read + 1) & INDEX_MASK;
                self.deliver(Vec::new());
                self.update_lines(access);
                u64::from(message.endpoint) | (snapshot << 32)
            }
            (I2A_RECV0 | I2A_RECV1, Width::Double) => {
                return Err(fail("MxWrap load of an empty or disabled outbox"));
            }
            (CPU_IDLE, Width::Word) => {
                return Err(fail("MxWrap idle requires the firmware power contract"));
            }
            _ => return Err(fail("MxWrap register or access width without a model")),
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
            (CPU_RUN, Width::Word) if value == RUN => self.start().map_err(fail)?,
            (CPU_RUN, Width::Word) if value == STOP => self.stop().map_err(fail)?,
            (A2I_CONTROL, Width::Word) if value & !(ENABLE | STATUS) == 0 => {
                self.a2i_enabled = value & ENABLE != 0;
            }
            (I2A_CONTROL, Width::Word) if value & !(ENABLE | STATUS) == 0 => {
                self.i2a_enabled = value & ENABLE != 0;
            }
            (A2I_SEND0, Width::Double) => self.staged = Some(value),
            (A2I_SEND1, Width::Double) => {
                self.send(value).map_err(fail)?;
                if let Some(request) = self.firmware.take_transition() {
                    access.request_transition(request.device, request.transition, request.reason);
                }
            }
            _ => {
                return Err(fail(
                    "MxWrap register, field or access width without a model",
                ));
            }
        }
        self.update_lines(access);
        Ok(())
    }

    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        let result = if self.running {
            let mut produced = Vec::new();
            let result = self.firmware.poll(&mut produced);
            self.deliver(produced);
            result
        } else {
            Ok(())
        };
        self.update_lines(access);
        result.map_err(|reason| refuse(NAME, 0, Width::Double, Direction::Read, reason))?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::InterruptLatch};

    #[derive(Default)]
    struct Peer {
        starts: usize,
        messages: Vec<Message>,
        burst: usize,
        fail_start: bool,
        fail_poll: bool,
    }
    impl Firmware for Peer {
        fn start(&mut self, output: &mut Vec<Message>) -> Result<(), &'static str> {
            if self.fail_start {
                return Err("peer boot failure");
            }
            self.starts += 1;
            output.extend((0..self.burst).map(|i| Message {
                endpoint: 0x20,
                payload: i as u64,
            }));
            Ok(())
        }
        fn receive(
            &mut self,
            message: Message,
            output: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            if message.endpoint == 0xff {
                return Err("peer rejected endpoint");
            }
            self.messages.push(message);
            output.push(message);
            Ok(())
        }
        fn poll(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
            if self.fail_poll {
                Err("peer asynchronous failure")
            } else {
                Ok(())
            }
        }
    }
    fn count(control: u64) -> u64 {
        // Original AppleMxWrap::_pendingMessages: full/empty disambiguate
        // equal modulo-eight pointers. This is a consumer, not model state.
        if control & FULL != 0 {
            8
        } else if control & EMPTY != 0 {
            0
        } else {
            ((control >> WRITE_SHIFT).wrapping_sub(control >> READ_SHIFT)) & 7
        }
    }
    fn receive(wrapper: &mut MxWrap, access: &mut Access<'_>) -> (u64, u64) {
        let payload = wrapper.read(I2A_RECV0, Width::Double, access).unwrap();
        (
            payload,
            wrapper.read(I2A_RECV1, Width::Double, access).unwrap(),
        )
    }

    #[test]
    fn original_bulk_consumer_drains_wrapping_fifo_and_transmitter_backlog() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut wrapper = MxWrap::booted(
            Box::new(Peer {
                burst: 21,
                ..Peer::default()
            }),
            Lines::default(),
        )
        .unwrap();
        let status = wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap();
        assert_eq!(count(status), 8);
        assert_ne!(status & FULL, 0);
        assert_eq!((status >> WRITE_SHIFT) & 7, (status >> READ_SHIFT) & 7);
        let mut values = Vec::new();
        loop {
            let (payload, word) = receive(&mut wrapper, &mut access);
            values.push(payload);
            assert_eq!(word & 0xffff_ffff, 0x20);
            if count(word >> 32) == 1 {
                break;
            }
        }
        assert_eq!(values, (0..21).collect::<Vec<_>>());
        let status = wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap();
        assert_eq!(count(status), 0);
        assert_eq!((status >> READ_SHIFT) & 7, 5);
        assert_eq!((status >> WRITE_SHIFT) & 7, 5);
        assert!(wrapper.read(I2A_RECV0, Width::Double, &mut access).is_err());
        assert!(wrapper.read(I2A_RECV1, Width::Double, &mut access).is_err());
    }

    #[test]
    fn enable_rmw_preserves_fifo_and_drives_actual_level_changes() {
        let lines = [0x42c, 0x42b, 0x42e, 0x42d].map(|i| AicInput::new(0, i));
        let mut latch = InterruptLatch::new();
        let mut wrapper = MxWrap::booted(
            Box::new(Peer {
                burst: 2,
                ..Peer::default()
            }),
            Lines::from_interrupts(lines),
        )
        .unwrap();
        {
            let mut access = Access::new(0, 0, &mut latch);
            wrapper.advance(&mut access).unwrap();
        }
        assert!(latch.is_asserted(Wire::Aic(lines[1])));
        assert!(latch.is_asserted(Wire::Aic(lines[2])));
        {
            let mut access = Access::new(0, 0, &mut latch);
            let status = wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap();
            wrapper
                .write(I2A_CONTROL, Width::Word, status & !ENABLE, &mut access)
                .unwrap();
            assert_eq!(
                count(wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap()),
                0
            );
            assert!(wrapper.read(I2A_RECV0, Width::Double, &mut access).is_err());
            wrapper
                .write(I2A_CONTROL, Width::Word, status, &mut access)
                .unwrap();
            assert_eq!(receive(&mut wrapper, &mut access).0, 0);
            assert_eq!(receive(&mut wrapper, &mut access).0, 1);
        }
        assert!(!latch.is_asserted(Wire::Aic(lines[0])));
        assert!(!latch.is_asserted(Wire::Aic(lines[2])));
        assert!(latch.is_asserted(Wire::Aic(lines[3])));
    }

    #[test]
    fn commit_is_atomic_and_refused_endpoint_keeps_payload_for_retry() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut wrapper = MxWrap::booted(Box::<Peer>::default(), Lines::default()).unwrap();
        assert!(
            wrapper
                .write(A2I_SEND1, Width::Double, 1, &mut access)
                .is_err()
        );
        wrapper
            .write(A2I_SEND0, Width::Double, 0xabc, &mut access)
            .unwrap();
        assert!(wrapper.firmware::<Peer>().unwrap().messages.is_empty());
        assert!(
            wrapper
                .write(A2I_SEND1, Width::Double, 0x100, &mut access)
                .is_err()
        );
        assert!(
            wrapper
                .write(A2I_SEND1, Width::Double, 0xff, &mut access)
                .is_err()
        );
        wrapper
            .write(A2I_SEND1, Width::Double, 7, &mut access)
            .unwrap();
        assert_eq!(
            wrapper.firmware::<Peer>().unwrap().messages,
            [Message {
                endpoint: 7,
                payload: 0xabc
            }]
        );
        let (payload, word) = receive(&mut wrapper, &mut access);
        assert_eq!((payload, word & 0xff), (0xabc, 7));
        assert_eq!(count(word >> 32), 1);
        assert!(
            wrapper
                .write(A2I_SEND1, Width::Double, 1, &mut access)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_requires_real_firmware_and_explicit_power_contract() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut wrapper = MxWrap::new(Box::<Peer>::default(), Lines::default());
        wrapper
            .write(A2I_SEND0, Width::Double, 5, &mut access)
            .unwrap();
        assert!(
            wrapper
                .write(A2I_SEND1, Width::Double, 1, &mut access)
                .is_err()
        );
        wrapper
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        wrapper
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        assert_eq!(wrapper.firmware::<Peer>().unwrap().starts, 1);
        wrapper
            .write(A2I_SEND1, Width::Double, 1, &mut access)
            .unwrap();
        assert!(
            wrapper
                .write(CPU_RUN, Width::Word, STOP, &mut access)
                .is_err()
        );
        assert!(wrapper.read(CPU_IDLE, Width::Word, &mut access).is_err());
        let mut failing = MxWrap::new(
            Box::new(Peer {
                fail_start: true,
                ..Peer::default()
            }),
            Lines::default(),
        );
        assert!(
            failing
                .write(CPU_RUN, Width::Word, RUN, &mut access)
                .is_err()
        );
        assert!(!failing.running);
        failing.firmware_mut::<Peer>().unwrap().fail_start = false;
        failing
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        failing.firmware_mut::<Peer>().unwrap().fail_poll = true;
        assert!(failing.advance(&mut access).is_err());
    }

    #[test]
    fn shared_rtkit_management_runs_through_the_original_mailbox_framing() {
        use crate::platform::apple::rtkit::RtKit;
        let firmware =
            RtKit::new(Vec::new(), stela_formats::builds::DEFAULT.rtkit_version).unwrap();
        let mut wrapper = MxWrap::booted(Box::new(firmware), Lines::default()).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(
            receive(&mut wrapper, &mut access).0,
            1 << 52 | 12 << 16 | 12
        );
        let send = |wrapper: &mut MxWrap, payload, access: &mut Access<'_>| {
            wrapper
                .write(A2I_SEND0, Width::Double, payload, access)
                .unwrap();
            wrapper.write(A2I_SEND1, Width::Double, 0, access).unwrap();
        };
        send(&mut wrapper, 2 << 52 | 12 << 16 | 12, &mut access);
        let (payload, word) = receive(&mut wrapper, &mut access);
        assert_eq!(payload, 8 << 52 | 1 << 51 | 3);
        assert_eq!(word & 0xffff_ffff, 0);
        assert_eq!(count(word >> 32), 1);
        send(&mut wrapper, 8 << 52 | 1 << 51 | 1, &mut access);
        assert_eq!(receive(&mut wrapper, &mut access).0, 7 << 52 | 0x20);
        // Native synchronous-drain choice, shared with Asc: bit0 remains
        // readable, while a running receiver accepts an AP send regardless.
        // This does not establish disabled-FIFO behavior on physical silicon.
        wrapper
            .write(A2I_CONTROL, Width::Word, 0, &mut access)
            .unwrap();
        send(&mut wrapper, 3 << 52 | 0xabcdef, &mut access);
        assert_eq!(receive(&mut wrapper, &mut access).0, 4 << 52 | 0xabcdef);
        assert_eq!(
            wrapper.read(A2I_CONTROL, Width::Word, &mut access).unwrap() & ENABLE,
            0
        );
        // Ready alone is not the firmware's retained-halt power contract.
        assert!(
            wrapper
                .write(CPU_RUN, Width::Word, STOP, &mut access)
                .is_err()
        );
        send(&mut wrapper, 6 << 52 | 0x201, &mut access);
        assert_eq!(receive(&mut wrapper, &mut access).0, 7 << 52 | 0x201);
        // An already emitted reply must remain before the autonomous wake.
        send(&mut wrapper, 3 << 52 | 0x9999, &mut access);
        wrapper
            .write(CPU_RUN, Width::Word, STOP, &mut access)
            .unwrap();
        assert!(wrapper.read(CPU_IDLE, Width::Word, &mut access).is_err());
        wrapper
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        wrapper
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        // Resume appends RUNNING once, behind retained traffic and before
        // later replies. It preserves the original endpoint enumeration.
        send(&mut wrapper, 3 << 52 | 0x1234, &mut access);
        assert_eq!(receive(&mut wrapper, &mut access).0, 4 << 52 | 0x9999);
        assert_eq!(receive(&mut wrapper, &mut access).0, 7 << 52 | 0x20);
        assert_eq!(receive(&mut wrapper, &mut access).0, 4 << 52 | 0x1234);
        assert_eq!(
            count(wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap()),
            0
        );
    }

    #[test]
    fn retained_halt_preserves_fifo_indexes_backlog_staging_and_levels() {
        #[derive(Default)]
        struct Retained {
            starts: usize,
            stops: usize,
            resumes: usize,
            polls: usize,
            refuse_resume: bool,
        }
        impl Firmware for Retained {
            fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
                self.starts += 1;
                outbox.extend((0..12).map(|payload| Message {
                    endpoint: 0x20,
                    payload,
                }));
                Ok(())
            }
            fn stop(&mut self) -> Result<(), &'static str> {
                self.stops += 1;
                Ok(())
            }
            fn resume(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
                if self.refuse_resume {
                    return Err("peer resume refused");
                }
                self.resumes += 1;
                Ok(())
            }
            fn receive(
                &mut self,
                message: Message,
                output: &mut Vec<Message>,
            ) -> Result<(), &'static str> {
                output.push(message);
                Ok(())
            }
            fn poll(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
                self.polls += 1;
                Ok(())
            }
            fn dma_pending(&self) -> bool {
                true
            }
        }
        let lines = [0x42c, 0x42b, 0x42e, 0x42d].map(|i| AicInput::new(0, i));
        let mut latch = InterruptLatch::new();
        let mut wrapper =
            MxWrap::booted(Box::<Retained>::default(), Lines::from_interrupts(lines)).unwrap();
        {
            let mut access = Access::new(0, 0, &mut latch);
            assert_eq!(receive(&mut wrapper, &mut access).0, 0);
            wrapper
                .write(A2I_SEND0, Width::Double, 0xfeed, &mut access)
                .unwrap();
            let frozen = wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap();
            assert!(wrapper.dma_pending());
            wrapper
                .write(CPU_RUN, Width::Word, STOP, &mut access)
                .unwrap();
            wrapper
                .write(CPU_RUN, Width::Word, STOP, &mut access)
                .unwrap();
            wrapper.advance(&mut access).unwrap();
            assert!(!wrapper.dma_pending());
            assert_eq!(wrapper.firmware::<Retained>().unwrap().polls, 0);
            assert_eq!(wrapper.firmware::<Retained>().unwrap().stops, 1);
            assert_eq!(
                wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap(),
                frozen
            );
            assert!(
                wrapper
                    .write(A2I_SEND1, Width::Double, 0x20, &mut access)
                    .is_err()
            );
            wrapper.firmware_mut::<Retained>().unwrap().refuse_resume = true;
            assert!(
                wrapper
                    .write(CPU_RUN, Width::Word, RUN, &mut access)
                    .is_err()
            );
            wrapper.advance(&mut access).unwrap();
            assert_eq!(wrapper.firmware::<Retained>().unwrap().polls, 0);
            assert!(!wrapper.dma_pending());
        }
        // Mailbox hardware remains visible and interrupting during a CPU halt.
        assert!(latch.is_asserted(Wire::Aic(lines[2])));
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(receive(&mut wrapper, &mut access).0, 1);
        wrapper.firmware_mut::<Retained>().unwrap().refuse_resume = false;
        wrapper
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        wrapper
            .write(CPU_RUN, Width::Word, RUN, &mut access)
            .unwrap();
        assert!(wrapper.dma_pending());
        assert_eq!(wrapper.firmware::<Retained>().unwrap().starts, 1);
        assert_eq!(wrapper.firmware::<Retained>().unwrap().resumes, 1);
        for expected in 2..12 {
            assert_eq!(receive(&mut wrapper, &mut access).0, expected);
        }
        // The staged AP send survives both the halt and a refused resume.
        wrapper
            .write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert_eq!(receive(&mut wrapper, &mut access).0, 0xfeed);
        assert_eq!(
            count(wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap()),
            0
        );
    }

    #[test]
    fn native_dma_completes_through_ram_before_its_mailbox_reply_is_visible() {
        use {stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram};
        struct DmaPeer(bool);
        impl Firmware for DmaPeer {
            fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
            fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<(), &'static str> {
                self.0 = true;
                Ok(())
            }
            fn dma_pending(&self) -> bool {
                self.0
            }
            fn dma(
                &mut self,
                port: &mut Port<'_, '_>,
                output: &mut Vec<Message>,
            ) -> Result<(), &'static str> {
                let mut data = [0; 4];
                port.read(0x1000, &mut data)
                    .map_err(|_| "peer DMA read failed")?;
                data.reverse();
                port.write(0x1004, &data)
                    .map_err(|_| "peer DMA write failed")?;
                self.0 = false;
                output.push(Message {
                    endpoint: 0x20,
                    payload: u64::from(u32::from_le_bytes(data)),
                });
                Ok(())
            }
        }
        let mut wrapper = MxWrap::booted(Box::new(DmaPeer(false)), Lines::default()).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut memory = Ram::new(0x1000, 8);
        memory.bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
        wrapper
            .write(A2I_SEND0, Width::Double, 0, &mut access)
            .unwrap();
        wrapper
            .write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert!(wrapper.dma_pending());
        assert!(wrapper.read(I2A_RECV0, Width::Double, &mut access).is_err());
        wrapper
            .service_dma(&mut Port {
                iommu: &mut Physical,
                stream: 1,
                memory: &mut memory,
                access: &mut access,
            })
            .unwrap();
        assert_eq!(&memory.bytes[4..], &[4, 3, 2, 1]);
        assert!(!wrapper.dma_pending());
        assert_eq!(receive(&mut wrapper, &mut access).0, 0x01020304);
        let mut stopped = MxWrap::new(Box::new(DmaPeer(false)), Lines::default());
        assert!(
            stopped
                .service_dma(&mut Port {
                    iommu: &mut Physical,
                    stream: 1,
                    memory: &mut memory,
                    access: &mut access
                })
                .is_err()
        );
    }

    #[test]
    fn committed_dma_messages_survive_faults_masking_halt_and_wrapping_backlog() {
        use {stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram};
        #[derive(Default)]
        struct PartialDma {
            committed: bool,
            calls: usize,
            writes: usize,
        }
        impl Firmware for PartialDma {
            fn start(&mut self, out: &mut Vec<Message>) -> Result<(), &'static str> {
                out.extend((0..6).map(|payload| Message {
                    endpoint: 0x20,
                    payload,
                }));
                Ok(())
            }
            fn stop(&mut self) -> Result<(), &'static str> {
                Ok(())
            }
            fn resume(&mut self, out: &mut Vec<Message>) -> Result<(), &'static str> {
                out.push(Message {
                    endpoint: 0,
                    payload: 7 << 52 | 0x20,
                });
                Ok(())
            }
            fn receive(
                &mut self,
                message: Message,
                out: &mut Vec<Message>,
            ) -> Result<(), &'static str> {
                out.push(message);
                Ok(())
            }
            fn dma_pending(&self) -> bool {
                true
            }
            fn dma(
                &mut self,
                port: &mut Port<'_, '_>,
                out: &mut Vec<Message>,
            ) -> Result<(), &'static str> {
                self.calls += 1;
                if !self.committed {
                    port.write(0, b"done").map_err(|_| "first DMA failed")?;
                    self.writes += 1;
                    out.extend((100..112).map(|payload| Message {
                        endpoint: 0x24,
                        payload,
                    }));
                    self.committed = true;
                }
                port.read(0x1000, &mut [0]).map_err(|_| "later DMA failed")
            }
        }
        for enabled in [false, true] {
            let lines = [0x42c, 0x42b, 0x42e, 0x42d].map(|i| AicInput::new(0, i));
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            let mut wrapper =
                MxWrap::booted(Box::<PartialDma>::default(), Lines::from_interrupts(lines))
                    .unwrap();
            let mut memory = Ram::new(0, 8);
            for expected in 0..3 {
                assert_eq!(receive(&mut wrapper, &mut access).0, expected);
            }
            wrapper
                .write(A2I_SEND0, Width::Double, 0xfeed, &mut access)
                .unwrap();
            wrapper
                .write(I2A_CONTROL, Width::Word, u64::from(enabled), &mut access)
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    wrapper.service_dma(&mut Port {
                        memory: &mut memory,
                        iommu: &mut Physical,
                        stream: 0,
                        access: &mut access,
                    }),
                    Err("later DMA failed")
                );
            }
            assert_eq!(&memory.bytes[..4], b"done");
            assert_eq!(wrapper.firmware::<PartialDma>().unwrap().writes, 1);
            assert_eq!(wrapper.outbox.len(), 8);
            assert_eq!(wrapper.pending.len(), 7);
            assert_eq!((wrapper.rx_write, wrapper.rx_read), (3, 3));
            assert_eq!(wrapper.levels[2], Some(enabled));
            if enabled {
                assert_eq!(
                    count(wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap()),
                    8
                );
            } else {
                assert_eq!(
                    wrapper.read(I2A_CONTROL, Width::Word, &mut access).unwrap(),
                    EMPTY
                );
                assert!(wrapper.read(I2A_RECV1, Width::Double, &mut access).is_err());
            }
            wrapper
                .write(CPU_RUN, Width::Word, STOP, &mut access)
                .unwrap();
            assert!(!wrapper.dma_pending());
            assert!(
                wrapper
                    .service_dma(&mut Port {
                        memory: &mut memory,
                        iommu: &mut Physical,
                        stream: 0,
                        access: &mut access,
                    })
                    .is_err()
            );
            assert_eq!(wrapper.firmware::<PartialDma>().unwrap().calls, 2);
            wrapper
                .write(CPU_RUN, Width::Word, RUN, &mut access)
                .unwrap();
            wrapper
                .write(CPU_RUN, Width::Word, RUN, &mut access)
                .unwrap();
            assert_eq!(wrapper.pending.len(), 8);
            assert_eq!(wrapper.staged, Some(0xfeed));
            wrapper
                .write(I2A_CONTROL, Width::Word, ENABLE | STATUS, &mut access)
                .unwrap();
            let expected: Vec<_> = (3..6)
                .map(|payload| (0x20, payload))
                .chain((100..112).map(|payload| (0x24, payload)))
                .chain([(0, 7 << 52 | 0x20)])
                .collect();
            for (index, (endpoint, payload)) in expected.into_iter().enumerate() {
                let (actual, word) = receive(&mut wrapper, &mut access);
                assert_eq!((word & 0xff, actual), (endpoint, payload));
                assert_eq!(count(word >> 32), (16 - index).min(8) as u64);
            }
            assert_eq!((wrapper.rx_write, wrapper.rx_read), (3, 3));
            assert_eq!(wrapper.levels[2], Some(false));
            assert_eq!(wrapper.levels[3], Some(true));
            wrapper
                .write(A2I_SEND1, Width::Double, 0x20, &mut access)
                .unwrap();
            assert_eq!(receive(&mut wrapper, &mut access).0, 0xfeed);
            assert_eq!(wrapper.firmware::<PartialDma>().unwrap().writes, 1);
            assert!(wrapper.pending.is_empty());
            assert!(wrapper.outbox.is_empty());
        }
    }

    #[test]
    fn emitted_poll_messages_remain_visible_after_a_later_asynchronous_error() {
        struct PartialPoll(bool);
        impl Firmware for PartialPoll {
            fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
            fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
            fn poll(&mut self, out: &mut Vec<Message>) -> Result<(), &'static str> {
                if !self.0 {
                    out.extend((0..12).map(|payload| Message {
                        endpoint: 0x24,
                        payload,
                    }));
                    self.0 = true;
                }
                Err("later asynchronous failure")
            }
        }
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut wrapper = MxWrap::booted(Box::new(PartialPoll(false)), Lines::default()).unwrap();
        for _ in 0..2 {
            assert!(wrapper.advance(&mut access).is_err());
        }
        assert_eq!(wrapper.outbox.len(), 8);
        assert_eq!(wrapper.pending.len(), 4);
        assert_eq!(wrapper.levels[2], Some(true));
        for expected in 0..12 {
            assert_eq!(receive(&mut wrapper, &mut access).0, expected);
        }
        assert_eq!(wrapper.levels[2], Some(false));
        assert!(wrapper.outbox.is_empty());
        assert!(wrapper.pending.is_empty());
    }

    #[test]
    fn unknown_fields_widths_and_error_injection_are_explicit() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut wrapper = MxWrap::booted(Box::<Peer>::default(), Lines::default()).unwrap();
        for offset in [0, 0x118, CPU_RUN, CPU_IDLE + 4] {
            assert!(wrapper.read(offset, Width::Word, &mut access).is_err());
        }
        for offset in [A2I_CONTROL, I2A_CONTROL] {
            assert!(wrapper.read(offset, Width::Double, &mut access).is_err());
            assert!(
                wrapper
                    .write(offset, Width::Word, 1 << 18, &mut access)
                    .is_err()
            );
        }
        assert!(wrapper.write(CPU_RUN, Width::Word, 0, &mut access).is_err());
        assert!(
            wrapper
                .write(A2I_SEND0, Width::Word, 5, &mut access)
                .is_err()
        );
        assert!(
            wrapper
                .write(A2I_SEND1, Width::Half, 5, &mut access)
                .is_err()
        );
    }
}
