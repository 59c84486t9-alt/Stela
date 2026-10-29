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
//! readback state; the running native receiver accepts sends even
//! when that bit is clear. The AP send path checks FIFO status; the electrical
//! meaning of a cleared enable bit is not established. These are stated
//! emulation choices, not proof of disabled hardware FIFO behavior. Empty
//! reads, unknown fields and unimplemented firmware requests refuse. Retained
//! CPU halt/resume requires the firmware's explicit lifecycle hooks; it never
//! repeats cold start or resets the mailboxes. CPU idle remains unsupported,
//! never inferred from FIFO emptiness.
use crate::platform::apple::asc::{Firmware, Lines, Message};
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
        // committed when a later transfer faults. Keep those messages in
        // FIFO/backlog order and publish their visibility before the
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
mod tests;
