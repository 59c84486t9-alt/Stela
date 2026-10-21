//! Apple SPMI Gen2 controller (`aapl,spmi`, `gen = 2`), a MIPI SPMI bus
//! master and the interrupt controller of its slaves.
//!
//! Evidence (26A434 KC VAs, unslid): `AppleGen2SPMIHandler::initHandler`
//! 0xfffffe0009dc757c loads the register offsets; `fifoQueuesEmpty`
//! 0xfffffe0009dcb4fc, `queuePop` 0xfffffe0009dcbe64,
//! `extendedReadWriteCommand` 0xfffffe0009dcfec0..0xfffffe0009dd000c and
//! `resetQueueBase` 0xfffffe0009dceb50 use them. Bank A is `reg[0]`, bank B
//! `reg[1]`; both are 32-bit registers.
//!
//! - A+0x00 STATUS: bit 24 response FIFO empty, bit 8 request FIFO empty.
//! - A+0x04 request FIFO: a header word, then a write's payload words.
//! - A+0x08 response FIFO: one word per read.
//! - A+0x20 + 4g / A+0x60 + 4g: interrupt enable / write-1-clear status of
//!   vector group g (0..=8), bit `vector & 31`.
//! - A+0xa0 control: `Gen2::resetQueue` saves, zeroes and restores it.
//! - A+0xa4 queue reset: writing 1 flushes both FIFOs; `resetQueueBase`
//!   then requires STATUS to read exactly 0x01000100.
//! - B+0x110..0x11c fault latches; B+0x200..0x224 and B+0x25c..0x274 the
//!   17 fault counters `Gen2::dumpFaultCounters` reads.
//!
//! A header is `address << 16 | last << 15 | sid << 8 | opcode`, the opcode
//! carrying the byte count minus one: extended write 0x00 and read 0x20
//! (16-byte, 8-bit address), extended-long write 0x30 and read 0x38 (8-byte,
//! 16-bit address), the MIPI SPMI opcodes. The driver pops one response per
//! request chunk and requires its low twelve bits to echo the request
//! (`getHeaderMatch` masks 0xfff). A write response's bit 15 is the slave's
//! ACK (NACK fails 0xe00002ed). A read response carries one parity-good bit
//! per byte at bits 16 and up, then the data in little-endian words; a NACKed
//! read is modeled with its parity bits clear and zero data, which the driver
//! reports as a parity failure (0xe00002bc). The last chunk raises local
//! vector 0x100, which the driver polls or takes through the AIC line.
//!
//! Stela handoff: idle, empty FIFOs, every vector masked and clear, no
//! faults. The model executes a command when its last payload word arrives.
//! It has no faults to latch or count, so those registers read zero.
//!
//! Retained lifecycle pauses require no partial request and every vector
//! masked. Masked responses/pending latches and attached PMIC state remain
//! owned; physical reset/rail loss and armed-source wake behavior refuse.
//! Quiesce permits nonmutating reads, while a clock-stop MMIO access remains
//! unqualified. Slave autonomous time is independent of controller gating.
//! The debug queue windows (A+0xb0..0xb8), command types other than the four
//! extended forms and request or response overflow refuse.
use super::{
    bus::{Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};

pub const BANK_BYTES: u64 = 0x4000;
/// Bank B's device offset; the placement maps `reg[1]` here.
pub const BANK_B: u64 = BANK_BYTES;
const NAME: &str = "SPMI";
const STATUS: u64 = 0x00;
const REQUEST: u64 = 0x04;
const RESPONSE: u64 = 0x08;
const ENABLE: u64 = 0x20;
const PENDING: u64 = 0x60;
const GROUPS: usize = 9;
const CONTROL: u64 = 0xa0;
const QUEUE_RESET: u64 = 0xa4;
const FAULT_LATCHES: u64 = BANK_B + 0x110;
const FAULT_COUNTERS: [(u64, u64); 2] = [(BANK_B + 0x200, 10), (BANK_B + 0x25c, 7)];
const RESPONSE_EMPTY: u32 = 1 << 24;
const REQUEST_EMPTY: u32 = 1 << 8;
const LAST: u32 = 1 << 15;
const ACK: u32 = 1 << 15;
/// The controller's own response vector.
pub const RESPONSE_VECTOR: u32 = 0x100;
/// `queue-depth`'s 0x100 response entries; more pending words refuse.
const RESPONSE_CAPACITY: usize = 0x100;

/// A slave's refusal to complete a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaveError {
    /// The slave answers NACK, a bus result the driver reports.
    Nack,
    /// The transaction needs behavior the model does not have; the machine
    /// stops with this reason.
    Unsupported(&'static str),
}

/// One SPMI slave on a controller, addressed by its slave ID. Accesses
/// cover consecutive register addresses. A failed access changes nothing.
pub trait SpmiSlave {
    fn read(&mut self, address: u16, data: &mut [u8], now: u64) -> Result<(), SlaveError>;
    fn write(&mut self, address: u16, data: &[u8], now: u64) -> Result<(), SlaveError>;
    /// Bring time-driven state up to `now`; the next counter value at which
    /// the slave changes state by itself, if any.
    fn advance(&mut self, _now: u64) -> Option<u64> {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Write,
    Read,
}

/// A decoded request chunk.
#[derive(Clone, Copy, Debug)]
struct Chunk {
    header: u32,
    kind: Kind,
    sid: u8,
    address: u16,
    bytes: usize,
}

impl Chunk {
    fn decode(header: u32) -> Result<Self, &'static str> {
        let opcode = header & 0xff;
        let address = (header >> 16) as u16;
        let (kind, bytes, long) = match opcode {
            0x00..=0x0f => (Kind::Write, (opcode & 0xf) + 1, false),
            0x20..=0x2f => (Kind::Read, (opcode & 0xf) + 1, false),
            0x30..=0x37 => (Kind::Write, (opcode & 7) + 1, true),
            0x38..=0x3f => (Kind::Read, (opcode & 7) + 1, true),
            _ => return Err("SPMI command other than an extended register access"),
        };
        if !long && address > 0xff {
            return Err("SPMI extended access with a 16-bit address");
        }
        if header & 0x7000 != 0 {
            return Err("SPMI request header reserved bits");
        }
        Ok(Self {
            header,
            kind,
            sid: ((header >> 8) & 0xf) as u8,
            address,
            bytes: bytes as usize,
        })
    }
    fn words(&self) -> usize {
        self.bytes.div_ceil(4)
    }
}

pub struct Spmi {
    lifecycle: LifecycleState,
    irq: AicInput,
    slaves: Vec<(u8, Box<dyn SpmiSlave>)>,
    enable: [u32; GROUPS],
    pending: [u32; GROUPS],
    control: u32,
    /// A write chunk waiting for its payload words.
    partial: Option<(Chunk, Vec<u32>)>,
    responses: VecDeque<u32>,
}

impl Spmi {
    pub fn new(irq: AicInput) -> Self {
        Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            },
            irq,
            slaves: Vec::new(),
            enable: [0; GROUPS],
            pending: [0; GROUPS],
            control: 0,
            partial: None,
            responses: VecDeque::new(),
        }
    }
    /// Attaches a slave at its four-bit ID; an unoccupied ID NACKs.
    pub fn attach(&mut self, sid: u8, slave: Box<dyn SpmiSlave>) -> Result<(), &'static str> {
        if sid > 0xf || self.slaves.iter().any(|(id, _)| *id == sid) {
            return Err("invalid or duplicate SPMI slave ID");
        }
        self.slaves.push((sid, slave));
        Ok(())
    }
    fn status(&self) -> u32 {
        (if self.responses.is_empty() {
            RESPONSE_EMPTY
        } else {
            0
        }) | if self.partial.is_none() {
            REQUEST_EMPTY
        } else {
            0
        }
    }
    fn update_irq(&self, access: &mut Access<'_>) {
        let asserted = self
            .enable
            .iter()
            .zip(&self.pending)
            .any(|(e, p)| e & p != 0);
        access.interrupts.set_level(Wire::Aic(self.irq), asserted);
    }
    fn request(&mut self, word: u32, now: u64) -> Result<(), &'static str> {
        let (chunk, payload) = match self.partial.take() {
            Some((chunk, mut payload)) => {
                payload.push(word);
                if payload.len() < chunk.words() {
                    self.partial = Some((chunk, payload));
                    return Ok(());
                }
                (chunk, payload)
            }
            None => {
                let chunk = Chunk::decode(word)?;
                if chunk.kind == Kind::Write {
                    self.partial = Some((chunk, Vec::with_capacity(chunk.words())));
                    return Ok(());
                }
                (chunk, Vec::new())
            }
        };
        self.execute(chunk, &payload, now)
    }
    fn execute(&mut self, chunk: Chunk, payload: &[u32], now: u64) -> Result<(), &'static str> {
        let words = 1 + if chunk.kind == Kind::Read {
            chunk.words()
        } else {
            0
        };
        if self.responses.len() + words > RESPONSE_CAPACITY {
            return Err("SPMI response FIFO overflow");
        }
        let slave = self
            .slaves
            .iter_mut()
            .find(|(id, _)| *id == chunk.sid)
            .map(|(_, slave)| slave);
        let echo = chunk.header & 0x7fff;
        match chunk.kind {
            Kind::Write => {
                let bytes: Vec<u8> = payload
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .take(chunk.bytes)
                    .collect();
                let result = match slave {
                    Some(slave) => slave.write(chunk.address, &bytes, now),
                    None => Err(SlaveError::Nack),
                };
                match result {
                    Ok(()) => self.responses.push_back(echo | ACK),
                    Err(SlaveError::Nack) => self.responses.push_back(echo),
                    Err(SlaveError::Unsupported(reason)) => return Err(reason),
                }
            }
            Kind::Read => {
                let mut bytes = [0u8; 16];
                let data = &mut bytes[..chunk.bytes];
                let result = match slave {
                    Some(slave) => slave.read(chunk.address, data, now),
                    None => Err(SlaveError::Nack),
                };
                let parity = match result {
                    Ok(()) => ((1u32 << chunk.bytes) - 1) << 16 | ACK,
                    Err(SlaveError::Nack) => {
                        data.fill(0);
                        0
                    }
                    Err(SlaveError::Unsupported(reason)) => return Err(reason),
                };
                self.responses.push_back((chunk.header & 0xfff) | parity);
                for word in data.chunks(4) {
                    let mut le = [0u8; 4];
                    le[..word.len()].copy_from_slice(word);
                    self.responses.push_back(u32::from_le_bytes(le));
                }
            }
        }
        if chunk.header & LAST != 0 {
            self.pending[(RESPONSE_VECTOR >> 5) as usize] |= 1 << (RESPONSE_VECTOR & 31);
        }
        Ok(())
    }
}

impl Lifecycle for Spmi {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if !proposed.powered || proposed.reset {
            return Err(
                "SPMI physical reset/supply retention is unqualified; queue reset is a separate software operation",
            );
        }
        if !proposed.clocked || proposed.quiesced {
            if self.partial.is_some() {
                return Err(
                    "SPMI pause while a partial request owns the transaction is unqualified",
                );
            }
            if self.enable.iter().any(|&enabled| enabled != 0) {
                return Err(
                    "SPMI pause with an armed interrupt has unqualified wake/capture semantics",
                );
            }
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        self.lifecycle = proposed;
    }
}

impl MmioDevice for Spmi {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let err = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(err(
                "SPMI MMIO while the physical clock is stopped is unqualified",
            ));
        }
        if self.lifecycle.quiesced && offset == RESPONSE {
            return Err(err("SPMI response ownership cannot advance while quiesced"));
        }
        if width != Width::Word {
            return Err(err("SPMI registers are 32-bit"));
        }
        let value = match offset {
            STATUS => self.status(),
            RESPONSE => {
                let word = self
                    .responses
                    .pop_front()
                    .ok_or_else(|| err("SPMI response FIFO read while empty"))?;
                self.update_irq(access);
                word
            }
            at if (ENABLE..ENABLE + 4 * GROUPS as u64).contains(&at) => {
                self.enable[((at - ENABLE) / 4) as usize]
            }
            at if (PENDING..PENDING + 4 * GROUPS as u64).contains(&at) => {
                self.pending[((at - PENDING) / 4) as usize]
            }
            CONTROL => self.control,
            QUEUE_RESET => 0,
            at if (FAULT_LATCHES..FAULT_LATCHES + 0x10).contains(&at) => 0,
            at if FAULT_COUNTERS
                .iter()
                .any(|&(base, count)| (base..base + 4 * count).contains(&at)) =>
            {
                0
            }
            _ => return Err(err("unmodeled SPMI register")),
        };
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let err = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if !self.lifecycle.clocked || self.lifecycle.quiesced {
            return Err(err("SPMI controller transactions are paused"));
        }
        if width != Width::Word {
            return Err(err("SPMI registers are 32-bit"));
        }
        let value = value as u32;
        match offset {
            REQUEST => self.request(value, access.now).map_err(err)?,
            at if (ENABLE..ENABLE + 4 * GROUPS as u64).contains(&at) => {
                self.enable[((at - ENABLE) / 4) as usize] = value;
            }
            at if (PENDING..PENDING + 4 * GROUPS as u64).contains(&at) => {
                self.pending[((at - PENDING) / 4) as usize] &= !value;
            }
            CONTROL => self.control = value,
            QUEUE_RESET => {
                if value != 1 {
                    return Err(err("SPMI queue reset other than bit 0"));
                }
                self.partial = None;
                self.responses.clear();
            }
            // Read-then-write-back acknowledges latched faults; none latch.
            at if (FAULT_LATCHES..FAULT_LATCHES + 0x10).contains(&at) => {
                if value != 0 {
                    return Err(err("SPMI fault latch acknowledge of an unlatched fault"));
                }
            }
            _ => return Err(err("unmodeled SPMI register")),
        }
        self.update_irq(access);
        Ok(())
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        // Slaves such as the PMIC own independent clocks, rails and timers.
        // Gating the SPMI master cannot suspend their autonomous time.
        Ok(self
            .slaves
            .iter_mut()
            .filter_map(|(_, slave)| slave.advance(access.now))
            .min())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    /// A byte register file of 256 registers; address 0xff NACKs.
    struct Bytes([u8; 0x100]);
    impl SpmiSlave for Bytes {
        fn read(&mut self, address: u16, data: &mut [u8], _: u64) -> Result<(), SlaveError> {
            let at = address as usize;
            if at + data.len() > 0xff {
                return Err(SlaveError::Nack);
            }
            data.copy_from_slice(&self.0[at..at + data.len()]);
            Ok(())
        }
        fn write(&mut self, address: u16, data: &[u8], _: u64) -> Result<(), SlaveError> {
            let at = address as usize;
            if at + data.len() > 0xff {
                return Err(SlaveError::Nack);
            }
            self.0[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    fn wr(c: &mut Spmi, a: &mut Access<'_>, offset: u64, value: u32) {
        c.write(offset, Width::Word, u64::from(value), a).unwrap();
    }
    fn rd(c: &mut Spmi, a: &mut Access<'_>, offset: u64) -> u32 {
        c.read(offset, Width::Word, a).unwrap() as u32
    }
    fn asserted(c: &Spmi) -> bool {
        c.enable.iter().zip(&c.pending).any(|(e, p)| e & p != 0)
    }
    fn controller() -> Spmi {
        let mut c = Spmi::new(AicInput::new(0, 0x180));
        c.attach(0xe, Box::new(Bytes([0; 0x100]))).unwrap();
        c
    }

    #[test]
    fn extended_long_write_then_read_round_trips_with_ack_parity_and_vector() {
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let mut c = controller();
        assert_eq!(rd(&mut c, &mut a, STATUS), 0x0100_0100);
        wr(&mut c, &mut a, ENABLE + 4 * 8, 1);
        // Write 5 bytes at 0x10 (ext-long write, len-1 = 4), last chunk.
        let write = 0x10 << 16 | LAST | 0xe << 8 | 0x30 | 4;
        wr(&mut c, &mut a, REQUEST, write);
        assert_eq!(rd(&mut c, &mut a, STATUS), RESPONSE_EMPTY);
        wr(&mut c, &mut a, REQUEST, 0x4433_2211);
        wr(&mut c, &mut a, REQUEST, 0x55);
        assert!(asserted(&c));
        assert_eq!(rd(&mut c, &mut a, STATUS), REQUEST_EMPTY);
        assert_eq!(
            rd(&mut c, &mut a, RESPONSE) & 0xffff,
            (write & 0x7fff) | ACK
        );
        wr(&mut c, &mut a, PENDING + 4 * 8, 1);
        assert!(!asserted(&c));
        // Read 6 bytes at 0x10 (ext-long read, len-1 = 5).
        let read = 0x10 << 16 | LAST | 0xe << 8 | 0x38 | 5;
        wr(&mut c, &mut a, REQUEST, read);
        let header = rd(&mut c, &mut a, RESPONSE);
        assert_eq!(header & 0xfff, read & 0xfff);
        assert_eq!(header >> 16, 0x3f);
        assert_eq!(rd(&mut c, &mut a, RESPONSE), 0x4433_2211);
        assert_eq!(rd(&mut c, &mut a, RESPONSE), 0x55);
        assert_eq!(rd(&mut c, &mut a, STATUS), 0x0100_0100);
        // The read's last chunk raised the enabled response vector again.
        assert!(latch.is_asserted(Wire::Aic(AicInput::new(0, 0x180))));
    }

    #[test]
    fn absent_slaves_and_slave_refusals_nack_and_reads_fail_parity() {
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let mut c = controller();
        let write = 3 << 8 | LAST | 0x30;
        wr(&mut c, &mut a, REQUEST, write);
        wr(&mut c, &mut a, REQUEST, 7);
        assert_eq!(rd(&mut c, &mut a, RESPONSE) & ACK, 0);
        let read = 0xff << 16 | 0xe << 8 | LAST | 0x38 | 1;
        wr(&mut c, &mut a, REQUEST, read);
        assert_eq!(rd(&mut c, &mut a, RESPONSE) >> 15, 0);
        assert_eq!(rd(&mut c, &mut a, RESPONSE), 0);
        // An 8-bit extended access cannot carry a 16-bit address.
        assert!(
            c.write(
                REQUEST,
                Width::Word,
                u64::from(0x100u32 << 16 | 0xe << 8 | 0x20),
                &mut a
            )
            .is_err()
        );
        assert!(c.read(RESPONSE, Width::Word, &mut a).is_err());
    }

    #[test]
    fn queue_reset_flushes_a_partial_command_and_unknown_commands_refuse() {
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let mut c = controller();
        wr(&mut c, &mut a, REQUEST, 0xe << 8 | 0x30 | 7);
        assert_eq!(rd(&mut c, &mut a, STATUS), RESPONSE_EMPTY);
        wr(&mut c, &mut a, CONTROL, 0x8000_0001);
        wr(&mut c, &mut a, CONTROL, 0);
        wr(&mut c, &mut a, QUEUE_RESET, 1);
        assert_eq!(rd(&mut c, &mut a, QUEUE_RESET), 0);
        assert_eq!(rd(&mut c, &mut a, STATUS), 0x0100_0100);
        // Register 0 write (0x80) and the sleep command (0x11) are not modeled.
        for opcode in [0x80, 0x11] {
            assert!(
                c.write(
                    REQUEST,
                    Width::Word,
                    u64::from(0xe << 8 | LAST | opcode),
                    &mut a
                )
                .is_err()
            );
        }
        assert_eq!(rd(&mut c, &mut a, BANK_B + 0x200), 0);
        assert_eq!(rd(&mut c, &mut a, BANK_B + 0x274), 0);
        assert!(c.read(0xb0, Width::Word, &mut a).is_err());
        assert!(c.read(STATUS, Width::Byte, &mut a).is_err());
    }
    #[test]
    fn retained_pauses_keep_masked_response_ownership_and_independent_inputs() {
        let mut c = controller();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let command = 0x10 << 16 | LAST | 0xe << 8 | 0x33;
        wr(&mut c, &mut a, REQUEST, command);
        wr(&mut c, &mut a, REQUEST, 0x4433_2211);
        let responses = c.responses.clone();
        let pending = c.pending;
        let running = c.lifecycle;
        let paused = LifecycleState {
            clocked: false,
            quiesced: true,
            ..running
        };
        c.check_lifecycle(paused).unwrap();
        c.set_lifecycle(paused, &mut a);
        assert!(c.read(RESPONSE, Width::Word, &mut a).is_err());
        assert!(c.write(QUEUE_RESET, Width::Word, 1, &mut a).is_err());
        assert_eq!(c.responses, responses);
        assert_eq!(c.pending, pending);
        // Clock restart cannot clear an independent quiesce input or pop a reply.
        let quiesced = LifecycleState {
            clocked: true,
            ..paused
        };
        c.check_lifecycle(quiesced).unwrap();
        c.set_lifecycle(quiesced, &mut a);
        assert_eq!(rd(&mut c, &mut a, STATUS), REQUEST_EMPTY);
        assert!(c.read(RESPONSE, Width::Word, &mut a).is_err());
        assert!(c.write(REQUEST, Width::Word, 0, &mut a).is_err());
        assert_eq!(c.responses, responses);
        c.check_lifecycle(running).unwrap();
        c.set_lifecycle(running, &mut a);
        assert_eq!(rd(&mut c, &mut a, RESPONSE), responses[0]);
        assert_eq!(c.pending, pending); // FIFO pop does not acknowledge the vector.
        assert!(c.read(RESPONSE, Width::Word, &mut a).is_err());
        wr(&mut c, &mut a, REQUEST, 0x10 << 16 | LAST | 0xe << 8 | 0x3b);
        assert_eq!(rd(&mut c, &mut a, RESPONSE) >> 16, 0xf);
        assert_eq!(rd(&mut c, &mut a, RESPONSE), 0x4433_2211);
    }
    #[test]
    fn partial_requests_armed_vectors_and_destructive_edges_refuse_before_effects() {
        let mut c = controller();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let running = c.lifecycle;
        wr(&mut c, &mut a, REQUEST, 0x10 << 16 | LAST | 0xe << 8 | 0x37);
        wr(&mut c, &mut a, REQUEST, 0x4433_2211);
        for proposed in [
            LifecycleState {
                clocked: false,
                ..running
            },
            LifecycleState {
                quiesced: true,
                ..running
            },
            LifecycleState {
                reset: true,
                ..running
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..running
            },
            LifecycleState {
                powered: false,
                retention: false,
                ..running
            },
        ] {
            assert!(c.check_lifecycle(proposed).is_err());
            assert_eq!(c.lifecycle, running);
            assert_eq!(c.partial.as_ref().unwrap().1, [0x4433_2211]);
            assert!(c.responses.is_empty());
        }
        wr(&mut c, &mut a, REQUEST, 0x8877_6655);
        assert_eq!(c.responses.len(), 1);
        wr(&mut c, &mut a, ENABLE + 4 * 8, 1);
        assert!(
            c.check_lifecycle(LifecycleState {
                clocked: false,
                ..running
            })
            .is_err()
        );
        assert!(
            c.check_lifecycle(LifecycleState {
                quiesced: true,
                ..running
            })
            .is_err()
        );
        assert!(asserted(&c));
        assert_eq!(c.responses.len(), 1);
        assert!(latch.is_asserted(Wire::Aic(AicInput::new(0, 0x180))));
    }
    #[test]
    fn actual_pmic_alarm_time_and_output_continue_while_spmi_master_clock_is_paused() {
        use crate::platform::apple::{
            counter::FREQUENCY_HZ,
            pmu::{Pmu, Rtc},
        };
        let rtc = Rtc {
            upcount: 0xf802,
            clock_offset: 0xf900,
            alarm_control: 0xf800,
            alarm_enable: 0x40,
            alarm_offset: 0xf808,
            alarm_event: 0xf80c,
            irq_mask: 0xf80e,
            event_mask: 1,
            interrupt_mask: 1,
        };
        let pmu = Pmu::new(Vec::new(), Some(rtc), None);
        let alarm = pmu.interrupt();
        let mut c = Spmi::new(AicInput::new(0, 0x180));
        c.attach(0xe, Box::new(pmu)).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        for (address, opcode, value) in [
            (rtc.alarm_offset, 0x33, 30),
            (rtc.alarm_control, 0x30, 0x41),
        ] {
            wr(
                &mut c,
                &mut a,
                REQUEST,
                u32::from(address) << 16 | LAST | 0xe << 8 | opcode,
            );
            wr(&mut c, &mut a, REQUEST, value);
            assert_ne!(rd(&mut c, &mut a, RESPONSE) & ACK, 0);
        }
        assert_eq!(c.advance(&mut a), Ok(Some(30 * FREQUENCY_HZ)));
        let running = c.lifecycle;
        let paused = LifecycleState {
            clocked: false,
            quiesced: true,
            ..running
        };
        c.check_lifecycle(paused).unwrap();
        c.set_lifecycle(paused, &mut a);
        a.now = 30 * FREQUENCY_HZ;
        assert_eq!(c.advance(&mut a), Ok(None));
        assert!(alarm.asserted()); // PMIC's external output is not the SPMI response IRQ.
        assert!(c.read(RESPONSE, Width::Word, &mut a).is_err());
        assert!(
            c.check_lifecycle(LifecycleState {
                reset: true,
                ..running
            })
            .is_err()
        );
        assert!(alarm.asserted());
        c.check_lifecycle(running).unwrap();
        c.set_lifecycle(running, &mut a);
        wr(
            &mut c,
            &mut a,
            REQUEST,
            u32::from(rtc.alarm_event) << 16 | LAST | 0xe << 8 | 0x38,
        );
        assert_eq!(rd(&mut c, &mut a, RESPONSE) >> 16, 1);
        assert_eq!(rd(&mut c, &mut a, RESPONSE), 1);
        assert!(alarm.asserted()); // Reading does not acknowledge the PMIC event.
    }
    #[test]
    fn mounted_spmi_aliases_share_one_checked_controller_capability() {
        use crate::platform::apple::bus::Bus;
        let mut bus = Bus::new();
        let device = bus.add(Box::new(controller()));
        bus.map(device, 0x10000, BANK_BYTES, 0).unwrap();
        bus.map(device, 0x20000, BANK_BYTES, BANK_B).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let paused = LifecycleState {
            powered: true,
            clocked: false,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let lifecycle = bus.lifecycle(device).unwrap();
        lifecycle.check_lifecycle(paused).unwrap();
        lifecycle.set_lifecycle(paused, &mut a);
        assert!(bus.read(0x10000 + STATUS, Width::Word, &mut a).is_err());
        assert!(bus.read(0x20000 + 0x110, Width::Word, &mut a).is_err());
        let running = LifecycleState {
            clocked: true,
            ..paused
        };
        let lifecycle = bus.lifecycle(device).unwrap();
        lifecycle.check_lifecycle(running).unwrap();
        lifecycle.set_lifecycle(running, &mut a);
        assert_eq!(
            bus.read(0x10000 + STATUS, Width::Word, &mut a),
            Ok(u64::from(REQUEST_EMPTY | RESPONSE_EMPTY))
        );
        assert_eq!(bus.read(0x20000 + 0x110, Width::Word, &mut a), Ok(0));
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires STELA_TEST_PMGR_KERNELCACHE naming the pinned original 26A434 Mach-O"]
    fn original_gen2_fifo_reset_is_separate_from_physical_controller_lifecycle() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var_os("STELA_TEST_PMGR_KERNELCACHE").expect("original KernelCache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        for (offset, opcode) in [
            (0x2dc35fc, 0x91029048u32),
            (0x2dc3668, 0xf9406408u32),
            (0x2dc366c, 0xb9400114u32),
            (0x2dc3670, 0xb900011fu32),
            (0x2dc3678, 0x94001d36u32),
            (0x2dc3680, 0xb9000114u32),
            (0x2dcabe8, 0x710006b5u32),
            (0x2dcac00, 0x2a080128u32),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original opcode at {offset:#x}"
            );
        }
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires STELA_TEST_PMGR_M1_KERNELCACHE naming the pinned original mac13j 26A434 Mach-O"]
    fn original_m1_gen2_queue_reset_preserves_separate_controller_control() {
        use sha2::{Digest, Sha256};
        let path = std::env::var_os("STELA_TEST_PMGR_M1_KERNELCACHE")
            .expect("original M1 Pro KernelCache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
        );
        // Original Gen2 init records the software queue-reset word at A+a4;
        // resetQueue saves control, zeros it, resets the queue, then restores it.
        for (offset, opcode) in [
            (0x2d4600c, 0x91029048u32),
            (0x2d46078, 0xf9406408u32),
            (0x2d4607c, 0xb9400114u32),
            (0x2d46080, 0xb900011fu32),
            (0x2d46088, 0x94001d36u32),
            (0x2d46090, 0xb9000114u32),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original M1 opcode at {offset:#x}"
            );
        }
    }
}
