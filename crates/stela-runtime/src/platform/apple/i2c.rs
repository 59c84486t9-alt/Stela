//! PASemi-derived Apple I2C byte PIO controller (`i2c,t8101`).
//!
//! Linux `drivers/i2c/busses/i2c-pasemi-core.c` at a0ff06b3 documents
//! START/STOP/read-count FIFO words, RX empty, status, mask and control.
//! The original `AppleS5L8940XI2CController` confirms the 32-bit accesses:
//! `executeIICCommand` (26A434 KC file 0x2cc1010..0x2cc10a8),
//! `_checkInterrupts` (0x2cc2238) and `_initRegs` (0x2cc0678).
//! FIFO counts at +8 are TX [7:0], RX [15:8] (`_runPolledModeProcessing`,
//! 0x2cc2528). +0x10 bit31 disables the auxiliary timeout at handoff
//! (0x2cc0708); other timer configurations refuse.
//!
//! Stela's emulated die implements revision 2, a revision the original driver
//! supports without the later semaphore and timing extensions. The boot stage
//! hands off idle, empty FIFOs, interrupts masked, divider zero and no tunables.
//! The functional shifter completes eagerly; it models no analog timing,
//! arbitration competitor or clock stretching. Its 128-byte receive capacity
//! matches the driver's bounded PIO command (0x2cc0f08). Unknown registers,
//! fields and target operations refuse, including diagnostic XFSTA, whose
//! encoding the available evidence does not establish.
use super::{
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};

pub const BYTES: u64 = 0x4000;
const NAME: &str = "Apple I2C";
const TX: u64 = 0x00;
const RX: u64 = 0x04;
const COUNTS: u64 = 0x08;
const TIMEOUT: u64 = 0x10;
const STATUS: u64 = 0x14;
const MASK: u64 = 0x18;
const CONTROL: u64 = 0x1c;
const REVISION: u64 = 0x28;
const RX_CONFIG: u64 = 0x2c;
const TIMING: u64 = 0x30;
const FILTER: u64 = 0x38;
const START: u32 = 1 << 8;
const STOP: u32 = 1 << 9;
const READ: u32 = 1 << 10;
const EMPTY: u32 = 1 << 8;
const MTE: u32 = 1 << 16;
const MRNE: u32 = 1 << 19;
const RX_THRESHOLD: u32 = 1 << 20;
const NACK: u32 = 1 << 21;
const END: u32 = 1 << 27;
const ACTIVE: u32 = 1 << 28;
// _initRegs acknowledges 0x2aa00040. Live status bits are never W1C storage.
const LATCHES: u32 = 0x2aa0_0040;
const STATUS_KNOWN: u32 = LATCHES | MTE | MRNE | RX_THRESHOLD | ACTIVE | 0x18;
const TX_RESET: u32 = 1 << 9;
const RX_RESET: u32 = 1 << 10;
const UNJAM: u32 = 1 << 8;
const DISABLE_TIMEOUT: u32 = 1 << 31;
const CAPACITY: usize = 128;

/// A target NACK is a bus result; an undescribed operation stops the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    Nack,
    Unsupported(&'static str),
}

/// One seven-bit I2C target. `write` is the buffered write phase, followed by
/// `read.len()` clocks in the read phase. `stop=false` permits split block reads;
/// the target retains its register cursor until STOP or another selector.
/// An error must leave target state and the supplied read buffer unchanged.
/// Controller reset aborts framing, without resetting the target's hardware.
pub trait I2cTarget {
    fn transfer(&mut self, write: &[u8], read: &mut [u8], stop: bool) -> Result<(), TargetError>;
    fn abort(&mut self) {}
    /// Re-evaluates outputs that change without a transfer, such as an
    /// interrupt line that follows external state.
    fn advance(&mut self) {}
}

/// An electrically present target whose protocol has not been qualified.
/// It refuses accesses instead of presenting the target as absent (NACK).
pub struct Unmodeled(pub &'static str);
impl I2cTarget for Unmodeled {
    fn transfer(&mut self, _: &[u8], _: &mut [u8], _: bool) -> Result<(), TargetError> {
        Err(TargetError::Unsupported(self.0))
    }
}

struct Target {
    address: u8,
    device: Box<dyn I2cTarget>,
}

pub struct I2c {
    targets: Vec<Target>,
    irq: AicInput,
    control: u32,
    timeout: u32,
    rx_config: u32,
    timing: u32,
    filter: u32,
    mask: u32,
    status: u32,
    address: Option<u8>,
    reading: bool,
    write: Vec<u8>,
    rx: VecDeque<u8>,
}

impl I2c {
    pub fn new(irq: AicInput) -> Self {
        Self {
            targets: Vec::new(),
            irq,
            control: 0,
            timeout: DISABLE_TIMEOUT,
            rx_config: 0,
            timing: 0,
            filter: 0,
            mask: 0,
            status: 0,
            address: None,
            reading: false,
            write: Vec::new(),
            rx: VecDeque::new(),
        }
    }
    /// Attach only explicitly placed targets; an unoccupied address NACKs.
    pub fn attach(&mut self, address: u8, device: Box<dyn I2cTarget>) -> Result<(), &'static str> {
        if address == 0 || address >= 0x78 || self.targets.iter().any(|t| t.address == address) {
            return Err("invalid, reserved or duplicate I2C target address");
        }
        if self.address.is_some() {
            return Err("cannot attach an I2C target during a transfer");
        }
        self.targets.push(Target { address, device });
        Ok(())
    }
    fn status(&self) -> u32 {
        self.status
            | MTE
            | 0x18
            | if self.rx.is_empty() { 0 } else { MRNE }
            | if self.address.is_some() { ACTIVE } else { 0 }
            | if self.rx_config >> 8 & 0xff != 0
                && self.rx.len() >= (self.rx_config >> 8 & 0xff) as usize
            {
                RX_THRESHOLD
            } else {
                0
            }
    }
    fn interrupt(&self, access: &mut Access<'_>) {
        access
            .interrupts
            .set_level(Wire::Aic(self.irq), self.status() & self.mask != 0);
    }
    fn exchange(
        &mut self,
        write: &[u8],
        count: usize,
        stop: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let address = self.address.ok_or("I2C FIFO data without START")?;
        let mut data = alloc::vec![0; count];
        let result = self
            .targets
            .iter_mut()
            .find(|t| t.address == address)
            .map_or(Err(TargetError::Nack), |t| {
                t.device.transfer(write, &mut data, stop)
            });
        match result {
            Ok(()) => Ok(data),
            Err(TargetError::Nack) => {
                self.status |= NACK;
                Ok(Vec::new())
            }
            // A refusal stops the machine: name the transaction it refused.
            Err(TargetError::Unsupported(reason)) => Err(Box::leak(
                alloc::format!(
                    "{reason} (target {address:#04x}, wrote {write:02x?}, read {count})"
                )
                .into_boxed_str(),
            )),
        }
    }
    fn fifo(&mut self, word: u32) -> Result<(), &'static str> {
        if word & !(START | STOP | READ | 0xff) != 0 || word & (START | READ) == (START | READ) {
            return Err("unknown I2C FIFO fields or simultaneous START/read-count");
        }
        let stop = word & STOP != 0;
        if word & START != 0 {
            let address = (word as u8) >> 1;
            if address == 0 || address >= 0x78 {
                return Err("reserved or ten-bit I2C addressing");
            }
            if self.address.is_some()
                && (self.address != Some(address) || self.reading || stop || word & 1 == 0)
            {
                return Err("only same-target write-to-read I2C repeated START is modeled");
            }
            if stop {
                return Err("I2C address-only QUICK transactions are undetermined");
            }
            self.address = Some(address);
            self.reading = word & 1 != 0;
            // An address is physically acknowledged before any data clock.
            if !self.targets.iter().any(|t| t.address == address) {
                self.status |= NACK;
            }
            return Ok(());
        }
        if word & READ != 0 {
            let count = (word & 0xff) as usize;
            if !self.reading || count == 0 {
                return Err("I2C read-count without read address or zero count");
            }
            if self.rx.len() + count > CAPACITY {
                return Err("I2C receive FIFO backpressure is not modeled");
            }
            let data = self.exchange(&self.write.clone(), count, stop)?;
            self.rx.extend(data);
            self.write.clear();
            // READ without STOP also completes a split receive operation (Linux block reads).
            self.status |= END;
        } else {
            if self.address.is_none() || self.reading {
                return Err("I2C write byte without write address");
            }
            if self.write.len() == CAPACITY {
                return Err("I2C write phase exceeds PIO capacity");
            }
            if stop {
                let mut data = self.write.clone();
                data.push(word as u8);
                self.exchange(&data, 0, true)?;
                self.write.clear();
            } else {
                self.write.push(word as u8);
            }
        }
        if stop {
            self.address = None;
            self.reading = false;
            self.status |= END;
        }
        Ok(())
    }
}

impl MmioDevice for I2c {
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
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("I2C registers require aligned 32-bit accesses"));
        }
        let value = match offset {
            RX => self.rx.pop_front().map_or(EMPTY, u32::from),
            COUNTS => (self.rx.len() as u32) << 8,
            TIMEOUT => self.timeout,
            STATUS => self.status(),
            MASK => self.mask,
            CONTROL => self.control,
            REVISION => 2,
            RX_CONFIG => self.rx_config,
            TIMING => self.timing,
            FILTER => self.filter,
            _ => return Err(err("unmodeled I2C register or write-only FIFO")),
        };
        self.interrupt(access);
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
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("I2C registers require aligned 32-bit accesses"));
        }
        let value = value as u32;
        match offset {
            TX => self.fifo(value).map_err(err)?,
            STATUS => {
                if value & !STATUS_KNOWN != 0 {
                    return Err(err("unknown I2C status acknowledgement bits"));
                }
                self.status &= !(value & LATCHES);
            }
            MASK => {
                if value & !STATUS_KNOWN != 0 {
                    return Err(err("unknown I2C interrupt mask bits"));
                }
                self.mask = value;
            }
            CONTROL => {
                if value & !(0xff | UNJAM | TX_RESET | RX_RESET) != 0 {
                    return Err(err("I2C revision-2 control fields are undetermined"));
                }
                if value & TX_RESET != 0 {
                    for target in &mut self.targets {
                        target.device.abort();
                    }
                    self.address = None;
                    self.reading = false;
                    self.write.clear();
                    self.status = 0;
                }
                if value & RX_RESET != 0 {
                    self.rx.clear();
                }
                self.control = value & 0xff;
            }
            TIMEOUT if value == DISABLE_TIMEOUT => self.timeout = value,
            // Original driver's RMW tunables are configuration storage. Their
            // full32 handoff image is zero, an explicit Stela boot-stage choice.
            RX_CONFIG => self.rx_config = value,
            TIMING => self.timing = value,
            FILTER => self.filter = value,
            _ => {
                return Err(err(
                    "unmodeled I2C register, timeout setting or read-only register",
                ));
            }
        }
        self.interrupt(access);
        Ok(())
    }
    fn advance(&mut self, _: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        for target in &mut self.targets {
            target.device.advance();
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    struct Echo {
        cursor: u8,
    }
    impl I2cTarget for Echo {
        fn transfer(&mut self, write: &[u8], read: &mut [u8], _: bool) -> Result<(), TargetError> {
            if write.first() == Some(&0xff) {
                return Err(TargetError::Unsupported("test target refusal"));
            }
            let mut cursor = write.first().copied().unwrap_or(self.cursor);
            for byte in read {
                *byte = cursor;
                cursor = cursor.wrapping_add(1);
            }
            self.cursor = cursor;
            Ok(())
        }
    }
    fn wr(c: &mut I2c, a: &mut Access<'_>, offset: u64, value: u32) {
        c.write(offset, Width::Word, u64::from(value), a).unwrap();
    }
    fn rd(c: &mut I2c, a: &mut Access<'_>, offset: u64) -> u64 {
        c.read(offset, Width::Word, a).unwrap()
    }
    #[test]
    fn combined_split_read_counts_mask_ack_and_reset() {
        let irq = AicInput::new(0, 761);
        let mut c = I2c::new(irq);
        c.attach(0x38, Box::new(Echo { cursor: 0 })).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        wr(&mut c, &mut a, TX, START | 0x70);
        wr(&mut c, &mut a, TX, 0x1a);
        wr(&mut c, &mut a, TX, START | 0x71);
        wr(&mut c, &mut a, TX, READ | 1);
        assert_eq!(rd(&mut c, &mut a, COUNTS), 0x100);
        assert_eq!(rd(&mut c, &mut a, RX), 0x1a);
        wr(&mut c, &mut a, TX, READ | STOP | 3);
        assert_eq!(rd(&mut c, &mut a, STATUS) & ACTIVE as u64, 0);
        wr(&mut c, &mut a, MASK, END);

        assert_eq!(
            [
                rd(&mut c, &mut a, RX),
                rd(&mut c, &mut a, RX),
                rd(&mut c, &mut a, RX)
            ],
            [0x1b, 0x1c, 0x1d]
        );
        assert_eq!(rd(&mut c, &mut a, RX), u64::from(EMPTY));
        wr(&mut c, &mut a, STATUS, END);
        assert_eq!(rd(&mut c, &mut a, STATUS) & END as u64, 0);
        wr(&mut c, &mut a, CONTROL, TX_RESET | RX_RESET | UNJAM | 4);
        assert_eq!(rd(&mut c, &mut a, CONTROL), 4);
        assert_eq!(rd(&mut c, &mut a, COUNTS), 0);
    }
    #[test]
    fn interrupt_deasserts_only_after_the_enabled_source_is_acknowledged() {
        let irq = AicInput::new(0, 761);
        let mut c = I2c::new(irq);
        let mut latch = InterruptLatch::new();
        {
            let mut a = Access::new(0, 0, &mut latch);
            wr(&mut c, &mut a, MASK, END | NACK);
            wr(&mut c, &mut a, TX, START | 0x72);
            wr(&mut c, &mut a, TX, STOP);
        }
        assert!(latch.is_asserted(Wire::Aic(irq)));
        {
            let mut a = Access::new(0, 0, &mut latch);
            wr(&mut c, &mut a, STATUS, END);
        }
        assert!(latch.is_asserted(Wire::Aic(irq)));
        {
            let mut a = Access::new(0, 0, &mut latch);
            wr(&mut c, &mut a, STATUS, NACK);
        }
        assert!(!latch.is_asserted(Wire::Aic(irq)));
    }
    #[test]
    fn absent_target_nacks_and_undescribed_target_refuses_without_effect() {
        let mut c = I2c::new(AicInput::new(0, 761));
        c.attach(0x38, Box::new(Echo { cursor: 0 })).unwrap();
        assert!(c.attach(0x38, Box::new(Echo { cursor: 0 })).is_err());
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        wr(&mut c, &mut a, TX, START | 0x72);
        wr(&mut c, &mut a, TX, STOP);
        assert_ne!(rd(&mut c, &mut a, STATUS) & NACK as u64, 0);
        wr(&mut c, &mut a, STATUS, LATCHES);
        wr(&mut c, &mut a, TX, START | 0x70);
        let before = c.status();
        assert!(
            c.write(TX, Width::Word, (STOP | 0xff).into(), &mut a)
                .is_err()
        );
        assert_eq!(c.status(), before);
        assert!(c.write.is_empty());
        for (offset, width) in [(0xc, Width::Word), (RX, Width::Byte), (0x40, Width::Word)] {
            assert!(c.read(offset, width, &mut a).is_err());
        }
        assert!(c.write(CONTROL, Width::Word, 1 << 11, &mut a).is_err());
    }
}
