//! GPIO output bank for peripheral chip-select wiring.
//!
//! Linux `drivers/pinctrl/pinctrl-apple-gpio.c` documents per-pin words at
//! `4 * pin`, DATA bit 0, MODE [3:1], PERIPH [6:5], pulls [8:7], input
//! enable 9, drive strength [11:10]/[23:22], Schmitt 15, group [18:16]
//! and LOCK 21. The 26A434 `AppleT8101GPIOIC::initPinsAndGroups` file
//! 0x24db5b8 snapshots these words and clears IRQ groups at 0x800 +
//! group * 0x40; `_readReg32`/`_writeReg32` 0x24db7e8/0x24db7f8,
//! `setGPIODirection` 0x24dd094 and `setGPIOData` 0x24dd3b0 use them.
//! Only output and interrupt-disabled input modes are implemented. Other
//! peripherals, interrupt enables and global/wake registers explicitly refuse.
//! Stela boot handoff uses interrupt-disabled input words (0xe), with
//! peripheral CS pins configured as GPIO outputs high (0x3); no external inputs
//! drive this bank. Enabling an unconnected input without a pull refuses.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::{vec, vec::Vec};
const NAME: &str = "Apple GPIO";
const DATA: u32 = 1;
const MODE: u32 = 7 << 1;
const OUTPUT: u32 = 1 << 1;
const INPUT_OFF: u32 = 7 << 1;
const INPUT_ENABLE: u32 = 1 << 9;
const PERIPH: u32 = 3 << 5;
const LOCK: u32 = 1 << 21;
const FIELDS: u32 =
    DATA | MODE | PERIPH | 3 << 7 | INPUT_ENABLE | 3 << 10 | 1 << 15 | 7 << 16 | LOCK | 3 << 22;
const IRQ_BASE: u64 = 0x800;
const IRQ_STRIDE: u64 = 0x40;

pub struct Gpio {
    pins: Vec<u32>,
    groups: u32,
}
impl Gpio {
    pub fn new(pins: u32, groups: u32, selects: &[u32]) -> Result<Self, &'static str> {
        if pins == 0
            || pins > 512
            || groups == 0
            || groups > 7
            || selects.iter().any(|&p| p >= pins)
        {
            return Err("invalid GPIO pin/group geometry or CS pin");
        }
        let mut pins = vec![INPUT_OFF; pins as usize];
        for &pin in selects {
            pins[pin as usize] = OUTPUT | DATA;
        }
        Ok(Self { pins, groups })
    }
    pub fn output(&self, pin: u32) -> Option<bool> {
        Self::driven_level(*self.pins.get(pin as usize)?)
    }
    pub(crate) fn driven_level(word: u32) -> Option<bool> {
        (word & MODE == OUTPUT && word & PERIPH == 0).then_some(word & DATA != 0)
    }
    fn irq_word(&self, offset: u64) -> bool {
        offset >= IRQ_BASE
            && (offset - IRQ_BASE) / IRQ_STRIDE < u64::from(self.groups)
            && (offset - IRQ_BASE) % IRQ_STRIDE < (self.pins.len() as u64).div_ceil(32) * 4
    }
}
impl MmioDevice for Gpio {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let err = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("GPIO registers require aligned 32-bit accesses"));
        }
        if let Some(&word) = self.pins.get(offset as usize / 4) {
            return Ok(u64::from(word));
        }
        if self.irq_word(offset) {
            return Ok(0);
        } // No interrupt-enabled pins exist.
        Err(err("unmodeled GPIO register"))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let err = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("GPIO registers require aligned 32-bit accesses"));
        }
        if let Some(word) = self.pins.get_mut(offset as usize / 4) {
            let mut value = value as u32;
            if value & !FIELDS != 0
                || value & PERIPH != 0
                || !matches!(value & MODE, OUTPUT | INPUT_OFF)
            {
                return Err(err(
                    "GPIO interrupts, peripheral mux or unknown fields are not modeled",
                ));
            }
            if value & MODE == INPUT_OFF && value & INPUT_ENABLE != 0 {
                match (value >> 7) & 3 {
                    0 => return Err(err("unconnected GPIO input has no pull")),
                    1 => value &= !DATA,
                    _ => value |= DATA,
                }
            }
            if *word & LOCK != 0 {
                if (*word ^ value) & !(DATA | LOCK) != 0 {
                    return Err(err("GPIO configuration is locked"));
                }
                value |= LOCK;
            }
            *word = value;
            return Ok(());
        }
        if self.irq_word(offset) {
            return Ok(());
        } // W1C of inactive input latches.
        Err(err("unmodeled GPIO register"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    #[test]
    fn cs_output_and_lock_and_unsupported_interrupt_are_explicit() {
        let mut bank = Gpio::new(213, 7, &[49]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        assert_eq!(bank.output(49), Some(true));
        bank.write(49 * 4, Width::Word, 2, &mut a).unwrap();
        assert_eq!(bank.output(49), Some(false));
        bank.write(49 * 4, Width::Word, u64::from(2 | LOCK), &mut a)
            .unwrap();
        assert!(bank.write(49 * 4, Width::Word, 0x202, &mut a).is_err());
        assert!(bank.write(0, Width::Word, 4, &mut a).is_err());
        assert!(bank.read(0xc48, Width::Word, &mut a).is_err());
        assert_eq!(bank.read(0x800, Width::Word, &mut a), Ok(0));
    }
}
