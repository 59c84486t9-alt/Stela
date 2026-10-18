//! GPIO output bank for peripheral chip-select wiring.
//!
//! Linux `drivers/pinctrl/pinctrl-apple-gpio.c` documents per-pin words at
//! `4 * pin`, DATA bit 0, MODE [3:1], PERIPH [6:5], pulls [8:7], input
//! enable 9, drive strength [11:10]/[23:22], Schmitt 15, group [18:16]
//! and LOCK 21. The 26A434 `AppleT8101GPIOIC::initPinsAndGroups` file
//! 0x24db5b8 snapshots these words and clears IRQ groups at 0x800 +
//! group * 0x40; `_readReg32`/`_writeReg32` 0x24db7e8/0x24db7f8,
//! `setGPIODirection` 0x24dd094 and `setGPIOData` 0x24dd3b0 use them.
//! MODE values are 1 output, 2/3 level-high/low, 4/5/6 rising/falling/any
//! edge interrupt and 7 interrupt-disabled input. Edge modes are accepted:
//! nothing in the model drives this bank, so no edge ever latches. A level
//! mode is accepted only when its pull holds the line inactive; a level
//! that would assert, or an undetermined one, refuses because delivering
//! GPIO interrupts to the AIC is not modeled. A PERIPH function (such as
//! i2c0's `gpio-iic_sda` pin) is recorded on an interrupt-disabled input:
//! the pin then has no GPIO-driven level, and peripheral models do not gate
//! on the mux. PERIPH with output or interrupt modes, and global/wake
//! registers, explicitly refuse.
//! Stela boot handoff uses interrupt-disabled input words (0xe), with
//! peripheral CS pins configured as GPIO outputs high (0x3). The only
//! external levels are the board's I2C pull-ups on the ADT's
//! `gpio-iic_scl`/`gpio-iic_sda` pins: I2C lines are open-drain and pulled
//! high (NXP UM10204 section 3.1.1), and the I2C models complete each
//! transaction between register accesses, so a receiver samples the idle
//! high level. Nothing else drives this bank. Receiver configuration does not
//! sample DATA: an unconnected input can be enabled without a pull, but
//! reading that word then refuses until software supplies a pull or disables
//! the receiver. No level is invented.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::{vec, vec::Vec};
const NAME: &str = "Apple GPIO";
const DATA: u32 = 1;
const MODE: u32 = 7 << 1;
const OUTPUT: u32 = 1 << 1;
const LEVEL_HIGH: u32 = 2 << 1;
const LEVEL_LOW: u32 = 3 << 1;
const EDGE_RISING: u32 = 4 << 1;
const EDGE_ANY: u32 = 6 << 1;
const INPUT_OFF: u32 = 7 << 1;
const INPUT_ENABLE: u32 = 1 << 9;
const PULL: u32 = 3 << 7;
const PERIPH: u32 = 3 << 5;
const LOCK: u32 = 1 << 21;
const FIELDS: u32 =
    DATA | MODE | PERIPH | PULL | INPUT_ENABLE | 3 << 10 | 1 << 15 | 7 << 16 | LOCK | 3 << 22;
const IRQ_BASE: u64 = 0x800;
const IRQ_STRIDE: u64 = 0x40;

pub struct Gpio {
    pins: Vec<u32>,
    pulled_up: Vec<bool>,
    groups: u32,
}
impl Gpio {
    /// `selects` are chip-select outputs; `pulled_up` are I2C lines.
    pub fn new(
        pins: u32,
        groups: u32,
        selects: &[u32],
        pulled_up: &[u32],
    ) -> Result<Self, &'static str> {
        if pins == 0
            || pins > 512
            || groups == 0
            || groups > 7
            || selects.iter().chain(pulled_up).any(|&p| p >= pins)
            || selects.iter().any(|p| pulled_up.contains(p))
        {
            return Err("invalid GPIO pin/group geometry, CS or I2C pin");
        }
        let mut bank = Self {
            pins: vec![INPUT_OFF; pins as usize],
            pulled_up: vec![false; pins as usize],
            groups,
        };
        for &pin in selects {
            bank.pins[pin as usize] = OUTPUT | DATA;
        }
        for &pin in pulled_up {
            bank.pulled_up[pin as usize] = true;
        }
        Ok(bank)
    }
    /// The level a receiver samples on an input pin, when one is determined:
    /// a board pull-up, otherwise the pin's own pull. Without either it floats.
    fn input_level(&self, pin: usize, word: u32) -> Option<bool> {
        if self.pulled_up[pin] {
            return Some(true);
        }
        match (word >> 7) & 3 {
            0 => None,
            1 => Some(false),
            _ => Some(true),
        }
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
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            if word & MODE != OUTPUT
                && word & INPUT_ENABLE != 0
                && self.input_level(pin, word).is_none()
            {
                return Err(err(
                    "unconnected GPIO input has no pull; DATA is undetermined",
                ));
            }
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
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            let mut value = value as u32;
            let mode = value & MODE;
            if value & !FIELDS != 0 || mode == 0 {
                return Err(err("unknown GPIO fields are not modeled"));
            }
            if value & PERIPH != 0 && mode != INPUT_OFF {
                return Err(err(
                    "GPIO peripheral mux with output or interrupt mode is not modeled",
                ));
            }
            let level = self.input_level(pin, value);
            if mode != OUTPUT && value & INPUT_ENABLE != 0 {
                // Enabling the receiver changes configuration, but does not
                // observe an undetermined DATA. A later read refuses.
                match level {
                    None => {}
                    Some(false) => value &= !DATA,
                    Some(true) => value |= DATA,
                }
            }
            let asserted = match mode {
                LEVEL_HIGH => level != Some(false),
                LEVEL_LOW => level != Some(true),
                _ => false,
            };
            if asserted {
                return Err(err(
                    "GPIO level interrupt would assert or has an undetermined level; AIC delivery is not modeled",
                ));
            }
            if word & LOCK != 0 {
                if (word ^ value) & !(DATA | LOCK) != 0 {
                    return Err(err("GPIO configuration is locked"));
                }
                value |= LOCK;
            }
            self.pins[pin] = value;
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
    fn enabling_an_undriven_receiver_does_not_invent_a_sample() {
        let mut bank = Gpio::new(213, 7, &[], &[]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let input = INPUT_OFF | INPUT_ENABLE | 2 << 16;
        bank.write(4 * 84, Width::Word, input.into(), &mut a)
            .unwrap();
        assert_eq!(bank.pins[84], input);
        assert!(bank.read(4 * 84, Width::Word, &mut a).is_err());
        assert_eq!(bank.pins[84], input);
        bank.write(4 * 84, Width::Word, (input | 1 << 7).into(), &mut a)
            .unwrap();
        assert_eq!(
            bank.read(4 * 84, Width::Word, &mut a),
            Ok(u64::from(input | 1 << 7))
        );
        bank.write(4 * 84, Width::Word, (input | 2 << 7).into(), &mut a)
            .unwrap();
        assert_eq!(
            bank.read(4 * 84, Width::Word, &mut a),
            Ok(u64::from(input | 2 << 7 | DATA))
        );
        bank.write(4 * 84, Width::Word, input.into(), &mut a)
            .unwrap();
        bank.write(4 * 84, Width::Word, u64::from(INPUT_OFF), &mut a)
            .unwrap();
        assert_eq!(
            bank.read(4 * 84, Width::Word, &mut a),
            Ok(u64::from(INPUT_OFF))
        );
    }
    #[test]
    fn edge_interrupts_never_latch_and_asserting_levels_refuse() {
        let mut bank = Gpio::new(213, 7, &[], &[]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        for mode in (EDGE_RISING..=EDGE_ANY).step_by(2) {
            let word = mode | INPUT_ENABLE | 2 << 16;
            bank.write(4 * 84, Width::Word, word.into(), &mut a)
                .unwrap();
            assert_eq!(bank.pins[84], word);
            assert_eq!(bank.read(0x800 + 2 * 0x40 + 8, Width::Word, &mut a), Ok(0));
        }
        let pulled_down = INPUT_ENABLE | 1 << 7;
        assert!(
            bank.write(
                4 * 84,
                Width::Word,
                (LEVEL_HIGH | INPUT_ENABLE).into(),
                &mut a
            )
            .is_err()
        );
        assert!(
            bank.write(
                4 * 84,
                Width::Word,
                (LEVEL_LOW | pulled_down).into(),
                &mut a
            )
            .is_err()
        );
        bank.write(
            4 * 84,
            Width::Word,
            (LEVEL_HIGH | pulled_down).into(),
            &mut a,
        )
        .unwrap();
        assert!(bank.write(4 * 84, Width::Word, 0, &mut a).is_err());
    }
    #[test]
    fn i2c_lines_sample_their_board_pull_up() {
        let mut bank = Gpio::new(213, 7, &[49], &[86]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let sda = INPUT_OFF | INPUT_ENABLE | 1 << 5;
        bank.write(4 * 86, Width::Word, sda.into(), &mut a).unwrap();
        assert_eq!(
            bank.read(4 * 86, Width::Word, &mut a),
            Ok(u64::from(sda | DATA))
        );
        // Even an internal pull-down loses to the external pull-up.
        bank.write(4 * 86, Width::Word, (sda | 1 << 7).into(), &mut a)
            .unwrap();
        assert_eq!(
            bank.read(4 * 86, Width::Word, &mut a),
            Ok(u64::from(sda | 1 << 7 | DATA))
        );
        let level_low = LEVEL_LOW | INPUT_ENABLE | 2 << 16;
        bank.write(4 * 86, Width::Word, level_low.into(), &mut a)
            .unwrap();
        assert!(
            bank.write(
                4 * 86,
                Width::Word,
                (LEVEL_HIGH | INPUT_ENABLE).into(),
                &mut a
            )
            .is_err()
        );
        assert!(Gpio::new(213, 7, &[49], &[49]).is_err());
    }
    #[test]
    fn peripheral_functions_record_the_mux_without_a_gpio_level() {
        let mut bank = Gpio::new(213, 7, &[49], &[]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let sda = INPUT_OFF | INPUT_ENABLE | 1 << 5;
        bank.write(4 * 110, Width::Word, sda.into(), &mut a)
            .unwrap();
        assert_eq!(bank.pins[110], sda);
        assert!(
            bank.write(49 * 4, Width::Word, u64::from(OUTPUT | 1 << 5), &mut a)
                .is_err()
        );
        assert!(
            bank.write(
                4 * 110,
                Width::Word,
                u64::from(EDGE_RISING | 1 << 5),
                &mut a
            )
            .is_err()
        );
        assert_eq!(bank.output(110), None);
    }
    #[test]
    fn cs_output_and_lock_and_unsupported_interrupt_are_explicit() {
        let mut bank = Gpio::new(213, 7, &[49], &[]).unwrap();
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
