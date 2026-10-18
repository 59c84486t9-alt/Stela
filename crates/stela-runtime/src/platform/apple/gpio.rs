//! Apple GPIO bank: chip-select outputs, board-net inputs and pin interrupts.
//!
//! Linux `drivers/pinctrl/pinctrl-apple-gpio.c` documents per-pin words at
//! `4 * pin`, DATA bit 0, MODE [3:1], PERIPH [6:5], pulls [8:7], input
//! enable 9, drive strength [11:10]/[23:22], Schmitt 15, group [18:16]
//! and LOCK 21. The 26A434 `AppleT8101GPIOIC::initPinsAndGroups` file
//! 0x24db5b8 snapshots these words and clears IRQ groups at 0x800 +
//! group * 0x40; `_readReg32`/`_writeReg32` 0x24db7e8/0x24db7f8,
//! `setGPIODirection` 0x24dd094 and `setGPIOData` 0x24dd3b0 use them.
//! MODE values are 1 output, 2/3 level-high/low, 4/5/6 rising/falling/any
//! edge interrupt and 7 interrupt-disabled input (Linux
//! `apple_gpio_irq_type`). Each pin's group selects one IRQ status bank at
//! 0x800 + group * 0x40, one bit per pin, write-one-to-clear
//! (`apple_gpio_irq_ack`); the group's DT `interrupts` entry is the OR of
//! its bank. A level mode latches while its input is active, so it relatches
//! immediately after an acknowledgement; an edge mode latches on a sampled
//! transition. Linux masks a pin by switching it to mode 7; a latched bit
//! remains until software acknowledges it. A level mode on an input whose
//! level is undetermined refuses rather than choosing whether it asserts.
//! A PERIPH function (such as i2c0's `gpio-iic_sda` pin) is recorded on an
//! interrupt-disabled input: the pin then has no GPIO-driven level, and
//! peripheral models do not gate on the mux. PERIPH with output or interrupt
//! modes, and global/wake registers, explicitly refuse.
//!
//! Stela boot handoff uses interrupt-disabled input words (0xe), with
//! peripheral CS pins configured as GPIO outputs high (0x3). External levels
//! come only from board nets: open-drain lines pulled high, such as the
//! ADT's `gpio-iic_scl`/`gpio-iic_sda` I2C lines (NXP UM10204 section
//! 3.1.1; the I2C models complete each transaction between register
//! accesses, so a receiver samples the idle high level) and device interrupt
//! outputs that pull their net low. Receiver configuration does not sample
//! DATA: an unconnected input can be enabled without a pull, but reading
//! that word then refuses until software supplies a pull or disables the
//! receiver. No level is invented. Levels are sampled on each access and
//! each device advance, so a net change is observed at the next one.
use super::{
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::Cell;
const NAME: &str = "Apple GPIO";
const DATA: u32 = 1;
const MODE: u32 = 7 << 1;
const OUTPUT: u32 = 1 << 1;
const LEVEL_HIGH: u32 = 2 << 1;
const LEVEL_LOW: u32 = 3 << 1;
const EDGE_RISING: u32 = 4 << 1;
const EDGE_FALLING: u32 = 5 << 1;
const EDGE_ANY: u32 = 6 << 1;
const INPUT_OFF: u32 = 7 << 1;
const INPUT_ENABLE: u32 = 1 << 9;
const PULL: u32 = 3 << 7;
const PERIPH: u32 = 3 << 5;
const GROUP_SHIFT: u32 = 16;
const LOCK: u32 = 1 << 21;
const FIELDS: u32 =
    DATA | MODE | PERIPH | PULL | INPUT_ENABLE | 3 << 10 | 1 << 15 | 7 << 16 | LOCK | 3 << 22;
const IRQ_BASE: u64 = 0x800;
const IRQ_STRIDE: u64 = 0x40;

/// A board net pulled high: open-drain outputs attached to it pull it low.
/// Clones share the net; at most 64 outputs attach to one net.
#[derive(Debug, Clone, Default)]
pub struct Net(Rc<Cell<NetState>>);
#[derive(Debug, Clone, Copy, Default)]
struct NetState {
    pulling: u64,
    outputs: u32,
}
impl Net {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn open_drain(&self) -> Result<OpenDrain, &'static str> {
        let mut state = self.0.get();
        let bit = 1u64
            .checked_shl(state.outputs)
            .ok_or("too many open-drain outputs on one net")?;
        state.outputs += 1;
        self.0.set(state);
        Ok(OpenDrain {
            net: self.clone(),
            bit,
        })
    }
    pub fn level(&self) -> bool {
        self.0.get().pulling == 0
    }
}
/// One device output on a pulled-up net; it starts released.
#[derive(Debug, Clone)]
pub struct OpenDrain {
    net: Net,
    bit: u64,
}
impl OpenDrain {
    pub fn pull_low(&self, low: bool) {
        let mut state = self.net.0.get();
        if low {
            state.pulling |= self.bit;
        } else {
            state.pulling &= !self.bit;
        }
        self.net.0.set(state);
    }
}

pub struct Gpio {
    pins: Vec<u32>,
    nets: Vec<Option<Net>>,
    /// Last sampled level of each pin in an edge mode.
    sampled: Vec<Option<bool>>,
    /// Pins in an interrupt mode, so sampling visits only those.
    armed: Vec<usize>,
    /// IRQ status, `words` 32-bit words per group.
    pending: Vec<u32>,
    words: usize,
    lines: Vec<AicInput>,
    asserted: Vec<bool>,
}
impl Gpio {
    /// One AIC input per interrupt group; `selects` are chip-select outputs
    /// and `nets` the pulled-up board nets wired to input pins.
    pub fn new(
        pins: u32,
        lines: Vec<AicInput>,
        selects: &[u32],
        nets: Vec<(u32, Net)>,
    ) -> Result<Self, &'static str> {
        if pins == 0
            || pins > 512
            || lines.is_empty()
            || lines.len() > 7
            || selects
                .iter()
                .chain(nets.iter().map(|(pin, _)| pin))
                .any(|&p| p >= pins)
            || selects.iter().any(|p| nets.iter().any(|(n, _)| n == p))
        {
            return Err("invalid GPIO pin/group geometry, CS or board net");
        }
        let words = (pins as usize).div_ceil(32);
        let mut bank = Self {
            pins: vec![INPUT_OFF; pins as usize],
            nets: vec![None; pins as usize],
            sampled: vec![None; pins as usize],
            armed: Vec::new(),
            pending: vec![0; words * lines.len()],
            words,
            asserted: vec![false; lines.len()],
            lines,
        };
        for &pin in selects {
            bank.pins[pin as usize] = OUTPUT | DATA;
        }
        for (pin, net) in nets {
            if bank.nets[pin as usize].replace(net).is_some() {
                return Err("two board nets on one GPIO pin");
            }
        }
        Ok(bank)
    }
    /// The level a receiver samples on an input pin, when one is determined:
    /// a board net, otherwise the pin's own pull. Without either it floats.
    fn input_level(&self, pin: usize, word: u32) -> Option<bool> {
        if let Some(net) = &self.nets[pin] {
            return Some(net.level());
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
    fn group(&self, word: u32) -> Option<usize> {
        let group = ((word >> GROUP_SHIFT) & 7) as usize;
        (group < self.lines.len()).then_some(group)
    }
    fn irq_word(&self, offset: u64) -> Option<usize> {
        let offset = offset.checked_sub(IRQ_BASE)?;
        let (group, word) = (
            (offset / IRQ_STRIDE) as usize,
            (offset % IRQ_STRIDE) as usize / 4,
        );
        (group < self.lines.len() && word < self.words).then_some(group * self.words + word)
    }
    /// Latches every armed pin's condition and drives each group's line.
    fn sample(&mut self, access: &mut Access<'_>) {
        for &pin in &self.armed {
            let word = self.pins[pin];
            let level = self.input_level(pin, word);
            let latch = match word & MODE {
                LEVEL_HIGH => level == Some(true),
                LEVEL_LOW => level == Some(false),
                mode => {
                    let previous = core::mem::replace(&mut self.sampled[pin], level);
                    match (previous, level) {
                        (Some(a), Some(b)) if a != b => match mode {
                            EDGE_RISING => b,
                            EDGE_FALLING => !b,
                            _ => true,
                        },
                        _ => false,
                    }
                }
            };
            if latch && let Some(group) = self.group(word) {
                self.pending[group * self.words + pin / 32] |= 1 << (pin % 32);
            }
        }
        for (group, line) in self.lines.iter().enumerate() {
            let asserted = self.pending[group * self.words..][..self.words]
                .iter()
                .any(|&word| word != 0);
            if asserted != self.asserted[group] {
                self.asserted[group] = asserted;
                access.interrupts.set_level(Wire::Aic(*line), asserted);
            }
        }
    }
}
impl MmioDevice for Gpio {
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
            return Err(err("GPIO registers require aligned 32-bit accesses"));
        }
        self.sample(access);
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            if word & MODE == OUTPUT || word & INPUT_ENABLE == 0 {
                return Ok(u64::from(word));
            }
            return match self.input_level(pin, word) {
                Some(level) => Ok(u64::from(word & !DATA | u32::from(level))),
                None => Err(err(
                    "unconnected GPIO input has no pull; DATA is undetermined",
                )),
            };
        }
        if let Some(index) = self.irq_word(offset) {
            return Ok(u64::from(self.pending[index]));
        }
        Err(err("unmodeled GPIO register"))
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
            if matches!(mode, LEVEL_HIGH | LEVEL_LOW) && level.is_none() {
                return Err(err(
                    "GPIO level interrupt on an input whose level is undetermined",
                ));
            }
            if mode != OUTPUT && value & INPUT_ENABLE != 0 {
                // Enabling the receiver changes configuration, but does not
                // observe an undetermined DATA. A later read refuses.
                match level {
                    None => {}
                    Some(false) => value &= !DATA,
                    Some(true) => value |= DATA,
                }
            }
            if matches!(mode, LEVEL_HIGH..=EDGE_ANY) && self.group(value).is_none() {
                return Err(err("GPIO interrupt group beyond the DT group count"));
            }
            if word & LOCK != 0 {
                if (word ^ value) & !(DATA | LOCK) != 0 {
                    return Err(err("GPIO configuration is locked"));
                }
                value |= LOCK;
            }
            self.pins[pin] = value;
            self.armed.retain(|&armed| armed != pin);
            if matches!(mode, LEVEL_HIGH..=EDGE_ANY) {
                self.armed.push(pin);
                // An edge is a transition after the mode was selected.
                self.sampled[pin] = level;
            }
            self.sample(access);
            return Ok(());
        }
        if let Some(index) = self.irq_word(offset) {
            self.pending[index] &= !(value as u32);
            self.sample(access);
            return Ok(());
        }
        Err(err("unmodeled GPIO register"))
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.sample(access);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    fn lines() -> Vec<AicInput> {
        (199..206).map(|irq| AicInput::new(0, irq)).collect()
    }
    #[test]
    fn enabling_an_undriven_receiver_does_not_invent_a_sample() {
        let mut bank = Gpio::new(213, lines(), &[], vec![]).unwrap();
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
    fn level_interrupts_follow_their_net_until_acknowledged_inactive() {
        let net = Net::new();
        let hpm = net.open_drain().unwrap();
        let mut bank = Gpio::new(213, lines(), &[], vec![(8, net.clone())]).unwrap();
        let mut latch = InterruptLatch::new();
        let level_low = LEVEL_LOW | INPUT_ENABLE | 1 << 16;
        let status = 0x800 + 0x40;
        let wire = Wire::Aic(AicInput::new(0, 200));
        {
            let mut a = Access::new(0, 0, &mut latch);
            bank.write(4 * 8, Width::Word, level_low.into(), &mut a)
                .unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(0));
            hpm.pull_low(true);
            bank.advance(&mut a).unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(1 << 8));
            assert_eq!(bank.read(4 * 8, Width::Word, &mut a), Ok(level_low.into()));
            // Acknowledging an active level relatches it at once.
            bank.write(status, Width::Word, 1 << 8, &mut a).unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(1 << 8));
        }
        assert!(latch.is_asserted(wire));
        {
            let mut a = Access::new(0, 0, &mut latch);
            hpm.pull_low(false);
            bank.write(status, Width::Word, 1 << 8, &mut a).unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(0));
        }
        assert!(!latch.is_asserted(wire));
        assert_eq!(
            latch.take_aic_inputs(),
            [
                (AicInput::new(0, 200), true),
                (AicInput::new(0, 200), false)
            ]
        );
        // A floating level input cannot be armed.
        let mut a = Access::new(0, 0, &mut latch);
        assert!(
            bank.write(4 * 9, Width::Word, level_low.into(), &mut a)
                .is_err()
        );
        assert!(
            bank.write(4 * 8, Width::Word, (level_low | 7 << 16).into(), &mut a)
                .is_err()
        );
    }
    #[test]
    fn edges_latch_on_sampled_transitions_and_masking_keeps_the_latch() {
        let net = Net::new();
        let line = net.open_drain().unwrap();
        let mut bank = Gpio::new(213, lines(), &[], vec![(84, net)]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let status = 0x800 + 2 * 0x40 + 8;
        for (mode, falls, rises) in [
            (EDGE_RISING, 0, 1 << 20),
            (EDGE_FALLING, 1 << 20, 0),
            (EDGE_ANY, 1 << 20, 1 << 20),
        ] {
            let word = mode | INPUT_ENABLE | 2 << 16;
            bank.write(4 * 84, Width::Word, word.into(), &mut a)
                .unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(0));
            line.pull_low(true);
            bank.advance(&mut a).unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(falls));
            bank.write(status, Width::Word, u64::MAX >> 32, &mut a)
                .unwrap();
            line.pull_low(false);
            bank.advance(&mut a).unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(rises));
            if rises != 0 {
                bank.write(4 * 84, Width::Word, u64::from(INPUT_OFF), &mut a)
                    .unwrap();
                assert_eq!(bank.read(status, Width::Word, &mut a), Ok(rises));
            }
            bank.write(status, Width::Word, u64::MAX >> 32, &mut a)
                .unwrap();
        }
    }
    #[test]
    fn i2c_lines_sample_their_board_pull_up() {
        let mut bank = Gpio::new(213, lines(), &[49], vec![(86, Net::new())]).unwrap();
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
        assert!(Gpio::new(213, lines(), &[49], vec![(49, Net::new())]).is_err());
        assert!(Gpio::new(213, vec![], &[], vec![]).is_err());
    }
    #[test]
    fn peripheral_functions_record_the_mux_without_a_gpio_level() {
        let mut bank = Gpio::new(213, lines(), &[49], vec![]).unwrap();
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
    fn cs_output_and_lock_and_unknown_registers_are_explicit() {
        let mut bank = Gpio::new(213, lines(), &[49], vec![]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        assert_eq!(bank.output(49), Some(true));
        bank.write(49 * 4, Width::Word, 2, &mut a).unwrap();
        assert_eq!(bank.output(49), Some(false));
        bank.write(49 * 4, Width::Word, u64::from(2 | LOCK), &mut a)
            .unwrap();
        assert!(bank.write(49 * 4, Width::Word, 0x202, &mut a).is_err());
        assert!(bank.write(0, Width::Word, 0, &mut a).is_err());
        assert!(bank.read(0xc48, Width::Word, &mut a).is_err());
        assert_eq!(bank.read(0x800, Width::Word, &mut a), Ok(0));
    }
}
