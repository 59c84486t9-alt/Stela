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
//! its bank. A bank has `#gpio-int-groups` status banks, at most the eight
//! the group field selects, and an AIC line for each of its first
//! `interrupts` groups: J414sAP's `gpio0` states 8 groups and wires 7.
//! A pin interrupt routed to a group without a line refuses, since what
//! hardware signals then is not documented. A level mode latches while its input is active, so it relatches
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
//!
//! Powered clock/quiesce pauses preserve pad configuration and driven chip
//! selects. They require no armed or pending GPIO interrupt: the original
//! driver's separate enableWakeOnly/claimWakeEvents contract is not modeled,
//! so a stopped clock cannot silently discard edge/wake ownership. Physical
//! supply loss, pad retention and reset remain explicit refusals.
use crate::Result;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::Cell;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
    stela_contracts::interrupt::AicInput, stela_contracts::interrupt::Wire,
};
const NAME: &str = "Apple GPIO";
const DATA: u32 = 1;
const MODE: u32 = 7 << 1;
const INPUT: u32 = 0;
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
use stela_soc_data::gpio::{GROUPS, Profile};

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
    pub fn open_drain(&self) -> Result<OpenDrain> {
        let mut state = self.0.get();
        let bit = 1u64
            .checked_shl(state.outputs)
            .ok_or(refuse!("too many open-drain outputs on one net"))?;
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
    pub fn is_low(&self) -> bool {
        self.net.0.get().pulling & self.bit != 0
    }
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
    profile: Profile,
    lifecycle: LifecycleState,
    pins: Vec<u32>,
    nets: Vec<Option<Net>>,
    /// Last sampled level of each pin in an edge mode.
    sampled: Vec<Option<bool>>,
    /// Pins in an interrupt mode, so sampling visits only those.
    armed: Vec<usize>,
    /// IRQ status, `words` 32-bit words per group.
    pending: Vec<u32>,
    words: usize,
    groups: usize,
    /// The AIC lines of the first groups.
    lines: Vec<AicInput>,
    asserted: Vec<bool>,
}
impl Gpio {
    /// One AIC input per interrupt group; `selects` are chip-select outputs
    /// and `nets` the pulled-up board nets wired to input pins.
    #[cfg(test)]
    pub fn new(
        pins: u32,
        lines: Vec<AicInput>,
        selects: &[u32],
        nets: Vec<(u32, Net)>,
    ) -> Result<Self> {
        Self::with_profile(Profile::T8101, pins, lines, selects, nets)
    }

    /// Select register semantics at construction; the immutable profile
    /// cannot be switched after any pin, net or interrupt has become live.
    pub fn with_profile(
        profile: Profile,
        pins: u32,
        lines: Vec<AicInput>,
        selects: &[u32],
        nets: Vec<(u32, Net)>,
    ) -> Result<Self> {
        if pins == 0
            || pins > 512
            || lines.is_empty()
            || lines.len() > GROUPS
            || selects
                .iter()
                .chain(nets.iter().map(|(pin, _)| pin))
                .any(|&p| p >= pins)
            || selects.iter().any(|p| nets.iter().any(|(n, _)| n == p))
        {
            return Err(refuse!("invalid GPIO pin/group geometry, CS or board net"));
        }
        let words = (pins as usize).div_ceil(32);
        let mut bank = Self {
            profile,
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            },
            pins: vec![INPUT_OFF; pins as usize],
            nets: vec![None; pins as usize],
            sampled: vec![None; pins as usize],
            armed: Vec::new(),
            pending: vec![0; words * lines.len()],
            words,
            groups: lines.len(),
            asserted: vec![false; lines.len()],
            lines,
        };
        for &pin in selects {
            bank.pins[pin as usize] = OUTPUT | DATA;
        }
        for (pin, net) in nets {
            if bank.nets[pin as usize].replace(net).is_some() {
                return Err(refuse!("two board nets on one GPIO pin"));
            }
        }
        Ok(bank)
    }
    /// A bank of `groups` interrupt groups, of which the first have the
    /// AIC lines [`Gpio::new`] took.
    pub fn with_groups(mut self, groups: usize) -> Result<Self> {
        if groups < self.lines.len() || groups > GROUPS {
            return Err(refuse!(
                "GPIO group count below its lines or beyond the group field"
            ));
        }
        self.groups = groups;
        self.pending = vec![0; self.words * groups];
        Ok(self)
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
    #[cfg(test)]
    pub fn output(&self, pin: u32) -> Option<bool> {
        Self::driven_level(*self.pins.get(pin as usize)?)
    }
    pub(crate) fn driven_level(word: u32) -> Option<bool> {
        (word & MODE == OUTPUT && word & PERIPH == 0).then_some(word & DATA != 0)
    }
    fn group(&self, word: u32) -> Option<usize> {
        let group = ((word >> GROUP_SHIFT) & 7) as usize;
        (group < self.groups).then_some(group)
    }
    fn irq_word(&self, offset: u64) -> Option<usize> {
        let offset = offset.checked_sub(IRQ_BASE)?;
        let (group, word) = (
            (offset / IRQ_STRIDE) as usize,
            (offset % IRQ_STRIDE) as usize / 4,
        );
        (group < self.groups && word < self.words).then_some(group * self.words + word)
    }
    /// Latches every armed pin's condition and drives each group's line.
    fn sample(&mut self, access: &mut Access<'_>) {
        if !self.lifecycle.clocked || self.lifecycle.quiesced {
            return;
        }
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
impl Lifecycle for Gpio {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if proposed.reset {
            return Err(refuse!(
                "GPIO physical reset, pad state and interrupt restoration are unqualified"
            ));
        }
        if !proposed.powered {
            return Err(refuse!(
                "GPIO supply loss and physical pad/interrupt retention are unqualified"
            ));
        }
        if (!proposed.clocked || proposed.quiesced)
            && (!self.armed.is_empty() || self.pending.iter().any(|word| *word != 0))
        {
            return Err(refuse!(
                "GPIO pause with armed or pending interrupts has unqualified edge/wake capture"
            ));
        }
        Ok(())
    }

    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        // Clock/quiesce never rewrite pad configuration or withdraw a driven
        // chip select. Armed/pending IRQ ownership was checked before commit.
        self.lifecycle = proposed;
        self.sample(access);
    }
}
impl MmioDevice for Gpio {
    fn name(&self) -> &'static str {
        NAME
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let err = |reason: Refusal| refuse(NAME, offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(err(refuse!(
                "GPIO MMIO while its physical clock is stopped is unqualified"
            )));
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err(refuse!(
                "GPIO registers require aligned 32-bit accesses"
            )));
        }
        self.sample(access);
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            if word & MODE == INPUT && word & INPUT_ENABLE == 0 {
                return Err(err(refuse!(
                    "plain GPIO input DATA with receiver disabled is unqualified"
                )));
            }
            if word & MODE == OUTPUT || word & INPUT_ENABLE == 0 {
                return Ok(u64::from(word));
            }
            return match self.input_level(pin, word) {
                Some(level) => Ok(u64::from(word & !DATA | u32::from(level))),
                None => Err(err(refuse!(
                    "unconnected GPIO input has no pull; DATA is undetermined"
                ))),
            };
        }
        if let Some(index) = self.irq_word(offset) {
            return Ok(u64::from(self.pending[index]));
        }
        Err(err(refuse!("unmodeled GPIO register")))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let err = |reason: Refusal| refuse(NAME, offset, width, Direction::Write, reason);
        if !self.lifecycle.clocked {
            return Err(err(refuse!(
                "GPIO MMIO while its physical clock is stopped is unqualified"
            )));
        }
        if self.lifecycle.quiesced {
            return Err(err(refuse!(
                "GPIO register changes while native service is quiesced are unqualified"
            )));
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err(refuse!(
                "GPIO registers require aligned 32-bit accesses"
            )));
        }
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            let mut value = value as u32;
            let mode = value & MODE;
            if value & !FIELDS != 0 {
                return Err(err(refuse!("unknown GPIO fields are not modeled")));
            }
            // Original mac13j S5L getGPIOData calls direction0, which
            // changes output/mode7 into plain input with receiver9 set
            // (VA 0xfffffe00094fc420..440). Safe reconfiguration may first
            // write the same plain input with its old receiver bit clear.
            // That intermediate form grants no sampled DATA level; reads
            // refuse until the source enables the receiver.
            if self.profile == Profile::S5l8960x && value & LOCK != 0 {
                return Err(err(refuse!("S5L GPIO lock bit semantics are unqualified")));
            }
            if value & PERIPH != 0 && mode != INPUT_OFF {
                return Err(err(refuse!(
                    "GPIO peripheral mux with output or interrupt mode is not modeled"
                )));
            }
            let level = self.input_level(pin, value);
            if matches!(mode, LEVEL_HIGH | LEVEL_LOW) && level.is_none() {
                return Err(err(refuse!(
                    "GPIO level interrupt on an input whose level is undetermined"
                )));
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
            if matches!(mode, LEVEL_HIGH..=EDGE_ANY) {
                match self.group(value) {
                    None => {
                        return Err(err(refuse!(
                            "GPIO interrupt group beyond the DT group count"
                        )));
                    }
                    Some(group) if group >= self.lines.len() => {
                        return Err(err(refuse!("GPIO interrupt group without an AIC line")));
                    }
                    Some(_) => {}
                }
            }
            if word & LOCK != 0 {
                if (word ^ value) & !(DATA | LOCK) != 0 {
                    return Err(err(refuse!("GPIO configuration is locked")));
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
        Err(err(refuse!("unmodeled GPIO register")))
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.sample(access);
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
