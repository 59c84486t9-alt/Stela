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
use super::{
    bus::{Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::Cell;
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
/// The interrupt groups the 3-bit group field selects.
pub const GROUPS: usize = 8;

/// Source-qualified register behavior; board nets and lifecycle remain
/// separately owned. The S5L driver does not implement T8101 lockGPIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    T8101,
    S5l8960x,
}

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
    pub fn new(
        pins: u32,
        lines: Vec<AicInput>,
        selects: &[u32],
        nets: Vec<(u32, Net)>,
    ) -> Result<Self, &'static str> {
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
    ) -> Result<Self, &'static str> {
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
            return Err("invalid GPIO pin/group geometry, CS or board net");
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
                return Err("two board nets on one GPIO pin");
            }
        }
        Ok(bank)
    }
    /// A bank of `groups` interrupt groups, of which the first have the
    /// AIC lines [`Gpio::new`] took.
    pub fn with_groups(mut self, groups: usize) -> Result<Self, &'static str> {
        if groups < self.lines.len() || groups > GROUPS {
            return Err("GPIO group count below its lines or beyond the group field");
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
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset {
            return Err("GPIO physical reset, pad state and interrupt restoration are unqualified");
        }
        if !proposed.powered {
            return Err("GPIO supply loss and physical pad/interrupt retention are unqualified");
        }
        if (!proposed.clocked || proposed.quiesced)
            && (!self.armed.is_empty() || self.pending.iter().any(|word| *word != 0))
        {
            return Err(
                "GPIO pause with armed or pending interrupts has unqualified edge/wake capture",
            );
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
        let err = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(err(
                "GPIO MMIO while its physical clock is stopped is unqualified",
            ));
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("GPIO registers require aligned 32-bit accesses"));
        }
        self.sample(access);
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            if word & MODE == INPUT && word & INPUT_ENABLE == 0 {
                return Err(err(
                    "plain GPIO input DATA with receiver disabled is unqualified",
                ));
            }
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
        if !self.lifecycle.clocked {
            return Err(err(
                "GPIO MMIO while its physical clock is stopped is unqualified",
            ));
        }
        if self.lifecycle.quiesced {
            return Err(err(
                "GPIO register changes while native service is quiesced are unqualified",
            ));
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("GPIO registers require aligned 32-bit accesses"));
        }
        let pin = offset as usize / 4;
        if let Some(&word) = self.pins.get(pin) {
            let mut value = value as u32;
            let mode = value & MODE;
            if value & !FIELDS != 0 {
                return Err(err("unknown GPIO fields are not modeled"));
            }
            // Original mac13j S5L getGPIOData calls direction0, which
            // changes output/mode7 into plain input with receiver9 set
            // (VA 0xfffffe00094fc420..440). Safe reconfiguration may first
            // write the same plain input with its old receiver bit clear.
            // That intermediate form grants no sampled DATA level; reads
            // refuse until the source enables the receiver.
            if self.profile == Profile::S5l8960x && value & LOCK != 0 {
                return Err(err("S5L GPIO lock bit semantics are unqualified"));
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
            if matches!(mode, LEVEL_HIGH..=EDGE_ANY) {
                match self.group(value) {
                    None => return Err(err("GPIO interrupt group beyond the DT group count")),
                    Some(group) if group >= self.lines.len() => {
                        return Err(err("GPIO interrupt group without an AIC line"));
                    }
                    Some(_) => {}
                }
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
    fn plain_input_samples_real_net_without_arming_or_clearing_interrupts() {
        for profile in [Profile::T8101, Profile::S5l8960x] {
            let net = Net::new();
            let driver = net.open_drain().unwrap();
            let mut bank = Gpio::with_profile(profile, 32, lines(), &[], vec![(3, net)]).unwrap();
            let mut latch = InterruptLatch::new();
            {
                let mut access = Access::new(0, 0, &mut latch);
                // Actual source safe-reconfiguration order: old receiver0,
                // intermediate plain-input0, then receiver9. Do not sample an
                // invented DATA value from the intermediate hardware state.
                bank.write(12, Width::Word, 0, &mut access).unwrap();
                assert!(bank.read(12, Width::Word, &mut access).is_err());
                bank.write(12, Width::Word, INPUT_ENABLE.into(), &mut access)
                    .unwrap();
                assert_eq!(
                    bank.read(12, Width::Word, &mut access),
                    Ok(u64::from(INPUT_ENABLE | DATA))
                );
                driver.pull_low(true);
                bank.advance(&mut access).unwrap();
                assert_eq!(
                    bank.read(12, Width::Word, &mut access),
                    Ok(u64::from(INPUT_ENABLE))
                );
                assert!(bank.armed.is_empty());
                assert!(bank.pending.iter().all(|word| *word == 0));
            }
            assert!(latch.take_aic_inputs().is_empty());
            let mut access = Access::new(0, 0, &mut latch);
            // Changing to plain input removes edge capture but does not
            // surrender an existing pending interrupt owned by software.
            bank.write(
                12,
                Width::Word,
                (EDGE_RISING | INPUT_ENABLE).into(),
                &mut access,
            )
            .unwrap();
            driver.pull_low(false);
            bank.advance(&mut access).unwrap();
            assert_eq!(bank.pending[0], 1 << 3);
            bank.write(12, Width::Word, INPUT_ENABLE.into(), &mut access)
                .unwrap();
            assert_eq!(bank.pending[0], 1 << 3);
            bank.write(IRQ_BASE, Width::Word, 1 << 3, &mut access)
                .unwrap();
            assert_eq!(bank.pending[0], 0);
        }
    }

    #[test]
    fn plain_input_uses_pulls_and_refuses_floating_data_for_both_profiles() {
        for profile in [Profile::T8101, Profile::S5l8960x] {
            let mut bank = Gpio::with_profile(profile, 32, lines(), &[], vec![]).unwrap();
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            bank.write(4, Width::Word, INPUT_ENABLE.into(), &mut access)
                .unwrap();
            assert!(bank.read(4, Width::Word, &mut access).is_err());
            for (pull, level) in [(1 << 7, false), (2 << 7, true)] {
                let value = INPUT_ENABLE | pull;
                bank.write(4, Width::Word, value.into(), &mut access)
                    .unwrap();
                assert_eq!(
                    bank.read(4, Width::Word, &mut access),
                    Ok(u64::from(value | u32::from(level)))
                );
            }
            assert!(bank.armed.is_empty());
        }
    }

    #[test]
    fn s5l_lock_refuses_before_effects_while_t8101_lock_stays_monotonic() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut bank = Gpio::with_profile(Profile::S5l8960x, 32, lines(), &[3], vec![]).unwrap();
        let before = bank.pins.clone();
        for value in [
            OUTPUT | LOCK,
            INPUT_ENABLE | LOCK,
            EDGE_RISING | INPUT_ENABLE | LOCK,
        ] {
            assert!(
                bank.write(12, Width::Word, value.into(), &mut access)
                    .is_err()
            );
            assert_eq!(bank.pins, before);
            assert!(bank.armed.is_empty());
            assert!(bank.pending.iter().all(|word| *word == 0));
        }
        for value in [0, u32::MAX] {
            assert!(
                bank.write(0xc48, Width::Word, value.into(), &mut access)
                    .is_err()
            );
            assert_eq!(bank.pins, before);
        }
        assert!(bank.read(0xc48, Width::Word, &mut access).is_err());
        let mut old = Gpio::new(32, lines(), &[3], vec![]).unwrap();
        old.write(12, Width::Word, (OUTPUT | LOCK).into(), &mut access)
            .unwrap();
        old.write(12, Width::Word, (OUTPUT | DATA).into(), &mut access)
            .unwrap();
        assert_eq!(old.pins[3], OUTPUT | DATA | LOCK);
        assert!(
            old.write(12, Width::Word, INPUT_ENABLE.into(), &mut access)
                .is_err()
        );
    }

    #[test]
    fn retained_clock_and_quiesce_preserve_pad_ownership_independently() {
        let net = Net::new();
        let input = net.open_drain().unwrap();
        let mut bank = Gpio::new(64, lines(), &[49], vec![(8, net)]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        bank.write(49 * 4, Width::Word, u64::from(OUTPUT | LOCK), &mut access)
            .unwrap();
        bank.write(
            8 * 4,
            Width::Word,
            u64::from(INPUT_OFF | INPUT_ENABLE),
            &mut access,
        )
        .unwrap();
        let active = bank.lifecycle;
        let quiesced = LifecycleState {
            quiesced: true,
            ..active
        };
        bank.check_lifecycle(quiesced).unwrap();
        bank.set_lifecycle(quiesced, &mut access);
        assert_eq!(bank.output(49), Some(false));
        assert!(
            bank.write(49 * 4, Width::Word, u64::from(OUTPUT | DATA), &mut access)
                .is_err()
        );
        assert_eq!(bank.output(49), Some(false));
        let stopped = LifecycleState {
            clocked: false,
            ..quiesced
        };
        bank.check_lifecycle(stopped).unwrap();
        bank.set_lifecycle(stopped, &mut access);
        assert!(bank.read(49 * 4, Width::Word, &mut access).is_err());
        input.pull_low(true);
        bank.advance(&mut access).unwrap();
        assert_eq!(bank.output(49), Some(false));
        bank.check_lifecycle(quiesced).unwrap();
        bank.set_lifecycle(quiesced, &mut access);
        assert!(
            bank.lifecycle.quiesced,
            "clock restart does not resume service"
        );
        assert_eq!(
            bank.read(49 * 4, Width::Word, &mut access),
            Ok(u64::from(OUTPUT | LOCK))
        );
        bank.check_lifecycle(active).unwrap();
        bank.set_lifecycle(active, &mut access);
        assert_eq!(
            bank.read(8 * 4, Width::Word, &mut access),
            Ok(u64::from(INPUT_OFF | INPUT_ENABLE))
        );
        assert!(bank.pending.iter().all(|word| *word == 0));
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn armed_edge_or_owned_pending_interrupt_prevents_pause_without_losing_events() {
        let net = Net::new();
        let input = net.open_drain().unwrap();
        let mut bank = Gpio::new(64, lines(), &[], vec![(8, net)]).unwrap();
        let mut latch = InterruptLatch::new();
        let active = bank.lifecycle;
        let stopped = LifecycleState {
            clocked: false,
            ..active
        };
        let mut access = Access::new(0, 0, &mut latch);
        bank.write(
            8 * 4,
            Width::Word,
            u64::from(EDGE_FALLING | INPUT_ENABLE),
            &mut access,
        )
        .unwrap();
        assert!(bank.check_lifecycle(stopped).is_err());
        assert_eq!(bank.lifecycle, active);
        input.pull_low(true);
        bank.advance(&mut access).unwrap();
        input.pull_low(false);
        bank.advance(&mut access).unwrap();
        assert_eq!(
            bank.pending[0],
            1 << 8,
            "refused pause leaves edge capture active"
        );
        // Removing the trigger does not surrender an already-owned latch.
        bank.write(8 * 4, Width::Word, u64::from(INPUT_OFF), &mut access)
            .unwrap();
        assert!(bank.armed.is_empty());
        assert!(bank.check_lifecycle(stopped).is_err());
        assert!(
            bank.check_lifecycle(LifecycleState {
                quiesced: true,
                ..active
            })
            .is_err()
        );
        bank.write(IRQ_BASE, Width::Word, 1 << 8, &mut access)
            .unwrap();
        bank.check_lifecycle(stopped).unwrap();
        bank.set_lifecycle(stopped, &mut access);
        for proposed in [
            LifecycleState {
                reset: true,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: false,
                ..active
            },
        ] {
            assert!(bank.check_lifecycle(proposed).is_err());
            assert_eq!(bank.lifecycle, stopped);
            assert_eq!(bank.pending[0], 0);
        }
        assert_eq!(
            latch.take_aic_inputs(),
            [(lines()[0], true), (lines()[0], false)]
        );
    }

    #[test]
    fn mounted_gpio_refusal_keeps_real_aic_delivery_owned() {
        use crate::platform::apple::{
            aic::{AIC2_IRQ_CFG, AIC2_TIMESTAMPS, Aic2, Aic2Config},
            bus::Bus,
        };
        let net = Net::new();
        let input = net.open_drain().unwrap();
        let gpio = Gpio::new(32, vec![AicInput::new(0, 3)], &[], vec![(8, net)]).unwrap();
        let aic = Aic2::new(Aic2Config {
            version: 2,
            nr_irq: 32,
            max_irq: 32,
            irq_config: AIC2_IRQ_CFG,
            event_offset: 0x4000,
            timestamps: 0,
            timestamp_base: AIC2_TIMESTAMPS,
            cpus: 1,
            default_cpus: 1,
            target_groups: [None; 4],
        })
        .unwrap();
        let mut bus = Bus::new();
        let gpio_id = bus.add(Box::new(gpio));
        let aic_id = bus.add(Box::new(aic));
        bus.map(gpio_id, 0x10000, 0x1000, 0).unwrap();
        bus.map(aic_id, 0x20000, 0x4004, 0).unwrap();
        let mut latch = InterruptLatch::new();
        bus.write(
            0x10020,
            Width::Word,
            u64::from(LEVEL_LOW | INPUT_ENABLE),
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        // An aggregate preflight must check every real bank before committing
        // either one. AIC is idle, but the GPIO wake/edge path is unqualified.
        let paused = LifecycleState {
            powered: true,
            clocked: false,
            quiesced: false,
            reset: false,
            retention: true,
        };
        bus.lifecycle(aic_id)
            .unwrap()
            .check_lifecycle(paused)
            .unwrap();
        assert!(
            bus.lifecycle(gpio_id)
                .unwrap()
                .check_lifecycle(paused)
                .is_err()
        );
        input.pull_low(true);
        bus.advance(&mut Access::new(0, 1, &mut latch)).unwrap();
        for (line, level) in latch.take_aic_inputs() {
            bus.device_mut::<Aic2>(aic_id)
                .unwrap()
                .set_input(line, level, &mut Access::new(0, 1, &mut latch))
                .unwrap();
        }
        // Unmask source 3 and enable the actual mapped AIC. The earlier
        // refused lifecycle preflight changed neither bank or input level.
        bus.write(
            0x20000 + AIC2_IRQ_CFG + 4 * 32 + 12,
            Width::Word,
            1 << 3,
            &mut Access::new(0, 2, &mut latch),
        )
        .unwrap();
        bus.write(0x20014, Width::Word, 1, &mut Access::new(0, 2, &mut latch))
            .unwrap();
        assert!(latch.pins(0).irq);
        assert_eq!(
            bus.read(0x24000, Width::Word, &mut Access::new(0, 3, &mut latch)),
            Ok(1 << 16 | 3)
        );
        assert!(!latch.pins(0).irq);
        assert_eq!(
            bus.read(0x10800, Width::Word, &mut Access::new(0, 3, &mut latch)),
            Ok(1 << 8)
        );
    }
    #[test]
    #[ignore = "requires pinned original J473 26A434 kernelcache; no Apple image is committed"]
    fn original_drivers_keep_wake_claim_and_timestamp_disarm_explicit() {
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_TEST_PMGR_KERNELCACHE")
            .expect("pinned original J473 kernelcache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        // GPIO setPowerState claims separate wake ownership; this is not
        // evidence for resetting pads or dropping pending edges on suspend.
        // AIC stopInterruptTimestamping separately disarms its slot.
        for (offset, opcode) in [
            (0x24d9480, 0xf900b401),
            (0x24d9484, 0xf100043f),
            (0x24d9498, 0x97fffded),
            (0x24dd7a0, 0x528041c9),
            (0x24dd7a8, 0xb9000308),
            (0x24dd7f8, 0xb9000128),
            (0x24dd91c, 0x321f0922),
            (0x24dd920, 0xb9000102),
            (0x24dd9b8, 0xb9000128),
            (0x28232e0, 0x52830009),
            (0x28232e4, 0x0b081121),
            (0x2823308, 0x52800002),
            (0x2823310, 0xd73f0910),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original IRQ lifecycle source at {offset:#x}"
            );
        }
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
    fn an_eighth_group_without_a_line_has_status_but_takes_no_interrupt() {
        // J414sAP `gpio0`: `#gpio-int-groups` 8, seven `interrupts`.
        let mut bank = Gpio::new(255, lines(), &[], vec![(8, Net::new())])
            .unwrap()
            .with_groups(GROUPS)
            .unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let last = IRQ_BASE + (GROUPS as u64 - 1) * IRQ_STRIDE;
        bank.write(last, Width::Word, u64::from(u32::MAX), &mut a)
            .unwrap();
        assert_eq!(bank.read(last, Width::Word, &mut a), Ok(0));
        let unwired = EDGE_RISING | (GROUPS as u32 - 1) << GROUP_SHIFT;
        assert!(
            bank.write(4 * 8, Width::Word, u64::from(unwired), &mut a)
                .is_err()
        );
        let wired = EDGE_RISING | 6 << GROUP_SHIFT;
        bank.write(4 * 8, Width::Word, u64::from(wired), &mut a)
            .unwrap();
        assert!(
            Gpio::new(255, lines(), &[], vec![])
                .unwrap()
                .with_groups(GROUPS + 1)
                .is_err()
        );
        assert!(
            Gpio::new(255, lines(), &[], vec![])
                .unwrap()
                .with_groups(1)
                .is_err()
        );
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
        bank.write(0, Width::Word, 0, &mut a).unwrap();
        assert!(bank.read(0, Width::Word, &mut a).is_err());
        assert!(bank.read(0xc48, Width::Word, &mut a).is_err());
        assert_eq!(bank.read(0x800, Width::Word, &mut a), Ok(0));
    }
}
