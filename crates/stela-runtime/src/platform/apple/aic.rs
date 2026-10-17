//! Apple Interrupt Controller v2 (`apple,t8112-aic`, `apple,aic2`; ADT
//! `aic,2`), the T8112 controller for peripheral IRQs, and v3
//! (`apple,t8122-aic3`; ADT `aic,3`), which is v2 with its per-die arrays at
//! 0x10000 (Linux `AIC3_IRQ_CFG`; ADT `extint-baseaddress`). Fast IPIs and
//! timer FIQs bypass it (see `ipi` and `timer`).
//!
//! Documented by Linux `drivers/irqchip/irq-apple-aic.c` and m1n1
//! `src/aic.c` / `src/aic_regs.h`:
//! - `INFO1` (`CAP0`, 0x4) holds NR_IRQ [15:0] and LAST_DIE [27:24]; `INFO3`
//!   (`MAXNUMIRQ`, 0xc) holds MAX_IRQ [15:0] and MAX_DIE [27:24]; `CONFIG`
//!   (0x14) bit 0 enables the controller.
//! - From 0x2000 (v3: 0x10000) each die has `IRQ_CFG[MAX_IRQ]` (TARGET [3:0], DELAY_IDX
//!   [7:5]), then `SW_SET`, `SW_CLR`, `MASK_SET`, `MASK_CLR` and `HW_STATE`,
//!   each `MAX_IRQ / 32` words.
//! - The event register is a separate block (`aic-iack-offset`; DT `reg[1]`).
//!   Reading it returns DIE [31:24], TYPE [23:16] (1 = hardware IRQ) and
//!   NUM [15:0], or 0, and masks the returned IRQ ("reading the interrupt
//!   reason automatically acknowledges and masks the IRQ"). Software pending
//!   bits are ORed with the hardware line; lower IRQ numbers win.
//! - AICv2 has no IPI registers; IPIs are fast IPIs.
//!
//! Inferred, not documented: the reset state masks every IRQ with zero
//! configuration; `SET`/`CLR` reads return the current bits; IRQs with TARGET 0
//! go to the default CPU set, and each TARGET bit selects a CPU group that the
//! board configuration must name (the hardware group assignment is not
//! public), so an unnamed group is refused; the first CPU to read the event
//! register claims the IRQ; delay groups only affect coalescing latency, so
//! immediate delivery is a permitted timing. Only one die is modeled.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::interrupt::{AicInput, CpuIndex, Wire};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const NAME: &str = "aic2";

const VERSION: u64 = 0x0000;
const INFO1: u64 = 0x0004;
const INFO2: u64 = 0x0008;
const INFO3: u64 = 0x000c;
const RESET: u64 = 0x0010;
const CONFIG: u64 = 0x0014;
/// Where AICv2's per-die arrays start (Linux `AIC2_IRQ_CFG`).
pub const AIC2_IRQ_CFG: u64 = 0x2000;
/// Where AICv3's per-die arrays start (Linux `AIC3_IRQ_CFG`).
pub const AIC3_IRQ_CFG: u64 = 0x10000;

const INFO_DIE_SHIFT: u32 = 24;
const CONFIG_ENABLE: u32 = 1;
const IRQ_CFG_TARGET: u32 = 0xf;
const IRQ_CFG_DELAY_IDX: u32 = 0b111 << 5;
const EVENT_TYPE_IRQ: u32 = 1 << 16;
const TARGET_GROUPS: usize = 4;

/// Which AIC a board has: an AICv1 (`aic1`), whose event register is in its
/// core block, or an AICv2 or AICv3 with its per-die arrays at `irq_config`
/// ([`AIC2_IRQ_CFG`] or [`AIC3_IRQ_CFG`]) and its event register `event`
/// bytes from the core block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AicLayout {
    V1,
    V2 { irq_config: u64, event: u64 },
}

/// Hardware facts of one AICv2 instance. NR_IRQ and MAX_IRQ come from the
/// controller, not the ADT; the board profile must record them from the
/// real machine (m1n1 prints them as "AIC: AIC2 with 1/1 dies, N/M IRQs").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aic2Config {
    pub nr_irq: u16,
    /// A multiple of 32.
    pub max_irq: u16,
    /// Offset of the first die's `IRQ_CFG` array: [`AIC2_IRQ_CFG`] or
    /// [`AIC3_IRQ_CFG`].
    pub irq_config: u64,
    /// Offset of the event register from the core block: ADT
    /// `aic-iack-offset`, or DT `reg[1] - reg[0]` (0x8000 on T8112).
    pub event_offset: u64,
    pub cpus: usize,
    /// CPUs that receive IRQs whose TARGET is 0, as a bit mask.
    pub default_cpus: u64,
    /// CPUs selected by each TARGET bit; `None` refuses that bit.
    pub target_groups: [Option<u64>; TARGET_GROUPS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aic2Error {
    InvalidConfig(&'static str),
    UnknownInput(AicInput),
}

pub struct Aic2 {
    config: Aic2Config,
    enabled: bool,
    irq_cfg: Vec<u32>,
    software: Vec<u32>,
    hardware: Vec<u32>,
    mask: Vec<u32>,
    irq_level: Vec<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Array {
    SoftwareSet,
    SoftwareClear,
    MaskSet,
    MaskClear,
    HardwareState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Register {
    Info1,
    Info3,
    Config,
    IrqConfig(usize),
    Bits(Array, usize),
    Event,
}

impl Aic2 {
    pub fn new(config: Aic2Config) -> Result<Self, Aic2Error> {
        let invalid = |reason| Err(Aic2Error::InvalidConfig(reason));
        if config.max_irq == 0 || !config.max_irq.is_multiple_of(32) {
            return invalid("MAX_IRQ must be a nonzero multiple of 32");
        }
        if config.nr_irq == 0 || config.nr_irq > config.max_irq {
            return invalid("NR_IRQ must be in 1..=MAX_IRQ");
        }
        if config.cpus == 0 || config.cpus > 64 {
            return invalid("the CPU count must be in 1..=64");
        }
        let all_cpus = u64::MAX >> (64 - config.cpus);
        let groups = config.target_groups.iter().flatten();
        if core::iter::once(&config.default_cpus)
            .chain(groups)
            .any(|cpus| cpus & !all_cpus != 0)
        {
            return invalid("a CPU set names a CPU beyond the CPU count");
        }
        if config.irq_config <= CONFIG || !config.irq_config.is_multiple_of(4) {
            return invalid("the IRQ_CFG array must be a word after CONFIG");
        }
        let words = usize::from(config.max_irq / 32);
        let end = config.irq_config + 4 * u64::from(config.max_irq) + 4 * 5 * words as u64;
        if config.event_offset < end || !config.event_offset.is_multiple_of(4) {
            return invalid("the event register must follow the per-die arrays");
        }
        Ok(Self {
            enabled: false,
            irq_cfg: vec![0; usize::from(config.nr_irq)],
            software: vec![0; words],
            hardware: vec![0; words],
            mask: vec![u32::MAX; words],
            irq_level: vec![false; config.cpus],
            config,
        })
    }
    /// Size of the device address space to map: core block plus event word.
    pub fn span(&self) -> u64 {
        self.config.event_offset + 4
    }
    /// Sets the level of one hardware input, as wired by the engine from the
    /// device models' `Wire::Aic` outputs.
    pub fn set_input(
        &mut self,
        input: AicInput,
        asserted: bool,
        access: &mut Access<'_>,
    ) -> Result<(), Aic2Error> {
        if input.die != 0 || input.irq >= self.config.nr_irq {
            return Err(Aic2Error::UnknownInput(input));
        }
        let (word, bit) = position(usize::from(input.irq));
        if asserted {
            self.hardware[word] |= bit;
        } else {
            self.hardware[word] &= !bit;
        }
        self.update(access);
        Ok(())
    }
    /// Applies the ADT `aic-ext-intr-cfg` property as iBoot does: triples of
    /// IRQ [7:0], die [7:4] with IRQ [11:8], and TARGET (m1n1 `aic23_init`).
    pub fn apply_ext_intr_cfg(&mut self, property: &[u8]) -> Result<(), Aic2Error> {
        if !property.len().is_multiple_of(3) {
            return Err(Aic2Error::InvalidConfig(
                "aic-ext-intr-cfg is not a list of triples",
            ));
        }
        for entry in property.as_chunks::<3>().0 {
            let input = AicInput::new(
                entry[1] >> 4,
                u16::from(entry[0]) | u16::from(entry[1] & 0xf) << 8,
            );
            if input.die != 0 || input.irq >= self.config.nr_irq {
                return Err(Aic2Error::UnknownInput(input));
            }
            let target = u32::from(entry[2]);
            self.check_target(target)
                .map_err(Aic2Error::InvalidConfig)?;
            let cfg = &mut self.irq_cfg[usize::from(input.irq)];
            *cfg = *cfg & !IRQ_CFG_TARGET | target;
        }
        Ok(())
    }

    fn check_target(&self, target: u32) -> Result<(), &'static str> {
        if target & !IRQ_CFG_TARGET != 0 {
            return Err("IRQ_CFG TARGET has only four bits");
        }
        if (0..TARGET_GROUPS)
            .any(|group| target & 1 << group != 0 && self.config.target_groups[group].is_none())
        {
            return Err("IRQ_CFG TARGET names a CPU group the board profile does not define");
        }
        Ok(())
    }
    fn cpus_of(&self, irq: usize) -> u64 {
        let target = self.irq_cfg[irq] & IRQ_CFG_TARGET;
        if target == 0 {
            return self.config.default_cpus;
        }
        (0..TARGET_GROUPS)
            .filter(|group| target & 1 << group != 0)
            .filter_map(|group| self.config.target_groups[group])
            .fold(0, |cpus, group| cpus | group)
    }
    /// The highest-priority deliverable IRQ for `cpu`.
    fn pending_for(&self, cpu: CpuIndex) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        (0..self.software.len())
            .flat_map(|word| {
                let pending = (self.software[word] | self.hardware[word]) & !self.mask[word];
                (0..32)
                    .filter(move |bit| pending & 1 << bit != 0)
                    .map(move |bit| word * 32 + bit)
            })
            .take_while(|&irq| irq < usize::from(self.config.nr_irq))
            .find(|&irq| self.cpus_of(irq) & 1 << cpu != 0)
    }
    fn update(&mut self, access: &mut Access<'_>) {
        for cpu in 0..self.config.cpus {
            let level = self.pending_for(cpu).is_some();
            if self.irq_level[cpu] != level {
                self.irq_level[cpu] = level;
                access.interrupts.set_level(Wire::Irq(cpu), level);
            }
        }
    }
    fn decode(&self, offset: u64) -> Option<Register> {
        let words = self.software.len() as u64;
        let irq_config = self.config.irq_config;
        let configs = irq_config + 4 * u64::from(self.config.max_irq);
        let used_words = usize::from(self.config.nr_irq).div_ceil(32) as u64;
        Some(match offset {
            INFO1 => Register::Info1,
            INFO3 => Register::Info3,
            CONFIG => Register::Config,
            offset if offset == self.config.event_offset => Register::Event,
            offset if (irq_config..configs).contains(&offset) => {
                let irq = (offset - irq_config) / 4;
                if irq >= u64::from(self.config.nr_irq) {
                    return None;
                }
                Register::IrqConfig(irq as usize)
            }
            offset if (configs..configs + 4 * 5 * words).contains(&offset) => {
                let index = (offset - configs) / 4;
                let (array, word) = (index / words, index % words);
                if word >= used_words {
                    return None;
                }
                let array = [
                    Array::SoftwareSet,
                    Array::SoftwareClear,
                    Array::MaskSet,
                    Array::MaskClear,
                    Array::HardwareState,
                ][array as usize];
                Register::Bits(array, word as usize)
            }
            _ => return None,
        })
    }
    fn unknown_reason(offset: u64) -> &'static str {
        match offset {
            VERSION => "AIC2 VERSION value is not known",
            INFO2 => "AIC2 INFO2 is not documented",
            RESET => "AIC2 RESET is not modeled",
            _ => "unknown or unimplemented AIC2 register",
        }
    }
    /// Bits of `word` that name implemented IRQs.
    fn implemented(&self, word: usize) -> u32 {
        let first = word * 32;
        let count = usize::from(self.config.nr_irq)
            .saturating_sub(first)
            .min(32);
        if count == 32 {
            u32::MAX
        } else {
            (1 << count) - 1
        }
    }
    fn read_register(&mut self, register: Register, cpu: CpuIndex) -> Result<u32, &'static str> {
        Ok(match register {
            Register::Info1 => u32::from(self.config.nr_irq),
            Register::Info3 => u32::from(self.config.max_irq) | 1 << INFO_DIE_SHIFT,
            Register::Config => u32::from(self.enabled),
            Register::IrqConfig(irq) => self.irq_cfg[irq],
            Register::Bits(Array::SoftwareSet | Array::SoftwareClear, word) => self.software[word],
            Register::Bits(Array::MaskSet | Array::MaskClear, word) => {
                self.mask[word] & self.implemented(word)
            }
            Register::Bits(Array::HardwareState, word) => self.hardware[word],
            Register::Event => {
                if cpu >= self.config.cpus {
                    return Err("event read from a CPU the AIC does not serve");
                }
                match self.pending_for(cpu) {
                    Some(irq) => {
                        let (word, bit) = position(irq);
                        self.mask[word] |= bit;
                        EVENT_TYPE_IRQ | irq as u32
                    }
                    None => 0,
                }
            }
        })
    }
    fn write_register(&mut self, register: Register, value: u32) -> Result<(), &'static str> {
        match register {
            Register::Config => {
                if value & !CONFIG_ENABLE != 0 {
                    return Err("AIC2 CONFIG fields other than ENABLE are not modeled");
                }
                self.enabled = value & CONFIG_ENABLE != 0;
            }
            Register::IrqConfig(irq) => {
                if value & !(IRQ_CFG_TARGET | IRQ_CFG_DELAY_IDX) != 0 {
                    return Err("AIC2 IRQ_CFG reserved field is not modeled");
                }
                self.check_target(value & IRQ_CFG_TARGET)?;
                self.irq_cfg[irq] = value;
            }
            Register::Bits(array, word) => {
                let bits = value & self.implemented(word);
                match array {
                    Array::SoftwareSet => self.software[word] |= bits,
                    Array::SoftwareClear => self.software[word] &= !bits,
                    Array::MaskSet => self.mask[word] |= bits,
                    Array::MaskClear => self.mask[word] &= !bits,
                    Array::HardwareState => return Err("AIC2 HW_STATE is read-only"),
                }
            }
            Register::Info1 | Register::Info3 => {
                return Err("AIC2 capability registers are read-only");
            }
            Register::Event => return Err("AIC2 event register is read-only"),
        }
        Ok(())
    }
}

fn position(irq: usize) -> (usize, u32) {
    (irq / 32, 1 << (irq % 32))
}

impl MmioDevice for Aic2 {
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
        if width != Width::Word {
            return Err(fail("AIC2 registers are 32-bit"));
        }
        let register = self
            .decode(offset)
            .ok_or_else(|| fail(Self::unknown_reason(offset)))?;
        let value = self.read_register(register, access.cpu).map_err(fail)?;
        self.update(access);
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word {
            return Err(fail("AIC2 registers are 32-bit"));
        }
        let register = self
            .decode(offset)
            .ok_or_else(|| fail(Self::unknown_reason(offset)))?;
        self.write_register(register, value as u32).map_err(fail)?;
        self.update(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    const NR_IRQ: u16 = 0x3a0;
    const MAX_IRQ: u16 = 0x400;
    const IRQ_CFG: u64 = AIC2_IRQ_CFG;
    const MASK_SET: u64 = IRQ_CFG + 4 * MAX_IRQ as u64 + 2 * 4 * (MAX_IRQ as u64 / 32);
    const MASK_CLR: u64 = MASK_SET + 4 * (MAX_IRQ as u64 / 32);
    const SW_SET: u64 = IRQ_CFG + 4 * MAX_IRQ as u64;
    const SW_CLR: u64 = SW_SET + 4 * (MAX_IRQ as u64 / 32);
    const EVENT: u64 = 0x8000;
    const UART: AicInput = AicInput::new(0, 739);

    fn aic(cpus: usize) -> Aic2 {
        Aic2::new(Aic2Config {
            nr_irq: NR_IRQ,
            max_irq: MAX_IRQ,
            irq_config: IRQ_CFG,
            event_offset: EVENT,
            cpus,
            default_cpus: 1,
            target_groups: [Some(0b0001), Some(0b0010), None, None],
        })
        .unwrap()
    }
    fn read(aic: &mut Aic2, latch: &mut InterruptLatch, cpu: CpuIndex, offset: u64) -> u32 {
        aic.read(offset, Width::Word, &mut Access::new(cpu, 0, latch))
            .unwrap() as u32
    }
    fn write(aic: &mut Aic2, latch: &mut InterruptLatch, offset: u64, value: u32) {
        aic.write(
            offset,
            Width::Word,
            value.into(),
            &mut Access::new(0, 0, latch),
        )
        .unwrap();
    }
    /// Linux `aic_of_ic_init`: read INFO1/INFO3, mask and clear every IRQ,
    /// then set CONFIG.ENABLE with a read-modify-write.
    fn linux_init(aic: &mut Aic2, latch: &mut InterruptLatch) {
        let info1 = read(aic, latch, 0, INFO1);
        let info3 = read(aic, latch, 0, INFO3);
        assert_eq!(info1 & 0xffff, u32::from(NR_IRQ));
        assert_eq!(info1 >> 24 & 0xf, 0, "LAST_DIE");
        assert_eq!(info3 & 0xffff, u32::from(MAX_IRQ));
        assert_eq!(info3 >> 24 & 0xf, 1, "MAX_DIE");
        for word in 0..u64::from(NR_IRQ).div_ceil(32) {
            write(aic, latch, MASK_SET + 4 * word, u32::MAX);
            write(aic, latch, SW_CLR + 4 * word, u32::MAX);
        }
        let config = read(aic, latch, 0, CONFIG);
        write(aic, latch, CONFIG, config | CONFIG_ENABLE);
    }

    /// Linux `aic_irq_unmask`, `aic_handle_irq` (event read with auto-mask)
    /// and `aic_irq_eoi` (unmask again) for the UART line.
    #[test]
    fn linux_hardware_irq_cycle() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        linux_init(&mut aic, &mut latch);
        let (word, bit) = position(UART.irq.into());
        write(&mut aic, &mut latch, MASK_CLR + 4 * word as u64, bit);
        aic.set_input(UART, true, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        assert!(latch.pins(0).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16 | 739);
        assert!(!latch.pins(0).irq, "the event read masked the IRQ");
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
        aic.set_input(UART, false, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        write(&mut aic, &mut latch, MASK_CLR + 4 * word as u64, bit);
        assert!(!latch.pins(0).irq);
        aic.set_input(UART, true, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        assert!(latch.pins(0).irq);
    }

    #[test]
    fn software_triggers_and_priority() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        linux_init(&mut aic, &mut latch);
        write(&mut aic, &mut latch, MASK_CLR, 0b1010);
        write(&mut aic, &mut latch, SW_SET, 0b1110);
        assert_eq!(read(&mut aic, &mut latch, 0, SW_SET), 0b1110);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16 | 1);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16 | 3);
        assert_eq!(
            read(&mut aic, &mut latch, 0, EVENT),
            0,
            "IRQ 2 stays masked"
        );
        write(&mut aic, &mut latch, SW_CLR, 0b1110);
        write(&mut aic, &mut latch, MASK_CLR, 0b1010);
        assert!(!latch.pins(0).irq);
    }

    #[test]
    fn disabled_controller_and_targets_gate_delivery() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        write(&mut aic, &mut latch, MASK_CLR, 1);
        aic.set_input(
            AicInput::new(0, 0),
            true,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        assert!(!latch.pins(0).irq, "CONFIG.ENABLE is clear");
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        assert!(
            latch.pins(0).irq && !latch.pins(1).irq,
            "TARGET 0 uses the default CPUs"
        );
        write(&mut aic, &mut latch, IRQ_CFG, 0b10);
        assert!(!latch.pins(0).irq && latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
        assert_eq!(read(&mut aic, &mut latch, 1, EVENT), 1 << 16);
        assert!(
            aic.write(
                IRQ_CFG,
                Width::Word,
                0b100,
                &mut Access::new(0, 0, &mut latch)
            )
            .is_err()
        );
    }

    #[test]
    fn ext_intr_cfg_and_refusals() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        // IRQ 0x2e3 (739) to TARGET 2.
        aic.apply_ext_intr_cfg(&[0xe3, 0x02, 0x02]).unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, IRQ_CFG + 4 * 739), 2);
        assert!(
            aic.apply_ext_intr_cfg(&[0xe3, 0x12, 0x01]).is_err(),
            "die 1"
        );
        let mut access = Access::new(0, 0, &mut latch);
        for offset in [
            VERSION,
            INFO2,
            RESET,
            0x28,
            IRQ_CFG + 4 * u64::from(NR_IRQ),
            EVENT + 4,
        ] {
            assert!(
                aic.read(offset, Width::Word, &mut access).is_err(),
                "{offset:#x}"
            );
        }
        assert!(
            aic.write(CONFIG, Width::Word, 1 << 28, &mut access)
                .is_err()
        );
        assert!(aic.write(EVENT, Width::Word, 0, &mut access).is_err());
        assert!(aic.read(EVENT, Width::Double, &mut access).is_err());
        assert!(
            aic.set_input(AicInput::new(0, NR_IRQ), true, &mut access)
                .is_err()
        );
    }

    /// AICv3 (Linux `aic3_info`, `t8122.dtsi`): the same registers with the
    /// per-die arrays at 0x10000 and, on T8122, the event register at
    /// +0x40000.
    #[test]
    fn aic3_moves_the_per_die_arrays() {
        let v3 = |irq_config, event_offset| {
            Aic2::new(Aic2Config {
                nr_irq: NR_IRQ,
                max_irq: MAX_IRQ,
                irq_config,
                event_offset,
                cpus: 1,
                default_cpus: 1,
                target_groups: [None; 4],
            })
        };
        let mut aic = v3(AIC3_IRQ_CFG, 0x40000).unwrap();
        assert_eq!(aic.span(), 0x40004);
        let mut latch = InterruptLatch::new();
        let mask_clear = AIC3_IRQ_CFG + 4 * u64::from(MAX_IRQ) + 3 * 4 * u64::from(MAX_IRQ / 32);
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, mask_clear, 1 << 3);
        write(&mut aic, &mut latch, AIC3_IRQ_CFG + 4 * 3, 0);
        aic.set_input(
            AicInput::new(0, 3),
            true,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, 0x40000), 1 << 16 | 3);
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            aic.read(AIC2_IRQ_CFG, Width::Word, &mut access).is_err(),
            "AICv2's array offset is unallocated"
        );
        assert!(
            v3(AIC3_IRQ_CFG, EVENT).is_err(),
            "the event overlaps the arrays"
        );
        assert!(v3(CONFIG, 0x40000).is_err());
        assert!(v3(AIC3_IRQ_CFG + 2, 0x40000).is_err());
    }
}
