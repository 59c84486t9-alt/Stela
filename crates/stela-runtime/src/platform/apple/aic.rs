//! Apple Interrupt Controller v2 (`apple,t8112-aic`, `apple,aic2`; ADT
//! `aic,2`), the T8112 controller for peripheral IRQs, and v3
//! (`apple,t8122-aic3`; ADT `aic,3`), which is v2 with its per-die arrays at
//! 0x10000 (Linux `AIC3_IRQ_CFG`; ADT `extint-baseaddress`). Fast IPIs and
//! timer FIQs bypass it (see `ipi` and `timer`).
//!
//! Documented by Linux `drivers/irqchip/irq-apple-aic.c` and m1n1
//! `src/aic.c` / `src/aic_regs.h`:
//! - `VERSION` (`REV`, 0x0) holds VER [7:0]; `INFO1` (`CAP0`, 0x4) holds
//!   NR_IRQ [15:0] and LAST_DIE [27:24]; `INFO3`
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
//! - The vGIC maintenance interrupt is the core's own: Linux numbers it
//!   `AIC_VGIC_MI` in its FIQ-source domain but finds it in `aic_handle_irq`,
//!   after the event register reads 0, by reading ICH_MISR_EL2, so it
//!   arrives on IRQ without an AIC event (`machine::vgic`), not as an FIQ.
//!
//! The 26A434 kernel's `AppleInterruptControllerV2` documents the shared
//! interrupt timestamps the ADT counts in `#shared-timestamps`: slot N is at
//! 0x1800 + 0x10 * N, with a configuration word at +0 holding ENABLE [31],
//! DIE [26:24] and IRQ [10:0] (`startInterruptTimestamping`, which also
//! restores saved words), and the timestamp's low and high words at +0x8 and
//! +0xc, which `AICInterruptTimestampFunction::getTimestamp` adds to
//! `ml_get_abstime_offset()`, so the timestamp is the raw system counter.
//!
//! The 26A434 kernel's `AppleInterruptControllerV2` (the ADT `aic,2` driver)
//! hard-codes `MASK_SET` at 0x6400, `MASK_CLR` at 0x6600, `HW_STATE` at
//! 0x6800 and a die stride of 0x4a00 (`start` and `_configureExternalInterruptMap`),
//! the layout of a MAX_IRQ of 4096 ([`stela_soc_data::aic::AIC2_MAX_IRQ`]), and reads INFO3's
//! MAX_IRQ to split IRQ numbers into dies. Its `start` keeps VERSION [7:0] in a
//! field no code reads.
//!
//! The `aic,3` driver (`AppleInterruptControllerV3`, every M3-to-M6 board)
//! does read VERSION: it masks it to eight bits and from revision 0xb takes
//! die and SoC topology paths that read the ADT's `aic-numdies`,
//! `aic-numdies-per-die`, `aic-die-offset-stride`, `aic-soc-offset-stride`
//! and `max-extint-num` (Snapintosh `docs/DEVICE-REFERENCES.md`, for the
//! J700 driver; the 26A434 M4 kernelcache carries those names beside "_aicNumDies
//! is not defined in DT"). No 26A434 Mac DeviceTree has any of them, nor
//! `aic-rev` (J613, J773g, J813, J873g, J514c/m, J575d), so those boards'
//! AICs report a revision below 0xb (inference); what each chip reports is
//! not public.
//!
//! Below that revision the `aic,3` driver, one build on every 26A434 M3 to M6
//! kernel (J613, J514s, J514c, J773g, J873g), hard-codes the per-die arrays
//! as the AICv2's 4096-IRQ layout moved to `extint-baseaddress`: IRQ_CFG at
//! +0, `MASK_SET` at +0x4400, `MASK_CLR` at +0x4600 and `HW_STATE` at
//! +0x4800, with a die stride of 0x4a00 unless the ADT states one
//! (`getAICExtIntrCfgOffset`, `getAICIntMaskSetOffset`,
//! `getAICIntMaskClrOffset`, `getAICHwIntMonOffset`). Only an ADT
//! `max-extint-num`, which no 26A434 Mac DeviceTree has, selects a doubled
//! layout (+0x8800, +0x8c00, +0x9000), which is not modeled. So an AICv3's
//! MAX_IRQ is [`stela_soc_data::aic::AIC2_MAX_IRQ`] too: `startInterruptTimestamping` splits an
//! IRQ number into its die by INFO3's MAX_IRQ. Its shared timestamps are the
//! AICv2's slots at the ADT's `pubstampcfg0-offset` 0x1000
//! ([`stela_soc_data::aic::AIC3_TIMESTAMPS`]; `getAICPubStampCfgOffset`, `getAICPubStampLoOffset`
//! and `getAICPubStampHiOffset` default to 0x1000, 0x1008 and 0x100c plus
//! 0x10 per slot), with the same ENABLE, DIE and IRQ fields.
//!
//! Both 26A434 drivers number their vectors die by die (`start` of
//! `AppleInterruptControllerV2` in `kernelcache.release.mac13j` and of
//! `AppleInterruptControllerV3` in `kernelcache.release.mac15j`): they take
//! the populated dies from INFO1's LAST_DIE + 1 and MAX_IRQ from INFO3, and
//! size the vector table at their product, the `_aicNumVectors` `start`
//! logs; enabling, disabling and acknowledging vector V address die
//! V / MAX_IRQ, IRQ V % MAX_IRQ, and a vector at or past the product panics
//! ("Invalid interrupt number"). NR_IRQ, which the `aic,2` driver reads from
//! INFO1 [10:0] and the `aic,3` driver from CAP0 under the ADT's
//! `cap0_max_interrupt_umask` (0xffff when absent; MAX_IRQ likewise under
//! `max_irq_interrupt_umask`), only bounds the mask words `start` sets on
//! every die, NR_IRQ / 32 rounded up. So a DeviceTree specifier naming the
//! AIC is a vector: J575d's second-die CLPC line 0x15bf is die 1, IRQ 0x5bf.
//! Dies sit [`stela_soc_data::aic::AIC2_DIE_STRIDE`] apart: the `aic,2` driver hard-codes it,
//! and the `aic,3` driver multiplies the die by the ADT's
//! `extintrcfg-stride`, `intmaskset-stride`, `intmaskclear-stride` and
//! `hwintmon-stride` once `extint-baseaddress` is stated, which J575d and
//! J775d state as 0x4a00 (single-die J613 and J504 state 0, which die 0
//! never multiplies).
//!
//! Inferred, not documented: VER is the controller's generation (2 for
//! AICv2, 3 for AICv3), below the `aic,3` driver's 0xb topology threshold;
//! an enabled
//! timestamp slot latches the system counter at each rising edge of its
//! hardware input, and a slot reads 0 until it first latches; the reset state masks every IRQ with zero
//! configuration; `SET`/`CLR` reads return the current bits; IRQs with TARGET 0
//! use the configured AP eligible CPU set; the first CPU to read the event
//! register claims the IRQ. Across dies, the lowest die
//! number wins before the lowest IRQ number; cross-die arbitration is not
//! documented, so this is a deterministic permitted ordering.
//!
//! TARGET [3:0] is a destination selector, not four CPU-group mask bits.
//! Hector Martin's 2021-12-18 AICv2 observations identify selector 0 as AP
//! delivery and suggest coprocessor destinations otherwise; they distinguish
//! the separate three-bit IRQ configuration group. Linux names that group
//! DELAY_IDX [7:5], but its delay/priority effects remain unchecked here.
//! Nonzero TARGET or DELAY_IDX therefore refuses before changing state.
//! The configured AP roster is software policy, not a silicon arbitration
//! contract or proof of delivery to any physical MPIDR (including 0x100).
//! 26A434 J473's AIC start at 0xfffffe0009825a84..0xfffffe0009825ad0
//! preserves inherited CONFIG except enabling bit 0; its optional
//! `aic-ext-intr-cfg` consumer only replaces the per-source low four bits.
//! Neither operation derives a physical recipient from a CPU's logical ID.
//!
//! Multiple dies and AICv3's relocated capability/array registers require an
//! explicit [`Aic2Layout`]. m1n1 `src/aic.c` reads `cap0-offset`,
//! `maxnumirq-offset`, `extintrcfg-stride`, `intmaskset-stride` and
//! `intmaskclear-stride` from the ADT. Each bank's established address is
//! supplied independently; the legacy constructor keeps the single-die
//! contiguous layout. Unknown banks or hardware capacity are not inferred.
//!
//! Physical lifecycle is checked independently of CONFIG.ENABLE. Retained
//! clock/quiesce pauses require delivery disabled and all timestamp slots
//! disarmed: capture/wake behavior while the physical clock is stopped is
//! unchecked. Software pending, current external levels, masks, routes and
//! timestamp history remain owned. Supply loss and physical reset refuse.

#[cfg(test)]
use stela_soc_data::aic::AIC2_DIE_STRIDE;
#[cfg(test)]
use stela_soc_data::aic::AIC2_IRQ_CFG;
#[cfg(test)]
use stela_soc_data::aic::AIC2_MAX_IRQ;
#[cfg(test)]
use stela_soc_data::aic::AIC2_TIMESTAMPS;
#[cfg(test)]
use stela_soc_data::aic::AIC3_IRQ_CFG;
#[cfg(test)]
use stela_soc_data::aic::AIC3_TIMESTAMPS;
use stela_soc_data::aic::CONFIG;
#[cfg(test)]
use stela_soc_data::aic::INFO1;
#[cfg(test)]
use stela_soc_data::aic::INFO3;
use stela_soc_data::aic::TIMESTAMP_STRIDE;
use stela_soc_data::aic::VERSION;
use stela_soc_data::aic::layout::Aic2Layout;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};
use {
    stela_contracts::interrupt::AicInput, stela_contracts::interrupt::CpuIndex,
    stela_contracts::interrupt::Wire,
};

const NAME: &str = "aic2";

const INFO2: u64 = 0x0008;
const RESET: u64 = 0x0010;

const TIMESTAMP_LOW: u64 = 0x8;
const TIMESTAMP_HIGH: u64 = 0xc;
const TIMESTAMP_ENABLE: u32 = 1 << 31;
const TIMESTAMP_DIE: u32 = 0b111 << 24;
const TIMESTAMP_IRQ: u32 = 0x7ff;

const INFO_DIE_SHIFT: u32 = 24;
const CONFIG_ENABLE: u32 = 1;
const IRQ_CFG_TARGET: u32 = 0xf;
const IRQ_CFG_DELAY_IDX: u32 = 0b111 << 5;
const EVENT_TYPE_IRQ: u32 = 1 << 16;

use stela_soc_data::aic::Aic2Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aic2Error {
    InvalidConfig(&'static str),
    UnknownInput(AicInput),
}

/// One shared timestamp slot: its configuration word and its latched
/// system counter value.
#[derive(Debug, Clone, Copy, Default)]
struct Timestamp {
    config: u32,
    counter: u64,
}

pub struct Aic2 {
    lifecycle: LifecycleState,
    config: Aic2Config,
    layout: Aic2Layout,
    span: u64,
    timestamps: Vec<Timestamp>,
    enabled: bool,
    irq_cfg: Vec<u32>,
    software: Vec<u32>,
    hardware: Vec<u32>,
    mask: Vec<u32>,
    irq_level: Vec<bool>,
    /// The CPUs whose SIQ_CFG_EL1 refuses IRQs ([`Aic2::steer`]).
    refusing: u64,
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
    Version,
    Info1,
    Info3,
    Config,
    IrqConfig(usize),
    Bits(Array, usize),
    Event,
    TimestampConfig(usize),
    TimestampLow(usize),
    TimestampHigh(usize),
}

impl Aic2 {
    #[cfg(test)]
    pub fn new(config: Aic2Config) -> Result<Self, Aic2Error> {
        Self::stacked(config, 1)
    }

    /// An AIC with `dies` populated dies, each die's arrays right after the
    /// previous die's ([`Aic2Layout::stacked`]) and the event register after
    /// the last.
    pub fn stacked(config: Aic2Config, dies: u8) -> Result<Self, Aic2Error> {
        let layout = Aic2Layout::stacked(&config, dies).ok_or(Aic2Error::InvalidConfig(
            "AIC contiguous register layout overflows",
        ))?;
        let last = layout
            .dies
            .last()
            .ok_or(Aic2Error::InvalidConfig("an AIC has at least one die"))?;
        let end = last.hardware_state + 4 * u64::from(config.max_irq / 32);
        if config.event_offset < end {
            return Err(Aic2Error::InvalidConfig(
                "the event register must follow the per-die arrays",
            ));
        }
        Self::new_with_layout(config, layout)
    }

    /// Construct only from established capability and per-die bank facts.
    /// This supports multiple dies and AICv3's relocated capability/mask
    /// banks without assuming a layout for an unobserved generation.
    pub fn new_with_layout(config: Aic2Config, layout: Aic2Layout) -> Result<Self, Aic2Error> {
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
        if config.default_cpus & !all_cpus != 0 {
            return invalid("a CPU set names a CPU beyond the CPU count");
        }
        if config.irq_config <= CONFIG || !config.irq_config.is_multiple_of(4) {
            return invalid("the IRQ_CFG array must be a word after CONFIG");
        }
        if config.timestamps != 0
            && TIMESTAMP_STRIDE
                .checked_mul(config.timestamps as u64)
                .and_then(|bytes| config.timestamp_base.checked_add(bytes))
                .is_none_or(|end| end > config.irq_config)
        {
            return invalid("the timestamp slots must end before the IRQ_CFG array");
        }
        let span = layout.validate(&config).map_err(Aic2Error::InvalidConfig)?;
        let words = usize::from(config.max_irq / 32) * layout.dies.len();
        Ok(Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            },
            timestamps: vec![Timestamp::default(); config.timestamps],
            enabled: false,
            irq_cfg: vec![0; usize::from(config.max_irq) * layout.dies.len()],
            software: vec![0; words],
            hardware: vec![0; words],
            mask: vec![u32::MAX; words],
            irq_level: vec![false; config.cpus],
            refusing: 0,
            config,
            layout,
            span,
        })
    }
    /// Size of the device address space to map: core block plus event word.
    pub fn span(&self) -> u64 {
        self.span
    }
    /// Sets the level of one hardware input, as wired by the engine from the
    /// device models' `Wire::Aic` outputs.
    pub fn set_input(
        &mut self,
        input: AicInput,
        asserted: bool,
        access: &mut Access<'_>,
    ) -> Result<(), Aic2Error> {
        if usize::from(input.die) >= self.layout.dies.len() || input.irq >= self.config.nr_irq {
            return Err(Aic2Error::UnknownInput(input));
        }
        let (word, bit) = position(self.input_index(input));
        if asserted && self.hardware[word] & bit == 0 {
            let config =
                TIMESTAMP_ENABLE | u32::from(input.die) << INFO_DIE_SHIFT | u32::from(input.irq);
            for slot in &mut self.timestamps {
                if slot.config == config {
                    slot.counter = access.now;
                }
            }
        }
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
    #[cfg(test)]
    pub fn apply_ext_intr_cfg(&mut self, property: &[u8]) -> Result<(), Aic2Error> {
        if !property.len().is_multiple_of(3) {
            return Err(Aic2Error::InvalidConfig(
                "aic-ext-intr-cfg is not a list of triples",
            ));
        }
        // Validate the whole firmware property before applying any entry.
        for entry in property.as_chunks::<3>().0 {
            let input = Self::ext_input(entry);
            if usize::from(input.die) >= self.layout.dies.len() || input.irq >= self.config.nr_irq {
                return Err(Aic2Error::UnknownInput(input));
            }
            Self::check_target(u32::from(entry[2])).map_err(Aic2Error::InvalidConfig)?;
            let index = self.input_index(input);
            Self::check_irq_config(self.irq_cfg[index] & !IRQ_CFG_TARGET | u32::from(entry[2]))
                .map_err(Aic2Error::InvalidConfig)?;
        }
        for entry in property.as_chunks::<3>().0 {
            let index = self.input_index(Self::ext_input(entry));
            self.irq_cfg[index] = self.irq_cfg[index] & !IRQ_CFG_TARGET | u32::from(entry[2]);
        }
        Ok(())
    }

    #[cfg(test)]
    fn ext_input(entry: &[u8; 3]) -> AicInput {
        AicInput::new(
            entry[1] >> 4,
            u16::from(entry[0]) | u16::from(entry[1] & 0xf) << 8,
        )
    }
    fn input_index(&self, input: AicInput) -> usize {
        usize::from(input.die) * usize::from(self.config.max_irq) + usize::from(input.irq)
    }

    fn check_target(target: u32) -> Result<(), &'static str> {
        if target & !IRQ_CFG_TARGET != 0 {
            return Err("IRQ_CFG TARGET has only four bits");
        }
        if target != 0 {
            return Err("nonzero IRQ_CFG TARGET destination selectors are unqualified");
        }
        Ok(())
    }
    fn check_irq_config(value: u32) -> Result<(), &'static str> {
        if value & !(IRQ_CFG_TARGET | IRQ_CFG_DELAY_IDX) != 0 {
            return Err("AIC2 IRQ_CFG reserved field is not modeled");
        }
        Self::check_target(value & IRQ_CFG_TARGET)?;
        if value & IRQ_CFG_DELAY_IDX != 0 {
            return Err("nonzero IRQ_CFG DELAY_IDX delay/priority effects are unqualified");
        }
        Ok(())
    }
    /// CPU `cpu`'s SIQ_CFG_EL1 mode refuses IRQs (`true`) or accepts them:
    /// a refusing CPU is sent none, so an IRQ targeting it reaches only the
    /// other CPUs of its target set, or waits for one to accept
    /// (`registers::SIQ_CFG_NO_IRQ`). A CPU the AIC does not serve changes
    /// nothing.
    pub fn steer(&mut self, cpu: CpuIndex, refuses: bool, access: &mut Access<'_>) {
        if cpu >= self.config.cpus {
            return;
        }
        if refuses {
            self.refusing |= 1 << cpu;
        } else {
            self.refusing &= !(1 << cpu);
        }
        self.update(access);
    }
    /// The highest-priority deliverable IRQ for `cpu`.
    fn pending_for(&self, cpu: CpuIndex) -> Option<usize> {
        if !self.enabled
            || !self.lifecycle.clocked
            || self.lifecycle.quiesced
            || self.refusing & 1 << cpu != 0
            || self.config.default_cpus & 1 << cpu == 0
        {
            return None;
        }
        (0..self.software.len())
            .flat_map(|word| {
                let pending = (self.software[word] | self.hardware[word]) & !self.mask[word];
                (0..32)
                    .filter(move |bit| pending & 1 << bit != 0)
                    .map(move |bit| word * 32 + bit)
            })
            .find(|&irq| irq % usize::from(self.config.max_irq) < usize::from(self.config.nr_irq))
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
        if !offset.is_multiple_of(4) {
            return None;
        }
        if offset == self.layout.info1 {
            return Some(Register::Info1);
        }
        if offset == self.layout.info3 {
            return Some(Register::Info3);
        }
        match offset {
            VERSION => return Some(Register::Version),
            CONFIG => return Some(Register::Config),
            offset if offset == self.config.event_offset => return Some(Register::Event),
            _ => {}
        }
        let timestamps = self.config.timestamp_base;
        if (timestamps..timestamps + TIMESTAMP_STRIDE * self.timestamps.len() as u64)
            .contains(&offset)
        {
            let slot = ((offset - timestamps) / TIMESTAMP_STRIDE) as usize;
            return match offset % TIMESTAMP_STRIDE {
                0 => Some(Register::TimestampConfig(slot)),
                TIMESTAMP_LOW => Some(Register::TimestampLow(slot)),
                TIMESTAMP_HIGH => Some(Register::TimestampHigh(slot)),
                _ => None,
            };
        }
        let words = usize::from(self.config.max_irq / 32);
        let used_words = usize::from(self.config.nr_irq).div_ceil(32);
        for (die, layout) in self.layout.dies.iter().enumerate() {
            for (array, start) in layout.banks().into_iter().enumerate() {
                let entries = if array == 0 {
                    usize::from(self.config.nr_irq)
                } else {
                    used_words
                };
                if offset >= start && (offset - start) / 4 < entries as u64 {
                    let index = ((offset - start) / 4) as usize;
                    return Some(if array == 0 {
                        Register::IrqConfig(die * usize::from(self.config.max_irq) + index)
                    } else {
                        Register::Bits(
                            [
                                Array::SoftwareSet,
                                Array::SoftwareClear,
                                Array::MaskSet,
                                Array::MaskClear,
                                Array::HardwareState,
                            ][array - 1],
                            die * words + index,
                        )
                    });
                }
            }
        }
        None
    }
    fn unknown_reason(offset: u64) -> &'static str {
        match offset {
            INFO2 => "AIC2 INFO2 is not documented",
            RESET => "AIC2 RESET is not modeled",
            _ => "unknown or unimplemented AIC2 register",
        }
    }
    /// Bits of `word` that name implemented IRQs.
    fn implemented(&self, word: usize) -> u32 {
        let first = word % usize::from(self.config.max_irq / 32) * 32;
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
            Register::Version => u32::from(self.config.version),
            Register::Info1 => {
                u32::from(self.config.nr_irq)
                    | ((self.layout.dies.len() - 1) as u32) << INFO_DIE_SHIFT
            }
            Register::Info3 => {
                u32::from(self.config.max_irq) | u32::from(self.layout.max_dies) << INFO_DIE_SHIFT
            }
            Register::Config => u32::from(self.enabled),
            Register::IrqConfig(irq) => self.irq_cfg[irq],
            Register::Bits(Array::SoftwareSet | Array::SoftwareClear, word) => self.software[word],
            Register::Bits(Array::MaskSet | Array::MaskClear, word) => {
                self.mask[word] & self.implemented(word)
            }
            Register::Bits(Array::HardwareState, word) => self.hardware[word],
            Register::TimestampConfig(slot) => self.timestamps[slot].config,
            Register::TimestampLow(slot) => self.timestamps[slot].counter as u32,
            Register::TimestampHigh(slot) => (self.timestamps[slot].counter >> 32) as u32,
            Register::Event => {
                if cpu >= self.config.cpus {
                    return Err("event read from a CPU the AIC does not serve");
                }
                match self.pending_for(cpu) {
                    Some(irq) => {
                        let (word, bit) = position(irq);
                        self.mask[word] |= bit;
                        let die = irq / usize::from(self.config.max_irq);
                        let local = irq % usize::from(self.config.max_irq);
                        EVENT_TYPE_IRQ | (die as u32) << INFO_DIE_SHIFT | local as u32
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
                Self::check_irq_config(value)?;
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
            Register::Version | Register::Info1 | Register::Info3 => {
                return Err("AIC2 capability registers are read-only");
            }
            Register::Event => return Err("AIC2 event register is read-only"),
            Register::TimestampConfig(slot) => {
                if value & !(TIMESTAMP_ENABLE | TIMESTAMP_DIE | TIMESTAMP_IRQ) != 0 {
                    return Err("AIC2 timestamp configuration reserved field is not modeled");
                }
                if value & TIMESTAMP_ENABLE != 0
                    && ((value & TIMESTAMP_DIE) >> INFO_DIE_SHIFT >= self.layout.dies.len() as u32
                        || value & TIMESTAMP_IRQ >= u32::from(self.config.nr_irq))
                {
                    return Err("AIC2 timestamp names an IRQ the model does not have");
                }
                self.timestamps[slot].config = value;
            }
            Register::TimestampLow(_) | Register::TimestampHigh(_) => {
                return Err("AIC2 timestamps are read-only");
            }
        }
        Ok(())
    }
}

impl Lifecycle for Aic2 {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset {
            return Err("AIC physical reset and interrupt/timestamp restoration are unqualified");
        }
        if !proposed.powered {
            return Err(
                "AIC supply loss, input wake capture and physical retention are unqualified",
            );
        }
        if (!proposed.clocked || proposed.quiesced)
            && (self.enabled
                || self
                    .timestamps
                    .iter()
                    .any(|slot| slot.config & TIMESTAMP_ENABLE != 0))
        {
            return Err(
                "AIC pause with IRQ delivery or timestamp capture armed has unqualified wake behavior",
            );
        }
        Ok(())
    }

    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        // All-bank preflight has already checked this edge. Input levels,
        // software pending bits, masks and timestamp history remain owned.
        self.lifecycle = proposed;
        self.update(access);
    }
}

fn position(irq: usize) -> (usize, u32) {
    (irq / 32, 1 << (irq % 32))
}

impl MmioDevice for Aic2 {
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(fail(
                "AIC MMIO while its physical clock is stopped is unqualified",
            ));
        }
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
        if !self.lifecycle.clocked {
            return Err(fail(
                "AIC MMIO while its physical clock is stopped is unqualified",
            ));
        }
        if self.lifecycle.quiesced {
            return Err(fail(
                "AIC register changes while native service is quiesced are unqualified",
            ));
        }
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
    use stela_contracts::interrupt::InterruptLatch;
    use stela_soc_data::aic::layout::Aic2DieLayout;

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
            version: 2,
            nr_irq: NR_IRQ,
            max_irq: MAX_IRQ,
            irq_config: IRQ_CFG,
            event_offset: EVENT,
            timestamps: 16,
            timestamp_base: AIC2_TIMESTAMPS,
            cpus,
            default_cpus: 1,
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
    #[test]
    fn retained_clock_pause_preserves_pending_levels_masks_and_timestamp_history() {
        let mut aic = aic(2);
        let mut latch = InterruptLatch::new();
        let (word, bit) = position(usize::from(UART.irq));
        write(&mut aic, &mut latch, MASK_CLR + 4 * word as u64, bit);
        write(&mut aic, &mut latch, SW_SET + 4 * word as u64, bit);
        write(
            &mut aic,
            &mut latch,
            AIC2_TIMESTAMPS,
            TIMESTAMP_ENABLE | u32::from(UART.irq),
        );
        aic.set_input(UART, true, &mut Access::new(0, 123, &mut latch))
            .unwrap();
        write(&mut aic, &mut latch, AIC2_TIMESTAMPS, 0);
        let active = aic.lifecycle;
        let paused = LifecycleState {
            clocked: false,
            ..active
        };
        aic.check_lifecycle(paused).unwrap();
        aic.set_lifecycle(paused, &mut Access::new(0, 124, &mut latch));
        assert!(
            aic.read(VERSION, Width::Word, &mut Access::new(0, 125, &mut latch))
                .is_err()
        );
        // External lines remain levels. No enabled timestamp or delivery
        // engine was suspended, so no pulse/wake behavior is invented.
        aic.set_input(UART, false, &mut Access::new(0, 126, &mut latch))
            .unwrap();
        aic.set_input(UART, true, &mut Access::new(0, 127, &mut latch))
            .unwrap();
        assert!(!latch.pins(0).irq);
        assert_eq!(aic.software[word] & bit, bit);
        assert_eq!(aic.hardware[word] & bit, bit);
        assert_eq!(aic.mask[word] & bit, 0);
        assert_eq!(aic.timestamps[0].counter, 123);
        aic.check_lifecycle(active).unwrap();
        aic.set_lifecycle(active, &mut Access::new(0, 128, &mut latch));
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        assert!(latch.pins(0).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ | 739);
        assert!(!latch.pins(0).irq);
        // Claim masks the source without consuming software or wire state.
        assert_eq!(aic.software[word] & bit, bit);
        assert_eq!(aic.hardware[word] & bit, bit);
    }

    #[test]
    fn quiesce_is_independent_of_clock_and_cannot_arm_new_delivery() {
        let mut aic = aic(2);
        let mut latch = InterruptLatch::new();
        let active = aic.lifecycle;
        let quiesced = LifecycleState {
            quiesced: true,
            ..active
        };
        aic.check_lifecycle(quiesced).unwrap();
        aic.set_lifecycle(quiesced, &mut Access::new(0, 0, &mut latch));
        assert_eq!(read(&mut aic, &mut latch, 0, CONFIG), 0);
        assert!(
            aic.write(
                CONFIG,
                Width::Word,
                CONFIG_ENABLE.into(),
                &mut Access::new(0, 1, &mut latch),
            )
            .is_err()
        );
        assert!(!aic.enabled);
        let clock_stopped = LifecycleState {
            clocked: false,
            ..quiesced
        };
        aic.check_lifecycle(clock_stopped).unwrap();
        aic.set_lifecycle(clock_stopped, &mut Access::new(0, 2, &mut latch));
        aic.check_lifecycle(quiesced).unwrap();
        aic.set_lifecycle(quiesced, &mut Access::new(0, 3, &mut latch));
        assert!(
            aic.lifecycle.quiesced,
            "clock restart cannot resume service"
        );
        aic.check_lifecycle(active).unwrap();
        aic.set_lifecycle(active, &mut Access::new(0, 4, &mut latch));
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    }

    #[test]
    fn armed_delivery_capture_and_destructive_edges_refuse_without_effects() {
        let mut aic = aic(2);
        let mut latch = InterruptLatch::new();
        let active = aic.lifecycle;
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        for proposed in [
            LifecycleState {
                clocked: false,
                ..active
            },
            LifecycleState {
                quiesced: true,
                ..active
            },
            LifecycleState {
                reset: true,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: false,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..active
            },
        ] {
            assert!(aic.check_lifecycle(proposed).is_err());
            assert_eq!(aic.lifecycle, active);
            assert!(aic.enabled);
        }
        write(&mut aic, &mut latch, CONFIG, 0);
        write(&mut aic, &mut latch, AIC2_TIMESTAMPS, TIMESTAMP_ENABLE | 5);
        assert!(
            aic.check_lifecycle(LifecycleState {
                clocked: false,
                ..active
            })
            .is_err()
        );
        aic.set_input(
            AicInput::new(0, 5),
            true,
            &mut Access::new(0, 99, &mut latch),
        )
        .unwrap();
        assert_eq!(
            aic.timestamps[0].counter, 99,
            "refused pause still captures"
        );
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

    /// The 26A434 kernel's `AppleInterruptControllerV2::start` on a T8112:
    /// VERSION, INFO1 and INFO3, then masks at its fixed 0x6400 and reads
    /// back through 0x6600 and HW_STATE at 0x6800.
    #[test]
    fn xnu_aic2_layout_is_that_of_4096_irqs() {
        let mut latch = InterruptLatch::new();
        let mut aic = Aic2::new(Aic2Config {
            version: 2,
            nr_irq: 740,
            max_irq: AIC2_MAX_IRQ,
            irq_config: AIC2_IRQ_CFG,
            event_offset: 0x8000,
            timestamps: 16,
            timestamp_base: AIC2_TIMESTAMPS,
            cpus: 1,
            default_cpus: 1,
        })
        .unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, VERSION) & 0xff, 2);
        assert_eq!(read(&mut aic, &mut latch, 0, INFO1) & 0x7ff, 740);
        assert_eq!(read(&mut aic, &mut latch, 0, INFO3), 1 << 24 | 0x1000);
        for word in 0..740u64.div_ceil(32) {
            write(&mut aic, &mut latch, 0x6400 + 4 * word, u32::MAX);
        }
        assert_eq!(read(&mut aic, &mut latch, 0, 0x6600), u32::MAX);
        assert_eq!(read(&mut aic, &mut latch, 0, 0x6600 + 4 * 23), 0xf);
        assert_eq!(read(&mut aic, &mut latch, 0, 0x6800), 0);
    }

    /// `startInterruptTimestamping` enables slot 0 for IRQ 0xc9 and
    /// `getTimestamp` reads the high word, then the low one.
    #[test]
    fn timestamp_slots_latch_the_counter_at_their_irqs_rising_edge() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        let irq = AicInput::new(0, 0xc9);
        write(&mut aic, &mut latch, 0x1800, 0x8000_00c9);
        assert_eq!(read(&mut aic, &mut latch, 0, 0x1800), 0x8000_00c9);
        let stamp = 0x1_2345_6789;
        aic.set_input(irq, true, &mut Access::new(0, stamp, &mut latch))
            .unwrap();
        aic.set_input(irq, true, &mut Access::new(0, stamp + 5, &mut latch))
            .unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, 0x180c), 1);
        assert_eq!(read(&mut aic, &mut latch, 0, 0x1808), 0x2345_6789);
        // Slot 1 is idle; slots past `#shared-timestamps` do not exist.
        assert_eq!(read(&mut aic, &mut latch, 0, 0x1818), 0);
        let mut access = Access::new(0, 0, &mut latch);
        assert!(aic.read(0x1900, Width::Word, &mut access).is_err());
        assert!(aic.read(0x1804, Width::Word, &mut access).is_err());
        assert!(aic.write(0x1808, Width::Word, 0, &mut access).is_err());
        assert!(
            aic.write(
                0x1810,
                Width::Word,
                0x8000_0000 | u64::from(NR_IRQ),
                &mut access
            )
            .is_err()
        );
        assert!(
            aic.write(0x1810, Width::Word, 0x4000_0000, &mut access)
                .is_err()
        );
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
    fn disabled_controller_gates_default_ap_delivery() {
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
        assert!(latch.pins(0).irq && !latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 1, EVENT), 0);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ);
        assert!(!latch.pins(0).irq);
    }

    /// TARGET0 uses the explicit AP roster; SIQ filters each PE independently.
    #[test]
    fn a_cpu_refusing_irqs_through_siq_cfg_is_sent_none() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        aic.config.default_cpus = 0b11;
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, MASK_CLR, 1);
        aic.set_input(
            AicInput::new(0, 0),
            true,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        assert!(latch.pins(0).irq && latch.pins(1).irq);
        aic.steer(0, true, &mut Access::new(0, 0, &mut latch));
        assert!(!latch.pins(0).irq && latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
        aic.steer(1, true, &mut Access::new(0, 0, &mut latch));
        assert!(!latch.pins(0).irq && !latch.pins(1).irq);
        aic.steer(0, false, &mut Access::new(0, 0, &mut latch));
        assert!(latch.pins(0).irq && !latch.pins(1).irq);
        // A CPU the AIC does not serve changes nothing.
        aic.steer(5, true, &mut Access::new(0, 0, &mut latch));
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ);
    }

    #[test]
    fn ext_intr_cfg_and_refusals() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        // IRQ 0x2e3 (739) keeps the supported AP selector0.
        aic.apply_ext_intr_cfg(&[0xe3, 0x02, 0x00]).unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, IRQ_CFG + 4 * 739), 0);
        assert!(
            aic.apply_ext_intr_cfg(&[0xe3, 0x12, 0x01]).is_err(),
            "die 1"
        );
        let mut access = Access::new(0, 0, &mut latch);
        for offset in [
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

    fn two_dies() -> (Aic2Config, Aic2Layout) {
        let config = Aic2Config {
            version: 3,
            nr_irq: 33,
            max_irq: 64,
            irq_config: IRQ_CFG,
            event_offset: EVENT,
            timestamps: 16,
            timestamp_base: AIC2_TIMESTAMPS,
            cpus: 2,
            default_cpus: 1,
        };
        let first = Aic2DieLayout::contiguous(IRQ_CFG, config.max_irq).unwrap();
        let mut second = Aic2DieLayout::contiguous(0x4000, config.max_irq).unwrap();
        // Later firmware may supply distinct mask strides. Every other
        // array is explicit too; none aliases the corresponding die0 bank.
        second.mask_set = 0x6000;
        second.mask_clear = 0x7000;
        let layout = Aic2Layout {
            info1: 0x100,
            info3: 0x108,
            max_dies: 4,
            dies: vec![first, second],
        };
        (config, layout)
    }

    #[test]
    fn explicit_layout_routes_claims_masks_and_timestamps_independently_per_die() {
        let (config, layout) = two_dies();
        let (first, second) = (layout.dies[0], layout.dies[1]);
        let mut aic = Aic2::new_with_layout(config, layout).unwrap();
        let mut latch = InterruptLatch::new();
        assert_eq!(read(&mut aic, &mut latch, 0, 0x100), 1 << 24 | 33);
        assert_eq!(read(&mut aic, &mut latch, 0, 0x108), 4 << 24 | 64);
        assert_eq!(aic.span(), EVENT + 4);
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, first.mask_clear + 4, 1);
        write(&mut aic, &mut latch, second.mask_clear + 4, 1);
        write(
            &mut aic,
            &mut latch,
            AIC2_TIMESTAMPS,
            TIMESTAMP_ENABLE | 1 << 24 | 32,
        );
        let input = AicInput::new(1, 32);
        aic.set_input(
            input,
            true,
            &mut Access::new(0, 0x1234_5678_9abc_def0, &mut latch),
        )
        .unwrap();
        assert_eq!(
            read(&mut aic, &mut latch, 0, AIC2_TIMESTAMPS + TIMESTAMP_LOW),
            0x9abc_def0
        );
        assert_eq!(
            read(&mut aic, &mut latch, 0, AIC2_TIMESTAMPS + TIMESTAMP_HIGH),
            0x1234_5678
        );
        assert_eq!(read(&mut aic, &mut latch, 0, first.hardware_state + 4), 0);
        assert_eq!(read(&mut aic, &mut latch, 0, second.hardware_state + 4), 1);
        write(&mut aic, &mut latch, first.software_set + 4, 1);
        assert!(latch.pins(0).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ | 32);
        assert!(latch.pins(0).irq, "die1 remains independently pending");
        assert_eq!(
            read(&mut aic, &mut latch, 0, EVENT),
            1 << 24 | EVENT_TYPE_IRQ | 32
        );
        assert!(!latch.pins(0).irq);
        // A held level fires again only after that die is unmasked.
        write(&mut aic, &mut latch, first.mask_clear + 4, 1);
        write(&mut aic, &mut latch, first.software_clear + 4, 1);
        assert!(!latch.pins(0).irq);
        write(&mut aic, &mut latch, second.mask_clear + 4, u32::MAX);
        assert!(latch.pins(0).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, second.mask_set + 4), 0);
        // Invalid tail bits are ignored independently in each die.
        assert_eq!(read(&mut aic, &mut latch, 0, first.mask_set + 4), 0);
        let mut access = Access::new(0, 0, &mut latch);
        for offset in [
            INFO1,
            INFO3,
            second.mask_set + 8,
            second.irq_config + 4 * 33,
            second.mask_set + 1,
        ] {
            assert!(aic.read(offset, Width::Word, &mut access).is_err());
        }
        assert!(
            aic.set_input(AicInput::new(2, 0), true, &mut access)
                .is_err()
        );
    }

    #[test]
    fn firmware_routing_refusals_are_atomic_across_dies() {
        let (mut config, layout) = two_dies();
        config.default_cpus = 0b10;
        let second = layout.dies[1];
        let mut aic = Aic2::new_with_layout(config, layout).unwrap();
        let first_index = aic.input_index(AicInput::new(0, 3));
        let second_index = aic.input_index(AicInput::new(1, 3));
        // Seed an unadmitted selector so applying the valid prefix
        // would visibly change it. Production never accepts this selector.
        aic.irq_cfg[first_index] = 5;
        let before = aic.irq_cfg.clone();
        for suffix in [[3, 0x10, 2], [0, 0x20, 0], [3, 0x10, 0x20]] {
            let property = [3, 0, 0, suffix[0], suffix[1], suffix[2]];
            assert!(aic.apply_ext_intr_cfg(&property).is_err());
            assert_eq!(aic.irq_cfg, before);
        }
        // A firmware target replacement must also validate the whole word:
        // it cannot preserve an unchecked nonzero delay field.
        aic.irq_cfg[second_index] = 1 << 5;
        let before = aic.irq_cfg.clone();
        assert_eq!(
            aic.apply_ext_intr_cfg(&[3, 0, 0, 3, 0x10, 0]),
            Err(Aic2Error::InvalidConfig(
                "nonzero IRQ_CFG DELAY_IDX delay/priority effects are unqualified"
            ))
        );
        assert_eq!(aic.irq_cfg, before);
        aic.irq_cfg[second_index] = 0;
        aic.apply_ext_intr_cfg(&[3, 0, 0, 3, 0x10, 0]).unwrap();
        assert_eq!(aic.irq_cfg[first_index], 0);
        assert_eq!(aic.irq_cfg[second_index], 0);
        let mut latch = InterruptLatch::new();
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, second.mask_clear, 1 << 3);
        write(&mut aic, &mut latch, second.software_set, 1 << 3);
        assert!(!latch.pins(0).irq && latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
        assert_eq!(
            read(&mut aic, &mut latch, 1, EVENT),
            1 << 24 | EVENT_TYPE_IRQ | 3
        );
    }

    #[test]
    fn unqualified_irq_cfg_selectors_and_delays_refuse_without_effects() {
        for version in [2, 3] {
            let (mut config, layout) = two_dies();
            config.version = version;
            config.default_cpus = 0b10;
            for die in 0..2 {
                let bank = layout.dies[die];
                let mut aic = Aic2::new_with_layout(config.clone(), layout.clone()).unwrap();
                let mut latch = InterruptLatch::new();
                write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
                write(&mut aic, &mut latch, bank.mask_clear, 1 << 3);
                write(&mut aic, &mut latch, bank.software_set, 1 << 3);
                write(
                    &mut aic,
                    &mut latch,
                    AIC2_TIMESTAMPS,
                    TIMESTAMP_ENABLE | (die as u32) << 24 | 3,
                );
                aic.set_input(
                    AicInput::new(die as u8, 3),
                    true,
                    &mut Access::new(0, 123, &mut latch),
                )
                .unwrap();
                assert!(!latch.pins(0).irq && latch.pins(1).irq);
                let before = (
                    aic.irq_cfg.clone(),
                    aic.software.clone(),
                    aic.hardware.clone(),
                    aic.mask.clone(),
                    aic.irq_level.clone(),
                    aic.refusing,
                    aic.timestamps
                        .iter()
                        .map(|t| (t.config, t.counter))
                        .collect::<Vec<_>>(),
                );
                let pins = [latch.pins(0), latch.pins(1)];
                for value in (1..=15).chain((1..=7).map(|index| index << 5)) {
                    let reason = if value & IRQ_CFG_TARGET != 0 {
                        "nonzero IRQ_CFG TARGET destination selectors are unqualified"
                    } else {
                        "nonzero IRQ_CFG DELAY_IDX delay/priority effects are unqualified"
                    };
                    assert!(matches!(
                        aic.write(bank.irq_config + 12, Width::Word, u64::from(value),
                                  &mut Access::new(0, 456, &mut latch)),
                        Err(MmioError::Unsupported { reason: actual, .. }) if actual == reason
                    ));
                    assert_eq!(
                        (
                            aic.irq_cfg.clone(),
                            aic.software.clone(),
                            aic.hardware.clone(),
                            aic.mask.clone(),
                            aic.irq_level.clone(),
                            aic.refusing,
                            aic.timestamps
                                .iter()
                                .map(|t| (t.config, t.counter))
                                .collect::<Vec<_>>()
                        ),
                        before
                    );
                    assert_eq!([latch.pins(0), latch.pins(1)], pins);
                }
                write(&mut aic, &mut latch, bank.irq_config + 12, 0);
                assert_eq!(read(&mut aic, &mut latch, 0, bank.irq_config + 12), 0);
                assert_eq!(
                    read(&mut aic, &mut latch, 1, EVENT),
                    (die as u32) << 24 | EVENT_TYPE_IRQ | 3
                );
                assert!(!latch.pins(1).irq);
            }
        }
    }

    #[test]
    fn explicit_layout_refuses_missing_overlapping_unaligned_and_overflowing_banks() {
        let (config, layout) = two_dies();
        for invalid in [
            Aic2Layout {
                max_dies: 1,
                ..layout.clone()
            },
            Aic2Layout {
                max_dies: 16,
                ..layout.clone()
            },
            Aic2Layout {
                dies: vec![],
                ..layout.clone()
            },
            Aic2Layout {
                info1: VERSION,
                ..layout.clone()
            },
            Aic2Layout {
                info3: 0x101,
                ..layout.clone()
            },
            Aic2Layout {
                info1: AIC2_TIMESTAMPS,
                ..layout.clone()
            },
            Aic2Layout {
                info3: u64::MAX - 3,
                ..layout.clone()
            },
        ] {
            assert!(Aic2::new_with_layout(config.clone(), invalid).is_err());
        }
        for offset in [layout.dies[0].mask_set, EVENT, 0x6001, u64::MAX - 3] {
            let mut invalid = layout.clone();
            invalid.dies[1].mask_set = offset;
            assert!(Aic2::new_with_layout(config.clone(), invalid).is_err());
        }
        let mut invalid = layout.clone();
        invalid.dies[0].irq_config += 4;
        assert!(Aic2::new_with_layout(config, invalid).is_err());
        assert!(Aic2DieLayout::contiguous(u64::MAX - 3, 64).is_none());
    }

    /// AICv3 as the 26A434 `aic,3` driver addresses it: the AICv2's
    /// 4096-IRQ arrays at 0x10000, `MASK_CLR` at 0x14600, the event register
    /// at the +0x40000 iBoot publishes and the timestamp slots at 0x1000.
    #[test]
    fn aic3_moves_the_per_die_arrays() {
        let v3 = |irq_config, event_offset| {
            Aic2::new(Aic2Config {
                version: 3,
                nr_irq: NR_IRQ,
                max_irq: AIC2_MAX_IRQ,
                irq_config,
                event_offset,
                timestamps: 16,
                timestamp_base: AIC3_TIMESTAMPS,
                cpus: 1,
                default_cpus: 1,
            })
        };
        let mut aic = v3(AIC3_IRQ_CFG, 0x40000).unwrap();
        assert_eq!(aic.span(), 0x40004);
        let mut latch = InterruptLatch::new();
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, 0x14600, 1 << 3);
        write(&mut aic, &mut latch, AIC3_IRQ_CFG + 4 * 3, 0);
        write(&mut aic, &mut latch, AIC3_TIMESTAMPS, TIMESTAMP_ENABLE | 3);
        aic.set_input(
            AicInput::new(0, 3),
            true,
            &mut Access::new(0, 77, &mut latch),
        )
        .unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, 0x40000), 1 << 16 | 3);
        assert_eq!(
            read(&mut aic, &mut latch, 0, AIC3_TIMESTAMPS + TIMESTAMP_LOW),
            77
        );
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            aic.read(AIC2_IRQ_CFG, Width::Word, &mut access).is_err(),
            "AICv2's array offset is unallocated"
        );
        assert!(
            aic.read(AIC2_TIMESTAMPS, Width::Word, &mut access).is_err(),
            "AICv2's timestamp offset is unallocated"
        );
        assert!(
            v3(AIC3_IRQ_CFG, EVENT).is_err(),
            "the event overlaps the arrays"
        );
        assert!(v3(CONFIG, 0x40000).is_err());
        assert!(v3(AIC3_IRQ_CFG + 2, 0x40000).is_err());
    }

    /// An M3 Ultra's AICv3 as the 26A434 driver reads it: CAP0 counts two
    /// dies (LAST_DIE 1) of NR_IRQ inputs, MAXNUMIRQ 4096 IRQs per die and
    /// MAX_DIE 2, and die 1's arrays follow die 0's at 0x4a00, so its
    /// vector 0x15bf is die 1's `MASK_CLR` word at 0x14600 + 0x4a00 + 4 * 45.
    #[test]
    fn stacked_dies_follow_one_another_at_the_die_stride() {
        let config = Aic2Config {
            version: 3,
            nr_irq: 0x93f,
            max_irq: AIC2_MAX_IRQ,
            irq_config: AIC3_IRQ_CFG,
            event_offset: 0x40000,
            timestamps: 16,
            timestamp_base: AIC3_TIMESTAMPS,
            cpus: 1,
            default_cpus: 1,
        };
        let mut aic = Aic2::stacked(config.clone(), 2).unwrap();
        let mut latch = InterruptLatch::new();
        assert_eq!(read(&mut aic, &mut latch, 0, INFO1), 1 << 24 | 0x93f);
        assert_eq!(read(&mut aic, &mut latch, 0, INFO3), 2 << 24 | 0x1000);
        let (word, bit) = position(0x5bf);
        let die1 = AIC3_IRQ_CFG + AIC2_DIE_STRIDE;
        assert_eq!(die1 + 0x4600, 0x14600 + 0x4a00);
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, die1 + 0x4600 + 4 * word as u64, bit);
        write(&mut aic, &mut latch, die1 + 4 * 0x5bf, 0);
        aic.set_input(
            AicInput::new(1, 0x5bf),
            true,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        assert_eq!(
            read(&mut aic, &mut latch, 0, 0x40000),
            1 << 24 | EVENT_TYPE_IRQ | 0x5bf
        );
        // A third die, at 0x19400, is not populated: it has no inputs and
        // no registers.
        assert!(
            aic.set_input(
                AicInput::new(2, 0),
                true,
                &mut Access::new(0, 0, &mut latch)
            )
            .is_err()
        );
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            aic.read(die1 + AIC2_DIE_STRIDE, Width::Word, &mut access)
                .is_err()
        );
        // The event register must follow the last die's arrays.
        let crowded = Aic2Config {
            event_offset: die1 + AIC2_DIE_STRIDE - 4,
            ..config
        };
        assert!(Aic2::stacked(crowded, 2).is_err());
    }
}
