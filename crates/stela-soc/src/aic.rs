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
use crate::Result;
use stela_contracts::Refusal;
use stela_contracts::refuse;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aic2Error {
    InvalidConfig(Refusal),
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
    irq_level: u64,
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
            refuse!("AIC contiguous register layout overflows"),
        ))?;
        let last = layout.dies.last().ok_or(Aic2Error::InvalidConfig(refuse!(
            "an AIC has at least one die"
        )))?;
        let end = last.hardware_state + 4 * u64::from(config.max_irq / 32);
        if config.event_offset < end {
            return Err(Aic2Error::InvalidConfig(refuse!(
                "the event register must follow the per-die arrays"
            )));
        }
        Self::new_with_layout(config, layout)
    }

    /// Construct only from established capability and per-die bank facts.
    /// This supports multiple dies and AICv3's relocated capability/mask
    /// banks without assuming a layout for an unobserved generation.
    pub fn new_with_layout(config: Aic2Config, layout: Aic2Layout) -> Result<Self, Aic2Error> {
        let invalid = |reason| Err(Aic2Error::InvalidConfig(reason));
        if config.max_irq == 0 || !config.max_irq.is_multiple_of(32) {
            return invalid(refuse!("MAX_IRQ must be a nonzero multiple of 32"));
        }
        if config.nr_irq == 0 || config.nr_irq > config.max_irq {
            return invalid(refuse!("NR_IRQ must be in 1..=MAX_IRQ"));
        }
        if config.cpus == 0 || config.cpus > 64 {
            return invalid(refuse!("the CPU count must be in 1..=64"));
        }
        let all_cpus = u64::MAX >> (64 - config.cpus);
        if config.default_cpus & !all_cpus != 0 {
            return invalid(refuse!("a CPU set names a CPU beyond the CPU count"));
        }
        if config.irq_config <= CONFIG || !config.irq_config.is_multiple_of(4) {
            return invalid(refuse!("the IRQ_CFG array must be a word after CONFIG"));
        }
        if config.timestamps != 0
            && TIMESTAMP_STRIDE
                .checked_mul(config.timestamps as u64)
                .and_then(|bytes| config.timestamp_base.checked_add(bytes))
                .is_none_or(|end| end > config.irq_config)
        {
            return invalid(refuse!(
                "the timestamp slots must end before the IRQ_CFG array"
            ));
        }
        let span = layout.validate(&config).map_err(Aic2Error::InvalidConfig)?;
        // The register decoder exposes only implemented entries. Keep the
        // inter-die stride, but omit unaddressable trailing state.
        let preceding = usize::from(config.max_irq) * (layout.dies.len() - 1);
        let interrupts = preceding + usize::from(config.nr_irq);
        let words = interrupts.div_ceil(32);
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
            irq_cfg: vec![0; interrupts],
            software: vec![0; words],
            hardware: vec![0; words],
            mask: vec![u32::MAX; words],
            irq_level: 0,
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
            return Err(Aic2Error::InvalidConfig(refuse!(
                "aic-ext-intr-cfg is not a list of triples"
            )));
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

    fn check_target(target: u32) -> Result<()> {
        if target & !IRQ_CFG_TARGET != 0 {
            return Err(refuse!("IRQ_CFG TARGET has only four bits"));
        }
        if target != 0 {
            return Err(refuse!(
                "nonzero IRQ_CFG TARGET destination selectors are unqualified"
            ));
        }
        Ok(())
    }
    fn check_irq_config(value: u32) -> Result<()> {
        if value & !(IRQ_CFG_TARGET | IRQ_CFG_DELAY_IDX) != 0 {
            return Err(refuse!("AIC2 IRQ_CFG reserved field is not modeled"));
        }
        Self::check_target(value & IRQ_CFG_TARGET)?;
        if value & IRQ_CFG_DELAY_IDX != 0 {
            return Err(refuse!(
                "nonzero IRQ_CFG DELAY_IDX delay/priority effects are unqualified"
            ));
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
    fn accepting_cpus(&self) -> u64 {
        if self.enabled && self.lifecycle.clocked && !self.lifecycle.quiesced {
            self.config.default_cpus & !self.refusing
        } else {
            0
        }
    }

    fn first_pending(&self) -> Option<usize> {
        // Hardware inputs are range-checked. Bank writes exclude padding
        // independently on each die, so the lowest set bit is implemented.
        self.software
            .iter()
            .zip(&self.hardware)
            .zip(&self.mask)
            .enumerate()
            .find_map(|(word, ((software, hardware), mask))| {
                let pending = (software | hardware) & !mask;
                (pending != 0).then(|| word * 32 + pending.trailing_zeros() as usize)
            })
    }

    /// The highest-priority deliverable IRQ for `cpu`.
    fn pending_for(&self, cpu: CpuIndex) -> Option<usize> {
        if self.accepting_cpus() & 1 << cpu == 0 {
            return None;
        }
        self.first_pending()
    }

    fn update(&mut self, access: &mut Access<'_>) {
        // TARGET0 is shared by the eligible CPUs. Scan the pending bank once.
        let accepting = self.accepting_cpus();
        let level = if accepting != 0 && self.first_pending().is_some() {
            accepting
        } else {
            0
        };
        let mut changed = self.irq_level ^ level;
        self.irq_level = level;
        while changed != 0 {
            let cpu = changed.trailing_zeros() as usize;
            let bit = 1 << cpu;
            access
                .interrupts
                .set_level(Wire::Irq(cpu), level & bit != 0);
            changed ^= bit;
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
    fn read_register(&mut self, register: Register, cpu: CpuIndex) -> Result<u32> {
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
                    return Err(refuse!("event read from a CPU the AIC does not serve"));
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
    fn write_register(&mut self, register: Register, value: u32) -> Result<()> {
        match register {
            Register::Config => {
                if value & !CONFIG_ENABLE != 0 {
                    return Err(refuse!(
                        "AIC2 CONFIG fields other than ENABLE are not modeled"
                    ));
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
                    Array::HardwareState => return Err(refuse!("AIC2 HW_STATE is read-only")),
                }
            }
            Register::Version | Register::Info1 | Register::Info3 => {
                return Err(refuse!("AIC2 capability registers are read-only"));
            }
            Register::Event => return Err(refuse!("AIC2 event register is read-only")),
            Register::TimestampConfig(slot) => {
                if value & !(TIMESTAMP_ENABLE | TIMESTAMP_DIE | TIMESTAMP_IRQ) != 0 {
                    return Err(refuse!(
                        "AIC2 timestamp configuration reserved field is not modeled"
                    ));
                }
                if value & TIMESTAMP_ENABLE != 0
                    && ((value & TIMESTAMP_DIE) >> INFO_DIE_SHIFT >= self.layout.dies.len() as u32
                        || value & TIMESTAMP_IRQ >= u32::from(self.config.nr_irq))
                {
                    return Err(refuse!(
                        "AIC2 timestamp names an IRQ the model does not have"
                    ));
                }
                self.timestamps[slot].config = value;
            }
            Register::TimestampLow(_) | Register::TimestampHigh(_) => {
                return Err(refuse!("AIC2 timestamps are read-only"));
            }
        }
        Ok(())
    }
}

impl Lifecycle for Aic2 {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if proposed.reset {
            return Err(refuse!(
                "AIC physical reset and interrupt/timestamp restoration are unqualified"
            ));
        }
        if !proposed.powered {
            return Err(refuse!(
                "AIC supply loss, input wake capture and physical retention are unqualified"
            ));
        }
        if (!proposed.clocked || proposed.quiesced)
            && (self.enabled
                || self
                    .timestamps
                    .iter()
                    .any(|slot| slot.config & TIMESTAMP_ENABLE != 0))
        {
            return Err(refuse!(
                "AIC pause with IRQ delivery or timestamp capture armed has unqualified wake behavior"
            ));
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
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(fail(refuse!(
                "AIC MMIO while its physical clock is stopped is unqualified"
            )));
        }
        if width != Width::Word {
            return Err(fail(refuse!("AIC2 registers are 32-bit")));
        }
        let register = self
            .decode(offset)
            .ok_or_else(|| fail(Self::unknown_reason(offset).into()))?;
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
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Write, reason);
        if !self.lifecycle.clocked {
            return Err(fail(refuse!(
                "AIC MMIO while its physical clock is stopped is unqualified"
            )));
        }
        if self.lifecycle.quiesced {
            return Err(fail(refuse!(
                "AIC register changes while native service is quiesced are unqualified"
            )));
        }
        if width != Width::Word {
            return Err(fail(refuse!("AIC2 registers are 32-bit")));
        }
        let register = self
            .decode(offset)
            .ok_or_else(|| fail(Self::unknown_reason(offset).into()))?;
        self.write_register(register, value as u32).map_err(fail)?;
        self.update(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
