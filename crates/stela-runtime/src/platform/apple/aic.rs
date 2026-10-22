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
//! the layout of a MAX_IRQ of 4096 ([`AIC2_MAX_IRQ`]), and reads INFO3's
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
//! Inferred, not documented: VER is the controller's generation (2 for
//! AICv2, 3 for AICv3), below the `aic,3` driver's 0xb topology threshold;
//! an AICv3's MAX_IRQ is NR_IRQ rounded up to a mask word; an enabled
//! timestamp slot latches the system counter at each rising edge of its
//! hardware input, and a slot reads 0 until it first latches; the reset state masks every IRQ with zero
//! configuration; `SET`/`CLR` reads return the current bits; IRQs with TARGET 0
//! go to the default CPU set, and each TARGET bit selects a CPU group that the
//! board configuration must name (the hardware group assignment is not
//! public), so an unnamed group is refused; the first CPU to read the event
//! register claims the IRQ; delay groups only affect coalescing latency, so
//! immediate delivery is a permitted timing. Across dies, the lowest die
//! number wins before the lowest IRQ number; cross-die arbitration is not
//! documented, so this is a deterministic permitted ordering.
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
//! unqualified. Software pending, current external levels, masks, routes and
//! timestamp history remain owned. Supply loss and physical reset refuse.
pub mod layout;
pub use layout::Aic2Layout;

use super::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
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
/// An AICv2's IRQs per die, which fix its per-die array layout.
pub const AIC2_MAX_IRQ: u16 = 4096;

/// The first shared timestamp slot and the distance between slots.
const TIMESTAMPS: u64 = 0x1800;
const TIMESTAMP_STRIDE: u64 = 0x10;
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
const TARGET_GROUPS: usize = 4;

/// Which AIC a board has: an AICv1 (`aic1`), whose event register is in its
/// core block, or an AICv2 or AICv3 of generation `version` with its per-die
/// arrays at `irq_config` ([`AIC2_IRQ_CFG`] or [`AIC3_IRQ_CFG`]) sized for
/// `max_irq` IRQs (NR_IRQ rounded up to a mask word when `None`), its event
/// register `event` bytes from the core block and `timestamps` shared
/// timestamp slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AicLayout {
    V1,
    V2 {
        version: u8,
        irq_config: u64,
        max_irq: Option<u16>,
        event: u64,
        timestamps: u8,
    },
}

impl AicLayout {
    /// An AICv2 whose event register is `event` bytes from its core block,
    /// with `timestamps` shared timestamp slots.
    pub const fn aic2(event: u64, timestamps: u8) -> Self {
        Self::V2 {
            version: 2,
            irq_config: AIC2_IRQ_CFG,
            max_irq: Some(AIC2_MAX_IRQ),
            event,
            timestamps,
        }
    }
    /// An AICv3 whose event register is `event` bytes from its core block.
    pub const fn aic3(event: u64) -> Self {
        Self::V2 {
            version: 3,
            irq_config: AIC3_IRQ_CFG,
            max_irq: None,
            event,
            timestamps: 0,
        }
    }
}

/// Hardware facts of one AICv2 instance. NR_IRQ and MAX_IRQ come from the
/// controller, not the ADT; the board profile must record them from the
/// real machine (m1n1 prints them as "AIC: AIC2 with 1/1 dies, N/M IRQs").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aic2Config {
    /// VERSION's VER field.
    pub version: u8,
    pub nr_irq: u16,
    /// A multiple of 32.
    pub max_irq: u16,
    /// Offset of the first die's `IRQ_CFG` array: [`AIC2_IRQ_CFG`] or
    /// [`AIC3_IRQ_CFG`].
    pub irq_config: u64,
    /// Offset of the event register from the core block: ADT
    /// `aic-iack-offset`, or DT `reg[1] - reg[0]` (0x8000 on T8112).
    pub event_offset: u64,
    /// Shared timestamp slots (ADT `#shared-timestamps`).
    pub timestamps: usize,
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
    pub fn new(config: Aic2Config) -> Result<Self, Aic2Error> {
        let layout = Aic2Layout::single(&config).ok_or(Aic2Error::InvalidConfig(
            "AIC contiguous register layout overflows",
        ))?;
        let end = config
            .irq_config
            .checked_add(4 * u64::from(config.max_irq))
            .and_then(|end| end.checked_add(20 * u64::from(config.max_irq / 32)))
            .ok_or(Aic2Error::InvalidConfig("AIC register extent overflows"))?;
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
        if config.timestamps != 0
            && TIMESTAMP_STRIDE
                .checked_mul(config.timestamps as u64)
                .and_then(|bytes| TIMESTAMPS.checked_add(bytes))
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
            self.check_target(u32::from(entry[2]))
                .map_err(Aic2Error::InvalidConfig)?;
        }
        for entry in property.as_chunks::<3>().0 {
            let index = self.input_index(Self::ext_input(entry));
            self.irq_cfg[index] = self.irq_cfg[index] & !IRQ_CFG_TARGET | u32::from(entry[2]);
        }
        Ok(())
    }

    fn ext_input(entry: &[u8; 3]) -> AicInput {
        AicInput::new(
            entry[1] >> 4,
            u16::from(entry[0]) | u16::from(entry[1] & 0xf) << 8,
        )
    }
    fn input_index(&self, input: AicInput) -> usize {
        usize::from(input.die) * usize::from(self.config.max_irq) + usize::from(input.irq)
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
            .filter(|&irq| irq % usize::from(self.config.max_irq) < usize::from(self.config.nr_irq))
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
        if (TIMESTAMPS..TIMESTAMPS + TIMESTAMP_STRIDE * self.timestamps.len() as u64)
            .contains(&offset)
        {
            let slot = ((offset - TIMESTAMPS) / TIMESTAMP_STRIDE) as usize;
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
        // All-bank preflight has already qualified this edge. Input levels,
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
    use super::layout::Aic2DieLayout;
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
            version: 2,
            nr_irq: NR_IRQ,
            max_irq: MAX_IRQ,
            irq_config: IRQ_CFG,
            event_offset: EVENT,
            timestamps: 16,
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
            TIMESTAMPS,
            TIMESTAMP_ENABLE | u32::from(UART.irq),
        );
        aic.set_input(UART, true, &mut Access::new(0, 123, &mut latch))
            .unwrap();
        write(&mut aic, &mut latch, TIMESTAMPS, 0);
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
        write(&mut aic, &mut latch, TIMESTAMPS, TIMESTAMP_ENABLE | 5);
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
            cpus: 1,
            default_cpus: 1,
            target_groups: [None; 4],
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

    /// A CPU whose SIQ_CFG_EL1 mode is 3 is sent no IRQs: one targeting
    /// both CPUs goes to the other, and one targeting it alone waits.
    #[test]
    fn a_cpu_refusing_irqs_through_siq_cfg_is_sent_none() {
        let mut latch = InterruptLatch::new();
        let mut aic = aic(2);
        write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
        write(&mut aic, &mut latch, IRQ_CFG, 0b11);
        write(&mut aic, &mut latch, MASK_CLR, 1);
        let mut access = Access::new(0, 0, &mut latch);
        aic.set_input(AicInput::new(0, 0), true, &mut access)
            .unwrap();
        aic.steer(0, true, &mut access);
        assert!(!latch.pins(0).irq && latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
        write(&mut aic, &mut latch, IRQ_CFG, 0b01);
        assert!(!latch.pins(0).irq && !latch.pins(1).irq);
        aic.steer(0, false, &mut Access::new(0, 0, &mut latch));
        assert!(latch.pins(0).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16);
        // A CPU the AIC does not serve changes nothing.
        aic.steer(5, true, &mut Access::new(0, 0, &mut latch));
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
            cpus: 2,
            default_cpus: 1,
            target_groups: [Some(1), Some(2), None, None],
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
            TIMESTAMPS,
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
            read(&mut aic, &mut latch, 0, TIMESTAMPS + TIMESTAMP_LOW),
            0x9abc_def0
        );
        assert_eq!(
            read(&mut aic, &mut latch, 0, TIMESTAMPS + TIMESTAMP_HIGH),
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
    fn firmware_routing_is_atomic_and_multi_die_targets_reach_the_selected_cpu() {
        let (config, layout) = two_dies();
        let second = layout.dies[1];
        let mut aic = Aic2::new_with_layout(config, layout).unwrap();
        assert!(aic.apply_ext_intr_cfg(&[3, 0x10, 2, 0, 0x20, 1]).is_err());
        let mut latch = InterruptLatch::new();
        assert_eq!(read(&mut aic, &mut latch, 0, second.irq_config + 12), 0);
        aic.apply_ext_intr_cfg(&[3, 0x10, 2]).unwrap();
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
                info1: TIMESTAMPS,
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

    /// AICv3 (Linux `aic3_info`, `t8122.dtsi`): the same registers with the
    /// per-die arrays at 0x10000 and, on T8122, the event register at
    /// +0x40000.
    #[test]
    fn aic3_moves_the_per_die_arrays() {
        let v3 = |irq_config, event_offset| {
            Aic2::new(Aic2Config {
                version: 3,
                nr_irq: NR_IRQ,
                max_irq: MAX_IRQ,
                irq_config,
                event_offset,
                timestamps: 0,
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
