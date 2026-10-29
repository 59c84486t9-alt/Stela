//! AIC family identity and explicit per-die register geometry.
//! Declared IRQ capacity and AP target configuration do not establish silicon
//! arbitration, affinity ownership or interrupt delivery effects.
pub mod layout;

/// The distance between consecutive dies' arrays: the contiguous arrays of
/// [`AIC2_MAX_IRQ`] IRQs ([`layout::Aic2DieLayout::contiguous`]).
pub const AIC2_DIE_STRIDE: u64 = 0x4a00;
/// The most dies the 26A434 drivers accept in INFO3's MAX_DIE (`start`
/// panics past it: "Unsupported max die count").
pub const AIC2_MAX_DIES: u8 = 8;
/// Where AICv2's per-die arrays start (Linux `AIC2_IRQ_CFG`).
pub const AIC2_IRQ_CFG: u64 = 0x2000;
/// Where AICv3's per-die arrays start (Linux `AIC3_IRQ_CFG`).
pub const AIC3_IRQ_CFG: u64 = 0x10000;
/// An AICv2's or AICv3's IRQs per die, which fix its per-die array layout.
pub const AIC2_MAX_IRQ: u16 = 4096;
/// An AICv2's first shared timestamp slot (`AppleInterruptControllerV2`).
pub const AIC2_TIMESTAMPS: u64 = 0x1800;
/// An AICv3's first shared timestamp slot (ADT `pubstampcfg0-offset`).
pub const AIC3_TIMESTAMPS: u64 = 0x1000;
pub const VERSION: u64 = 0x0000;
pub const INFO1: u64 = 0x0004;
pub const INFO3: u64 = 0x000c;
pub const CONFIG: u64 = 0x0014;
/// The distance between shared timestamp slots.
pub const TIMESTAMP_STRIDE: u64 = 0x10;
pub const AIC1_MAX_IRQ: u16 = 0x400;
pub const AIC1_EVENT: u64 = 0x2004;

/// Which AIC a board has: an AICv1 (`aic1`), whose event register is in its
/// core block, or an AICv2 or AICv3 of generation `version` with its per-die
/// arrays at `irq_config` ([`AIC2_IRQ_CFG`] or [`AIC3_IRQ_CFG`]) sized for
/// `max_irq` IRQs ([`AIC2_MAX_IRQ`] for both), its event
/// register `event` bytes from the core block and `timestamps` shared
/// timestamp slots from `timestamp_base` ([`AIC2_TIMESTAMPS`] or
/// [`AIC3_TIMESTAMPS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AicLayout {
    V1,
    V2 {
        version: u8,
        irq_config: u64,
        max_irq: u16,
        event: u64,
        timestamps: u8,
        timestamp_base: u64,
        /// Populated dies, each with its own arrays [`AIC2_DIE_STRIDE`]
        /// after the previous die's.
        dies: u8,
    },
}

impl AicLayout {
    /// An AICv2 whose event register is `event` bytes from its core block,
    /// with `timestamps` shared timestamp slots.
    pub const fn aic2(event: u64, timestamps: u8) -> Self {
        Self::V2 {
            version: 2,
            irq_config: AIC2_IRQ_CFG,
            max_irq: AIC2_MAX_IRQ,
            event,
            timestamps,
            timestamp_base: AIC2_TIMESTAMPS,
            dies: 1,
        }
    }
    /// An AICv3 whose event register is `event` bytes from its core block,
    /// with `timestamps` shared timestamp slots.
    pub const fn aic3(event: u64, timestamps: u8) -> Self {
        Self::V2 {
            version: 3,
            irq_config: AIC3_IRQ_CFG,
            max_irq: AIC2_MAX_IRQ,
            event,
            timestamps,
            timestamp_base: AIC3_TIMESTAMPS,
            dies: 1,
        }
    }
    /// This layout with `dies` populated dies; an AICv1 has one.
    pub const fn with_dies(self, dies: u8) -> Self {
        match self {
            Self::V1 => Self::V1,
            Self::V2 {
                version,
                irq_config,
                max_irq,
                event,
                timestamps,
                timestamp_base,
                dies: _,
            } => Self::V2 {
                version,
                irq_config,
                max_irq,
                event,
                timestamps,
                timestamp_base,
                dies,
            },
        }
    }
    /// The IRQs each die's arrays hold, which split a vector into its die
    /// and IRQ.
    pub const fn max_irq(self) -> u16 {
        match self {
            Self::V1 => AIC1_MAX_IRQ,
            Self::V2 { max_irq, .. } => max_irq,
        }
    }
    /// The populated dies.
    pub const fn dies(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 { dies, .. } => dies,
        }
    }
}

/// Hardware facts of one AICv2 instance. NR_IRQ and MAX_IRQ come from the
/// controller, not the ADT (m1n1 prints them as "AIC: AIC2 with 1/1 dies,
/// N/M IRQs"); no 26A434 ADT or firmware states NR_IRQ, so a board supplies
/// the inputs its DeviceTree wires (`machine::soc::board`).
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
    /// Offset of the first timestamp slot: [`AIC2_TIMESTAMPS`] or
    /// [`AIC3_TIMESTAMPS`].
    pub timestamp_base: u64,
    pub cpus: usize,
    /// Software-configured AP eligible CPUs for TARGET 0, as a bit mask.
    /// This roster does not establish silicon arbitration or physical affinity.
    pub default_cpus: u64,
}
