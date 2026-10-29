//! PMU byte resources, RTC field layout and initial wall-clock metadata.
//! Register geometry and an initial timestamp grant no live PMIC/RTC service,
//! firmware execution, interrupt or physical-resource ownership.
use alloc::vec::Vec;

/// `AppleDialogSPMIPMURTC::_readConfiguration`'s event mask when the
/// DeviceTree gives none.
pub const DEFAULT_EVENT_MASK: u8 = 0x1;
/// The legacy scratchpad's extent (see the module comment).
pub const LEGACY_SCRATCH_BYTES: u16 = 0x100;
/// A legacy-scratch offset's seconds and fraction within the scratchpad.
pub const LEGACY_OFFSET_SECONDS: u16 = 0x4;
pub const LEGACY_OFFSET_FRACTION: u16 = 0x15;
pub const UPCOUNT_BYTES: u16 = 6;
pub const ALARM_BYTES: u16 = 4;
pub const OFFSET_BYTES: u16 = 6;

/// A DeviceTree-named register window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub base: u16,
    pub bytes: u16,
}
impl Window {
    pub fn contains(&self, address: u16) -> bool {
        address >= self.base && u32::from(address) < u32::from(self.base) + u32::from(self.bytes)
    }
}

/// One PMU's RTC registers, each from its `info-rtc*` property.
/// Their presence does not imply primary system-service ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtc {
    pub upcount: u16,
    pub clock_offset: ClockOffset,
    pub alarm_control: u16,
    /// `info-rtc_alarm_ctrl_en_mask`: the alarm-enable bits of the control.
    pub alarm_enable: u8,
    pub alarm_offset: u16,
    pub alarm_event: u16,
    pub irq_mask: u16,
    /// `info-rtc_alarm_event_mask`: the event register's alarm bits.
    pub event_mask: u8,
    /// `info-rtc_alarm_mask`: the IRQ mask register's alarm bits.
    pub interrupt_mask: u8,
}

/// Where `AppleDialogSPMIPMURTC` keeps the signed calendar offset in ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOffset {
    /// `info-clock_offset=<base 6>`: a six-byte little-endian register.
    Register(u16),
    /// No `info-clock_offset`: inside the legacy scratchpad at this base, the
    /// offset's seconds as four little-endian bytes at +4 and its 15-bit
    /// fraction as two bytes at +0x15 (see the module comment).
    LegacyScratch(u16),
}

impl ClockOffset {
    /// The register's base, when the offset has its own register.
    pub fn register(self) -> Option<u16> {
        match self {
            Self::Register(base) => Some(base),
            Self::LegacyScratch(_) => None,
        }
    }

    /// The seconds and fraction fields of a legacy-scratch offset.
    pub fn legacy_fields(self) -> Option<[Window; 2]> {
        let Self::LegacyScratch(base) = self else {
            return None;
        };
        Some([
            Window {
                base: base.checked_add(LEGACY_OFFSET_SECONDS)?,
                bytes: 4,
            },
            Window {
                base: base.checked_add(LEGACY_OFFSET_FRACTION)?,
                bytes: 2,
            },
        ])
    }
}

impl Rtc {
    /// Chapel, Abbey and Woodcote declare one byte for the alarm control and
    /// its event (see the module comment).
    pub fn shares_event(&self) -> bool {
        self.alarm_control == self.alarm_event
    }

    /// Every register byte the RTC owns, one window per distinct register.
    /// A legacy-scratch offset is scratch storage, not an RTC register.
    pub fn windows(&self) -> Vec<Window> {
        let mut windows = alloc::vec![
            Window {
                base: self.upcount,
                bytes: UPCOUNT_BYTES,
            },
            Window {
                base: self.alarm_control,
                bytes: 1,
            },
            Window {
                base: self.alarm_offset,
                bytes: ALARM_BYTES,
            },
            Window {
                base: self.irq_mask,
                bytes: 1,
            },
        ];
        if !self.shares_event() {
            windows.push(Window {
                base: self.alarm_event,
                bytes: 1,
            });
        }
        if let Some(base) = self.clock_offset.register() {
            windows.push(Window {
                base,
                bytes: OFFSET_BYTES,
            });
        }
        windows
    }
}

/// An outside-scratch retained-history owner, whose initial bytes the
/// placement must supply explicitly (the native placement configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retained {
    /// `info-fault_log`.
    FaultLog,
    /// `info-off2wake_source`.
    WakeSource,
}

/// Host wall time at a system counter value, for the RTC's initial offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClock {
    pub unix_seconds: u64,
    pub counter: u64,
}

pub mod configuration;
pub mod firmware;
pub mod history;
mod pmic_epoch;
pub use configuration::{Configuration, Resources};
pub use firmware::{FirmwareSram, FirmwareStartup};
pub use pmic_epoch::PmicEpoch;
/// AP mailbox register extent, independent of firmware execution.
pub const MAILBOX_BYTES: u16 = 0xb;
