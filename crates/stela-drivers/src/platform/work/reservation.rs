//! Immutable continuation and admission layout; this grants no native services.
use super::{Lane, WorkError};
use core::ops::Range;

/// Bounded qualification layout, requiring sixteen genuine guarded stacks.
/// Two portal AML and two Notify continuations, one each GPE/control/Linux
/// service/foreground, and eight General tasks. It does not qualify arbitrary
/// dependency chains, IRQ producers, thread IDs or an ACPICA provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationPolicy {
    NativeFirmware16,
}
/// Independently flushed OSL workqueues. Neither queue includes ordinary AML,
/// Linux service/control work or General callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareQueue {
    Gpe,
    Notify,
}
#[cfg(target_arch = "x86_64")]
impl FirmwareQueue {
    pub(super) fn lane(self) -> Lane {
        match self {
            Self::Gpe => Lane::Gpe,
            Self::Notify => Lane::Notify,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareRole {
    Control,
    PortalAml,
    Gpe,
    Notify,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(target_arch = "x86_64"),
    allow(
        dead_code,
        reason = "only x86-64 has native continuation constructors; portable queues still use admission layout"
    )
)]
pub(super) enum Layout {
    Ordinary,
    LinuxService,
    FirmwareControl,
    NativeFirmware16,
}
impl Layout {
    pub(super) fn slots(self) -> usize {
        match self {
            Self::Ordinary | Self::LinuxService => 0,
            Self::FirmwareControl => 2,
            Self::NativeFirmware16 => 8,
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn validate(self, stacks: usize, jobs: usize) -> Result<(), WorkError> {
        let valid = match self {
            Self::Ordinary => true,
            Self::LinuxService => stacks >= 5,
            Self::FirmwareControl => stacks >= 6 && jobs >= 3,
            Self::NativeFirmware16 => stacks == 16 && jobs >= 16,
        };
        if valid {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn lane(self, index: usize) -> Lane {
        match index {
            0 => Lane::Foreground,
            1 => Lane::Notify,
            2 if self != Self::Ordinary => Lane::Service,
            3 if matches!(self, Self::FirmwareControl | Self::NativeFirmware16) => Lane::Firmware,
            4 if self == Self::NativeFirmware16 => Lane::Gpe,
            5 | 6 if self == Self::NativeFirmware16 => Lane::Portal,
            7 if self == Self::NativeFirmware16 => Lane::Notify,
            _ => Lane::General,
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn role(self, lane: Lane) -> Option<FirmwareRole> {
        match lane {
            Lane::Firmware if matches!(self, Self::FirmwareControl | Self::NativeFirmware16) => {
                Some(FirmwareRole::Control)
            }
            Lane::Portal if self == Self::NativeFirmware16 => Some(FirmwareRole::PortalAml),
            Lane::Gpe if self == Self::NativeFirmware16 => Some(FirmwareRole::Gpe),
            Lane::Notify if self == Self::NativeFirmware16 => Some(FirmwareRole::Notify),
            _ => None,
        }
    }
    /// Portal/Notify slots match the actual immutable worker cardinality.
    /// Every accepted job therefore claims a distinct idle continuation before
    /// callback/context transfer. Completion releases the slot and marks its
    /// worker Idle in one IF0 return path, without an intervening producer.
    /// Foreground has its own slot too; General traffic cannot consume it.
    /// GPE is serial and may queue into spare ordinary slots after its reserved
    /// slot; it never borrows an ordinary continuation or a portal/Notify slot.
    pub(super) fn admission(self, lane: Lane, jobs: usize) -> Result<[Range<usize>; 2], WorkError> {
        if matches!(lane, Lane::Portal | Lane::Gpe) && self != Self::NativeFirmware16 {
            return Err(WorkError::Unavailable);
        }
        let reserved = self.slots();
        if jobs < reserved {
            return Err(WorkError::Unavailable);
        }
        let start = jobs - reserved;
        let primary = match self {
            Self::NativeFirmware16 => match lane {
                Lane::Service => start..start + 1,
                Lane::Firmware => start + 1..start + 2,
                Lane::Gpe => start + 2..start + 3,
                Lane::Portal => start + 3..start + 5,
                Lane::Notify => start + 5..start + 7,
                Lane::Foreground => start + 7..jobs,
                _ => 0..start,
            },
            Self::FirmwareControl => match lane {
                Lane::Service => start..start + 1,
                Lane::Firmware => start + 1..jobs,
                _ => 0..start,
            },
            _ => 0..jobs,
        };
        let overflow = if self == Self::NativeFirmware16 && lane == Lane::Gpe {
            0..start
        } else {
            0..0
        };
        Ok([primary, overflow])
    }
}
