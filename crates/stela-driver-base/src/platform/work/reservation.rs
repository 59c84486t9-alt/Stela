//! Immutable continuation and admission layout; this grants no native services.
use super::{Lane, WorkError};
use core::ops::Range;

/// Bounded validation layout, requiring sixteen guarded stacks.
/// Two portal AML and two Notify continuations, one each GPE/control/Linux
/// service/foreground, and eight General tasks. It does not check arbitrary
/// dependency chains, IRQ producers, thread IDs or an ACPICA provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationPolicy {
    NativeFirmware16,
    /// Production's 32 stacks: the same 8 roles and 24 General workers.
    /// Requires mapped owners.
    NativeFirmware32Protected {
        gpe: GpeQueueBudget,
    },
    /// Same sixteen stack roles, with independently reserved pending GPE jobs.
    NativeFirmware16Protected {
        gpe: GpeQueueBudget,
    },
}
/// Preallocated GPE admission budget: one active job plus protected pending jobs.
/// This is a resource bound, not SCI synchronization or a provider capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpeQueueBudget {
    pending: usize,
}
impl GpeQueueBudget {
    /// Bounded validation minimum: one active and one protected pending job.
    pub const QUALIFICATION: Self = Self { pending: 1 };

    pub fn with_pending(pending: usize) -> Result<Self, WorkError> {
        if pending == 0 {
            return Err(WorkError::Unavailable);
        }
        pending.checked_add(16).ok_or(WorkError::Exhausted)?;
        Ok(Self { pending })
    }
    pub const fn protected_pending(self) -> usize {
        self.pending
    }
    pub const fn total_jobs(self) -> usize {
        self.pending + 1
    }
}
#[cfg(target_arch = "x86_64")]
impl ReservationPolicy {
    pub(super) fn layout(self) -> Layout {
        match self {
            Self::NativeFirmware16 => Layout::NativeFirmware16,
            Self::NativeFirmware16Protected { gpe } => Layout::NativeFirmware16Protected(gpe),
            Self::NativeFirmware32Protected { gpe } => Layout::NativeFirmware32Protected(gpe),
        }
    }
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
    NativeFirmware16Protected(GpeQueueBudget),
    NativeFirmware32Protected(GpeQueueBudget),
}
impl Layout {
    pub(super) fn firmware_roles(self) -> bool {
        matches!(
            self,
            Self::NativeFirmware16
                | Self::NativeFirmware16Protected(_)
                | Self::NativeFirmware32Protected(_)
        )
    }
    pub(super) fn protected_gpe(self) -> Option<GpeQueueBudget> {
        match self {
            Self::NativeFirmware16Protected(gpe) | Self::NativeFirmware32Protected(gpe) => {
                Some(gpe)
            }
            _ => None,
        }
    }
    fn pending_gpe(self) -> usize {
        self.protected_gpe()
            .map_or(0, GpeQueueBudget::protected_pending)
    }
    pub(super) fn slots(self) -> usize {
        match self {
            Self::Ordinary | Self::LinuxService => 0,
            Self::FirmwareControl => 2,
            Self::NativeFirmware16 => 8,
            Self::NativeFirmware16Protected(gpe) | Self::NativeFirmware32Protected(gpe) => {
                8 + gpe.protected_pending()
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn stack_limit(self) -> usize {
        if matches!(self, Self::NativeFirmware32Protected(_)) {
            super::MAX_CONTINUATIONS
        } else {
            16
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn validate(self, stacks: usize, jobs: usize) -> Result<(), WorkError> {
        let valid = match self {
            Self::Ordinary => true,
            Self::LinuxService => stacks >= 5,
            Self::FirmwareControl => stacks >= 6 && jobs >= 3,
            Self::NativeFirmware16 => stacks == 16 && jobs >= 16,
            Self::NativeFirmware16Protected(gpe) => {
                stacks == 16 && jobs >= 16 + gpe.protected_pending()
            }
            Self::NativeFirmware32Protected(gpe) => {
                let minimum = 32usize
                    .checked_add(gpe.protected_pending())
                    .ok_or(WorkError::Exhausted)?;
                stacks == 32 && jobs >= minimum
            }
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
            3 if self == Self::FirmwareControl || self.firmware_roles() => Lane::Firmware,
            4 if self.firmware_roles() => Lane::Gpe,
            5 | 6 if self.firmware_roles() => Lane::Portal,
            7 if self.firmware_roles() => Lane::Notify,
            _ => Lane::General,
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn role(self, lane: Lane) -> Option<FirmwareRole> {
        match lane {
            Lane::Firmware if self == Self::FirmwareControl || self.firmware_roles() => {
                Some(FirmwareRole::Control)
            }
            Lane::Portal if self.firmware_roles() => Some(FirmwareRole::PortalAml),
            Lane::Gpe if self.firmware_roles() => Some(FirmwareRole::Gpe),
            Lane::Notify if self.firmware_roles() => Some(FirmwareRole::Notify),
            _ => None,
        }
    }
    /// Portal/Notify slots match the immutable worker cardinality.
    /// Every accepted job therefore claims a distinct idle continuation before
    /// callback/context transfer. Completion releases the slot and marks its
    /// worker Idle in one IF0 return path, without an intervening producer.
    /// Foreground has its own slot too; General traffic cannot consume it.
    /// GPE is serial. The original Native16 policy may use spare ordinary job
    /// slots; the protected policy uses only its named fixed GPE budget. Neither
    /// borrows an ordinary continuation or a portal/Notify job slot.
    pub(super) fn admission(self, lane: Lane, jobs: usize) -> Result<[Range<usize>; 2], WorkError> {
        if matches!(lane, Lane::Portal | Lane::Gpe) && !self.firmware_roles() {
            return Err(WorkError::Unavailable);
        }
        let reserved = self.slots();
        if jobs < reserved {
            return Err(WorkError::Unavailable);
        }
        let start = jobs - reserved;
        let primary = match self {
            Self::NativeFirmware16
            | Self::NativeFirmware16Protected(_)
            | Self::NativeFirmware32Protected(_) => match lane {
                Lane::Service => start..start + 1,
                Lane::Firmware => start + 1..start + 2,
                Lane::Gpe => start + 2..start + 3 + self.pending_gpe(),
                Lane::Portal => start + 3 + self.pending_gpe()..start + 5 + self.pending_gpe(),
                Lane::Notify => start + 5 + self.pending_gpe()..start + 7 + self.pending_gpe(),
                Lane::Foreground => start + 7 + self.pending_gpe()..jobs,
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
