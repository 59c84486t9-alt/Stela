//! Fallible PCI configuration access, independent of the owned transport.
use super::assignment;
use crate::bus::mmio::owned::Error as MappingError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFailure {
    Window,
    Address,
    PhysicalSpan,
    CacheAttribute,
    Protection,
    CpuAddress,
    Access {
        offset: u16,
        width: usize,
    },
    Mapping(MappingError),
    Ownership(assignment::Error),
    ForeignGrant,
    UnqualifiedControl,
    BusMasterSealed,
    RoutingSealed,
    Readback {
        offset: u16,
        width: usize,
        expected: u32,
        observed: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigEffect {
    /// No volatile configuration write was issued by this failed access.
    /// This does not assert that a vendor register read had no side effect.
    None,
    /// A volatile write was issued before validation failed. Keep the exact
    /// owner; this error supplies no permission to retry or roll back.
    WriteMayHaveApplied { offset: u16, width: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub reason: ConfigFailure,
    pub effect: ConfigEffect,
}
impl ConfigError {
    pub const fn before_effect(reason: ConfigFailure) -> Self {
        Self {
            reason,
            effect: ConfigEffect::None,
        }
    }
    pub const fn write_may_have_applied(offset: u16, width: u8, reason: ConfigFailure) -> Self {
        Self {
            reason,
            effect: ConfigEffect::WriteMayHaveApplied { offset, width },
        }
    }
}
impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCI configuration {:?} ({:?})", self.reason, self.effect)
    }
}
