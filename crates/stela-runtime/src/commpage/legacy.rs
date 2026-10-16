//! Owned legacy ARM commpage layout, independent of clock sampling policy.
//!
//! XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
//! osfmk/arm/cpu_capabilities.h and osfmk/arm/commpage/commpage.c.
//! Only explicitly declared fields have ABI meaning; allocation padding does not.
use crate::memory::{MemoryRegion, PublishedReadOnlyRegion};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::{Context, Result};
use serde::Serialize;

pub const CLOCK_PROFILE_ID: &str = "darwin-arm64-legacy-clock-v1";
pub const CLOCK_DISABLED_KDEBUG_PROFILE_ID: &str = "darwin-arm64-legacy-clock-disabled-kdebug-v1";
pub const CLOCK_DYLD_FLAGS_PROFILE_ID: &str =
    "darwin-arm64-legacy-clock-opaque-dyld-flags-disabled-tpro-v1";
pub const CLOCK_DISABLED_KDEBUG_DYLD_FLAGS_PROFILE_ID: &str =
    "darwin-arm64-legacy-clock-disabled-kdebug-opaque-dyld-flags-disabled-tpro-v1";
pub const GUEST_BASE: u64 = 0xfffffc000;
pub const GUEST_BYTES: usize = 16 * 1024;
pub const TIMEBASE_OFFSET: usize = 0x88;
pub const USER_TIMEBASE: usize = 0x90;
pub const CONT_HWCLOCK: usize = 0x91;
pub const CONT_TIMEBASE: usize = 0x98;
pub const CONT_HW_TIMEBASE: usize = 0xa8;
pub const KDEBUG_ENABLE: usize = 0x100;
pub const DYLD_FLAGS: usize = 0x160;
pub(crate) const CLOCK_FIELD_START: usize = TIMEBASE_OFFSET;
pub(crate) const CLOCK_FIELD_END: usize = CONT_HW_TIMEBASE + size_of::<u64>();
pub(crate) const CLOCK_FIELD_BYTES: usize = CLOCK_FIELD_END - CLOCK_FIELD_START;
const KDEBUG_DISABLED: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KdebugState {
    Disabled,
}

/// A process-profile declaration, independent of the opaque flags' bit values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadProtection {
    Disabled,
}

/// Raw legacy DYLD_FLAGS. Unknown bits round-trip without invented semantics.
/// The supplied platform profile explicitly disables hardware TPRO; a guest
/// entering a TPRO operation still reaches an unsupported architectural boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DyldFlags {
    pub value: u64,
    pub thread_protection: ThreadProtection,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Configuration {
    pub kdebug: Option<KdebugState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dyld_flags: Option<DyldFlags>,
}
impl Configuration {
    pub const fn profile_id(self) -> &'static str {
        match (self.kdebug, self.dyld_flags) {
            (None, None) => CLOCK_PROFILE_ID,
            (Some(KdebugState::Disabled), None) => CLOCK_DISABLED_KDEBUG_PROFILE_ID,
            (None, Some(_)) => CLOCK_DYLD_FLAGS_PROFILE_ID,
            (Some(KdebugState::Disabled), Some(_)) => CLOCK_DISABLED_KDEBUG_DYLD_FLAGS_PROFILE_ID,
        }
    }

    /// Admit a continuation requiring this field without treating zero padding
    /// as a supplied platform value. Direct RAM does not trap padding reads.
    pub fn require_dyld_flags(self) -> Result<DyldFlags> {
        self.dyld_flags
            .context("legacy DYLD_FLAGS has no declared process value")
    }
}

/// One read-only guest page and private publication alias. It exposes no host
/// pointer; the clock may publish only its fixed field interval.
pub(crate) struct Page {
    mapping: PublishedReadOnlyRegion,
    configuration: Configuration,
}
impl Page {
    pub(crate) fn map(
        clock_fields: &[u8; CLOCK_FIELD_BYTES],
        configuration: Configuration,
    ) -> Result<Self> {
        let mut initial = vec![0; GUEST_BYTES];
        initial[CLOCK_FIELD_START..CLOCK_FIELD_END].copy_from_slice(clock_fields);
        if configuration.kdebug == Some(KdebugState::Disabled) {
            initial[KDEBUG_ENABLE..KDEBUG_ENABLE + size_of::<u32>()]
                .copy_from_slice(&KDEBUG_DISABLED.to_le_bytes());
        }
        if let Some(flags) = configuration.dyld_flags {
            initial[DYLD_FLAGS..DYLD_FLAGS + size_of::<u64>()]
                .copy_from_slice(&flags.value.to_le_bytes());
        }
        Ok(Self {
            mapping: PublishedReadOnlyRegion::map(GUEST_BASE, &initial)?,
            configuration,
        })
    }
    pub(crate) fn shared_memory_participant(
        &mut self,
        address_space: u64,
    ) -> crate::memory::SharedMemoryParticipant<'_> {
        crate::memory::SharedMemoryParticipant::published(&mut self.mapping, address_space)
    }

    pub(crate) fn check_execution_thread<P: crate::memory::domain::DataPolicy>(
        &self,
        thread: &crate::memory::domain::MemoryThread<P>,
    ) -> Result<(), stela_compiler::context::memory::MemoryStatus> {
        self.mapping.check_execution_thread(thread)
    }

    pub(crate) fn configuration(&self) -> Configuration {
        self.configuration
    }
    pub(crate) fn region(&self) -> &MemoryRegion {
        self.mapping.region()
    }
    pub(crate) fn read_snapshot(&self, offset: usize, bytes: usize) -> Result<Vec<u8>> {
        self.mapping.read_snapshot(offset, bytes)
    }
    pub(crate) fn publish_clock(&mut self, fields: &[u8; CLOCK_FIELD_BYTES]) -> Result<()> {
        self.mapping.publish(CLOCK_FIELD_START, fields)
    }
}

#[cfg(test)]
mod tests;
