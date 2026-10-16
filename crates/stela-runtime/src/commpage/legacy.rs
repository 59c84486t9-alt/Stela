//! The legacy ARM commpage layout (clock and tracing fields).
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

/// Raw legacy DYLD_FLAGS; unknown bits round-trip unchanged. Hardware TPRO is
/// disabled, so a guest TPRO operation stops as unsupported.
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
mod tests {
    use super::*;

    #[test]
    fn opaque_configuration_requires_admission_and_preserves_old_profile_ids() -> Result<()> {
        let old = Configuration::default();
        assert_eq!(
            serde_json::to_value(old)?,
            serde_json::json!({"kdebug": null})
        );
        assert_eq!(
            serde_json::to_value(Configuration {
                kdebug: Some(KdebugState::Disabled),
                ..old
            })?,
            serde_json::json!({"kdebug": "disabled"})
        );
        assert_eq!(old.profile_id(), CLOCK_PROFILE_ID);
        assert!(old.require_dyld_flags().is_err());
        assert_eq!(
            Configuration {
                kdebug: Some(KdebugState::Disabled),
                ..old
            }
            .profile_id(),
            CLOCK_DISABLED_KDEBUG_PROFILE_ID
        );
        for value in [0, u64::MAX, 0x800000, 0xfedcba9876543210] {
            let flags = DyldFlags {
                value,
                thread_protection: ThreadProtection::Disabled,
            };
            let configuration = Configuration {
                dyld_flags: Some(flags),
                ..old
            };
            assert_eq!(configuration.require_dyld_flags()?, flags);
            let serialized = serde_json::to_vec(&configuration)?;
            let roundtrip: serde_json::Value = serde_json::from_slice(&serialized)?;
            assert_eq!(
                roundtrip,
                serde_json::json!({
                    "kdebug": null,
                    "dyld_flags": {"value": value, "thread_protection": "disabled"}
                })
            );
            assert_eq!(configuration.profile_id(), CLOCK_DYLD_FLAGS_PROFILE_ID);
            assert_eq!(
                Configuration {
                    kdebug: Some(KdebugState::Disabled),
                    ..configuration
                }
                .profile_id(),
                CLOCK_DISABLED_KDEBUG_DYLD_FLAGS_PROFILE_ID
            );
        }
        Ok(())
    }

    #[test]
    fn explicit_static_field_survives_clock_publication_and_owner_collisions() -> Result<()> {
        let _guard = crate::clock::TEST_CONTEXT_LOCK.lock().unwrap();
        let configuration = Configuration {
            kdebug: Some(KdebugState::Disabled),
            dyld_flags: Some(DyldFlags {
                value: 0xfedcba9876543210,
                thread_protection: ThreadProtection::Disabled,
            }),
        };
        let mut page = Page::map(&[0xa5; CLOCK_FIELD_BYTES], configuration)?;
        assert_eq!(page.configuration(), configuration);
        assert_ne!(
            configuration.profile_id(),
            Configuration::default().profile_id()
        );
        assert!(Page::map(&[0; CLOCK_FIELD_BYTES], Configuration::default()).is_err());
        assert!(page.region().readable && !page.region().writable && !page.region().executable);
        let before = page.read_snapshot(0, GUEST_BYTES)?;
        page.publish_clock(&[0x5a; CLOCK_FIELD_BYTES])?;
        let after = page.read_snapshot(0, GUEST_BYTES)?;
        assert_eq!(
            &after[CLOCK_FIELD_START..CLOCK_FIELD_END],
            &[0x5a; CLOCK_FIELD_BYTES]
        );
        assert_eq!(
            &after[KDEBUG_ENABLE..KDEBUG_ENABLE + size_of::<u32>()],
            &KDEBUG_DISABLED.to_le_bytes()
        );
        assert_eq!(
            &after[DYLD_FLAGS..DYLD_FLAGS + size_of::<u64>()],
            &configuration.require_dyld_flags()?.value.to_le_bytes()
        );
        assert_eq!(&after[..CLOCK_FIELD_START], &before[..CLOCK_FIELD_START]);
        assert_eq!(&after[CLOCK_FIELD_END..], &before[CLOCK_FIELD_END..]);
        assert!(page.read_snapshot(GUEST_BYTES, 1).is_err());
        drop(page);
        let clock_only = Page::map(&[0; CLOCK_FIELD_BYTES], Configuration::default())?;
        assert_eq!(clock_only.configuration().kdebug, None);
        assert!(clock_only.configuration().require_dyld_flags().is_err());
        Ok(())
    }
}
