//! Owned legacy ARM commpage layout, independent of clock sampling policy.
//!
//! XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
//! osfmk/arm/cpu_capabilities.h and osfmk/arm/commpage/commpage.c.
//! Only explicitly declared fields have ABI meaning; allocation padding does not.
use crate::memory::{MemoryRegion, PublishedReadOnlyRegion};
use anyhow::Result;
use serde::Serialize;

pub const CLOCK_PROFILE_ID: &str = "darwin-arm64-legacy-clock-v1";
pub const CLOCK_DISABLED_KDEBUG_PROFILE_ID: &str = "darwin-arm64-legacy-clock-disabled-kdebug-v1";
pub const GUEST_BASE: u64 = 0xfffffc000;
pub const GUEST_BYTES: usize = 16 * 1024;
pub const TIMEBASE_OFFSET: usize = 0x88;
pub const USER_TIMEBASE: usize = 0x90;
pub const CONT_HWCLOCK: usize = 0x91;
pub const CONT_TIMEBASE: usize = 0x98;
pub const CONT_HW_TIMEBASE: usize = 0xa8;
pub const KDEBUG_ENABLE: usize = 0x100;
pub(crate) const CLOCK_FIELD_START: usize = TIMEBASE_OFFSET;
pub(crate) const CLOCK_FIELD_END: usize = CONT_HW_TIMEBASE + size_of::<u64>();
pub(crate) const CLOCK_FIELD_BYTES: usize = CLOCK_FIELD_END - CLOCK_FIELD_START;
const KDEBUG_DISABLED: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KdebugState {
    Disabled,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Configuration {
    pub kdebug: Option<KdebugState>,
}
impl Configuration {
    pub const fn profile_id(self) -> &'static str {
        match self.kdebug {
            None => CLOCK_PROFILE_ID,
            Some(KdebugState::Disabled) => CLOCK_DISABLED_KDEBUG_PROFILE_ID,
        }
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
        Ok(Self {
            mapping: PublishedReadOnlyRegion::map(GUEST_BASE, &initial)?,
            configuration,
        })
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
    fn explicit_static_field_survives_clock_publication_and_owner_collisions() -> Result<()> {
        let _guard = crate::clock::TEST_CONTEXT_LOCK.lock().unwrap();
        let configuration = Configuration {
            kdebug: Some(KdebugState::Disabled),
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
        assert_eq!(&after[..CLOCK_FIELD_START], &before[..CLOCK_FIELD_START]);
        assert_eq!(&after[CLOCK_FIELD_END..], &before[CLOCK_FIELD_END..]);
        assert!(page.read_snapshot(GUEST_BYTES, 1).is_err());
        drop(page);
        let clock_only = Page::map(&[0; CLOCK_FIELD_BYTES], Configuration::default())?;
        assert_eq!(clock_only.configuration().kdebug, None);
        Ok(())
    }
}
