use super::*;
use crate::bus::pci::{ConfigEffect, ConfigError, ConfigFailure, assignment};

struct FaultConfig {
    inner: Config,
    offset: u16,
    write: bool,
    error: ConfigError,
}
impl FaultConfig {
    fn denied(&self, offset: u16, write: bool) -> Option<ConfigError> {
        (offset == self.offset && write == self.write).then_some(self.error)
    }
}
macro_rules! width {
    ($read:ident, $write:ident, $ty:ty) => {
        fn $read(&self, offset: u16) -> Result<$ty, ConfigError> {
            if let Some(error) = self.denied(offset, false) {
                return Err(error);
            }
            self.inner.$read(offset)
        }
        fn $write(&mut self, offset: u16, value: $ty) -> Result<(), ConfigError> {
            let failure = self.denied(offset, true);
            if let Some(error) = failure
                && error.effect == ConfigEffect::None
            {
                return Err(error);
            }
            self.inner.$write(offset, value)?;
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    };
}
impl ConfigSpace for FaultConfig {
    width!(read8, write8, u8);
    width!(read16, write16, u16);
    width!(read32, write32, u32);
}
fn rejected(offset: u16, write: bool, effect: ConfigEffect) -> Function<FaultConfig> {
    Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        FaultConfig {
            inner: Config {
                id: u32::from(ASMEDIA) | u32::from(ASMEDIA_FLOW_CONTROL) << 16,
                control: Cell::new(0),
                writes: Vec::new(),
                acknowledge: true,
            },
            offset,
            write,
            error: ConfigError {
                reason: ConfigFailure::Ownership(assignment::Error::Closed),
                effect,
            },
        },
    )
    .unwrap()
}
fn check_failure(function: &mut Function<FaultConfig>) {
    let expected = function.config().error;
    assert_eq!(
        after_reset(
            function,
            Clock {
                ticks_per_microsecond: 1
            }
        ),
        Err(BlockError::Config(expected))
    );
}
#[test]
fn control_read_denial_stops_before_any_mailbox_write() {
    let mut function = rejected(ASMEDIA_CONTROL, false, ConfigEffect::None);
    check_failure(&mut function);
    assert!(function.config().inner.writes.is_empty());
}
#[test]
fn rejected_first_mailbox_store_cannot_publish_the_doorbell() {
    let mut function = rejected(ASMEDIA_DATA0, true, ConfigEffect::None);
    check_failure(&mut function);
    assert!(function.config().inner.writes.is_empty());
}
#[test]
fn uncertain_applied_store_is_retained_without_retry_or_following_stores() {
    let mut function = rejected(
        ASMEDIA_DATA0,
        true,
        ConfigEffect::WriteMayHaveApplied {
            offset: ASMEDIA_DATA0,
            width: 4,
        },
    );
    check_failure(&mut function);
    assert_eq!(
        function.config().inner.writes,
        [(ASMEDIA_DATA0, ASMEDIA_WRITE_COMMAND, 4)]
    );
}
#[test]
fn successful_all_ones_is_distinct_from_transport_denial() {
    let mut function = function(true);
    function.config().control.set(u8::MAX);
    assert!(matches!(
        after_reset(
            &mut function,
            Clock {
                ticks_per_microsecond: 1
            }
        ),
        Err(BlockError::Unsupported(_))
    ));
    assert!(function.config().writes.is_empty());
}

#[test]
fn later_denial_preserves_prior_published_store() {
    let mut function = rejected(ASMEDIA_DATA1, true, ConfigEffect::None);
    let expected =
        ConfigError::write_may_have_applied(ASMEDIA_DATA0, 4, function.config().error.reason);
    assert_eq!(
        after_reset(
            &mut function,
            Clock {
                ticks_per_microsecond: 1
            }
        ),
        Err(BlockError::Config(expected))
    );
    assert_eq!(
        function.config().inner.writes,
        [(ASMEDIA_DATA0, ASMEDIA_WRITE_COMMAND, 4)]
    );
}
