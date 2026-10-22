//! A source update target retains actual bank identity and one startup lifetime.
use super::{Error, transport};
use crate::platform::apple::{
    bus::Access,
    ptd::{Range, transport::notifications::LocalNotifications},
};
use alloc::rc::Rc;
use core::cell::Cell;

/// Bounded native publisher capability. A later startup creates a new epoch;
/// an old cloned target cannot acquire the new lifetime via mutable context.
#[derive(Clone)]
pub struct Target {
    local: LocalNotifications,
    range: Range,
    epoch: Rc<Cell<bool>>,
}
impl Target {
    pub(super) fn new(local: LocalNotifications, range: Range, epoch: Rc<Cell<bool>>) -> Self {
        Self {
            local,
            range,
            epoch,
        }
    }
    pub fn range(&self) -> &Range {
        &self.range
    }
    pub fn owns(&self, local: &LocalNotifications) -> bool {
        local.owns(self.local.bank())
    }
    pub fn publish(&self, relative: u32, value: u64, access: &mut Access<'_>) -> Result<(), Error> {
        if !self.epoch.get() {
            return Err(Error::Contract(
                "PMP publisher lifetime retired or its native owner was abandoned",
            ));
        }
        if relative >= self.range.count {
            return Err(Error::Contract("PMP publisher exceeds its actual range"));
        }
        transport::publish(&self.local, self.range.start + relative, value, access)
    }
}
