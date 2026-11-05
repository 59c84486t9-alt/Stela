//! MSI routes on a platform with no remapping hardware: a message is a plain
//! write to the local APIC's window that names its CPU and vector.
use alloc::{boxed::Box, sync::Arc};
use stela_drivers::bus::irq::{
    CpuTarget, MsiMessage, Platform,
    posted_msi::{self, AllocationError, EndpointRetirement, NotificationDomain, RouteOwner},
};

/// The xAPIC message window, whose address bits 19:12 name the destination.
const MESSAGE_WINDOW: u64 = 0xfee0_0000;

/// A route owner for one requester's untranslated messages.
pub(crate) fn route_owner() -> Box<dyn RouteOwner> {
    Box::new(Direct { message: None })
}

struct Direct {
    message: Option<MsiMessage>,
}

fn check() -> Result<(), posted_msi::Error> {
    super::NativePlatform(())
        .check_process()
        .map_err(|_| posted_msi::Error::Context)
}

struct Delivery;

// SAFETY: with no remapping hardware no table or mode sits between a message
// and its local APIC, so ordinary fixed/edge delivery is always admitted.
unsafe impl NotificationDomain for Delivery {
    fn check(&self) -> Result<(), posted_msi::Error> {
        Ok(())
    }
}

// SAFETY: issued only for an unremapped requester's attachment, whose route
// therefore reaches the APIC untranslated. Allocation joins the controller's
// own reserved target and records one message; nothing stays to retire.
unsafe impl RouteOwner for Direct {
    fn allocate(&mut self, target: &CpuTarget<'_>) -> Result<MsiMessage, AllocationError> {
        check().map_err(AllocationError::Unexposed)?;
        if self.message.is_some() {
            return Err(AllocationError::Unexposed(posted_msi::Error::AlreadyBound));
        }
        if !target.belongs_to(super::CONTROLLER.identity()) {
            return Err(AllocationError::Unexposed(posted_msi::Error::Context));
        }
        target
            .check_current()
            .map_err(|_| AllocationError::Unexposed(posted_msi::Error::Context))?;
        let target = target.descriptor();
        let message = MsiMessage {
            address: MESSAGE_WINDOW | u64::from(target.destination) << 12,
            data: u32::from(target.vector),
        };
        self.message = Some(message);
        Ok(message)
    }
    fn validate(&self) -> Result<(), posted_msi::Error> {
        check()
    }
    fn notification_domain(&self) -> Result<Arc<dyn NotificationDomain>, posted_msi::Error> {
        check()?;
        Ok(Arc::new(Delivery))
    }
    unsafe fn release_endpoint(
        &mut self,
        _proof: &EndpointRetirement<'_>,
    ) -> Result<(), posted_msi::Error> {
        check()
    }
}
