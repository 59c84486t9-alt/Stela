// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stela contributors
//! Private consumer boundary pending the common root delivery adapter.
use super::Error;
use crate::bus::irq::MsiMessage;
use alloc::boxed::Box;

/// Consumed requester/root epoch and its exclusively allocated route.
/// This stays crate-private until the common native root owner supplies it.
/// # Safety
/// Binding uses only the registry's allocated route for this owner; no
/// caller BDF or numeric address creates permission. Keep the original root,
/// delivery/remapping resources and epoch through drain/release or quarantine.
/// `drain_posted_msi` completes every already-issued MSI on that bound
/// path before returning success, independently of payload IOTLB write drain,
/// FLR, delay and CPU IRR/ISR observations. Failures preserve uncertain owners.
/// Operations are bounded process-context effects, never an inferred barrier.
pub(crate) unsafe trait DeliveryOwner {
    fn bind_route(&mut self, message: MsiMessage) -> Result<(), Error>;
    /// # Safety
    /// Source is terminal, MSI/INTx and bus mastering are off, reset is
    /// complete, payload writes drained and all original resources kept.
    unsafe fn drain_posted_msi(&self) -> Result<(), Error>;
}

/// Production root completion is currently unavailable. An explicit native
/// attachment may perform I/O, but cannot release an armed route without the
/// common root delivery adapter (host-driver requirement 9.2).
/// No public constructor permits a caller to manufacture completion evidence.
pub struct MsiCompletion {
    owner: Option<Box<dyn DeliveryOwner>>,
    message: Option<MsiMessage>,
}
impl MsiCompletion {
    pub fn unavailable() -> Self {
        Self {
            owner: None,
            message: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn model(owner: Box<dyn DeliveryOwner>) -> Self {
        Self {
            owner: Some(owner),
            message: None,
        }
    }
    pub(super) fn bind_route(&mut self, message: MsiMessage) -> Result<(), Error> {
        if self.message.is_some() {
            return Err(Error::Requirement("one actual bound native MSI route"));
        }
        // Preserve the exact attempted route even if the real binding faults.
        self.message = Some(message);
        if let Some(owner) = &mut self.owner {
            owner.bind_route(message)?;
        }
        Ok(())
    }
    pub(super) unsafe fn drain(&self) -> Result<(), Error> {
        if self.message.is_none() {
            return Err(Error::Requirement("actual allocated native MSI route"));
        }
        let owner = self.owner.as_ref().ok_or(Error::Requirement(
            "actual root posted-MSI completion unavailable (9.2)",
        ))?;
        // SAFETY: caller provides terminal source/payload completion;
        // this owner independently completes the original MSI path.
        unsafe { owner.drain_posted_msi() }
    }
}
