// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Terminal source-stop configuration ownership, independent of IRQ/DMA drain.
use super::{Address, MsiConfigSpace, MsiError, QUARANTINED, Released};
use core::sync::atomic::Ordering;

/// The original function/root owner after verified MSI/INTx disable. This type
/// offers no programming/unmask path and proves no device/DMA completion.
/// The device-specific source still stops real engines before IRQ retirement.
pub struct DisabledMsiConfig<C: MsiConfigSpace> {
    owner: Option<Released<C>>,
    stop_attempted: bool,
}
impl<C: MsiConfigSpace> DisabledMsiConfig<C> {
    pub(super) fn new(owner: Released<C>) -> Self {
        Self {
            owner: Some(owner),
            stop_attempted: false,
        }
    }
    /// Metadata only; valid even after a real device power-down/reset.
    pub fn address(&self) -> Result<Address, MsiError> {
        Ok(self.owner.as_ref().ok_or(MsiError::Released)?.0.address)
    }
    /// Run exactly one scoped device-specific stop using the original config.
    /// Its return value is held verbatim, including an original stop error.
    /// The attempt is latched before the closure can have any effects; neither
    /// an error nor unwinding authorizes a second uncertain reset/PM sequence.
    ///
    /// # Safety
    /// Process/deferred context serializes every device/config user.
    /// The callback performs only the supported terminal BM/reset/PM or
    /// vendor-stop sequence, with bounded completion and original diagnostics.
    /// It must not replace, swap, move out, clone or duplicate the original C,
    /// retire/unmap its resources, or escape configuration/mapping ownership
    /// or raw views through the return value, captured state or other aliases.
    /// A scoped borrow alone does not prevent owned/raw escapes.
    /// It cannot re-enable MSI/MSI-X/INTx/BM, change BDF/identity/BAR assignment/root
    /// routing, or perform save/restore that republishes delivery. A
    /// supported function reset may clear config while all original resources
    /// remain held; no later device/config operation may assume the old
    /// running epoch. Callback/device sources cannot access invalidated BARs.
    /// Quiescence and posted-write/domain completion are proved independently;
    /// BM-clear or Transaction Pending alone is not that proof. All original
    /// power/root/IRQ/DMA owners remain held through failure and quarantine.
    pub unsafe fn with_device_stop<T>(
        &mut self,
        stop: impl FnOnce(&mut C) -> T,
    ) -> Result<T, MsiError> {
        let owner = self.owner.as_mut().ok_or(MsiError::Released)?;
        if self.stop_attempted {
            return Err(MsiError::StopAlreadyAttempted);
        }
        self.stop_attempted = true;
        Ok(stop(owner.0.config()))
    }
    /// Transfer the original owners without touching powered-down or
    /// reset configuration space. This does not infer stop from scoped access.
    ///
    /// # Safety
    /// The source and its DMA/posted writes are stopped/drained. The
    /// real registry has subsequently drained pending CPU vectors, callbacks
    /// and deferred/timer/reset users, and none can restart. Every mapping,
    /// cache, domain and IOTLB retirement obligation remains owned until its
    /// completion. An out-of-band stop can establish these facts without
    /// using with_device_stop; the presence of an attempt proves none of them.
    pub unsafe fn release_after_drain(&mut self) -> Result<Released<C>, MsiError> {
        self.owner.take().ok_or(MsiError::Released)
    }
}
impl<C: MsiConfigSpace> Drop for DisabledMsiConfig<C> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            core::mem::forget(owner);
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        }
    }
}
