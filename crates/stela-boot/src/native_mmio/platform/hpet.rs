//! Captured-HPET reservation and typed owner. Intended child of platform.
use super::*;
use crate::{
    engine::host::{RootContext, RootProcessScope},
    native_clock::hpet::Descriptor,
};
use core::mem::ManuallyDrop;
use stela_drivers::{
    bus::mmio::owned::{Mapping, ResourceId},
    platform::work::WorkError,
};

/// Original Source-owned page reservation, exact 1024-byte register view, and
/// active time-free root epoch. There is no caller-number/pointer constructor.
pub(crate) struct HpetMapping {
    descriptor: Descriptor,
    mapping: ManuallyDrop<Mapping>,
    scope: ManuallyDrop<Arc<RootProcessScope>>,
    authority: ManuallyDrop<Authority>,
    platform: ManuallyDrop<Arc<Platform>>,
    registration: Option<ResourceId>,
    mapping_retired: bool,
    retired: bool,
    closing: bool,
}
impl HpetMapping {
    pub(crate) fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    pub(crate) fn mapping(&self) -> &Mapping {
        &self.mapping
    }
    pub(crate) fn context(&self) -> &Arc<RootContext> {
        self.scope.context()
    }
    /// Pure exact process-epoch observation, including after unmap uncertainty.
    /// Do not call Mapping::check_current here: LIVE is not a retry permission.
    pub(crate) fn check_process(&self) -> Result<(), WorkError> {
        self.scope.check()
    }
    pub(crate) fn check_irq_cpu(&self) -> Result<(), WorkError> {
        if self.closing || self.mapping_retired || self.retired {
            return Err(WorkError::Closed);
        }
        self.scope.check_irq_cpu()
    }
    /// # Safety
    /// Clock/entry hooks and every raw counter/config reader/writer have stopped
    /// and drained, including failure paths. Caller has settled HPET
    /// ownership (stopping only a counter it was authorized to start). No new
    /// access may begin. Failure keeps the owner and epoch for retry.
    pub(crate) unsafe fn retire_mapping(&mut self) -> Result<(), WorkError> {
        self.check_process()?;
        if self.retired {
            return Ok(());
        }
        self.closing = true;
        if !self.mapping_retired {
            // SAFETY: caller supplies complete hardware/callback drain.
            unsafe { self.mapping.retire() }.map_err(unavailable)?;
            self.mapping_retired = true;
        }
        if let Some(id) = self.registration {
            self.authority
                .unregister_resource(id)
                .map_err(unavailable)?;
            self.registration = None;
        }
        self.retired = true;
        Ok(())
    }
}
impl Drop for HpetMapping {
    fn drop(&mut self) {
        // Any live/uncertain token permanently keeps the original root epoch
        // as well as Mapping; generic Mapping quarantine alone is insufficient.
        if !self.retired || self.check_process().is_err() {
            return;
        }
        // SAFETY: exact admitted CPU, drained explicit unmap acknowledged, then
        // resource unregistered. No native callback can use these fields again.
        unsafe {
            ManuallyDrop::drop(&mut self.mapping);
            ManuallyDrop::drop(&mut self.authority);
            ManuallyDrop::drop(&mut self.platform);
            ManuallyDrop::drop(&mut self.scope);
        }
    }
}

/// A whole-controller handoff distinct from a read-only running view.
/// Non-Clone; only the Source can mint this original owner.
pub(crate) struct ExclusiveHpet {
    mapping: HpetMapping,
}
impl ExclusiveHpet {
    pub(crate) fn into_mapping(self) -> HpetMapping {
        self.mapping
    }
}

fn unavailable<T>(_: T) -> WorkError {
    WorkError::Unavailable
}
impl ScopedSource {
    /// Inspect complete PTE/journal retirement while the permanent
    /// adopted Clock still keeps its one original typed HPET mapping.
    pub(crate) fn verify_only_hpet(&self, owner: &HpetMapping) -> Result<(), Error> {
        self.platform.check_context(self.platform.space)?;
        owner.check_process().map_err(failed)?;
        owner.mapping().check_current()?;
        if !Arc::ptr_eq(&owner.platform, &self.platform) {
            return Err(Error::OutsideResource);
        }
        let physical = owner.descriptor().registers();
        if owner.mapping().physical_span()? != physical
            || owner.mapping().attribute()? != CacheAttribute::Uncached
        {
            return Err(Error::InvalidPlatformReply);
        }
        let expected = PhysicalSpan::new(physical.start(), PAGE)?;
        let mut guard = self.platform.lock()?;
        let mappings = guard.mappings();
        let [allocation] = mappings.as_slice() else {
            return Err(Error::Busy);
        };
        if allocation.pages != 1
            || allocation.first >= ENTRIES
            || allocation.request.physical != expected
            || allocation.request.attribute != CacheAttribute::Uncached
        {
            return Err(Error::InvalidPlatformReply);
        }
        let rights = PRESENT
            | NX
            | (1 << 3)
            | (1 << 4)
            | if allocation.request.protection == Protection::ReadWrite {
                WRITABLE
            } else {
                0
            };
        for index in 0..ENTRIES {
            // SAFETY: same current source/root/held ownership and
            // bounded original LOADER_DATA aperture PT.
            let entry = unsafe { self.platform.leaf(index)?.read_volatile() };
            if index == allocation.first {
                if entry & !((1 << 5) | (1 << 6)) != (expected.start() | rights) {
                    return Err(Error::UnmapFailed);
                }
            } else if entry != 0 {
                return Err(Error::UnmapFailed);
            }
        }
        Ok(())
    }

    /// # Safety
    /// Native dispatcher has kept the original running HPET owner
    /// and the WHOLE rounded page/control-block exclusion from firmware, SMM,
    /// other drivers/CPUs, comparator/legacy/FSB/route users and independent raw
    /// aliases. No decode/reset/stop/counter-write/rate/suspend discontinuity may
    /// occur through final Clock/source drain and unmap. The kept SDT and
    /// quiet register contents alone never establish this ownership contract.
    pub(crate) unsafe fn map_running_hpet(&self) -> Result<HpetMapping, Error> {
        self.map_original_hpet(Protection::ReadOnly)
    }
    /// # Safety
    /// Post-EBS main has transferred exclusive ownership of the original
    /// complete HPET block AND rounded page, including every firmware/SMM/native
    /// timer/route/counter/config/decode writer and in-flight access. No outside
    /// owner may resume until drained retirement. This authorizes the consumer
    /// to enable only the main counter after its independent configuration checks;
    /// it grants no comparator/route takeover. SDT/EBS/configuration observations
    /// do not prove that physical handoff. Missing exclusion must refuse here.
    pub(crate) unsafe fn take_hpet(&self) -> Result<ExclusiveHpet, Error> {
        Ok(ExclusiveHpet {
            mapping: self.map_original_hpet(Protection::ReadWrite)?,
        })
    }
    fn map_original_hpet(&self, protection: Protection) -> Result<HpetMapping, Error> {
        self.platform.check_context(self.platform.space)?;
        // Parse only the source-kept original SDT, never caller bytes.
        let descriptor =
            Descriptor::from_sdt(self.platform.resources.wire.hpet()).map_err(failed)?;
        let span = descriptor.registers();
        let page = PhysicalSpan::new(span.start(), PAGE)?;
        if span.bytes() != 1024
            || !span.start().is_multiple_of(PAGE)
            || span.end() > page.end()
            || page.end() > 1u64 << self.platform.space.physical_bits
            || !self
                .platform
                .resources
                .wire
                .excludes_memory(page.start(), page.end())
        {
            return Err(Error::OutsideResource);
        }
        let pointer = self.platform.scope.load(Ordering::Acquire);
        if pointer.is_null() {
            return Err(Error::Unavailable);
        }
        // SAFETY: same CPU/process was checked BEFORE pointer load. The
        // one !Send Session owns this Arc until same-CPU IRQ-disabled removal.
        let scope = unsafe {
            Arc::increment_strong_count(pointer);
            Arc::from_raw(pointer)
        };
        scope.check().map_err(failed)?;
        let resource = Resource::new(Box::new(Backing {
            owner: self.platform.resources.clone(),
            span: page,
        }));
        let registration = self.authority.register_resource(resource.clone())?;
        let mapping =
            match self
                .authority
                .map(resource, 0, 1024, CacheAttribute::Uncached, protection)
            {
                Ok(mapping) => mapping,
                Err(error) => {
                    // An uncertain native map keeps its registry reservation.
                    // Keep the exact scope as well: no rollback success is inferred.
                    if self.authority.unregister_resource(registration).is_err() {
                        core::mem::forget(scope);
                    }
                    return Err(error);
                }
            };
        Ok(HpetMapping {
            descriptor,
            mapping: ManuallyDrop::new(mapping),
            scope: ManuallyDrop::new(scope),
            authority: ManuallyDrop::new(self.authority.clone()),
            platform: ManuallyDrop::new(self.platform.clone()),
            registration: Some(registration),
            mapping_retired: false,
            retired: false,
            closing: false,
        })
    }
}
