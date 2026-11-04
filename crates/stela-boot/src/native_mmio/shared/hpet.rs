//! Production HPET ownership through the shared native resource registry.
//! The immutable CPU/root pin survives only the checked RAM ownership join;
//! this owner grants no absent-RAM or mutable root-publication permission.
use super::*;
use crate::{
    engine::host::RootIdentity,
    native_clock::{Prepared, hpet::Descriptor},
};
use alloc::rc::Rc;
use core::mem::ManuallyDrop;
use stela_contracts::refuse;
use stela_drivers::{
    bus::{
        mmio::owned::{Mapping, ResourceId},
        pci::power::Timer,
    },
    platform::work::WorkError,
};

pub(crate) struct HpetMapping {
    descriptor: Descriptor,
    mapping: ManuallyDrop<Option<Mapping>>,
    identity: ManuallyDrop<Arc<RootIdentity>>,
    authority: ManuallyDrop<Authority>,
    platform: ManuallyDrop<Arc<Platform>>,
    registration: Option<ResourceId>,
    admission: Option<AdmissionClose>,
    mapping_retired: bool,
    closing: bool,
    retired: bool,
}
impl HpetMapping {
    pub(crate) fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    pub(crate) fn identity(&self) -> &Arc<RootIdentity> {
        &self.identity
    }
    pub(crate) fn mapping(&self) -> Result<&Mapping, WorkError> {
        if self.closing || self.retired {
            return Err(WorkError::Closed);
        }
        self.mapping.as_ref().ok_or(WorkError::Unavailable)
    }
    pub(crate) fn check_process(&self) -> Result<(), WorkError> {
        self.identity.check_dispatch()?;
        self.platform
            .check_context(self.platform.space)
            .map_err(unavailable)
    }
    pub(crate) fn check_irq_cpu(&self) -> Result<(), WorkError> {
        if self.closing || self.mapping_retired || self.retired {
            return Err(WorkError::Closed);
        }
        self.identity.check_irq_cpu()
    }
    /// # Safety
    /// Every real counter/configuration reader and callback has stopped and
    /// drained under this CPU/root owner; no future entry can begin.
    /// Counter configuration has been restored only by its authorized owner.
    /// On failure keep this whole object; neither resource nor identity may
    /// be reused because the mapping's metadata became inaccessible.
    pub(crate) unsafe fn retire_mapping(&mut self) -> Result<(), WorkError> {
        self.check_process()?;
        if self.retired {
            return Ok(());
        }
        self.admission.as_ref().ok_or(WorkError::Closed)?.close();
        self.closing = true;
        if !self.mapping_retired {
            if let Some(mapping) = self.mapping.as_mut() {
                // SAFETY: caller supplies real complete source/callback drain;
                // this is the original mapping, on its checked process CPU.
                unsafe { mapping.retire() }.map_err(unavailable)?;
            }
            self.mapping_retired = true;
        }
        if let Some(id) = self.registration {
            self.authority
                .unregister_resource(id)
                .map_err(unavailable)?;
            self.registration = None;
        }
        self.admission.take().ok_or(WorkError::Closed)?.dismiss();
        self.retired = true;
        self.platform
            .captured
            .hpet_unregistered
            .store(true, Ordering::Release);
        Ok(())
    }
}
impl Drop for HpetMapping {
    fn drop(&mut self) {
        if !self.retired || self.check_process().is_err() {
            return;
        }
        // SAFETY: explicit acknowledged unmap/resource retirement and
        // CPU/root exclusion above. No raw counter reader can remain. A live
        // or uncertain owner instead keeps every field permanently.
        unsafe {
            ManuallyDrop::drop(&mut self.mapping);
            ManuallyDrop::drop(&mut self.authority);
            ManuallyDrop::drop(&mut self.platform);
            ManuallyDrop::drop(&mut self.identity);
        }
    }
}
/// Non-Clone whole-controller grant; only the production Source mints it.
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

impl Source {
    /// # Safety
    /// The BSP owns the complete captured HPET block and rounded page through
    /// shutdown. Firmware, SMM and other controller users have stopped, with
    /// all earlier accesses drained and no future comparator, route, reset or
    /// decode changes. The source and root outlive every retained PCI timer.
    pub(crate) unsafe fn install_pci_clock(&self) -> crate::Result<()> {
        if self.pci_clock.get().is_some() {
            return Err(refuse!("the native PCI clock is already retained"));
        }
        // SAFETY: caller provides the whole-controller handoff and the
        // original root identity is the same one that activated this Source.
        let owner = unsafe { self.take_hpet(self.identity.clone()) }
            .map_err(|error| refuse!("PCI HPET handoff: {error}", ?error))?;
        let prepared = Prepared::exclusive_native_hpet(owner)
            .map_err(|error| refuse!("PCI HPET counter: {error}", ?error))?;
        // This keeps the physical owner even if a later context or power
        // observation refuses a timer. The mount has no live device teardown.
        self.pci_clock
            .set(prepared)
            .map_err(|_| refuse!("the native PCI clock is already retained"))
    }

    pub(crate) fn pci_minimum(&self) -> Result<Rc<dyn Timer>, WorkError> {
        self.identity.check_dispatch()?;
        self.pci_clock
            .get()
            .ok_or(WorkError::Unavailable)?
            .pci_minimum()
    }

    /// Reclaim the original controller only after native unmap and resource
    /// withdrawal acknowledged, and all independent backing pins have joined.
    pub(crate) fn join_hpet(&self) -> Result<(), Error> {
        self.identity.check_dispatch().map_err(failed)?;
        let mut slot = self
            .hpet_assignment
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?;
        if slot.is_some()
            && !self
                .platform
                .captured
                .hpet_unregistered
                .load(Ordering::Acquire)
        {
            return Err(Error::Busy);
        }
        if let Some(previous) = slot.take()
            && let Err(refusal) = previous.into_original()
        {
            *slot = Some(refusal.owner);
            return Err(Error::Assignment(refusal.error));
        }
        Ok(())
    }

    /// # Safety
    /// The post-EBS BSP dispatcher owns this entire original captured
    /// controller and rounded page, including every firmware/SMM/native route,
    /// comparator, legacy-replacement, reset, decode and counter writer. No
    /// outside actor may resume until acknowledged final drain/unmap. A table,
    /// EBS observation or quiet configuration alone does not supply this grant.
    /// RootIdentity is this same real HostOwner; controls and all root/window
    /// mappings stay held through pause, RAM adoption and quarantine.
    pub(crate) unsafe fn take_hpet(
        &self,
        identity: Arc<RootIdentity>,
    ) -> Result<ExclusiveHpet, Error> {
        identity.check_dispatch().map_err(failed)?;
        // Source was activated by this original HostOwner. Its host
        // root differs from the loader window root, and RestoreRoot can be
        // active here; comparing their numeric CR3s would reject a valid owner.
        // Identity pointer equality preserves the captured owner instead.
        if !Arc::ptr_eq(&identity, &self.identity) {
            return Err(Error::Unavailable);
        }
        self.platform.check_context(self.platform.space)?;
        let descriptor = Descriptor::from_sdt(self.platform.wire().hpet()).map_err(failed)?;
        let span = descriptor.registers();
        let page = PhysicalSpan::new(span.start(), PAGE)?;
        if span.bytes() != 1024
            || !span.start().is_multiple_of(PAGE)
            || span.end() > page.end()
            || page.end() > (1u64 << self.platform.space.physical_bits)
            || !self
                .platform
                .wire()
                .excludes_memory(page.start(), page.end())
        {
            return Err(Error::OutsideResource);
        }
        self.join_hpet()?;
        let mut slot = self
            .hpet_assignment
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?;
        let (resource, registration, assignment) =
            self.register_reservation(page, ResourceKind::Registers)?;
        let admission = assignment.admission_close();
        *slot = Some(assignment);
        self.platform
            .captured
            .hpet_unregistered
            .store(false, Ordering::Release);
        drop(slot);
        // Keep every original owner BEFORE an alias/PTE effect. Constructor
        // errors can then quarantine the same real identity/resource bundle.
        let mut owned = HpetMapping {
            descriptor,
            mapping: ManuallyDrop::new(None),
            identity: ManuallyDrop::new(identity),
            authority: ManuallyDrop::new(self.authority.clone()),
            platform: ManuallyDrop::new(self.platform.clone()),
            registration: Some(registration),
            admission: Some(admission),
            mapping_retired: false,
            closing: false,
            retired: false,
        };
        match self.authority.map(
            resource,
            0,
            1024,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        ) {
            Ok(mapping) => {
                *owned.mapping = Some(mapping);
                Ok(ExclusiveHpet { mapping: owned })
            }
            Err(error) => {
                // SAFETY: no counter/IRQ/consumer was published and no Mapping
                // escaped this constructor. A registry-held uncertain map
                // prevents unregistering, so the whole bundle stays held.
                let _ = unsafe { owned.retire_mapping() };
                Err(error)
            }
        }
    }
}
