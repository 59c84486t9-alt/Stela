//! Production HPET ownership through the shared native resource registry.
//! The immutable CPU/root pin survives only the checked RAM ownership join;
//! this owner grants no absent-RAM or mutable root-publication permission.
use super::*;
use crate::{engine::host::RootIdentity, native_clock::hpet::Descriptor};
use core::mem::ManuallyDrop;
use stela_drivers::{
    bus::mmio::owned::{Mapping, ResourceId},
    platform::work::WorkError,
};

pub(crate) struct HpetMapping {
    descriptor: Descriptor,
    mapping: ManuallyDrop<Option<Mapping>>,
    identity: ManuallyDrop<Arc<RootIdentity>>,
    authority: ManuallyDrop<Authority>,
    platform: ManuallyDrop<Arc<Platform>>,
    registration: Option<ResourceId>,
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
        self.retired = true;
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
        let resource = Resource::new(Box::new(Backing {
            owner: self.platform.captured.clone(),
            span: page,
            kind: ResourceKind::Registers,
        }));
        let registration = self
            .authority
            .register_resource(resource.clone())
            .map_err(|refusal| refusal.error)?;
        // Keep every original owner BEFORE an alias/PTE effect. Constructor
        // errors can then quarantine the same real identity/resource bundle.
        let mut owned = HpetMapping {
            descriptor,
            mapping: ManuallyDrop::new(None),
            identity: ManuallyDrop::new(identity),
            authority: ManuallyDrop::new(self.authority.clone()),
            platform: ManuallyDrop::new(self.platform.clone()),
            registration: Some(registration),
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
