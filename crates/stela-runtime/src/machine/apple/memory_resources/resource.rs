//! Borrowed dispatch to the actual placed memory resource, never copied state.
use super::Prepared;
use super::t6020;
use super::t8112;
use stela_contracts::bus::Access;
use stela_contracts::bus::Bus;
use stela_contracts::bus::DeviceId;
use stela_contracts::bus::Width;
use stela_engine::memory::CanonicalRamService;

pub(in crate::machine::apple) enum Resource<'a> {
    Direct(&'a Prepared),
    T8112(&'a t8112::Prepared),
    T6020(&'a t6020::Prepared),
}
pub(in crate::machine::apple) fn resource_for(bus: &Bus, device: DeviceId) -> Option<Resource<'_>> {
    bus.device::<Prepared>(device)
        .map(Resource::Direct)
        .or_else(|| bus.device::<t8112::Prepared>(device).map(Resource::T8112))
        .or_else(|| bus.device::<t6020::Prepared>(device).map(Resource::T6020))
}
impl Resource<'_> {
    pub(in crate::machine::apple) fn requires_ram_read(&self, offset: u64, width: Width) -> bool {
        match self {
            Self::Direct(owner) => owner.requires_ram_read(offset, width),
            Self::T8112(owner) => owner.requires_ram_read(offset, width),
            Self::T6020(owner) => owner.requires_ram_read(offset, width),
        }
    }
    /// # Safety
    /// The complete live canonical owner/closed producer contract of the
    /// selected resource's read_ram_drain holds throughout this operation.
    pub(in crate::machine::apple) unsafe fn read_ram_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64, &'static str> {
        match self {
            Self::Direct(owner) => unsafe { owner.read_ram_drain(offset, width, memory) },
            Self::T8112(owner) => unsafe { owner.read_ram_drain(offset, width, memory) },
            Self::T6020(owner) => unsafe { owner.read_ram_drain(offset, width, memory) },
        }
    }
    /// # Safety
    /// The selected resource's same complete live ownership contract holds
    /// through consumption; no device transfer or worker can advance meanwhile.
    pub(in crate::machine::apple) unsafe fn write_ram_drain(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        now: u64,
        memory: &CanonicalRamService<'_>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Direct(owner) => unsafe {
                owner.write_ram_drain(offset, width, value, now, memory)
            },
            Self::T8112(owner) => unsafe {
                owner.write_ram_drain(offset, width, value, now, memory)
            },
            Self::T6020(owner) => unsafe {
                owner.write_ram_drain(offset, width, value, now, memory)
            },
        }
    }
    pub(in crate::machine::apple) fn supports_pair(&self, offset: u64, bytes: u8) -> bool {
        match self {
            Self::Direct(owner) => owner.supports_pair(offset, bytes),
            Self::T8112(owner) => owner.supports_pair(offset, bytes),
            Self::T6020(_) => false,
        }
    }
    pub(in crate::machine::apple) fn read_pair_values(
        &self,
        offset: u64,
        bytes: u8,
        access: &mut Access<'_>,
    ) -> Result<[u64; 2], &'static str> {
        match self {
            Self::Direct(owner) => owner.read_pair_values(offset, bytes, access),
            Self::T8112(owner) => owner.read_pair_values(offset, bytes, access),
            Self::T6020(_) => Err("T602x paired PTD consumption has no qualified source owner"),
        }
    }
    /// Physical ownership only. This remains visible when publication effects
    /// refuse, so display overlap cannot acquire a replacement PTD owner.
    pub(in crate::machine::apple) fn publication_footprint(&self) -> (u64, u64, u64) {
        match self {
            Self::Direct(owner) => owner.publication_binding(),
            Self::T8112(owner) => owner.publication_binding(),
            Self::T6020(owner) => owner.publication_footprint(),
        }
    }
    /// A shared publication view requires the actual implemented protocol,
    /// independently of the physically owned bank's extent.
    pub(in crate::machine::apple) fn publication_binding(
        &self,
    ) -> Result<(u64, u64, u64), &'static str> {
        match self {
            Self::Direct(owner) => Ok(owner.publication_binding()),
            Self::T8112(owner) => Ok(owner.publication_binding()),
            Self::T6020(_) => Err("T602x PTD publication has no qualified source owner"),
        }
    }
    pub(in crate::machine::apple) fn display_publication_view(
        &self,
        physical: u64,
        bytes: u64,
    ) -> Result<(u64, u64, u64), &'static str> {
        match self {
            Self::Direct(owner) => owner.display_publication_view(physical, bytes),
            Self::T8112(owner) => owner.display_publication_view(physical, bytes),
            Self::T6020(_) => Err("T602x display PTD alias has no qualified source owner"),
        }
    }
    pub(in crate::machine::apple) fn locked_regions(&self) -> Option<stela_soc_data::amcc::Locked> {
        match self {
            Self::Direct(owner) => Some(owner.locked_regions()),
            Self::T8112(_) => None,
            Self::T6020(owner) => Some(owner.locked_regions()),
        }
    }
}
