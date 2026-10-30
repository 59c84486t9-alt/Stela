//! Source-placed T8112 DCS/PTD composition, independent of AMCC lock ownership.
//!
//! 26A434 J473 KC SHA256 06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d:
//! start file 0x2efac98..0x2efacf0 reads eight channels at stride 0x400000;
//! _dcsWriteQueueFlush file 0x2efde44..0x2efdf14 consumes the low16 clear at +0xa40.
//! t8112pmp SHA256 b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! files 0x355f8/0x457f8 check 256 implemented PTD entries and 16 local routes.
//! Construction initializes declared software backing, never hardware readiness,
//! native PMP services, DVFS completion or an AP AIC wire. The PMP's PTD duties
//! the drivers wait for are modeled behaviorally (`pmp::duties`).
use super::dcs::NativeDcs;
use crate::Result;
use crate::dcs::native::ChannelProgress;
pub use crate::dcs::native::{CHANNEL_STRIDE, CHANNELS, ChannelConfiguration};
use crate::pmp::duties::Duties;
use stela_contracts::refuse;
use stela_soc_data::board::MemoryCache;

use crate::ptd::Ptd;
#[cfg(test)]
use crate::ptd::transport::IRQ_STATUS;
use crate::ptd::transport::notifications::LocalNotifications;
use crate::ptd::transport::notifications::NativeProfile;
use alloc::{sync::Arc, vec::Vec};
use stela_contracts::bus::Access;
use stela_contracts::bus::Direction;
use stela_contracts::bus::Lifecycle;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::MmioDevice;
use stela_contracts::bus::MmioError;
use stela_contracts::bus::Width;
use stela_contracts::bus::refuse;
use stela_contracts::refusal::Within;
use stela_engine::memory::CanonicalRamService;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::ptd::Geometry;

const DCS_BYTES: u64 = CHANNEL_STRIDE * CHANNELS as u64;
const PTD_OFFSET: u64 = DCS_BYTES;
const PROFILE: NativeProfile = NativeProfile::T8112;
const ALIAS_ENTRIES: usize = 2048;

pub mod amcc;
pub mod cache;

/// One DCS frontend and one publication bank with immutable source placement.
/// AMCC locks/cache policy remain separately owned; this is no mount-admission
/// token and provides no successful configuration/refresh/counter/PMP backend.
pub struct Prepared {
    descriptor: MemoryCache,
    ram: Arc<RegisteredSystemRam>,
    dcs: NativeDcs,
    ptd: Ptd,
    local: LocalNotifications,
    duties: Option<Duties>,
}
impl Prepared {
    /// Explicit software initialization before admitting any guest publisher.
    /// Configuration/lifecycle words are caller-declared resource inputs, not
    /// inferred Apple reset observations or copied source requests.
    pub fn initialized(
        descriptor: MemoryCache,
        configuration: Vec<ChannelConfiguration>,
        lifecycle: LifecycleState,
        ram: Arc<RegisteredSystemRam>,
    ) -> Result<Self> {
        let (physical, bytes, channels) = descriptor.channels;
        let geometry = Geometry::new(
            (descriptor.ptd.physical, stela_soc_data::ptd::PTD_BYTES),
            descriptor.ptd_updates,
        )?;
        if channels != CHANNELS || bytes != DCS_BYTES || !physical.is_multiple_of(CHANNEL_STRIDE) {
            return Err(refuse!(
                "T8112 DCS placement is not eight complete source-stride channels"
            ));
        }
        if geometry.entries() != ALIAS_ENTRIES || descriptor.ptd_entries != geometry.entries() {
            return Err(refuse!(
                "T8112 PTD physical capacity differs from its source update alias"
            ));
        }
        if descriptor.ptd.ranges.is_empty()
            || descriptor.ptd.ranges.len() != descriptor.ptd.interrupts.len()
        {
            return Err(refuse!(
                "T8112 PTD ranges omit their original interrupt resources"
            ));
        }
        super::cold::check_mmio(
            &ram,
            &[
                (physical, bytes),
                (descriptor.ptd.physical, stela_soc_data::ptd::PTD_BYTES),
            ],
        )
        .within(|| refuse!("T8112 DCS/PTD placement"))?;
        let dcs = NativeDcs::initialized(configuration, lifecycle, Arc::clone(&ram))?;
        // Validate every range against native 256 as well as physical 2048.
        let (ptd, local) =
            Ptd::initialized_local_profile(PROFILE, geometry, &descriptor.ptd.ranges, lifecycle)?;
        let duties = Duties::new(&descriptor.ptd.ranges)?;
        Ok(Self {
            descriptor,
            ram,
            dcs,
            ptd,
            local,
            duties,
        })
    }
    pub fn descriptor(&self) -> &MemoryCache {
        &self.descriptor
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    /// Initialize a distinct software AMCC lock resource over this exact RAM.
    /// Cache status/capacity/quota/flush effects remain explicitly unavailable.
    pub fn initialize_amcc_locks(
        &self,
        controller: stela_soc_data::board::MemoryController,
        programmed: stela_soc_data::amcc::Programmed,
        lifecycle: LifecycleState,
    ) -> Result<amcc::LockResource> {
        amcc::LockResource::initialized(self, controller, programmed, lifecycle)
    }
    pub fn publication_bank(&self) -> &Ptd {
        &self.ptd
    }
    pub fn notifications(&self) -> &LocalNotifications {
        &self.local
    }
    pub fn progress(&self) -> [ChannelProgress; CHANNELS] {
        self.dcs.progress()
    }

    /// Complete device-offset bindings. Installing them is placement only;
    /// source-checked cache/AMCC and native service admission remain required.
    pub fn bindings(&self) -> [(u64, u64, u64); 2] {
        [
            (self.descriptor.channels.0, DCS_BYTES, 0),
            self.publication_binding(),
        ]
    }
    pub(super) fn publication_binding(&self) -> (u64, u64, u64) {
        self.publication_layout().binding()
    }
    pub(super) fn display_publication_view(
        &self,
        physical: u64,
        bytes: u64,
    ) -> Result<(u64, u64, u64)> {
        self.publication_layout().display_view(physical, bytes)
    }
    pub fn requires_ram_read(&self, offset: u64, width: Width) -> bool {
        offset < DCS_BYTES && self.dcs.requires_ram_access(offset, width)
    }
    /// # Safety
    /// NativeDcs::read_ram_drain's complete stopped-cohort, closed synchronous
    /// producer and exclusive Devices contract holds for this entire borrow.
    pub unsafe fn read_ram_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64> {
        if !self.requires_ram_read(offset, width) {
            return Err(refuse!(
                "T8112 canonical read is not a source DCS drain word"
            ));
        }
        // SAFETY: caller keeps the complete live canonical ownership contract.
        unsafe { self.dcs.read_ram_drain(offset, width, memory) }
    }
    /// # Safety
    /// The same complete NativeDcs::write_ram_drain contract holds through
    /// consumption; a matching numeric request supplies no ownership evidence.
    pub unsafe fn write_ram_drain(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        now: u64,
        memory: &CanonicalRamService<'_>,
    ) -> Result<()> {
        if !self.requires_ram_read(offset, width) {
            return Err(refuse!(
                "T8112 canonical write is not a source DCS drain word"
            ));
        }
        // SAFETY: caller keeps the same live closed producer set and RAM hold.
        unsafe { self.dcs.write_ram_drain(offset, width, value, now, memory) }
    }
    pub(super) fn supports_pair(&self, offset: u64, bytes: u8) -> bool {
        self.publication_layout().supports_pair(offset, bytes)
    }
    fn publication_layout(&self) -> super::publication::Layout {
        super::publication::Layout {
            physical: self.descriptor.ptd.physical,
            updates: self.descriptor.ptd_updates,
            device_offset: PTD_OFFSET,
            entries: PROFILE.entries() as usize,
        }
    }
    pub(super) fn read_pair_values(
        &self,
        offset: u64,
        bytes: u8,
        access: &mut Access<'_>,
    ) -> Result<[u64; 2]> {
        let layout = self.publication_layout();
        if layout.entry(offset, bytes).is_some() {
            self.start_duties(access)
                .map_err(|_| refuse!("the PMP's PTD duties could not start"))?;
        }
        layout.read_pair(&self.ptd, offset, bytes, access)
    }
    fn start_duties(&self, access: &mut Access<'_>) -> Result<(), MmioError> {
        match &self.duties {
            Some(duties) => duties.start(&self.ptd, access),
            None => Ok(()),
        }
    }
    fn in_bank(&self, offset: u64, width: Width, direction: Direction) -> Result<(), MmioError> {
        if offset
            .checked_add(width.bytes())
            .is_some_and(|end| end <= PTD_OFFSET + stela_soc_data::ptd::PTD_BYTES)
        {
            Ok(())
        } else {
            Err(refuse(
                self.name(),
                offset,
                width,
                direction,
                "access exceeds T8112 source-owned DCS/PTD extent",
            ))
        }
    }
}
impl Lifecycle for Prepared {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        self.dcs.check_lifecycle(proposed)?;
        self.ptd.check_lifecycle(proposed)
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.dcs.set_lifecycle(proposed, access);
        self.ptd.set_lifecycle(proposed, access);
    }
}
impl MmioDevice for Prepared {
    fn name(&self) -> &'static str {
        "t8112-dcs-ptd"
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        self.in_bank(offset, width, Direction::Read)?;
        if offset < PTD_OFFSET {
            self.dcs.read(offset, width, access)
        } else {
            self.start_duties(access)?;
            self.ptd.read(offset - PTD_OFFSET, width, access)
        }
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.in_bank(offset, width, Direction::Write)?;
        if offset < PTD_OFFSET {
            return self.dcs.write(offset, width, value, access);
        }
        self.start_duties(access)?;
        self.ptd.write(offset - PTD_OFFSET, width, value, access)?;
        match &self.duties {
            Some(duties) => duties.written(&self.ptd, offset - PTD_OFFSET, width, value, access),
            None => Ok(()),
        }
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.ptd.advance(access)
    }
}

impl crate::machine::AppleDevices {
    /// Place the supplied DCS/PTD storage without changing AMCC locks or
    /// admitting the remaining cache/PMP/IRQ requirements of a whole mount.
    pub fn add_t8112_memory_resources(&mut self, owner: Prepared) -> Result<()> {
        if self.memory_publication.is_some()
            || self
                .memory_controller
                .is_some_and(|id| super::resource_for(&self.bus, id).is_some())
        {
            return Err(refuse!("memory publication storage is already installed"));
        }
        let bindings = owner.bindings();
        let id = self
            .bus
            .install(alloc::boxed::Box::new(owner), &bindings)
            .map_err(|error| refuse!("T8112 DCS/PTD placement: {error}", ?error))?;
        self.memory_publication = Some(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
