//! Prepared direct MCC/AMCC/PTD resources. No native RAM/DSB permission is
//! manufactured here and no engine mount is enabled by constructing this object.
use crate::Result;
use crate::platform::apple::amcc::Amcc;
use crate::platform::apple::mcc::Configuration;
use crate::platform::apple::mcc::Controller;
use crate::platform::apple::ptd::Ptd;
use crate::platform::apple::ptd::transport::notifications::LocalNotifications;
use alloc::vec::Vec;
use stela_contracts::bus::Access;
use stela_contracts::bus::Direction;
use stela_contracts::bus::Lifecycle;
use stela_contracts::bus::MmioDevice;
use stela_contracts::bus::MmioError;
use stela_contracts::bus::Width;
use stela_contracts::bus::refuse;
use stela_contracts::interrupt::Wire;
use stela_contracts::refuse;
use stela_soc_data::amcc::Layout;
use stela_soc_data::amcc::Register;
use stela_soc_data::board::DirectMemoryCache;
use stela_soc_data::board::MemoryController;

// The mount configures these resources; it must be able to name their
// typed configuration, lifecycle and original register/publication geometry.
pub use crate::platform::apple::amcc;
pub use crate::platform::apple::mcc;

pub use stela_contracts::bus::LifecycleState;

mod canonical;
pub(crate) mod cold;
pub mod dcs;
mod publication;
mod resource;
pub(super) use resource::resource_for;
pub mod t6000_cold;
pub mod t6020;
pub mod t8112;

/// One prepared software resource with immutable placement and shared
/// controller identity. A caller must still bind canonical RAM, all writers,
/// execution ownership, DSB retirement and paired PTD reads before mounting it.
/// Engine adoption is separate: neither descriptor parsing nor a
/// cacheless boot argument supplies that admission proof.
pub struct Prepared {
    router: Router,
    ptd: Ptd,
    local: Option<LocalNotifications>,
    descriptor: DirectMemoryCache,
    ram: Option<alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>>,
}
impl Prepared {
    pub fn new(
        descriptor: DirectMemoryCache,
        locks: &MemoryController,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
        ptd_bindings: [Option<Wire>; 16],
    ) -> Result<Self> {
        let router =
            Self::prepare_router(&descriptor, locks, programmed, configuration, lifecycle)?;
        let ptd = Ptd::initialized(
            u32::try_from(descriptor.ptd_entries)
                .map_err(|_| refuse!("PTD entry count exceeds source width"))?,
            &descriptor.ptd.ranges,
            lifecycle,
            ptd_bindings,
        )?;
        Ok(Self {
            router,
            ptd,
            local: None,
            descriptor,
            ram: None,
        })
    }
    /// Build one local-notification bank, returning its receiver for
    /// the native PMP owner. No AP interrupt binding or service ACK is inferred.
    pub fn new_local(
        descriptor: DirectMemoryCache,
        locks: &MemoryController,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications)> {
        let router =
            Self::prepare_router(&descriptor, locks, programmed, configuration, lifecycle)?;
        let (ptd, local) = Ptd::initialized_local(
            u32::try_from(descriptor.ptd_entries)
                .map_err(|_| refuse!("PTD entry count exceeds source width"))?,
            &descriptor.ptd.ranges,
            lifecycle,
        )?;
        Ok((
            Self {
                router,
                ptd,
                local: Some(local.clone()),
                descriptor,
                ram: None,
            },
            local,
        ))
    }
    fn prepare_router(
        descriptor: &DirectMemoryCache,
        locks: &MemoryController,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
    ) -> Result<Router> {
        descriptor.validate(locks)?;
        if configuration.dram.len() != descriptor.apertures.len()
            || descriptor.apertures != locks.apertures
            || descriptor.ptd.ranges.len() != descriptor.ptd.interrupts.len()
        {
            return Err(refuse!(
                "MCC preparation does not match actual descriptor/configuration ownership"
            ));
        }
        let controller = Controller::initialized_cacheless(configuration, lifecycle)?;
        Router::new(
            locks.layout,
            programmed,
            controller,
            descriptor.apertures.len(),
        )
    }
    pub fn controller(&self) -> &Controller {
        &self.router.controller
    }
    pub fn publication_bank(&self) -> &Ptd {
        &self.ptd
    }
    /// The SAME receiver initialized with the local PTD. Borrowing it
    /// creates no service/callback/IRQ owner or ready/ACK permission.
    pub fn local_notifications(&self) -> Option<&LocalNotifications> {
        self.local.as_ref()
    }
    pub fn registered_ram(
        &self,
    ) -> Option<&alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>> {
        self.ram.as_ref()
    }
    pub fn descriptor(&self) -> &DirectMemoryCache {
        &self.descriptor
    }
    pub fn locked_regions(&self) -> stela_soc_data::amcc::Locked {
        self.router.locks.locked_regions()
    }
    /// Complete aperture bindings, not a permission to publish them yet. One
    /// bus device owns both register interpretations and every aperture.
    pub fn bindings(&self) -> Vec<(u64, u64, u64)> {
        let mut bindings: Vec<_> = self
            .descriptor
            .apertures
            .iter()
            .enumerate()
            .map(|(index, &pa)| (pa, mcc::APERTURE_BYTES, index as u64 * mcc::APERTURE_BYTES))
            .collect();
        bindings.push(self.publication_binding());
        bindings
    }
    pub(super) fn publication_binding(&self) -> (u64, u64, u64) {
        self.publication_layout().binding()
    }
    /// A declared physical display view may cover the PTD update alias and its
    /// unimplemented tail. It must start at the update bank, cover every
    /// update slot and stay inside this owner's complete publication aperture.
    /// The returned device offset routes to this exact Ptd, without increasing
    /// its checked register geometry or allocating another backing.
    pub(super) fn display_publication_view(
        &self,
        physical: u64,
        bytes: u64,
    ) -> Result<(u64, u64, u64)> {
        self.publication_layout().display_view(physical, bytes)
    }
    fn ptd_offset(&self) -> u64 {
        self.descriptor.apertures.len() as u64 * mcc::APERTURE_BYTES
    }
    pub(super) fn supports_pair(&self, offset: u64, bytes: u8) -> bool {
        self.publication_layout().supports_pair(offset, bytes)
    }
    fn publication_layout(&self) -> publication::Layout {
        publication::Layout {
            physical: self.descriptor.ptd.physical,
            updates: self.descriptor.ptd_updates,
            device_offset: self.ptd_offset(),
            entries: self.descriptor.ptd_entries,
        }
    }
    pub(super) fn read_pair_values(
        &self,
        offset: u64,
        bytes: u8,
        access: &mut Access<'_>,
    ) -> Result<[u64; 2]> {
        self.publication_layout()
            .read_pair(&self.ptd, offset, bytes, access)
    }
}
impl Lifecycle for Prepared {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        self.router.check_lifecycle(proposed)?;
        self.ptd.check_lifecycle(proposed)
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.router.set_lifecycle(proposed, access);
        self.ptd.set_lifecycle(proposed, access);
    }
}
impl MmioDevice for Prepared {
    fn name(&self) -> &'static str {
        "mcc-amcc-ptd"
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
        if offset >= self.ptd_offset() {
            self.ptd.read(offset - self.ptd_offset(), width, access)
        } else {
            self.router.read(offset, width, access)
        }
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if offset >= self.ptd_offset() {
            self.ptd
                .write(offset - self.ptd_offset(), width, value, access)
        } else {
            self.router.write(offset, width, value, access)
        }
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.ptd.advance(access)
    }
}

/// Private until the canonical memory admission can consume Prepared. The lock
/// model has no independent cache status/DSID bank: aliases have one owner.
struct Router {
    locks: Amcc,
    controller: Controller,
    views: Vec<mcc::View>,
    offsets: Vec<u64>,
    lock_layout: Layout,
}
impl Router {
    fn new(
        mut layout: Layout,
        programmed: stela_soc_data::amcc::Programmed,
        controller: Controller,
        apertures: usize,
    ) -> Result<Self> {
        // J314s 26A434 iBoot builder0x38660 declares the plane
        // way-command word as cache-status (mask0x1f, disabled value0).
        // Builder0x3862c separately names +0x10000c as broadcast control.
        if layout.cache_status
            != Some(Register {
                offset: 0x1c00,
                mask: 0x1f,
                value: 0,
            })
        {
            return Err(refuse!(
                "joint MCC/AMCC cache-status descriptor is not source-qualified"
            ));
        }
        if apertures == 0
            || apertures > 16
            || layout.planes != u32::from(mcc::PLANES)
            || layout.stride != mcc::PLANE_STRIDE
            || layout.aperture_bytes > mcc::APERTURE_BYTES
        {
            return Err(refuse!(
                "joint MCC/AMCC geometry has no original direct-controller contract"
            ));
        }
        // The MCC owns every plane's way-command backing. Remove
        // Amcc's independent disabled bit: source cache-status reads must
        // observe that same command image, not a copied healthy value.
        layout.cache_status = None;
        let locks = Amcc::new(layout, apertures, programmed, None)?;
        let mut views = Vec::new();
        for aperture in 0..apertures {
            views.push(controller.view(aperture as u8)?);
        }
        if controller.view(apertures as u8).is_ok() {
            return Err(refuse!("MCC owner has extra unplaced apertures"));
        }
        let offsets = controller.register_offsets();
        // A lock word colliding with an MCC word needs one source-checked
        // protocol, not priority-based fallback between independent devices.
        for register in layout.groups.into_iter().flatten().flat_map(|group| {
            [
                Some(group.lower_limit),
                Some(group.upper_limit),
                group.enable,
                group.write_disable,
                group.lock,
            ]
            .into_iter()
            .flatten()
        }) {
            for plane in 0..layout.planes {
                if offsets.contains(&(register.offset + u64::from(plane) * layout.stride)) {
                    return Err(refuse!(
                        "MCC and CTRR registers overlap without a shared protocol"
                    ));
                }
            }
        }
        Ok(Self {
            locks,
            controller,
            views,
            offsets,
            lock_layout: layout,
        })
    }
    fn target(&self, offset: u64) -> Result<(usize, u64)> {
        let lifecycle = self.controller.lifecycle_state();
        if !lifecycle.powered || !lifecycle.clocked || lifecycle.quiesced || lifecycle.reset {
            return Err(refuse!(
                "joint MCC/AMCC resource is paused by its actual owner"
            ));
        }
        let aperture = usize::try_from(offset / mcc::APERTURE_BYTES)
            .map_err(|_| refuse!("MCC aperture index overflows"))?;
        if aperture >= self.views.len() {
            return Err(refuse!("MCC access exceeds prepared aperture ownership"));
        }
        Ok((aperture, offset % mcc::APERTURE_BYTES))
    }
}
impl Lifecycle for Router {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        for view in &self.views {
            view.check_lifecycle(proposed)?;
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        // Views share the Controller. Commit once, after full preflight.
        self.views[0].set_lifecycle(proposed, access);
    }
}
impl MmioDevice for Router {
    fn name(&self) -> &'static str {
        "mcc-amcc"
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
        let (aperture, within) = self
            .target(offset)
            .map_err(|reason| refuse(self.name(), offset, width, Direction::Read, reason))?;
        if self.offsets.contains(&within) {
            return self.views[aperture].read(within, width, access);
        }
        if within >= self.lock_layout.aperture_bytes {
            return Err(refuse(
                self.name(),
                offset,
                width,
                Direction::Read,
                "unqualified MCC register beyond lock aperture",
            ));
        }
        self.locks.read(
            aperture as u64 * self.lock_layout.aperture_bytes + within,
            width,
            access,
        )
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let (aperture, within) = self
            .target(offset)
            .map_err(|reason| refuse(self.name(), offset, width, Direction::Write, reason))?;
        if self.offsets.contains(&within) {
            return self.views[aperture].write(within, width, value, access);
        }
        if within >= self.lock_layout.aperture_bytes {
            return Err(refuse(
                self.name(),
                offset,
                width,
                Direction::Write,
                "unqualified MCC register beyond lock aperture",
            ));
        }
        self.locks.write(
            aperture as u64 * self.lock_layout.aperture_bytes + within,
            width,
            value,
            access,
        )
    }
}

#[cfg(test)]
mod tests;
