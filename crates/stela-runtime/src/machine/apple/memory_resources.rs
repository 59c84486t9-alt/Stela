//! Prepared direct MCC/AMCC/PTD resources. No native RAM/DSB authority is
//! manufactured here and no engine mount is enabled by constructing this object.
use crate::machine::soc::DirectMemoryCache;
use crate::machine::soc::MemoryController;
use crate::platform::apple::amcc::Amcc;
use crate::platform::apple::amcc::Layout;
use crate::platform::apple::amcc::Register;
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

// The mount configures these actual resources; it must be able to name their
// typed configuration, lifecycle and original register/publication geometry.
pub use crate::platform::apple::amcc;
pub use crate::platform::apple::mcc;
pub use crate::platform::apple::ptd;
pub use stela_contracts::bus::LifecycleState;

mod canonical;
pub mod dcs;
mod publication;
mod resource;
pub(super) use resource::resource_for;
pub mod t6000_cold;
pub mod t6020;
pub mod t8112;

/// One prepared software resource with immutable placement and actual shared
/// controller identity. A caller must still bind canonical RAM, all writers,
/// execution ownership, DSB retirement and paired PTD reads before mounting it.
/// Engine adoption is deliberately separate: neither descriptor parsing nor a
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
        programmed: amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
        ptd_bindings: [Option<Wire>; 16],
    ) -> Result<Self, &'static str> {
        let router =
            Self::prepare_router(&descriptor, locks, programmed, configuration, lifecycle)?;
        let ptd = Ptd::initialized(
            u32::try_from(descriptor.ptd_entries)
                .map_err(|_| "PTD entry count exceeds source width")?,
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
    /// Build one actual local-notification bank, returning its receiver for
    /// the native PMP owner. No AP interrupt binding or service ACK is inferred.
    pub fn new_local(
        descriptor: DirectMemoryCache,
        locks: &MemoryController,
        programmed: amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        let router =
            Self::prepare_router(&descriptor, locks, programmed, configuration, lifecycle)?;
        let (ptd, local) = Ptd::initialized_local(
            u32::try_from(descriptor.ptd_entries)
                .map_err(|_| "PTD entry count exceeds source width")?,
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
        programmed: amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
    ) -> Result<Router, &'static str> {
        descriptor.validate(locks)?;
        if configuration.dram.len() != descriptor.apertures.len()
            || descriptor.apertures != locks.apertures
            || descriptor.ptd.ranges.len() != descriptor.ptd.interrupts.len()
        {
            return Err("MCC preparation does not match actual descriptor/configuration ownership");
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
    /// The SAME actual receiver initialized with the local PTD. Borrowing it
    /// creates no service/callback/IRQ owner or ready/ACK authority.
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
    pub fn locked_regions(&self) -> amcc::Locked {
        self.router.locks.locked_regions()
    }
    /// Complete aperture bindings, not a permission to publish them yet. One
    /// bus device owns both register interpretations and every actual aperture.
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
    /// unimplemented tail. It must start at the actual update bank, cover every
    /// update slot and stay inside this owner's complete publication aperture.
    /// The returned device offset routes to this exact Ptd, without increasing
    /// its qualified register geometry or allocating another backing.
    pub(super) fn display_publication_view(
        &self,
        physical: u64,
        bytes: u64,
    ) -> Result<(u64, u64, u64), &'static str> {
        self.publication_layout().display_view(physical, bytes)
    }
    fn ptd_offset(&self) -> u64 {
        self.descriptor.apertures.len() as u64 * mcc::APERTURE_BYTES
    }
    /// A pair is consuming only at a complete publication entry. The update
    /// alias, scalar halves and unknown tail retain their own MMIO semantics.
    pub(super) fn paired_entry(&self, offset: u64, bytes: u8) -> Option<u32> {
        self.publication_layout().entry(offset, bytes)
    }
    pub(super) fn consume_entry(
        &self,
        entry: u32,
        access: &mut Access<'_>,
    ) -> Result<[u64; 2], &'static str> {
        let entry = self.ptd.consume_entry(entry, access)?;
        Ok([entry.value, entry.metadata])
    }
    fn status_pair(
        &self,
        offset: u64,
        bytes: u8,
    ) -> Option<(u64, crate::platform::apple::ptd::transport::status::Width)> {
        self.publication_layout().status_pair(offset, bytes)
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
    ) -> Result<[u64; 2], &'static str> {
        if let Some(entry) = self.paired_entry(offset, bytes) {
            return self.consume_entry(entry, access);
        }
        let (offset, width) = self
            .status_pair(offset, bytes)
            .ok_or("unqualified PTD pair read shape")?;
        let value = self.ptd.interrupt_snapshot(offset, width)?;
        Ok(if bytes == 8 {
            [value.low, value.high]
        } else {
            [value.low & u64::from(u32::MAX), value.low >> 32]
        })
    }
}
impl Lifecycle for Prepared {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
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
        programmed: amcc::Programmed,
        controller: Controller,
        apertures: usize,
    ) -> Result<Self, &'static str> {
        // J314s 26A434 iBoot builder0x38660 declares the actual plane
        // way-command word as cache-status (mask0x1f, disabled value0).
        // Builder0x3862c separately names +0x10000c as broadcast control.
        if layout.cache_status
            != Some(Register {
                offset: 0x1c00,
                mask: 0x1f,
                value: 0,
            })
        {
            return Err("joint MCC/AMCC cache-status descriptor is not source-qualified");
        }
        if apertures == 0
            || apertures > 16
            || layout.planes != u32::from(mcc::PLANES)
            || layout.stride != mcc::PLANE_STRIDE
            || layout.aperture_bytes > mcc::APERTURE_BYTES
        {
            return Err("joint MCC/AMCC geometry has no original direct-controller contract");
        }
        // The MCC owns every plane's actual way-command backing. Remove
        // Amcc's independent disabled bit: source cache-status reads must
        // observe that same command image, not a copied healthy value.
        layout.cache_status = None;
        let locks = Amcc::new(layout, apertures, programmed, None)?;
        let mut views = Vec::new();
        for aperture in 0..apertures {
            views.push(controller.view(aperture as u8)?);
        }
        if controller.view(apertures as u8).is_ok() {
            return Err("MCC owner has extra unplaced apertures");
        }
        let offsets = controller.register_offsets();
        // A lock word colliding with an MCC word needs one source-qualified
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
                    return Err("MCC and CTRR registers overlap without a shared protocol");
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
    fn target(&self, offset: u64) -> Result<(usize, u64), &'static str> {
        let lifecycle = self.controller.lifecycle_state();
        if !lifecycle.powered || !lifecycle.clocked || lifecycle.quiesced || lifecycle.reset {
            return Err("joint MCC/AMCC resource is paused by its actual owner");
        }
        let aperture = usize::try_from(offset / mcc::APERTURE_BYTES)
            .map_err(|_| "MCC aperture index overflows")?;
        if aperture >= self.views.len() {
            return Err("MCC access exceeds prepared aperture ownership");
        }
        Ok((aperture, offset % mcc::APERTURE_BYTES))
    }
}
impl Lifecycle for Router {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        for view in &self.views {
            view.check_lifecycle(proposed)?;
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        // Views share the actual Controller. Commit once, after full preflight.
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
mod tests {
    use super::*;
    use crate::machine::soc::PtdBank;
    use crate::platform::apple::amcc::LockGroup;
    use crate::platform::apple::mcc::RequestKind;
    use crate::platform::apple::ptd;
    use alloc::{boxed::Box, vec};
    use stela_contracts::bus::Bus;
    use stela_contracts::interrupt::InterruptLatch;

    pub(super) fn prepared() -> Prepared {
        let reg = |offset, mask, value| Register {
            offset,
            mask,
            value,
        };
        let locks = MemoryController {
            apertures: vec![0x200000000, 0x201000000],
            layout: Layout {
                aperture_bytes: 0x200000,
                planes: 4,
                stride: mcc::PLANE_STRIDE,
                cache_status: Some(reg(0x1c00, 0x1f, 0)),
                dram_base: 0x800000000,
                groups: [
                    Some(LockGroup {
                        page_size_shift: 14,
                        lower_limit: reg(0x680, u32::MAX, 0),
                        upper_limit: reg(0x684, u32::MAX, 0),
                        enable: Some(reg(0x688, 1, 1)),
                        write_disable: None,
                        lock: Some(reg(0x68c, 1, 1)),
                    }),
                    None,
                    None,
                    None,
                ],
            },
        };
        let descriptor = DirectMemoryCache {
            apertures: locks.apertures.clone(),
            config_data: vec![1],
            alternate_dram_configuration: 0xffff0000,
            ptd: PtdBank {
                physical: 0x28e3c0000,
                ranges: vec![ptd::Range {
                    id: 1,
                    start: 0,
                    count: 2,
                    name: "DECLARED".into(),
                }],
                interrupts: vec![14],
            },
            ptd_updates: (0x28e3d0000, 0xc00),
            ptd_entries: 384,
        };
        Prepared::new(
            descriptor,
            &locks,
            amcc::ctrr_a(Some((0x800004000, 0x4000))),
            Configuration {
                dram: vec![[7; 4]; 2],
                weights: [1; 32],
            },
            LifecycleState {
                powered: true,
                clocked: true,
                reset: false,
                quiesced: false,
                retention: true,
            },
            [None; 16],
        )
        .unwrap()
    }
    #[test]
    fn joint_resource_has_one_backing_for_broadcast_policy_and_publications() {
        let owner = prepared();
        let controller = owner.controller().clone();
        let publication = owner.publication_bank().clone();
        let bindings = owner.bindings();
        assert_eq!(bindings.len(), 3);
        let mut bus = Bus::new();
        let id = bus.install(Box::new(owner), &bindings).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 17, &mut latch);
        let base = 0x200000000;
        assert_eq!(bus.read(base + 0x10000c, Width::Word, &mut access), Ok(0));
        bus.write(base + 0x10000c, Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(
            controller
                .observations()
                .iter()
                .find(|word| word.aperture == 0 && word.offset == 0x10000c)
                .unwrap()
                .value,
            1
        );
        // The extra Stela status views share the actual selector; no
        // independent Amcc disabled/ready values exist behind these addresses.
        for plane in 1..4 {
            assert_eq!(
                bus.read(
                    base + 0x10000c + plane * mcc::PLANE_STRIDE,
                    Width::Word,
                    &mut access
                ),
                Ok(1)
            );
        }
        bus.write(base + 0x1c00, Width::Word, 0, &mut access)
            .unwrap();
        assert_eq!(bus.read(base + 0x1c04, Width::Word, &mut access), Ok(0));
        assert!(
            bus.write(base + 0x1c00, Width::Word, 1, &mut access)
                .is_err()
        );
        bus.write(base + 0x14000, Width::Word, 2, &mut access)
            .unwrap();
        assert!(matches!(
            controller.requests().last().unwrap().kind,
            RequestKind::Deprioritize { dsid: 1, .. }
        ));
        let before = controller.requests();
        assert!(
            bus.write(base + 0x14000, Width::Word, 1, &mut access)
                .is_err()
        );
        assert!(
            bus.write(base + mcc::DCS_BASE + 0xa40, Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(controller.requests(), before);
        // The second aperture reaches the same actual owner's separate bank.
        bus.write(
            base + mcc::APERTURE_BYTES + 0xa000,
            Width::Word,
            0x10002,
            &mut access,
        )
        .unwrap();
        assert_eq!(
            controller.policy(1, 1, 0).unwrap().configured_quota_bytes(),
            2 << 17
        );
        assert_eq!(
            controller.policy(0, 1, 0).unwrap().configured_quota_bytes(),
            0
        );
        bus.write(0x28e3d0000, Width::Double, 0x1234, &mut access)
            .unwrap();
        assert!(bus.read(0x28e3c0000, Width::Double, &mut access).is_err());
        assert_eq!(
            publication.consume_entry(0, &mut access).unwrap().value,
            0x1234
        );
        assert_eq!(
            bus.device::<Prepared>(id).unwrap().locked_regions(),
            [None; 4]
        );
        // No register beyond AMCC's smaller lock aperture can alias a later
        // aperture's lock plane through a changed device-offset divisor.
        assert!(bus.read(base + 0x200680, Width::Word, &mut access).is_err());
    }
    #[test]
    fn old_mount_paths_refuse_missing_owners_before_publishing_any_aperture() {
        let owner = prepared();
        let mut devices = super::super::AppleDevices::new();
        let mut layout = owner.router.lock_layout;
        let missing = devices.add_memory_controller(
            &[0x400000000],
            layout,
            [None; 4],
            Some(crate::platform::apple::amcc::Cache {
                shared: (0x100000, 0x80000),
                broadcast: 0xf00000,
                bytes: 8 << 20,
                ways: 16,
            }),
        );
        assert!(
            missing
                .unwrap_err()
                .contains("qualified memory, drain and service owner")
        );
        assert!(devices.memory_controller.is_none());
        assert!(devices.bus.route(0x400000680, Width::Word).is_err());
        layout.cache_status = Some(Register {
            offset: 0x10000c,
            mask: 1,
            value: 1,
        });
        assert!(
            devices
                .add_memory_controller(&[0x400000000], layout, [None; 4], None)
                .is_err()
        );
        assert!(devices.bus.route(0x400000680, Width::Word).is_err());
        // Failure at a later aperture must not leave the earlier one mapped.
        layout.cache_status = None;
        let bindings = owner.bindings();
        devices.bus.install(Box::new(owner), &bindings).unwrap();
        assert!(
            devices
                .add_io_access_controller(&[0x400000000, 0x200000000], layout, [None; 4])
                .is_err()
        );
        assert!(devices.bus.route(0x400000680, Width::Word).is_err());
        assert!(devices.bus.route(0x200000680, Width::Word).is_ok());
    }

    #[test]
    fn paused_joint_owner_refuses_locks_and_retains_checked_state() {
        let mut owner = prepared();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(owner.read(0x680, Width::Word, &mut access), Ok(1));
        let running = owner.controller().lifecycle_state();
        let paused = LifecycleState {
            clocked: false,
            ..running
        };
        owner.set_lifecycle(paused, &mut access);
        assert!(owner.read(0x680, Width::Word, &mut access).is_err());
        assert!(owner.write(0x688, Width::Word, 1, &mut access).is_err());
        owner.set_lifecycle(running, &mut access);
        assert_eq!(owner.read(0x680, Width::Word, &mut access), Ok(1));
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    reset: true,
                    ..running
                })
                .is_err()
        );
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    powered: false,
                    retention: false,
                    ..running
                })
                .is_err()
        );
        owner.write(0x688, Width::Word, 1, &mut access).unwrap();
        assert_eq!(owner.locked_regions()[0], Some((0x800004000, 0x800007fff)));
        for aperture in 0..2 {
            for plane in 0..4 {
                owner
                    .write(
                        aperture * mcc::APERTURE_BYTES + plane * mcc::PLANE_STRIDE + 0x688,
                        Width::Word,
                        1,
                        &mut access,
                    )
                    .unwrap();
            }
        }
        assert_eq!(owner.locked_regions()[0], Some((0x800004000, 0x800007fff)));
    }

    #[test]
    fn paired_read_consumes_only_the_actual_complete_publication_entry() {
        use stela_engine::machine::Devices;
        let owner = prepared();
        let offset = owner.ptd_offset();
        assert_eq!(owner.paired_entry(offset, 8), Some(0));
        assert_eq!(owner.paired_entry(offset + 383 * 16, 8), Some(383));
        for (offset, bytes) in [
            (offset, 4),
            (offset + 8, 8),
            (offset + 384 * 16, 8),
            (offset + ptd::UPDATE_OFFSET, 8),
            (0, 8),
        ] {
            assert_eq!(owner.paired_entry(offset, bytes), None);
        }
        let publication = owner.publication_bank().clone();
        let bindings = owner.bindings();
        let mut board = super::super::AppleDevices::new();
        let id = board.bus.install(Box::new(owner), &bindings).unwrap();
        board.memory_controller = Some(id);
        let mut access = Access::new(0, 17, &mut board.latch);
        board
            .bus
            .write(0x28e3d0000, Width::Double, 0x1234, &mut access)
            .unwrap();
        // Probing an unrelated width/half must not consume or settle anything.
        assert_eq!(board.read_pair(0, 0x28e3c0000, 4, 17), Ok(None));
        assert_eq!(board.read_pair(0, 0x28e3c0008, 8, 17), Ok(None));
        let pair = board.read_pair(0, 0x28e3c0000, 8, 17).unwrap().unwrap();
        assert_eq!(pair.values[0], 0x1234);
        assert!(pair.values[1] & 2 != 0);
        assert_eq!(pair.settlement, Ok(()));
        let mut access = Access::new(0, 17, &mut board.latch);
        let consumed = publication.consume_entry(0, &mut access).unwrap();
        assert_eq!(consumed.value, 0x1234);
        assert_eq!(consumed.metadata & 3, 0);
        // CPU and DMA callers query the very same prepared lock owner.
        board
            .bus
            .write(0x200000688, Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(board.memory_lock()[0], Some((0x800004000, 0x800007fff)));
    }

    #[test]
    fn local_constructor_returns_the_same_publication_and_notification_owner() {
        let original = prepared();
        let lifecycle = original.controller().lifecycle_state();
        let mut locks = MemoryController {
            apertures: original.descriptor.apertures.clone(),
            layout: original.router.lock_layout,
        };
        // Router removed this alias from Amcc because the actual MCC
        // controller owns it. Reconstruct the source descriptor, not that
        // already-normalized private lock-only view.
        locks.layout.cache_status = Some(Register {
            offset: 0x1c00,
            mask: 0x1f,
            value: 0,
        });
        let (mut owner, local) = Prepared::new_local(
            original.descriptor,
            &locks,
            [None; 4],
            Configuration {
                dram: vec![[7; 4]; 2],
                weights: [1; 32],
            },
            lifecycle,
        )
        .unwrap();
        assert!(local.owns(owner.publication_bank()));
        assert_eq!(local.asserted(), 0);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 17, &mut latch);
        let base = owner.ptd_offset();
        owner
            .write(base + 0x18400, Width::Word, 3, &mut access)
            .unwrap();
        owner
            .write(base + 0x18200, Width::Word, 1, &mut access)
            .unwrap();
        owner
            .write(
                base + ptd::UPDATE_OFFSET,
                Width::Double,
                0x1234,
                &mut access,
            )
            .unwrap();
        assert_eq!(local.asserted(), 1 << 3);
        assert_eq!(owner.consume_entry(0, &mut access).unwrap()[0], 0x1234);
        assert_eq!(local.asserted(), 0);
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn paired_read_keeps_data_and_pending_service_after_wire_forwarding_refusal() {
        use stela_contracts::interrupt::AicInput;
        use stela_contracts::interrupt::InterruptSink;
        use stela_engine::machine::Devices;
        let owner = prepared();
        let publication = owner.publication_bank().clone();
        let bindings = owner.bindings();
        let mut board = super::super::AppleDevices::new();
        board.bus.install(Box::new(owner), &bindings).unwrap();
        let mut access = Access::new(0, 17, &mut board.latch);
        board
            .bus
            .write(0x28e3d0000, Width::Double, 0x5678, &mut access)
            .unwrap();
        // This genuinely queued wire has no AIC receiver. Its failed
        // forwarding follows consumption and must not erase the read result.
        board.latch.set_level(Wire::Aic(AicInput::new(0, 3)), true);
        let pair = board.read_pair(0, 0x28e3c0000, 8, 17).unwrap().unwrap();
        assert_eq!(pair.values[0], 0x5678);
        assert!(pair.values[1] & 2 != 0);
        assert!(pair.settlement.is_err());
        assert_eq!(board.pending_service().unwrap().committed(), 0);
        assert_eq!(board.pending_service().unwrap().inputs().len(), 1);
        let mut access = Access::new(0, 17, &mut board.latch);
        assert_eq!(
            publication.consume_entry(0, &mut access).unwrap().metadata & 3,
            0
        );
    }

    #[test]
    fn status_pairs_snapshot_one_pending_bank_without_consuming_publications() {
        use crate::platform::apple::ptd::transport::IRQ_STATUS;
        use stela_engine::machine::Devices;
        let owner = prepared();
        let bindings = owner.bindings();
        let mut board = super::super::AppleDevices::new();
        board.bus.install(Box::new(owner), &bindings).unwrap();
        let mut access = Access::new(0, 17, &mut board.latch);
        for entry in [0, 33, 65] {
            board
                .bus
                .write(
                    0x28e3d0000 + entry * 8,
                    Width::Double,
                    entry + 0x1000,
                    &mut access,
                )
                .unwrap();
        }
        let status = 0x28e3c0000 + IRQ_STATUS;
        for _ in 0..2 {
            let narrow = board.read_pair(0, status, 4, 17).unwrap().unwrap();
            assert_eq!(narrow.values, [1, 2]);
            assert_eq!(narrow.settlement, Ok(()));
            let wide = board.read_pair(0, status, 8, 17).unwrap().unwrap();
            assert_eq!(wide.values, [0x0000000200000001, 2]);
            assert_eq!(wide.settlement, Ok(()));
        }
        // The last status pair cannot extend past the twelve actual words.
        assert_eq!(board.read_pair(0, status + 40, 8, 17), Ok(None));
        // Only a publication read consumes its pending flag.
        assert_eq!(
            board
                .read_pair(0, 0x28e3c0000, 8, 17)
                .unwrap()
                .unwrap()
                .values[0],
            0x1000
        );
        assert_eq!(
            board.read_pair(0, status, 8, 17).unwrap().unwrap().values,
            [0x0000000200000000, 2]
        );
    }

    #[test]
    fn original_cache_status_reads_the_same_actual_per_plane_way_commands() {
        let mut owner = prepared();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 3, &mut latch);
        for aperture in 0..2 {
            let base = aperture * mcc::APERTURE_BYTES;
            for plane in 0..u64::from(mcc::PLANES) {
                let status = base + plane * mcc::PLANE_STRIDE + 0x1c00;
                assert_eq!(owner.read(status, Width::Word, &mut access), Ok(0));
                owner.write(status, Width::Word, 0, &mut access).unwrap();
                assert_eq!(owner.read(status, Width::Word, &mut access), Ok(0));
                assert!(owner.write(status, Width::Word, 1, &mut access).is_err());
                assert_eq!(owner.read(status, Width::Word, &mut access), Ok(0));
            }
            // Changing broadcast selects scope; it cannot invent powered
            // ways or change the separate original cache-status word.
            owner
                .write(base + 0x10000c, Width::Word, 1, &mut access)
                .unwrap();
            assert_eq!(owner.read(base + 0x1c00, Width::Word, &mut access), Ok(0));
        }
        let original = prepared();
        let mut layout = original.router.lock_layout;
        for invalid in [
            Register {
                offset: 0x10000c,
                mask: 1,
                value: 1,
            },
            Register {
                offset: 0x1c00,
                mask: 1,
                value: 0,
            },
            Register {
                offset: 0x1c00,
                mask: 0x1f,
                value: 1,
            },
        ] {
            layout.cache_status = Some(invalid);
            let controller = original.controller().clone();
            assert!(Router::new(layout, [None; 4], controller, 2).is_err());
        }
    }
}
