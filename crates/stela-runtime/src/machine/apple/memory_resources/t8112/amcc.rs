//! Independent T8112 AMCC lock ownership, without a successful cache facade.
//!
//! Original 26A434 J473 iBoot SHA256
//! 082cf7b48f9827daefcb5a58e7fd0038aae00b3fe6d36db9ff1528ba3f3a3a3b:
//! builder 0x378d4..0x37a18 declares the aperture, four planes, status and
//! CTRR-A registers. Original J473 ADT separately places MCC shared/broadcast
//! windows and DCS/PTD. See docs/research/apple-mcc.md for the source contract
//! and missing all-access cache accounting. No Apple firmware is executed.
use super::Prepared;
use crate::platform::apple::amcc::Amcc;
use alloc::sync::Arc;
use stela_contracts::bus::Access;
use stela_contracts::bus::Direction;
use stela_contracts::bus::Lifecycle;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::MmioDevice;
use stela_contracts::bus::MmioError;
use stela_contracts::bus::Width;
use stela_contracts::bus::refuse;
use stela_engine::memory::CanonicalRamService;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::amcc::Locked;
use stela_soc_data::amcc::Programmed;
use stela_soc_data::amcc::Register;
use stela_soc_data::board::MemoryController;

const PLANES: u32 = 4;
pub(super) const STRIDE: u64 = 0x40000;
const APERTURE_BYTES: u64 = 0xf40000;
const SHARED: (u64, u64) = (0x100000, 0x80000);
pub(super) const BROADCAST: u64 = 0xf00000;
const BROADCAST_BYTES: u64 = 0x100000;
pub(super) const MMIO_BYTES: u64 = BROADCAST + BROADCAST_BYTES;
const DCS_OFFSET: u64 = 0x1000000;
const CACHE_STATUS: u64 = 0x424;
pub(super) const LOCK_REGISTERS: [u64; 5] = [0x680, 0x684, 0x688, 0x68c, 0x7f0];

/// Source placement only; these spans report no installed cache capacity,
/// allocated ways, resident data, quota grant or completed controller command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub aperture: (u64, u64),
    /// Union of iBoot's aperture and the complete original MCC broadcast view.
    pub window: (u64, u64),
    pub planes: (u64, u64),
    pub shared: (u64, u64),
    pub broadcast: (u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheRequirement {
    AllAccessAccounting,
}
impl CacheRequirement {
    pub const fn reason(self) -> &'static str {
        "T8112 cache requires all-access client-to-DSID/group attribution and owned tag/data, occupancy and dirty-writeback effects"
    }
}

/// A newly initialized software lock image, associated with the existing
/// DCS/PTD RAM owner.
/// Do not clone the lock model into another state bank or assign the DCS/PTD
/// publication ID as this resource's distinct memory-controller identity.
pub struct LockResource {
    source: MemoryController,
    placement: Placement,
    ram: Arc<RegisteredSystemRam>,
    model: Amcc,
    lifecycle: LifecycleState,
}
impl LockResource {
    pub(super) fn initialized(
        owner: &Prepared,
        source: MemoryController,
        programmed: Programmed,
        lifecycle: LifecycleState,
    ) -> Result<Self, &'static str> {
        if lifecycle.reset || !lifecycle.retention {
            return Err("T8112 AMCC requires explicit retained initialized lock state");
        }
        let [physical] = source.apertures[..] else {
            return Err("T8112 AMCC lock join requires its one source aperture");
        };
        let layout = source.layout;
        let limit = |offset| Register {
            offset,
            mask: u32::MAX,
            value: 0,
        };
        let bit = |offset| Register {
            offset,
            mask: 1,
            value: 1,
        };
        let Some(group) = layout.groups[0] else {
            return Err("T8112 AMCC source omits CTRR-A");
        };
        if layout.planes != PLANES
            || layout.stride != STRIDE
            || layout.aperture_bytes != APERTURE_BYTES
            || layout.cache_status != Some(bit(CACHE_STATUS))
            || layout.groups[1..].iter().any(Option::is_some)
            || group.page_size_shift != 14
            || group.lower_limit != limit(0x680)
            || group.upper_limit != limit(0x684)
            || group.enable != Some(bit(0x688))
            || group.lock != Some(bit(0x68c))
            || group.write_disable != Some(bit(0x7f0))
            || owner.descriptor.cache.shared != SHARED
            || owner.descriptor.cache.broadcast != BROADCAST
        {
            return Err("T8112 AMCC lock/cache placement differs from its original source profile");
        }
        let end = physical
            .checked_add(MMIO_BYTES)
            .ok_or("T8112 AMCC aperture overflows")?;
        if !physical.is_multiple_of(STRIDE)
            || physical.checked_add(DCS_OFFSET) != Some(owner.descriptor.channels.0)
        {
            return Err("T8112 AMCC planes and DCS do not share their source physical placement");
        }
        let ptd = owner.descriptor.ptd.physical;
        if physical < ptd + stela_soc_data::ptd::PTD_BYTES && ptd < end {
            return Err("T8112 AMCC ownership overlaps the actual PTD bank");
        }
        for (start, _, bytes) in owner.ram.placements() {
            let top = start
                .checked_add(bytes as u64)
                .ok_or("canonical RAM extent overflows")?;
            if physical < top && start < end {
                return Err("T8112 AMCC ownership overlaps its canonical guest RAM");
            }
        }
        for (start, bytes) in programmed.into_iter().flatten() {
            let top = start
                .checked_add(bytes)
                .ok_or("AMCC programmed region overflows")?;
            if bytes == 0 || !covers(&owner.ram, start, top) {
                return Err("AMCC programmed region is outside its actual canonical RAM");
            }
        }
        // The caller declares limits and clear controls in NEW software backing.
        // This is not kept Apple reset state. Strip the status descriptor
        // internally so even the lock-only leaf cannot leak its legacy default.
        let mut lock_layout = layout;
        lock_layout.cache_status = None;
        let model = Amcc::new(lock_layout, 1, programmed, None)?;
        Ok(Self {
            source,
            placement: Placement {
                aperture: (physical, APERTURE_BYTES),
                window: (physical, MMIO_BYTES),
                planes: (physical, STRIDE * u64::from(PLANES)),
                shared: (physical + SHARED.0, SHARED.1),
                broadcast: (physical + BROADCAST, BROADCAST_BYTES),
            },
            ram: Arc::clone(&owner.ram),
            model,
            lifecycle,
        })
    }
    pub fn source(&self) -> &MemoryController {
        &self.source
    }
    pub fn placement(&self) -> Placement {
        self.placement
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    pub fn binding(&self) -> (u64, u64, u64) {
        (self.placement.window.0, self.placement.window.1, 0)
    }
    pub fn locked_regions(&self) -> Locked {
        self.model.locked_regions()
    }
    pub fn cache_requirement(&self) -> CacheRequirement {
        CacheRequirement::AllAccessAccounting
    }
    /// Identity/generation preflight only. A held synchronous RAM service does
    /// not prove outer-cache residency, flush, invalidate, quota or source DSB.
    pub fn check_ram_service(&self, memory: &CanonicalRamService<'_>) -> Result<(), &'static str> {
        self.accessible()?;
        if !memory.belongs_to(&self.ram) {
            return Err("AMCC borrowed another actual canonical RAM owner");
        }
        memory
            .validate_current()
            .map_err(|_| "AMCC lost its actual RAM generation/writer hold")
    }
    pub(super) fn accessible(&self) -> Result<(), &'static str> {
        let state = self.lifecycle;
        if !state.powered || !state.clocked || state.quiesced || state.reset {
            return Err("T8112 AMCC lock resource is paused by its actual lifecycle owner");
        }
        Ok(())
    }
    fn check(&self, offset: u64, width: Width, direction: Direction) -> Result<(), MmioError> {
        let fail = |reason| refuse(self.name(), offset, width, direction, reason);
        self.accessible().map_err(fail)?;
        if offset
            .checked_add(width.bytes())
            .is_none_or(|end| end > MMIO_BYTES)
        {
            return Err(fail(
                "AMCC access exceeds its source aperture/broadcast union",
            ));
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail(
                "AMCC lock access requires one aligned full32 source word",
            ));
        }
        if offset >= STRIDE * u64::from(PLANES) || !LOCK_REGISTERS.contains(&(offset % STRIDE)) {
            return Err(fail(self.cache_requirement().reason()));
        }
        Ok(())
    }
}
fn covers(ram: &RegisteredSystemRam, start: u64, end: u64) -> bool {
    let mut covered = start;
    let mut ranges: alloc::vec::Vec<_> = ram.placements().collect();
    ranges.sort_unstable_by_key(|range| range.0);
    for (base, _, bytes) in ranges {
        let Some(top) = base.checked_add(bytes as u64) else {
            return false;
        };
        if base > covered {
            break;
        }
        if top > covered {
            covered = top.min(end);
        }
        if covered == end {
            return true;
        }
    }
    false
}
impl Lifecycle for LockResource {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset || !proposed.retention {
            return Err(
                "T8112 AMCC destructive reset/power loss has no qualified lock/cache owner",
            );
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.lifecycle = proposed;
    }
}
impl MmioDevice for LockResource {
    fn name(&self) -> &'static str {
        "t8112-amcc-locks"
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
        self.check(offset, width, Direction::Read)?;
        self.model.read(offset, width, access)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.check(offset, width, Direction::Write)?;
        self.model.write(offset, width, value, access)
    }
}

#[cfg(test)]
pub(in crate::machine::apple) mod tests {
    use super::super::tests::{configuration, descriptor, ram_at};
    use super::*;
    use alloc::{boxed::Box, vec};
    use core::{cell::UnsafeCell, ptr::NonNull};
    use stela_contracts::interrupt::InterruptLatch;
    use stela_engine::memory::ReservedSystemRamRange;
    use stela_engine::memory::system_ram::fixture;
    use stela_soc_data::amcc::Layout;
    use stela_soc_data::amcc::LockGroup;
    const BASE: u64 = 0x200000000;
    const RAM: u64 = 0x800000000;
    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    #[repr(C, align(16))]
    struct Storage(UnsafeCell<[u8; 0x8000]>);
    // SAFETY: the fixture transfers these stable, disjoint bytes to registration.
    unsafe impl Sync for Storage {}
    pub(in crate::machine::apple) fn ram() -> Arc<RegisteredSystemRam> {
        let storage = Arc::new(Storage(UnsafeCell::new([0; 0x8000])));
        let range = ReservedSystemRamRange {
            source_pa: RAM,
            host_pa: 0x400000,
            bytes: 0x8000,
            host_base: NonNull::new(storage.0.get().cast()).unwrap(),
        };
        // SAFETY: no PE or independent producer exists; fixture owns all bytes.
        Arc::new(unsafe { fixture(&[range], storage) })
    }
    pub(in crate::machine::apple) fn source() -> MemoryController {
        let limit = |offset| Register {
            offset,
            mask: u32::MAX,
            value: 0,
        };
        let bit = |offset| Register {
            offset,
            mask: 1,
            value: 1,
        };
        MemoryController {
            apertures: vec![BASE],
            layout: Layout {
                aperture_bytes: APERTURE_BYTES,
                planes: PLANES,
                stride: STRIDE,
                cache_status: Some(bit(CACHE_STATUS)),
                dram_base: RAM,
                groups: [
                    Some(LockGroup {
                        page_size_shift: 14,
                        lower_limit: limit(0x680),
                        upper_limit: limit(0x684),
                        enable: Some(bit(0x688)),
                        write_disable: Some(bit(0x7f0)),
                        lock: Some(bit(0x68c)),
                    }),
                    None,
                    None,
                    None,
                ],
            },
        }
    }
    pub(in crate::machine::apple) fn frontend(ram: Arc<RegisteredSystemRam>) -> Prepared {
        let mut d = descriptor();
        d.cache.shared = SHARED;
        d.cache.broadcast = BROADCAST;
        Prepared::initialized(d, configuration(), LIVE, ram).unwrap()
    }
    #[test]
    fn one_source_aperture_has_checked_distinct_plane_shared_and_broadcast_placement() {
        let owner = frontend(ram());
        let lock = owner
            .initialize_amcc_locks(source(), [None; 4], LIVE)
            .unwrap();
        assert!(Arc::ptr_eq(lock.registered_ram(), owner.registered_ram()));
        assert_eq!(lock.binding(), (BASE, MMIO_BYTES, 0));
        assert_eq!(
            lock.placement(),
            Placement {
                aperture: (BASE, APERTURE_BYTES),
                window: (BASE, MMIO_BYTES),
                planes: (BASE, 0x100000),
                shared: (BASE + 0x100000, 0x80000),
                broadcast: (BASE + 0xf00000, BROADCAST_BYTES),
            }
        );
        assert_eq!(lock.source(), &source());
        assert!(owner.notifications().owns(owner.publication_bank()));
        let mut bus = stela_contracts::bus::Bus::new();
        let memory = owner.bindings();
        bus.install(Box::new(owner), &memory).unwrap();
        let lock_binding = lock.binding();
        bus.install(Box::new(lock), &[lock_binding]).unwrap();
        assert_ne!(
            bus.route(BASE + 0x680, Width::Word).unwrap().0,
            bus.route(memory[1].0, Width::Word).unwrap().0
        );
    }
    #[test]
    fn invalid_profile_placement_or_programmed_ram_refuses_before_installation() {
        let owner = frontend(ram());
        let original = source();
        let mut variants = vec![];
        let mut d = original.clone();
        d.apertures.push(BASE + APERTURE_BYTES);
        variants.push(d);
        let mut d = original.clone();
        d.apertures[0] += STRIDE;
        variants.push(d);
        let mut d = original.clone();
        d.apertures[0] = u64::MAX;
        variants.push(d);
        let mut d = original.clone();
        d.layout.stride /= 2;
        variants.push(d);
        let mut d = original.clone();
        d.layout.aperture_bytes -= 4;
        variants.push(d);
        let mut d = original.clone();
        d.layout.cache_status = None;
        variants.push(d);
        let mut d = original.clone();
        d.layout.groups[0].as_mut().unwrap().write_disable = None;
        variants.push(d);
        let mut d = original.clone();
        d.layout.groups[1] = d.layout.groups[0];
        variants.push(d);
        for d in variants {
            assert!(owner.initialize_amcc_locks(d, [None; 4], LIVE).is_err());
        }
        for programmed in [
            Some((RAM, 0)),
            Some((RAM + 0x4000, 0x8000)),
            Some((RAM + 4, 0x4000)),
            Some((u64::MAX - 3, 16)),
        ] {
            assert!(
                owner
                    .initialize_amcc_locks(original.clone(), [programmed, None, None, None], LIVE)
                    .is_err()
            );
        }
        let mut wrong = descriptor();
        wrong.cache.shared = SHARED;
        wrong.cache.broadcast = BROADCAST - STRIDE;
        let wrong = Prepared::initialized(wrong, configuration(), LIVE, ram()).unwrap();
        assert!(
            wrong
                .initialize_amcc_locks(original.clone(), [None; 4], LIVE)
                .is_err()
        );
        let overlapping = frontend(ram_at(BASE + 0x80000));
        assert!(
            overlapping
                .initialize_amcc_locks(original, [None; 4], LIVE)
                .is_err()
        );
    }
    #[test]
    fn initialized_limits_and_reached_lock_effects_survive_pause_and_refuse_reprogramming() {
        let owner = frontend(ram());
        let programmed = [Some((RAM + 0x4000, 0x4000)), None, None, None];
        let mut lock = owner
            .initialize_amcc_locks(source(), programmed, LIVE)
            .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 9, &mut latch);
        assert_eq!(lock.locked_regions(), [None; 4]);
        for plane in 0..PLANES {
            let base = u64::from(plane) * STRIDE;
            assert_eq!(lock.read(base + 0x680, Width::Word, &mut access), Ok(1));
            assert_eq!(lock.read(base + 0x684, Width::Word, &mut access), Ok(1));
            for word in [0x688, 0x7f0, 0x68c] {
                assert_eq!(lock.read(base + word, Width::Word, &mut access), Ok(0));
                lock.write(base + word, Width::Word, 1, &mut access)
                    .unwrap();
            }
            assert!(
                lock.write(base + 0x680, Width::Word, 2, &mut access)
                    .is_err()
            );
            assert!(
                lock.write(base + 0x688, Width::Word, 0, &mut access)
                    .is_err()
            );
        }
        let expected = [Some((RAM + 0x4000, RAM + 0x7fff)), None, None, None];
        assert_eq!(lock.locked_regions(), expected);
        let paused = LifecycleState {
            quiesced: true,
            ..LIVE
        };
        lock.set_lifecycle(paused, &mut access);
        assert!(lock.read(0x680, Width::Word, &mut access).is_err());
        assert_eq!(lock.locked_regions(), expected);
        lock.set_lifecycle(LIVE, &mut access);
        assert_eq!(lock.read(0x68c, Width::Word, &mut access), Ok(1));
        assert!(
            lock.check_lifecycle(LifecycleState {
                reset: true,
                ..LIVE
            })
            .is_err()
        );
        assert!(
            lock.check_lifecycle(LifecycleState {
                retention: false,
                ..LIVE
            })
            .is_err()
        );
        assert_eq!(owner.publication_bank().lifecycle_state(), LIVE);
    }
    #[test]
    fn cache_status_quotas_capacity_flush_and_firmware_effects_stay_unknown_under_ram_hold() {
        let ram = ram();
        let owner = frontend(Arc::clone(&ram));
        let mut lock = owner
            .initialize_amcc_locks(source(), [None; 4], LIVE)
            .unwrap();
        let foreign = self::ram();
        let service = ram.try_service().unwrap().unwrap();
        let other = foreign.try_service().unwrap().unwrap();
        assert_eq!(lock.check_ram_service(&service), Ok(()));
        assert!(lock.check_ram_service(&other).is_err());
        assert_eq!(
            lock.cache_requirement(),
            CacheRequirement::AllAccessAccounting
        );
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 4, &mut latch);
        for offset in [
            CACHE_STATUS,
            0x1c00,
            0x1c04,
            0x1c2c,
            0xa000,
            0x14000,
            SHARED.0 + 0x1c,
            BROADCAST + 0x1c00,
            BROADCAST + 0x1c2c,
            BROADCAST + 0xa000,
            APERTURE_BYTES,
            MMIO_BYTES - 4,
            MMIO_BYTES,
        ] {
            assert!(lock.read(offset, Width::Word, &mut access).is_err());
            assert!(lock.write(offset, Width::Word, 0, &mut access).is_err());
            assert!(lock.write(offset, Width::Word, 1, &mut access).is_err());
        }
        for width in [Width::Byte, Width::Half, Width::Double] {
            assert!(lock.read(0x680, width, &mut access).is_err());
            assert!(lock.write(0x680, width, 0, &mut access).is_err());
        }
        assert_eq!(lock.locked_regions(), [None; 4]);
        assert!(latch.take_aic_inputs().is_empty());
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_IBOOT_J473, STELA_TEST_MCC_J473_DT"]
    fn original_j473_iboot_lock_map_and_mcc_views_check_the_independent_owner() {
        use stela_contracts::adt::Node;
        let data = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&data),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let io = Node::root(&data).unwrap().child("arm-io").unwrap();
        let mcc = io.child("mcc").unwrap().pairs("reg").unwrap();
        let original = source();
        let base = original.apertures[0];
        let physical = |i: usize| (io.translate_range(mcc[i].0, mcc[i].1).unwrap(), mcc[i].1);
        assert_eq!(physical(1), (base, STRIDE * u64::from(PLANES)));
        assert_eq!(physical(0), (base + SHARED.0, SHARED.1));
        assert_eq!(physical(3), (base + BROADCAST, 0x100000));
        assert_eq!(physical(2), (base + DCS_OFFSET, 0x2000000));
        // The DT broadcast view extends beyond iBoot's lock aperture. The
        // complete source union grants no cache or additional lock semantics.
        let code = std::fs::read(std::env::var("STELA_TEST_IBOOT_J473").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&code),
            "082cf7b48f9827daefcb5a58e7fd0038aae00b3fe6d36db9ff1528ba3f3a3a3b"
        );
        for (offset, value) in [
            (0x378dc, 0x52a01e88u32),
            (0x378e0, 0x52800089),
            (0x378e8, 0x52a00088),
            (0x37930, 0x52808489),
            (0x379a0, 0x5280d009),
            (0x379c4, 0x5280d089),
            (0x379dc, 0x5280d109),
            (0x379f4, 0x5280fe09),
            (0x37a0c, 0x5280d189),
        ] {
            assert_eq!(
                u32::from_le_bytes(code[offset..offset + 4].try_into().unwrap()),
                value
            );
        }
        let owner = frontend(ram());
        let lock = owner
            .initialize_amcc_locks(original, [None; 4], LIVE)
            .unwrap();
        assert_eq!(lock.placement().shared, physical(0));
        assert_eq!(lock.placement().broadcast, physical(3));
        assert_eq!(lock.binding(), (base, DCS_OFFSET, 0));
        assert_eq!(
            lock.cache_requirement(),
            CacheRequirement::AllAccessAccounting
        );
    }
}
