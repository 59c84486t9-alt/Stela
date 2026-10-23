//! Retained T602x MCC/AMCC views over actual registered canonical RAM.
//!
//! The complete PTD and auxiliary windows are owned but explicitly refuse:
//! their service/interrupt state is not inferred from the original ADT's
//! physical capacity. Construction is not native PMP admission, a cache grant
//! or a source-supported initial CPU/PMGR handoff. Root owns those joins.
use crate::{
    machine::soc::{MemoryController, T6020Memory},
    memory::{CanonicalRamService, RegisteredSystemRam},
    platform::apple::{
        amcc::{self, Amcc},
        bus::{Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse},
        mcc::t6020::{self, Configuration, Controller, View},
        ptd,
    },
};
use alloc::{string::String, sync::Arc, vec::Vec};

const NAME: &str = "t6020-mcc-amcc";
const PTD_OFFSET: u64 = t6020::MAX_APERTURES as u64 * t6020::APERTURE_BYTES;
const AUXILIARY_OFFSET: u64 = PTD_OFFSET + ptd::PTD_BYTES;

/// One actual RAM owner and one shared controller/lock state. Numeric geometry
/// cannot substitute for this Arc identity or a later live canonical service.
pub struct Prepared {
    descriptor: T6020Memory,
    source_locks: MemoryController,
    locks: Amcc,
    controller: Controller,
    views: Vec<View>,
    registers: Vec<u64>,
    ram: Arc<RegisteredSystemRam>,
    generation: u64,
}
impl Prepared {
    /// Retains actual reservations supplied by the canonical boot owner. The
    /// explicit initial controls/lifecycle describe newly owned Stela state;
    /// they are not observed Apple reset or acknowledged PMGR/PMP effects.
    /// Source power-graph resolution/actual placed PMGR sampling must precede
    /// production placement, and root must retain all writers through teardown.
    pub fn new(
        descriptor: T6020Memory,
        source_locks: MemoryController,
        programmed: amcc::Programmed,
        configuration: Configuration,
        lifecycle: LifecycleState,
        ram: Arc<RegisteredSystemRam>,
    ) -> Result<Self, String> {
        descriptor.validate(&source_locks).map_err(String::from)?;
        validate_ram(&descriptor, &source_locks, programmed, &ram).map_err(String::from)?;
        if source_locks.layout.cache_status
            != Some(amcc::Register {
                offset: t6020::CACHE_STATUS,
                mask: 1,
                value: 0,
            })
        {
            return Err(
                "T602x AMCC cache-status field differs from its original source map".into(),
            );
        }
        let controller = Controller::initialized(
            descriptor.layout().map_err(String::from)?,
            configuration,
            lifecycle,
        )
        .map_err(String::from)?;
        let registers = controller.register_offsets();
        let mut lock_layout = source_locks.layout;
        // A standalone AMCC disabled-bit image must not answer for this
        // controller's still-unqualified cache state. The actual MCC owns all
        // four source cache-status words and refuses without a real producer.
        lock_layout.cache_status = None;
        for group in lock_layout.groups.into_iter().flatten() {
            for register in [
                Some(group.lower_limit),
                Some(group.upper_limit),
                group.enable,
                group.write_disable,
                group.lock,
            ]
            .into_iter()
            .flatten()
            {
                for plane in 0..lock_layout.planes {
                    if registers
                        .contains(&(register.offset + u64::from(plane) * lock_layout.stride))
                    {
                        return Err("T602x controller and AMCC lock registers overlap without a shared protocol".into());
                    }
                }
            }
        }
        let locks = Amcc::new(lock_layout, descriptor.apertures.len(), programmed, None)
            .map_err(String::from)?;
        let views = (0..descriptor.apertures.len())
            .map(|index| controller.view(index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(String::from)?;
        let generation = ram
            .domain()
            .generation()
            .map_err(|_| "T602x canonical RAM generation is not live")?;
        Ok(Self {
            descriptor,
            source_locks,
            locks,
            controller,
            views,
            registers,
            ram,
            generation,
        })
    }
    pub fn descriptor(&self) -> &T6020Memory {
        &self.descriptor
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    pub fn locked_regions(&self) -> amcc::Locked {
        self.locks.locked_regions()
    }
    pub fn controller(&self) -> &Controller {
        &self.controller
    }
    /// All source physical owners, including refused windows. The PTD update
    /// alias stays inside the same bank; never install a second mutable copy.
    pub fn bindings(&self) -> Vec<(u64, u64, u64)> {
        let mut bindings = self
            .descriptor
            .apertures
            .iter()
            .enumerate()
            .map(|(i, &pa)| (pa, t6020::APERTURE_BYTES, i as u64 * t6020::APERTURE_BYTES))
            .collect::<Vec<_>>();
        bindings.push((self.descriptor.ptd.physical, ptd::PTD_BYTES, PTD_OFFSET));
        bindings.push((
            self.descriptor.auxiliary.0,
            self.descriptor.auxiliary.1,
            AUXILIARY_OFFSET,
        ));
        bindings
    }
    fn live_generation(&self) -> Result<(), &'static str> {
        if self
            .ram
            .domain()
            .generation()
            .map_err(|_| "T602x canonical RAM is not live")?
            != self.generation
        {
            return Err("T602x canonical RAM generation changed");
        }
        Ok(())
    }
    fn live(&self) -> Result<(), &'static str> {
        self.live_generation()?;
        let state = self.controller.lifecycle_state();
        if !state.powered || !state.clocked || state.quiesced || state.reset {
            return Err("T602x memory frontend is paused by its actual owner");
        }
        Ok(())
    }
    fn target(&self, offset: u64) -> Result<(usize, u64), &'static str> {
        self.live()?;
        let index = usize::try_from(offset / t6020::APERTURE_BYTES)
            .map_err(|_| "T602x aperture index overflows")?;
        if index >= self.views.len() {
            return Err("T602x access is outside its actual controller apertures");
        }
        Ok((index, offset % t6020::APERTURE_BYTES))
    }
    pub fn requires_ram_read(&self, offset: u64, width: Width) -> bool {
        offset / t6020::APERTURE_BYTES < self.views.len() as u64
            && self
                .controller
                .requires_ram_read(offset % t6020::APERTURE_BYTES, width)
    }
    /// # Safety
    /// Actual native workers/jobs are stopped and fenced, and the same actual
    /// Host/Devices producer cohort is exclusively held through this borrow.
    /// Every synchronous transfer has completed; no raw/unjoined DMA, firmware
    /// or autonomous producer can touch the RAM. Free writer gates alone do not
    /// prove that cohort exclusion or an empty hardware command queue.
    pub unsafe fn read_ram_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64, &'static str> {
        if !self.requires_ram_read(offset, width) {
            return Err("T602x canonical read is not a source DCS drain word");
        }
        if !memory.belongs_to(&self.ram) {
            return Err("T602x drain borrowed a different actual canonical RAM owner");
        }
        memory
            .validate_current()
            .map_err(|_| "T602x drain lost its actual RAM/writer hold")?;
        if memory.generation() != self.generation {
            return Err("T602x drain borrowed a different RAM generation");
        }
        let (aperture, within) = self.target(offset)?;
        self.controller
            .drain_control(aperture, within)
            .map(u64::from)
    }
    /// # Safety
    /// The complete producer-exclusion contract of read_ram_drain holds for
    /// the entire consuming write. It does not retire a DRAM/cache request;
    /// the guest's source330us delay and barriers remain separate operations.
    pub unsafe fn write_ram_drain(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        now: u64,
        memory: &CanonicalRamService<'_>,
    ) -> Result<(), &'static str> {
        // SAFETY: caller holds this exact canonical RAM and producer cohort.
        let expected = unsafe { self.read_ram_drain(offset, width, memory) }?;
        if value != expected {
            return Err("T602x flush must preserve high16 and clear low16 without truncation");
        }
        let (aperture, within) = self.target(offset)?;
        self.controller
            .record_ram_drain(aperture, within, value as u32, now)
    }
}

fn validate_ram(
    descriptor: &T6020Memory,
    locks: &MemoryController,
    programmed: amcc::Programmed,
    ram: &RegisteredSystemRam,
) -> Result<(), &'static str> {
    let mut regions = ram.placements().collect::<Vec<_>>();
    regions.sort_by_key(|&(source, _, _)| source);
    if regions.is_empty() {
        return Err("T602x memory requires actual registered RAM reservations");
    }
    let mut mmio = descriptor
        .apertures
        .iter()
        .map(|&pa| (pa, t6020::APERTURE_BYTES))
        .collect::<Vec<_>>();
    mmio.extend([
        (descriptor.ptd.physical, ptd::PTD_BYTES),
        descriptor.auxiliary,
    ]);
    for &(source, _, bytes) in &regions {
        let end = source
            .checked_add(bytes as u64)
            .ok_or("T602x canonical RAM wraps")?;
        if mmio.iter().any(|&(pa, size)| {
            pa.checked_add(size)
                .is_none_or(|top| pa < end && source < top)
        }) {
            return Err("T602x MMIO overlaps its actual canonical RAM");
        }
    }
    for (index, range) in programmed.into_iter().enumerate() {
        let Some((base, bytes)) = range else {
            continue;
        };
        let group = locks.layout.groups[index].ok_or("T602x programmed an absent lock group")?;
        let page = 1u64
            .checked_shl(group.page_size_shift)
            .ok_or("T602x lock page shift is invalid")?;
        let end = base
            .checked_add(bytes)
            .ok_or("T602x programmed lock wraps")?;
        if bytes == 0 || !base.is_multiple_of(page) || !bytes.is_multiple_of(page) {
            return Err("T602x programmed lock is empty or unaligned");
        }
        let mut cursor = base;
        for &(source, _, bytes) in &regions {
            let top = source
                .checked_add(bytes as u64)
                .ok_or("T602x canonical RAM wraps")?;
            if source <= cursor && cursor < top {
                cursor = end.min(top);
            }
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err("T602x programmed lock is not backed by the same actual RAM");
        }
    }
    Ok(())
}

impl Lifecycle for Prepared {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        self.live_generation()?;
        self.views[0].check_lifecycle(proposed)
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.views[0].set_lifecycle(proposed, access);
    }
}
impl MmioDevice for Prepared {
    fn name(&self) -> &'static str {
        NAME
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        self.live().map_err(fail)?;
        if offset >= PTD_OFFSET {
            return Err(fail(
                "T602x PTD/auxiliary register and interrupt effects require their qualified source owner",
            ));
        }
        let (index, within) = self.target(offset).map_err(fail)?;
        if self.registers.contains(&within) {
            return self.views[index].read(within, width, access);
        }
        if within >= self.source_locks.layout.aperture_bytes {
            return Err(fail("T602x register effect is not qualified"));
        }
        self.locks.read(
            index as u64 * self.source_locks.layout.aperture_bytes + within,
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        self.live().map_err(fail)?;
        if offset >= PTD_OFFSET {
            return Err(fail(
                "T602x PTD/auxiliary register and interrupt effects require their qualified source owner",
            ));
        }
        let (index, within) = self.target(offset).map_err(fail)?;
        if self.registers.contains(&within) {
            return self.views[index].write(within, width, value, access);
        }
        if within >= self.source_locks.layout.aperture_bytes {
            return Err(fail("T602x register effect is not qualified"));
        }
        self.locks.write(
            index as u64 * self.source_locks.layout.aperture_bytes + within,
            width,
            value,
            access,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        machine::soc::PtdBank,
        memory::{ReservedSystemRamRange, source_ram::system::fixture},
        platform::apple::{
            amcc::{Layout, LockGroup, Register},
            interrupt::InterruptLatch,
        },
    };
    use core::{cell::UnsafeCell, ptr::NonNull};
    const RAM: u64 = 0x10000000000;
    #[repr(C, align(16))]
    struct Storage(UnsafeCell<[u8; 0x10000]>);
    // SAFETY: only the joined single-thread authored fixture accesses these
    // stable bytes; there are no native frames, DMA or external publishers.
    unsafe impl Sync for Storage {}
    fn ram(source: u64) -> Arc<RegisteredSystemRam> {
        let storage = Arc::new(Storage(UnsafeCell::new([0; 0x10000])));
        let range = ReservedSystemRamRange {
            source_pa: source,
            host_pa: 0x400000,
            host_base: NonNull::new(storage.0.get().cast()).unwrap(),
            bytes: 0x10000,
        };
        // SAFETY: cfg(test) only. This checks owner identity/geometry and is
        // deliberately not the production CPL0 registration constructor.
        Arc::new(unsafe { fixture(&[range], storage) })
    }
    fn running() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    fn parts(count: usize) -> (T6020Memory, MemoryController, Configuration) {
        let apertures = (0..count)
            .map(|index| {
                if index < 8 {
                    0x200000000 + index as u64 * t6020::APERTURE_BYTES
                } else {
                    0x2200000000 + (index - 8) as u64 * t6020::APERTURE_BYTES
                }
            })
            .collect::<Vec<_>>();
        let descriptor = T6020Memory {
            apertures: apertures.clone(),
            auxiliary: (0x28e4d0000, 0x149c),
            ptd: PtdBank {
                physical: 0x28e3c0000,
                ranges: [14, 18, 28]
                    .into_iter()
                    .enumerate()
                    .map(|(index, id)| ptd::Range {
                        id,
                        start: index as u32,
                        count: 1,
                        name: alloc::format!("r{id}"),
                    })
                    .collect(),
                interrupts: alloc::vec![12, 13, 0],
            },
            updates: (0x28e3d0000, 0x2000),
            entries: 1024,
            alternate_dram: alloc::vec![0x133, 0x55555340],
            mcache_pmp: Some(1),
            dsid_management: Some(1),
            thermal_loop: Some(1),
            memory_ranges: alloc::vec![14, 18],
            smc_ranges: alloc::vec![28],
            command_entries: 2,
            command_ack_entries: 1,
            quota_request_entries: 8,
            quota_response_entries: 8,
        };
        let register = |offset, mask, value| Register {
            offset,
            mask,
            value,
        };
        let locks = MemoryController {
            apertures,
            layout: Layout {
                aperture_bytes: 0x200000,
                planes: 4,
                stride: 0x40000,
                cache_status: Some(register(0x1c00, 1, 0)),
                dram_base: RAM,
                groups: [
                    Some(LockGroup {
                        page_size_shift: 14,
                        lower_limit: register(0x680, 0xfffff, 0),
                        upper_limit: register(0x688, 0xfffff, 0),
                        enable: Some(register(0x690, 1, 1)),
                        write_disable: Some(register(0x694, 1, 1)),
                        lock: Some(register(0x698, 1, 1)),
                    }),
                    None,
                    None,
                    None,
                ],
            },
        };
        let configuration = Configuration::clear_software_controls(descriptor.layout().unwrap());
        (descriptor, locks, configuration)
    }
    fn prepared(count: usize, ram: Arc<RegisteredSystemRam>) -> Prepared {
        let (descriptor, locks, configuration) = parts(count);
        Prepared::new(
            descriptor,
            locks,
            amcc::ctrr_a(Some((RAM, 0x8000))),
            configuration,
            running(),
            ram,
        )
        .unwrap()
    }
    #[test]
    fn complete_sparse_ultra_bindings_keep_ptd_auxiliary_and_both_dies_distinct() {
        for count in [4, 8, 16] {
            let owner = prepared(count, ram(RAM));
            let bindings = owner.bindings();
            assert_eq!(bindings.len(), count + 2);
            assert_eq!(bindings[count], (0x28e3c0000, ptd::PTD_BYTES, PTD_OFFSET));
            assert_eq!(bindings[count + 1], (0x28e4d0000, 0x149c, AUXILIARY_OFFSET));
            if count == 16 {
                assert_eq!(
                    bindings[8],
                    (
                        0x2200000000,
                        t6020::APERTURE_BYTES,
                        8 * t6020::APERTURE_BYTES
                    )
                );
            }
        }
    }
    #[test]
    fn foreign_ram_and_ordinary_mmio_cannot_supply_a_drain_completion() {
        let ram = ram(RAM);
        let mut owner = prepared(16, Arc::clone(&ram));
        let offset =
            15 * t6020::APERTURE_BYTES + t6020::DCS_BASE + 3 * t6020::DCS_STRIDE + t6020::DRAIN;
        let other = self::ram(RAM);
        let foreign = other.try_service().unwrap().unwrap();
        // SAFETY: complete single-thread fixture producer set is stopped.
        assert!(unsafe { owner.read_ram_drain(offset, Width::Word, &foreign) }.is_err());
        let service = ram.try_service().unwrap().unwrap();
        // SAFETY: this exact joined fixture has no frames/independent producer.
        assert_eq!(
            unsafe { owner.read_ram_drain(offset, Width::Word, &service) },
            Ok(0)
        );
        assert!(unsafe { owner.write_ram_drain(offset, Width::Word, 1, 7, &service) }.is_err());
        assert!(owner.controller().drain_receipts().is_empty());
        assert!(unsafe { owner.write_ram_drain(offset, Width::Word, 0, 7, &service) }.is_ok());
        assert_eq!(owner.controller().drain_receipts()[0].aperture, 15);
        drop(service);
        drop(foreign);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 8, &mut latch);
        assert!(owner.read(offset, Width::Word, &mut access).is_err());
        owner
            .write(
                t6020::DCS_BASE + t6020::DRAM_CONFIGURATION,
                Width::Word,
                0x133,
                &mut access,
            )
            .unwrap();
        let service = ram.try_service().unwrap().unwrap();
        // SAFETY: same real fixture hold; the pending controller effect must
        // still refuse even though all canonical RAM writers are excluded.
        assert!(unsafe { owner.read_ram_drain(offset, Width::Word, &service) }.is_err());
    }
    #[test]
    fn retained_pause_resumes_without_reset_or_a_fabricated_cache_status() {
        let mut owner = prepared(4, ram(RAM));
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let before = owner.read(0x680, Width::Word, &mut access).unwrap();
        let pause = LifecycleState {
            clocked: false,
            ..running()
        };
        owner.set_lifecycle(pause, &mut access);
        assert!(owner.read(0x680, Width::Word, &mut access).is_err());
        owner.set_lifecycle(running(), &mut access);
        assert_eq!(owner.read(0x680, Width::Word, &mut access), Ok(before));
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    reset: true,
                    ..running()
                })
                .is_err()
        );
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    retention: false,
                    ..running()
                })
                .is_err()
        );
        for offset in [
            0x1c00,
            0x41c00,
            t6020::CACHE_SIZE,
            PTD_OFFSET,
            AUXILIARY_OFFSET,
        ] {
            assert!(owner.read(offset, Width::Word, &mut access).is_err());
        }
    }
    #[test]
    fn real_ram_geometry_refuses_overlaps_and_foreign_programmed_lock_ranges() {
        let (descriptor, locks, configuration) = parts(4);
        assert!(
            Prepared::new(
                descriptor.clone(),
                locks.clone(),
                [None; 4],
                configuration.clone(),
                running(),
                ram(descriptor.apertures[0])
            )
            .is_err()
        );
        assert!(
            Prepared::new(
                descriptor.clone(),
                locks.clone(),
                amcc::ctrr_a(Some((RAM + 0x10000, 0x4000))),
                configuration.clone(),
                running(),
                ram(RAM)
            )
            .is_err()
        );
        let mut invalid = locks.clone();
        invalid.layout.cache_status = Some(Register {
            offset: 0x10000c,
            mask: 1,
            value: 0,
        });
        assert!(
            Prepared::new(
                descriptor,
                invalid,
                [None; 4],
                configuration,
                running(),
                ram(RAM)
            )
            .is_err()
        );
    }
}
