//! Permanently empty T8112 outer cache, composed with its one actual lock owner.
//!
//! Original 26A434 J473 KC SHA256
//! 06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d:
//! generic zero selection file1c71874..1c719d8; T8112 way waiter
//! 2efd010..2efd234, enable2efd354..2efd5b0, raw flush2efd234..2efd354,
//! direct quota2eff664..2eff924 and occupancy2effa54..2effb34. Exact original
//! windows are retained in t8112-cache-contract-r1/contract.json. This is new
//! software backing, never an Apple reset observation or a nonempty flush.
//! Native quota views: t8112pmp SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c,
//! file0x45e0..0x4664 reads low9 seeds; 0x4e20..0x4e8c writes low9 and
//! optional bits23:16/30. AP file0x2eff890 masks low7 after a full32 read.
//!
//! `_writePerfCtrl` and `_enablePerfCtrl` (file 0x2efe90c, 0x2efeb60) program
//! each window's AMC performance counter configuration at +18000..+18800
//! through `_mccWriteReg64` (0x2efe870), with addresses from the driver's
//! `AMCPerfCounterConfig` table; the words hold their 64-bit writes from a
//! zero handoff. The counters they select count memory events, which no
//! producer supplies, so `_mccReadReg64` reads beyond that block refuse.
use super::amcc::{BROADCAST, LOCK_REGISTERS, LockResource, MMIO_BYTES, Placement, STRIDE};
use crate::platform::apple::pmp::native::cache::publisher;
mod native;
use crate::machine::soc::MemoryController;
use crate::platform::apple::amcc::Locked;
use alloc::{collections::BTreeMap, sync::Arc};
pub use native::QuotaView;
use stela_contracts::bus::Access;
use stela_contracts::bus::Direction;
use stela_contracts::bus::Lifecycle;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::MmioDevice;
use stela_contracts::bus::MmioError;
use stela_contracts::bus::Width;
use stela_contracts::bus::refuse;
use stela_engine::machine::engine::CanonicalDeviceMemory;
use stela_engine::memory::CanonicalRamService;
use stela_engine::memory::RegisteredSystemRam;

const PLANES: usize = 4;
const STATUS: u64 = 0x424;
const WAY_REQUEST: u64 = 0x1c00;
const WAY_STATUS: u64 = 0x1c04;
const FLUSH: u64 = 0x1c2c;
const QUOTAS: u64 = 0xa000;
const OCCUPANCY: u64 = 0xc000;
const WAY_COUNTS: u32 = (0x1f << 10) | (0x1f << 5);
const QUOTA_FIELDS: u32 = 0x1ff | (0xff << 16) | (1 << 30);
const PERF_CONFIG: core::ops::Range<u64> = 0x18000..0x18800;

/// Declared original driver configuration, not a readiness or mount token.
/// The caller must coordinate this selection with the actual live original
/// boot argument/provider input. In particular a conflicting numeric clamp can
/// override ProviderDisabled, while DisableArgument bypasses numeric parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroWayConfiguration {
    DisableArgument,
    ProviderDisabled,
    ClampZero,
}

/// Explicitly initialized software words, not captured or inferred reset state.
/// Counts/flush-busy must be clear because this object owns no outer entries.
/// Other status bits are opaque retained inputs, not newly decoded effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareImage {
    pub way_status: [u32; PLANES],
    pub disabled: [bool; PLANES],
    pub flush_status: [u32; PLANES],
    /// One actual full32 register per group. AP's low7 getter and native
    /// low9 programming/attributes observe this same backing, not two limits.
    pub quota_words: [u32; 32],
}
impl SoftwareImage {
    /// Deliberately allocate clear software words and disabled controls. This
    /// does not assert that Apple firmware or a physical cache had these words.
    pub const fn zeroed_control_image() -> Self {
        Self {
            way_status: [0; PLANES],
            disabled: [true; PLANES],
            flush_status: [0; PLANES],
            quota_words: [0; 32],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushCompletion {
    pub serial: u64,
    pub at: u64,
    pub ram_generation: u64,
}

/// Fixed-size progress. Numeric observations confer no completion authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    pub way_commands: u64,
    pub control_writes: u64,
    pub quota_writes: u64,
    pub completed_flushes: u64,
    pub latest_flush: Option<FlushCompletion>,
}

/// One bus owner for cache AND locks. Consuming LockResource preserves its
/// reached state; there is no separate overlapping lock/cache bus installation.
/// No fill, dirty entry, nonzero-way, capacity or PMP grant path exists here.
pub struct EmptyResource {
    locks: LockResource,
    selection: ZeroWayConfiguration,
    image: SoftwareImage,
    progress: Progress,
    quota_identity: publisher::Identity,
    quota_claimed: bool,
    perf_config: BTreeMap<u64, u64>,
}
impl EmptyResource {
    /// Construct before admitting cache clients, with an actually selected
    /// original zero-way configuration. `selection` declares that input but
    /// cannot verify boot arguments, insert a flag, grant mount admission or
    /// change an observed Apple resource into an empty one. The same retained
    /// DCS/PTD RAM and lock state are consumed without cloning their backing.
    pub fn initialized(
        locks: LockResource,
        selection: ZeroWayConfiguration,
        image: SoftwareImage,
    ) -> Result<Self, &'static str> {
        if image.way_status.iter().any(|value| value & WAY_COUNTS != 0)
            || image.flush_status.iter().any(|value| value & 1 != 0)
            || image
                .quota_words
                .iter()
                .any(|&value| value & !QUOTA_FIELDS != 0)
        {
            return Err(
                "permanently empty T8112 cache image has powered ways, busy flush or invalid quota",
            );
        }
        Ok(Self {
            locks,
            selection,
            image,
            progress: Progress::default(),
            quota_identity: publisher::Identity::new(),
            quota_claimed: false,
            perf_config: BTreeMap::new(),
        })
    }
    pub fn source(&self) -> &MemoryController {
        self.locks.source()
    }
    pub fn placement(&self) -> Placement {
        self.locks.placement()
    }
    pub fn binding(&self) -> (u64, u64, u64) {
        self.locks.binding()
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        self.locks.registered_ram()
    }
    pub fn locked_regions(&self) -> Locked {
        self.locks.locked_regions()
    }
    pub fn locks(&self) -> &LockResource {
        &self.locks
    }
    pub fn configuration(&self) -> ZeroWayConfiguration {
        self.selection
    }
    pub fn image(&self) -> SoftwareImage {
        self.image
    }
    pub fn progress(&self) -> Progress {
        self.progress
    }
    pub fn check_ram_service(&self, memory: &CanonicalRamService<'_>) -> Result<(), &'static str> {
        self.locks.check_ram_service(memory)
    }
    pub fn requires_ram_flush(&self, offset: u64, width: Width) -> bool {
        offset == BROADCAST + FLUSH && width == Width::Word
    }
    /// Consume the source broadcast write1 through the engine's sealed actual
    /// held-memory adapter. Preflight precedes ordering and every cache effect.
    /// The adapter retains all stopped native owners, the closed synchronous
    /// producer set and same RAM generation. Its fence supplies CPU/copyout
    /// visibility; only this object's permanent absence of outer entries makes
    /// its own eviction/writeback effect empty. Neither establishes nonempty
    /// cache eviction, Apple DRAM/DMA effects, a source DSB or any PMP ACK.
    pub fn write_ram_flush(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        at: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<(), &'static str> {
        let completion = self.prepare_flush(offset, width, value, at, memory.memory())?;
        memory.fence_cpu_memory();
        // The exclusive composite borrow excludes control changes. Recheck
        // actual writer/mapping identity after the real adapter's ordering.
        self.check_ram_service(memory.memory())?;
        self.complete_flush(completion);
        Ok(())
    }
    fn prepare_flush(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        at: u64,
        memory: &CanonicalRamService<'_>,
    ) -> Result<FlushCompletion, &'static str> {
        self.check_ram_service(memory)?;
        if !self.requires_ram_flush(offset, width) || value != 1 {
            return Err("empty T8112 flush requires its source broadcast full32 write1");
        }
        if self.image.disabled.iter().any(|&disabled| !disabled) {
            return Err("source raw cache flush requires all actual plane controls disabled");
        }
        let serial = next(self.progress.completed_flushes)?;
        Ok(FlushCompletion {
            serial,
            at,
            ram_generation: memory.generation(),
        })
    }
    fn complete_flush(&mut self, completion: FlushCompletion) {
        // Only a preflighted, actually ordered empty-resource operation reaches
        // this private consumer. Initial idle words are never counted as work.
        self.progress.completed_flushes = completion.serial;
        self.progress.latest_flush = Some(completion);
    }
    fn checked(&self, offset: u64, width: Width) -> Result<(), &'static str> {
        self.locks.accessible()?;
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err("T8112 empty cache requires aligned full32 source words");
        }
        if offset.checked_add(4).is_none_or(|end| end > MMIO_BYTES) {
            return Err("empty cache access exceeds the complete source MMIO union");
        }
        Ok(())
    }
    fn read_cache(&self, offset: u64) -> Result<u64, &'static str> {
        if let Some((plane, register)) = plane(offset) {
            match register {
                STATUS => return Ok(u64::from(self.image.disabled[plane])),
                WAY_STATUS => return Ok(u64::from(self.image.way_status[plane])),
                FLUSH => return Ok(u64::from(self.image.flush_status[plane])),
                _ => {}
            }
        }
        if let Some(group) = table(offset, QUOTAS, 32).or_else(|| {
            offset
                .checked_sub(BROADCAST)
                .and_then(|offset| table(offset, QUOTAS, 32))
        }) {
            return Ok(u64::from(self.image.quota_words[group]));
        }
        if table(offset, OCCUPANCY, 256).is_some() {
            return Ok(0); // No outer tag/data allocation path exists in this owner.
        }
        Err("T8112 capacity, counters, attribution and PMP service effects remain unqualified")
    }
    fn write_cache(&mut self, offset: u64, value: u64) -> Result<(), &'static str> {
        if offset == BROADCAST + WAY_REQUEST {
            if value != 0 {
                return Err(
                    "permanently empty T8112 resource cannot power nonzero or unknown ways",
                );
            }
            self.progress.way_commands = next(self.progress.way_commands)?;
            return Ok(());
        }
        if offset == BROADCAST + STATUS {
            if value > 1 {
                return Err("T8112 enable control has only source bit0 set/clear meaning");
            }
            let count = next(self.progress.control_writes)?;
            self.image.disabled = [value == 1; PLANES];
            self.progress.control_writes = count;
            return Ok(());
        }
        if let Some(group) = offset
            .checked_sub(BROADCAST)
            .and_then(|offset| table(offset, QUOTAS, 32))
        {
            if value & !u64::from(QUOTA_FIELDS) != 0 {
                return Err(
                    "T8112 quota write has fields outside native low9 and retained attributes",
                );
            }
            let count = next(self.progress.quota_writes)?;
            self.image.quota_words[group] = value as u32;
            self.progress.quota_writes = count;
            return Ok(());
        }
        if offset == BROADCAST + FLUSH {
            return Err(
                "raw empty-cache flush requires the actual sealed canonical memory service",
            );
        }
        Err("T8112 cache write has no qualified source effect or native PMP ACK owner")
    }
}
fn next(value: u64) -> Result<u64, &'static str> {
    value
        .checked_add(1)
        .ok_or("empty cache progress exhausted before effects")
}
fn plane(offset: u64) -> Option<(usize, u64)> {
    (offset < STRIDE * PLANES as u64).then_some(((offset / STRIDE) as usize, offset % STRIDE))
}
fn table(offset: u64, base: u64, count: u64) -> Option<usize> {
    let within = offset.checked_sub(base)?;
    (within < count * 4 && within.is_multiple_of(4)).then_some((within / 4) as usize)
}
fn perf_config(offset: u64, width: Width) -> bool {
    width == Width::Double
        && offset.is_multiple_of(8)
        && offset < MMIO_BYTES
        && PERF_CONFIG.contains(&(offset % STRIDE))
}
fn lock_word(offset: u64) -> bool {
    plane(offset).is_some_and(|(_, register)| LOCK_REGISTERS.contains(&register))
}
impl Lifecycle for EmptyResource {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        self.locks.check_lifecycle(proposed)
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        self.locks.set_lifecycle(proposed, access);
    }
}
impl MmioDevice for EmptyResource {
    fn name(&self) -> &'static str {
        "t8112-empty-cache"
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
        let fail = |reason| refuse("t8112-empty-cache", offset, width, Direction::Read, reason);
        if perf_config(offset, width) {
            self.locks.accessible().map_err(fail)?;
            return Ok(self.perf_config.get(&offset).copied().unwrap_or(0));
        }
        self.checked(offset, width).map_err(fail)?;
        if lock_word(offset) {
            return self.locks.read(offset, width, access);
        }
        self.read_cache(offset).map_err(fail)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse("t8112-empty-cache", offset, width, Direction::Write, reason);
        if perf_config(offset, width) {
            self.locks.accessible().map_err(fail)?;
            self.perf_config.insert(offset, value);
            return Ok(());
        }
        self.checked(offset, width).map_err(fail)?;
        if value > u64::from(u32::MAX) {
            return Err(fail(
                "full32 cache/lock write has bits outside its actual source word",
            ));
        }
        if lock_word(offset) {
            return self.locks.write(offset, width, value, access);
        }
        self.write_cache(offset, value).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::super::amcc::tests::{frontend, ram, source};
    use super::*;
    use alloc::boxed::Box;
    use {stela_contracts::bus::Bus, stela_contracts::interrupt::InterruptLatch};

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    fn resource(image: SoftwareImage) -> EmptyResource {
        let owner = frontend(ram());
        let locks = owner
            .initialize_amcc_locks(source(), [None; 4], LIVE)
            .unwrap();
        EmptyResource::initialized(locks, ZeroWayConfiguration::ClampZero, image).unwrap()
    }
    fn access(latch: &mut InterruptLatch) -> Access<'_> {
        Access::new(0, 21, latch)
    }
    fn read(resource: &mut EmptyResource, offset: u64) -> u64 {
        let mut latch = InterruptLatch::new();
        resource
            .read(offset, Width::Word, &mut access(&mut latch))
            .unwrap()
    }
    fn write(resource: &mut EmptyResource, offset: u64, value: u64) {
        let mut latch = InterruptLatch::new();
        resource
            .write(offset, Width::Word, value, &mut access(&mut latch))
            .unwrap();
    }
    #[test]
    fn perf_counter_configuration_holds_64_bit_words_and_counters_refuse() {
        let mut cache = resource(SoftwareImage::zeroed_control_image());
        let mut latch = InterruptLatch::new();
        let mut a = access(&mut latch);
        let word = 5 * STRIDE + 0x18288;
        assert_eq!(cache.read(word, Width::Double, &mut a), Ok(0));
        cache
            .write(word, Width::Double, 0x1100_0000_0000_0021, &mut a)
            .unwrap();
        assert_eq!(
            cache.read(word, Width::Double, &mut a),
            Ok(0x1100_0000_0000_0021)
        );
        assert_eq!(cache.read(0x18288, Width::Double, &mut a), Ok(0));
        for counter in [0x19000, 0x25000] {
            assert!(cache.read(counter, Width::Double, &mut a).is_err());
        }
        assert!(cache.read(0x18004, Width::Double, &mut a).is_err());
    }
    #[test]
    fn empty_composite_consumes_reached_lock_state_and_installs_one_source_union() {
        let owner = frontend(ram());
        let registered = Arc::clone(owner.registered_ram());
        let programmed = [Some((0x800004000, 0x4000)), None, None, None];
        let mut locks = owner
            .initialize_amcc_locks(source(), programmed, LIVE)
            .unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = access(&mut latch);
        for p in 0..4 {
            for word in [0x688, 0x7f0, 0x68c] {
                locks
                    .write(p * STRIDE + word, Width::Word, 1, &mut a)
                    .unwrap();
            }
        }
        let reached = locks.locked_regions();
        let cache = EmptyResource::initialized(
            locks,
            ZeroWayConfiguration::DisableArgument,
            SoftwareImage::zeroed_control_image(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(cache.registered_ram(), &registered));
        assert_eq!(cache.locked_regions(), reached);
        assert_eq!(cache.locks().locked_regions(), reached);
        assert_eq!(cache.configuration(), ZeroWayConfiguration::DisableArgument);
        assert_eq!(cache.binding(), (0x200000000, 0x1000000, 0));
        assert_eq!(cache.source(), &source());
        let mut bus = Bus::new();
        let memory_bindings = owner.bindings();
        bus.install(Box::new(owner), &memory_bindings).unwrap();
        let binding = cache.binding();
        let id = bus.install(Box::new(cache), &[binding]).unwrap();
        assert_eq!(bus.route(binding.0 + 0x680, Width::Word).unwrap().0, id);
        assert_eq!(
            bus.route(binding.0 + BROADCAST + STATUS, Width::Word)
                .unwrap()
                .0,
            id
        );
        assert_ne!(bus.route(memory_bindings[1].0, Width::Word).unwrap().0, id);
        assert!(
            bus.install(
                Box::new(resource(SoftwareImage::zeroed_control_image())),
                &[binding]
            )
            .is_err()
        );
    }
    #[test]
    fn zero_way_request_enable_and_declared_noncount_words_have_distinct_meaning() {
        let image = SoftwareImage {
            way_status: [0x80000001, 2, 4, 8],
            flush_status: [2, 4, 8, 16],
            ..SoftwareImage::zeroed_control_image()
        };
        let mut cache = resource(image);
        assert_eq!(cache.progress(), Progress::default());
        for p in 0..4 {
            assert_eq!(read(&mut cache, p * STRIDE + STATUS), 1);
        }
        write(&mut cache, BROADCAST + WAY_REQUEST, 0);
        for p in 0..4 {
            assert_eq!(
                read(&mut cache, p * STRIDE + WAY_STATUS),
                u64::from(image.way_status[p as usize])
            );
        }
        write(&mut cache, BROADCAST + STATUS, 0);
        for p in 0..4 {
            assert_eq!(read(&mut cache, p * STRIDE + STATUS), 0);
            assert_eq!(
                read(&mut cache, p * STRIDE + WAY_STATUS) & u64::from(WAY_COUNTS),
                0
            );
        }
        write(&mut cache, BROADCAST + STATUS, 1);
        assert_eq!(cache.progress().way_commands, 1);
        assert_eq!(cache.progress().control_writes, 2);
        assert_eq!(cache.progress().completed_flushes, 0);
        for p in 0..4 {
            assert_eq!(
                read(&mut cache, p * STRIDE + FLUSH),
                u64::from(image.flush_status[p as usize])
            );
        }
        let paused = LifecycleState {
            quiesced: true,
            ..LIVE
        };
        let mut latch = InterruptLatch::new();
        cache.set_lifecycle(paused, &mut access(&mut latch));
        assert!(
            cache
                .read(WAY_STATUS, Width::Word, &mut access(&mut latch))
                .is_err()
        );
        cache.set_lifecycle(LIVE, &mut access(&mut latch));
        assert_eq!(cache.image(), image);
        assert!(
            cache
                .check_lifecycle(LifecycleState {
                    retention: false,
                    ..LIVE
                })
                .is_err()
        );
        assert!(
            cache
                .check_lifecycle(LifecycleState {
                    reset: true,
                    ..LIVE
                })
                .is_err()
        );
    }
    #[test]
    fn direct_limits_apply_without_resident_bytes_or_pmp_grants() {
        let mut cache = resource(SoftwareImage::zeroed_control_image());
        for group in 0..32 {
            write(&mut cache, BROADCAST + QUOTAS + 4 * group, group * 4 + 3);
            assert_eq!(read(&mut cache, QUOTAS + 4 * group), group * 4 + 3);
        }
        for dsid in 0..256 {
            assert_eq!(read(&mut cache, OCCUPANCY + 4 * dsid), 0);
        }
        assert_eq!(cache.progress().quota_writes, 32);
        assert_eq!(cache.image().quota_words[31], 127);
        let mut latch = InterruptLatch::new();
        let mut a = access(&mut latch);
        for offset in [
            QUOTAS + 128,
            OCCUPANCY + 1024,
            STRIDE + QUOTAS,
            STRIDE + OCCUPANCY,
            BROADCAST + QUOTAS + 128,
        ] {
            assert!(cache.read(offset, Width::Word, &mut a).is_err());
        }
        assert!(latch.take_aic_inputs().is_empty());
    }
    #[test]
    fn native_and_ap_quota_views_share_full_words_without_truncating_or_shadowing() {
        let mut image = SoftwareImage::zeroed_control_image();
        image.quota_words[3] = 0x4012_0180;
        let mut cache = resource(image);
        let plane = QUOTAS + 3 * 4;
        let broadcast = BROADCAST + plane;
        assert_eq!(read(&mut cache, plane), 0x4012_0180);
        assert_eq!(read(&mut cache, broadcast), 0x4012_0180);
        assert_eq!(cache.progress().quota_writes, 0);
        // The original AP masks low7 in its caller, not in the MMIO read.
        assert_eq!(read(&mut cache, plane) & 0x7f, 0);
        assert_eq!(read(&mut cache, broadcast) & 0x1ff, 384);
        write(&mut cache, broadcast, 0x40fe_01ff);
        assert_eq!(read(&mut cache, plane), 0x40fe_01ff);
        assert_eq!(read(&mut cache, broadcast), 0x40fe_01ff);
        // An AP full32 low7 write replaces the word, including the attributes;
        // a native publisher must retain its own actual source attribute cache.
        write(&mut cache, broadcast, 17);
        assert_eq!(read(&mut cache, plane), 17);
        assert_eq!(read(&mut cache, broadcast), 17);
        assert_eq!(cache.progress().quota_writes, 2);
        assert_eq!(cache.progress().completed_flushes, 0);
        assert_eq!(read(&mut cache, OCCUPANCY + 3 * 4), 0);
        let before = (cache.image(), cache.progress());
        let mut latch = InterruptLatch::new();
        for value in [1 << 9, 1 << 24, 1 << 29, 1 << 31, 1 << 32] {
            assert!(
                cache
                    .write(broadcast, Width::Word, value, &mut access(&mut latch))
                    .is_err()
            );
            assert_eq!((cache.image(), cache.progress()), before);
        }
        cache.set_lifecycle(
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            &mut access(&mut latch),
        );
        assert!(
            cache
                .read(broadcast, Width::Word, &mut access(&mut latch))
                .is_err()
        );
        assert!(
            cache
                .write(broadcast, Width::Word, 31, &mut access(&mut latch))
                .is_err()
        );
        cache.set_lifecycle(LIVE, &mut access(&mut latch));
        assert_eq!(read(&mut cache, plane), 17);
        assert_eq!((cache.image(), cache.progress()), before);
    }
    #[test]
    fn invalid_images_widths_unknown_effects_and_overflow_refuse_before_any_state() {
        for image in [
            SoftwareImage {
                way_status: [1 << 10, 0, 0, 0],
                ..SoftwareImage::zeroed_control_image()
            },
            SoftwareImage {
                way_status: [0, 1 << 5, 0, 0],
                ..SoftwareImage::zeroed_control_image()
            },
            SoftwareImage {
                flush_status: [0, 0, 1, 0],
                ..SoftwareImage::zeroed_control_image()
            },
            SoftwareImage {
                quota_words: [512; 32],
                ..SoftwareImage::zeroed_control_image()
            },
        ] {
            let owner = frontend(ram());
            let locks = owner
                .initialize_amcc_locks(source(), [None; 4], LIVE)
                .unwrap();
            assert!(
                EmptyResource::initialized(locks, ZeroWayConfiguration::ProviderDisabled, image)
                    .is_err()
            );
        }
        let mut cache = resource(SoftwareImage::zeroed_control_image());
        let before = (cache.image(), cache.progress(), cache.locked_regions());
        let mut latch = InterruptLatch::new();
        let mut a = access(&mut latch);
        for (offset, value) in [
            (BROADCAST + WAY_REQUEST, 1),
            (BROADCAST + WAY_REQUEST, u64::MAX),
            (BROADCAST + STATUS, 2),
            (BROADCAST + QUOTAS, 512),
            (BROADCAST + FLUSH, 1),
            (WAY_REQUEST, 0),
            (STATUS, 0),
            (OCCUPANCY, 0),
            (QUOTAS, 0),
            (BROADCAST + 0x13ffc + 4, 1),
            (BROADCAST + 0x13ffc + 4, 2),
            (0x10001c, 0),
            (MMIO_BYTES, 0),
            (u64::MAX - 3, 0),
            (0x680, 1 << 32),
        ] {
            assert!(
                cache.write(offset, Width::Word, value, &mut a).is_err(),
                "{offset:x}/{value:x}"
            );
        }
        for width in [Width::Byte, Width::Half, Width::Double] {
            assert!(cache.write(BROADCAST + STATUS, width, 1, &mut a).is_err());
            assert!(cache.read(WAY_STATUS, width, &mut a).is_err());
        }
        assert!(cache.read(WAY_STATUS + 1, Width::Word, &mut a).is_err());
        assert!(cache.read(0x10001c, Width::Word, &mut a).is_err());
        assert_eq!(
            (cache.image(), cache.progress(), cache.locked_regions()),
            before
        );
        cache.progress.control_writes = u64::MAX;
        assert!(
            cache
                .write(BROADCAST + STATUS, Width::Word, 0, &mut a)
                .is_err()
        );
        assert_eq!(cache.image(), before.0);
        cache.progress.quota_writes = u64::MAX;
        assert!(
            cache
                .write(BROADCAST + QUOTAS, Width::Word, 1, &mut a)
                .is_err()
        );
        assert_eq!(cache.image(), before.0);
        assert!(latch.take_aic_inputs().is_empty());
    }
    #[test]
    fn raw_flush_requires_same_live_ram_disabled_controls_and_bounded_empty_effect() {
        let mut cache = resource(SoftwareImage::zeroed_control_image());
        let actual = Arc::clone(cache.registered_ram());
        let foreign = ram();
        let service = actual.try_service().unwrap().unwrap();
        let other = foreign.try_service().unwrap().unwrap();
        assert!(cache.requires_ram_flush(BROADCAST + FLUSH, Width::Word));
        assert!(!cache.requires_ram_flush(FLUSH, Width::Word));
        assert!(!cache.requires_ram_flush(BROADCAST + FLUSH, Width::Double));
        let before = (cache.image(), cache.progress());
        assert!(
            cache
                .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 1, &other)
                .is_err()
        );
        for (offset, width, value) in [
            (FLUSH, Width::Word, 1),
            (BROADCAST + FLUSH, Width::Half, 1),
            (BROADCAST + FLUSH, Width::Word, 0),
            (BROADCAST + FLUSH, Width::Word, 2),
        ] {
            assert!(
                cache
                    .prepare_flush(offset, width, value, 1, &service)
                    .is_err()
            );
        }
        assert_eq!((cache.image(), cache.progress()), before);
        write(&mut cache, BROADCAST + STATUS, 0);
        assert!(
            cache
                .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 1, &service)
                .is_err()
        );
        write(&mut cache, BROADCAST + STATUS, 1);
        // The fixture has no native PE/DMA/client, so its permanent-empty
        // effect can exercise this private consumer under actual RAM exclusion.
        // Production enters only through the sealed adapter and actual fences.
        for at in 1..=3 {
            let prepared = cache
                .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, at, &service)
                .unwrap();
            cache.complete_flush(prepared);
        }
        assert_eq!(cache.progress().completed_flushes, 3);
        assert_eq!(
            cache.progress().latest_flush,
            Some(FlushCompletion {
                serial: 3,
                at: 3,
                ram_generation: service.generation()
            })
        );
        for p in 0..4 {
            assert_eq!(read(&mut cache, p * STRIDE + FLUSH), 0);
        }
        cache.progress.completed_flushes = u64::MAX;
        let before = cache.progress();
        assert!(
            cache
                .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 4, &service)
                .is_err()
        );
        assert_eq!(cache.progress(), before);
        let mut latch = InterruptLatch::new();
        cache.set_lifecycle(
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            &mut access(&mut latch),
        );
        assert!(
            cache
                .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 4, &service)
                .is_err()
        );
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_native_quota_seed_and_publisher_share_the_broadcast_full_word() {
        let code = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&code),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        for (start, end, hash) in [
            (
                0x426c,
                0x472c,
                "e4971d2db1643fd5fa9412d278d2dbb1ea177f902bba9ec22d4dc41c0fd62a7b",
            ),
            (
                0x4cbc,
                0x4ee8,
                "9d7f54726ce6b42b4f802022a6f3fb0902a2a53cb1f57bdfb028513d67d99ad7",
            ),
            (
                0x33ea8,
                0x33fd0,
                "949295e2f93ed5c1f89e3e2712b07ba2a039d29dcb382a94ba003f35fb258601",
            ),
        ] {
            assert_eq!(stela_formats::sha256(&code[start..end]), hash);
        }
        assert_eq!(
            u64::from_le_bytes(code[0x46360..0x46368].try_into().unwrap()),
            0x200f04000
        );
        // Both the initial seed and later programming use AND W12,#0x1ff.
        for offset in [0x4654, 0x4e60] {
            assert_eq!(
                u32::from_le_bytes(code[offset..offset + 4].try_into().unwrap()),
                0x1200218c
            );
        }
        assert_eq!(0x200f04000 + 0x6000, 0x200000000 + BROADCAST + QUOTAS);
        assert_eq!(QUOTA_FIELDS, 0x40ff_01ff);
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_MCC_J473_KERNELCACHE"]
    fn original_j473_zero_mode_way_flush_quota_and_occupancy_windows_match() {
        let code =
            std::fs::read(std::env::var("STELA_TEST_MCC_J473_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&code),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        for (start, end, hash) in [
            (
                0x1c71874,
                0x1c719d8,
                "d9ec1c82e6e0625634c0eaaf040440f9b97f29d869ab71bba1eaef7d0149cd9a",
            ),
            (
                0x2efd354,
                0x2efd5b0,
                "762b24538ec890d4ecf738385a0a8a0ec10237a9be19149b1cb56488f3321da2",
            ),
            (
                0x2efdf14,
                0x2efdfec,
                "a74c2838255731a373c51d85471f79cc689c26013474e6485f9068abcc4d4ff2",
            ),
            (
                0x2efd010,
                0x2efd234,
                "12fb82ea20b708995577b41fa026705b3e3cd9a7bf4230129aa2f18c1a0a0bc8",
            ),
            (
                0x2efd234,
                0x2efd354,
                "cca95cd9acf337b877c05b5c706b00b731b97ec5b1e3439ed5f0ba4679f71233",
            ),
            (
                0x2eff664,
                0x2eff924,
                "1e9ee5dfb705e2f39efb276e714f60b828b25ad45ee6fb68cb7726bc4a1128d8",
            ),
            (
                0x2effa54,
                0x2effb34,
                "e6aa987254d58eda768ef148602596c4e4583aa7cb77c2b9f2aacc679c7529cd",
            ),
        ] {
            assert_eq!(
                stela_formats::sha256(&code[start..end]),
                hash,
                "{start:x}..{end:x}"
            );
        }
        assert_eq!(&code[0x17dba3..0x17dbaf], b"disable-mcc\0");
        assert_eq!(&code[0x17dbaf..0x17dbbc], b"-disable_mcc\0");
        assert_eq!(&code[0x17dc0f..0x17dc21], b"mcc_clampwaycount\0");
        assert_eq!(WAY_COUNTS, (0x1f << 10) | (0x1f << 5));
        assert_eq!(SoftwareImage::zeroed_control_image().way_status, [0; 4]);
    }
}
