//! Permanently empty T8112 outer cache, composed with its one lock owner.
//!
//! Original 26A434 J473 KC SHA256
//! 06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d:
//! generic zero selection file1c71874..1c719d8; T8112 way waiter
//! 2efd010..2efd234, enable2efd354..2efd5b0, raw flush2efd234..2efd354,
//! direct quota2eff664..2eff924 and occupancy2effa54..2effb34. Original
//! windows are held in t8112-cache-contract-r1/contract.json. This is new
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
use crate::Result;
use crate::platform::apple::pmp::native::cache::publisher;
use stela_contracts::Refusal;
use stela_contracts::refuse;
mod native;
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
use stela_soc_data::amcc::Locked;
use stela_soc_data::board::MemoryController;

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
/// The caller must coordinate this selection with the live original
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
/// Other status bits are opaque kept inputs, not newly decoded effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareImage {
    pub way_status: [u32; PLANES],
    pub disabled: [bool; PLANES],
    pub flush_status: [u32; PLANES],
    /// One full32 register per group. AP's low7 getter and native
    /// low9 programming/attributes observe this same backing, not two limits.
    pub quota_words: [u32; 32],
}
impl SoftwareImage {
    /// Allocate clear software words and disabled controls. This
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

/// Fixed-size progress. Numeric observations confer no completion permission.
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
    /// Construct before admitting cache clients, with a selected
    /// original zero-way configuration. `selection` declares that input but
    /// cannot verify boot arguments, insert a flag, grant mount admission or
    /// change an observed Apple resource into an empty one. The same kept
    /// DCS/PTD RAM and lock state are consumed without cloning their backing.
    pub fn initialized(
        locks: LockResource,
        selection: ZeroWayConfiguration,
        image: SoftwareImage,
    ) -> Result<Self> {
        if image.way_status.iter().any(|value| value & WAY_COUNTS != 0)
            || image.flush_status.iter().any(|value| value & 1 != 0)
            || image
                .quota_words
                .iter()
                .any(|&value| value & !QUOTA_FIELDS != 0)
        {
            return Err(refuse!(
                "permanently empty T8112 cache image has powered ways, busy flush or invalid quota"
            ));
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
    pub fn check_ram_service(&self, memory: &CanonicalRamService<'_>) -> Result<()> {
        self.locks.check_ram_service(memory)
    }
    pub fn requires_ram_flush(&self, offset: u64, width: Width) -> bool {
        offset == BROADCAST + FLUSH && width == Width::Word
    }
    /// Consume the source broadcast write1 through the engine's sealed
    /// held-memory adapter. Preflight precedes ordering and every cache effect.
    /// The adapter keeps all stopped native owners, the closed synchronous
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
    ) -> Result<()> {
        let completion = self.prepare_flush(offset, width, value, at, memory.memory())?;
        memory.fence_cpu_memory();
        // The exclusive composite borrow excludes control changes. Recheck
        // writer/mapping identity after the real adapter's ordering.
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
    ) -> Result<FlushCompletion> {
        self.check_ram_service(memory)?;
        if !self.requires_ram_flush(offset, width) || value != 1 {
            return Err(refuse!(
                "empty T8112 flush requires its source broadcast full32 write1"
            ));
        }
        if self.image.disabled.iter().any(|&disabled| !disabled) {
            return Err(refuse!(
                "source raw cache flush requires all actual plane controls disabled"
            ));
        }
        let serial = next(self.progress.completed_flushes)?;
        Ok(FlushCompletion {
            serial,
            at,
            ram_generation: memory.generation(),
        })
    }
    fn complete_flush(&mut self, completion: FlushCompletion) {
        // Only a preflighted, ordered empty-resource operation reaches
        // this private consumer. Initial idle words are never counted as work.
        self.progress.completed_flushes = completion.serial;
        self.progress.latest_flush = Some(completion);
    }
    fn checked(&self, offset: u64, width: Width) -> Result<()> {
        self.locks.accessible()?;
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(refuse!(
                "T8112 empty cache requires aligned full32 source words"
            ));
        }
        if offset.checked_add(4).is_none_or(|end| end > MMIO_BYTES) {
            return Err(refuse!(
                "empty cache access exceeds the complete source MMIO union"
            ));
        }
        Ok(())
    }
    fn read_cache(&self, offset: u64) -> Result<u64> {
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
        Err(refuse!(
            "T8112 capacity, counters, attribution and PMP service effects remain unqualified"
        ))
    }
    fn write_cache(&mut self, offset: u64, value: u64) -> Result<()> {
        if offset == BROADCAST + WAY_REQUEST {
            if value != 0 {
                return Err(refuse!(
                    "permanently empty T8112 resource cannot power nonzero or unknown ways"
                ));
            }
            self.progress.way_commands = next(self.progress.way_commands)?;
            return Ok(());
        }
        if offset == BROADCAST + STATUS {
            if value > 1 {
                return Err(refuse!(
                    "T8112 enable control has only source bit0 set/clear meaning"
                ));
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
                return Err(refuse!(
                    "T8112 quota write has fields outside native low9 and retained attributes"
                ));
            }
            let count = next(self.progress.quota_writes)?;
            self.image.quota_words[group] = value as u32;
            self.progress.quota_writes = count;
            return Ok(());
        }
        if offset == BROADCAST + FLUSH {
            return Err(refuse!(
                "raw empty-cache flush requires the actual sealed canonical memory service"
            ));
        }
        Err(refuse!(
            "T8112 cache write has no qualified source effect or native PMP ACK owner"
        ))
    }
}
fn next(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or(refuse!("empty cache progress exhausted before effects"))
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
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
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
        let fail =
            |reason: Refusal| refuse("t8112-empty-cache", offset, width, Direction::Read, reason);
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
        let fail =
            |reason: Refusal| refuse("t8112-empty-cache", offset, width, Direction::Write, reason);
        if perf_config(offset, width) {
            self.locks.accessible().map_err(fail)?;
            self.perf_config.insert(offset, value);
            return Ok(());
        }
        self.checked(offset, width).map_err(fail)?;
        if value > u64::from(u32::MAX) {
            return Err(fail(refuse!(
                "full32 cache/lock write has bits outside its actual source word"
            )));
        }
        if lock_word(offset) {
            return self.locks.write(offset, width, value, access);
        }
        self.write_cache(offset, value).map_err(fail)
    }
}

#[cfg(test)]
mod tests;
