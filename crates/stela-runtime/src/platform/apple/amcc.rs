//! The AMCC memory controller aperture: the cache status and the CTRR-A to
//! CTRR-D lock groups of every plane, as iBoot describes them in
//! `/chosen/lock-regs/amcc` (`machine::soc::MemoryController`), and, when the
//! DeviceTree shows the `mcc,t8112` memory cache controller, the registers
//! its driver programs.
//!
//! No public source documents the AMCC. The lock register map is iBoot's
//! (26A434 `iBoot.j473.RELEASE` builds it, `stela_loader::lock_regs`); the
//! behavior comes from SPTM 26A434 `ctrr_map_lock_group` and
//! `ctrr_lock_boot`:
//!
//! - each plane's cache-status register reads `value` under `mask` while
//!   the cache is disabled, which SPTM asserts before the lockdown; iBoot
//!   leaves it disabled on this boot (no `early-memcache-enable`);
//! - a group's lower and upper limit registers hold the region iBoot
//!   programs, in pages of `1 << page-size-shift` bytes from the DRAM base,
//!   upper inclusive, the same on every plane;
//! - SPTM finds enable, write-disable and lock clear, then sets them in that
//!   order on every plane.
//!
//! The M1 to M3 describe CTRR-A alone, which SPTM locks. The M4 and later
//! describe CTRR-A to D (`stela_loader::lock_regs`). Their SPTM (T8132
//! link addresses; T6041, T8140, T8142, T6050 and T8152 carry the same
//! code and messages) reads all four groups (`0x...cab04..0x...cab48`,
//! register reader `0x...cae6c`: lower, upper and lock required, enable and
//! write-disable optional), requires every aperture's and plane's limits to
//! agree, and requires CTRR-C's and, unless `kernel-ctrr-to-be-enabled` is
//! 0, CTRR-D's limits to name the regions iBoot locked into the clusters'
//! CTRR-C/D copies ("AMCC [%p-%p] and ACC [%p-%p] CTRR-C regions don't
//! match", `0x...e8e00..0x...e90bc`). `ctrr_lock_sptm` (`0x...c7234`) then
//! asserts CTRR-C and D unlocked (`0x...caff8`: write-disable and lock
//! read clear on every plane) and locks CTRR-C (`0x...cb130` with group 2:
//! enable, write-disable and lock written on every plane, last plane
//! first), and `0x...c7460` does the same for CTRR-D. No component writes
//! CTRR-A or B on these chips: they keep what iBoot leaves (the bundle's
//! CTRR-A region, CTRR-B zero).
//!
//! Inferred from that order: write-disable freezes the limits and lock
//! freezes the group, so a change after either stops, because what hardware
//! does is not documented. Once a group's enable or write-disable is set its
//! region is taken as locked against writes from any requester, which the
//! engine applies to every PE (`machine::mmu::Ctrr`), each group's region
//! on its own.
//!
//! The memory cache ([`Cache`]) follows the 26A434 J473AP
//! `AppleT8112MemCacheController` driver, which reaches each plane through
//! `/arm-io/mcc` `reg[1]`, the registers the planes share through `reg[0]`
//! and every plane at once through the broadcast window `reg[3]`:
//!
//! - `mccEnableCacheMode` writes the ways to power to broadcast `0x1c00`
//!   (at most 16) and `_mccWaitForWaysPwrOn` waits until each plane's
//!   `0x1c04` shows that many data ways in bits 14:10 and tag ways in 9:5;
//!   then it clears the cache-status register to enable the cache, and
//!   disabling writes 0 ways;
//! - `_cacheFlush` sets cache-status (disabling the cache) and broadcast
//!   `0x1c2c`, then waits for each plane's `0x1c2c` bit 0 to clear;
//! - `readCacheSize` reads the size in MiB from bits 15:8 of shared `0x1c`;
//! - `setDSIDGroupQuota` writes group `n`'s quota, in 128 KiB units, to
//!   broadcast `0xa000 + 4n`, which `getDSIDGroupQuota` reads back;
//! - the performance counter, DSID profiling and group timeout registers
//!   hold the configuration the driver writes, and the event counters read
//!   what they counted.
//!
//! The model keeps no cached data: guest memory is the host's, coherent for
//! every requester, so powering ways takes effect at once, a flush has
//! nothing to write back and completes at once, and no event is counted.
//! `_mccDramAccessDisable` (kernel file 0x2efdfec) writes full32 zero at
//! DT reg[3]+410, disabling DRAM access through all broadcast planes. The
//! model records that state and requests a guest stop before further RAM
//! execution: post-disable access and re-enable behavior are not established.
//! This uses the bus's reset/stop request boundary, never a host reset.
//! Readback, nonzero encodings and other widths refuse without effects.
//! Every other register of the aperture refuses.
use super::regfile::{self, Held, Span};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{Ordering, fence};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError,
    stela_contracts::bus::Transition, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

const NAME: &str = "amcc";
const DRAM_ACCESS: u64 = 0x410;

use stela_soc_data::amcc::Cache;
use stela_soc_data::amcc::GROUPS;
use stela_soc_data::amcc::Layout;
#[cfg(test)]
use stela_soc_data::amcc::LockGroup;
use stela_soc_data::amcc::Locked;
use stela_soc_data::amcc::Programmed;
use stela_soc_data::amcc::Register;
#[cfg(test)]
use stela_soc_data::amcc::ctrr_a;

/// What a plane or shared register of the memory cache means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    DsidInvalidate,
    DramAccess,
    /// The ways to power.
    Ways,
    /// The powered data and tag ways.
    PoweredWays,
    /// Bit 0 starts a flush and reads set until it completes.
    Flush,
    /// The size in MiB in bits 15:8.
    Size,
    /// Holds what the driver writes.
    Held,
    /// Counts events.
    Counter,
}

const MIB: u64 = 1 << 20;

/// The `mcc,t8112` plane registers besides the lock-regs ones.
const T8112_PLANE: [Span<Role>; 14] = [
    Span::new(DRAM_ACCESS, DRAM_ACCESS + 4, Width::Word, Role::DramAccess),
    Span::new(0x1c00, 0x1c04, Width::Word, Role::Ways),
    Span::new(0x1c04, 0x1c08, Width::Word, Role::PoweredWays),
    Span::new(0x1c2c, 0x1c30, Width::Word, Role::Flush),
    // DSID group quotas (32 groups) and the group timeout.
    Span::new(0xa000, 0xa080, Width::Word, Role::Held),
    Span::new(0xa820, 0xa824, Width::Word, Role::Held),
    // Original G14G firmware type3 +fffc+4*DSID, with the source
    // descriptor rooted at the MCC broadcast aperture +4000.
    Span::new(0x1_3ffc, 0x1_43fc, Width::Word, Role::DsidInvalidate),
    // Performance counter control and configuration.
    Span::new(0x1_c00c, 0x1_c014, Width::Word, Role::Held),
    Span::new(0x1_e004, 0x1_e008, Width::Word, Role::Held),
    Span::new(0x1_f000, 0x1_f040, Width::Word, Role::Held),
    Span::new(0x2_4000, 0x2_4110, Width::Double, Role::Held),
    Span::new(0x2_4800, 0x2_4870, Width::Double, Role::Held),
    Span::new(0x2_5000, 0x2_5080, Width::Double, Role::Counter),
    // DSID profile counter configuration.
    Span::new(0x2_7000, 0x2_7020, Width::Double, Role::Held),
];

/// The `mcc,t8112` registers the planes share.
const T8112_SHARED: [Span<Role>; 8] = [
    Span::new(0x1c, 0x20, Width::Word, Role::Size),
    // Performance counter control, configuration and counters.
    Span::new(0x5_2000, 0x5_2008, Width::Word, Role::Held),
    Span::new(0x5_3000, 0x5_3020, Width::Word, Role::Held),
    Span::new(0x5_8000, 0x5_83b8, Width::Double, Role::Held),
    Span::new(0x5_8800, 0x5_8938, Width::Double, Role::Held),
    Span::new(0x5_9000, 0x5_91d8, Width::Double, Role::Counter),
    Span::new(0x5_a000, 0x5_a010, Width::Double, Role::Counter),
    // DSID profile counter enable.
    Span::new(0x5_e000, 0x5_e004, Width::Word, Role::Held),
];

/// One lock group's state in one plane.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Group {
    lower: u32,
    upper: u32,
    enable: bool,
    write_disable: bool,
    lock: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Plane {
    groups: [Group; GROUPS],
    cache_disabled: bool,
    dram_access: bool,
    ways: u32,
    held: Held,
    dsid_completions: Vec<(u8, u64)>,
}

impl Default for Plane {
    fn default() -> Self {
        Self {
            groups: [Group::default(); GROUPS],
            cache_disabled: true,
            dram_access: true,
            ways: 0,
            held: Held::default(),
            dsid_completions: Vec::new(),
        }
    }
}

/// A lock register: the cache status, or a field of the group with this
/// index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    CacheStatus,
    Lower(usize),
    Upper(usize),
    Enable(usize),
    WriteDisable(usize),
    Lock(usize),
}

/// Where an aperture offset lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// A plane (aperture-wide index) and its register.
    Plane(usize, u64),
    /// Every plane of an aperture (its first index) and the register.
    Broadcast(usize, u64),
    /// An aperture's shared register.
    Shared(usize, u64),
}

/// Every aperture's planes behind one device.
#[derive(Debug)]
pub struct Amcc {
    layout: Layout,
    cache: Option<Cache>,
    planes: Rc<RefCell<Vec<Plane>>>,
    shared: Vec<Held>,
}

// An explicit model snapshot remains independent. Firmware handles, in
// contrast, share only the controller's plane/coherency state.
impl Clone for Amcc {
    fn clone(&self) -> Self {
        Self {
            layout: self.layout,
            cache: self.cache,
            planes: Rc::new(RefCell::new(self.planes.borrow().clone())),
            shared: self.shared.clone(),
        }
    }
}

impl Amcc {
    /// The controller with `apertures` apertures and each group's region
    /// iBoot programmed, `[base, base + bytes)` in whole pages above the
    /// DRAM base, on every plane; a group with none programmed reads limits
    /// of 0. With a `cache`, its registers are modeled too.
    pub fn new(
        layout: Layout,
        apertures: usize,
        programmed: Programmed,
        cache: Option<Cache>,
    ) -> Result<Self, &'static str> {
        if layout.groups[0].is_none() {
            return Err("AMCC map without CTRR-A");
        }
        let stride = if layout.planes == 1 && layout.stride == 0 {
            layout.aperture_bytes
        } else {
            layout.stride
        };
        let layout = Layout { stride, ..layout };
        let planes_end = layout
            .stride
            .checked_mul(u64::from(layout.planes))
            .ok_or("AMCC plane geometry wraps")?;
        if layout.planes == 0 || layout.stride == 0 || planes_end > layout.aperture_bytes {
            return Err("AMCC planes do not fit the aperture");
        }
        if apertures == 0 || apertures.checked_mul(layout.planes as usize).is_none() {
            return Err("AMCC aperture count is empty or overflows");
        }
        let mut addresses = Vec::new();
        for register in lock_registers(&layout).map(|(register, _)| register) {
            if !register.offset.is_multiple_of(4)
                || register.mask == 0
                || register.value & !register.mask != 0
            {
                return Err("AMCC lock register has invalid alignment or mask");
            }
            for plane in 0..layout.planes {
                let address = u64::from(plane)
                    .checked_mul(layout.stride)
                    .and_then(|offset| offset.checked_add(register.offset))
                    .ok_or("AMCC lock register address wraps")?;
                if address
                    .checked_add(4)
                    .is_none_or(|end| end > layout.aperture_bytes)
                    || addresses.contains(&address)
                {
                    return Err("AMCC lock registers overlap or exceed the aperture");
                }
                addresses.push(address);
            }
        }
        if let Some(cache) = cache {
            let (shared, shared_bytes) = cache.shared;
            let inside = |start: u64, bytes: u64| {
                start >= planes_end
                    && start
                        .checked_add(bytes)
                        .is_some_and(|end| end <= layout.aperture_bytes)
            };
            if !inside(shared, shared_bytes)
                || !inside(cache.broadcast, layout.stride)
                || (shared < cache.broadcast + layout.stride
                    && cache.broadcast < shared + shared_bytes)
            {
                return Err("memory cache blocks do not fit the aperture beside its planes");
            }
            if cache.ways == 0
                || cache.ways > 0x1f
                || !cache.bytes.is_multiple_of(MIB)
                || cache.bytes / MIB > 0xff
            {
                return Err("memory cache geometry the registers cannot state");
            }
        }
        let mut plane = Plane::default();
        for ((group, state), region) in layout.groups.iter().zip(&mut plane.groups).zip(programmed)
        {
            let Some((base, bytes)) = region else {
                continue;
            };
            let group = group.ok_or("a lock group the map does not describe is programmed")?;
            let shift = group.page_size_shift;
            let page = 1u64.checked_shl(shift).ok_or("page-size-shift too large")?;
            let end = base
                .checked_add(bytes)
                .ok_or("lock group region overflows")?;
            if base < layout.dram_base || bytes == 0 || base % page != 0 || end % page != 0 {
                return Err("lock group region is not whole pages above the DRAM base");
            }
            let limit = |address: u64| u32::try_from((address - layout.dram_base) >> shift);
            state.lower = limit(base).map_err(|_| "lock group region beyond its limits")?;
            state.upper = limit(end - page).map_err(|_| "lock group region beyond its limits")?;
        }
        Ok(Self {
            planes: Rc::new(RefCell::new(
                alloc::vec![plane; apertures * layout.planes as usize],
            )),
            shared: alloc::vec![Held::default(); apertures],
            layout,
            cache,
        })
    }

    /// Each group's region locked against writes, first and last byte: the
    /// limits of every plane that has set the group's enable or
    /// write-disable.
    pub fn locked_regions(&self) -> Locked {
        let base = self.layout.dram_base;
        let planes = self.planes.borrow();
        core::array::from_fn(|index| {
            let shift = self.layout.groups[index]?.page_size_shift;
            planes
                .iter()
                .map(|plane| plane.groups[index])
                .filter(|group| group.enable || group.write_disable)
                .map(|group| {
                    (
                        base + (u64::from(group.lower) << shift),
                        base + ((u64::from(group.upper) + 1) << shift) - 1,
                    )
                })
                .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)))
        })
    }

    fn target(&self, offset: u64) -> Result<Target, &'static str> {
        let layout = &self.layout;
        let aperture = (offset / layout.aperture_bytes) as usize;
        let within = offset % layout.aperture_bytes;
        if aperture >= self.planes.borrow().len() / layout.planes as usize {
            return Err("AMCC offset exceeds the retained apertures");
        }
        let first = aperture * layout.planes as usize;
        // DT register offsets are relative to each plane's origin, and may
        // exceed the stride (T6000 cache status is at 0x10000c). Decode these
        // exact addresses before dividing the rest into conventional blocks.
        for (register, _) in self.lock_registers() {
            if let Some(delta) = within.checked_sub(register.offset)
                && delta.is_multiple_of(layout.stride)
                && delta / layout.stride < u64::from(layout.planes)
            {
                return Ok(Target::Plane(
                    first + (delta / layout.stride) as usize,
                    register.offset,
                ));
            }
        }
        let plane = within / layout.stride;
        if plane < u64::from(layout.planes) {
            return Ok(Target::Plane(
                first + plane as usize,
                within % layout.stride,
            ));
        }
        let cache = self
            .cache
            .ok_or("AMCC register outside the lock-regs planes")?;
        let (shared, bytes) = cache.shared;
        if (cache.broadcast..cache.broadcast + layout.stride).contains(&within) {
            Ok(Target::Broadcast(first, within - cache.broadcast))
        } else if (shared..shared + bytes).contains(&within) {
            Ok(Target::Shared(aperture, within - shared))
        } else {
            Err("AMCC register outside the planes and memory cache blocks")
        }
    }

    fn lock_registers(&self) -> impl Iterator<Item = (Register, Kind)> + '_ {
        lock_registers(&self.layout)
    }

    fn lock_kind(&self, register: u64) -> Option<(Kind, Register)> {
        self.lock_registers()
            .find(|(candidate, _)| candidate.offset == register)
            .map(|(register, kind)| (kind, register))
    }

    fn plane_role(&self, register: u64, width: Width) -> Result<Role, &'static str> {
        if self.cache.is_none() {
            return Err("AMCC register without public description");
        }
        regfile::role(&T8112_PLANE, register, width)
    }

    fn read_plane(&self, index: usize, register: u64, width: Width) -> Result<u64, &'static str> {
        let planes = self.planes.borrow();
        let plane = &planes[index];
        if let Some((kind, bits)) = self.lock_kind(register) {
            if width != Width::Word {
                return Err("AMCC register access other than 32 bits");
            }
            let group = |index: usize| plane.groups[index];
            return Ok(match kind {
                Kind::CacheStatus => bit(plane.cache_disabled, bits),
                Kind::Lower(index) => u64::from(group(index).lower),
                Kind::Upper(index) => u64::from(group(index).upper),
                Kind::Enable(index) => bit(group(index).enable, bits),
                Kind::WriteDisable(index) => bit(group(index).write_disable, bits),
                Kind::Lock(index) => bit(group(index).lock, bits),
            });
        }
        Ok(match self.plane_role(register, width)? {
            Role::DramAccess => return Err("DRAM access command readback is not established"),
            Role::DsidInvalidate => {
                return Err("MCC DSID invalidation command readback is not established");
            }
            Role::Ways => u64::from(plane.ways),
            Role::PoweredWays => u64::from(plane.ways) << 10 | u64::from(plane.ways) << 5,
            Role::Flush | Role::Counter => 0,
            Role::Held => plane.held.get(register),
            Role::Size => unreachable!("no plane register states the size"),
        })
    }

    fn write_plane(
        &mut self,
        index: usize,
        register: u64,
        width: Width,
        value: u64,
    ) -> Result<(), &'static str> {
        let Some((kind, bits)) = self.lock_kind(register) else {
            let role = self.plane_role(register, width)?;
            let ways = self.cache.map_or(0, |cache| cache.ways);
            let mut planes = self.planes.borrow_mut();
            let plane = &mut planes[index];
            return match role {
                Role::DramAccess if value == 0 => {
                    plane.dram_access = false;
                    Ok(())
                }
                Role::DramAccess => Err("only DRAM access disable write0 is described"),
                Role::Ways if value <= u64::from(ways) => {
                    plane.ways = value as u32;
                    Ok(())
                }
                Role::Ways => Err("more memory cache ways than the cache has"),
                Role::Flush if value == 1 => Ok(()),
                Role::Flush => Err("memory cache flush value other than 1"),
                Role::DsidInvalidate => invalidate(plane, register, value),
                Role::Held => {
                    plane.held.set(register, value);
                    Ok(())
                }
                Role::PoweredWays | Role::Counter | Role::Size => {
                    Err("write to a memory cache status or counter")
                }
            };
        };
        if width != Width::Word {
            return Err("AMCC register access other than 32 bits");
        }
        let value = value as u32;
        if value & !bits.mask != 0 {
            return Err("AMCC register bit without described meaning");
        }
        let mut planes = self.planes.borrow_mut();
        let plane = &mut planes[index];
        let set = match kind {
            Kind::CacheStatus if self.cache.is_none() => return Err("AMCC cache-status write"),
            Kind::Lower(group) | Kind::Upper(group) => {
                let group = &mut plane.groups[group];
                let frozen = group.lock || group.write_disable;
                let limit = if matches!(kind, Kind::Lower(_)) {
                    &mut group.lower
                } else {
                    &mut group.upper
                };
                if *limit != value && frozen {
                    return Err("AMCC limit change after write-disable or lock");
                }
                *limit = value;
                return Ok(());
            }
            _ if value == bits.value => true,
            _ if value == 0 => false,
            _ => return Err("AMCC bit register value other than set or clear"),
        };
        let group = match kind {
            Kind::CacheStatus => {
                plane.cache_disabled = set;
                return Ok(());
            }
            Kind::Lower(group)
            | Kind::Upper(group)
            | Kind::Enable(group)
            | Kind::WriteDisable(group)
            | Kind::Lock(group) => &mut plane.groups[group],
        };
        let locked = group.lock;
        let flag = match kind {
            Kind::Enable(_) => &mut group.enable,
            Kind::WriteDisable(_) => &mut group.write_disable,
            _ => &mut group.lock,
        };
        if locked && *flag != set {
            return Err("AMCC lock group change after its lock");
        }
        *flag = set;
        Ok(())
    }

    fn read_shared(
        &self,
        aperture: usize,
        register: u64,
        width: Width,
    ) -> Result<u64, &'static str> {
        let cache = self
            .cache
            .ok_or("AMCC register outside the lock-regs planes")?;
        Ok(match regfile::role(&T8112_SHARED, register, width)? {
            Role::Size => (cache.bytes / MIB) << 8,
            Role::Held => self.shared[aperture].get(register),
            _ => 0,
        })
    }

    fn write_shared(
        &mut self,
        aperture: usize,
        register: u64,
        width: Width,
        value: u64,
    ) -> Result<(), &'static str> {
        match regfile::role(&T8112_SHARED, register, width)? {
            Role::Held => {
                self.shared[aperture].set(register, value);
                Ok(())
            }
            _ => Err("write to a memory cache status or counter"),
        }
    }

    fn access(
        &mut self,
        offset: u64,
        width: Width,
        write: Option<u64>,
    ) -> Result<u64, &'static str> {
        let planes = self.layout.planes as usize;
        match (self.target(offset)?, write) {
            (Target::Plane(index, register), None) => self.read_plane(index, register, width),
            (Target::Plane(index, register), Some(value)) => {
                self.write_plane(index, register, width, value).map(|()| 0)
            }
            (Target::Shared(aperture, register), None) => {
                self.read_shared(aperture, register, width)
            }
            (Target::Shared(aperture, register), Some(value)) => self
                .write_shared(aperture, register, width, value)
                .map(|()| 0),
            // A broadcast read answers only while the planes agree.
            (Target::Broadcast(first, register), None) => {
                let value = self.read_plane(first, register, width)?;
                for index in first + 1..first + planes {
                    if self.read_plane(index, register, width)? != value {
                        return Err("broadcast read of planes that differ");
                    }
                }
                Ok(value)
            }
            // Every plane takes the write, or none does.
            (Target::Broadcast(first, register), Some(value)) => {
                let before = self.planes.borrow()[first..first + planes].to_vec();
                for index in first..first + planes {
                    if let Err(reason) = self.write_plane(index, register, width, value) {
                        self.planes.borrow_mut()[first..first + planes].clone_from_slice(&before);
                        return Err(reason);
                    }
                }
                Ok(0)
            }
        }
    }
}

/// Every lock register `layout` describes: the cache status, then each
/// group's limits and controls.
fn lock_registers(layout: &Layout) -> impl Iterator<Item = (Register, Kind)> + '_ {
    let status = layout
        .cache_status
        .map(|register| (register, Kind::CacheStatus));
    let groups = layout.groups.iter().enumerate().flat_map(|(index, group)| {
        group.iter().flat_map(move |group| {
            [
                Some((group.lower_limit, Kind::Lower(index))),
                Some((group.upper_limit, Kind::Upper(index))),
                group.enable.map(|register| (register, Kind::Enable(index))),
                group
                    .write_disable
                    .map(|register| (register, Kind::WriteDisable(index))),
                group.lock.map(|register| (register, Kind::Lock(index))),
            ]
            .into_iter()
            .flatten()
        })
    });
    status.into_iter().chain(groups)
}

fn bit(set: bool, register: Register) -> u64 {
    if set {
        u64::from(register.value & register.mask)
    } else {
        0
    }
}

fn invalidate(plane: &mut Plane, register: u64, value: u64) -> Result<(), &'static str> {
    if value != 1 {
        return Err("MCC DSID invalidation requires its original write1 command");
    }
    if !plane.dram_access {
        return Err("MCC DSID invalidation after DRAM access disable");
    }
    retire_invalidation(plane, register);
    Ok(())
}

fn retire_invalidation(plane: &mut Plane, register: u64) {
    let dsid = ((register - 0x13ffc) / 4) as u8;
    // This memory-controller model stores no dirty cache lines.
    // All PE/DMA/GPU writes copy directly to shared RAM, and a completed
    // DMA call owns no deferred writeback. Establish their visibility before
    // retiring the command; no successful completion is sent while a native
    // job or its earlier DMA publication is still pending in its caller.
    fence(Ordering::SeqCst);
    if let Some((_, completed)) = plane
        .dsid_completions
        .iter_mut()
        .find(|(id, _)| *id == dsid)
    {
        *completed = completed.wrapping_add(1);
    } else {
        plane.dsid_completions.push((dsid, 1));
    }
}

impl MmioDevice for Amcc {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        self.access(offset, width, None)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let disables = matches!(
            self.target(offset),
            Ok(Target::Plane(_, DRAM_ACCESS) | Target::Broadcast(_, DRAM_ACCESS))
        );
        self.access(offset, width, Some(value))
            .map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))?;
        if disables {
            access.request_transition(
                NAME,
                Transition::Halt,
                "DRAM access disabled; execution with disabled guest RAM is unsupported",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    const fn bit_register(offset: u64) -> Register {
        Register {
            offset,
            mask: 1,
            value: 1,
        }
    }

    fn layout() -> Layout {
        let limit = |offset| Register {
            offset,
            mask: u32::MAX,
            value: 0,
        };
        Layout {
            aperture_bytes: 0xf4_0000,
            planes: 4,
            stride: 0x4_0000,
            cache_status: Some(bit_register(0x424)),
            groups: [
                Some(LockGroup {
                    page_size_shift: 14,
                    lower_limit: limit(0x680),
                    upper_limit: limit(0x684),
                    enable: Some(bit_register(0x688)),
                    write_disable: Some(bit_register(0x7f0)),
                    lock: Some(bit_register(0x68c)),
                }),
                None,
                None,
                None,
            ],
            dram_base: 0x8_0000_0000,
        }
    }

    const NONE: Programmed = [None; GROUPS];

    /// CTRR-A's registers.
    fn a(layout: &mut Layout) -> &mut LockGroup {
        layout.groups[0].as_mut().unwrap()
    }

    /// The M4 Pro and later's map: four groups, each register a word apart
    /// from the same register of the next group.
    fn interleaved() -> Layout {
        let limit = |offset| Register {
            offset,
            mask: u32::MAX,
            value: 0,
        };
        let group = |index: u64| {
            Some(LockGroup {
                page_size_shift: 14,
                lower_limit: limit(0xaa0 + 4 * index),
                upper_limit: limit(0xab0 + 4 * index),
                enable: Some(bit_register(0xac0 + 4 * index)),
                write_disable: Some(bit_register(0xae0 + 4 * index)),
                lock: Some(bit_register(0xad0 + 4 * index)),
            })
        };
        Layout {
            aperture_bytes: 0x14_0000,
            planes: 4,
            stride: 0x4_0000,
            cache_status: Some(bit_register(0x82c)),
            groups: [group(0), group(1), group(2), group(3)],
            dram_base: 0x100_0000_0000,
        }
    }

    /// SPTM's `ctrr_lock_sptm` on the M4 and later: CTRR-C and D read
    /// iBoot's limits and unlocked controls on every plane, then lock, last
    /// plane first; each group's region is locked on its own, and CTRR-A
    /// and B, which no component writes, stay unlocked.
    #[test]
    fn sptm_locks_ctrr_c_and_d_each_over_its_own_region() {
        let base = 0x100_0000_0000;
        let c = (base + 0x400_0000, 0x10_0000);
        let d = (base + 0x800_0000, 0x40_0000);
        let mut amcc = Amcc::new(
            interleaved(),
            2,
            [Some((base + 0x200_0000, 0x4000)), None, Some(c), Some(d)],
            None,
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let at = |aperture: u64, plane: u64, offset: u64| {
            aperture * 0x14_0000 + plane * 0x4_0000 + offset
        };
        for aperture in 0..2 {
            for plane in 0..4 {
                let read = |amcc: &mut Amcc, offset, access: &mut Access<'_>| {
                    amcc.read(at(aperture, plane, offset), Width::Word, access)
                };
                assert_eq!(read(&mut amcc, 0xaa8, &mut access), Ok(0x1000));
                assert_eq!(read(&mut amcc, 0xab8, &mut access), Ok(0x103f));
                assert_eq!(read(&mut amcc, 0xaac, &mut access), Ok(0x2000));
                assert_eq!(read(&mut amcc, 0xabc, &mut access), Ok(0x20ff));
                assert_eq!(read(&mut amcc, 0xaa4, &mut access), Ok(0));
                for control in [0xae8, 0xad8, 0xaec, 0xadc] {
                    assert_eq!(read(&mut amcc, control, &mut access), Ok(0));
                }
            }
        }
        for group in [2, 3] {
            for aperture in 0..2 {
                for plane in (0..4).rev() {
                    for control in [0xac0, 0xae0, 0xad0] {
                        amcc.write(
                            at(aperture, plane, control + 4 * group),
                            Width::Word,
                            1,
                            &mut access,
                        )
                        .unwrap();
                    }
                }
            }
        }
        assert_eq!(
            amcc.locked_regions(),
            [
                None,
                None,
                Some((c.0, c.0 + c.1 - 1)),
                Some((d.0, d.0 + d.1 - 1)),
            ]
        );
        // A locked group's limits and controls stay; others still change.
        assert!(amcc.write(0xaa8, Width::Word, 0, &mut access).is_err());
        assert!(amcc.write(0xac8, Width::Word, 0, &mut access).is_err());
        amcc.write(0xaa4, Width::Word, 7, &mut access).unwrap();
        assert_eq!(amcc.read(0xaa4, Width::Word, &mut access), Ok(7));
        // A region programmed into a group the map lacks refuses.
        let mut lacking = interleaved();
        lacking.groups[3] = None;
        assert!(Amcc::new(lacking, 1, [None, None, None, Some(d)], None).is_err());
        lacking.groups[0] = None;
        assert!(Amcc::new(lacking, 1, NONE, None).is_err());
    }

    #[test]
    fn io_access_limits_are_absolute_and_need_no_cache_or_lock_register() {
        let mut description = layout();
        description.aperture_bytes = 0x4000;
        description.planes = 1;
        description.stride = 0;
        description.dram_base = 0;
        description.cache_status = None;
        a(&mut description).lower_limit.offset = 0x220;
        a(&mut description).upper_limit.offset = 0x224;
        a(&mut description).enable = Some(bit_register(0x228));
        a(&mut description).write_disable = None;
        a(&mut description).lock = None;
        let base = 0x100_0200_0000;
        let mut model = Amcc::new(description, 4, ctrr_a(Some((base, 0x8000))), None).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(model.locked_regions()[0], None);
        for aperture in 0..4 {
            let origin = aperture * 0x4000;
            assert_eq!(
                model.read(origin + 0x220, Width::Word, &mut access),
                Ok(base >> 14)
            );
            assert_eq!(
                model.read(origin + 0x224, Width::Word, &mut access),
                Ok((base + 0x7fff) >> 14)
            );
            model
                .write(origin + 0x228, Width::Word, 1, &mut access)
                .unwrap();
            assert_eq!(model.read(origin + 0x228, Width::Word, &mut access), Ok(1));
            for absent in [0, 0x22c, 0x424, 0x68c, 0x7f0] {
                assert!(
                    model
                        .read(origin + absent, Width::Word, &mut access)
                        .is_err()
                );
                assert!(
                    model
                        .write(origin + absent, Width::Word, 1, &mut access)
                        .is_err()
                );
            }
        }
        assert_eq!(model.locked_regions()[0], Some((base, base + 0x7fff)));
        description.planes = 2;
        assert!(Amcc::new(description, 1, NONE, None).is_err());
    }

    #[test]
    fn disabling_dram_broadcasts_and_stops_before_further_guest_ram_execution() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut m = Amcc::new(layout(), 1, NONE, Some(CACHE)).unwrap();
        assert!(m.planes.borrow().iter().all(|p| p.dram_access));
        assert!(
            m.write(CACHE.broadcast + DRAM_ACCESS, Width::Word, 1, &mut a)
                .is_err()
        );
        assert!(a.reset_request().is_none());
        assert!(m.planes.borrow().iter().all(|p| p.dram_access));
        m.write(CACHE.broadcast + DRAM_ACCESS, Width::Word, 0, &mut a)
            .unwrap();
        assert!(m.planes.borrow().iter().all(|p| !p.dram_access));
        let request = a.reset_request().unwrap();
        assert_eq!(request.transition, Transition::Halt);
        assert!(request.reason.contains("DRAM access disabled"));
        assert!(
            m.read(CACHE.broadcast + DRAM_ACCESS, Width::Word, &mut a)
                .is_err()
        );
        assert!(
            m.write(CACHE.broadcast + DRAM_ACCESS, Width::Double, 0, &mut a)
                .is_err()
        );
    }

    #[test]
    fn extended_status_offsets_and_absent_controls_keep_each_plane_independent() {
        let mut description = layout();
        description.aperture_bytes = 0x20_0000;
        description.cache_status = Some(bit_register(0x10_000c));
        a(&mut description).write_disable = None;
        let base = description.dram_base;
        let mut device = Amcc::new(
            description,
            2,
            ctrr_a(Some((base + 0x200_0000, 0x4000))),
            None,
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for aperture in 0..2 {
            for plane in 0..4 {
                let origin = aperture * description.aperture_bytes + plane * description.stride;
                assert_eq!(
                    device.read(origin + 0x10_000c, Width::Word, &mut access),
                    Ok(1)
                );
                assert_eq!(
                    device.read(origin + 0x680, Width::Word, &mut access),
                    Ok(0x800)
                );
                assert!(
                    device
                        .read(origin + 0x7f0, Width::Word, &mut access)
                        .is_err()
                );
                assert!(
                    device
                        .write(origin + 0x7f0, Width::Word, 1, &mut access)
                        .is_err()
                );
                device
                    .write(origin + 0x688, Width::Word, 1, &mut access)
                    .unwrap();
                device
                    .write(origin + 0x68c, Width::Word, 1, &mut access)
                    .unwrap();
                assert!(
                    device
                        .write(origin + 0x680, Width::Word, 0, &mut access)
                        .is_err()
                );
            }
        }
        assert_eq!(
            device.locked_regions()[0],
            Some((base + 0x200_0000, base + 0x200_3fff))
        );
        assert!(
            device
                .read(2 * description.aperture_bytes, Width::Word, &mut access)
                .is_err()
        );
        a(&mut description).enable = None;
        let mut absent = Amcc::new(description, 1, NONE, None).unwrap();
        assert!(absent.read(0x688, Width::Word, &mut access).is_err());
        description.cache_status.as_mut().unwrap().offset = 0x20_0000;
        assert!(Amcc::new(description, 1, NONE, None).is_err());
        description.cache_status.as_mut().unwrap().offset =
            a(&mut description).lower_limit.offset + description.stride;
        assert!(Amcc::new(description, 1, NONE, None).is_err());
    }

    #[test]
    fn sptms_lockdown_reads_iboots_limits_and_locks_every_plane() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut amcc =
            Amcc::new(layout(), 1, ctrr_a(Some((0x8_0200_0000, 0x579_0000))), None).unwrap();
        for plane in 0..4u64 {
            let at = |offset: u64| plane * 0x4_0000 + offset;
            assert_eq!(amcc.read(at(0x424), Width::Word, &mut access), Ok(1));
            assert_eq!(amcc.read(at(0x680), Width::Word, &mut access), Ok(0x800));
            assert_eq!(amcc.read(at(0x684), Width::Word, &mut access), Ok(0x1de3));
            assert_eq!(amcc.read(at(0x7f0), Width::Word, &mut access), Ok(0));
            assert_eq!(amcc.read(at(0x68c), Width::Word, &mut access), Ok(0));
        }
        assert_eq!(amcc.locked_regions()[0], None);
        for plane in (0..4u64).rev() {
            for offset in [0x688, 0x7f0, 0x68c] {
                amcc.write(plane * 0x4_0000 + offset, Width::Word, 1, &mut access)
                    .unwrap();
            }
        }
        assert_eq!(
            amcc.locked_regions()[0],
            Some((0x8_0200_0000, 0x8_0778_ffff))
        );
        // A repeat completes; a change, other registers and widths stop.
        amcc.write(0x688, Width::Word, 1, &mut access).unwrap();
        amcc.write(0x680, Width::Word, 0x800, &mut access).unwrap();
        assert!(amcc.write(0x680, Width::Word, 0, &mut access).is_err());
        assert!(amcc.write(0x68c, Width::Word, 0, &mut access).is_err());
        assert!(amcc.write(0x424, Width::Word, 1, &mut access).is_err());
        assert!(amcc.read(0x428, Width::Word, &mut access).is_err());
        assert!(amcc.read(0x680, Width::Double, &mut access).is_err());
        assert!(amcc.read(0x10_0000, Width::Word, &mut access).is_err());
    }

    #[test]
    fn programmed_regions_are_whole_pages_above_dram() {
        assert!(Amcc::new(layout(), 1, ctrr_a(Some((0x8_0200_1000, 0x4000))), None).is_err());
        assert!(Amcc::new(layout(), 1, ctrr_a(Some((0x7_0000_0000, 0x4000))), None).is_err());
        let blank = Amcc::new(layout(), 2, NONE, None).unwrap();
        assert_eq!(blank.planes.borrow().len(), 8);
    }

    const CACHE: Cache = Cache {
        shared: (0x10_0000, 0x8_0000),
        broadcast: 0xf0_0000,
        bytes: 8 << 20,
        ways: 16,
    };

    /// `mccEnableCacheMode`, `_cacheFlush` and `readCacheSize` as the 26A434
    /// J473AP driver runs them.
    #[test]
    fn the_memory_cache_powers_ways_enables_and_flushes_at_once() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut amcc = Amcc::new(layout(), 1, NONE, Some(CACHE)).unwrap();
        let plane = |n: u64, offset: u64| n * 0x4_0000 + offset;
        let mut read = |amcc: &mut Amcc, offset, width| amcc.read(offset, width, &mut access);
        assert_eq!(read(&mut amcc, 0x10_001c, Width::Word), Ok(0x800));
        for n in 0..4 {
            assert_eq!(read(&mut amcc, plane(n, 0x424), Width::Word), Ok(1));
            assert_eq!(read(&mut amcc, plane(n, 0x1c04), Width::Word), Ok(0));
        }
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut write =
            |amcc: &mut Amcc, offset, width, value| amcc.write(offset, width, value, &mut access);
        // Enable: power 16 ways, wait, then clear cache-status.
        write(&mut amcc, 0xf0_1c00, Width::Word, 16).unwrap();
        write(&mut amcc, 0xf0_0424, Width::Word, 0).unwrap();
        assert!(write(&mut amcc, 0xf0_1c00, Width::Word, 17).is_err());
        // Flush: set cache-status and start the flush.
        write(&mut amcc, 0xf0_0424, Width::Word, 1).unwrap();
        write(&mut amcc, 0xf0_1c2c, Width::Word, 1).unwrap();
        // A group quota through the broadcast window, and the shared
        // configuration.
        write(&mut amcc, 0xf0_a010, Width::Word, 0x20).unwrap();
        write(&mut amcc, 0x15_8000, Width::Double, 1 << 55).unwrap();
        assert!(write(&mut amcc, 0x15_9000, Width::Double, 0).is_err());
        assert!(write(&mut amcc, 0x10_001c, Width::Word, 0).is_err());
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut read = |amcc: &mut Amcc, offset, width| amcc.read(offset, width, &mut access);
        for n in 0..4 {
            assert_eq!(
                read(&mut amcc, plane(n, 0x1c04), Width::Word),
                Ok(16 << 10 | 16 << 5)
            );
            assert_eq!(read(&mut amcc, plane(n, 0x1c2c), Width::Word), Ok(0));
            assert_eq!(read(&mut amcc, plane(n, 0x424), Width::Word), Ok(1));
            assert_eq!(read(&mut amcc, plane(n, 0xa010), Width::Word), Ok(0x20));
            assert_eq!(read(&mut amcc, plane(n, 0x2_5000), Width::Double), Ok(0));
        }
        assert_eq!(read(&mut amcc, 0xf0_a010, Width::Word), Ok(0x20));
        assert_eq!(read(&mut amcc, 0x15_8000, Width::Double), Ok(1 << 55));
        // Undescribed registers and widths still refuse.
        assert!(read(&mut amcc, 0x1c04, Width::Double).is_err());
        assert!(read(&mut amcc, 0x1c08, Width::Word).is_err());
        assert!(read(&mut amcc, 0x18_0000, Width::Word).is_err());
    }

    #[test]
    fn a_broadcast_write_reaches_every_plane_or_none() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut amcc = Amcc::new(layout(), 1, NONE, Some(CACHE)).unwrap();
        // Plane 3 locks its group; a broadcast change of enable then stops
        // without changing planes 0 to 2.
        for offset in [0x688, 0x68c] {
            amcc.write(3 * 0x4_0000 + offset, Width::Word, 1, &mut access)
                .unwrap();
        }
        assert!(amcc.write(0xf0_0688, Width::Word, 0, &mut access).is_err());
        assert!(amcc.read(0xf0_0688, Width::Word, &mut access).is_err());
        assert_eq!(amcc.read(0x688, Width::Word, &mut access), Ok(0));
        // Blocks that overlap the planes or each other are refused.
        let overlapping = Cache {
            shared: (0xf0_0000, 0x8_0000),
            ..CACHE
        };
        assert!(Amcc::new(layout(), 1, NONE, Some(overlapping)).is_err());
    }
    #[test]
    fn native_cache_geometry_refuses_wrapped_or_zero_plane_spans_before_allocating() {
        assert!(
            Amcc::new(
                Layout {
                    stride: u64::MAX,
                    ..layout()
                },
                1,
                NONE,
                Some(CACHE)
            )
            .unwrap_err()
            .contains("geometry wraps")
        );
        assert!(
            Amcc::new(
                Layout {
                    stride: 0,
                    ..layout()
                },
                1,
                NONE,
                Some(CACHE)
            )
            .is_err()
        );
    }
}
