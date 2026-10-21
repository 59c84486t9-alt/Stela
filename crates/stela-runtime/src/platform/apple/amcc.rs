//! The AMCC memory controller aperture: the cache status and CTRR-A lock
//! group of every plane, as iBoot describes them in `/chosen/lock-regs/amcc`
//! (`machine::soc::MemoryController`), and, when the DeviceTree shows the
//! `mcc,t8112` memory cache controller, the registers its driver programs.
//!
//! No public source documents the AMCC. The lock register map is iBoot's
//! (26A434 `iBoot.j473.RELEASE` builds it, `stela_loader::lock_regs`); the
//! behavior comes from SPTM 26A434 `ctrr_map_lock_group` and
//! `ctrr_lock_boot`:
//!
//! - each plane's cache-status register reads `value` under `mask` while
//!   the cache is disabled, which SPTM asserts before the lockdown; iBoot
//!   leaves it disabled on this boot (no `early-memcache-enable`);
//! - the lower and upper limit registers hold the CTRR-A region iBoot
//!   programs, in pages of `1 << page-size-shift` bytes from the DRAM base,
//!   upper inclusive, the same on every plane;
//! - SPTM finds enable, write-disable and lock clear, then sets them in that
//!   order on every plane.
//!
//! Inferred from that order: write-disable freezes the limits and lock
//! freezes the group, so a change after either stops, because what hardware
//! does is not documented. Once enable or write-disable is set the region is
//! taken as locked against writes from any requester, which the engine
//! applies to every PE (`machine::mmu::Ctrr`).
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
use super::bus::{Access, Direction, MmioDevice, MmioError, Transition, Width, refuse};
use super::regfile::{self, Held, Span};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{Ordering, fence};

const NAME: &str = "amcc";
const DRAM_ACCESS: u64 = 0x410;

/// A plane register: its offset in the plane, the bits that hold it and,
/// for a bit register, the masked value that means set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub offset: u64,
    pub mask: u32,
    pub value: u32,
}

/// The CTRR-A lock group's registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockGroup {
    pub page_size_shift: u32,
    pub lower_limit: Register,
    pub upper_limit: Register,
    pub enable: Register,
    pub write_disable: Register,
    pub lock: Register,
}

/// One aperture's planes and registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub aperture_bytes: u64,
    pub planes: u32,
    pub stride: u64,
    pub cache_status: Register,
    pub group: LockGroup,
    /// The address limit 0 names.
    pub dram_base: u64,
}

/// The memory cache of an `mcc,t8112`, its blocks as aperture offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cache {
    /// The registers the planes share (`/arm-io/mcc` `reg[0]`): offset and
    /// bytes.
    pub shared: (u64, u64),
    /// The window whose writes reach every plane (`reg[3]`), one plane
    /// stride long.
    pub broadcast: u64,
    pub bytes: u64,
    pub ways: u32,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Plane {
    lower: u32,
    upper: u32,
    enable: bool,
    write_disable: bool,
    lock: bool,
    cache_disabled: bool,
    dram_access: bool,
    ways: u32,
    held: Held,
    dsid_completions: Vec<(u8, u64)>,
}

impl Default for Plane {
    fn default() -> Self {
        Self {
            lower: 0,
            upper: 0,
            enable: false,
            write_disable: false,
            lock: false,
            cache_disabled: true,
            dram_access: true,
            ways: 0,
            held: Held::default(),
            dsid_completions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    CacheStatus,
    Lower,
    Upper,
    Enable,
    WriteDisable,
    Lock,
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
// contrast, share only the actual controller's plane/coherency state.
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

pub mod firmware;

impl Amcc {
    /// The controller with `apertures` apertures and the CTRR-A region iBoot
    /// programmed, `[base, base + bytes)` in whole pages above the DRAM
    /// base, on every plane; with none programmed the limits read 0. With a
    /// `cache`, its registers are modeled too.
    pub fn new(
        layout: Layout,
        apertures: usize,
        programmed: Option<(u64, u64)>,
        cache: Option<Cache>,
    ) -> Result<Self, &'static str> {
        let shift = layout.group.page_size_shift;
        let page = 1u64.checked_shl(shift).ok_or("page-size-shift too large")?;
        let planes_end = layout
            .stride
            .checked_mul(u64::from(layout.planes))
            .ok_or("AMCC plane geometry wraps")?;
        if layout.planes == 0 || layout.stride == 0 || planes_end > layout.aperture_bytes {
            return Err("AMCC planes do not fit the aperture");
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
        if let Some((base, bytes)) = programmed {
            let end = base.checked_add(bytes).ok_or("CTRR-A region overflows")?;
            if base < layout.dram_base || bytes == 0 || base % page != 0 || end % page != 0 {
                return Err("CTRR-A region is not whole pages above the DRAM base");
            }
            let limit = |address: u64| u32::try_from((address - layout.dram_base) >> shift);
            plane.lower = limit(base).map_err(|_| "CTRR-A region beyond the limit registers")?;
            plane.upper =
                limit(end - page).map_err(|_| "CTRR-A region beyond the limit registers")?;
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

    /// The region locked against writes, first and last byte: the limits of
    /// every plane that has set enable or write-disable.
    pub fn locked_region(&self) -> Option<(u64, u64)> {
        let shift = self.layout.group.page_size_shift;
        let base = self.layout.dram_base;
        self.planes
            .borrow()
            .iter()
            .filter(|plane| plane.enable || plane.write_disable)
            .map(|plane| {
                (
                    base + (u64::from(plane.lower) << shift),
                    base + ((u64::from(plane.upper) + 1) << shift) - 1,
                )
            })
            .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)))
    }

    fn target(&self, offset: u64) -> Result<Target, &'static str> {
        let layout = &self.layout;
        let aperture = (offset / layout.aperture_bytes) as usize;
        let within = offset % layout.aperture_bytes;
        let first = aperture * layout.planes as usize;
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

    fn lock_kind(&self, register: u64) -> Option<Kind> {
        let layout = &self.layout;
        let group = &layout.group;
        [
            (layout.cache_status, Kind::CacheStatus),
            (group.lower_limit, Kind::Lower),
            (group.upper_limit, Kind::Upper),
            (group.enable, Kind::Enable),
            (group.write_disable, Kind::WriteDisable),
            (group.lock, Kind::Lock),
        ]
        .into_iter()
        .find(|(candidate, _)| candidate.offset == register)
        .map(|(_, kind)| kind)
    }

    fn register(&self, kind: Kind) -> Register {
        let group = &self.layout.group;
        match kind {
            Kind::CacheStatus => self.layout.cache_status,
            Kind::Lower => group.lower_limit,
            Kind::Upper => group.upper_limit,
            Kind::Enable => group.enable,
            Kind::WriteDisable => group.write_disable,
            Kind::Lock => group.lock,
        }
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
        if let Some(kind) = self.lock_kind(register) {
            if width != Width::Word {
                return Err("AMCC register access other than 32 bits");
            }
            let bits = self.register(kind);
            return Ok(match kind {
                Kind::CacheStatus => bit(plane.cache_disabled, bits),
                Kind::Lower => u64::from(plane.lower),
                Kind::Upper => u64::from(plane.upper),
                Kind::Enable => bit(plane.enable, bits),
                Kind::WriteDisable => bit(plane.write_disable, bits),
                Kind::Lock => bit(plane.lock, bits),
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
        let Some(kind) = self.lock_kind(register) else {
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
        let bits = self.register(kind);
        let value = value as u32;
        if value & !bits.mask != 0 {
            return Err("AMCC register bit without described meaning");
        }
        let mut planes = self.planes.borrow_mut();
        let plane = &mut planes[index];
        let set = match kind {
            Kind::CacheStatus if self.cache.is_none() => return Err("AMCC cache-status write"),
            Kind::Lower | Kind::Upper => {
                let limit = if kind == Kind::Lower {
                    &mut plane.lower
                } else {
                    &mut plane.upper
                };
                if *limit != value && (plane.lock || plane.write_disable) {
                    return Err("AMCC limit change after write-disable or lock");
                }
                *limit = value;
                return Ok(());
            }
            _ if value == bits.value => true,
            _ if value == 0 => false,
            _ => return Err("AMCC bit register value other than set or clear"),
        };
        let locked = plane.lock;
        let flag = match kind {
            Kind::CacheStatus => {
                plane.cache_disabled = set;
                return Ok(());
            }
            Kind::Enable => &mut plane.enable,
            Kind::WriteDisable => &mut plane.write_disable,
            _ => &mut plane.lock,
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
    // This actual memory-controller model stores no dirty cache lines.
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
    use crate::platform::apple::interrupt::InterruptLatch;

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
            cache_status: bit_register(0x424),
            group: LockGroup {
                page_size_shift: 14,
                lower_limit: limit(0x680),
                upper_limit: limit(0x684),
                enable: bit_register(0x688),
                write_disable: bit_register(0x7f0),
                lock: bit_register(0x68c),
            },
            dram_base: 0x8_0000_0000,
        }
    }

    #[test]
    fn disabling_dram_broadcasts_and_stops_before_further_guest_ram_execution() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut m = Amcc::new(layout(), 1, None, Some(CACHE)).unwrap();
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
    fn sptms_lockdown_reads_iboots_limits_and_locks_every_plane() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut amcc = Amcc::new(layout(), 1, Some((0x8_0200_0000, 0x579_0000)), None).unwrap();
        for plane in 0..4u64 {
            let at = |offset: u64| plane * 0x4_0000 + offset;
            assert_eq!(amcc.read(at(0x424), Width::Word, &mut access), Ok(1));
            assert_eq!(amcc.read(at(0x680), Width::Word, &mut access), Ok(0x800));
            assert_eq!(amcc.read(at(0x684), Width::Word, &mut access), Ok(0x1de3));
            assert_eq!(amcc.read(at(0x7f0), Width::Word, &mut access), Ok(0));
            assert_eq!(amcc.read(at(0x68c), Width::Word, &mut access), Ok(0));
        }
        assert_eq!(amcc.locked_region(), None);
        for plane in (0..4u64).rev() {
            for offset in [0x688, 0x7f0, 0x68c] {
                amcc.write(plane * 0x4_0000 + offset, Width::Word, 1, &mut access)
                    .unwrap();
            }
        }
        assert_eq!(amcc.locked_region(), Some((0x8_0200_0000, 0x8_0778_ffff)));
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
        assert!(Amcc::new(layout(), 1, Some((0x8_0200_1000, 0x4000)), None).is_err());
        assert!(Amcc::new(layout(), 1, Some((0x7_0000_0000, 0x4000)), None).is_err());
        let blank = Amcc::new(layout(), 2, None, None).unwrap();
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
        let mut amcc = Amcc::new(layout(), 1, None, Some(CACHE)).unwrap();
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
        let mut amcc = Amcc::new(layout(), 1, None, Some(CACHE)).unwrap();
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
        assert!(Amcc::new(layout(), 1, None, Some(overlapping)).is_err());
    }
    #[test]
    fn native_firmware_dsid_commands_share_the_actual_controller_and_veto_late_disabled_planes() {
        let base = 0x200000000;
        let mut model = Amcc::new(layout(), 1, None, Some(CACHE)).unwrap();
        let handle = model.firmware_cache(&[base]).unwrap();
        assert!(
            handle
                .command_ranges()
                .contains(&(base + CACHE.broadcast + 0x13ffc, 0x400))
        );
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let register = 0x13ffc + 255 * 4;
        handle
            .invalidate(base + CACHE.broadcast + register)
            .unwrap();
        assert!(
            model
                .planes
                .borrow()
                .iter()
                .all(|plane| plane.dsid_completions == [(255, 1)])
        );
        assert!(
            model
                .read(CACHE.broadcast + register, Width::Word, &mut access)
                .is_err()
        );
        for value in [0, 2, u64::MAX] {
            assert!(
                model
                    .write(CACHE.broadcast + register, Width::Word, value, &mut access)
                    .is_err()
            );
        }
        assert!(handle.check(base + CACHE.broadcast + 0x143fc).is_err());
        assert!(handle.check(base + CACHE.broadcast + 0x13ffe).is_err());
        assert!(handle.check(base + CACHE.broadcast + 0x13ff8).is_err());
        assert!(handle.check(base + layout().aperture_bytes).is_err());
        assert!(model.firmware_cache(&[]).is_err());
        assert!(model.firmware_cache(&[u64::MAX - 1]).is_err());
        model
            .write(
                2 * layout().stride + DRAM_ACCESS,
                Width::Word,
                0,
                &mut access,
            )
            .unwrap();
        let before = model.planes.borrow().clone();
        assert!(
            handle
                .invalidate(base + CACHE.broadcast + register)
                .is_err()
        );
        assert!(
            model
                .write(CACHE.broadcast + register, Width::Word, 1, &mut access)
                .is_err()
        );
        assert_eq!(*model.planes.borrow(), before);
        // A targeted plane is independent; cloning a model is a deep snapshot,
        // while the original handle continues to observe its actual owner.
        handle.invalidate(base + register).unwrap();
        assert_eq!(model.planes.borrow()[0].dsid_completions, [(255, 2)]);
        let clone = model.clone();
        handle.invalidate(base + register).unwrap();
        assert_eq!(clone.planes.borrow()[0].dsid_completions, [(255, 2)]);
        assert_eq!(model.planes.borrow()[0].dsid_completions, [(255, 3)]);
        let unknown = Amcc::new(layout(), 1, None, None).unwrap();
        assert!(unknown.firmware_cache(&[base]).is_err());
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
                None,
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
                None,
                Some(CACHE)
            )
            .is_err()
        );
    }
}
