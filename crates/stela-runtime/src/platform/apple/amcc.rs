//! The AMCC memory controller's lock registers: the cache status and the
//! CTRR-A lock group of every plane, as iBoot describes them in
//! `/chosen/lock-regs/amcc` (`machine::soc::MemoryController`).
//!
//! No public source documents the AMCC. The register map is iBoot's (26A434
//! `iBoot.j473.RELEASE` builds it, `stela_loader::lock_regs`); the behavior
//! comes from SPTM 26A434 `ctrr_map_lock_group` and `ctrr_lock_boot`:
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
//! applies to every PE (`machine::mmu::Ctrr`). Every other register of the
//! aperture refuses.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::vec::Vec;

const NAME: &str = "amcc";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Plane {
    lower: u32,
    upper: u32,
    enable: bool,
    write_disable: bool,
    lock: bool,
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

/// Every aperture's planes behind one device.
#[derive(Debug, Clone)]
pub struct Amcc {
    layout: Layout,
    planes: Vec<Plane>,
}

impl Amcc {
    /// The controller with `apertures` apertures and the CTRR-A region iBoot
    /// programmed, `[base, base + bytes)` in whole pages above the DRAM
    /// base, on every plane; with none programmed the limits read 0.
    pub fn new(
        layout: Layout,
        apertures: usize,
        programmed: Option<(u64, u64)>,
    ) -> Result<Self, &'static str> {
        let shift = layout.group.page_size_shift;
        let page = 1u64.checked_shl(shift).ok_or("page-size-shift too large")?;
        if layout.planes == 0 || layout.stride * u64::from(layout.planes) > layout.aperture_bytes {
            return Err("AMCC planes do not fit the aperture");
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
            planes: alloc::vec![plane; apertures * layout.planes as usize],
            layout,
        })
    }

    /// The region locked against writes, first and last byte: the limits of
    /// every plane that has set enable or write-disable.
    pub fn locked_region(&self) -> Option<(u64, u64)> {
        let shift = self.layout.group.page_size_shift;
        let base = self.layout.dram_base;
        self.planes
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

    fn locate(
        &self,
        offset: u64,
        width: Width,
        direction: Direction,
    ) -> Result<(usize, Kind), MmioError> {
        let refused = |reason| refuse(NAME, offset, width, direction, reason);
        let layout = &self.layout;
        let aperture = offset / layout.aperture_bytes;
        let within = offset % layout.aperture_bytes;
        let plane = within / layout.stride;
        if plane >= u64::from(layout.planes) {
            return Err(refused("AMCC register outside the lock-regs planes"));
        }
        let register = within % layout.stride;
        let group = &layout.group;
        let kind = [
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
        .ok_or_else(|| refused("AMCC register without public description"))?;
        if width != Width::Word {
            return Err(refused("AMCC register access other than 32 bits"));
        }
        let index = aperture as usize * layout.planes as usize + plane as usize;
        Ok((index, kind))
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
}

fn bit(set: bool, register: Register) -> u64 {
    if set { u64::from(register.value) } else { 0 }
}

impl MmioDevice for Amcc {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let (index, kind) = self.locate(offset, width, Direction::Read)?;
        let plane = &self.planes[index];
        let register = self.register(kind);
        Ok(match kind {
            Kind::CacheStatus => u64::from(register.value & register.mask),
            Kind::Lower => u64::from(plane.lower),
            Kind::Upper => u64::from(plane.upper),
            Kind::Enable => bit(plane.enable, register),
            Kind::WriteDisable => bit(plane.write_disable, register),
            Kind::Lock => bit(plane.lock, register),
        })
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let (index, kind) = self.locate(offset, width, Direction::Write)?;
        let refused = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        let register = self.register(kind);
        let value = value as u32;
        if value & !register.mask != 0 {
            return Err(refused("AMCC register bit without described meaning"));
        }
        let plane = &mut self.planes[index];
        let set = match kind {
            Kind::CacheStatus => return Err(refused("AMCC cache-status write")),
            Kind::Lower | Kind::Upper => {
                let limit = if kind == Kind::Lower {
                    &mut plane.lower
                } else {
                    &mut plane.upper
                };
                if *limit != value && (plane.lock || plane.write_disable) {
                    return Err(refused("AMCC limit change after write-disable or lock"));
                }
                *limit = value;
                return Ok(());
            }
            _ if value == register.value => true,
            _ if value == 0 => false,
            _ => return Err(refused("AMCC bit register value other than set or clear")),
        };
        let locked = plane.lock;
        let flag = match kind {
            Kind::Enable => &mut plane.enable,
            Kind::WriteDisable => &mut plane.write_disable,
            _ => &mut plane.lock,
        };
        if locked && *flag != set {
            return Err(refused("AMCC lock group change after its lock"));
        }
        *flag = set;
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
    fn sptms_lockdown_reads_iboots_limits_and_locks_every_plane() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut amcc = Amcc::new(layout(), 1, Some((0x8_0200_0000, 0x579_0000))).unwrap();
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
        assert!(Amcc::new(layout(), 1, Some((0x8_0200_1000, 0x4000))).is_err());
        assert!(Amcc::new(layout(), 1, Some((0x7_0000_0000, 0x4000))).is_err());
        let blank = Amcc::new(layout(), 2, None).unwrap();
        assert_eq!(blank.planes.len(), 8);
    }
}
