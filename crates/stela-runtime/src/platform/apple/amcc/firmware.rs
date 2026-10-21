//! Firmware access to the actual coherent MCC cache owner. Geometry comes
//! from its mounted AMCC apertures, not from an SGX-relative address guess.

use super::{Amcc, Layout, Plane, retire_invalidation};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

#[derive(Clone)]
pub struct FirmwareCache {
    layout: Layout,
    broadcast: u64,
    apertures: Vec<u64>,
    planes: Rc<RefCell<Vec<Plane>>>,
}
impl Amcc {
    pub fn firmware_cache(&self, apertures: &[u64]) -> Result<FirmwareCache, &'static str> {
        let cache = self
            .cache
            .ok_or("MCC firmware cache has no qualified native coherency model")?;
        if apertures.is_empty() || apertures.len() != self.shared.len() {
            return Err("MCC firmware aperture count disagrees with its actual controller");
        }
        if self.layout.stride < 0x143fc {
            return Err("MCC firmware DSID registers exceed the actual plane stride");
        }
        for (index, physical) in apertures.iter().copied().enumerate() {
            let end = physical
                .checked_add(self.layout.aperture_bytes)
                .ok_or("MCC firmware aperture wraps")?;
            if apertures[..index]
                .iter()
                .any(|other| physical < *other + self.layout.aperture_bytes && *other < end)
            {
                return Err("MCC firmware apertures overlap");
            }
        }
        Ok(FirmwareCache {
            layout: self.layout,
            broadcast: cache.broadcast,
            apertures: apertures.to_vec(),
            planes: self.planes.clone(),
        })
    }
}
impl FirmwareCache {
    #[cfg(test)]
    pub(crate) fn completions(&self, dsid: u8) -> Vec<u64> {
        self.planes
            .borrow()
            .iter()
            .map(|plane| {
                plane
                    .dsid_completions
                    .iter()
                    .find(|(id, _)| *id == dsid)
                    .map_or(0, |(_, count)| *count)
            })
            .collect()
    }
    /// Complete command spans for final bus-route checks by the mount. The
    /// handle is usable only if those physical targets route to this instance.
    pub fn command_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        for base in &self.apertures {
            for plane in 0..u64::from(self.layout.planes) {
                ranges.push((base + plane * self.layout.stride + 0x13ffc, 0x400));
            }
            ranges.push((base + self.broadcast + 0x13ffc, 0x400));
        }
        ranges
    }
    /// Resolve the complete write to an actual plane or the actual broadcast
    /// view. Unknown cache commands, values and readback never become success.
    fn target(&self, physical: u64) -> Result<(usize, usize, u64), &'static str> {
        if physical & 3 != 0 {
            return Err("MCC firmware DSID command is unaligned");
        }
        for (aperture, base) in self.apertures.iter().copied().enumerate() {
            let Some(offset) = physical.checked_sub(base) else {
                continue;
            };
            if offset
                .checked_add(4)
                .is_none_or(|end| end > self.layout.aperture_bytes)
            {
                continue;
            }
            let first = aperture * self.layout.planes as usize;
            let (first, count, register) =
                if (self.broadcast..self.broadcast + self.layout.stride).contains(&offset) {
                    (first, self.layout.planes as usize, offset - self.broadcast)
                } else if offset / self.layout.stride < u64::from(self.layout.planes) {
                    (
                        first + (offset / self.layout.stride) as usize,
                        1,
                        offset % self.layout.stride,
                    )
                } else {
                    continue;
                };
            if !(0x13ffc..0x143fc).contains(&register) {
                return Err("MCC firmware target is not a qualified DSID invalidation register");
            }
            return Ok((first, count, register));
        }
        Err("MCC firmware command does not target its mounted native controller")
    }
    pub fn check(&self, physical: u64) -> Result<(), &'static str> {
        let (first, count, _) = self.target(physical)?;
        if self.planes.borrow()[first..first + count]
            .iter()
            .any(|plane| !plane.dram_access)
        {
            return Err("MCC firmware DSID command after DRAM access disable");
        }
        Ok(())
    }
    pub fn invalidate(&self, physical: u64) -> Result<(), &'static str> {
        self.check(physical)?;
        let (first, count, register) = self.target(physical)?;
        let mut planes = self.planes.borrow_mut();
        // Preflight above covers every affected plane. Each commit is
        // infallible for the source-qualified command and coherent backend.
        for plane in &mut planes[first..first + count] {
            retire_invalidation(plane, register);
        }
        Ok(())
    }
}
