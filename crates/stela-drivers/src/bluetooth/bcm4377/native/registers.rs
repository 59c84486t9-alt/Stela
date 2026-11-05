// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stela contributors
//! Native volatile accesses through original kept UC BAR mappings.
use super::{Error, Space};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, PhysicalSpan, Protection};

/// Original native BAR0/2 resources, or an explicit independent model.
/// # Safety
/// Each span is the complete exclusive BAR resource, with an original
/// UC/RW mapping covering all accesses. Mappings keep the same native root /
/// reset epoch as configuration; no competing raw views/reset/removal exists.
/// Accesses have native width and bounds. Failed retirement must keep
/// uncertain mapping/resource owners, never release or reuse native storage.
pub unsafe trait Registers: 'static {
    fn spans(&self) -> [PhysicalSpan; 2];
    fn read32(&self, space: Space, offset: u32) -> Result<u32, Error>;
    fn write32(&self, space: Space, offset: u32, value: u32) -> Result<(), Error>;
    fn read8(&self, space: Space, offset: u32) -> Result<u8, Error>;
    /// # Safety
    /// All native source/posted/CPU/IRQ/callback/work accesses have stopped /
    /// drained. Future service/config/BAR access is permanently excluded.
    unsafe fn retire(&mut self) -> Result<(), Error>;
}
pub struct MappedRegisters {
    full_bars: [PhysicalSpan; 2],
    mappings: [Mapping; 2],
}
impl MappedRegisters {
    /// # Safety
    /// Both full spans and original mappings belong to this same native
    /// endpoint and kept assignment/reset epoch. They reserve complete BAR
    /// resources; native mappings are exclusive with no escaped views/accessors.
    /// Metadata matching is insufficient to grant real hardware ownership.
    /// Rejection returns the original mappings without native accesses.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub unsafe fn new(
        full_bars: [PhysicalSpan; 2],
        mappings: [Mapping; 2],
    ) -> Result<Self, (Error, [Mapping; 2])> {
        let valid = (|| {
            for (full, mapping) in full_bars.iter().zip(&mappings) {
                let span = mapping.physical_span().map_err(Error::Mapping)?;
                if span != *full
                    || mapping.attribute().map_err(Error::Mapping)? != CacheAttribute::Uncached
                    || mapping.protection().map_err(Error::Mapping)? != Protection::ReadWrite
                {
                    return Err(Error::Requirement(
                        "actual full original UC/RW BAR0/2 mappings",
                    ));
                }
                let pointer = mapping.address(0, 4).map_err(Error::Mapping)?;
                if !(pointer.as_ptr() as usize).is_multiple_of(4) {
                    return Err(Error::Requirement("aligned native BAR DWORD mapping"));
                }
            }
            Ok(())
        })();
        match valid {
            Ok(()) => Ok(Self {
                full_bars,
                mappings,
            }),
            Err(error) => Err((error, mappings)),
        }
    }
    fn mapping(&self, space: Space) -> Result<&Mapping, Error> {
        match space {
            Space::Bar0 => Ok(&self.mappings[0]),
            Space::Bar2 => Ok(&self.mappings[1]),
            _ => Err(Error::Requirement("native BAR register space")),
        }
    }
}
// SAFETY: constructor keeps original exclusive UC resources; each
// concrete access is bounded and exactly the native byte/DWORD requested.
unsafe impl Registers for MappedRegisters {
    fn spans(&self) -> [PhysicalSpan; 2] {
        self.full_bars
    }
    fn read32(&self, space: Space, offset: u32) -> Result<u32, Error> {
        if !offset.is_multiple_of(4) {
            return Err(Error::Requirement("aligned native BAR DWORD"));
        }
        let pointer = self
            .mapping(space)?
            .address(offset as usize, 4)
            .map_err(Error::Mapping)?;
        // SAFETY: checked aligned kept live UC DWORD, no Rust reference.
        Ok(unsafe { pointer.as_ptr().cast::<u32>().read_volatile() })
    }
    fn write32(&self, space: Space, offset: u32, value: u32) -> Result<(), Error> {
        if !offset.is_multiple_of(4) {
            return Err(Error::Requirement("aligned native BAR DWORD"));
        }
        let pointer = self
            .mapping(space)?
            .address(offset as usize, 4)
            .map_err(Error::Mapping)?;
        // SAFETY: checked native DWORD, never a W1C wider RMW.
        unsafe { pointer.as_ptr().cast::<u32>().write_volatile(value) };
        Ok(())
    }
    fn read8(&self, space: Space, offset: u32) -> Result<u8, Error> {
        let pointer = self
            .mapping(space)?
            .address(offset as usize, 1)
            .map_err(Error::Mapping)?;
        // SAFETY: checked UC byte, used for original OTP.
        Ok(unsafe { pointer.as_ptr().read_volatile() })
    }
    unsafe fn retire(&mut self) -> Result<(), Error> {
        for mapping in &mut self.mappings {
            // SAFETY: enclosing caller proves native completion/drain.
            unsafe { mapping.retire() }.map_err(Error::Mapping)?;
        }
        Ok(())
    }
}
