// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015, Intel Corporation.
//! Native UC access retaining original PCI and complete resource reservations.
use super::*;
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection, Resource},
    pci::{ConfigSpace, Function, owned::OwnedConfig, requester::StoppedRequester},
};

pub struct NativeResources {
    pub requester: StoppedRequester,
    /// Complete original CFGBAR, MEMBAR1 and MEMBAR2 reservations, in that order.
    pub bars: [Resource; 3],
    pub cfgbar: Mapping,
    /// UC view covering native/BIOS shadow registers in MEMBAR2. Vendor-shadow
    /// profiles need no shadow MMIO view. Never map the child resource region
    /// with an independent owner overlapping this reservation.
    pub shadow: Option<Mapping>,
    /// Actual reserved MEMBAR2 table/PBA mappings from the shared MSI-X owner.
    pub msix: Option<crate::bus::pci::msix::MappedBar>,
}
pub struct NativeRegisters {
    function: Function<OwnedConfig>,
    bars: [Resource; 3],
    descriptors: [(u64, u64, bool); 3],
    cfgbar: Mapping,
    shadow: Option<Mapping>,
    msix: Option<crate::bus::pci::msix::MappedBar>,
}
impl NativeRegisters {
    /// # Safety
    /// All resources belong to this exact actual VMD parent/reset epoch. Own
    /// all firmware-enumerated child config/reset/routing resources exclusively;
    /// every child engine, DMA/IRQ and work item has actually stopped/drained.
    /// The mapping authority grants real UC/RW CPU mappings, not physical-number
    /// casts. All access is process/deferred context; no callback or foreign
    /// config writer accesses the CFGBAR while a host/child borrow exists.
    /// No child BAR is reassigned without reserving its complete routed span.
    #[allow(clippy::result_large_err)]
    pub unsafe fn claim(mut resources: NativeResources) -> Result<Self, (Error, NativeResources)> {
        let valid = (|| {
            resources
                .requester
                .check_stopped()
                .map_err(|_| Error::ActiveChild)?;
            validate_mapping(&resources.cfgbar)?;
            if resources
                .cfgbar
                .physical_span()
                .map_err(|_| Error::Mapping)?
                != resources.bars[0].physical_span()
            {
                return Err(Error::InvalidResource);
            }
            for (i, bar) in resources.bars.iter().enumerate() {
                let span = bar.physical_span();
                if !span.start().is_multiple_of(4096) || !span.bytes().is_multiple_of(4096) {
                    return Err(Error::InvalidResource);
                }
                if resources.bars[..i].iter().any(|other| {
                    let o = other.physical_span();
                    o.start() < span.end() && span.start() < o.end()
                }) {
                    return Err(Error::InvalidResource);
                }
            }
            if let Some(mapping) = &resources.shadow {
                validate_mapping(mapping)?;
                let span = mapping.physical_span().map_err(|_| Error::Mapping)?;
                let bar = resources.bars[2].physical_span();
                if span.start() < bar.start() || span.end() > bar.end() {
                    return Err(Error::InvalidResource);
                }
            }
            if let Some(msix) = &resources.msix {
                use crate::bus::pci::msix::BarAccess;
                if msix.physical_span() != resources.bars[2].physical_span() {
                    return Err(Error::InvalidResource);
                }
            }
            Ok(())
        })();
        if let Err(error) = valid {
            return Err((error, resources));
        }
        let function = resources.requester.into_function();
        // Preserve original BAR classification, verified again against sized
        // descriptors by Host initialization's retained producer contract.
        let descriptors = core::array::from_fn(|i| {
            let span = resources.bars[i].physical_span();
            (
                span.start(),
                span.bytes(),
                resources.bars[i].kind()
                    == crate::bus::mmio::owned::ResourceKind::PrefetchableMemory,
            )
        });
        Ok(Self {
            function,
            bars: resources.bars,
            descriptors,
            cfgbar: resources.cfgbar,
            shadow: resources.shadow,
            msix: resources.msix,
        })
    }
    /// Actual stopped owners after Host::retire. Mappings still require their
    /// authority's acknowledged retire; dropping a Mapping quarantines it.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Function<OwnedConfig>,
        [Resource; 3],
        Mapping,
        Option<Mapping>,
        Option<crate::bus::pci::msix::MappedBar>,
    ) {
        (
            self.function,
            self.bars,
            self.cfgbar,
            self.shadow,
            self.msix,
        )
    }
}
fn validate_mapping(mapping: &Mapping) -> Result<(), Error> {
    if mapping.attribute().map_err(|_| Error::Mapping)? != CacheAttribute::Uncached
        || mapping.protection().map_err(|_| Error::Mapping)? != Protection::ReadWrite
    {
        return Err(Error::Mapping);
    }
    Ok(())
}
fn pointer(mapping: &Mapping, offset: usize, width: u8) -> Result<core::ptr::NonNull<u8>, Error> {
    if !matches!(width, 1 | 2 | 4 | 8) || !offset.is_multiple_of(usize::from(width)) {
        return Err(Error::Address);
    }
    let pointer = mapping
        .address(offset, usize::from(width))
        .map_err(|_| Error::Mapping)?;
    if !(pointer.as_ptr() as usize).is_multiple_of(usize::from(width)) {
        return Err(Error::Mapping);
    }
    Ok(pointer)
}
fn read(mapping: &Mapping, offset: usize, width: u8) -> Result<u64, Error> {
    let p = pointer(mapping, offset, width)?;
    // SAFETY: checked live UC view, bounds/alignment, exclusive retained epoch.
    Ok(unsafe {
        match width {
            1 => u64::from(p.as_ptr().read_volatile()),
            2 => u64::from(p.cast::<u16>().as_ptr().read_volatile()),
            4 => u64::from(p.cast::<u32>().as_ptr().read_volatile()),
            8 => p.cast::<u64>().as_ptr().read_volatile(),
            _ => unreachable!(),
        }
    })
}
// SAFETY: claim requires actual resources, stopped child hierarchy, exclusive
// parent/CFGBAR access and native UC mappings. No raw pointer survives access.
unsafe impl Registers for NativeRegisters {
    fn parent_read(&mut self, offset: u16, width: u8) -> Result<u32, Error> {
        if !matches!(width, 1 | 2 | 4)
            || !offset.is_multiple_of(u16::from(width))
            || usize::from(offset) + usize::from(width) > 4096
        {
            return Err(Error::Address);
        }
        Ok(match width {
            1 => u32::from(self.function.config().read8(offset)),
            2 => u32::from(self.function.config().read16(offset)),
            _ => self.function.config().read32(offset),
        })
    }
    fn parent_write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error> {
        if !matches!(width, 1 | 2 | 4)
            || !offset.is_multiple_of(u16::from(width))
            || usize::from(offset) + usize::from(width) > 4096
        {
            return Err(Error::Address);
        }
        match width {
            1 => self.function.config().write8(offset, value as u8),
            2 => self.function.config().write16(offset, value as u16),
            _ => self.function.config().write32(offset, value),
        }
        Ok(())
    }
    fn bar(&self, index: u8) -> (u64, u64, bool) {
        self.descriptors[match index {
            0 => 0,
            2 => 1,
            4 => 2,
            _ => panic!("invalid VMD BAR"),
        }]
    }
    fn shadow_read(&mut self, offset: usize) -> Result<u64, Error> {
        let mapping = self.shadow.as_ref().ok_or(Error::Mapping)?;
        let physical = self.descriptors[2]
            .0
            .checked_add(offset as u64)
            .ok_or(Error::Address)?;
        let base = mapping.physical_span().map_err(|_| Error::Mapping)?.start();
        let local = usize::try_from(physical.checked_sub(base).ok_or(Error::Address)?)
            .map_err(|_| Error::Address)?;
        read(mapping, local, 8)
    }
    fn child_read(&mut self, offset: usize, width: u8) -> Result<u32, Error> {
        if !matches!(width, 1 | 2 | 4) {
            return Err(Error::Address);
        }
        Ok(read(&self.cfgbar, offset, width)? as u32)
    }
    fn child_write(&mut self, offset: usize, width: u8, value: u32) -> Result<(), Error> {
        if !matches!(width, 1 | 2 | 4) {
            return Err(Error::Address);
        }
        let p = pointer(&self.cfgbar, offset, width)?;
        // SAFETY: exact-width bounded UC write. No adjacent W1C fields replayed.
        unsafe {
            match width {
                1 => p.as_ptr().write_volatile(value as u8),
                2 => p.cast::<u16>().as_ptr().write_volatile(value as u16),
                _ => p.cast::<u32>().as_ptr().write_volatile(value),
            }
        };
        // VMD converts config writes into posted writes; this read forces
        // completion, including for write-only/W1C fields where equality is not
        // an appropriate completion predicate.
        let _ = read(&self.cfgbar, offset, width)?;
        Ok(())
    }
    fn table_read(&mut self, offset: u64) -> Result<u32, Error> {
        use crate::bus::pci::msix::BarAccess;
        self.msix
            .as_ref()
            .ok_or(Error::Mapping)?
            .read32(offset)
            .map_err(|_| Error::Mapping)
    }
    fn table_write(&mut self, offset: u64, value: u32) -> Result<(), Error> {
        use crate::bus::pci::msix::BarAccess;
        self.msix
            .as_mut()
            .ok_or(Error::Mapping)?
            .write32(offset, value)
            .map_err(|_| Error::Mapping)
    }
}
