// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014-2019 aQuantia Corporation
// Copyright (C) 2019-2020 Marvell International Ltd.
//! Native AQtion cold preparation and the kept requester retirement owner.
use super::{MappedRegisters, Registers, Timer};
use crate::bus::{
    dma::{mapping::DmaError, memory::PageSource},
    mmio::owned,
    pci::requester::preparation::{self, PreparingRequester},
};
use alloc::boxed::Box;
use core::any::Any;

mod cold;
mod lifetime;
pub use lifetime::Attached;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Device(super::Error),
    Preparation(preparation::Error),
    Configuration(owned::Error),
    Power(crate::block::BlockError),
    Detach(DmaError),
    Profile {
        vendor: u16,
        device: u16,
        class: [u8; 3],
    },
    Bar {
        base: u64,
        bytes: u64,
    },
    BusMaster(u16),
    ConfigurationEpoch,
    Retired,
}
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Device(error)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Stela AQtion native: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Failed initialization retains the original cold or attached resource graph.
pub struct Failure {
    pub error: Error,
    _owner: Box<dyn Any>,
}
impl core::fmt::Debug for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Failure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// The register mapping kept until device/DMA and requester retirement.
///
/// # Safety
/// The window is this same function's complete UC BAR0 and reset epoch.
/// `physical_span` reports that actual kept mapping. An incomplete Drop retains
/// uncertain mappings/resources. Retirement preserves the owner on failure.
pub unsafe trait RetirableRegisters: Registers + 'static {
    fn physical_span(&self) -> super::Result<owned::PhysicalSpan>;
    /// # Safety
    /// This same device cannot resume; every DMA mapping is unmapped and its
    /// requester detached. All IRQ/work and CPU register users have retired.
    unsafe fn retire(&mut self) -> super::Result<()>;
}
// SAFETY: the owned mapping provides its bounds and retains failed retirement.
unsafe impl RetirableRegisters for MappedRegisters {
    fn physical_span(&self) -> super::Result<owned::PhysicalSpan> {
        Ok(self.mapping.physical_span()?)
    }
    unsafe fn retire(&mut self) -> super::Result<()> {
        // SAFETY: inherited complete device/DMA/IRQ/work/register-user contract.
        unsafe { self.mapping.retire() }?;
        Ok(())
    }
}

pub struct Inputs<R: RetirableRegisters, T: Timer + 'static> {
    pub requester: PreparingRequester,
    pub registers: R,
    pub timer: T,
}

/// # Safety
/// Inputs are the original exclusively owned function, UC BAR0 and qualified
/// timer in the same process/root context. Prior firmware, IRQ/work, bypass
/// and competing PCI writers are excluded; inherited DMA backing stays kept.
/// The page provider supplies stable coherent WB pages for this native domain.
pub unsafe fn attach<R: RetirableRegisters, T: Timer + 'static>(
    inputs: Inputs<R, T>,
    pages: &dyn PageSource,
) -> Result<Attached<R, T>, Failure> {
    // SAFETY: the caller supplies the original cold-owner and exclusion contract.
    let bound = unsafe { cold::prepare(inputs) }?;
    lifetime::attach(bound, pages)
}
