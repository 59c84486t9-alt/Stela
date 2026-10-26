// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015, Intel Corporation.
//! Firmware-assigned, polled NVMe attachment below an owned VMD hierarchy.
//!
//! This consumes the actual host, not an MCFG alias for a synthetic segment.
//! The platform must already own the real requester-alias IOMMU domain. There
//! is deliberately no identity-DMA fallback, hotplug or BAR reassignment.
use super::*;
use crate::{
    Clock,
    block::BlockError,
    bus::{
        dma::{mapping::DmaDomain, memory::PageSource},
        mmio::owned::{Authority, CacheAttribute, Protection, Resource},
    },
    storage::nvme::{Attached, owned},
};
use alloc::{boxed::Box, rc::Rc, string::String, sync::Arc};
use core::cell::RefCell;

mod capabilities;
mod hierarchy;
use hierarchy::Hierarchy;

struct Returned<R>(Option<R>);
impl<R> Drop for Returned<R> {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            core::mem::forget(owner);
        }
    }
}
/// Receives the exact original stopped parent Function, resource reservations
/// and configuration mappings, only after the NVMe engine retired every RAM
/// mapping and its register mapping and then successfully stopped this Host.
/// This handoff does not detach the IOMMU domain or unmap parent configuration.
pub struct RetiredHierarchy<R = NativeRegisters>(Rc<RefCell<Returned<R>>>);
impl<R> RetiredHierarchy<R> {
    /// The owned NVMe teardown and actual Host stop published original owners.
    /// This does not certify domain detach or final parent mapping retirement.
    pub fn is_ready(&self) -> bool {
        self.0.borrow().0.is_some()
    }

    /// None means retirement has not completed, or an uncertain effect retained
    /// the hierarchy. Success returns original owners, never an active Host.
    /// The platform must finish its real domain/alias retirement and final
    /// mapping unmaps under those original owners. Retired NVMe namespace and
    /// controller handles can still hold the domain Arc; drop them before
    /// attempting a final config unmap whose domain binding pins that mapping.
    ///
    /// # Safety
    /// The actual old requester/alias domain attachment has retired under its
    /// real platform owner, and all stale NVMe namespace/controller handles
    /// have been dropped. A returned owner or unmapped RAM alone authorizes no
    /// reset, reassignment or new DMA attachment. Final mapping unmaps still
    /// require the original platform's CPU/root/context acknowledgements.
    pub unsafe fn take_after_retirement(&mut self) -> Option<R> {
        self.0.borrow_mut().0.take()
    }
}

/// The firmware's complete sized BAR0 assignment, pinned to this original host.
/// A number obtained by probing a running BAR is not an ownership grant.
pub struct FirmwareBar {
    domain: u32,
    child: Address,
    low: u32,
    high: u32,
    bus_start: u64,
    bytes: u64,
    window: Window,
    resource: Resource,
}
impl FirmwareBar {
    /// # Safety
    /// `bytes` is the actual complete firmware-sized NVMe BAR0 reservation for
    /// `child` at this host's retained assignment/reset epoch. It is not an
    /// estimate, a new allocation or a size probe with decode enabled. The
    /// original VMD resource owner reserves the whole routed interval, including
    /// rounded mapping pages, exclusively from RAM and other child resources.
    /// The original takeover grant excludes reset/removal/reassignment and all
    /// firmware/foreign child access until the eventual owned attachment retires.
    pub unsafe fn claim(
        host: &mut Host<NativeRegisters>,
        child: Address,
        bytes: u64,
    ) -> Result<Self, Error> {
        host.check_live()?;
        hierarchy::parent_d0(host)?;
        if child.domain != host.domain
            || bytes < 0x2000
            || !bytes.is_power_of_two()
            || !bytes.is_multiple_of(4096)
        {
            return Err(Error::InvalidResource);
        }
        let (low, high) = {
            let mut config = host.config(child.bus, child.device, child.function)?;
            let low = config.read(0x10, 4)?;
            let high = if low & 6 == 4 {
                config.read(0x14, 4)?
            } else {
                0
            };
            (low, high)
        };
        let (bus_start, prefetchable) = bar_address(low, high, bytes)?;
        let (index, window) = host
            .windows
            .iter()
            .copied()
            .enumerate()
            .find(|(_, window)| {
                window.prefetchable == prefetchable && window.translate(bus_start, bytes).is_ok()
            })
            .ok_or(Error::InvalidResource)?;
        // This is the actual original parent reservation, not a new overlapping
        // child ResourceBacking manufactured from physical address metadata.
        let resource = host.io().resource(index + 1);
        let physical = window.translate(bus_start, bytes)?;
        let span = resource.physical_span();
        if !physical.is_multiple_of(4096)
            || physical < span.start()
            || physical
                .checked_add(bytes)
                .is_none_or(|end| end > span.end())
        {
            return Err(Error::InvalidResource);
        }
        Ok(Self {
            domain: host.domain,
            child,
            low,
            high,
            bus_start,
            bytes,
            window,
            resource,
        })
    }
}

fn bar_address(low: u32, high: u32, bytes: u64) -> Result<(u64, bool), Error> {
    if bytes < 0x2000
        || !bytes.is_power_of_two()
        || low == u32::MAX
        || low & 1 != 0
        || !matches!(low & 6, 0 | 4)
    {
        return Err(Error::InvalidResource);
    }
    let base = (u64::from(high) << 32) | u64::from(low & !15);
    if base == 0
        || !base.is_multiple_of(bytes)
        || base.checked_add(bytes).is_none()
        || (low & 6 == 0 && base + bytes > 1u64 << 32)
    {
        return Err(Error::InvalidResource);
    }
    Ok((base, low & 8 != 0))
}

fn block(error: Error) -> BlockError {
    match error {
        Error::ReadFailed | Error::Readback | Error::Mapping | Error::Quarantined => {
            BlockError::Protocol("VMD retained hierarchy access failed")
        }
        _ => BlockError::Unsupported("VMD firmware NVMe assignment or lifecycle"),
    }
}

/// Attach the selected firmware NVMe through actual VMD child configuration,
/// original parent resource reservations and the shared domain-owned engine.
/// Both success and error return a retirement handle. It receives original
/// owners only if actual teardown completed, including teardown on failed NVMe
/// initialization. Uncertain effects retain the original hierarchy/domain.
///
/// # Safety
/// `domain` is already installed on the actual parent requester and **every**
/// alias/child requester in this exact original hierarchy, with real isolation,
/// translated payload drain and qualified coherent completion observation. It
/// retains the original IOMMU/root/alias and hierarchy reset/assignment owners.
/// Neither a numeric VMD domain/BDF nor an unrelated DmaDomain establishes this
/// fact; the shared DmaDomain API has no runtime identity-query operation.
/// All other children and parent engines, IRQs and work are stopped/drained;
/// no other native source registration or child driver exists. Firmware/foreign
/// access, reset, removal, sleep and resource reassignment remain excluded for
/// this consumed host's complete lifetime. `authority` is the original real
/// native mapping authority for these retained resources and native CPU roots.
/// `bar` was claimed from this same actual host and complete firmware assignment.
/// All calls/final releases obey the providers' process/deferred context rules.
#[allow(clippy::type_complexity)]
pub unsafe fn attach(
    host: Host<NativeRegisters>,
    bar: FirmwareBar,
    domain: Arc<dyn DmaDomain>,
    authority: Authority,
    pages: &dyn PageSource,
    clock: Clock,
    label: String,
) -> Result<(Attached, RetiredHierarchy), (BlockError, RetiredHierarchy)> {
    // SAFETY: the public native boundary retains the actual mapping authority;
    // only this private factory seam varies in independent protocol tests.
    unsafe {
        attach_with_registers(host, bar, domain, pages, clock, label, |bar| {
            let mapping = map_registers(bar, &authority)?;
            let registers = owned::MappingRegisters::new(mapping).map_err(|(error, mapping)| {
                // Mapping Drop itself quarantines its original reservation and roots.
                drop(mapping);
                error
            })?;
            Ok(Box::new(registers))
        })
    }
}

// Same actual hierarchy/engine sequence for native mappings and the independent
// cfg(test) register peer. This never exposes a public model attachment route.
// SAFETY: the caller retains the matching original hierarchy/domain authority,
// and the factory retains registers for that exact selected controller.
#[allow(clippy::type_complexity)]
unsafe fn attach_with_registers<R: Registers + 'static>(
    host: Host<R>,
    bar: FirmwareBar,
    domain: Arc<dyn DmaDomain>,
    pages: &dyn PageSource,
    clock: Clock,
    label: String,
    registers: impl FnOnce(&FirmwareBar) -> Result<Box<dyn owned::Registers>, BlockError>,
) -> Result<(Attached, RetiredHierarchy<R>), (BlockError, RetiredHierarchy<R>)> {
    // SAFETY: the native/public path always uses the unchanged owned controller
    // policy. Only a cfg(test) model caller supplies the bounded model policy.
    unsafe {
        attach_with_registers_using(
            host,
            bar,
            domain,
            pages,
            clock,
            label,
            (registers, owned::attach),
        )
    }
}
type AttachPolicy = unsafe fn(
    Box<dyn owned::Registers>,
    Box<dyn owned::Lifecycle>,
    &dyn PageSource,
    Arc<dyn DmaDomain>,
    Clock,
    String,
) -> Result<Attached, BlockError>;

#[allow(clippy::type_complexity)]
unsafe fn attach_with_registers_using<R: Registers + 'static>(
    host: Host<R>,
    bar: FirmwareBar,
    domain: Arc<dyn DmaDomain>,
    pages: &dyn PageSource,
    clock: Clock,
    label: String,
    factories: (
        impl FnOnce(&FirmwareBar) -> Result<Box<dyn owned::Registers>, BlockError>,
        AttachPolicy,
    ),
) -> Result<(Attached, RetiredHierarchy<R>), (BlockError, RetiredHierarchy<R>)> {
    let (registers, attach_policy) = factories;
    let returned = Rc::new(RefCell::new(Returned(None)));
    let handle = RetiredHierarchy(Rc::clone(&returned));
    let result = (|| {
        let mut lifecycle = Box::new(Lifecycle {
            host: Some(host),
            returned,
            hierarchy: None,
            domain: Some(Arc::clone(&domain)),
            clock,
            phase: Phase::Claimed,
        });
        // Admit the shared NVMe controller's complete operation budget before
        // discovery performs any actual CFGBAR/config or mapping effects.
        crate::storage::nvme::validate_clock(clock)?;
        let prepared = Hierarchy::discover(lifecycle.host.as_mut().expect("retained"), &bar);
        lifecycle.hierarchy = Some(prepared.map_err(block)?);
        let registers = registers(&bar)?;
        // SAFETY: caller grants the actual original hierarchy/domain identity; the
        // reservation-backed mapping and consumed lifecycle refer to its selected
        // controller. No independent numeric-domain assertion is used as proof.
        unsafe { attach_policy(registers, lifecycle, pages, domain, clock, label) }
    })();
    match result {
        Ok(attached) => Ok((attached, handle)),
        Err(error) => Err((error, handle)),
    }
}
fn map_registers(
    bar: &FirmwareBar,
    authority: &Authority,
) -> Result<crate::bus::mmio::owned::Mapping, BlockError> {
    let physical = bar
        .window
        .translate(bar.bus_start, bar.bytes)
        .map_err(block)?;
    let offset = usize::try_from(physical - bar.resource.physical_span().start())
        .map_err(|_| block(Error::Address))?;
    let bytes = usize::try_from(bar.bytes).map_err(|_| block(Error::Address))?;
    authority
        .map(
            bar.resource.clone(),
            offset,
            bytes,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .map_err(|_| block(Error::Mapping))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Claimed,
    Prepared,
    Enabled,
    Disabled,
    Released,
    Quarantined,
}

struct Lifecycle<R: Registers> {
    host: Option<Host<R>>,
    returned: Rc<RefCell<Returned<R>>>,
    hierarchy: Option<Hierarchy>,
    domain: Option<Arc<dyn DmaDomain>>,
    clock: Clock,
    phase: Phase,
}
impl<R: Registers> Lifecycle<R> {
    fn transition(
        &mut self,
        effect: impl FnOnce(&mut Host<R>, &mut Hierarchy, Clock) -> Result<(), Error>,
    ) -> Result<(), BlockError> {
        if self.phase == Phase::Quarantined || self.phase == Phase::Released {
            return Err(block(Error::Quarantined));
        }
        let result = effect(
            self.host
                .as_mut()
                .ok_or_else(|| block(Error::Quarantined))?,
            self.hierarchy
                .as_mut()
                .ok_or_else(|| block(Error::InvalidResource))?,
            self.clock,
        );
        if result.is_err() {
            self.phase = Phase::Quarantined;
        }
        result.map_err(block)
    }
}
// SAFETY: the consumed original host serializes every child config effect.
// Real register readback proves Command changes; the owned engine independently
// stops NVMe, drains this same retained domain and unmaps before release.
unsafe impl<R: Registers> owned::Lifecycle for Lifecycle<R> {
    fn prepare(&mut self) -> Result<(), BlockError> {
        if self.phase != Phase::Claimed {
            return Err(block(Error::ActiveChild));
        }
        self.transition(|host, hierarchy, clock| hierarchy.prepare(host, clock))?;
        self.phase = Phase::Prepared;
        Ok(())
    }
    fn enable_dma(&mut self) -> Result<(), BlockError> {
        if self.phase != Phase::Prepared {
            return Err(block(Error::ActiveChild));
        }
        self.transition(|host, hierarchy, _| hierarchy.enable(host))?;
        self.phase = Phase::Enabled;
        Ok(())
    }
    fn disable_dma(&mut self) -> Result<(), BlockError> {
        if !matches!(
            self.phase,
            Phase::Claimed | Phase::Prepared | Phase::Enabled | Phase::Disabled
        ) {
            return Err(block(Error::Quarantined));
        }
        self.transition(|host, hierarchy, _| hierarchy.disable(host))?;
        self.phase = Phase::Disabled;
        Ok(())
    }
    fn release(&mut self) -> Result<(), BlockError> {
        if self.phase != Phase::Disabled {
            return Err(block(Error::ActiveChild));
        }
        self.transition(|host, hierarchy, _| hierarchy.recheck(host, false))?;
        let host = self.host.take().ok_or_else(|| block(Error::Quarantined))?;
        self.phase = Phase::Quarantined;
        // SAFETY: owned engine invokes release only after CC.EN0/RDY0,
        // hierarchy BM-clear, original-domain drain, all RAM unmaps and MMIO
        // retirement. This polled profile has no IRQ registrations.
        let registers = unsafe { host.retire() }.map_err(block)?;
        self.returned.borrow_mut().0 = Some(registers);
        self.phase = Phase::Released;
        self.domain = None;
        Ok(())
    }
}
impl<R: Registers> Drop for Lifecycle<R> {
    fn drop(&mut self) {
        if self.phase != Phase::Released {
            if let Some(host) = self.host.take() {
                core::mem::forget(host);
            }
            if let Some(domain) = self.domain.take() {
                core::mem::forget(domain);
            }
        }
    }
}

#[cfg(test)]
mod tests;
