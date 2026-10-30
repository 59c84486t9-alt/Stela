//! Source-owned HPET counter with live control and power eligibility.
use super::{hpet::Descriptor, tsc::PowerControl};
use crate::{
    engine::host::RootIdentity,
    native_mmio::{ExclusiveHpet, HpetMapping, NativeExclusiveHpet, NativeHpetMapping},
};
use alloc::sync::Arc;
use core::ptr::{read_volatile, write_volatile};
use stela_boot_core::hpet::{Geometry, coherent_counter};
use stela_drivers::{
    bus::mmio::owned::{CacheAttribute, Mapping, Protection},
    platform::work::WorkError,
};

const ENABLED: u32 = 1;
const LEGACY: u32 = 2;
const TIMER_INTERRUPTS: u32 = 4 | 0x4000;

/// These are distinct resource owners, never a caller-provided
/// pointer/lifetime facade. The scoped diagnostic path keeps its
/// finite RAM epoch; the production path keeps immutable RootIdentity only.
enum Owner {
    Scoped(HpetMapping),
    Native(NativeHpetMapping),
}
impl Owner {
    fn descriptor(&self) -> Descriptor {
        match self {
            Self::Scoped(owner) => owner.descriptor(),
            Self::Native(owner) => owner.descriptor(),
        }
    }
    fn identity(&self) -> &Arc<RootIdentity> {
        match self {
            Self::Scoped(owner) => owner.context().identity(),
            Self::Native(owner) => owner.identity(),
        }
    }
    fn check_process(&self) -> Result<(), WorkError> {
        match self {
            Self::Scoped(owner) => owner.check_process(),
            Self::Native(owner) => owner.check_process(),
        }
    }
    fn check_irq_cpu(&self) -> Result<(), WorkError> {
        match self {
            Self::Scoped(owner) => owner.check_irq_cpu(),
            Self::Native(owner) => owner.check_irq_cpu(),
        }
    }
    fn mapping(&self) -> Result<&Mapping, WorkError> {
        match self {
            Self::Scoped(owner) => Ok(owner.mapping()),
            Self::Native(owner) => owner.mapping(),
        }
    }
    unsafe fn retire_mapping(&mut self) -> Result<(), WorkError> {
        match self {
            // SAFETY: forwarded complete reader/IRQ/controller drain;
            // each variant keeps its own original resource/root permission.
            Self::Scoped(owner) => unsafe { owner.retire_mapping() },
            // SAFETY: same drain, using the production registry's owner.
            Self::Native(owner) => unsafe { owner.retire_mapping() },
        }
    }
}

/// Owns Source mapping/root pin. No caller-provided pointer or generic
/// lifetime token can instantiate this counter. There is no automatic stop in
/// Drop: uncertain state remains quarantined by the owned Mapping registry.
enum Eligibility {
    Scoped,
    Native(Result<PowerControl, WorkError>),
}
pub(crate) struct Counter {
    eligibility: Eligibility,
    owned: Owner,
    base: usize,
    geometry: Geometry,
    started: bool,
    closing: bool,
    retired: bool,
    original_config: u32,
}
impl Counter {
    /// # Safety
    /// Original running-counter owner keeps control/exclusion and guarantees
    /// no stop/reset/counter-write/rate/decode/suspend discontinuity for the
    /// entire source lifetime. Firmware/SMM/native route users cannot
    /// alter this resource. Descriptor/mapping authenticity alone is no such
    /// continuity guarantee. Consumers check same CPU before raw reads.
    pub(crate) unsafe fn attach_running(owned: HpetMapping) -> Result<Self, WorkError> {
        Self::attach(Owner::Scoped(owned), false)
    }

    /// The separately minted exclusive whole-controller handoff authorizes a
    /// main-counter enable only. Any legacy, comparator/FSB interrupt or pending
    /// status refuses; no unknown route/configuration is disabled or stolen.
    pub(crate) fn attach_exclusive(owned: ExclusiveHpet) -> Result<Self, WorkError> {
        Self::attach(Owner::Scoped(owned.into_mapping()), true)
    }

    pub(crate) fn attach_native_exclusive(owned: NativeExclusiveHpet) -> Result<Self, WorkError> {
        Self::attach(Owner::Native(owned.into_mapping()), true)
    }
    fn attach(owned: Owner, may_enable: bool) -> Result<Self, WorkError> {
        owned.check_process()?;
        let eligibility = match &owned {
            Owner::Scoped(_) => Eligibility::Scoped,
            Owner::Native(_) => Eligibility::Native(PowerControl::capture(owned.identity())),
        };
        let descriptor = owned.descriptor();
        let mapping = owned.mapping()?;
        if mapping.physical_span().map_err(unavailable)? != descriptor.registers()
            || mapping.attribute().map_err(unavailable)? != CacheAttribute::Uncached
        {
            return Err(WorkError::Unavailable);
        }
        let base = mapping.address(0, 1024).map_err(unavailable)?.as_ptr() as usize;
        if !base.is_multiple_of(8) {
            return Err(WorkError::Unavailable);
        }
        // Linux hpet_cfg_working: SB700 SMM initialization can transiently
        // return all ones after the first access. Only read this owned block;
        // no route or reserved bit is written to make it appear available.
        let original_config = working_config(base)?;
        // SAFETY: process-checked Source UC mapping of exact span.
        let geometry = unsafe { descriptor.geometry(read32(base, 0), read32(base, 4))? };
        let pending_mask = (1u32 << geometry.timers) - 1;
        // SAFETY: same authentic exact register mapping.
        if original_config & LEGACY != 0 || unsafe { read32(base, 0x20) } & pending_mask != 0 {
            return Err(WorkError::Busy);
        }
        for index in 0..geometry.timers {
            // SAFETY: geometry checked every configuration register footprint.
            if unsafe { read32(base, 0x100 + index * 0x20) } & TIMER_INTERRUPTS != 0 {
                return Err(WorkError::Busy);
            }
        }
        let started = original_config & ENABLED == 0;
        if started
            && (!may_enable || mapping.protection().map_err(unavailable)? != Protection::ReadWrite)
        {
            return Err(WorkError::Unavailable);
        }
        let result = Self {
            eligibility,
            owned,
            base,
            geometry,
            started,
            closing: false,
            retired: false,
            original_config,
        };
        if started {
            // SAFETY: non-Clone ExclusiveHpet was consumed; controller
            // handoff excludes all writers/in-flight routes. Only main enable
            // changes, preserving all reserved configuration bits.
            unsafe {
                write32(base, 0x10, original_config | ENABLED);
            }
        }
        // SAFETY: same process/resource. Readback orders prior write.
        if unsafe { read32(base, 0x10) } & (ENABLED | LEGACY) != ENABLED {
            return Err(WorkError::Unavailable);
        }
        let first = result.read_irq()?;
        for _ in 0..32 {
            let now = result.read_irq()?;
            if now > first {
                return Ok(result);
            }
            if now < first {
                return Err(WorkError::CorruptContext);
            }
        }
        Err(WorkError::Unavailable)
    }
    pub(crate) fn check_process(&self) -> Result<(), WorkError> {
        if self.closing || self.retired {
            return Err(WorkError::Closed);
        }
        self.owned.check_process()
    }
    pub(crate) fn owner(&self) -> Result<&HpetMapping, WorkError> {
        self.check_process()?;
        match &self.owned {
            Owner::Scoped(owner) => Ok(owner),
            Owner::Native(_) => Err(WorkError::Unavailable),
        }
    }
    /// Only a native resource plus eligible live platform can back
    /// an unbounded counter epoch. Scoped/C0 calibration does not mint one.
    pub(crate) fn continuous_period(&self) -> Result<u32, WorkError> {
        self.owned.check_irq_cpu()?;
        if self.closing || self.retired {
            return Err(WorkError::Closed);
        }
        match &self.eligibility {
            Eligibility::Native(Ok(control)) => {
                control.check(self.identity())?;
                Ok(self.geometry.period_fs)
            }
            Eligibility::Native(Err(error)) => Err(*error),
            Eligibility::Scoped => Err(WorkError::Unavailable),
        }
    }

    pub(crate) fn elapsed_bounds(
        &self,
        ticks: u64,
    ) -> Result<super::source::ElapsedBounds, WorkError> {
        self.continuous_period()?;
        self.geometry
            .elapsed_bounds(ticks)
            .map_err(|_| WorkError::Exhausted)
    }

    fn controls(&self) -> Result<(), WorkError> {
        if let Eligibility::Native(Ok(control)) = &self.eligibility {
            control.check(self.identity())?;
        }
        // SAFETY: caller first validates this real owner/IRQ CPU. Geometry
        // bounds every register; MMIO is the original UC mapping.
        unsafe {
            let geometry = self
                .descriptor()
                .geometry(read32(self.base, 0), read32(self.base, 4))?;
            if geometry.period_fs != self.geometry.period_fs
                || geometry.timers != self.geometry.timers
                || read32(self.base, 0x10) & (ENABLED | LEGACY) != ENABLED
            {
                return Err(WorkError::CorruptContext);
            }
            let mask = (1u32 << geometry.timers) - 1;
            if read32(self.base, 0x20) & mask != 0 {
                return Err(WorkError::Busy);
            }
            for timer in 0..geometry.timers {
                if read32(self.base, 0x100 + timer * 0x20) & TIMER_INTERRUPTS != 0 {
                    return Err(WorkError::Busy);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn period_fs(&self) -> u32 {
        self.geometry.period_fs
    }
    pub(crate) fn descriptor(&self) -> Descriptor {
        self.owned.descriptor()
    }
    pub(crate) fn identity(&self) -> &Arc<RootIdentity> {
        self.owned.identity()
    }
    /// A short active-spin reference, never an HPET continuity/PC10 grant.
    /// Require the production owner and the exact CPU identity;
    /// validate period/routing controls on both sides of the sample.
    pub(crate) fn calibration_sample(
        &self,
        identity: &Arc<RootIdentity>,
    ) -> Result<u64, WorkError> {
        if !matches!(&self.owned, Owner::Native(_)) || !Arc::ptr_eq(self.identity(), identity) {
            return Err(WorkError::Unavailable);
        }
        self.check_process()?;
        self.read_irq()
    }

    pub(crate) fn ns(&self, ticks: u64) -> Result<u64, WorkError> {
        self.geometry.ns(ticks).map_err(|_| WorkError::Exhausted)
    }
    /// Check same physical CPU/root before the cached register read;
    /// no process-only Mapping call is made inside an ISR.
    pub(crate) fn read_irq(&self) -> Result<u64, WorkError> {
        if self.closing || self.retired {
            return Err(WorkError::Closed);
        }
        self.owned.check_irq_cpu()?;
        self.controls()?;
        // HPET 1.0a 2.4.7 explicitly warns that even readq can be split
        // into two bus reads. Use ordered UC dword transactions and admit a
        // low word only when both surrounding high observations agree.
        for _ in 0..8 {
            // SAFETY: same CPU/allroot UC source, exact
            // aligned implemented high/low counter dwords inside live map.
            let (first, low, last) = unsafe {
                (
                    read32(self.base, 0xf4),
                    read32(self.base, 0xf0),
                    read32(self.base, 0xf4),
                )
            };
            if let Some(sample) = coherent_counter(first, low, last) {
                self.controls()?;
                self.owned.check_irq_cpu()?;
                return Ok(sample);
            }
        }
        Err(WorkError::Unavailable)
    }
    /// Verify advancement when a normal sample equals the preceding
    /// value. This is a C0 liveness probe, not a TSC rate or time grant.
    /// Linux hpet_counting uses a 200,000 raw-cycle budget; the finite read cap
    /// also prevents a broken/unavailable TSC from making this loop unbounded.
    pub(crate) fn progress_after(&self, previous: u64) -> Result<u64, WorkError> {
        self.owned.check_irq_cpu()?;
        let has_tsc = core::arch::x86_64::__cpuid_count(1, 0).edx & (1 << 4) != 0;
        let start = has_tsc.then(super::tsc::ordered);
        for _ in 0..1000 {
            let current = self.read_irq()?;
            if current != previous {
                if current.wrapping_sub(previous) > u64::MAX / 2 {
                    return Err(WorkError::CorruptContext);
                }
                return Ok(current);
            }
            if start.is_some_and(|start| super::tsc::ordered().wrapping_sub(start) >= 200_000) {
                break;
            }
        }
        Err(WorkError::Unavailable)
    }

    /// # Safety
    /// Every Clock/Runtime/cached pointer/IRQ-entry user has finally stopped and
    /// drained before this process call. The immutable identity (and a
    /// diagnostic source's finite scope) remains live until acknowledged unmap. Wholeblock ownership is
    /// and no future source reader may start.
    pub(crate) unsafe fn retire(&mut self) -> Result<(), WorkError> {
        if self.retired {
            return Err(WorkError::Closed);
        }
        self.owned.check_process()?;
        self.closing = true;
        if self.started {
            // SAFETY: process/source ownership kept after complete
            // reader drain. Preserve firmware's original stopped configuration.
            let current = unsafe { read32(self.base, 0x10) };
            if current & (ENABLED | LEGACY) != ENABLED {
                return Err(WorkError::CorruptContext);
            }
            // SAFETY: sole wholeblock owner; no routes were changed.
            // RMW preserves current reserved bits without assuming they stay
            // constant between separate register observations.
            unsafe {
                write32(self.base, 0x10, current & !ENABLED);
            }
            // SAFETY: same mapped controller readback acknowledges disable.
            if unsafe { read32(self.base, 0x10) } & (ENABLED | LEGACY)
                != self.original_config & (ENABLED | LEGACY)
            {
                return Err(WorkError::Unavailable);
            }
            self.started = false;
        }
        // SAFETY: real source consumer drain plus its root owner.
        unsafe { self.owned.retire_mapping() }?;
        self.retired = true;
        Ok(())
    }
}
fn unavailable<T>(_: T) -> WorkError {
    WorkError::Unavailable
}
unsafe fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: callers validate UC mapping, register bounds and alignment.
    unsafe { read_volatile((base + offset) as *const u32) }
}
unsafe fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: callers supply exclusive handoff and exact writable map.
    unsafe { write_volatile((base + offset) as *mut u32, value) }
}

fn working_config(base: usize) -> Result<u32, WorkError> {
    for _ in 0..1000 {
        // SAFETY: attach validated the exact owned UC controller mapping.
        let value = unsafe { read32(base, 0x10) };
        if value != u32::MAX {
            return Ok(value);
        }
    }
    Err(WorkError::Unavailable)
}
