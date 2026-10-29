//! Typed actual Source-owned HPET counter consumer candidate.
use super::hpet::Descriptor;
use crate::native_mmio::{ExclusiveHpet, HpetMapping};
use alloc::sync::Arc;
use core::ptr::{read_volatile, write_volatile};
use stela_boot_core::hpet::{Geometry, coherent_counter};
use stela_drivers::{
    bus::mmio::owned::{CacheAttribute, Protection},
    platform::work::WorkError,
};

const ENABLED: u32 = 1;
const LEGACY: u32 = 2;
const TIMER_INTERRUPTS: u32 = 4 | 0x4000;

/// Owns genuine Source mapping/root pin. No caller-provided pointer or generic
/// lifetime token can instantiate this counter. There is no automatic stop in
/// Drop: uncertain state remains quarantined by the owned Mapping registry.
pub(crate) struct Counter {
    owned: HpetMapping,
    base: usize,
    geometry: Geometry,
    started: bool,
    closing: bool,
    retired: bool,
    original_config: u32,
}
impl Counter {
    /// # Safety
    /// Original running-counter owner retains control/exclusion and guarantees
    /// no stop/reset/counter-write/rate/decode/suspend discontinuity for the
    /// entire source lifetime. Actual firmware/SMM/native route users cannot
    /// alter this resource. Descriptor/mapping authenticity alone is no such
    /// continuity guarantee. Consumers check actual same CPU before raw reads.
    pub(crate) unsafe fn attach_running(owned: HpetMapping) -> Result<Self, WorkError> {
        Self::attach(owned, false)
    }

    /// The separately minted exclusive whole-controller handoff authorizes a
    /// main-counter enable only. Any legacy, comparator/FSB interrupt or pending
    /// status refuses; no unknown route/configuration is disabled or stolen.
    pub(crate) fn attach_exclusive(owned: ExclusiveHpet) -> Result<Self, WorkError> {
        Self::attach(owned.into_mapping(), true)
    }

    fn attach(owned: HpetMapping, may_enable: bool) -> Result<Self, WorkError> {
        owned.check_process()?;
        let descriptor = owned.descriptor();
        let mapping = owned.mapping();
        if mapping.physical_span().map_err(unavailable)? != descriptor.registers()
            || mapping.attribute().map_err(unavailable)? != CacheAttribute::Uncached
        {
            return Err(WorkError::Unavailable);
        }
        let base = mapping.address(0, 1024).map_err(unavailable)?.as_ptr() as usize;
        if !base.is_multiple_of(8) {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: process-qualified genuine Source UC mapping of exact span.
        let geometry = unsafe { descriptor.geometry(read32(base, 0), read32(base, 4))? };
        // SAFETY: same authentic retained exact register mapping.
        let original_config = unsafe { read32(base, 0x10) };
        let pending_mask = (1u32 << geometry.timers) - 1;
        // SAFETY: same authentic retained exact register mapping.
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
            owned,
            base,
            geometry,
            started,
            closing: false,
            retired: false,
            original_config,
        };
        if started {
            // SAFETY: non-Clone ExclusiveHpet was consumed; actual controller
            // handoff excludes all writers/in-flight routes. Only main enable
            // changes, preserving all reserved configuration bits.
            unsafe {
                write32(base, 0x10, original_config | ENABLED);
            }
        }
        // SAFETY: same retained process/resource. Readback orders prior write.
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
        Ok(&self.owned)
    }
    pub(crate) fn period_fs(&self) -> u32 {
        self.geometry.period_fs
    }
    pub(crate) fn descriptor(&self) -> Descriptor {
        self.owned.descriptor()
    }
    pub(crate) fn context(&self) -> &Arc<crate::engine::host::RootContext> {
        self.owned.context()
    }
    pub(crate) fn ns(&self, ticks: u64) -> Result<u64, WorkError> {
        self.geometry.ns(ticks).map_err(|_| WorkError::Exhausted)
    }
    /// Qualify genuine same physical CPU/root before the cached register read;
    /// no process-only Mapping call is made inside an ISR.
    pub(crate) fn read_irq(&self) -> Result<u64, WorkError> {
        if self.closing || self.retired {
            return Err(WorkError::Closed);
        }
        self.owned.check_irq_cpu()?;
        // HPET 1.0a 2.4.7 explicitly warns that even readq can be split
        // into two bus reads. Use ordered UC dword transactions and admit a
        // low word only when both surrounding high observations agree.
        for _ in 0..8 {
            // SAFETY: actual retained same CPU/allroot UC source, exact
            // aligned implemented high/low counter dwords inside live map.
            let (first, low, last) = unsafe {
                (
                    read32(self.base, 0xf4),
                    read32(self.base, 0xf0),
                    read32(self.base, 0xf4),
                )
            };
            if let Some(sample) = coherent_counter(first, low, last) {
                return Ok(sample);
            }
        }
        Err(WorkError::Unavailable)
    }
    /// # Safety
    /// Every Clock/Runtime/cached pointer/IRQ-entry user has finally stopped and
    /// drained before this process call. RootProcessScope remains live until
    /// actual mapping/TLB retirement acknowledgement. Wholeblock ownership is
    /// retained and no future source reader may start.
    pub(crate) unsafe fn retire(&mut self) -> Result<(), WorkError> {
        if self.retired {
            return Err(WorkError::Closed);
        }
        self.owned.check_process()?;
        self.closing = true;
        if self.started {
            // SAFETY: actual process/source ownership retained after complete
            // reader drain. Preserve firmware's original stopped configuration.
            let current = unsafe { read32(self.base, 0x10) };
            if current & (ENABLED | LEGACY) != ENABLED {
                return Err(WorkError::CorruptContext);
            }
            // SAFETY: sole actual wholeblock owner; no routes were changed.
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
        // SAFETY: real source consumer drain plus retained root process scope.
        unsafe { self.owned.retire_mapping() }?;
        self.retired = true;
        Ok(())
    }
}
fn unavailable<T>(_: T) -> WorkError {
    WorkError::Unavailable
}
unsafe fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: callers validate actual UC mapping, register bounds and alignment.
    unsafe { read_volatile((base + offset) as *const u32) }
}
unsafe fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: callers supply genuine exclusive handoff and exact writable map.
    unsafe { write_volatile((base + offset) as *mut u32, value) }
}
