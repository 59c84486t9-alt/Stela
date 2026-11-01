// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Owned VT-d remapped MSI routes and terminal, non-reused interrupt indexes.
//! Intel VT-d D51397-017 sections 5.1, 6.5.2 and 6.5.5 define the formats
//! and IEC/Wait drain. A fence drains old mapped deliveries, not upstream
//! requests; blocked indexes and their original root therefore remain held.
use super::*;
use alloc::boxed::Box;
use core::{cell::Cell, marker::PhantomData, ops::Deref};
use stela_drivers::bus::irq::MsiMessage;

mod queue;
#[cfg(test)]
mod tests;

const IQH: usize = 0x80;
const IQT: usize = 0x88;
const IQA: usize = 0x90;
const IRTA: usize = 0xb8;
const INTERRUPT_POINTER: u32 = 1 << 24;
const COMPATIBILITY: u32 = 1 << 23;
const PERSISTENT: u32 = TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP | COMPATIBILITY;
const QI_SUPPORT: u64 = 1 << 1;
const IR_SUPPORT: u64 = 1 << 3;
const EIM_REQUIRED: u64 = 1 << 61;
const ENTRIES: usize = PAGE / 16;
const TABLE_SIZE: u64 = 7;
// P=0 still blocks every request. FPD=1 suppresses the qualified absent-entry
// fault for intentionally delayed old traffic (VT-d 5.0 sections 5.1.4.1, 9.9).
// Unqualified faults and live-entry source checking remain fully enabled.
const BLOCKED_ENTRY: u64 = 1 << 1;

/// Immutable context endpoint shared from the original whole-root owner.
///
/// # Safety
/// This checks the original process CPU/root scope and refuses hard-IRQ,
/// wrong-CPU and unsupported root contexts before any Unit/mapping lock or
/// register operation. It is IRQ-safe, nonblocking and allocation-free, does
/// not reenter Unit, and grants no second root permission. RootOwner retains
/// this same endpoint; callers receive only Arc clones of its original owner.
pub unsafe trait Context: Send + Sync {
    fn check(&self) -> Result<(), VtdError>;
}

/// Original whole-root interrupt-policy ownership, retained with the tables.
///
/// # Safety
/// This is the same canonical native process/CPU/root epoch as Unit. Its
/// complete PCI/IOAPIC/HPET source inventory permits xAPIC interrupt remapping
/// with compatibility messages blocked. No source is live during takeover;
/// old firmware delivery, SMM, reset/routing writers, other CPUs and bypass
/// sources are excluded. Check observes that original execution/ownership
/// epoch; generation is nonzero, nonwrapping and immutable. An advertised
/// IR bit, DMA ownership or inactive target BDF alone grants none of this.
/// Check and context access are nonblocking, allocation-free and cannot
/// reenter Unit or acquire root/mapping locks; wrong context is refused before
/// such accesses. Final release requires acknowledged root retirement, never
/// IRQ context. Context returns an Arc clone of the retained original endpoint,
/// never a new permission or reconstructed CPU/root grant.
pub unsafe trait RootOwner: Send + Sync {
    fn context(&self) -> Arc<dyn Context>;
    fn check(&self) -> Result<(), VtdError>;
    fn generation(&self) -> u64;
}

/// Immutable metadata attached to the original exact MSI source owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    pub source_id: u16,
    pub configuration_epoch: u64,
    pub reset_epoch: u64,
}

/// Original configuration/reset retention for one exact MSI source identity.
///
/// # Safety
/// This owner belongs to the same original root/route epoch as the Unit it
/// is passed to. Its SID is the actual full 16-bit interrupt requester,
/// independently resolved from topology/MSI identity, not an arbitrary DMA
/// alias. No bridge/proxy, wildcard or unresolved peer shares this identity.
/// Configuration/reset epochs are nonzero, nonwrapping and immutable; check
/// observes the kept mapping and original process context and refuses changes.
/// No duplicate route/config/reset writer or old firmware delivery remains.
/// Check/identity are read-only and cannot allocate, block or reenter Unit;
/// they refuse invalid process context before any mapping/root lock. Dropping
/// it is process-affine and requires its own endpoint retirement.
pub unsafe trait ExactSourceOwner {
    fn check(&self) -> Result<(), VtdError>;
    fn identity(&self) -> SourceIdentity;
}

/// One checked fixed physical xAPIC target, not vector allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteTarget {
    destination: u8,
    vector: u8,
}
impl RouteTarget {
    pub fn new(destination: u8, vector: u8) -> Result<Self, VtdError> {
        if destination == 255 || !(32..255).contains(&vector) {
            return Err(VtdError::Unsupported);
        }
        Ok(Self {
            destination,
            vector,
        })
    }
    pub fn destination(self) -> u8 {
        self.destination
    }
    pub fn vector(self) -> u8 {
        self.vector
    }
}

/// An unpublished root grant whose Drop retains the original affine owner.
pub struct KeptRootOwner(ManuallyDrop<Box<dyn RootOwner>>);
impl Deref for KeptRootOwner {
    type Target = dyn RootOwner;
    fn deref(&self) -> &Self::Target {
        &**self.0
    }
}
impl KeptRootOwner {
    /// Extract the original unpublished owner for retry or final release.
    ///
    /// # Safety
    /// Check its original native process/root/CPU context first and keep its
    /// complete original lifetime obligations through subsequent use and Drop.
    /// No hardware exposure occurred through the refusal returning this owner.
    pub unsafe fn into_owner(mut self) -> Box<dyn RootOwner> {
        // SAFETY: sole extraction under the caller's original owner obligations.
        unsafe { ManuallyDrop::take(&mut self.0) }
    }
}
/// An unpublished source pin whose Drop retains its original affine owner.
pub struct KeptSourceOwner(ManuallyDrop<Box<dyn ExactSourceOwner>>);
impl Deref for KeptSourceOwner {
    type Target = dyn ExactSourceOwner;
    fn deref(&self) -> &Self::Target {
        &**self.0
    }
}
impl KeptSourceOwner {
    /// Extract the original unpublished owner for retry or final release.
    ///
    /// # Safety
    /// Check its original native process/root/CPU context first and keep its
    /// configuration/reset lifetime obligations through subsequent use/Drop.
    /// No route exposure occurred through the refusal returning this owner.
    pub unsafe fn into_owner(mut self) -> Box<dyn ExactSourceOwner> {
        // SAFETY: sole extraction under the caller's original owner obligations.
        unsafe { ManuallyDrop::take(&mut self.0) }
    }
}

/// Refusal before exposure returns the original whole-root grant.
pub struct EnableFailure {
    pub error: VtdError,
    pub returned: Option<KeptRootOwner>,
}
/// Refusal before index/table exposure returns the original source.
pub struct AllocationFailure {
    pub error: VtdError,
    pub returned: Option<KeptSourceOwner>,
}

/// Immutable identity of a permanently reserved actual interrupt index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteIdentity {
    pub index: u16,
    pub source: SourceIdentity,
    pub root_generation: u64,
    pub target: RouteTarget,
}
#[derive(Clone, Copy)]
struct Record {
    identity: RouteIdentity,
    fenced: bool,
}

pub(super) struct State {
    owner: KeptRootOwner,
    context: Arc<dyn Context>,
    generation: u64,
    root: u64,
    ring: Table,
    status: Table,
    table: Table,
    tail: usize,
    sequence: u64,
    token: u32,
    records: Vec<Record>,
    poisoned: bool,
    stopped: bool,
}
impl State {
    fn new<R: Registers>(
        unit: &Unit<R>,
        owner: KeptRootOwner,
        context: Arc<dyn Context>,
        root: u64,
    ) -> Result<Self, EnableFailure> {
        let prepared = (|| {
            owner.check()?;
            let generation = owner.generation();
            if generation == 0 {
                return Err(VtdError::Unsupported);
            }
            let mut records = Vec::new();
            records
                .try_reserve_exact(ENTRIES)
                .map_err(|_| VtdError::Memory)?;
            let ring = Table::new(unit.source, unit.physical_bits)?;
            let status = Table::new(unit.source, unit.physical_bits)?;
            let table = Table::new(unit.source, unit.physical_bits)?;
            owner.check()?;
            if owner.generation() != generation {
                return Err(VtdError::Unsupported);
            }
            Ok((generation, ring, status, table, records))
        })();
        match prepared {
            Ok((generation, ring, status, table, records)) => Ok(Self {
                generation,
                owner,
                context,
                root,
                ring,
                status,
                table,
                tail: 0,
                sequence: 0,
                token: 0,
                records,
                poisoned: true,
                stopped: false,
            }),
            Err(error) => Err(EnableFailure {
                error,
                returned: Some(owner),
            }),
        }
    }
    fn check<R: Registers>(&mut self, unit: &Unit<R>) -> Result<(), VtdError> {
        if self.poisoned || self.stopped {
            return Err(VtdError::Busy);
        }
        self.poisoned = true;
        self.check_hardware(unit)?;
        self.poisoned = false;
        Ok(())
    }
    fn check_hardware<R: Registers>(&self, unit: &Unit<R>) -> Result<(), VtdError> {
        self.context.check()?;
        self.owner.check()?;
        let status = unit.registers.read32(GSTS);
        if self.owner.generation() != self.generation
            || unit.registers.read64(CAP) != unit.cap
            || unit.registers.read64(ECAP) != unit.ecap
            || status == u32::MAX
            || status & PERSISTENT != unit.command.load(Ordering::Relaxed)
            || status & (ROOT_POINTER | INTERRUPT_POINTER) != ROOT_POINTER | INTERRUPT_POINTER
            || unit.registers.read64(RTADDR) != self.root
            || unit.registers.read32(PMEN) & (1 << 31 | 1) != 0
            || unit.registers.read64(IQA) != self.ring.physical()
            || unit.registers.read64(IRTA) != self.table.physical() | TABLE_SIZE
            || unit.registers.read32(FSTS) != 0
        {
            return Err(VtdError::Invalidation);
        }
        Ok(())
    }
    fn publish<R: Registers>(&self, unit: &Unit<R>, table: &Table) {
        if let Some(line) = unit.table_cacheline {
            table.flush(&*unit.registers, line)
        }
        publish();
    }
    fn record(&self, identity: RouteIdentity) -> Result<Record, VtdError> {
        let record = self
            .records
            .get(usize::from(identity.index))
            .copied()
            .ok_or(VtdError::Unsupported)?;
        if record.identity != identity {
            return Err(VtdError::Unsupported);
        }
        Ok(record)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if self.stopped && self.owner.check().is_ok() && self.owner.generation() == self.generation
        {
            // SAFETY: stopped is set only after IRE/QIE off and pointer removal;
            // Unit only drops this State after DMA root shutdown also completes.
            unsafe { ManuallyDrop::drop(&mut self.owner.0) }
        }
    }
}

impl<R: Registers> Unit<R> {
    /// Install a retained pre-arming whole-root policy; never a DMA-only grant.
    ///
    /// # Safety
    /// Owner is this original Unit's exclusive process/root/CPU grant. Every
    /// interrupt source under it permits compatibility-blocked xAPIC policy,
    /// is inactive and cannot race takeover. No old compatibility traffic,
    /// posted descriptor delivery, device IRQ/work/reset user or unknown
    /// source can remain. Native inventory/IOAPIC integration must establish
    /// these obligations before calling; this API does no native discovery.
    pub unsafe fn enable_interrupt_remapping(
        &self,
        owner: Box<dyn RootOwner>,
    ) -> Result<(), EnableFailure> {
        let owner = KeptRootOwner(ManuallyDrop::new(owner));
        let context = owner.context();
        if let Err(error) = context.check() {
            return Err(EnableFailure {
                error,
                returned: Some(owner),
            });
        }
        let mut guard = self.lock();
        let state = guard.state();
        let preflight = (|| {
            if state.shutdown || state.poisoned || self.with_interrupts(|irq| irq.is_some()) {
                return Err(VtdError::Busy);
            }
            owner.check()?;
            if self.ecap & (QI_SUPPORT | IR_SUPPORT) != QI_SUPPORT | IR_SUPPORT
                || self.ecap & EIM_REQUIRED != 0
                || self.registers.read64(ECAP) != self.ecap
                || self.registers.read32(GSTS) & PERSISTENT != TRANSLATION
                || self.registers.read32(FSTS) != 0
            {
                return Err(VtdError::Unsupported);
            }
            self.wait64(CCMD, CONTEXT_INVALIDATE)?;
            self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
            Ok(())
        })();
        if let Err(error) = preflight {
            return Err(EnableFailure {
                error,
                returned: Some(owner),
            });
        }
        let irq = State::new(self, owner, context, state.root.physical())?;
        // SAFETY: existing Unit lock exclusively owns the separate IRQ state.
        unsafe { *self.interrupts.get() = Some(irq) };
        let result = self.with_interrupts(|slot| {
            let irq = slot.as_mut().expect("installed IRQ state");
            // All targets and the root grant stay retained after exposure, even
            // on timeout/unwind. Only acknowledged root shutdown can drop them.
            (|| {
                irq.publish(self, &irq.ring);
                irq.publish(self, &irq.status);
                irq.publish(self, &irq.table);
                self.registers.write64(IQT, 0);
                self.registers.write64(IQA, irq.ring.physical());
                self.registers
                    .write64(IRTA, irq.table.physical() | TABLE_SIZE);
                self.set_control(QUEUED_INVALIDATION, true)?;
                self.write_command(INTERRUPT_POINTER)?;
                self.wait32(GSTS, INTERRUPT_POINTER, true)?;
                irq.poisoned = false;
                irq.execute(self, &[queue::Descriptor::iec(None)])?;
                irq.poisoned = true;
                self.set_control(INTERRUPT_REMAP, true)?;
                irq.check_hardware(self)?;
                irq.poisoned = false;
                Ok(())
            })()
        });
        result.map_err(|error| EnableFailure {
            error,
            returned: None,
        })
    }

    /// Allocate one fresh full-SID IM=0 route; no index is ever recycled.
    ///
    /// # Safety
    /// Source and target belong to this original admitted root and same kept
    /// configuration/reset/routing epoch. SID is the actual complete MSI SID,
    /// not a numeric DMA alias. Registry exclusively reserved this CPU/vector
    /// and keeps its callback before endpoint unmask. Every alternate
    /// MSI/MSI-X/INTx path is inactive. No source or other writer can issue
    /// this new message before publication returns successfully.
    pub unsafe fn allocate_interrupt_route(
        self: &Arc<Self>,
        source: Box<dyn ExactSourceOwner>,
        target: RouteTarget,
    ) -> Result<Route<R>, AllocationFailure> {
        let source = KeptSourceOwner(ManuallyDrop::new(source));
        if let Err(error) = source.check() {
            return Err(AllocationFailure {
                error,
                returned: Some(source),
            });
        }
        let mut guard = self.lock();
        let state = guard.state();
        let preflight = (|| {
            source.check()?;
            let identity = source.identity();
            if state.shutdown
                || state.poisoned
                || identity.configuration_epoch == 0
                || identity.reset_epoch == 0
                || !state.allowed.contains(&identity.source_id)
            {
                return Err(VtdError::Unsupported);
            }
            self.with_interrupts(|slot| {
                let irq = slot.as_mut().ok_or(VtdError::Unsupported)?;
                irq.check(self)?;
                irq.quiescent(self)?;
                if irq.sequence == u64::MAX {
                    return Err(VtdError::Exhausted);
                }
                if irq.records.len() == ENTRIES {
                    return Err(VtdError::Exhausted);
                }
                if irq
                    .records
                    .iter()
                    .any(|record| record.identity.source == identity)
                {
                    return Err(VtdError::Busy);
                }
                Ok((
                    identity,
                    irq.records.len() as u16,
                    irq.generation,
                    irq.context.clone(),
                ))
            })
        })();
        let (identity, index, root_generation, context) = match preflight {
            Ok(value) => value,
            Err(error) => {
                return Err(AllocationFailure {
                    error,
                    returned: Some(source),
                });
            }
        };
        let identity = RouteIdentity {
            index,
            source: identity,
            root_generation,
            target,
        };
        let result = self.with_interrupts(|slot| {
            let irq = slot.as_mut().expect("admitted IRQ state");
            // Burn before the first uncertain table mutation. Source is already
            // ManuallyDrop, so even a register peer panic keeps the config pin.
            // Capacity for all 256 records was reserved before hardware exposure.
            irq.records.push(Record {
                identity,
                fenced: false,
            });
            irq.poisoned = true;
            let entry = usize::from(index) * 2;
            irq.table
                .write(entry + 1, u64::from(identity.source.source_id) | 1 << 18);
            irq.publish(self, &irq.table);
            irq.table.write(
                entry,
                1 | u64::from(target.vector) << 16 | u64::from(target.destination) << 40,
            );
            irq.publish(self, &irq.table);
            irq.poisoned = false;
            if let Err(error) = irq.execute(self, &[queue::Descriptor::iec(Some(index))]) {
                irq.poisoned = true;
                return Err(error);
            }
            irq.poisoned = true;
            if source.check().is_err() || source.identity() != identity.source {
                irq.poisoned = true;
                return Err(VtdError::Unsupported);
            }
            irq.poisoned = false;
            Ok(())
        });
        if let Err(error) = result {
            return Err(AllocationFailure {
                error,
                returned: None,
            });
        }
        Ok(Route {
            unit: self.clone(),
            context,
            source,
            identity,
            precheck_failed: Cell::new(false),
            fenced: false,
            local: PhantomData,
        })
    }

    // Every caller holds the canonical Unit process-context lock. The closure
    // cannot return a borrow of IRQ state, and callers never nest this accessor.
    fn with_interrupts<T>(&self, operation: impl FnOnce(&mut Option<State>) -> T) -> T {
        // SAFETY: Unit's unique lock excludes every other IRQ-state accessor.
        unsafe { operation(&mut *self.interrupts.get()) }
    }
    pub(super) fn write_command(&self, pulse: u32) -> Result<(), VtdError> {
        // GCMD writes are undefined while an enhanced command is in flight.
        if self.cap & (1 << 61) != 0 {
            let response = self.registers.read64(0x410);
            if response == u64::MAX {
                return Err(VtdError::RegisterRead);
            }
            if response & 1 != 0 {
                return Err(VtdError::Busy);
            }
        }
        self.registers
            .write32(GCMD, self.command.load(Ordering::Relaxed) | pulse);
        Ok(())
    }
    fn set_control(&self, flag: u32, enabled: bool) -> Result<(), VtdError> {
        let previous = self.command.load(Ordering::Relaxed);
        self.command.store(
            if enabled {
                previous | flag
            } else {
                previous & !flag
            },
            Ordering::Relaxed,
        );
        self.write_command(0)?;
        self.wait32(GSTS, flag, enabled)
    }
    pub(super) fn check_interrupt_state(&self) -> Result<(), VtdError> {
        self.with_interrupts(|slot| match slot {
            Some(irq) if !irq.stopped => irq.check(self),
            _ => Ok(()),
        })
    }
    pub(super) fn queued_iotlb(
        &self,
        granularity: u8,
        did: u16,
        address: u64,
        mask: u8,
    ) -> Result<bool, VtdError> {
        self.with_interrupts(|slot| {
            let Some(irq) = slot.as_mut().filter(|irq| !irq.stopped) else {
                return Ok(false);
            };
            let descriptor = queue::Descriptor::iotlb(self.cap, granularity, did, address, mask)?;
            irq.execute(self, &[descriptor])?;
            Ok(true)
        })
    }
    pub(super) fn queued_global(&self, context: bool) -> Result<bool, VtdError> {
        self.with_interrupts(|slot| {
            let Some(irq) = slot.as_mut().filter(|irq| !irq.stopped) else {
                return Ok(false);
            };
            let iotlb = queue::Descriptor::iotlb(self.cap, 1, 0, 0, 0)?;
            if context {
                irq.execute(self, &[queue::Descriptor::context_global(), iotlb])?
            } else {
                irq.execute(self, &[iotlb])?
            }
            Ok(true)
        })
    }
    pub(super) fn interrupt_shutdown_ready(&self) -> Result<(), VtdError> {
        self.with_interrupts(|slot| {
            let Some(irq) = slot.as_mut() else {
                return Ok(());
            };
            if irq.stopped {
                return Ok(());
            }
            irq.check(self)?;
            if !irq.records.is_empty() {
                return Err(VtdError::Busy);
            }
            irq.quiescent(self)
        })
    }
    pub(super) fn stop_interrupt_remapping(&self) -> Result<(), VtdError> {
        self.with_interrupts(|slot| {
            let Some(irq) = slot.as_mut() else {
                return Ok(());
            };
            if irq.stopped {
                return Ok(());
            }
            irq.check(self)?;
            if !irq.records.is_empty() {
                return Err(VtdError::Busy);
            }
            irq.quiescent(self)?;
            irq.poisoned = true;
            self.set_control(INTERRUPT_REMAP, false)?;
            self.set_control(QUEUED_INVALIDATION, false)?;
            if self.registers.read64(IQH) != 0 {
                return Err(VtdError::Invalidation);
            }
            self.registers.write64(IRTA, 0);
            self.registers.write64(IQA, 0);
            self.registers.write64(IQT, 0);
            if self.registers.read64(IRTA) != 0
                || self.registers.read64(IQA) != 0
                || self.registers.read64(IQT) != 0
            {
                return Err(VtdError::Invalidation);
            }
            irq.stopped = true;
            irq.poisoned = false;
            Ok(())
        })
    }
}

/// Unique process-affine route. Drop retains its source pin even after fence.
pub struct Route<R: Registers> {
    unit: Arc<Unit<R>>,
    context: Arc<dyn Context>,
    source: KeptSourceOwner,
    identity: RouteIdentity,
    precheck_failed: Cell<bool>,
    fenced: bool,
    local: PhantomData<*mut ()>,
}
pub struct ReleaseFailure<R: Registers> {
    pub error: VtdError,
    pub route: Route<R>,
}
/// The original source pin and root-only terminal after endpoint retirement.
/// Source release remains subject to the caller's final BAR/config obligations;
/// field order keeps the terminal root held while that source owner is dropped.
pub struct ReleasedEndpoint<R: Registers> {
    pub source: Box<dyn ExactSourceOwner>,
    pub terminal: TerminalRoute<R>,
}
/// Root-only terminal proof; old index remains reserved after this is dropped.
pub struct TerminalRoute<R: Registers> {
    unit: Arc<Unit<R>>,
    context: Arc<dyn Context>,
    identity: RouteIdentity,
    local: PhantomData<*mut ()>,
}
impl<R: Registers> Route<R> {
    fn precheck(&self) -> Result<(), VtdError> {
        // Context refusal must happen even if this CPU interrupted a caller
        // already holding Unit's lock. No source/register access precedes it.
        self.context.check()?;
        if self.precheck_failed.replace(true) {
            return Err(VtdError::Busy);
        }
        self.source.check()?;
        if self.source.identity() != self.identity.source {
            return Err(VtdError::Unsupported);
        }
        self.precheck_failed.set(false);
        Ok(())
    }
    fn check(&self) -> Result<(), VtdError> {
        self.unit.with_interrupts(|slot| {
            let irq = slot.as_mut().ok_or(VtdError::Unsupported)?;
            irq.check(&self.unit)?;
            // External source callbacks cannot unwind past a healthy route.
            irq.poisoned = true;
            self.source.check()?;
            if self.source.identity() != self.identity.source {
                return Err(VtdError::Unsupported);
            }
            irq.record(self.identity)?;
            irq.poisoned = false;
            Ok(())
        })
    }
    pub fn identity(&self) -> RouteIdentity {
        self.identity
    }
    pub fn message(&self) -> Result<MsiMessage, VtdError> {
        self.precheck()?;
        let _guard = self.unit.lock();
        self.check()?;
        if self.fenced {
            return Err(VtdError::Busy);
        }
        let index = u64::from(self.identity.index);
        Ok(MsiMessage {
            address: 0xfee0_0010 | (index & 0x7fff) << 5 | (index >> 15) << 2,
            data: 0,
        })
    }
    /// Terminal cut and old mapped delivery drain to the LAPIC, not ingress.
    ///
    /// # Safety
    /// This exact original source/reset epoch cannot resume: engines and all
    /// alternate routes are stopped, every MSI/MSI-X entry is masked with
    /// acknowledgement, translated payload completion is independent and
    /// acknowledged, and config/BAR/DMA/callback owners remain kept.
    pub unsafe fn fence(&mut self) -> Result<(), VtdError> {
        self.precheck()?;
        let _guard = self.unit.lock();
        self.check()?;
        if self.fenced {
            return Ok(());
        }
        self.unit.with_interrupts(|slot| {
            let irq = slot.as_mut().expect("checked IRQ owner");
            irq.quiescent(&self.unit)?;
            if irq.sequence == u64::MAX {
                return Err(VtdError::Exhausted);
            }
            irq.poisoned = true;
            irq.table
                .write(usize::from(self.identity.index) * 2, BLOCKED_ENTRY);
            irq.publish(&self.unit, &irq.table);
            irq.poisoned = false;
            irq.execute(
                &self.unit,
                &[queue::Descriptor::iec(Some(self.identity.index))],
            )?;
            irq.records[usize::from(self.identity.index)].fenced = true;
            Ok(())
        })?;
        self.check()?;
        self.fenced = true;
        Ok(())
    }
    /// Return the original source pin only after this same native epoch retires.
    ///
    /// # Safety
    /// This exact route's CPU IRR/ISR, callbacks/EOI and callback-created work
    /// have retired in the canonical Registry, and its same original endpoint
    /// is stopped, payload-complete, all DMA leases unmapped and requester
    /// detached. No reset/reprobe changed its epoch. Keep the returned source
    /// owner until the original native BAR/configuration retirement completes;
    /// a vector/stopped boolean or this fence alone supplies none of these.
    pub unsafe fn release_after_retirement(
        mut self,
    ) -> Result<ReleasedEndpoint<R>, ReleaseFailure<R>> {
        if let Err(error) = self.precheck() {
            return Err(ReleaseFailure { error, route: self });
        }
        let check = {
            let _guard = self.unit.lock();
            self.check().and(if self.fenced {
                Ok(())
            } else {
                Err(VtdError::Busy)
            })
        };
        if let Err(error) = check {
            return Err(ReleaseFailure { error, route: self });
        }
        // SAFETY: sole extraction after caller's explicit same-epoch retirement.
        let source = unsafe { ManuallyDrop::take(&mut self.source.0) };
        Ok(ReleasedEndpoint {
            source,
            terminal: TerminalRoute {
                unit: self.unit.clone(),
                context: self.context.clone(),
                identity: self.identity,
                local: PhantomData,
            },
        })
    }
}
impl<R: Registers> TerminalRoute<R> {
    pub fn identity(&self) -> RouteIdentity {
        self.identity
    }
    pub fn check(&self) -> Result<(), VtdError> {
        self.context.check()?;
        let _guard = self.unit.lock();
        self.unit.with_interrupts(|slot| {
            let irq = slot.as_mut().ok_or(VtdError::Unsupported)?;
            irq.check(&self.unit)?;
            if !irq.record(self.identity)?.fenced {
                return Err(VtdError::Busy);
            }
            Ok(())
        })
    }
}

impl core::fmt::Debug for EnableFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnableFailure")
            .field("error", &self.error)
            .field("returned", &self.returned.is_some())
            .finish()
    }
}
impl core::fmt::Debug for AllocationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AllocationFailure")
            .field("error", &self.error)
            .field("returned", &self.returned.is_some())
            .finish()
    }
}
impl<R: Registers> core::fmt::Debug for ReleaseFailure<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReleaseFailure")
            .field("error", &self.error)
            .field("route", &self.route.identity)
            .finish()
    }
}
