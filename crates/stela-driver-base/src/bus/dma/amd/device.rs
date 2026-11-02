// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Author: Joerg Roedel <jroedel@suse.de>
//         Leo Duran <leo.duran@amd.com>
// DTE policy and host update ordering adapted from Linux drivers/iommu/amd
// at cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See platform/THIRD_PARTY.md.
//! Complete kept per-segment device-table RAM and native atomic updates.
//! This is not unit takeover, requester admission or a device DMA domain.
mod atomic;
mod entry;

use super::{
    format::{DomainId, FormatError, PhysicalAddress, TableLevel},
    memory::TableVisibility,
};
use crate::bus::dma::{
    mapping::DmaError,
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource, PinnedPages},
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use entry::{Entry, Policy};

pub const REQUESTERS: usize = 1 << 16;
pub const ENTRY_BYTES: usize = 32;
pub const DEVICE_TABLE_BYTES: usize = REQUESTERS * ENTRY_BYTES;
const TABLE_PAGE_BYTES: u64 = 4096;
const BASE_SIZE: u64 = DEVICE_TABLE_BYTES as u64 / TABLE_PAGE_BYTES - 1;
const DMA32_LIMIT: u64 = 1 << 32;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// Cumulative exposed owners kept by Drop, not reset/reclamation evidence.
pub fn quarantined_tables() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceTableError {
    Memory(MemoryError),
    Format(FormatError),
    Context(DmaError),
    Invalidation(DmaError),
    PolicyCount,
    InvalidProvider,
    PhysicalContiguity,
    AddressLimit,
    UnsupportedAtomic,
    Profile,
    ConcurrentWriter,
    Poisoned,
}

/// Query the CURRENT processor's half-DTE atomic capability. This observation
/// grants no root, RAM, source, retirement or permission to execute on another CPU.
pub fn original_data_atomic_supported() -> bool {
    atomic::supported()
}

/// Atomic first-half update for a genuinely owned original Device Table.
/// # Safety
/// `pointer` names first128 bits of an aligned, retained, coherent WB32-byte DTE
/// under actual original CPU/root/writer exclusion. It must not select the IRQ
/// half or an unrelated allocation. Complete original source/data retirement and
/// hardware-table-writer exclusion are supplied by the actual caller. Every
/// allowed execution CPU supports CX16; no migration occurs across this call.
/// Upper IRQ fields stay unchanged and required matched invalidation follows.
pub unsafe fn replace_original_data_half(
    pointer: NonNull<u64>,
    old: [u64; 2],
    new: [u64; 2],
) -> Result<(), DeviceTableError> {
    if !atomic::supported() {
        return Err(DeviceTableError::UnsupportedAtomic);
    }
    if !(pointer.as_ptr() as usize).is_multiple_of(16) {
        return Err(DeviceTableError::InvalidProvider);
    }
    // SAFETY: complete caller-owned original first-half/CPU/context grant above.
    if !unsafe { atomic::replace(pointer, old.map(u64::to_le), new.map(u64::to_le)) } {
        return Err(DeviceTableError::ConcurrentWriter);
    }
    Ok(())
}

/// Fixed real unit/segment context, allocation and completion ownership.
///
/// # Safety
/// Allocations provide fresh, currently zeroed CPU-exclusive table RAM. The
/// context keeps every unit using this segment table plus their IRQ,
/// command and completion resources. Only the admitted host-only profile is
/// active: unencrypted/SNP-disabled tables, no hardware DTE writes, guest
/// translation, ATS/PASID/PRI or interrupt-remapping table/pointer owners.
/// ATS/ATC must also be off for integrated non-PCI devices with alternate
/// signaling; missing PCI capabilities alone do not establish that fact. IVHD
/// ATCPermit metadata permits use but neither requires nor enables it here.
/// `enter` returns a real guard excluding other DTE writers and keeping a
/// checked CPU/process/root context through its Drop. CPU-affine validation
/// requires preventing migration; a context checked on every allowed CPU
/// need not prohibit scheduling. After a successful local CX16 probe every CPU
/// allowed under the guard must support CX16. No IRQ
/// callback may reenter this owner. The guard must admit completion IRQs during
/// invalidation; disabling delivery across that wait is not admissible.
/// Visibility performs coherent ordering
/// or checked cache maintenance, not a compiler-only fence.
/// `invalidate` acknowledges DTE/observed alias invalidation in every
/// relevant unit, plus full old-domain IOTLB invalidation when nonzero, before
/// success. It keeps all domain-ID reservations through that completion.
/// Unsupported operations, fault and timeout return failure; no queue-head or
/// elapsed-time observation substitutes. Enter/admission must not mutate DTEs.
pub unsafe trait DeviceTableHardware: PageSource + TableVisibility {
    type Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError>;
    fn invalidate(&self, requester: u16, old_domain: Option<DomainId>) -> Result<(), DmaError>;
}

struct State<H> {
    hardware: H,
    cpu: CpuMapping,
    physical: u64,
    policies: Vec<u8>,
    physical_bits: u8,
    entries: usize,
    original_irq: Option<Vec<[u64; 2]>>,
}

impl<H> State<H> {
    fn pointer(&self, requester: u16, word: usize) -> NonNull<u64> {
        assert!(word < 4, "bounded half-DTE word");
        assert!(
            usize::from(requester) < self.entries,
            "requester belongs to actual original table extent"
        );
        self.cpu
            .address(usize::from(requester) * ENTRY_BYTES + word * 8, 8)
            .expect("complete retained device table")
            .cast()
    }

    fn words(&self, requester: u16) -> [u64; 4] {
        core::array::from_fn(|word| {
            // SAFETY: complete kept WB table, bounded aligned word. The
            // admitted hardware is read-only and safe writers require &mut owner.
            u64::from_le(unsafe { self.pointer(requester, word).as_ptr().read_volatile() })
        })
    }

    fn policy(&self, requester: u16) -> Policy {
        Policy::new(self.policies[usize::from(requester)])
    }
}

/// A complete device table. Root exposure arms Drop quarantine of the
/// original full pin, immutable policy and fixed real unit context together.
pub struct DeviceTable<H: DeviceTableHardware> {
    state: Option<State<H>>,
    exposed: bool,
    poisoned: bool,
}

impl<H: DeviceTableHardware> DeviceTable<H> {
    /// Adopt the SAME actual original table after consumed data-only handoff.
    /// # Safety
    /// The actual native producer consumed the complete original source/unit
    /// retirement. These exact OS-transferred RAM pins are the still-published
    /// original DeviceTableBase, every ordinary data half is blocked and its
    /// matched invalidations/completion finished. No alias/other unit has an
    /// independent mutable owner. Original IRQ words/control/storage remain kept;
    /// this grants no IRQ delivery/history or root-mode retirement. Firmware
    /// requirements and no-SMM/bypass policy were qualified BEFORE effects.
    /// `hardware` retains the SAME original unit/queue/context, not a new cold
    /// owner justified by inactivity. Failures retain actual active backing.
    pub unsafe fn adopt_original_blocked(
        hardware: H,
        pages: PinnedPages,
        policies: &[u8],
        physical_bits: u8,
        expected_register: u64,
    ) -> Result<Self, DeviceTableError> {
        use super::original::{DataMode, Dte};
        use core::mem::ManuallyDrop;
        // Actual table is already hardware-visible; never release on a failed
        // callback/validation or unwind merely because no new Unit was returned.
        let kept = ManuallyDrop::new(Box::new((hardware, pages)));
        let (hardware, pages) = &**kept;
        let guard = hardware.enter().map_err(DeviceTableError::Context)?;
        if !atomic::supported() {
            return Err(DeviceTableError::UnsupportedAtomic);
        }
        PhysicalAddress::new(0, physical_bits).map_err(DeviceTableError::Format)?;
        let bytes = pages.logical_bytes();
        if bytes == 0
            || bytes > DEVICE_TABLE_BYTES
            || !bytes.is_multiple_of(TABLE_PAGE_BYTES as usize)
            || pages.page_shift() != 12
            || pages.bytes() != bytes
            || pages.cache_attribute() != CacheAttribute::WriteBack
            || policies.len() != REQUESTERS
        {
            return Err(DeviceTableError::InvalidProvider);
        }
        let physical = pages.physical_pages()[0];
        let register = physical | (bytes as u64 / TABLE_PAGE_BYTES - 1);
        if register != expected_register
            || physical
                .checked_add(bytes as u64)
                .is_none_or(|end| end > 1u64 << physical_bits)
        {
            return Err(DeviceTableError::AddressLimit);
        }
        for (index, &page) in pages.physical_pages().iter().enumerate() {
            if physical.checked_add(index as u64 * TABLE_PAGE_BYTES) != Some(page) {
                return Err(DeviceTableError::PhysicalContiguity);
            }
        }
        let cpu = pages
            .cpu_mapping_range(CacheAttribute::WriteBack, 0..bytes)
            .map_err(DeviceTableError::Memory)?;
        let pointer = cpu.address(0, bytes).map_err(DeviceTableError::Memory)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(TABLE_PAGE_BYTES as usize) {
            return Err(DeviceTableError::InvalidProvider);
        }
        let entries = bytes / ENTRY_BYTES;
        let mut irq = Vec::new();
        irq.try_reserve_exact(entries)
            .map_err(|_| DeviceTableError::Memory(MemoryError::OutOfMemory))?;
        for (requester, policy) in policies.iter().copied().take(entries).enumerate() {
            if policy & 0x30 != 0 {
                return Err(DeviceTableError::Profile);
            }
            let words = core::array::from_fn(|word| {
                // SAFETY: actual initialized original table, exact retained WB
                // CPU span, same writer guard; hardware writes are disabled.
                u64::from_le(unsafe {
                    pointer
                        .as_ptr()
                        .cast::<u64>()
                        .add(requester * 4 + word)
                        .read_volatile()
                })
            });
            if Dte::inspect_host(words, physical_bits)
                .map_err(|_| DeviceTableError::Profile)?
                .mode()
                != DataMode::WalkTerminated
            {
                return Err(DeviceTableError::Profile);
            }
            irq.push([words[2], words[3]]);
        }
        let retained_policy = policies[..entries].to_vec();
        drop(guard);
        let (hardware, pages) = *ManuallyDrop::into_inner(kept);
        drop(pages); // CPU mapping keeps the SAME underlying pin/backing owner.
        Ok(Self {
            state: Some(State {
                hardware,
                cpu,
                physical,
                policies: retained_policy,
                physical_bits,
                entries,
                original_irq: Some(irq),
            }),
            exposed: true,
            poisoned: false,
        })
    }

    pub fn entries(&self) -> usize {
        self.state.as_ref().expect("retained device table").entries
    }
    /// # Safety
    /// The producer admits the exact segment, all units and the host-only
    /// hardware profile/physical width. `policies` is the complete effective
    /// per-RID IVHD policy after range/alias resolution, not guessed from
    /// one GPU. All units' firmware ownership is resolved before root activation.
    pub unsafe fn new(
        hardware: H,
        policies: &[u8],
        physical_bits: u8,
    ) -> Result<Self, DeviceTableError> {
        PhysicalAddress::new(0, physical_bits).map_err(DeviceTableError::Format)?;
        if policies.len() != REQUESTERS {
            return Err(DeviceTableError::PolicyCount);
        }
        let mut retained_policy = Vec::new();
        retained_policy
            .try_reserve_exact(REQUESTERS)
            .map_err(|_| DeviceTableError::Memory(MemoryError::OutOfMemory))?;
        retained_policy.extend_from_slice(policies);
        let guard = hardware.enter().map_err(DeviceTableError::Context)?;
        if !atomic::supported() {
            return Err(DeviceTableError::UnsupportedAtomic);
        }
        let geometry = hardware.page_geometry().map_err(DeviceTableError::Memory)?;
        let request = DEVICE_TABLE_BYTES.max(geometry.base_bytes());
        let pages = hardware
            .allocate(request, geometry.base_bytes(), CacheAttribute::WriteBack)
            .map_err(DeviceTableError::Memory)?;
        if !geometry.supports(pages.page_shift())
            || pages.logical_bytes() != request
            || pages.bytes() < DEVICE_TABLE_BYTES
            || pages.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(DeviceTableError::InvalidProvider);
        }
        let physical = pages.physical_pages()[0];
        if !physical.is_multiple_of(TABLE_PAGE_BYTES)
            || physical
                .checked_add(DEVICE_TABLE_BYTES as u64)
                .is_none_or(|end| end > DMA32_LIMIT)
        {
            return Err(DeviceTableError::AddressLimit);
        }
        let native = 1usize << pages.page_shift();
        let used_pages = DEVICE_TABLE_BYTES.div_ceil(native);
        for (index, &page) in pages.physical_pages()[..used_pages].iter().enumerate() {
            if physical.checked_add((index * native) as u64) != Some(page) {
                return Err(DeviceTableError::PhysicalContiguity);
            }
        }
        let cpu = pages
            .cpu_mapping_range(CacheAttribute::WriteBack, 0..DEVICE_TABLE_BYTES)
            .map_err(DeviceTableError::Memory)?;
        let address = cpu
            .address(0, DEVICE_TABLE_BYTES)
            .map_err(DeviceTableError::Memory)?;
        if !(address.as_ptr() as usize).is_multiple_of(TABLE_PAGE_BYTES as usize) {
            return Err(DeviceTableError::InvalidProvider);
        }
        // Initial policy writes happen only while this fresh allocation is
        // unreachable by every remapper. Live IRQ-field preservation would
        // incorrectly erase the initial policy if applied to its zero image.
        for (requester, &flags) in retained_policy.iter().enumerate() {
            let words = Entry::blocked(Policy::new(flags)).words();
            for (word, value) in words.into_iter().enumerate() {
                // SAFETY: fresh exclusive complete table RAM, checked aligned
                // CPU span; no hardware or other software writer can reach it.
                unsafe {
                    address
                        .as_ptr()
                        .cast::<u64>()
                        .add(requester * 4 + word)
                        .write_volatile(value.to_le())
                };
            }
        }
        // SAFETY: exact WB CPU span; the guard excludes writers and
        // the fixed unsafe implementation supplies real hardware visibility.
        unsafe { hardware.publish(address, DEVICE_TABLE_BYTES) }
            .map_err(DeviceTableError::Memory)?;
        drop(guard);
        Ok(Self {
            state: Some(State {
                hardware,
                cpu,
                physical,
                policies: retained_policy,
                physical_bits,
                entries: REQUESTERS,
                original_irq: None,
            }),
            exposed: false,
            poisoned: false,
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Return the base-register image, arming retention before PA escape.
    /// This programs no register and grants no unit or requester ownership.
    pub fn register_for_publication(&mut self) -> Result<u64, DeviceTableError> {
        if self.poisoned {
            return Err(DeviceTableError::Poisoned);
        }
        self.exposed = true;
        let state = self.state.as_ref().expect("retained device table");
        Ok(state.physical
            | if state.original_irq.is_some() {
                (state.entries * ENTRY_BYTES) as u64 / TABLE_PAGE_BYTES - 1
            } else {
                BASE_SIZE
            })
    }

    /// Read the image under the real CPU/writer guard. Diagnostics may
    /// observe a poisoned owner; this grants no mutation, reuse or retirement.
    pub fn snapshot(&self, requester: u16) -> Result<[u64; 4], DeviceTableError> {
        let state = self.state.as_ref().expect("retained device table");
        if usize::from(requester) >= state.entries {
            return Err(DeviceTableError::Profile);
        }
        let _guard = state.hardware.enter().map_err(DeviceTableError::Context)?;
        Ok(state.words(requester))
    }

    /// # Safety
    /// The requester and complete alias group are stopped/drained with
    /// no queued DMA. The real root/mode is admitted; keep both old/new roots,
    /// domain reservations and pins until all group entries and required unit
    /// invalidations complete. Expose each page-table root before hardware use.
    /// Do not resume an alias until the complete group transaction succeeds.
    pub unsafe fn translate(
        &mut self,
        requester: u16,
        root: PhysicalAddress,
        level: TableLevel,
        domain: DomainId,
    ) -> Result<(), DeviceTableError> {
        if self.poisoned {
            return Err(DeviceTableError::Poisoned);
        }
        let state = self.state.as_ref().expect("retained device table");
        if usize::from(requester) >= state.entries {
            return Err(DeviceTableError::Profile);
        }
        let root = PhysicalAddress::new(root.value(), state.physical_bits)
            .map_err(DeviceTableError::Format)?;
        let new = Entry::translated(state.policy(requester), root, level, domain)?;
        self.update(requester, new)
    }

    /// # Safety
    /// As for translate: the entire alias group and all DMA/IRQ/deferred
    /// users are stopped/drained. Keep the old domain/root until every group
    /// entry is blocked and old-domain invalidation has completed.
    pub unsafe fn block(&mut self, requester: u16) -> Result<(), DeviceTableError> {
        if self.poisoned {
            return Err(DeviceTableError::Poisoned);
        }
        let state = self.state.as_ref().expect("retained device table");
        if usize::from(requester) >= state.entries {
            return Err(DeviceTableError::Profile);
        }
        self.update(requester, Entry::blocked(state.policy(requester)))
    }

    fn update(&mut self, requester: u16, new: Entry) -> Result<(), DeviceTableError> {
        let state = self.state.as_ref().expect("retained device table");
        let guard = state.hardware.enter().map_err(DeviceTableError::Context)?;
        if !atomic::supported() {
            return Err(DeviceTableError::UnsupportedAtomic);
        }
        self.poisoned = true;
        let old = if let Some(irq) = &state.original_irq {
            Entry::existing_original(
                state.words(requester),
                irq[usize::from(requester)],
                state.physical_bits,
            )?
        } else {
            Entry::existing(
                state.words(requester),
                state.policy(requester),
                state.physical_bits,
            )?
        };
        let new = new.preserving_interrupts(old).words();
        let words = old.words();
        // No callback/unwind may leave a partially changed live entry reusable.
        // Both admitted images have V=1 and GV=0: Linux's host-only transition
        // writes upper then lower. Advanced/invalid old profiles were refused.
        for (word, previous, next) in [
            (2, [words[2], words[3]], [new[2], new[3]]),
            (0, [words[0], words[1]], [new[0], new[1]]),
        ] {
            // Original adoption has MODE/STORAGE custody, with independent IRQ
            // history unresolved. Do not even rewrite an unchanged IRQ half.
            if word == 2 && state.original_irq.is_some() {
                continue;
            }
            // SAFETY: CX16 execution context remains checked by the guard;
            // aligned half-DTE in kept WB RAM with every writer excluded.
            if !unsafe {
                atomic::replace(
                    state.pointer(requester, word),
                    previous.map(u64::to_le),
                    next.map(u64::to_le),
                )
            } {
                return Err(DeviceTableError::ConcurrentWriter);
            }
        }
        let cpu = state
            .cpu
            .address(usize::from(requester) * ENTRY_BYTES, ENTRY_BYTES)
            .map_err(DeviceTableError::Memory)?;
        // SAFETY: exact aligned kept entry span; the fixed guard excludes
        // writers while real visibility completes, including its failure path.
        unsafe { state.hardware.publish(cpu, ENTRY_BYTES) }.map_err(DeviceTableError::Memory)?;
        state
            .hardware
            .invalidate(requester, old.domain())
            .map_err(DeviceTableError::Invalidation)?;
        // Guard teardown may also unwind in a hosted context. Do not mark the
        // owner reusable until the real execution/exclusion context is released.
        drop(guard);
        self.poisoned = false;
        Ok(())
    }

    /// # Safety
    /// Every unit using this base is detached/stopped and all walkers,
    /// invalidations/reset and posted writes have acknowledged completion.
    /// All old/new root, domain and IRQ-table lifetimes were separately retired.
    pub unsafe fn retire(&mut self) {
        self.exposed = false;
    }
}

impl<H: DeviceTableHardware> Drop for DeviceTable<H> {
    fn drop(&mut self) {
        if self.exposed {
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
            core::mem::forget(self.state.take());
        }
    }
}

#[cfg(test)]
mod tests;
