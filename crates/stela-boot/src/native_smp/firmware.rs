//! Copy processor identity/capabilities while UEFI MP Services still owns APs.
//! Every callback returns before ExitBootServices; persistent executors use
//! Stela's own INIT/SIPI entry, stacks and control memory afterward.
pub(crate) use record::Capture;
use stela_boot_core::record;

use super::{
    memory_types::amd,
    topology::{self, Cpuid, Location, Msr, Processor, Snapshot},
};
use crate::{cpu::msr, handoff::Region, tables::PAGE};
use alloc::vec::Vec;
use core::{
    arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count},
    },
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use uefi::{
    boot::{self, AllocateType, MemoryType},
    proto::pi::mp::{CPU_V2_EXTENDED_TOPOLOGY, MpServices},
};

const MAGIC: u64 = 0x5354_4c53_4d50_3031;
const VERSION: u32 = 3;
const MAX_VARIABLE_MTRRS: usize = 16;
const CR4_OSXSAVE: u64 = 1 << 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    NoMpServices,
    ProcessorInventory,
    Topology(topology::Refusal),
    CoreCount,
    WrongBootstrapProcessor,
    SnapshotCapacity,
    SnapshotCallback,
    SnapshotTimeout,
    ProcessorIdentity,
    Memory,
    AmdMemoryControls,
}

impl Error {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::NoMpServices => "native cores need UEFI MP Services source identity",
            Self::ProcessorInventory => "native processor inventory is invalid",
            Self::Topology(_) => "native physical-core topology is ambiguous",
            Self::CoreCount => {
                "requested native count exceeds the available physical cores or the executor's core capacity"
            }
            Self::WrongBootstrapProcessor => {
                "native BSP differs from the firmware processor identity"
            }
            Self::SnapshotCapacity => "native per-core source observations exceed capacity",
            Self::SnapshotCallback => "firmware AP callback did not publish its source observation",
            Self::SnapshotTimeout => "firmware AP source observation did not finish before timeout",
            Self::ProcessorIdentity => {
                "native observed CPUID identity differs from firmware identity"
            }
            Self::Memory => "native source record allocation or extent is invalid",
            Self::AmdMemoryControls => {
                "AMD encrypted/SNP or fixed-attribute visibility controls are unqualified"
            }
        }
    }
}

/// Opens only fixed-attribute read/write visibility, without changing routing,
/// type, encryption or latent attributes. The original control/IF is restored
/// before the joined firmware callback returns, including early errors.
struct FixedVisibility {
    syscfg: u64,
    interrupts: bool,
    changed: bool,
}
impl FixedVisibility {
    /// # Safety
    /// Actual CPL0 AMD64 with observed MSR/MTRR/PAT controls, no concurrent writer on
    /// this processor. No SNP/encryption owner may lock the visibility control.
    unsafe fn open(fixed: bool) -> Result<Self, Error> {
        let flags: u64;
        unsafe {
            asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        let original = unsafe { msr::AMD_SYSCFG.read() };
        let mut guard = Self {
            syscfg: original,
            interrupts: flags & (1 << 9) != 0,
            changed: false,
        };
        if original & amd::ENCRYPTION != 0 {
            return Err(Error::AmdMemoryControls);
        }
        if fixed && original & amd::FIXED_MODIFY == 0 {
            guard.changed = true;
            unsafe {
                msr::AMD_SYSCFG.write(original | amd::FIXED_MODIFY);
            }
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            if unsafe { msr::AMD_SYSCFG.read() } != original | amd::FIXED_MODIFY {
                // With MtrrFixDramEn clear the fixed MTRRs' RdMem and WrMem
                // bits have no effect (AMD APM Vol. 2 7.7.4), so the type
                // bits read without the modify enable are the whole policy.
                if original & amd::FIXED_DRAM != 0 {
                    return Err(Error::AmdMemoryControls);
                }
                guard.changed = false;
                unsafe {
                    msr::AMD_SYSCFG.write(original);
                }
            }
        }
        Ok(guard)
    }
}
impl Drop for FixedVisibility {
    fn drop(&mut self) {
        // SAFETY: this guard cannot migrate or escape the synchronous CPL0
        // observation. Only the original known control value is restored.
        unsafe {
            if self.changed {
                core::sync::atomic::compiler_fence(Ordering::SeqCst);
                msr::AMD_SYSCFG.write(self.syscfg);
            }
            if self.interrupts {
                asm!("sti", options(nomem, nostack));
            }
        }
    }
}

fn cpuid(leaf: u32, subleaf: u32) -> Cpuid {
    let result = __cpuid_count(leaf, subleaf);
    Cpuid {
        leaf,
        subleaf,
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

fn push(snapshot: &mut Snapshot, record: Cpuid) -> Result<(), Error> {
    let slot = snapshot
        .records
        .get_mut(snapshot.count as usize)
        .ok_or(Error::SnapshotCapacity)?;
    *slot = record;
    snapshot.count += 1;
    Ok(())
}

fn push_msr(snapshot: &mut Snapshot, index: u32, value: u64) -> Result<(), Error> {
    let slot = snapshot
        .msrs
        .get_mut(snapshot.msr_count as usize)
        .ok_or(Error::SnapshotCapacity)?;
    *slot = Msr { index, value };
    snapshot.msr_count += 1;
    Ok(())
}

/// # Safety
/// Runs at CPL0 on this actual processor, either in a joined firmware
/// callback or under its owned native executor. No CPU feature is cached from
/// another processor, and unsupported leaves/MSRs are not probed.
pub(crate) unsafe fn observe() -> Result<Snapshot, Error> {
    let mut snapshot = Snapshot::default();
    let maximum = __cpuid(0).eax;
    let extended = __cpuid(0x8000_0000).eax;
    for leaf in [
        0,
        1,
        6,
        7,
        0x15,
        0x16,
        0x8000_0000,
        0x8000_0001,
        0x8000_0007,
        0x8000_0008,
        0x8000_001e,
    ] {
        if leaf
            <= if leaf & 0x8000_0000 == 0 {
                maximum
            } else {
                extended
            }
        {
            push(&mut snapshot, cpuid(leaf, 0))?;
        }
    }
    for leaf in [0xb, 0x1f, 0x8000_0026] {
        if leaf
            > if leaf & 0x8000_0000 == 0 {
                maximum
            } else {
                extended
            }
        {
            continue;
        }
        for subleaf in 0..8 {
            let record = cpuid(leaf, subleaf);
            push(&mut snapshot, record)?;
            if record.ebx == 0 || record.ecx >> 8 & 0xff == 0 {
                break;
            }
            if subleaf == 7 {
                return Err(Error::SnapshotCapacity);
            }
        }
    }
    let basic = snapshot.get(1, 0).ok_or(Error::ProcessorIdentity)?;
    if maximum >= 0xd && basic.ecx & (1 << 26) != 0 {
        let xstate = cpuid(0xd, 0);
        push(&mut snapshot, xstate)?;
        push(&mut snapshot, cpuid(0xd, 1))?;
        let components = u64::from(xstate.eax) | (u64::from(xstate.edx) << 32);
        for subleaf in [2, 5, 6, 7, 9, 17, 18] {
            if components & (1u64 << subleaf) != 0 {
                push(&mut snapshot, cpuid(0xd, subleaf))?;
            }
        }
    }
    // SAFETY: CPL0 observation; these controls and EFER exist in x86-64.
    unsafe {
        asm!("mov {}, cr0",out(reg) snapshot.cr0,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr3",out(reg) snapshot.cr3,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr4",out(reg) snapshot.cr4,options(nomem,nostack,preserves_flags));
        snapshot.efer = msr::EFER.read();
        if basic.edx & (1 << 9) != 0 {
            snapshot.apic_base = msr::APIC_BASE.read();
        }
        if basic.edx & (1 << 16) != 0 {
            snapshot.pat = msr::PAT.read();
            snapshot.pat_valid = true;
        }
        if basic.edx & (1 << 12) != 0 {
            let cap = msr::MTRR_CAP.read();
            let variables = (cap & 0xff) as usize;
            if variables > MAX_VARIABLE_MTRRS {
                return Err(Error::SnapshotCapacity);
            }
            push_msr(&mut snapshot, msr::MTRR_CAP.index, cap)?;
            push_msr(
                &mut snapshot,
                msr::MTRR_DEFAULT.index,
                msr::MTRR_DEFAULT.read(),
            )?;
            let amd_controls = amd::architectural(&snapshot);
            let visibility = if amd_controls {
                Some(FixedVisibility::open(cap & (1 << 8) != 0)?)
            } else {
                None
            };
            if cap & (1 << 8) != 0 {
                for index in [
                    0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f,
                ] {
                    push_msr(&mut snapshot, index, msr::rdmsr(index))?;
                }
            }
            if let Some(visibility) = visibility {
                let original = visibility.syscfg;
                drop(visibility);
                if msr::AMD_SYSCFG.read() != original {
                    return Err(Error::AmdMemoryControls);
                }
                // Do not report masked fixed zeros as physical source state.
                snapshot.amd_fixed_raw = true;
                push_msr(&mut snapshot, amd::SYSCFG, original)?;
                for index in amd::REGISTERS.into_iter().skip(1) {
                    push_msr(&mut snapshot, index, msr::rdmsr(index))?;
                }
            }
            for offset in 0..variables as u32 * 2 {
                let index = msr::MTRR_PHYS_BASE.at(offset).index;
                push_msr(&mut snapshot, index, msr::rdmsr(index))?;
            }
        }
        if snapshot
            .get(7, 0)
            .is_some_and(|record| record.ebx & (1 << 1) != 0)
        {
            push_msr(&mut snapshot, msr::TSC_ADJUST.index, msr::TSC_ADJUST.read())?;
        }
        if basic.ecx & ((1 << 26) | (1 << 27)) == (1 << 26) | (1 << 27)
            && snapshot.cr4 & CR4_OSXSAVE != 0
        {
            let (low, high): (u32, u32);
            asm!("xgetbv",in("ecx") 0u32,out("eax") low,out("edx") high,options(nomem,nostack,preserves_flags));
            snapshot.xcr0 = u64::from(low) | (u64::from(high) << 32);
            snapshot.xcr0_valid = true;
        }
    }
    Ok(snapshot)
}

struct Callback {
    observation: UnsafeCell<Option<Result<Snapshot, Error>>>,
    complete: AtomicBool,
}

extern "efiapi" fn observe_ap(argument: *mut c_void) {
    // SAFETY: blocking StartupThisAP retains this one callback record until
    // it returns or the firmware terminates the timed-out callback.
    unsafe {
        let callback = &*argument.cast::<Callback>();
        *callback.observation.get() = Some(observe());
        callback.complete.store(true, Ordering::Release);
    }
}

/// Observe the assignable physical cores (`min(physical, MAX_CORES)`) even when
/// no explicit assignment was given. The default assignment is that roster;
/// --native-cores narrows ownership explicitly, never supplies invented PEs.
pub(crate) fn capture_assignment(requested: Option<usize>) -> Result<(Region, usize), Error> {
    let region = capture(requested.unwrap_or(1))?;
    // SAFETY: capture just allocated and initialized this exact retained UEFI
    // allocation; before EBS its physical address is directly accessible.
    let physical = unsafe { Capture::from_raw(region.physical as *const u8, 0).physical_count };
    let assigned =
        topology::assignment_count(requested, physical as usize).map_err(|_| Error::CoreCount)?;
    Ok((region, assigned))
}

pub(crate) fn capture(requested: usize) -> Result<Region, Error> {
    let handle = boot::get_handle_for_protocol::<MpServices>().map_err(|_| Error::NoMpServices)?;
    let mp =
        boot::open_protocol_exclusive::<MpServices>(handle).map_err(|_| Error::NoMpServices)?;
    let count = mp
        .get_number_of_processors()
        .map_err(|_| Error::ProcessorInventory)?;
    if count.total == 0 || count.total > u32::MAX as usize || count.enabled > count.total {
        return Err(Error::ProcessorInventory);
    }
    let mut processors = Vec::with_capacity(count.total);
    // Either the complete inventory uses V2 coordinates or it uses legacy
    // coordinates; mixing flattened and hierarchical core keys refuses.
    let extended = mp.get_processor_info(CPU_V2_EXTENDED_TOPOLOGY).is_ok();
    for number in 0..count.total {
        let info = mp
            .get_processor_info(
                number
                    | if extended {
                        CPU_V2_EXTENDED_TOPOLOGY
                    } else {
                        0
                    },
            )
            .map_err(|_| Error::ProcessorInventory)?;
        let mut flags = 0;
        if info.is_bsp() {
            flags |= topology::BSP;
        }
        if info.is_enabled() {
            flags |= topology::ENABLED;
        }
        if info.is_healthy() {
            flags |= topology::HEALTHY;
        }
        let (location, thread) = if extended {
            let value = info.extended_information;
            (
                Location {
                    package: value.package,
                    module: value.module,
                    tile: value.tile,
                    die: value.die,
                    core: value.core,
                },
                value.thread,
            )
        } else {
            let value = info.location;
            (
                Location {
                    package: value.package,
                    core: value.core,
                    ..Location::default()
                },
                value.thread,
            )
        };
        processors.push(Processor {
            processor_number: number as u32,
            apic_id: info.processor_id,
            flags,
            topology_version: if extended { 2 } else { 1 },
            location,
            thread,
        });
    }
    let physical = topology::select(&processors).map_err(Error::Topology)?;
    let assignable =
        topology::assignment_count(None, physical.len()).map_err(|_| Error::CoreCount)?;
    if requested == 0 || requested > assignable {
        return Err(Error::CoreCount);
    }
    let selected = &physical[..assignable];
    if mp.who_am_i().map_err(|_| Error::WrongBootstrapProcessor)?
        != processors[selected[0]].processor_number as usize
    {
        return Err(Error::WrongBootstrapProcessor);
    }
    let mut snapshots = Vec::with_capacity(selected.len());
    for (slot, &index) in selected.iter().enumerate() {
        let snapshot = if slot == 0 {
            // SAFETY: UEFI executes the loader at CPL0 on the recorded BSP.
            unsafe { observe() }?
        } else {
            let mut callback = Callback {
                observation: UnsafeCell::new(None),
                complete: AtomicBool::new(false),
            };
            mp.startup_this_ap(
                processors[index].processor_number as usize,
                observe_ap,
                (&raw mut callback).cast(),
                None,
                Some(Duration::from_millis(500)),
            )
            .map_err(|_| Error::SnapshotTimeout)?;
            if !callback.complete.load(Ordering::Acquire) {
                return Err(Error::SnapshotCallback);
            }
            callback
                .observation
                .into_inner()
                .ok_or(Error::SnapshotCallback)??
        };
        if !snapshot.matches(processors[index]) {
            return Err(Error::ProcessorIdentity);
        }
        snapshots.push(snapshot);
    }
    let pages = record_pages(processors.len()).ok_or(Error::Memory)?;
    let memory = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|_| Error::Memory)?;
    // SAFETY: fresh owned firmware pages; all-zero is valid for this closed
    // record of integers/booleans/arrays. No large intermediate sits on a UEFI
    // stack. All protocol/callback/Vec borrows end before ExitBootServices.
    unsafe {
        memory.as_ptr().write_bytes(0, pages * PAGE as usize);
        let capture = Capture::from_raw_mut(memory.as_ptr(), processors.len());
        capture.magic = MAGIC;
        capture.version = VERSION;
        capture.processor_count = processors.len() as u32;
        capture.enabled_count = count.enabled as u32;
        capture.core_count = selected.len() as u32;
        capture.physical_count = physical.len() as u32;
        capture.processors.copy_from_slice(&processors);
        for (slot, &index) in selected.iter().enumerate() {
            capture.selected[slot] = index as u32;
            capture.snapshots[slot] = snapshots[slot];
        }
    }
    Ok(Region {
        physical: memory.as_ptr() as u64,
        bytes: (pages * PAGE as usize) as u64,
    })
}

/// Whole pages holding a record of `processors` inventory entries.
fn record_pages(processors: usize) -> Option<usize> {
    Some(Capture::layout(processors)?.size().div_ceil(PAGE as usize))
}

/// # Safety
/// This is the loader's immutable owned record, mapped in the engine physmap.
pub(crate) unsafe fn captured(region: Region) -> Result<&'static Capture, Error> {
    let header_pages = record_pages(0).ok_or(Error::Memory)?;
    if region.bytes < (header_pages as u64) * PAGE
        || region.physical == 0
        || !region.physical.is_multiple_of(PAGE)
    {
        return Err(Error::Memory);
    }
    let base = crate::layout::physical(region.physical) as *const u8;
    // SAFETY: caller retains the exact loader allocation and its physmap; the
    // header-only view lies within the checked region.
    let count = unsafe { Capture::from_raw(base, 0) }.processor_count as usize;
    if record_pages(count).map(|pages| pages as u64 * PAGE) != Some(region.bytes) {
        return Err(Error::Memory);
    }
    // SAFETY: the region holds exactly the record for `count` entries.
    let capture = unsafe { Capture::from_raw(base, count) };
    let physical = capture.physical_count as usize;
    if capture.magic != MAGIC
        || capture.version != VERSION
        || capture.core_count == 0
        || topology::assignment_count(None, physical) != Ok(capture.core_count as usize)
    {
        return Err(Error::ProcessorInventory);
    }
    let processors = &capture.processors;
    let all = topology::select(processors).map_err(Error::Topology)?;
    let selected = &all[..all.len().min(topology::MAX_CORES)];
    if all.len() != physical
        || capture.enabled_count as usize
            != processors
                .iter()
                .filter(|processor| processor.flags & topology::ENABLED != 0)
                .count()
    {
        return Err(Error::ProcessorInventory);
    }
    for (slot, &selected_index) in selected.iter().enumerate() {
        let index = capture.selected[slot] as usize;
        if selected_index != index
            || capture.snapshots[slot].msr_count as usize > topology::MAX_MSRS
            || !capture.snapshots[slot].matches(capture.processors[index])
        {
            return Err(Error::ProcessorIdentity);
        }
    }
    Ok(capture)
}
