//! Loader-provided x86 resources: reserved RAM and the supervisor page tables.
//! Installation transfers their ownership once.
use super::sync::Mutex;
use crate::execution::boot_frames::{BootFramePool, BootFrames, BootRam, FrameError};
use alloc::{sync::Arc, vec::Vec};
use core::{arch::asm, ptr::NonNull};
use stela_compiler::TargetCpu;

const CR0_REQUIRED: u64 = 1 | (1 << 16) | (1 << 31);
const CR0_FP_DISABLED: u64 = (1 << 2) | (1 << 3);
const CR4_REQUIRED: u64 = (1 << 5) | (1 << 9) | (1 << 10);
const CR4_FORBIDDEN: u64 = (1 << 7) | (1 << 12) | (1 << 17);
const EFER_MSR: u32 = 0xc000_0080;
const EFER_REQUIRED: u64 = (1 << 10) | (1 << 11);
const FLAGS_IF: u64 = 1 << 9;
const CPUID_BASELINE: u32 = (1 << 0) | (1 << 5) | (1 << 24) | (1 << 25) | (1 << 26);
const CPUID_EXTENDED_MAX: u32 = 0x8000_0000;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_ADDRESS_SIZE: u32 = 0x8000_0008;
const CPUID_LONG_MODE_AND_NX: u32 = (1 << 29) | (1 << 20);
const PAGE_BYTES: usize = 4096;

/// A reserved identity-mapped arena and its empty 4 KiB page table, as input to
/// installation.
#[derive(Clone, Copy, Debug)]
pub struct BootArena {
    pub base: NonNull<u8>,
    pub pages: usize,
}

#[derive(Debug)]
pub enum MountError {
    AlreadyInstalled,
    Unmounted,
    UnsupportedCpuOrControls,
    ChangedRoot,
    OverlappingArenas,
    Storage(FrameError),
}
impl core::fmt::Display for MountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "freestanding platform mount failed: {self:?}")
    }
}
impl core::error::Error for MountError {}
impl MountError {
    pub(crate) fn storage_failure(self) -> FrameError {
        match self {
            Self::ChangedRoot => FrameError::ChangedRoot,
            Self::Storage(error) => error,
            _ => FrameError::UnsupportedControls,
        }
    }
}
impl From<FrameError> for MountError {
    fn from(value: FrameError) -> Self {
        Self::Storage(value)
    }
}

/// Actual privileged observations, retained for the development boot receipt.
/// They are a report, not a capability accepted by any execution entry.
#[derive(Clone, Copy, Debug)]
pub struct CpuObservation {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub flags: u64,
    pub cpuid1_ecx: u32,
    pub cpuid1_edx: u32,
    pub cpuid_extended_edx: u32,
    pub physical_bits: u32,
}
fn observe() -> Result<CpuObservation, MountError> {
    let cs: u16;
    let flags: u64;
    // SAFETY: CS/RFLAGS observations are unprivileged and leave state unchanged.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    if cs & 3 != 0 || flags & FLAGS_IF != 0 {
        return Err(MountError::UnsupportedCpuOrControls);
    }
    // SAFETY: CPUID exists on x86-64. Only reported standard/extended leaves
    // are queried, and privileged controls are read only after the CPL0 check.
    let (standard, extended) = {
        (
            core::arch::x86_64::__cpuid(0).eax,
            core::arch::x86_64::__cpuid(CPUID_EXTENDED_MAX).eax,
        )
    };
    if standard < 1 || extended < CPUID_ADDRESS_SIZE {
        return Err(MountError::UnsupportedCpuOrControls);
    }
    let one = core::arch::x86_64::__cpuid(1);
    let ext = core::arch::x86_64::__cpuid(CPUID_EXTENDED_FEATURES);
    let physical_bits = core::arch::x86_64::__cpuid(CPUID_ADDRESS_SIZE).eax & 0xff;
    if one.edx & CPUID_BASELINE != CPUID_BASELINE
        || ext.edx & CPUID_LONG_MODE_AND_NX != CPUID_LONG_MODE_AND_NX
        || !(32..=52).contains(&physical_bits)
    {
        return Err(MountError::UnsupportedCpuOrControls);
    }
    let (cr0, cr3, cr4): (u64, u64, u64);
    let (lo, hi): (u32, u32);
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        asm!("rdmsr", in("ecx") EFER_MSR, out("eax") lo, out("edx") hi,
             options(nostack, preserves_flags));
    }
    let efer = u64::from(lo) | (u64::from(hi) << 32);
    let mask = ((1u64 << physical_bits) - 1) & !(PAGE_BYTES as u64 - 1);
    if cr0 & CR0_REQUIRED != CR0_REQUIRED
        || cr0 & CR0_FP_DISABLED != 0
        || cr4 & CR4_REQUIRED != CR4_REQUIRED
        || cr4 & CR4_FORBIDDEN != 0
        || efer & EFER_REQUIRED != EFER_REQUIRED
        || cr3 == 0
        || cr3 & !mask != 0
        || cr3 >= 1 << 47
    {
        return Err(MountError::UnsupportedCpuOrControls);
    }
    Ok(CpuObservation {
        cr0,
        cr3,
        cr4,
        efer,
        flags,
        cpuid1_ecx: one.ecx,
        cpuid1_edx: one.edx,
        cpuid_extended_edx: ext.edx,
        physical_bits,
    })
}

struct Platform {
    root: u64,
    native: Vec<Arc<BootFramePool>>,
    ram: Vec<Arc<BootFramePool>>,
}
static PLATFORM: Mutex<Option<Platform>> = Mutex::new(None);

/// Hand the static arenas and root to the runtime.
///
/// # Safety
/// Runs at CPL0 on the boot processor with interrupts disabled, no other
/// processors, and no preemption or migration. NMI and fatal exception handlers
/// must stop without entering Rust, runtime or allocator locks, and the machine
/// must exclude SMI, firmware re-entry and DMA into these reservations. Every
/// arena, page table and root page is reserved live identity-mapped write-back
/// RAM, disjoint from each other and from the tables, image, heap, stack and
/// guest RAM, with no aliases or external writers. The caller keeps the root
/// and table identity mappings for the rest of the boot and transfers every
/// arena's reclamation and PTE obligations.
pub unsafe fn install(
    native: &[BootArena],
    ram: &[BootArena],
) -> Result<CpuObservation, MountError> {
    let mut platform = PLATFORM.lock().unwrap();
    if platform.is_some() {
        return Err(MountError::AlreadyInstalled);
    }
    let observed = observe()?;
    if native.is_empty() || ram.is_empty() {
        return Err(MountError::UnsupportedCpuOrControls);
    }
    let arenas: Vec<_> = native.iter().chain(ram).copied().collect();
    for (i, a) in arenas.iter().enumerate() {
        let start = a.base.as_ptr() as usize;
        let end = a
            .pages
            .checked_mul(PAGE_BYTES)
            .and_then(|bytes| start.checked_add(bytes))
            .ok_or(MountError::OverlappingArenas)?;
        for b in &arenas[..i] {
            let other = b.base.as_ptr() as usize;
            let other_end = b
                .pages
                .checked_mul(PAGE_BYTES)
                .and_then(|bytes| other.checked_add(bytes))
                .ok_or(MountError::OverlappingArenas)?;
            if start < other_end && other < end {
                return Err(MountError::OverlappingArenas);
            }
        }
    }
    let claim = |arenas: &[BootArena]| -> Result<Vec<Arc<BootFramePool>>, MountError> {
        arenas
            .iter()
            .map(|a| {
                // SAFETY: this function's contract covers the exclusive
                // resources; `claim` also checks the root, path and page
                // tables.
                unsafe { BootFramePool::claim(a.base, a.pages) }.map_err(MountError::from)
            })
            .collect()
    };
    let installed = Platform {
        root: observed.cr3,
        native: claim(native)?,
        ram: claim(ram)?,
    };
    if observe()?.cr3 != observed.cr3 {
        return Err(MountError::ChangedRoot);
    }
    *platform = Some(installed);
    Ok(observed)
}

pub(crate) fn ensure_live() -> Result<(), MountError> {
    let observed = observe()?;
    let platform = PLATFORM.lock().unwrap();
    let owner = platform.as_ref().ok_or(MountError::Unmounted)?;
    if observed.cr3 != owner.root {
        return Err(MountError::ChangedRoot);
    }
    if owner
        .native
        .iter()
        .chain(&owner.ram)
        .any(|pool| pool.failure().is_some())
    {
        return Err(MountError::Storage(FrameError::Quarantined));
    }
    for pool in owner.native.iter().chain(&owner.ram) {
        pool.validate_live()?;
    }
    Ok(())
}
pub(crate) fn admitted(target: TargetCpu) -> bool {
    // Extended targets stay unsupported until their control requirements are
    // mounted; the baseline still requires every live check.
    target == TargetCpu::Baseline && ensure_live().is_ok()
}
pub(crate) fn native(bytes: &[u8]) -> Result<BootFrames, MountError> {
    ensure_live()?;
    let pools = PLATFORM
        .lock()
        .unwrap()
        .as_ref()
        .ok_or(MountError::Unmounted)?
        .native
        .clone();
    for pool in pools {
        match pool.copy_native(bytes) {
            Ok(owner) => return Ok(owner),
            Err(FrameError::Exhausted) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(FrameError::Exhausted.into())
}
pub(crate) fn ram(
    initial: &[u8],
    leading: usize,
    bytes: usize,
    readable: bool,
    writable: bool,
) -> Result<BootRam, MountError> {
    ensure_live()?;
    let pools = PLATFORM
        .lock()
        .unwrap()
        .as_ref()
        .ok_or(MountError::Unmounted)?
        .ram
        .clone();
    for pool in pools {
        match pool.copy_ram(initial, leading, bytes, readable, writable) {
            Ok(owner) => return Ok(owner),
            Err(FrameError::Exhausted) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(FrameError::Exhausted.into())
}

/// Verify the hardware and storage after shutdown. A failure is terminal.
pub fn verify() -> Result<CpuObservation, MountError> {
    ensure_live()?;
    observe()
}
