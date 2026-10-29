//! The activated legacy table owner. This keeps real allocated table
//! pages and CPU/root/control observations. It supplies no controller, ECAM,
//! reset, cache-policy or hardware-service grant by itself.
use super::*;
use alloc::sync::Arc;
use core::{
    arch::x86_64::{__cpuid, __cpuid_count},
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_boot_core::guarded_stacks::mappings;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootError {
    Privilege,
    CpuFeatures,
    InterruptsEnabled,
    WrongCpu,
    RootChanged,
    ControlsChanged,
    NotActivated,
    Closed,
    CatalogSize,
    CatalogAllocation(uefi::Status),
    Traversal(mappings::Error),
    AliasMissing { physical: u64 },
    AliasMismatch { physical: u64 },
    Transition(&'static str),
}
impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Privilege => f.write_str("native root requires CPL0"),
            Self::CpuFeatures => f.write_str("native root requires actual MSR/APIC/PAT support"),
            Self::InterruptsEnabled => {
                f.write_str("native root activation requires excluded interrupts")
            }
            Self::WrongCpu => f.write_str("native root accessed on a foreign processor"),
            Self::RootChanged => f.write_str("native root CR3 changed"),
            Self::ControlsChanged => f.write_str("native root controls or PAT changed"),
            Self::NotActivated => f.write_str("new table root was not actually activated"),
            Self::Closed => f.write_str("native root ownership was closed after a context change"),
            Self::CatalogSize => f.write_str("loader catalog size overflows or is empty"),
            Self::CatalogAllocation(status) => {
                write!(f, "loader catalog allocation failed: {status:?}")
            }
            Self::Traversal(error) => write!(f, "owned page-table traversal refused: {error:?}"),
            Self::AliasMissing { physical } => {
                write!(f, "native tables omit their frame mapping at {physical:#x}")
            }
            Self::AliasMismatch { physical } => {
                write!(f, "native table-frame mapping mismatches at {physical:#x}")
            }
            Self::Transition(error) => f.write_str(error),
        }
    }
}
const BSP: u64 = 1 << 8;
#[derive(Clone, Copy)]
struct Context {
    cpu: u32,
    apic: u64,
    root: u64,
    cr0: u64,
    cr4: u64,
    efer: u64,
    pat: u64,
}
fn privileged() -> bool {
    let selector: u16;
    // SAFETY: unprivileged read-only CPL observation precedes privileged access.
    unsafe {
        asm!("mov {0:x}, cs",out(reg)selector,options(nomem,nostack,preserves_flags));
    }
    selector & 3 == 0
}
fn processor() -> u32 {
    let maximum = __cpuid(0).eax;
    for leaf in [0x1f, 0xb] {
        if maximum >= leaf {
            let value = __cpuid_count(leaf, 0);
            if value.ebx != 0 {
                return value.edx;
            }
        }
    }
    __cpuid(1).ebx >> 24
}
pub(super) fn validate_cpu() -> Result<(), RootError> {
    if !privileged() {
        return Err(RootError::Privilege);
    }
    let features = __cpuid(1).edx;
    if features & ((1 << 5) | (1 << 9) | (1 << 16)) != ((1 << 5) | (1 << 9) | (1 << 16)) {
        return Err(RootError::CpuFeatures);
    }
    let flags: u64;
    // SAFETY: CPL0 CPU; this only observes flags/control ownership.
    unsafe {
        asm!("pushfq","pop {}",out(reg)flags);
    }
    if flags & (1 << 9) != 0 {
        return Err(RootError::InterruptsEnabled);
    }
    if crate::apic::base_msr() & BSP == 0 {
        return Err(RootError::WrongCpu);
    }
    Ok(())
}
impl Context {
    fn observe() -> Result<Self, RootError> {
        if !privileged() {
            return Err(RootError::Privilege);
        }
        let (root, cr0, cr4): (u64, u64, u64);
        // SAFETY: CPL0 was just observed on this non-migrating boot processor.
        unsafe {
            asm!("mov {}, cr3","mov {}, cr0","mov {}, cr4",out(reg)root,out(reg)cr0,out(reg)cr4,options(nomem,nostack,preserves_flags));
        }
        Ok(Self {
            cpu: processor(),
            apic: crate::apic::base_msr(),
            root,
            cr0,
            cr4,
            // SAFETY: architectural MSRs of this checked CPL0 CPU.
            efer: unsafe { msr::EFER.read() },
            // SAFETY: the BSP was checked for PAT before activation;
            // this remains the same non-migrating CPU. Observation only.
            pat: unsafe { msr::PAT.read() },
        })
    }
    fn check(&self) -> Result<(), RootError> {
        if !privileged() || processor() != self.cpu {
            return Err(RootError::WrongCpu);
        }
        // BSP is a per-CPU architectural bit, avoiding a legacy APIC-ID
        // collision on a different processor before any table-page dereference.
        let apic = crate::apic::base_msr();
        if apic & BSP == 0 || apic != self.apic {
            return Err(RootError::WrongCpu);
        }
        let current = Self::observe()?;
        if current.root != self.root {
            return Err(RootError::RootChanged);
        }
        if current.cr0 != self.cr0
            || current.cr4 != self.cr4
            || current.efer != self.efer
            || current.pat != self.pat
        {
            return Err(RootError::ControlsChanged);
        }
        Ok(())
    }
}
/// One real builder after successful native activation. Its fields/constructor
/// are private; root numbers or Handoff records cannot instantiate this owner.
pub(crate) struct RetainedRoot {
    pub(super) tables: FrameCatalog,
    context: Context,
    closed: AtomicBool,
}
impl RetainedRoot {
    pub(crate) fn check_current(&self) -> Result<(), RootError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RootError::Closed);
        }
        match self.context.check() {
            Err(error @ (RootError::RootChanged | RootError::ControlsChanged)) => {
                // Returning to an old CR3/control tuple cannot revive an owner
                // whose uninterrupted context lifetime has already ended.
                self.closed.store(true, Ordering::Release);
                Err(error)
            }
            Ok(()) => self.tables.validate_table_aliases(),
            Err(error) => Err(error),
        }
    }
}
/// The primary CPU-affine activation owner, kept by the real standalone
/// or HostCheck machine. Existing mappings also need their own context/resource
/// pins; carrying this value does not authorize arbitrary MMIO or configuration.
#[must_use = "retain the actual activated table owner through every native consumer"]
pub(crate) struct ActivatedTables {
    pub(super) root: Arc<RetainedRoot>,
    _local: PhantomData<*mut ()>,
}
impl ActivatedTables {
    pub(super) fn retain(tables: Tables) -> Result<Self, RootError> {
        validate_cpu()?;
        let context = Context::observe()?;
        if context.root != tables.root() {
            return Err(RootError::NotActivated);
        }
        tables.validate_table_aliases()?;
        let root = Arc::new(RetainedRoot {
            tables: FrameCatalog::from_builder(tables),
            context,
            closed: AtomicBool::new(false),
        });
        root.check_current()?;
        // CR3 still reaches these pages after the lexical primary owner
        // drops. Preserve the original builder/catalog for the whole boot; this
        // is retention, not a fictitious table-reclamation or quiescence proof.
        core::mem::forget(root.clone());
        Ok(Self {
            root,
            _local: PhantomData,
        })
    }
    pub(crate) fn check_current(&self) -> Result<(), RootError> {
        self.root.check_current()
    }
}
