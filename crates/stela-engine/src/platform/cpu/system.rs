//! Current-processor permission for native system RAM execution. This
//! does not mount, replace or relax the legacy identity-frame platform.
use crate::machine::engine::publication::WorkerId;
use alloc::rc::Rc;
use core::cell::Cell;
use stela_compiler::TargetCpu;

const CR0_REQUIRED: u64 = 1 | (1 << 1) | (1 << 5) | (1 << 16) | (1 << 31);
const CR0_FORBIDDEN: u64 = (1 << 2) | (1 << 3) | (1 << 29) | (1 << 30);
const CR4_REQUIRED: u64 = (1 << 5) | (1 << 9) | (1 << 10);
// Global/PCID translations and CET need their own root/call contract.
const CR4_FORBIDDEN: u64 = (1 << 7) | (1 << 17) | (1 << 23);
const EFER_REQUIRED: u64 = (1 << 10) | (1 << 11);
const IF: u64 = 1 << 9;
const CPUID_FLOOR_EDX: u32 = (1 << 0)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 9)
    | (1 << 16)
    | (1 << 24)
    | (1 << 25)
    | (1 << 26);
const CPUID_LONG_NX: u32 = (1 << 20) | (1 << 29);

/// Why current-processor native admission refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCpuError {
    UnsupportedHost,
    Privilege,
    InterruptsEnabled,
    MissingCpuFeatures,
    Controls,
    ProcessorChanged,
    TargetChanged,
    OwnerRevoked,
    WorkerChanged,
}
use NativeCpuError as Refusal;

#[cfg_attr(
    not(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))),
    allow(
        dead_code,
        reason = "identity probes are selected on freestanding hardware"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityProbe {
    Legacy,
    Topology(u32),
    Amd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuDeclarations {
    vendor: [u32; 3],
    // Only the consumed immutable hardware bits; OSXSAVE is live CR4 state.
    cpuid1_ecx: u32,
    cpuid1_edx: u32,
    extended_edx: u32,
    cpuid7_ebx: u32,
    cpuid7_ecx: u32,
    identity: IdentityProbe,
}

/// CPUID.1:ECX bits, and CPUID.7.0:EBX's SHA, the instruction sets blocks use.
const CPUID_PCLMULQDQ: u32 = 1 << 1;
const CPUID_SSSE3: u32 = 1 << 9;
const CPUID_CX16: u32 = 1 << 13;
const CPUID_SSE41: u32 = 1 << 19;
const CPUID_SSE42: u32 = 1 << 20;
const CPUID_POPCNT: u32 = 1 << 23;
const CPUID_AES: u32 = 1 << 25;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))
))]
const CPUID1_ECX_READ: u32 = CPUID_PCLMULQDQ
    | CPUID_SSSE3
    | CPUID_CX16
    | CPUID_SSE41
    | CPUID_SSE42
    | CPUID_POPCNT
    | CPUID_AES
    | (1 << 28);
const CPUID_SHA: u32 = 1 << 29;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeControls {
    apic_id: u32,
    cs: u16,
    cr0: u64,
    cr4: u64,
    efer: u64,
    flags: u64,
}

fn privilege(cs: u16, flags: u64) -> Result<(), Refusal> {
    if cs & 3 != 0 {
        return Err(Refusal::Privilege);
    }
    if flags & IF != 0 {
        return Err(Refusal::InterruptsEnabled);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    declarations: CpuDeclarations,
    controls: NativeControls,
}

impl Observation {
    fn target(self) -> Result<TargetCpu, Refusal> {
        let c = self.controls;
        let d = self.declarations;
        privilege(c.cs, c.flags)?;
        if d.cpuid1_edx & CPUID_FLOOR_EDX != CPUID_FLOOR_EDX
            || d.extended_edx & CPUID_LONG_NX != CPUID_LONG_NX
        {
            return Err(Refusal::MissingCpuFeatures);
        }
        if c.cr0 & CR0_REQUIRED != CR0_REQUIRED
            || c.cr0 & CR0_FORBIDDEN != 0
            || c.cr4 & CR4_REQUIRED != CR4_REQUIRED
            || c.cr4 & CR4_FORBIDDEN != 0
            || c.efer & EFER_REQUIRED != EFER_REQUIRED
            || (c.cr4 & (1 << 12) != 0 && d.cpuid7_ecx & (1 << 16) == 0)
        {
            return Err(Refusal::Controls);
        }
        // Legacy XMM instructions, which OSFXSR (CR4_REQUIRED) enables: the
        // tiers nest, and blocks compile for what this core has.
        let mut target = match (
            d.cpuid1_ecx & CPUID_SSSE3 != 0,
            d.cpuid1_ecx & CPUID_SSE41 != 0,
            d.cpuid1_ecx & CPUID_SSE42 != 0,
        ) {
            (true, true, true) => TargetCpu::Sse42,
            (true, true, false) => TargetCpu::Sse41,
            (true, false, _) => TargetCpu::Ssse3,
            _ => TargetCpu::Baseline,
        };
        if d.cpuid1_ecx & CPUID_PCLMULQDQ != 0 {
            target = target.with_pclmulqdq();
        }
        if d.cpuid1_ecx & CPUID_POPCNT != 0 {
            target = target.with_popcnt();
        }
        if d.cpuid1_ecx & CPUID_AES != 0 {
            target = target.with_aes();
        }
        if d.cpuid7_ebx & CPUID_SHA != 0 {
            target = target.with_sha();
        }
        if d.cpuid1_edx & (1 << 8) != 0 {
            target = target.with_cx8();
        }
        if d.cpuid1_ecx & CPUID_CX16 != 0 {
            target = target.with_cx16();
        }
        // Intel SDM 325462-089 Vol.3A and AMD APM24593rev3.44 §7.3.2:
        // AVX hardware establishes aligned WB load atomicity, independently
        // of OS AVX state. The recipe uses only legacy XMM/SSE2.
        if TargetCpu::atomic_load16_guaranteed(d.vendor, d.cpuid1_ecx) {
            target = target.with_atomic_load16();
        }
        // No VEX/AVX, FMA, cache-line atomicity or DOIT recipe is admitted.
        Ok(target)
    }
}

#[derive(Debug)]
struct DeclarationSeal {
    declarations: CpuDeclarations,
    worker: WorkerId,
    apic_id: u32,
    live: Cell<bool>,
}

/// Destination-local owner of stable CPU declarations. Neither Send nor Sync.
/// Dropping or revoking it invalidates every outstanding handle and body proof.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<stela_engine::NativeCpuOwner>();
/// ```
/// ```compile_fail
/// fn share<T: Sync>() {}
/// share::<stela_engine::NativeCpuOwner>();
/// ```
#[derive(Debug)]
pub struct NativeCpuOwner {
    seal: Rc<DeclarationSeal>,
}

impl NativeCpuOwner {
    /// Enumerate this worker after its Host/control installation.
    ///
    /// # Safety
    /// The caller exclusively owns this physical processor, bound to `worker`,
    /// without migration through retirement. Trusted firmware and any VMM must
    /// preserve its relevant ISA/vendor/identity declarations for this lifetime.
    /// Stop all calls and revoke before host reset, resume, microcode update or
    /// feature/identity reconfiguration, including changes shared by SMT peers.
    /// No VM/vendor/ID/boolean can establish this environment promise. This
    /// constructor checks hardware, but cannot prove external stability.
    pub unsafe fn new(worker: WorkerId, expected_apic: u32) -> Result<Self, NativeCpuError> {
        Self::admit(worker, expected_apic, observe()?)
    }

    fn admit(worker: WorkerId, expected_apic: u32, observed: Observation) -> Result<Self, Refusal> {
        observed.target()?;
        if observed.controls.apic_id != expected_apic {
            return Err(Refusal::ProcessorChanged);
        }
        Ok(Self {
            seal: Rc::new(DeclarationSeal {
                declarations: observed.declarations,
                worker,
                apic_id: expected_apic,
                live: Cell::new(true),
            }),
        })
    }

    pub fn lease(&self) -> NativeCpuLease {
        NativeCpuLease {
            seal: Rc::clone(&self.seal),
        }
    }

    /// Irreversible. A replacement owner always has a fresh allocation identity.
    pub fn revoke(&mut self) {
        self.seal.live.set(false);
    }
}

impl Drop for NativeCpuOwner {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Opaque non-Send/non-Sync handle lent only by a live physical owner. It grants
/// no frame, RAM, code-address, source, publication or settlement permission.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<stela_engine::NativeCpuLease>();
/// ```
/// ```compile_fail
/// fn share<T: Sync>() {}
/// share::<stela_engine::NativeCpuLease>();
/// ```
/// ```compile_fail
/// let lease = stela_engine::NativeCpuLease {};
/// ```
#[derive(Debug, Clone)]
pub struct NativeCpuLease {
    seal: Rc<DeclarationSeal>,
}

impl NativeCpuLease {
    fn check(&self, worker: WorkerId) -> Result<(), Refusal> {
        if !self.seal.live.get() {
            return Err(Refusal::OwnerRevoked);
        }
        if self.seal.worker != worker {
            return Err(Refusal::WorkerChanged);
        }
        Ok(())
    }

    fn observe_with(
        &self,
        worker: WorkerId,
        live: impl FnOnce(IdentityProbe) -> Result<NativeControls, Refusal>,
    ) -> Result<Observation, Refusal> {
        self.check(worker)?;
        let controls = live(self.seal.declarations.identity)?;
        self.check(worker)?;
        if controls.apic_id != self.seal.apic_id {
            return Err(Refusal::ProcessorChanged);
        }
        let observed = Observation {
            declarations: self.seal.declarations,
            controls,
        };
        observed.target()?;
        Ok(observed)
    }
}

/// A fresh per-body proof. Default callers keep complete live enumeration;
/// an owned worker may keep declarations, never this body's exact controls.
#[derive(Debug)]
pub(crate) struct NativeSystemTarget {
    observed: Observation,
    target: TargetCpu,
    lease: Option<NativeCpuLease>,
}

impl NativeSystemTarget {
    pub(crate) fn capture() -> Result<Self, Refusal> {
        Self::capture_with(None, observe, observe_controls)
    }

    pub(crate) fn capture_for(
        worker: WorkerId,
        lease: Option<NativeCpuLease>,
    ) -> Result<Self, Refusal> {
        Self::capture_with(
            lease.map(|lease| (worker, lease)),
            observe,
            observe_controls,
        )
    }

    fn capture_with(
        owned: Option<(WorkerId, NativeCpuLease)>,
        full: impl FnOnce() -> Result<Observation, Refusal>,
        live: impl FnOnce(IdentityProbe) -> Result<NativeControls, Refusal>,
    ) -> Result<Self, Refusal> {
        let (observed, lease) = match owned {
            Some((worker, lease)) => (lease.observe_with(worker, live)?, Some(lease)),
            None => (full()?, None),
        };
        let target = observed.target()?;
        Ok(Self {
            observed,
            target,
            lease,
        })
    }

    pub(crate) fn target(&self) -> TargetCpu {
        self.target
    }

    pub(crate) fn physical_processor(&self) -> u32 {
        self.observed.controls.apic_id
    }

    /// Keep all four dynamic boundaries, including checked finalization.
    pub(crate) fn revalidate(&self) -> Result<(), Refusal> {
        self.revalidate_with(observe, observe_controls)
    }

    fn revalidate_with(
        &self,
        full: impl FnOnce() -> Result<Observation, Refusal>,
        live: impl FnOnce(IdentityProbe) -> Result<NativeControls, Refusal>,
    ) -> Result<(), Refusal> {
        let current = match &self.lease {
            Some(lease) => lease.observe_with(lease.seal.worker, live)?,
            None => full()?,
        };
        self.revalidate_observation(current)
    }

    fn revalidate_observation(&self, current: Observation) -> Result<(), Refusal> {
        let target = current.target()?;
        if current.controls.apic_id != self.observed.controls.apic_id
            || current.declarations.vendor != self.observed.declarations.vendor
        {
            return Err(Refusal::ProcessorChanged);
        }
        if !target.supports(self.target) {
            return Err(Refusal::TargetChanged);
        }
        if current.controls.cr0 != self.observed.controls.cr0
            || current.controls.cr4 != self.observed.controls.cr4
            || current.controls.efer != self.observed.controls.efer
            || current.controls.cs != self.observed.controls.cs
        {
            return Err(Refusal::Controls);
        }
        Ok(())
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))
))]
#[derive(Debug, Default, Clone, Copy)]
struct Cpuid {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))
))]
impl IdentityProbe {
    fn read(self, mut cpuid: impl FnMut(u32, u32) -> Cpuid) -> Result<u32, Refusal> {
        match self {
            Self::Legacy => Ok(cpuid(1, 0).ebx >> 24),
            Self::Topology(leaf) => {
                let record = cpuid(leaf, 0);
                if record.ebx & 0xffff == 0 || record.ecx >> 8 & 0xff == 0 {
                    return Err(Refusal::ProcessorChanged);
                }
                Ok(record.edx)
            }
            Self::Amd => Ok(cpuid(0x8000_001e, 0).eax),
        }
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))
))]
fn enumerate(mut cpuid: impl FnMut(u32, u32) -> Cpuid) -> Result<(CpuDeclarations, u32), Refusal> {
    let identity = cpuid(0, 0);
    let maximum = identity.eax;
    let extended = cpuid(0x8000_0000, 0).eax;
    if maximum < 1 || extended < 0x8000_0001 {
        return Err(Refusal::MissingCpuFeatures);
    }
    let basic = cpuid(1, 0);
    let ext = cpuid(0x8000_0001, 0);
    let leaf7 = if maximum >= 7 {
        cpuid(7, 0)
    } else {
        Cpuid::default()
    };
    if basic.edx & CPUID_FLOOR_EDX != CPUID_FLOOR_EDX || ext.edx & CPUID_LONG_NX != CPUID_LONG_NX {
        return Err(Refusal::MissingCpuFeatures);
    }
    let vendor = [identity.ebx, identity.edx, identity.ecx];
    let mut probe = IdentityProbe::Legacy;
    let mut apic_id = basic.ebx >> 24;
    for leaf in [0x1f, 0xb] {
        if maximum >= leaf
            && let Ok(id) = IdentityProbe::Topology(leaf).read(&mut cpuid)
        {
            probe = IdentityProbe::Topology(leaf);
            apic_id = id;
            break;
        }
    }
    if probe == IdentityProbe::Legacy
        && vendor == TargetCpu::AMD_VENDOR
        && extended >= 0x8000_001e
        && ext.ecx & (1 << 22) != 0
    {
        probe = IdentityProbe::Amd;
        apic_id = probe.read(&mut cpuid)?;
    }
    Ok((
        CpuDeclarations {
            vendor,
            cpuid1_ecx: basic.ecx & CPUID1_ECX_READ,
            cpuid1_edx: basic.edx & (CPUID_FLOOR_EDX | (1 << 8)),
            extended_edx: ext.edx & CPUID_LONG_NX,
            cpuid7_ebx: leaf7.ebx & CPUID_SHA,
            cpuid7_ecx: leaf7.ecx & (1 << 16),
            identity: probe,
        },
        apic_id,
    ))
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
fn cpuid(leaf: u32, subleaf: u32) -> Cpuid {
    let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    Cpuid {
        eax: r.eax,
        ebx: r.ebx,
        ecx: r.ecx,
        edx: r.edx,
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
fn preamble() -> Result<(u16, u64), Refusal> {
    use core::arch::asm;
    let cs: u16;
    let flags: u64;
    // SAFETY: unprivileged observations; check before any privileged access.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    privilege(cs, flags)?;
    Ok((cs, flags))
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
fn controls(cs: u16, flags: u64, apic_id: u32) -> NativeControls {
    use core::arch::asm;
    let (cr0, cr4): (u64, u64);
    let (low, high): (u32, u32);
    // SAFETY: live CPL0/IF preflight; these registers exist in long mode.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") high,
            options(nostack, preserves_flags));
    }
    NativeControls {
        apic_id,
        cs,
        cr0,
        cr4,
        flags,
        efer: u64::from(low) | u64::from(high) << 32,
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
fn observe() -> Result<Observation, Refusal> {
    let (cs, flags) = preamble()?;
    let (declarations, apic_id) = enumerate(cpuid)?;
    Ok(Observation {
        declarations,
        controls: controls(cs, flags, apic_id),
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
fn observe_controls(probe: IdentityProbe) -> Result<NativeControls, Refusal> {
    let (cs, flags) = preamble()?;
    let apic_id = probe.read(cpuid)?;
    Ok(controls(cs, flags, apic_id))
}

#[cfg(not(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))))]
fn observe() -> Result<Observation, Refusal> {
    Err(Refusal::UnsupportedHost)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))))]
fn observe_controls(_: IdentityProbe) -> Result<NativeControls, Refusal> {
    Err(Refusal::UnsupportedHost)
}

#[cfg(test)]
mod tests;
