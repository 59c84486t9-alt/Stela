//! Actual-current-processor authority for native system RAM execution. This
//! does not mount, replace or relax the legacy identity-frame platform.
use crate::machine::engine::publication::WorkerId;
use alloc::rc::Rc;
use core::cell::Cell;
use stela_compiler::TargetCpu;

const CR0_REQUIRED: u64 = 1 | (1 << 1) | (1 << 5) | (1 << 16) | (1 << 31);
const CR0_FORBIDDEN: u64 = (1 << 2) | (1 << 3) | (1 << 29) | (1 << 30);
const CR4_REQUIRED: u64 = (1 << 5) | (1 << 9) | (1 << 10);
// Global/PCID translations and CET need their own retained root/call contract.
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

/// Why actual-current-processor native admission refused.
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
    cpuid7_ecx: u32,
    identity: IdentityProbe,
}

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
        let mut target = TargetCpu::Baseline;
        if d.cpuid1_edx & (1 << 8) != 0 {
            target = target.with_cx8();
        }
        if d.cpuid1_ecx & (1 << 13) != 0 {
            target = target.with_cx16();
        }
        // Intel SDM 325462-089 Vol.3A and AMD APM24593rev3.44 §7.3.2:
        // AVX hardware establishes aligned WB load atomicity, independently
        // of OS AVX state. The actual recipe uses only legacy XMM/SSE2.
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
/// send::<stela_runtime::NativeCpuOwner>();
/// ```
/// ```compile_fail
/// fn share<T: Sync>() {}
/// share::<stela_runtime::NativeCpuOwner>();
/// ```
#[derive(Debug)]
pub struct NativeCpuOwner {
    seal: Rc<DeclarationSeal>,
}

impl NativeCpuOwner {
    /// Enumerate this actual worker after its Host/control installation.
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
/// no frame, RAM, code-address, source, publication or settlement authority.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<stela_runtime::NativeCpuLease>();
/// ```
/// ```compile_fail
/// fn share<T: Sync>() {}
/// share::<stela_runtime::NativeCpuLease>();
/// ```
/// ```compile_fail
/// let lease = stela_runtime::NativeCpuLease {};
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

/// A fresh per-body proof. Default callers retain complete live enumeration;
/// an owned worker may retain declarations, never this body's exact controls.
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

    /// Retain all four dynamic boundaries, including checked finalization.
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
            cpuid1_ecx: basic.ecx & ((1 << 13) | (1 << 28)),
            cpuid1_edx: basic.edx & (CPUID_FLOOR_EDX | (1 << 8)),
            extended_edx: ext.edx & CPUID_LONG_NX,
            cpuid7_ecx: if maximum >= 7 {
                cpuid(7, 0).ecx & (1 << 16)
            } else {
                0
            },
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
mod tests {
    use super::*;
    fn baseline() -> Observation {
        Observation {
            declarations: CpuDeclarations {
                vendor: TargetCpu::INTEL_VENDOR,
                cpuid1_ecx: 0,
                cpuid1_edx: CPUID_FLOOR_EDX,
                extended_edx: CPUID_LONG_NX,
                cpuid7_ecx: 0,
                identity: IdentityProbe::Topology(0x1f),
            },
            controls: NativeControls {
                apic_id: 0x1234,
                cs: 8,
                cr0: CR0_REQUIRED,
                cr4: CR4_REQUIRED,
                efer: EFER_REQUIRED,
                flags: 0,
            },
        }
    }

    #[test]
    fn legacy_xmm_floor_never_invents_extended_features() {
        let mut actual = baseline();
        assert_eq!(actual.target(), Ok(TargetCpu::Baseline));
        actual.declarations.cpuid1_edx |= 1 << 8;
        actual.declarations.cpuid1_ecx |= 1 << 13;
        let expected = TargetCpu::Baseline.with_cx8().with_cx16();
        assert_eq!(actual.target(), Ok(expected));
        actual.controls.cr4 |= 1 << 18; // OSXSAVE does not admit AVX or a wider target.
        actual.declarations.cpuid1_ecx |= !(1 << 28);
        assert_eq!(actual.target(), Ok(expected));
        actual.controls.cr4 |= 1 << 12;
        assert_eq!(actual.target(), Err(Refusal::Controls));
        actual.declarations.cpuid7_ecx |= 1 << 16;
        assert_eq!(actual.target(), Ok(expected));
    }
    #[test]
    fn aligned_atomic_legacy_xmm_capability_is_independent_of_os_avx_state() {
        let mut actual = baseline();
        actual.declarations.cpuid1_ecx |= 1 << 28;
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        assert_eq!(actual.controls.cr4 & (1 << 18), 0);
        assert!(!actual.target().unwrap().supports(TargetCpu::Avx2));
        actual.controls.cr4 |= 1 << 18;
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        let proof = NativeSystemTarget {
            observed: actual,
            lease: None,
            target: actual.target().unwrap(),
        };
        actual.declarations.cpuid1_ecx &= !(1 << 28);
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::TargetChanged)
        );
        actual.declarations.cpuid1_ecx |= 1 << 28;
        actual.declarations.vendor = TargetCpu::AMD_VENDOR;
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        actual.controls.cr4 &= !(1 << 18);
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        actual.declarations.vendor = [0; 3];
        assert_eq!(actual.target(), Ok(TargetCpu::Baseline));
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::ProcessorChanged)
        );
    }

    #[test]
    fn all_effective_native_requirements_are_checked_before_entry() {
        for bit in [0, 1, 5, 16, 31] {
            let mut actual = baseline();
            actual.controls.cr0 &= !(1 << bit);
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        for bit in [2, 3, 29, 30] {
            let mut actual = baseline();
            actual.controls.cr0 |= 1 << bit;
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        for bit in [5, 9, 10] {
            let mut actual = baseline();
            actual.controls.cr4 &= !(1 << bit);
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        for bit in [7, 17, 23] {
            let mut actual = baseline();
            actual.controls.cr4 |= 1 << bit;
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        let mut actual = baseline();
        actual.controls.flags = IF;
        assert_eq!(actual.target(), Err(Refusal::InterruptsEnabled));
    }
    #[test]
    fn physical_migration_control_changes_and_lost_capability_refuse() {
        let mut actual = baseline();
        actual.declarations.cpuid1_ecx |= 1 << 13;
        let proof = NativeSystemTarget {
            observed: actual,
            lease: None,
            target: actual.target().unwrap(),
        };
        assert_eq!(proof.revalidate_observation(actual), Ok(()));
        actual.controls.apic_id = 0x34;
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::ProcessorChanged)
        );
        actual = proof.observed;
        actual.controls.cr4 |= 1 << 18;
        assert_eq!(proof.revalidate_observation(actual), Err(Refusal::Controls));
        actual = proof.observed;
        actual.declarations.cpuid1_ecx &= !(1 << 13);
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::TargetChanged)
        );
        assert_eq!(
            NativeSystemTarget::capture().unwrap_err(),
            Refusal::UnsupportedHost
        );
    }

    // Private observation models exercise the same validators. They are not
    // a public fake-hardware constructor and establish no CPL0 qualification.
    fn modeled_owner(actual: Observation) -> NativeCpuOwner {
        NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, actual).unwrap()
    }

    fn modeled_capture(
        owner: &NativeCpuOwner,
        controls: NativeControls,
    ) -> Result<NativeSystemTarget, Refusal> {
        NativeSystemTarget::capture_with(
            Some((WorkerId(17), owner.lease())),
            || panic!("supplied lease must never fall back"),
            |_| Ok(controls),
        )
    }

    #[test]
    fn declaration_construction_requires_complete_floor_and_actual_local_owner() {
        let actual = baseline();
        for bit in 0..32 {
            if CPUID_FLOOR_EDX & (1 << bit) != 0 {
                let mut changed = actual;
                changed.declarations.cpuid1_edx &= !(1 << bit);
                assert_eq!(
                    NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, changed)
                        .unwrap_err(),
                    Refusal::MissingCpuFeatures
                );
            }
        }
        for bit in [20, 29] {
            let mut changed = actual;
            changed.declarations.extended_edx &= !(1 << bit);
            assert_eq!(
                NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, changed).unwrap_err(),
                Refusal::MissingCpuFeatures
            );
        }
        assert_eq!(
            NativeCpuOwner::admit(WorkerId(17), 0x34, actual).unwrap_err(),
            Refusal::ProcessorChanged
        );
        // Public construction cannot use the modeled observations on a POSIX
        // process, even with a baseline artifact and plausible numeric IDs.
        assert_eq!(
            unsafe { NativeCpuOwner::new(WorkerId(17), actual.controls.apic_id) }.unwrap_err(),
            Refusal::UnsupportedHost
        );
    }

    fn invalid_controls() -> alloc::vec::Vec<(NativeControls, Refusal)> {
        let base = baseline().controls;
        let mut cases = alloc::vec::Vec::new();
        for cs in [3, 0x1b] {
            cases.push((NativeControls { cs, ..base }, Refusal::Privilege));
        }
        cases.push((
            NativeControls { flags: IF, ..base },
            Refusal::InterruptsEnabled,
        ));
        cases.push((
            NativeControls {
                apic_id: 0x34,
                ..base
            },
            Refusal::ProcessorChanged,
        ));
        for bit in [0, 1, 5, 16, 31] {
            cases.push((
                NativeControls {
                    cr0: base.cr0 & !(1 << bit),
                    ..base
                },
                Refusal::Controls,
            ));
        }
        for bit in [2, 3, 29, 30] {
            cases.push((
                NativeControls {
                    cr0: base.cr0 | (1 << bit),
                    ..base
                },
                Refusal::Controls,
            ));
        }
        for bit in [5, 9, 10] {
            cases.push((
                NativeControls {
                    cr4: base.cr4 & !(1 << bit),
                    ..base
                },
                Refusal::Controls,
            ));
        }
        for bit in [7, 17, 23] {
            cases.push((
                NativeControls {
                    cr4: base.cr4 | (1 << bit),
                    ..base
                },
                Refusal::Controls,
            ));
        }
        for bit in [10, 11] {
            cases.push((
                NativeControls {
                    efer: base.efer & !(1 << bit),
                    ..base
                },
                Refusal::Controls,
            ));
        }
        // LA57 without an immutable hardware declaration refuses at capture.
        cases.push((
            NativeControls {
                cr4: base.cr4 | (1 << 12),
                ..base
            },
            Refusal::Controls,
        ));
        cases
    }

    #[test]
    fn leased_capture_and_all_three_rechecks_validate_actual_live_controls() {
        let actual = baseline();
        for (changed, expected) in invalid_controls() {
            let candidate = Observation {
                controls: changed,
                ..actual
            };
            assert!(
                NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, candidate).is_err()
            );
            for boundary in 0..4 {
                let owner = modeled_owner(actual);
                let initial = if boundary == 0 {
                    changed
                } else {
                    actual.controls
                };
                let proof = modeled_capture(&owner, initial);
                if boundary == 0 {
                    assert_eq!(proof.unwrap_err(), expected);
                    continue;
                }
                let proof = proof.unwrap();
                for recheck in 1..=boundary {
                    let live = if recheck == boundary {
                        changed
                    } else {
                        actual.controls
                    };
                    let result = proof.revalidate_with(
                        || panic!("leased recheck cannot enumerate declarations"),
                        |_| Ok(live),
                    );
                    assert_eq!(
                        result,
                        if recheck == boundary {
                            Err(expected)
                        } else {
                            Ok(())
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn body_controls_are_exact_even_when_a_new_capture_would_admit_them() {
        let actual = baseline();
        let owner = modeled_owner(actual);
        let proof = modeled_capture(&owner, actual.controls).unwrap();
        for changed in [
            NativeControls {
                cs: 16,
                ..actual.controls
            },
            NativeControls {
                cr0: actual.controls.cr0 | (1 << 18),
                ..actual.controls
            },
            NativeControls {
                cr4: actual.controls.cr4 | (1 << 18),
                ..actual.controls
            },
            NativeControls {
                efer: actual.controls.efer | 1,
                ..actual.controls
            },
        ] {
            assert!(modeled_capture(&owner, changed).is_ok());
            for _boundary in 1..4 {
                assert_eq!(
                    proof.revalidate_with(|| panic!("no fallback"), |_| Ok(changed)),
                    Err(Refusal::Controls)
                );
            }
        }
    }

    #[test]
    fn revoked_wrong_worker_and_replaced_owners_never_fall_back() {
        let actual = baseline();
        let mut owner = modeled_owner(actual);
        let lease = owner.lease();
        assert_eq!(
            NativeSystemTarget::capture_with(
                Some((WorkerId(18), lease.clone())),
                || panic!("wrong worker must not enumerate"),
                |_| panic!("wrong worker must not probe"),
            )
            .unwrap_err(),
            Refusal::WorkerChanged
        );
        let proof = modeled_capture(&owner, actual.controls).unwrap();
        owner.revoke();
        assert_eq!(
            modeled_capture(&owner, actual.controls).unwrap_err(),
            Refusal::OwnerRevoked
        );
        assert_eq!(
            proof.revalidate_with(|| panic!("no fallback"), |_| panic!("revoked before probe")),
            Err(Refusal::OwnerRevoked)
        );
        let replacement = modeled_owner(actual);
        assert!(!Rc::ptr_eq(&lease.seal, &replacement.seal));
        assert!(modeled_capture(&replacement, actual.controls).is_ok());
        assert_eq!(lease.check(WorkerId(17)), Err(Refusal::OwnerRevoked));
        let replacement_lease = replacement.lease();
        drop(replacement);
        assert_eq!(
            replacement_lease.check(WorkerId(17)),
            Err(Refusal::OwnerRevoked)
        );
    }

    #[test]
    fn revocation_during_observation_or_callback_finalization_refuses() {
        let actual = baseline();
        let mut owner = modeled_owner(actual);
        assert_eq!(
            NativeSystemTarget::capture_with(
                Some((WorkerId(17), owner.lease())),
                || panic!("no fallback"),
                |_| {
                    owner.revoke();
                    Ok(actual.controls)
                },
            )
            .unwrap_err(),
            Refusal::OwnerRevoked
        );
        for boundary in 1..4 {
            let mut owner = modeled_owner(actual);
            let proof = modeled_capture(&owner, actual.controls).unwrap();
            for _ in 1..boundary {
                proof
                    .revalidate_with(|| panic!("no fallback"), |_| Ok(actual.controls))
                    .unwrap();
            }
            // At boundary 3 this models retirement during callback/finalization;
            // the post-check rejects before the caller may settle success.
            owner.revoke();
            assert_eq!(
                proof.revalidate_with(|| panic!("no fallback"), |_| panic!("revoked before probe")),
                Err(Refusal::OwnerRevoked)
            );
        }
    }

    #[test]
    fn default_selection_keeps_complete_capture_and_revalidation() {
        let actual = baseline();
        let full = Cell::new(0);
        let proof = NativeSystemTarget::capture_with(
            None,
            || {
                full.set(full.get() + 1);
                Ok(actual)
            },
            |_| panic!("no owner means full observation"),
        )
        .unwrap();
        for _ in 1..4 {
            proof
                .revalidate_with(
                    || {
                        full.set(full.get() + 1);
                        Ok(actual)
                    },
                    |_| panic!("no owner means full revalidation"),
                )
                .unwrap();
        }
        assert_eq!(full.get(), 4);
        assert!(proof.lease.is_none());
        let mut changed = actual;
        changed.declarations.cpuid1_edx = 0;
        assert_eq!(
            proof.revalidate_with(|| Ok(changed), |_| panic!("no owner")),
            Err(Refusal::MissingCpuFeatures)
        );
    }

    #[test]
    fn retirement_reenumerates_mixed_worker_capabilities_without_promoting_avx() {
        let mut rich = baseline();
        rich.declarations.cpuid1_ecx = (1 << 13) | (1 << 28);
        rich.declarations.cpuid1_edx |= 1 << 8;
        rich.controls.cr4 |= 1 << 18;
        let mut owner = modeled_owner(rich);
        let proof = modeled_capture(&owner, rich.controls).unwrap();
        assert!(proof.target().supports(TargetCpu::Cx16));
        assert!(proof.target().supports(TargetCpu::AtomicLoad16));
        assert!(!proof.target().supports(TargetCpu::Avx2));
        let other = modeled_owner(baseline());
        assert_eq!(
            modeled_capture(&other, baseline().controls)
                .unwrap()
                .target(),
            TargetCpu::Baseline
        );
        owner.revoke();
        let replacement = modeled_owner(baseline());
        assert_eq!(
            proof.revalidate_with(|| panic!("no fallback"), |_| Ok(rich.controls)),
            Err(Refusal::OwnerRevoked)
        );
        assert_eq!(
            modeled_capture(&replacement, baseline().controls)
                .unwrap()
                .target(),
            TargetCpu::Baseline
        );
        rich.declarations.vendor = [0; 3];
        let unknown = modeled_owner(rich);
        assert!(
            !modeled_capture(&unknown, rich.controls)
                .unwrap()
                .target()
                .supports(TargetCpu::AtomicLoad16)
        );
    }

    fn declarations(
        vendor: [u32; 3],
        maximum: u32,
        extended: u32,
        topology: bool,
        leaf1f: Cpuid,
        leafb: Cpuid,
    ) -> (CpuDeclarations, u32) {
        enumerate(|leaf, _| match leaf {
            0 => Cpuid {
                eax: maximum,
                ebx: vendor[0],
                edx: vendor[1],
                ecx: vendor[2],
            },
            1 => Cpuid {
                ebx: 0x34 << 24,
                edx: CPUID_FLOOR_EDX,
                ..Cpuid::default()
            },
            0x8000_0000 => Cpuid {
                eax: extended,
                ..Cpuid::default()
            },
            0x8000_0001 => Cpuid {
                ecx: if topology { 1 << 22 } else { 0 },
                edx: CPUID_LONG_NX,
                ..Cpuid::default()
            },
            0x1f => leaf1f,
            0xb => leafb,
            0x8000_001e => Cpuid {
                eax: 0x1234,
                ..Cpuid::default()
            },
            7 => Cpuid::default(),
            _ => panic!("unexpected leaf"),
        })
        .unwrap()
    }

    #[test]
    fn identity_probe_selection_obeys_maxima_amd_gate_and_full_width_topology() {
        let valid = Cpuid {
            ebx: 2,
            ecx: 1 << 8,
            edx: 0x1234,
            ..Cpuid::default()
        };
        let invalid = Cpuid::default();
        for (maximum, first, second, expected) in [
            (1, valid, valid, IdentityProbe::Legacy),
            (0xb, valid, valid, IdentityProbe::Topology(0xb)),
            (0x1f, valid, valid, IdentityProbe::Topology(0x1f)),
            (0x1f, invalid, valid, IdentityProbe::Topology(0xb)),
            (0x1f, invalid, invalid, IdentityProbe::Legacy),
        ] {
            let (d, id) = declarations(
                TargetCpu::INTEL_VENDOR,
                maximum,
                0x8000_0001,
                false,
                first,
                second,
            );
            assert_eq!(d.identity, expected);
            assert_eq!(
                id,
                if expected == IdentityProbe::Legacy {
                    0x34
                } else {
                    0x1234
                }
            );
        }
        for vendor in [TargetCpu::AMD_VENDOR, TargetCpu::INTEL_VENDOR, [0; 3]] {
            for maximum in [0x8000_0001, 0x8000_001d, 0x8000_001e] {
                for topology in [false, true] {
                    let (d, id) = declarations(vendor, 1, maximum, topology, invalid, invalid);
                    let amd = vendor == TargetCpu::AMD_VENDOR && maximum >= 0x8000_001e && topology;
                    assert_eq!(
                        d.identity,
                        if amd {
                            IdentityProbe::Amd
                        } else {
                            IdentityProbe::Legacy
                        }
                    );
                    assert_eq!(id, if amd { 0x1234 } else { 0x34 });
                }
            }
        }
        // A selected topology route never silently falls back or truncates
        // after a now-invalid record. Count uses the architectural low 16 bits.
        for invalid in [
            Cpuid {
                ebx: 1 << 16,
                ..valid
            },
            Cpuid { ecx: 0, ..valid },
        ] {
            assert_eq!(
                IdentityProbe::Topology(0x1f).read(|leaf, _| {
                    assert_eq!(leaf, 0x1f);
                    invalid
                }),
                Err(Refusal::ProcessorChanged)
            );
        }
        assert_eq!(
            IdentityProbe::Amd.read(|leaf, _| {
                assert_eq!(leaf, 0x8000_001e);
                valid
            }),
            Ok(valid.eax)
        );
        assert_eq!(
            IdentityProbe::Legacy.read(|leaf, _| {
                assert_eq!(leaf, 1);
                Cpuid {
                    ebx: 0xfe << 24,
                    ..valid
                }
            }),
            Ok(0xfe)
        );
        for (maximum, extended) in [(0, 0x8000_0001), (1, 0x8000_0000)] {
            assert_eq!(
                enumerate(|leaf, _| Cpuid {
                    eax: if leaf == 0 { maximum } else { extended },
                    ..Cpuid::default()
                })
                .unwrap_err(),
                Refusal::MissingCpuFeatures
            );
        }
    }

    #[test]
    fn one_owner_enumeration_then_one_live_identity_probe_per_boundary() {
        let actual = baseline();
        let enumerations = Cell::new(0);
        let (d, id) = enumerate(|leaf, _| {
            enumerations.set(enumerations.get() + 1);
            match leaf {
                0 => Cpuid {
                    eax: 0x1f,
                    ebx: TargetCpu::INTEL_VENDOR[0],
                    edx: TargetCpu::INTEL_VENDOR[1],
                    ecx: TargetCpu::INTEL_VENDOR[2],
                },
                1 => Cpuid {
                    edx: CPUID_FLOOR_EDX,
                    ..Cpuid::default()
                },
                0x8000_0000 => Cpuid {
                    eax: 0x8000_0001,
                    ..Cpuid::default()
                },
                0x8000_0001 => Cpuid {
                    edx: CPUID_LONG_NX,
                    ..Cpuid::default()
                },
                0x1f => Cpuid {
                    ebx: 2,
                    ecx: 1 << 8,
                    edx: actual.controls.apic_id,
                    ..Cpuid::default()
                },
                7 => Cpuid::default(),
                _ => panic!("unexpected leaf"),
            }
        })
        .unwrap();
        assert_eq!(enumerations.get(), 6);
        let owner = modeled_owner(Observation {
            declarations: d,
            controls: NativeControls {
                apic_id: id,
                ..actual.controls
            },
        });
        let probes = Cell::new(0);
        let live = |probe: IdentityProbe| {
            let apic_id = probe.read(|leaf, _| {
                assert_eq!(leaf, 0x1f);
                probes.set(probes.get() + 1);
                Cpuid {
                    ebx: 2,
                    ecx: 1 << 8,
                    edx: id,
                    ..Cpuid::default()
                }
            })?;
            Ok(NativeControls {
                apic_id,
                ..actual.controls
            })
        };
        let proof = NativeSystemTarget::capture_with(
            Some((WorkerId(17), owner.lease())),
            || panic!("no reenumeration"),
            live,
        )
        .unwrap();
        for _ in 1..4 {
            proof
                .revalidate_with(|| panic!("no reenumeration"), live)
                .unwrap();
        }
        assert_eq!(probes.get(), 4);
        assert_eq!(enumerations.get(), 6);
    }
}
