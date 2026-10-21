//! Actual-current-processor authority for native system RAM execution. This
//! does not mount, replace or relax the legacy identity-frame platform.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    #[cfg(feature = "std")]
    UnsupportedHost,
    #[cfg(not(feature = "std"))]
    Privilege,
    InterruptsEnabled,
    MissingCpuFeatures,
    Controls,
    ProcessorChanged,
    TargetChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    apic_id: u32,
    vendor: [u32; 3],
    cr0: u64,
    cr4: u64,
    efer: u64,
    flags: u64,
    cpuid1_ecx: u32,
    cpuid1_edx: u32,
    extended_edx: u32,
    cpuid7_ecx: u32,
}

impl Observation {
    fn target(self) -> Result<TargetCpu, Refusal> {
        if self.flags & IF != 0 {
            return Err(Refusal::InterruptsEnabled);
        }
        if self.cpuid1_edx & CPUID_FLOOR_EDX != CPUID_FLOOR_EDX
            || self.extended_edx & CPUID_LONG_NX != CPUID_LONG_NX
        {
            return Err(Refusal::MissingCpuFeatures);
        }
        if self.cr0 & CR0_REQUIRED != CR0_REQUIRED
            || self.cr0 & CR0_FORBIDDEN != 0
            || self.cr4 & CR4_REQUIRED != CR4_REQUIRED
            || self.cr4 & CR4_FORBIDDEN != 0
            || self.efer & EFER_REQUIRED != EFER_REQUIRED
            || (self.cr4 & (1 << 12) != 0 && self.cpuid7_ecx & (1 << 16) == 0)
        {
            return Err(Refusal::Controls);
        }
        let mut target = TargetCpu::Baseline;
        if self.cpuid1_edx & (1 << 8) != 0 {
            target = target.with_cx8();
        }
        if self.cpuid1_ecx & (1 << 13) != 0 {
            target = target.with_cx16();
        }
        // Intel SDM 325462-089 Vol.3A Guaranteed Atomic Operations and AMD
        // APM24593rev3.44 §7.3.2 guarantee aligned cacheable16-byte accesses
        // with CPUID AVX hardware. Legacy MOVDQA requires only the actual
        // XMM controls checked above; VEX/AVX OS state is not inferred.
        if TargetCpu::atomic_load16_guaranteed(self.vendor, self.cpuid1_ecx) {
            target = target.with_atomic_load16();
        }
        // Legacy XMM/SSE2 only: no OSXSAVE/XGETBV, VEX/AVX, FMA,
        // cache-line atomicity or DOIT instruction recipe is admitted.
        Ok(target)
    }
}

/// Private construction requires live hardware observations. A proof cannot
/// be made from a requested target, a boolean or another processor's CPUID.
#[derive(Debug)]
pub(crate) struct NativeSystemTarget {
    observed: Observation,
    target: TargetCpu,
}

impl NativeSystemTarget {
    pub(crate) fn capture() -> Result<Self, Refusal> {
        let observed = observe()?;
        let target = observed.target()?;
        Ok(Self { observed, target })
    }

    pub(crate) fn target(&self) -> TargetCpu {
        self.target
    }

    pub(crate) fn physical_processor(&self) -> u32 {
        self.observed.apic_id
    }

    /// Recheck on the actual owner at native entry. LA57 and OSXSAVE state
    /// may not change behind the retained memory/root contract. This proves
    /// only native requirements, not guest feature or MMU/control authority.
    pub(crate) fn revalidate(&self) -> Result<(), Refusal> {
        let current = observe()?;
        self.revalidate_observation(current)
    }

    fn revalidate_observation(&self, current: Observation) -> Result<(), Refusal> {
        let target = current.target()?;
        if current.apic_id != self.observed.apic_id || current.vendor != self.observed.vendor {
            return Err(Refusal::ProcessorChanged);
        }
        if !target.supports(self.target) {
            return Err(Refusal::TargetChanged);
        }
        if current.cr0 != self.observed.cr0
            || current.cr4 != self.observed.cr4
            || current.efer != self.observed.efer
        {
            return Err(Refusal::Controls);
        }
        Ok(())
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
fn observe() -> Result<Observation, Refusal> {
    use core::arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count},
    };
    let selector: u16;
    let flags: u64;
    // SAFETY: these two observations are unprivileged and leave state intact.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) selector, options(nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    if selector & 3 != 0 {
        return Err(Refusal::Privilege);
    }
    if flags & IF != 0 {
        return Err(Refusal::InterruptsEnabled);
    }
    let identity = __cpuid(0);
    let maximum = identity.eax;
    let extended = __cpuid(0x8000_0000).eax;
    if maximum < 1 || extended < 0x8000_0001 {
        return Err(Refusal::MissingCpuFeatures);
    }
    let basic = __cpuid(1);
    if basic.edx & CPUID_FLOOR_EDX != CPUID_FLOOR_EDX {
        return Err(Refusal::MissingCpuFeatures);
    }
    let mut apic_id = basic.ebx >> 24;
    let mut extended_identity = false;
    for leaf in [0x1f, 0xb] {
        if maximum < leaf {
            continue;
        }
        let record = __cpuid_count(leaf, 0);
        if record.ebx != 0 && record.ecx >> 8 & 0xff != 0 {
            apic_id = record.edx;
            extended_identity = true;
            break;
        }
    }
    // AMD's extended ID is used only with its enumerated topology extension;
    // it must not truncate the identity to the legacy eight-bit field.
    let ext = __cpuid(0x8000_0001);
    if !extended_identity && extended >= 0x8000_001e && ext.ecx & (1 << 22) != 0 {
        apic_id = __cpuid(0x8000_001e).eax;
    }
    let (cr0, cr4): (u64, u64);
    let (low, high): (u32, u32);
    // SAFETY: CPL0 was observed above; CR0/CR4/EFER exist in long mode.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") high,
            options(nostack, preserves_flags));
    }
    Ok(Observation {
        apic_id,
        vendor: [identity.ebx, identity.edx, identity.ecx],
        cr0,
        cr4,
        flags,
        efer: u64::from(low) | u64::from(high) << 32,
        cpuid1_ecx: basic.ecx,
        cpuid1_edx: basic.edx,
        extended_edx: ext.edx,
        cpuid7_ecx: if maximum >= 7 {
            __cpuid_count(7, 0).ecx
        } else {
            0
        },
    })
}

#[cfg(not(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std"))))]
fn observe() -> Result<Observation, Refusal> {
    Err(Refusal::UnsupportedHost)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn baseline() -> Observation {
        Observation {
            apic_id: 0x1234,
            vendor: TargetCpu::INTEL_VENDOR,
            cr0: CR0_REQUIRED,
            cr4: CR4_REQUIRED,
            efer: EFER_REQUIRED,
            flags: 0,
            cpuid1_ecx: 0,
            cpuid1_edx: CPUID_FLOOR_EDX,
            extended_edx: CPUID_LONG_NX,
            cpuid7_ecx: 0,
        }
    }
    #[test]
    fn legacy_xmm_floor_never_invents_extended_features() {
        let mut actual = baseline();
        assert_eq!(actual.target(), Ok(TargetCpu::Baseline));
        actual.cpuid1_edx |= 1 << 8;
        actual.cpuid1_ecx |= 1 << 13;
        let expected = TargetCpu::Baseline.with_cx8().with_cx16();
        assert_eq!(actual.target(), Ok(expected));
        actual.cr4 |= 1 << 18; // OSXSAVE does not admit AVX or a wider target.
        actual.cpuid1_ecx |= !(1 << 28);
        assert_eq!(actual.target(), Ok(expected));
        actual.cr4 |= 1 << 12;
        assert_eq!(actual.target(), Err(Refusal::Controls));
        actual.cpuid7_ecx |= 1 << 16;
        assert_eq!(actual.target(), Ok(expected));
    }
    #[test]
    fn aligned_atomic_legacy_xmm_capability_is_independent_of_os_avx_state() {
        let mut actual = baseline();
        actual.cpuid1_ecx |= 1 << 28;
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        assert_eq!(actual.cr4 & (1 << 18), 0);
        assert!(!actual.target().unwrap().supports(TargetCpu::Avx2));
        actual.cr4 |= 1 << 18;
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        let proof = NativeSystemTarget {
            observed: actual,
            target: actual.target().unwrap(),
        };
        actual.cpuid1_ecx &= !(1 << 28);
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::TargetChanged)
        );
        actual.cpuid1_ecx |= 1 << 28;
        actual.vendor = TargetCpu::AMD_VENDOR;
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        actual.cr4 &= !(1 << 18);
        assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
        actual.vendor = [0; 3];
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
            actual.cr0 &= !(1 << bit);
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        for bit in [2, 3, 29, 30] {
            let mut actual = baseline();
            actual.cr0 |= 1 << bit;
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        for bit in [5, 9, 10] {
            let mut actual = baseline();
            actual.cr4 &= !(1 << bit);
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        for bit in [7, 17, 23] {
            let mut actual = baseline();
            actual.cr4 |= 1 << bit;
            assert_eq!(actual.target(), Err(Refusal::Controls));
        }
        let mut actual = baseline();
        actual.flags = IF;
        assert_eq!(actual.target(), Err(Refusal::InterruptsEnabled));
    }
    #[test]
    fn physical_migration_control_changes_and_lost_capability_refuse() {
        let mut actual = baseline();
        actual.cpuid1_ecx |= 1 << 13;
        let proof = NativeSystemTarget {
            observed: actual,
            target: actual.target().unwrap(),
        };
        assert_eq!(proof.revalidate_observation(actual), Ok(()));
        actual.apic_id = 0x34;
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::ProcessorChanged)
        );
        actual = proof.observed;
        actual.cr4 |= 1 << 18;
        assert_eq!(proof.revalidate_observation(actual), Err(Refusal::Controls));
        actual = proof.observed;
        actual.cpuid1_ecx &= !(1 << 13);
        assert_eq!(
            proof.revalidate_observation(actual),
            Err(Refusal::TargetChanged)
        );
        assert_eq!(
            NativeSystemTarget::capture().unwrap_err(),
            Refusal::UnsupportedHost
        );
    }
}
