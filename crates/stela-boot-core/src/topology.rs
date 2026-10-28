//! Copied firmware processor identity and per-processor CPUID observations.
//! One selected logical processor owns each physical core; SMT siblings never
//! increase the number of guest PEs admitted by this native executor.

use alloc::vec::Vec;

/// Physical cores the native executor can own. Hosts with more physical
/// cores run on the first `MAX_CORES` of `select`'s order.
pub const MAX_CORES: usize = 64;

/// Physical cores the executor owns from `available` discovered cores.
/// Without a request this is `min(available, MAX_CORES)`; an explicit count
/// narrows it and refuses when it exceeds either bound.
pub fn assignment_count(requested: Option<usize>, available: usize) -> Result<usize, &'static str> {
    let assignable = available.min(MAX_CORES);
    let count = requested.unwrap_or(assignable);
    if assignable == 0 || count == 0 || count > assignable {
        return Err("native assignment is outside the actual physical-core roster");
    }
    Ok(count)
}
pub const MAX_CPUID: usize = 48;
pub const MAX_MSRS: usize = 64;

pub const BSP: u32 = 1;
pub const ENABLED: u32 = 1 << 1;
pub const HEALTHY: u32 = 1 << 2;

/// Number of guest PEs admitted by both the retained host roster and the
/// source profile. Extra default workers stay parked; an explicit request
/// must fit both inventories.
pub fn guest_assignment_count(
    requested: Option<usize>,
    available: usize,
    source_slots: usize,
) -> Result<usize, &'static str> {
    assignment_count(requested, available.min(source_slots))
}

/// Coordinates copied from UEFI MP Services Location/Location2. Legacy
/// coordinates flatten the core identity within a package.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    pub package: u32,
    pub module: u32,
    pub tile: u32,
    pub die: u32,
    pub core: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Processor {
    pub processor_number: u32,
    pub apic_id: u64,
    pub flags: u32,
    /// 1: original three-level UEFI Location; 2: extended Location2.
    pub topology_version: u32,
    pub location: Location,
    pub thread: u32,
}

impl Processor {
    pub fn available(self) -> bool {
        self.flags & (ENABLED | HEALTHY) == ENABLED | HEALTHY
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cpuid {
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Msr {
    pub index: u32,
    pub value: u64,
}

/// The core class reported by the processor's CPUID interface. Unknown
/// includes unsupported leaves and reserved class values.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CoreClass {
    #[default]
    Unknown,
    Performance,
    Efficiency,
    LowPower,
}

/// Invalid input to a host/guest core assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    Cardinality,
    Capacity,
    Bootstrap,
}

/// Assign guest slots to host indices without changing guest slot order.
/// Host index zero runs the guest boot slot. Exact class matches are reserved
/// before an unmatched guest can consume another class's worker. Unknown
/// workers, then other unused workers, fill any remaining slots in host order.
/// Homogeneous host classes keep the original BSP-first assignment. When the
/// guest has fewer slots, choose from the complete retained host roster; a
/// matching class beyond the first guest-count workers remains eligible.
pub fn placement(
    guest: &[CoreClass],
    host: &[CoreClass],
    boot: usize,
) -> Result<Vec<usize>, PlacementError> {
    if guest.is_empty() || guest.len() > host.len() {
        return Err(PlacementError::Cardinality);
    }
    if host.len() > MAX_CORES {
        return Err(PlacementError::Capacity);
    }
    if boot >= guest.len() {
        return Err(PlacementError::Bootstrap);
    }
    let original: Vec<_> = (0..guest.len())
        .map(|slot| {
            if slot == boot {
                0
            } else if slot < boot {
                slot + 1
            } else {
                slot
            }
        })
        .collect();
    if host.windows(2).all(|pair| pair[0] == pair[1]) {
        return Ok(original);
    }
    let mut assigned = alloc::vec![usize::MAX; guest.len()];
    let mut used = alloc::vec![false; host.len()];
    assigned[boot] = 0;
    used[0] = true;
    for (slot, class) in guest.iter().enumerate() {
        if assigned[slot] != usize::MAX || *class == CoreClass::Unknown {
            continue;
        }
        if let Some(worker) = host
            .iter()
            .enumerate()
            .position(|(worker, kind)| !used[worker] && kind == class)
        {
            assigned[slot] = worker;
            used[worker] = true;
        }
    }
    // Low-power and efficiency cores can host the other's E-class work once
    // every exact match has been reserved.
    for (slot, class) in guest.iter().enumerate() {
        let alternate = match class {
            CoreClass::Efficiency => CoreClass::LowPower,
            CoreClass::LowPower => CoreClass::Efficiency,
            _ => continue,
        };
        if assigned[slot] == usize::MAX
            && let Some(worker) = host
                .iter()
                .enumerate()
                .position(|(worker, kind)| !used[worker] && *kind == alternate)
        {
            assigned[slot] = worker;
            used[worker] = true;
        }
    }
    for unknown_only in [true, false] {
        for worker in &mut assigned {
            if *worker != usize::MAX {
                continue;
            }
            if let Some(index) = host.iter().enumerate().position(|(index, kind)| {
                !used[index] && (!unknown_only || *kind == CoreClass::Unknown)
            }) {
                *worker = index;
                used[index] = true;
            }
        }
    }
    Ok(assigned)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub records: [Cpuid; MAX_CPUID],
    pub count: u32,
    pub msrs: [Msr; MAX_MSRS],
    pub msr_count: u32,
    /// The firmware's CR0/CR4/EFER, without inventing OS XSTATE enablement.
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub pat: u64,
    pub pat_valid: bool,
    pub apic_base: u64,
    pub xcr0: u64,
    pub xcr0_valid: bool,
    /// AMD fixed RdMem/WrMem were read with the visibility gate open,
    /// then the original SYSCFG was restored. Masked zeros are not evidence.
    pub amd_fixed_raw: bool,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            records: [Cpuid::default(); MAX_CPUID],
            count: 0,
            msrs: [Msr::default(); MAX_MSRS],
            msr_count: 0,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            pat: 0,
            pat_valid: false,
            apic_base: 0,
            xcr0: 0,
            xcr0_valid: false,
            amd_fixed_raw: false,
        }
    }
}

impl Snapshot {
    pub fn get(&self, leaf: u32, subleaf: u32) -> Option<Cpuid> {
        self.records
            .get(..self.count as usize)?
            .iter()
            .find(|record| record.leaf == leaf && record.subleaf == subleaf)
            .copied()
    }

    /// Prefer the original extended APIC ID. The legacy eight-bit field is
    /// accepted only when no implemented extended topology leaf supplies one.
    pub fn apic_id(&self) -> Option<u32> {
        let identity = self.get(0, 0)?;
        let maximum = identity.eax;
        if maximum < 1 {
            return None;
        }
        let basic = self.get(1, 0)?;
        for leaf in [0x1f, 0xb] {
            if maximum >= leaf {
                // A missing declared observation is not an unsupported leaf.
                let record = self.get(leaf, 0)?;
                if record.ebx & 0xffff != 0 && (record.ecx >> 8) & 0xff != 0 {
                    return Some(record.edx);
                }
            }
        }
        if [identity.ebx, identity.edx, identity.ecx] == stela_compiler::TargetCpu::AMD_VENDOR {
            let extended = self.get(0x8000_0000, 0)?;
            if extended.eax >= 0x8000_001e && self.get(0x8000_0001, 0)?.ecx & (1 << 22) != 0 {
                return self.get(0x8000_001e, 0).map(|record| record.eax);
            }
        }
        Some(basic.ebx >> 24)
    }

    pub fn matches(&self, processor: Processor) -> bool {
        self.apic_id()
            .is_some_and(|id| u64::from(id) == processor.apic_id)
    }

    /// Intel SDM CPUID.1AH and AMD CPUID.80000026H, decoded as Linux's
    /// `get_topology_cpu_type` and `parse_topology_amd` do. Each snapshot
    /// belongs to one processor; the BSP's class cannot describe an AP.
    pub fn core_class(&self) -> CoreClass {
        use stela_compiler::TargetCpu;
        let Some(identity) = self.get(0, 0) else {
            return CoreClass::Unknown;
        };
        match [identity.ebx, identity.edx, identity.ecx] {
            TargetCpu::INTEL_VENDOR if identity.eax >= 0x1a => {
                // Intel permits this leaf on non-hybrid processors too.
                match self.get(0x1a, 0).map(|record| record.eax >> 24) {
                    Some(0x20) => CoreClass::Efficiency,
                    Some(0x40) => CoreClass::Performance,
                    _ => CoreClass::Unknown,
                }
            }
            TargetCpu::AMD_VENDOR
                if self
                    .get(0x8000_0000, 0)
                    .is_some_and(|record| record.eax >= 0x8000_0026) =>
            {
                let Some(record) = self.get(0x8000_0026, 0) else {
                    return CoreClass::Unknown;
                };
                // A valid level with the Heterogeneous Core Topology bit.
                if record.eax & (1 << 30) == 0
                    || record.ebx & 0xffff == 0
                    || record.ecx >> 8 & 0xff == 0
                {
                    return CoreClass::Unknown;
                }
                match record.ebx >> 28 {
                    0 => CoreClass::Performance,
                    1 => CoreClass::Efficiency,
                    2 => CoreClass::LowPower,
                    _ => CoreClass::Unknown,
                }
            }
            _ => CoreClass::Unknown,
        }
    }
}

/// Conservative compiler policy from the assigned workers' actual installed
/// observations. This cannot grant execution: registration and each native
/// entry must still validate the destination's current hardware and controls.
pub fn common_native_target(
    observations: &[&Snapshot],
) -> Result<stela_compiler::TargetCpu, CapabilityRefusal> {
    use stela_compiler::TargetCpu;
    const SSSE3: u32 = 1 << 9;
    const SSE41: u32 = 1 << 19;
    const SSE42: u32 = 1 << 20;
    const PCLMULQDQ: u32 = 1 << 1;
    const POPCNT: u32 = 1 << 23;
    const AES: u32 = 1 << 25;
    const SHA: u32 = 1 << 29;
    const CX8: u32 = 1 << 8;
    const CX16: u32 = 1 << 13;
    if observations.is_empty() || observations.len() > MAX_CORES {
        return Err(CapabilityRefusal::InvalidSnapshot);
    }
    let (mut ecx, mut edx, mut structured) = (u32::MAX, u32::MAX, u32::MAX);
    let mut atomic16 = true;
    for snapshot in observations {
        let vendor = snapshot
            .get(0, 0)
            .filter(|record| record.eax >= 1)
            .ok_or(CapabilityRefusal::InvalidSnapshot)?;
        let basic = snapshot
            .get(1, 0)
            .ok_or(CapabilityRefusal::InvalidSnapshot)?;
        ecx &= basic.ecx;
        edx &= basic.edx;
        structured &= if vendor.eax >= 7 {
            snapshot.get(7, 0).map_or(0, |record| record.ebx)
        } else {
            0
        };
        atomic16 &=
            TargetCpu::atomic_load16_guaranteed([vendor.ebx, vendor.edx, vendor.ecx], basic.ecx);
    }
    let mut target = match (ecx & SSSE3 != 0, ecx & SSE41 != 0, ecx & SSE42 != 0) {
        (true, true, true) => TargetCpu::Sse42,
        (true, true, false) => TargetCpu::Sse41,
        (true, false, _) => TargetCpu::Ssse3,
        _ => TargetCpu::Baseline,
    };
    for (present, with) in [
        (
            ecx & PCLMULQDQ != 0,
            TargetCpu::with_pclmulqdq as fn(_) -> _,
        ),
        (ecx & POPCNT != 0, TargetCpu::with_popcnt),
        (ecx & AES != 0, TargetCpu::with_aes),
        (structured & SHA != 0, TargetCpu::with_sha),
        (edx & CX8 != 0, TargetCpu::with_cx8),
        (ecx & CX16 != 0, TargetCpu::with_cx16),
        (atomic16, TargetCpu::with_atomic_load16),
    ] {
        if present {
            target = with(target);
        }
    }
    Ok(target)
}

/// The initial native executor deliberately uses legacy XMM state only. It
/// derives this floor on each actual physical core rather than borrowing the
/// BSP's CPUID or firmware OSXSAVE state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityRefusal {
    InvalidSnapshot,
    NativeFloor,
    FiveLevelPaging,
    MemoryTypes,
}

impl Snapshot {
    pub fn qualify_native(&self, five_level: bool) -> Result<(), CapabilityRefusal> {
        if self.count as usize > MAX_CPUID || self.msr_count as usize > MAX_MSRS {
            return Err(CapabilityRefusal::InvalidSnapshot);
        }
        let basic = self.get(1, 0).ok_or(CapabilityRefusal::NativeFloor)?;
        let extended = self
            .get(0x8000_0001, 0)
            .ok_or(CapabilityRefusal::NativeFloor)?;
        // SSE3/SSSE3/CX16/SSE4.1/SSE4.2/POPCNT; FPU/TSC/MSR/PAE/CX8/
        // APIC/MTRR/PAT/FXSR/SSE/SSE2; LAHF-LM/NX/long mode.
        const ECX: u32 = (1 << 0) | (1 << 9) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 23);
        const EDX: u32 = (1 << 0)
            | (1 << 4)
            | (1 << 5)
            | (1 << 6)
            | (1 << 8)
            | (1 << 9)
            | (1 << 12)
            | (1 << 16)
            | (1 << 24)
            | (1 << 25)
            | (1 << 26);
        const EXTENDED_EDX: u32 = (1 << 20) | (1 << 29);
        if basic.ecx & ECX != ECX
            || basic.edx & EDX != EDX
            || extended.ecx & 1 == 0
            || extended.edx & EXTENDED_EDX != EXTENDED_EDX
            || !self.pat_valid
            || self.apic_base & (1 << 11) == 0
        {
            return Err(CapabilityRefusal::NativeFloor);
        }
        if five_level && !self.get(7, 0).is_some_and(|leaf| leaf.ecx & (1 << 16) != 0) {
            return Err(CapabilityRefusal::FiveLevelPaging);
        }
        Ok(())
    }

    /// Require the actual installed memory-type/routing image to equal the
    /// intended source image before sharing RAM or Stela metadata. Initial
    /// offline installation may establish this equality; TSC_ADJUST is separate.
    pub fn same_memory_types(&self, other: &Self) -> Result<(), CapabilityRefusal> {
        fn memory(index: u32) -> bool {
            index == 0xfe
                || index == 0x2ff
                || (0x200..=0x21f).contains(&index)
                || matches!(index, 0x250 | 0x258 | 0x259 | 0x268..=0x26f)
                || matches!(index, 0xc001_0010 | 0xc001_0016..=0xc001_001a | 0xc001_001d)
        }
        let left = self
            .msrs
            .get(..self.msr_count as usize)
            .ok_or(CapabilityRefusal::InvalidSnapshot)?;
        let right = other
            .msrs
            .get(..other.msr_count as usize)
            .ok_or(CapabilityRefusal::InvalidSnapshot)?;
        if self.amd_fixed_raw != other.amd_fixed_raw
            || !self.pat_valid
            || !other.pat_valid
            || self.pat != other.pat
            || !left
                .iter()
                .filter(|msr| memory(msr.index))
                .eq(right.iter().filter(|msr| memory(msr.index)))
            || !left.iter().any(|msr| msr.index == 0xfe)
            || !left.iter().any(|msr| msr.index == 0x2ff)
        {
            return Err(CapabilityRefusal::MemoryTypes);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NoBootstrapProcessor,
    MultipleBootstrapProcessors,
    BootstrapUnavailable,
    InvalidTopology,
    DuplicateProcessorNumber,
    DuplicateApicId,
    DuplicateThreadLocation,
    MixedTopologyVersions,
    InvalidAssignment,
}

fn bootstrap_index(processors: &[Processor]) -> Result<usize, Refusal> {
    let mut bsp = None;
    for (index, processor) in processors.iter().enumerate() {
        if !matches!(processor.topology_version, 1 | 2) {
            return Err(Refusal::InvalidTopology);
        }
        if processor.flags & BSP != 0 {
            if bsp.replace(index).is_some() {
                return Err(Refusal::MultipleBootstrapProcessors);
            }
            if !processor.available() {
                return Err(Refusal::BootstrapUnavailable);
            }
        }
        for previous in &processors[..index] {
            if processor.processor_number == previous.processor_number {
                return Err(Refusal::DuplicateProcessorNumber);
            }
            if processor.apic_id == previous.apic_id {
                return Err(Refusal::DuplicateApicId);
            }
            if processor.location == previous.location && processor.thread == previous.thread {
                return Err(Refusal::DuplicateThreadLocation);
            }
            if processor.topology_version != previous.topology_version {
                return Err(Refusal::MixedTopologyVersions);
            }
        }
    }
    bsp.ok_or(Refusal::NoBootstrapProcessor)
}

/// Return one original processor index per physical core, BSP first, then by
/// location, without renumbering their firmware identity. The list covers
/// every physical core; assignment takes a prefix (`assignment_count`). No AP
/// is started and no capability is inferred here.
pub fn select(processors: &[Processor]) -> Result<Vec<usize>, Refusal> {
    let bsp = bootstrap_index(processors)?;
    let mut selected = alloc::vec![bsp];
    // Prefer the lowest original thread/processor number on each other core.
    // The BSP owns its own physical core even when its thread number is nonzero.
    let mut candidates: Vec<_> = processors
        .iter()
        .enumerate()
        .filter(|(_, processor)| processor.available())
        .collect();
    candidates.sort_by_key(|(_, processor)| {
        (
            processor.location,
            processor.thread,
            processor.processor_number,
        )
    });
    for (index, processor) in candidates {
        if selected
            .iter()
            .any(|&other| processors[other].location == processor.location)
        {
            continue;
        }
        selected.push(index);
    }
    Ok(selected)
}

/// Enabled logical processors outside the actual requested physical roster.
/// Unlike admission, this includes enabled unhealthy APs: health does not prove
/// that their firmware execution has stopped. Disabled processors stay disabled.
/// No allocation or firmware access is needed at the post-EBS boundary.
pub fn enabled_unselected<'a>(
    processors: &'a [Processor],
    selected: &'a [u32],
) -> Result<impl Iterator<Item = usize> + Clone + 'a, Refusal> {
    let bsp = bootstrap_index(processors)?;
    if selected.is_empty() || selected.len() > MAX_CORES || selected[0] as usize != bsp {
        return Err(Refusal::InvalidAssignment);
    }
    for (slot, &index) in selected.iter().enumerate() {
        let processor = processors
            .get(index as usize)
            .filter(|processor| processor.available())
            .ok_or(Refusal::InvalidAssignment)?;
        if selected[..slot]
            .iter()
            .any(|&previous| processors[previous as usize].location == processor.location)
        {
            return Err(Refusal::InvalidAssignment);
        }
    }
    Ok(processors
        .iter()
        .enumerate()
        .filter(move |(index, processor)| {
            processor.flags & ENABLED != 0 && !selected.contains(&(*index as u32))
        })
        .map(|(index, _)| index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn processor(number: u32, package: u32, core: u32, thread: u32) -> Processor {
        Processor {
            processor_number: number,
            apic_id: u64::from(number) + 1000,
            flags: ENABLED | HEALTHY,
            topology_version: 2,
            location: Location {
                package,
                core,
                ..Location::default()
            },
            thread,
        }
    }

    fn classified_snapshot(vendor: [u32; 3], maximum: u32, class: Cpuid) -> Snapshot {
        let mut snapshot = Snapshot::default();
        snapshot.records[0] = Cpuid {
            leaf: 0,
            eax: maximum,
            ebx: vendor[0],
            edx: vendor[1],
            ecx: vendor[2],
            ..Cpuid::default()
        };
        snapshot.records[1] = Cpuid {
            leaf: 0x8000_0000,
            eax: 0x8000_0026,
            ..Cpuid::default()
        };
        snapshot.records[2] = class;
        snapshot.count = 3;
        snapshot
    }

    #[test]
    fn guest_assignment_fits_source_and_preserves_explicit_requests() {
        for available in [1, 8, 64, 128] {
            assert_eq!(
                guest_assignment_count(None, available, 8),
                Ok(available.min(8))
            );
        }
        assert_eq!(guest_assignment_count(Some(4), 64, 8), Ok(4));
        for (request, available, source) in [
            (Some(9), 64, 8),
            (Some(4), 2, 8),
            (Some(0), 64, 8),
            (None, 64, 0),
            (None, 0, 8),
        ] {
            assert!(guest_assignment_count(request, available, source).is_err());
        }
    }

    #[test]
    fn intel_core_classes_require_a_supported_known_type() {
        use stela_compiler::TargetCpu;
        for (kind, expected) in [
            (0x20, CoreClass::Efficiency),
            (0x40, CoreClass::Performance),
            (0, CoreClass::Unknown),
            (0x30, CoreClass::Unknown),
        ] {
            let class = Cpuid {
                leaf: 0x1a,
                eax: kind << 24 | 0x1234,
                ..Cpuid::default()
            };
            let mut snapshot = classified_snapshot(TargetCpu::INTEL_VENDOR, 0x1a, class);
            assert_eq!(snapshot.core_class(), expected);
            snapshot.records[0].eax = 0x19;
            assert_eq!(snapshot.core_class(), CoreClass::Unknown);
            snapshot.records[0].eax = 0x1a;
            snapshot.count = 2;
            assert_eq!(snapshot.core_class(), CoreClass::Unknown);
        }
    }

    #[test]
    fn amd_core_classes_require_a_valid_heterogeneous_level() {
        use stela_compiler::TargetCpu;
        for (kind, expected) in [
            (0, CoreClass::Performance),
            (1, CoreClass::Efficiency),
            (2, CoreClass::LowPower),
            (3, CoreClass::Unknown),
        ] {
            let class = Cpuid {
                leaf: 0x8000_0026,
                eax: 1 << 30,
                ebx: kind << 28 | 2,
                ecx: 1 << 8,
                ..Cpuid::default()
            };
            let snapshot = classified_snapshot(TargetCpu::AMD_VENDOR, 7, class);
            assert_eq!(snapshot.core_class(), expected);
            for changed in [
                Cpuid { eax: 0, ..class },
                Cpuid {
                    ebx: kind << 28,
                    ..class
                },
                Cpuid { ecx: 0, ..class },
            ] {
                let mut invalid = snapshot;
                invalid.records[2] = changed;
                assert_eq!(invalid.core_class(), CoreClass::Unknown);
            }
            let mut invalid = snapshot;
            invalid.records[1].eax = 0x8000_0025;
            assert_eq!(invalid.core_class(), CoreClass::Unknown);
            invalid = snapshot;
            invalid.count = 2;
            assert_eq!(invalid.core_class(), CoreClass::Unknown);
        }
    }

    #[test]
    fn unknown_vendor_or_malformed_snapshot_has_no_core_class() {
        let class = Cpuid {
            leaf: 0x1a,
            eax: 0x40 << 24,
            ..Cpuid::default()
        };
        let snapshot = classified_snapshot([0; 3], 0x1a, class);
        assert_eq!(snapshot.core_class(), CoreClass::Unknown);
        let mut malformed = snapshot;
        malformed.count = MAX_CPUID as u32 + 1;
        assert_eq!(malformed.core_class(), CoreClass::Unknown);
        assert_eq!(Snapshot::default().core_class(), CoreClass::Unknown);
    }

    #[test]
    fn placement_reserves_matches_before_cross_class_fallback() {
        use CoreClass::{Efficiency as E, Performance as P, Unknown as U};
        assert_eq!(
            placement(&[P, E, E, P], &[P, P, P, E], 0),
            Ok(vec![0, 3, 2, 1])
        );
        assert_eq!(
            placement(&[E, P, E, P], &[P, E, P, E], 1),
            Ok(vec![1, 0, 3, 2])
        );
        assert_eq!(
            placement(&[P, E, E, P], &[P, P, U, E], 0),
            Ok(vec![0, 3, 2, 1])
        );
    }

    #[test]
    fn placement_prefers_efficiency_before_low_power() {
        use CoreClass::{Efficiency as E, LowPower as L, Performance as P};
        assert_eq!(
            placement(&[P, E, E, P], &[P, L, E, P], 0),
            Ok(vec![0, 2, 1, 3])
        );
        assert_eq!(
            placement(&[P, E, L, P], &[P, L, E, P], 0),
            Ok(vec![0, 2, 1, 3])
        );
    }

    #[test]
    fn homogeneous_or_unknown_hosts_keep_bsp_first_order() {
        use CoreClass::{Efficiency as E, Performance as P, Unknown as U};
        for class in [P, E, U] {
            for boot in 0..4 {
                let result = placement(&[E, P, E, P], &[class; 4], boot).unwrap();
                assert_eq!(result[boot], 0);
                assert_eq!(
                    result
                        .iter()
                        .copied()
                        .filter(|&worker| worker != 0)
                        .collect::<Vec<_>>(),
                    vec![1, 2, 3]
                );
            }
        }
    }

    #[test]
    fn placement_is_a_permutation_with_the_boot_worker_fixed() {
        use CoreClass::{Efficiency, LowPower, Performance, Unknown};
        let classes = [Unknown, Performance, Efficiency, LowPower];
        for guest_bits in 0..64 {
            let guest = core::array::from_fn::<_, 3, _>(|i| classes[guest_bits >> (i * 2) & 3]);
            for host_bits in 0..64 {
                let host = core::array::from_fn::<_, 3, _>(|i| classes[host_bits >> (i * 2) & 3]);
                for boot in 0..3 {
                    let mut result = placement(&guest, &host, boot).unwrap();
                    assert_eq!(result[boot], 0);
                    result.sort_unstable();
                    assert_eq!(result, vec![0, 1, 2]);
                }
            }
        }
    }

    #[test]
    fn placement_searches_all_retained_workers_when_guest_has_fewer_slots() {
        use CoreClass::{Efficiency as E, Performance as P, Unknown as U};
        assert_eq!(placement(&[P, E], &[P, P, P, E], 0), Ok(vec![0, 3]));
        assert_eq!(placement(&[E, P], &[P, P, P, E], 1), Ok(vec![3, 0]));
        assert_eq!(placement(&[E], &[P, P, P, E], 0), Ok(vec![0]));
        assert_eq!(placement(&[P, E], &[U, U, U, U], 0), Ok(vec![0, 1]));
        let classes = [U, P, E, CoreClass::LowPower];
        for guest_bits in 0..16 {
            let guest = core::array::from_fn::<_, 2, _>(|i| classes[guest_bits >> (i * 2) & 3]);
            for host_bits in 0..256 {
                let host = core::array::from_fn::<_, 4, _>(|i| classes[host_bits >> (i * 2) & 3]);
                for boot in 0..2 {
                    let result = placement(&guest, &host, boot).unwrap();
                    assert_eq!(result[boot], 0);
                    assert_ne!(result[0], result[1]);
                    assert!(result.iter().all(|worker| *worker < host.len()));
                }
            }
        }
    }

    #[test]
    fn placement_rejects_invalid_rosters() {
        use CoreClass::Unknown as U;
        assert_eq!(placement(&[], &[], 0), Err(PlacementError::Cardinality));
        assert_eq!(
            placement(&[U, U], &[U], 0),
            Err(PlacementError::Cardinality)
        );
        assert_eq!(placement(&[U], &[U], 1), Err(PlacementError::Bootstrap));
        assert_eq!(
            placement(&[U; MAX_CORES + 1], &[U; MAX_CORES + 1], 0),
            Err(PlacementError::Capacity)
        );
    }

    #[test]
    fn default_assignment_uses_all_actual_cores_and_only_explicit_counts_narrow_it() {
        for available in 1..=MAX_CORES {
            assert_eq!(assignment_count(None, available), Ok(available));
            for selected in 1..=available {
                assert_eq!(assignment_count(Some(selected), available), Ok(selected));
            }
            assert!(assignment_count(Some(0), available).is_err());
            assert!(assignment_count(Some(available + 1), available).is_err());
        }
        assert!(assignment_count(None, 0).is_err());
    }

    #[test]
    fn default_assignment_caps_large_hosts_and_explicit_over_requests_refuse() {
        for available in [MAX_CORES + 1, 96, 192, 512] {
            assert_eq!(assignment_count(None, available), Ok(MAX_CORES));
            assert_eq!(assignment_count(Some(8), available), Ok(8));
            assert_eq!(assignment_count(Some(MAX_CORES), available), Ok(MAX_CORES));
            assert!(assignment_count(Some(MAX_CORES + 1), available).is_err());
        }
    }

    /// `packages` x `cores` x `threads` logical processors, BSP on the last
    /// thread of the last core of package 0.
    fn large_host(packages: u32, cores: u32, threads: u32) -> Vec<Processor> {
        let mut source = Vec::new();
        for package in 0..packages {
            for core in 0..cores {
                for thread in 0..threads {
                    let number = source.len() as u32;
                    source.push(processor(number, package, core, thread));
                }
            }
        }
        let bsp = (cores * threads - 1) as usize;
        source[bsp].flags |= BSP;
        source
    }

    #[test]
    fn large_hosts_select_every_physical_core_and_retire_those_past_the_assignment() {
        // Dual-socket 96-core SMT host: 384 logical processors, 192 cores.
        let source = large_host(2, 96, 2);
        let all = select(&source).unwrap();
        assert_eq!(all.len(), 192);
        assert_eq!(all[0], 191); // BSP first, even on thread 1
        assert!(all[1..].iter().all(|&index| source[index].thread == 0));
        let assigned = assignment_count(None, all.len()).unwrap();
        assert_eq!(assigned, MAX_CORES);
        // The assigned prefix stays on package 0 before using package 1.
        assert!(
            all[..assigned]
                .iter()
                .all(|&index| source[index].location.package == 0)
        );
        let selected: Vec<_> = all[..assigned].iter().map(|&index| index as u32).collect();
        let retired: Vec<_> = enabled_unselected(&source, &selected).unwrap().collect();
        assert_eq!(retired.len(), source.len() - MAX_CORES);
        for &index in &all[assigned..] {
            assert!(retired.contains(&index)); // unassigned physical cores get INIT
        }
        assert!(!retired.contains(&191));
    }

    #[test]
    fn processor_inventory_has_no_fixed_logical_ceiling() {
        let source = large_host(4, 80, 2); // 640 logical processors
        assert_eq!(select(&source).map(|cores| cores.len()), Ok(320));
        let source = large_host(1, 1, 300); // one core, 300 threads
        assert_eq!(select(&source), Ok(alloc::vec![299]));
    }

    #[test]
    fn one_thread_per_physical_core_and_original_bsp_are_preserved() {
        let mut cores = [
            processor(3, 0, 0, 1),
            processor(8, 0, 0, 0),
            processor(12, 0, 1, 1),
            processor(17, 0, 1, 0),
            processor(22, 1, 0, 0),
        ];
        cores[0].flags |= BSP;
        assert_eq!(select(&cores), Ok(alloc::vec![0, 3, 4]));
        // Extended die/module/tile coordinates distinguish physical cores.
        cores[4].location.package = 0;
        cores[4].location.die = 1;
        assert_eq!(select(&cores), Ok(alloc::vec![0, 3, 4]));
    }

    #[test]
    fn unselected_enabled_threads_and_unrequested_cores_need_init_without_identity_assumptions() {
        let mut source = [
            processor(41, 3, 9, 0),
            processor(77, 3, 9, 3),
            processor(12, 3, 2, 0),
            processor(93, 3, 2, 1),
            processor(3, 6, 1, 0),
            processor(66, 6, 1, 1),
            processor(51, 6, 8, 0),
            processor(24, 6, 8, 1),
        ];
        source[1].flags |= BSP; // BSP is neither first nor thread zero.
        source[6].flags = HEALTHY; // disabled: no INIT target
        source[7].flags = ENABLED; // unhealthy but still enabled: INIT target
        let all = select(&source).unwrap();
        assert_eq!(all, [1, 2, 4]);
        for requested in 1..=all.len() {
            let selected: Vec<_> = all[..requested].iter().map(|&index| index as u32).collect();
            let actual: Vec<_> = enabled_unselected(&source, &selected).unwrap().collect();
            let expected: Vec<_> = (0..source.len())
                .filter(|index| *index != 6 && !all[..requested].contains(index))
                .collect();
            assert_eq!(actual, expected);
            assert!(actual.contains(&0)); // BSP's enabled sibling
            assert!(actual.contains(&7)); // enabled, unhealthy AP
            assert!(!actual.contains(&1)); // never INIT the BSP
        }
    }

    #[test]
    fn malformed_quiescence_assignment_refuses_before_any_targets_are_exposed() {
        let mut source = [
            processor(9, 0, 0, 0),
            processor(5, 0, 0, 1),
            processor(3, 0, 1, 0),
        ];
        source[0].flags |= BSP;
        for selected in [&[][..], &[1][..], &[0, 0][..], &[0, 1][..], &[0, 3][..]] {
            assert!(matches!(
                enabled_unselected(&source, selected),
                Err(Refusal::InvalidAssignment)
            ));
        }
        source[2].flags = ENABLED;
        assert!(matches!(
            enabled_unselected(&source, &[0, 2]),
            Err(Refusal::InvalidAssignment)
        ));
        source[2].apic_id = source[0].apic_id;
        assert!(matches!(
            enabled_unselected(&source, &[0]),
            Err(Refusal::DuplicateApicId)
        ));
    }

    #[test]
    fn disabled_and_unhealthy_aps_cannot_supply_guest_capacity() {
        let mut cores = [
            processor(0, 0, 0, 0),
            processor(1, 0, 1, 0),
            processor(2, 0, 2, 0),
        ];
        cores[0].flags |= BSP;
        cores[1].flags = HEALTHY;
        cores[2].flags = ENABLED;
        assert_eq!(select(&cores), Ok(alloc::vec![0]));
        cores[0].flags = BSP | ENABLED;
        assert_eq!(select(&cores), Err(Refusal::BootstrapUnavailable));
    }

    #[test]
    fn invalid_and_ambiguous_source_identity_refuses_instead_of_oversubscribing() {
        let mut cores = [processor(0, 0, 0, 0), processor(1, 0, 1, 0)];
        assert_eq!(select(&cores), Err(Refusal::NoBootstrapProcessor));
        cores[0].flags |= BSP;
        cores[1].flags |= BSP;
        assert_eq!(select(&cores), Err(Refusal::MultipleBootstrapProcessors));
        cores[1].flags &= !BSP;
        cores[1].apic_id = cores[0].apic_id;
        assert_eq!(select(&cores), Err(Refusal::DuplicateApicId));
        cores[1].apic_id = 5;
        cores[1].processor_number = 0;
        assert_eq!(select(&cores), Err(Refusal::DuplicateProcessorNumber));
        cores[1].processor_number = 1;
        cores[1].topology_version = 1;
        assert_eq!(select(&cores), Err(Refusal::MixedTopologyVersions));
        cores[1].topology_version = 0;
        assert_eq!(select(&cores), Err(Refusal::InvalidTopology));
    }

    #[test]
    fn extended_apic_identity_is_not_truncated_to_the_legacy_smt_field() {
        let mut snapshot = Snapshot::default();
        snapshot.records[0] = Cpuid {
            leaf: 1,
            ebx: 7 << 24,
            ..Cpuid::default()
        };
        snapshot.records[1] = Cpuid {
            leaf: 0xb,
            ebx: 2,
            ecx: 1 << 8,
            edx: 0x1234,
            ..Cpuid::default()
        };
        snapshot.records[2] = Cpuid {
            leaf: 0x1f,
            ..Cpuid::default()
        };
        snapshot.records[3] = Cpuid {
            leaf: 0,
            eax: 0xb,
            ..Cpuid::default()
        };
        snapshot.count = 4;
        let mut core = processor(0, 0, 0, 0);
        core.apic_id = 0x1234;
        assert!(snapshot.matches(core));
        core.apic_id = 7;
        assert!(!snapshot.matches(core));
        snapshot.records[2] = Cpuid {
            leaf: 0x1f,
            ebx: 2,
            ecx: 1 << 8,
            edx: 0x5678,
            ..Cpuid::default()
        };
        snapshot.records[3].eax = 0x1f;
        assert_eq!(snapshot.apic_id(), Some(0x5678));
        snapshot.count = (MAX_CPUID + 1) as u32;
        assert_eq!(snapshot.apic_id(), None);
    }
    fn native_snapshot() -> Snapshot {
        let mut snapshot = Snapshot {
            count: 3,
            ..Snapshot::default()
        };
        snapshot.records[0] = Cpuid {
            leaf: 1,
            ecx: u32::MAX,
            edx: u32::MAX,
            ..Cpuid::default()
        };
        snapshot.records[1] = Cpuid {
            leaf: 0x8000_0001,
            ecx: 1,
            edx: (1 << 20) | (1 << 29),
            ..Cpuid::default()
        };
        snapshot.records[2] = Cpuid {
            leaf: 7,
            ecx: 1 << 16,
            ..Cpuid::default()
        };
        snapshot.pat_valid = true;
        snapshot.pat = 0x0007_0406_0007_0406;
        snapshot.apic_base = 1 << 11;
        snapshot.msr_count = 2;
        snapshot.msrs[0] = Msr {
            index: 0xfe,
            value: 8,
        };
        snapshot.msrs[1] = Msr {
            index: 0x2ff,
            value: 0xc06,
        };
        snapshot
    }

    fn target_snapshot(vendor: [u32; 3]) -> Snapshot {
        let mut snapshot = native_snapshot();
        snapshot.records[3] = Cpuid {
            leaf: 0,
            eax: 7,
            ebx: vendor[0],
            edx: vendor[1],
            ecx: vendor[2],
            ..Cpuid::default()
        };
        snapshot.records[2].ebx = 1 << 29;
        snapshot.count = 4;
        snapshot
    }

    #[test]
    fn identity_selection_checks_observed_maxima_low16_counts_and_amd_vendor() {
        use stela_compiler::TargetCpu;
        let source = |vendor: [u32; 3]| {
            let mut snapshot = target_snapshot(vendor);
            snapshot.records[0].ebx = 7 << 24;
            snapshot.records[1].ecx |= 1 << 22;
            snapshot.records[3].eax = 0x1f;
            snapshot.records[4] = Cpuid {
                leaf: 0x1f,
                ..Cpuid::default()
            };
            snapshot.records[5] = Cpuid {
                leaf: 0xb,
                ..Cpuid::default()
            };
            snapshot.records[6] = Cpuid {
                leaf: 0x8000_0000,
                eax: 0x8000_001e,
                ..Cpuid::default()
            };
            snapshot.records[7] = Cpuid {
                leaf: 0x8000_001e,
                eax: 0x1234,
                ..Cpuid::default()
            };
            snapshot.count = 8;
            snapshot
        };
        for vendor in [TargetCpu::AMD_VENDOR, TargetCpu::INTEL_VENDOR, [0; 3]] {
            let mut snapshot = source(vendor);
            assert_eq!(
                snapshot.apic_id(),
                Some(if vendor == TargetCpu::AMD_VENDOR {
                    0x1234
                } else {
                    7
                })
            );
            snapshot.records[6].eax = 0x8000_001d;
            assert_eq!(snapshot.apic_id(), Some(7));
        }
        let mut snapshot = source(TargetCpu::INTEL_VENDOR);
        snapshot.records[4] = Cpuid {
            leaf: 0x1f,
            ebx: 1 << 16,
            ecx: 1 << 8,
            edx: 0x5678,
            ..Cpuid::default()
        };
        // Only the architectural low16 count matters; high garbage is not a
        // valid topology source and cannot replace the real legacy identity.
        assert_eq!(snapshot.apic_id(), Some(7));
        snapshot.records[5] = Cpuid {
            leaf: 0xb,
            ebx: 2,
            ecx: 1 << 8,
            edx: 0x1234,
            ..Cpuid::default()
        };
        assert_eq!(snapshot.apic_id(), Some(0x1234));
        snapshot.records[4].ebx = 2;
        assert_eq!(snapshot.apic_id(), Some(0x5678));
        snapshot.records[3].eax = 0xb;
        assert_eq!(snapshot.apic_id(), Some(0x1234));
        snapshot.records[3].eax = 1;
        assert_eq!(snapshot.apic_id(), Some(7));
        snapshot.records[3].eax = 0x1f;
        snapshot.records[4].leaf = 0x1e;
        assert_eq!(snapshot.apic_id(), None); // incomplete declared observation
        let mut amd = source(TargetCpu::AMD_VENDOR);
        amd.records[7].leaf = 0x8000_001d;
        assert_eq!(amd.apic_id(), None);
        let mut amd = source(TargetCpu::AMD_VENDOR);
        amd.records[6].leaf = 0x8000_001d;
        assert_eq!(amd.apic_id(), None); // unknown maximum cannot authorize legacy fallback
        let mut amd = source(TargetCpu::AMD_VENDOR);
        amd.records[1].leaf = 0x8000_0002;
        assert_eq!(amd.apic_id(), None); // missing topology feature observation
    }

    #[test]
    fn common_target_retains_only_features_present_on_every_assigned_worker() {
        use stela_compiler::TargetCpu;
        let rich = target_snapshot(TargetCpu::INTEL_VENDOR);
        let mut weaker = target_snapshot(TargetCpu::AMD_VENDOR);
        weaker.records[0].ecx &= !((1 << 1) | (1 << 25) | (1 << 28));
        weaker.records[2].ebx = 0;
        let expected = TargetCpu::Sse42.with_popcnt().with_cx8().with_cx16();
        assert_eq!(common_native_target(&[&rich, &weaker]), Ok(expected));
        assert_eq!(common_native_target(&[&weaker, &rich]), Ok(expected));
        // Removing a worker recomputes a future cold-registration ceiling;
        // it never changes an existing RAM domain or grants a live entry.
        let solo = common_native_target(&[&rich]).unwrap();
        assert!(solo.supports(TargetCpu::Aes));
        assert!(solo.supports(TargetCpu::Sha));
        assert!(solo.supports(TargetCpu::Pclmulqdq));
        assert!(solo.supports(TargetCpu::AtomicLoad16));
        for excluded in [
            TargetCpu::Bmi1,
            TargetCpu::Fma,
            TargetCpu::F16c,
            TargetCpu::Avx2,
            TargetCpu::Avx512f,
            TargetCpu::Doit,
            TargetCpu::LineAtomic,
        ] {
            assert!(!solo.supports(excluded));
        }
    }

    #[test]
    fn common_target_obeys_leaf_maxima_vendor_atomicity_and_complete_sse_tiers() {
        use stela_compiler::TargetCpu;
        let rich = target_snapshot(TargetCpu::INTEL_VENDOR);
        let mut unknown = target_snapshot([0; 3]);
        unknown.records[3].eax = 1;
        // The stale structured record is outside the declared maximum.
        let target = common_native_target(&[&rich, &unknown]).unwrap();
        assert!(!target.supports(TargetCpu::Sha));
        assert!(!target.supports(TargetCpu::AtomicLoad16));
        assert!(target.supports(TargetCpu::Aes));
        for (removed, expected) in [
            (20, TargetCpu::Sse41),
            (19, TargetCpu::Ssse3),
            (9, TargetCpu::Baseline),
        ] {
            let mut worker = rich;
            worker.records[0].ecx &= !(1 << removed);
            let target = common_native_target(&[&rich, &worker]).unwrap();
            assert!(target.supports(expected));
            assert!(!target.supports(TargetCpu::Sse42));
            if removed == 9 {
                assert!(!target.supports(TargetCpu::Ssse3));
            }
            if removed == 19 {
                assert!(!target.supports(TargetCpu::Sse41));
            }
        }
        let mut missing = rich;
        missing.records[2].leaf = 6;
        assert!(
            !common_native_target(&[&rich, &missing])
                .unwrap()
                .supports(TargetCpu::Sha)
        );
        missing.count = MAX_CPUID as u32 + 1;
        assert_eq!(
            common_native_target(&[&missing]),
            Err(CapabilityRefusal::InvalidSnapshot)
        );
        assert_eq!(
            common_native_target(&[]),
            Err(CapabilityRefusal::InvalidSnapshot)
        );
        missing = rich;
        missing.records[3].eax = 0;
        assert_eq!(
            common_native_target(&[&missing]),
            Err(CapabilityRefusal::InvalidSnapshot)
        );
    }

    #[test]
    fn actual_core_floor_and_la57_are_required_independently_of_bsp() {
        let baseline = native_snapshot();
        assert_eq!(baseline.qualify_native(true), Ok(()));
        for bit in [0, 9, 13, 19, 20, 23] {
            let mut changed = baseline;
            changed.records[0].ecx &= !(1 << bit);
            assert_eq!(
                changed.qualify_native(false),
                Err(CapabilityRefusal::NativeFloor)
            );
        }
        for bit in [0, 4, 5, 6, 8, 9, 12, 16, 24, 25, 26] {
            let mut changed = baseline;
            changed.records[0].edx &= !(1 << bit);
            assert_eq!(
                changed.qualify_native(false),
                Err(CapabilityRefusal::NativeFloor)
            );
        }
        let mut changed = baseline;
        changed.records[2].ecx = 0;
        assert_eq!(changed.qualify_native(false), Ok(()));
        assert_eq!(
            changed.qualify_native(true),
            Err(CapabilityRefusal::FiveLevelPaging)
        );
        changed.msr_count = (MAX_MSRS + 1) as u32;
        assert_eq!(
            changed.qualify_native(false),
            Err(CapabilityRefusal::InvalidSnapshot)
        );
    }

    #[test]
    fn mtrr_pat_equality_does_not_conflate_clock_adjustment() {
        let baseline = native_snapshot();
        let mut changed = baseline;
        assert_eq!(baseline.same_memory_types(&changed), Ok(()));
        changed.msrs[2] = Msr {
            index: 0x3b,
            value: 123,
        };
        changed.msr_count = 3;
        assert_eq!(baseline.same_memory_types(&changed), Ok(()));
        changed.msrs[1].value ^= 1;
        assert_eq!(
            baseline.same_memory_types(&changed),
            Err(CapabilityRefusal::MemoryTypes)
        );
        changed = baseline;
        changed.pat ^= 1 << 8;
        assert_eq!(
            baseline.same_memory_types(&changed),
            Err(CapabilityRefusal::MemoryTypes)
        );
        changed = baseline;
        changed.msr_count = 1;
        assert_eq!(
            baseline.same_memory_types(&changed),
            Err(CapabilityRefusal::MemoryTypes)
        );
    }

    #[test]
    fn duplicate_physical_thread_refuses() {
        let mut cores = [processor(0, 0, 0, 0), processor(1, 0, 0, 0)];
        cores[0].flags |= BSP;
        assert_eq!(select(&cores), Err(Refusal::DuplicateThreadLocation));
    }
}
