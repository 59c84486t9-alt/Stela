//! Copied firmware processor identity and per-processor CPUID observations.
//! One selected logical processor owns each physical core; SMT siblings never
//! increase the number of guest PEs admitted by this native executor.
extern crate alloc;

use alloc::vec::Vec;

pub const MAX_PROCESSORS: usize = 256;
pub const MAX_CORES: usize = 64;

/// Default ownership covers every discovered physical core. An explicit count
/// is the only narrowing policy; unavailable cores are never fabricated.
pub(crate) fn assignment_count(
    requested: Option<usize>,
    available: usize,
) -> Result<usize, &'static str> {
    let count = requested.unwrap_or(available);
    if available == 0 || available > MAX_CORES || count == 0 || count > available {
        return Err("native assignment is outside the actual physical-core roster");
    }
    Ok(count)
}
pub const MAX_CPUID: usize = 48;
pub const MAX_MSRS: usize = 64;

pub const BSP: u32 = 1;
pub const ENABLED: u32 = 1 << 1;
pub const HEALTHY: u32 = 1 << 2;

/// The coordinates are the original UEFI MP Services Location/Location2
/// fields. Legacy coordinates flatten the core identity within a package.
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
        for leaf in [0x1f, 0xb] {
            if let Some(record) = self.get(leaf, 0)
                && record.ebx != 0
                && (record.ecx >> 8) & 0xff != 0
            {
                return Some(record.edx);
            }
        }
        if let Some(record) = self.get(0x8000_001e, 0)
            && self
                .get(0x8000_0001, 0)
                .is_some_and(|extended| extended.ecx & (1 << 22) != 0)
        {
            return Some(record.eax);
        }
        self.get(1, 0).map(|record| record.ebx >> 24)
    }

    pub fn matches(&self, processor: Processor) -> bool {
        self.apic_id()
            .is_some_and(|id| u64::from(id) == processor.apic_id)
    }
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
    Capacity,
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
    if processors.len() > MAX_PROCESSORS {
        return Err(Refusal::Capacity);
    }
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

/// Return original processor indices, BSP first, without renumbering their
/// firmware identity. No AP is started and no capability is inferred here.
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
        if selected.len() == MAX_CORES {
            return Err(Refusal::Capacity);
        }
        selected.push(index);
    }
    Ok(selected)
}

/// Enabled logical processors outside the actual requested physical roster.
/// Unlike admission, this includes enabled unhealthy APs: health does not prove
/// that their firmware execution has stopped. Disabled processors stay disabled.
/// No allocation or firmware access is needed at the post-EBS boundary.
pub(crate) fn enabled_unselected<'a>(
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
        assert!(assignment_count(None, MAX_CORES + 1).is_err());
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
        snapshot.count = 2;
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
        snapshot.count = 3;
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
    fn duplicate_physical_thread_and_excess_core_capacity_refuse() {
        let mut cores = [processor(0, 0, 0, 0), processor(1, 0, 0, 0)];
        cores[0].flags |= BSP;
        assert_eq!(select(&cores), Err(Refusal::DuplicateThreadLocation));
        let mut cores: Vec<_> = (0..=MAX_CORES)
            .map(|core| processor(core as u32, 0, core as u32, 0))
            .collect();
        cores[0].flags |= BSP;
        assert_eq!(select(&cores), Err(Refusal::Capacity));
    }
}
