//! Installing EL1 source and controls for register and literal blocks.
use super::{BlockRuntime, InstalledCodeSources, InstalledEl1Sources};
use crate::{
    memory::domain::physical::{ImmutableCodeBacking, PhysicalAddressSpace},
    system::{
        profile::EntryProfile,
        state::SystemState,
        translation_controls::{ControlProfile, RegisterValues, TranslationControls},
    },
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::{Result, ensure};
use stela_compiler::{GuestAddress, block::BlockProfile};
pub(in crate::blocks) struct InstalledEl1Owner {
    runtime: BlockRuntime,
    sources: InstalledEl1Sources,
    controls: TranslationControls,
}
impl InstalledEl1Owner {
    /// A host RAM service over this owner's physical memory, created before
    /// the executable scope is consumed. It creates no new domain, thread or
    /// source registry.
    pub(in crate::blocks) fn source_ram_publisher(
        &mut self,
        source_pa: u64,
        bytes: usize,
    ) -> Result<crate::memory::source_ram::SourceRamPublisher> {
        self.sources
            .physical
            .source_ram_publisher(source_pa, bytes)
            .map_err(|status| anyhow::anyhow!("source RAM publisher: {status:?}"))
    }

    /// # Safety
    /// As for `InstalledM0Owner::new`: every resource belongs to one declared
    /// CPU, and this owner alone publishes, retires and holds the storage for
    /// every alias while the machine runs. The PE, thread, system state,
    /// producers and native finalization checks remain mandatory after
    /// creation.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks) unsafe fn new(
        mut runtime: BlockRuntime,
        physical: PhysicalAddressSpace,
        immutable_sources: Vec<ImmutableCodeBacking>,
        entry_profile: EntryProfile,
        readbacks: RegisterValues,
        control_profile: ControlProfile,
        system: &SystemState,
        source_pc: GuestAddress,
    ) -> Result<Self> {
        ensure!(
            matches!(
                runtime.profile(),
                BlockProfile::El1DirectBranchV1
                    | BlockProfile::El1M0IntegerV1
                    | BlockProfile::El1PlatformV1
            ),
            "fresh EL1 source owner requires typed EL1 direct-B compiler profile"
        );
        ensure!(
            runtime.regions.is_empty() && runtime.loaded.is_empty(),
            "fresh EL1 source owner requires an unbound runtime"
        );
        // SAFETY: this owner hands its source, physical and publication
        // resources to initial publication as described above.
        let (sources, controls) = unsafe {
            InstalledCodeSources::install(
                &mut runtime,
                physical,
                immutable_sources,
                entry_profile,
                readbacks,
                control_profile,
                system,
            )
        }?;
        let mut owner = Self {
            runtime,
            sources,
            controls,
        };
        let scope = owner.sources.el1_scope().map_err(anyhow::Error::msg)?;
        scope
            .check_installed(&owner.controls, system)
            .map_err(anyhow::Error::msg)?;
        let execution = scope
            .physical_space()
            .initial_source_execution_loan()
            .map_err(|error| anyhow::anyhow!("EL1 initial source execution loan: {error:?}"))?;
        let reached = scope
            .physical_space()
            .fetch_el1_instruction(&execution, &owner.controls, &scope, system, source_pc.0)
            .map_err(|error| anyhow::anyhow!("EL1 initial source fetch: {error:?}"))?;
        owner
            .runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        drop(execution);
        Ok(owner)
    }
    pub(in crate::blocks) fn reload_ram_file_prefixes(
        &mut self,
        system: &SystemState,
        pc: GuestAddress,
    ) -> Result<()> {
        self.sources.reload_region_prefixes(&mut self.runtime)?;
        let scope = self.sources.el1_scope().map_err(anyhow::Error::msg)?;
        let execution = scope.physical_space().initial_source_execution_loan()?;
        let reached = scope
            .physical_space()
            .fetch_el1_instruction(&execution, &self.controls, &scope, system, pc.0)
            .map_err(|error| anyhow::anyhow!("RAM reload original source fetch: {error:?}"))?;
        self.runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        Ok(())
    }
    /// Consume this owner once for the machine's whole run. The callback
    /// captures the system state so the execution owner can hold it mutably
    /// throughout.
    pub(in crate::blocks) fn into_executable_scope<R>(
        mut self,
        _key: &crate::blocks::retirement::ConsumerKey,
        operation: impl for<'run> FnOnce(
            &'run mut BlockRuntime,
            &'run mut InstalledEl1Sources,
            &'run mut TranslationControls,
        ) -> R,
    ) -> Result<R> {
        let scope = self.sources.el1_scope().map_err(anyhow::Error::msg)?;
        self.controls
            .validate_installed_el1_source(&scope)
            .map_err(anyhow::Error::msg)?;
        scope
            .physical_space()
            .check_fetch_execution()
            .map_err(anyhow::Error::msg)?;
        Ok(operation(
            &mut self.runtime,
            &mut self.sources,
            &mut self.controls,
        ))
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    //! EL1 source installation and source-RAM fetches.
    use super::super::InstalledCodeSources;
    use crate::{
        blocks::BlockRuntime,
        memory::{
            domain::physical::PhysicalAddressSpace,
            source_ram::{
                OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
                SourceRamSystemConfig, materialize_source_ram,
            },
            stage1,
        },
        system::{
            profile::{EntryProfile, ScalableEntryAbsence, SystemEntryFeatures},
            state::{El1Registers, SystemState},
            translation_controls::{
                AsidBits, BaseEl1FeatureFacts, ControlProfile, Endianness, EvidenceBinding,
                FetchFailure, PanFeatures, PolicyProvenance, Presence, RegisterValues,
                TranslationControls,
            },
        },
    };
    use stela_compiler::{TargetCpu, block::BlockProfile};
    const VA: u64 = 0x100;
    const CODE_PA: u64 = 0x20000;
    const TABLE_STRIDE: u64 = 0x4000;
    const SOURCE_WORD: u32 = 0x1400_0000;
    const AF: u64 = 1 << 10;
    const PXN: u64 = 1 << 53;
    const DECLARATION: &[u8] = b"fresh-stela-walked-fetch-fixture-v1;singlePE;NS-EL1;pa40;asid8;4K48VA-or16K47VA;little;optionalentryeffects-absent;M1-C1-I1;explicit-owned-tables-and-immutable-branch;no-native-or-admission";
    const DECLARATION_SHA: [u8; 32] = [
        158, 184, 22, 177, 152, 155, 195, 77, 95, 226, 33, 73, 90, 254, 71, 32, 74, 41, 67, 228,
        176, 19, 62, 188, 69, 168, 20, 148, 105, 77, 138, 92,
    ];
    fn control_profile() -> ControlProfile {
        let hex = DECLARATION_SHA
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(crate::sha256(DECLARATION), hex);
        let evidence = EvidenceBinding {
            id: "fresh-stela-walked-fetch-fixture-v1",
            sha256: DECLARATION_SHA,
        };
        ControlProfile::base_el1(
            BaseEl1FeatureFacts {
                pauth: Presence::Absent,
                pan: PanFeatures::Absent,
                ssbs: Presence::Absent,
                exs: Presence::Absent,
                asid_bits: AsidBits::Eight,
                endianness: Endianness::LittleOnly,
            },
            PolicyProvenance {
                cpu_features: evidence,
                implementation_choices: evidence,
            },
            stage1::CpuProfile {
                pa_max: stage1::PaBits::Bits40,
                asid_bits: stage1::AsidBits::Bits8,
                granules: stage1::GranuleSupport {
                    kib4: true,
                    kib16: true,
                    kib64: false,
                    lower_fallback: stage1::Granule::KiB4,
                    upper_fallback: stage1::Granule::KiB4,
                },
                pauth: false,
                pan: false,
                pan3: false,
            },
        )
        .unwrap()
    }
    fn extent(pa: u64, bytes: Vec<u8>, executable: bool) -> OwnedRamExtent {
        OwnedRamExtent {
            source_pa: pa,
            bytes,
            permissions: SourceRamPermissions {
                readable: true,
                writable: !executable,
                executable,
            },
        }
    }
    fn installed(
        kib16: bool,
        leaf_flags: u64,
        hole: bool,
    ) -> (
        InstalledCodeSources,
        TranslationControls,
        SystemState,
        BlockRuntime,
    ) {
        let count = if kib16 { 3 } else { 4 };
        let mut extents = Vec::new();
        for index in 0..count {
            let value = if index + 1 == count {
                CODE_PA | 3 | leaf_flags
            } else {
                ((index + 2) * TABLE_STRIDE) | 3
            };
            if !(hole && index + 1 == count) {
                extents.push(extent(
                    (index + 1) * TABLE_STRIDE,
                    value.to_le_bytes().to_vec(),
                    false,
                ));
            }
        }
        let mut code = vec![0; VA as usize];
        code.extend_from_slice(&SOURCE_WORD.to_le_bytes());
        extents.push(extent(CODE_PA, code, true));
        let materialized = materialize_source_ram(
            SourceRamDeclaration {
                address_space: 713,
                target: TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: TABLE_STRIDE,
                    bytes: 0x30000,
                }],
                initialized: extents,
            },
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            },
        )
        .unwrap();
        let (binding, immutable) = materialized.into_parts();
        let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
        let state = SystemState::new(0x3c5, 0, El1Registers::new(VA, 0x3c5, 0, 0, 0)).unwrap();
        let entry = EntryProfile::base(
            SystemEntryFeatures::declared_absent(),
            ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
        )
        .unwrap();
        let mut runtime = BlockRuntime::new_for_target(
            713,
            std::env::temp_dir().join("stela-walked-fetch-fixture-no-native"),
            BlockProfile::El1DirectBranchV1,
            TargetCpu::Baseline,
        );
        let tcr = if kib16 {
            17 | (2 << 14) | (17 << 16)
        } else {
            16 | (16 << 16)
        };
        let values = RegisterValues {
            sctlr_el1: 0x00c5_0838 | 1 | (1 << 2) | (1 << 12),
            tcr_el1: tcr | (1 << 8) | (1 << 10) | (2 << 12) | (1 << 23) | (2 << 32),
            ttbr0_el1: TABLE_STRIDE,
            ttbr1_el1: 0,
            mair_el1: 0xff,
        };
        // SAFETY: the test owns these table and code allocations, the physical
        // domain and every alias; no PE, native code or external producer exists.
        let (sources, controls) = unsafe {
            InstalledCodeSources::install(
                &mut runtime,
                physical,
                immutable,
                entry,
                values,
                control_profile(),
                &state,
            )
        }
        .unwrap();
        (sources, controls, state, runtime)
    }
    #[test]
    fn real_4k_and_16k_tables_fetch_distinct_va_pa_under_original_outer() {
        for kib16 in [false, true] {
            let (sources, controls, state, mut runtime) = installed(kib16, AF, false);
            let scope = sources.el1_scope().unwrap();
            // M0 admission is refused.
            assert!(scope.check_installed(&controls, &state).is_err());
            let outer = scope
                .physical_space()
                .initial_source_execution_loan()
                .unwrap();
            let walked = scope.walked(&controls, &state, &outer).unwrap();
            for _ in 0..2 {
                let bound = walked
                    .physical_space()
                    .fetch_walked_instruction(&walked, VA)
                    .unwrap();
                assert_eq!(bound.raw_pc(), VA);
                assert_eq!(bound.physical_address(), CODE_PA + VA);
                assert_eq!(bound.word(), SOURCE_WORD);
                assert!(bound.is_current());
                // Reuse the runtime's source and code cache.
                runtime
                    .bind_physical_instruction(scope.installed_snapshot(), bound)
                    .unwrap();
            }
        }
    }
    #[test]
    fn actual_faults_keep_original_virtual_pc_level_and_descriptor_pa() {
        for (flags, expected) in [
            (0, stage1::FaultKind::AccessFlag),
            (AF | PXN, stage1::FaultKind::Permission),
        ] {
            let (sources, controls, state, _) = installed(false, flags, false);
            let scope = sources.el1_scope().unwrap();
            let outer = scope
                .physical_space()
                .initial_source_execution_loan()
                .unwrap();
            let walked = scope.walked(&controls, &state, &outer).unwrap();
            let Err(FetchFailure::Architectural(fault)) = walked.canonical_fetch(VA) else {
                panic!("canonical fault required")
            };
            assert_eq!(fault.kind, expected);
            assert_eq!(fault.level, 3);
            assert_eq!(fault.access.raw_virtual_address, VA);
            assert_eq!(fault.access.source_pc, VA);
            assert_eq!(fault.access.kind, stage1::AccessKind::Fetch);
            assert_eq!(fault.descriptor_address, Some(4 * TABLE_STRIDE));
        }
    }
    #[test]
    fn actual_descriptor_hole_stays_platform_and_alignment_stays_architectural() {
        let (sources, controls, state, _) = installed(false, AF, true);
        let scope = sources.el1_scope().unwrap();
        let outer = scope
            .physical_space()
            .initial_source_execution_loan()
            .unwrap();
        let walked = scope.walked(&controls, &state, &outer).unwrap();
        assert!(matches!(
            walked.canonical_fetch(VA),
            Err(FetchFailure::Platform(_))
        ));
        assert!(
            matches!(walked.canonical_fetch(VA + 1), Err(FetchFailure::InstructionAlignment { raw_pc, .. }) if raw_pc == VA + 1)
        );
    }
    #[test]
    fn same_numeric_machine_names_do_not_accept_foreign_controls_or_outer() {
        let (first, controls, state, _) = installed(false, AF, false);
        let (second, other_controls, _, _) = installed(false, AF, false);
        let scope = first.el1_scope().unwrap();
        let outer = scope
            .physical_space()
            .initial_source_execution_loan()
            .unwrap();
        let foreign = second
            .physical_space()
            .initial_source_execution_loan()
            .unwrap();
        assert!(scope.walked(&other_controls, &state, &outer).is_err());
        assert!(scope.walked(&controls, &state, &foreign).is_err());
        assert!(scope.walked(&controls, &state, &outer).is_ok());
    }
}
