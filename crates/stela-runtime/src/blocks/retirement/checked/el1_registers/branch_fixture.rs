//! Actual fresh-machine diagnostic caller; never an installer/firmware substitute.
//! All inputs describe this NEW software machine. No original firmware control
//! state, historical native body, live Mach thread or copied PE is adopted.
use super::super::{
    ConsumerKey, OwnedRunRequest, OwnedStop, ProcessEntryControls, provider::M0Owner,
};
use crate::{
    blocks::{BlockRuntime, InstalledEl1Owner, ThreadState},
    memory::{
        domain::physical::PhysicalAddressSpace,
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
        source_ram::{
            OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
            SourceRamSystemConfig, materialize_source_ram,
        },
        stage1,
    },
    system::{
        debug::DebugControls,
        events::EventDomain,
        execution::owner::SystemExecutionOwner,
        profile::{BaseSpeAbsence, EntryProfile, ScalableEntryAbsence, SystemEntryFeatures},
        state::{El1Registers, SystemState},
        translation_controls::{
            AsidBits, BaseEl1FeatureFacts, ControlProfile, Endianness, EvidenceBinding,
            PanFeatures, PolicyProvenance, Presence, RegisterValues,
        },
    },
};
use stela_compiler::{
    GuestAddress, GuestState, TargetCpu, block::BlockProfile, context::ExecutionContext,
};
const SOURCE_PC: GuestAddress = GuestAddress(0x82eb_0480);
const TARGET_PC: GuestAddress = GuestAddress(0x82eb_4070);
const SOURCE_WORD: u32 = 0x1400_0efc;
const ADDRESS_SPACE: u64 = 72;
const DECLARATION: &[u8] = b"fresh-stela-el1-b-diagnostic-v1;pa40;asid8;4k16k;little;pauth-pan-ssbs-exs-brbe-bti-spe-trbe-nmi-mte-absent;M0;sctlr0x00c50838;tcr0;ttbr0=0;ttbr1=0;mair0;PSTATE0x3c5;all784zero;sourcePA82eb0480=B14000efc;no-data;singlePE;closed-producer-universe";
fn profile() -> ControlProfile {
    assert_eq!(
        stela_core::sha256(DECLARATION),
        "683ff5eea656ae84584bb2aefc8088dee2271242ac4055ba237da152f572653d"
    );
    let raw: [u8; 32] = [
        104, 63, 245, 238, 166, 86, 174, 132, 88, 75, 178, 174, 252, 128, 136, 222, 226, 39, 18,
        66, 172, 64, 85, 186, 35, 125, 161, 82, 245, 114, 101, 61,
    ];
    let evidence = EvidenceBinding {
        id: "fresh-stela-el1-b-diagnostic-v1",
        sha256: raw,
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
#[test]
#[ignore = "actual translated branch under retained PE; requires reviewed frozen graph and fresh absolute output"]
fn actual_one_b_original_owner_full_state_and_pc() {
    let root = std::path::PathBuf::from(
        std::env::var_os("STELA_BRANCH_NATIVE_OUTPUT").expect("fresh output directory required"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("software-declaration.txt"), DECLARATION).unwrap();
    std::fs::write(
        root.join("compiler-source-sha256.txt"),
        stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
    )
    .unwrap();
    let materialized = materialize_source_ram(
        SourceRamDeclaration {
            address_space: ADDRESS_SPACE,
            target: TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: 0x8000_0000,
                bytes: 0x2000_0000,
            }],
            initialized: vec![OwnedRamExtent {
                source_pa: SOURCE_PC.0,
                bytes: SOURCE_WORD.to_le_bytes().to_vec(),
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: false,
                    executable: true,
                },
            }],
        },
        SourceRamSystemConfig {
            reservation_granule_bytes: 16,
            reservation_stripe_count: 8,
        },
    )
    .unwrap();
    let (binding, code) = materialized.into_parts();
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    let mut system =
        SystemState::new(0x3c5, 0, El1Registers::new(SOURCE_PC.0, 0x3c5, 0, 0, 0)).unwrap();
    let entry = EntryProfile::base(
        SystemEntryFeatures::declared_absent(),
        ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
    )
    .unwrap();
    let readbacks = RegisterValues {
        sctlr_el1: 0x00c5_0838,
        tcr_el1: 0,
        ttbr0_el1: 0,
        ttbr1_el1: 0,
        mair_el1: 0,
    };
    let runtime = BlockRuntime::new_with_profile(
        ADDRESS_SPACE,
        root.join("cache"),
        BlockProfile::El1DirectBranchV1,
    );
    // SAFETY: the real fresh physical factory owns these initialized immutable
    // bytes and sole physical-role domain; this synchronous NEW software machine
    // transfers all publication/retirement rights once. No other producer/PE/
    // alias/DMA/firmware or debugger can access these actual owned allocations.
    let installed = unsafe {
        InstalledEl1Owner::new(
            runtime,
            physical,
            code,
            entry,
            readbacks,
            profile(),
            &system,
            SOURCE_PC,
        )
    }
    .unwrap();
    installed
        .into_executable_scope(&ConsumerKey(()), |runtime, sources, controls| {
            let scope = sources.el1_scope().unwrap();
            let policy = MemoryControls::new(
                LowerAddressProfile::new(48, false).unwrap(),
                true,
                false,
                true,
                TagCheckFaultMode::Synchronous,
                true,
            );
            let mut memory = scope.physical_space().domain().thread(policy);
            let events = EventDomain::new();
            let endpoint = events.register(false, None).unwrap();
            memory.bind_events(&endpoint.producer()).unwrap();
            let mut context = ExecutionContext::default();
            // SAFETY: this is the complete producer universe of this NEW declared
            // single PE. Every creation/delivery path is owned by this retained registry.
            let mut asynchronous = unsafe {
                crate::blocks::retirement::software_async::SoftwareAsyncDomain::fresh_software_pe()
            };
            let pending = asynchronous.lease_no_sources().unwrap();
            // SAFETY: actual declared debug/optional-feature owner for this same
            // freshly constructed machine; no existing hardware state is inferred.
            let execution = unsafe {
                ProcessEntryControls::fresh_software(
                    entry,
                    BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                    0,
                    DebugControls::default(),
                )
            }
            .unwrap();
            let mut thread = ThreadState {
                registers: GuestState::default(),
                pc: SOURCE_PC,
            };
            // SAFETY: original disjoint fields of the consumed installed B machine,
            // retained for its ONE SystemExecutionOwner lifetime; no per-run adoption.
            let mut backend = unsafe {
                M0Owner::fresh_el1_branch(
                    ADDRESS_SPACE,
                    sources,
                    controls,
                    &execution,
                    &mut memory,
                    &endpoint,
                    &mut context,
                    pending,
                )
            }
            .unwrap();
            // SAFETY: this is the ONE canonical PE construction over actual original
            // ThreadState/System/backend. No copy/second PE/reset or raw entry exists.
            let mut owner =
                unsafe { SystemExecutionOwner::new_pe(&mut thread, &mut system, &mut backend) };
            let identity = owner.identity();
            let result = runtime.run_owned(
                owner.loan(),
                OwnedRunRequest {
                    #[cfg(all(
                        test,
                        target_arch = "x86_64",
                        any(target_os = "macos", target_os = "linux")
                    ))]
                    pair_read_fixture: None,
                    #[cfg(all(
                        test,
                        target_arch = "x86_64",
                        any(target_os = "macos", target_os = "linux")
                    ))]
                    verify_pair_alias_monitor: false,
                    stop_pc: Some(TARGET_PC),
                    block_budget: 1,
                },
            );
            std::fs::write(root.join("actual-outcome.txt"), format!("{result:#?}")).unwrap();
            assert!(identity.same_pe(&owner.identity()));
            assert!(matches!(result.stop, OwnedStop::StopAddress), "{result:#?}");
            assert_eq!(owner.pc(), TARGET_PC);
            assert_eq!(owner.registers(), &GuestState::default());
            assert_eq!(result.accounting.blocks_executed, 1);
            let observed = result.last_el1_register_observation.as_ref().unwrap();
            assert!(observed.report.invoked);
            assert_eq!(
                observed.report.raw_carrier,
                Some((TARGET_PC.0, stela_compiler::block::ExitKind::Direct as u64))
            );
            assert!(matches!(observed.report.storage_after, Some(Ok(()))));
            assert!(observed.report.failure.is_none() && observed.settlement_failure.is_none());
            assert_eq!(controls.snapshot().unwrap().readbacks(), readbacks);
            assert!(result.last_m0_observation.is_none());
        })
        .unwrap();
}
