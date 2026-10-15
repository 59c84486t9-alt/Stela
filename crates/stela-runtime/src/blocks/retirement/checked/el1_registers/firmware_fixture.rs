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
const SOURCE_PC: GuestAddress = GuestAddress(0x0010_0000);
const TARGET_PC: GuestAddress = GuestAddress(0x0010_0010);
const ADDRESS_SPACE: u64 = 72;
const DECLARATION: &[u8] = b"fresh-stela-el1-integer-diagnostic-v1;pa40;asid8;4k16k;little;pauth-pan-ssbs-exs-brbe-bti-spe-trbe-nmi-mte-absent;M0;sctlr0x00c50838;tcr0;ttbr0=0;ttbr1=0;mair0;PSTATE0x3c5;all784zero;original-source-whole-image-pa100000;singlePE;closed-producer-universe";
fn state_bytes(state: &GuestState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size_of::<GuestState>());
    for value in state.x {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(state.sp.to_le_bytes());
    bytes.extend(state.nzcv.to_le_bytes());
    bytes.extend(state.reserved.to_le_bytes());
    for vector in state.v {
        for limb in vector {
            bytes.extend(limb.to_le_bytes());
        }
    }
    bytes.extend(state.fpcr.to_le_bytes());
    bytes.extend(state.fpsr.to_le_bytes());
    assert_eq!(bytes.len(), 784);
    bytes
}
fn profile() -> ControlProfile {
    let raw: [u8; 32] = [
        6, 44, 29, 49, 239, 20, 175, 31, 108, 226, 138, 46, 34, 164, 98, 98, 12, 144, 135, 221,
        193, 226, 211, 152, 189, 44, 46, 192, 213, 170, 173, 209,
    ];
    let evidence = EvidenceBinding {
        id: "fresh-stela-el1-integer-diagnostic-v1",
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
#[ignore = "actual translated firmware prefix under retained PE; requires reviewed frozen graph and fresh absolute output"]
fn actual_original_firmware_integer_prefix_full_state_and_pc() {
    let root = std::path::PathBuf::from(
        std::env::var_os("STELA_INTEGER_NATIVE_OUTPUT").expect("fresh output directory required"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("software-declaration.txt"), DECLARATION).unwrap();
    std::fs::write(
        root.join("compiler-source-sha256.txt"),
        stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
    )
    .unwrap();
    let firmware = std::fs::read(
        std::env::var_os("STELA_INTEGER_FIRMWARE").expect("original firmware required"),
    )
    .unwrap();
    assert_eq!(
        stela_core::sha256(&firmware),
        "0286483ecafa487adbe4e19447e2426f8f5438a73b38a6dfe8f2f8f3addd8840"
    );
    let firmware_before = firmware.clone();
    let readable = std::env::var_os("STELA_INTEGER_EXECUTE_ONLY").is_none();
    std::fs::write(root.join("ram-readable.txt"), readable.to_string()).unwrap();
    let materialized = materialize_source_ram(
        SourceRamDeclaration {
            address_space: ADDRESS_SPACE,
            target: TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: 0,
                bytes: 0x4000_0000,
            }],
            initialized: vec![OwnedRamExtent {
                source_pa: SOURCE_PC.0,
                bytes: firmware,
                permissions: SourceRamPermissions {
                    readable,
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
    let system_before = format!("{system:#?}");
    std::fs::write(root.join("system-before.txt"), &system_before).unwrap();
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
    let runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE,
        root.join("cache"),
        BlockProfile::El1M0IntegerV1,
        TargetCpu::Baseline,
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
            let scope = sources.el1_scope();
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
                M0Owner::fresh_el1_integer(
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
            std::fs::write(root.join("before.bin"), state_bytes(&thread.registers)).unwrap();
            // SAFETY: this is the ONE canonical PE construction over actual original
            // ThreadState/System/backend. No copy/second PE/reset or raw entry exists.
            let mut owner =
                unsafe { SystemExecutionOwner::new_pe(&mut thread, &mut system, &mut backend) };
            let identity = owner.identity();
            let result = runtime.run_owned(
                owner.loan(),
                OwnedRunRequest {
                    stop_pc: Some(TARGET_PC),
                    block_budget: 5,
                },
            );
            std::fs::write(root.join("actual-outcome.txt"), format!("{result:#?}")).unwrap();
            assert!(identity.same_pe(&owner.identity()));
            if !readable {
                assert!(
                    matches!(result.stop, OwnedStop::Indeterminate(_)),
                    "{result:#?}"
                );
                assert_eq!(owner.pc(), GuestAddress(SOURCE_PC.0 + 8));
                assert_eq!(result.accounting.blocks_executed, 2);
                let mut expected = GuestState::default();
                expected.x[0] = SOURCE_PC.0;
                assert_eq!(owner.registers(), &expected);
                std::fs::write(root.join("native.bin"), state_bytes(owner.registers())).unwrap();
                assert!(
                    matches!(
                        result.last_m0_observation,
                        Some(super::super::m0::M0Observation::PreparationFailure { .. })
                    ),
                    "{result:#?}"
                );
                let retry = runtime.run_owned(
                    owner.loan(),
                    OwnedRunRequest {
                        stop_pc: None,
                        block_budget: 1,
                    },
                );
                assert!(
                    matches!(retry.stop, OwnedStop::EntryDeclined(_)),
                    "{retry:#?}"
                );
                assert_eq!(retry.accounting.blocks_executed, 0);
                assert_eq!(owner.pc(), GuestAddress(SOURCE_PC.0 + 8));
                assert_eq!(owner.registers(), &expected);
                std::fs::write(root.join("blocked-retry.txt"), format!("{retry:#?}")).unwrap();
                assert_eq!(controls.snapshot().unwrap().readbacks(), readbacks);
                drop(owner);
                let system_after = format!("{system:#?}");
                assert_eq!(system_before, system_after);
                std::fs::write(root.join("system-after.txt"), system_after).unwrap();
                let backing = scope.immutable_sources()[0].backing();
                let pointer = backing
                    .host_pointer(
                        0,
                        firmware_before.len(),
                        crate::memory::backing::AccessKind::Execute,
                    )
                    .unwrap();
                // SAFETY: original immutable executable allocation remains owned
                // and unchanged for this complete diagnostic readback.
                let ram =
                    unsafe { std::slice::from_raw_parts(pointer.as_ptr(), firmware_before.len()) };
                assert_eq!(ram, firmware_before);
                std::fs::write(root.join("ram-after.bin"), ram).unwrap();
                return;
            }
            assert!(matches!(result.stop, OwnedStop::StopAddress), "{result:#?}");
            assert_eq!(owner.pc(), TARGET_PC);
            let mut expected = GuestState::default();
            expected.x[0] = SOURCE_PC.0;
            expected.x[1] = SOURCE_PC.0;
            expected.x[30] = TARGET_PC.0;
            assert_eq!(owner.registers(), &expected);
            std::fs::write(root.join("native.bin"), state_bytes(owner.registers())).unwrap();
            let refused = runtime.run_owned(
                owner.loan(),
                OwnedRunRequest {
                    stop_pc: None,
                    block_budget: 1,
                },
            );
            assert!(
                matches!(refused.stop, OwnedStop::EntryDeclined(_)),
                "{refused:#?}"
            );
            assert_eq!(refused.accounting.blocks_executed, 0);
            assert_eq!(owner.pc(), TARGET_PC);
            assert_eq!(owner.registers(), &expected);
            assert!(
                refused.last_el1_register_observation.is_none()
                    && refused.last_m0_observation.is_none()
            );
            std::fs::write(root.join("daif-refusal.txt"), format!("{refused:#?}")).unwrap();
            let backing = scope.immutable_sources()[0].backing();
            let pointer = backing
                .host_pointer(
                    0,
                    firmware_before.len(),
                    crate::memory::backing::AccessKind::Read,
                )
                .unwrap();
            // SAFETY: actual retained immutable source allocation owns the whole
            // image, readable bytes and no writer/alias for this executable scope.
            let ram =
                unsafe { std::slice::from_raw_parts(pointer.as_ptr(), firmware_before.len()) };
            assert_eq!(ram, firmware_before);
            std::fs::write(root.join("ram-after.bin"), ram).unwrap();
            std::fs::write(
                root.join("actual-registers.txt"),
                format!("{:?}", owner.registers()),
            )
            .unwrap();
            assert_eq!(firmware_before.len(), 335096);
            assert_eq!(result.accounting.blocks_executed, 5);
            let observed = result.last_el1_register_observation.as_ref().unwrap();
            assert!(observed.report.invoked);
            assert_eq!(
                observed.report.raw_carrier,
                Some((TARGET_PC.0, stela_compiler::block::ExitKind::Return as u64))
            );
            assert!(matches!(observed.report.storage_after, Some(Ok(()))));
            assert!(observed.report.failure.is_none() && observed.settlement_failure.is_none());
            assert_eq!(controls.snapshot().unwrap().readbacks(), readbacks);
            assert!(result.last_m0_observation.is_some());
            drop(owner);
            let system_after = format!("{system:#?}");
            assert_eq!(system_before, system_after);
            std::fs::write(root.join("system-after.txt"), system_after).unwrap();
        })
        .unwrap();
}
