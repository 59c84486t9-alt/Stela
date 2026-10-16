//! Authored synthetic load under one canonical retained software PE.
//! Full native CPU/RAM/control comparison against an explicit model; no original or boot claim.
use super::super::{OwnedRunRequest, OwnedStop, ProcessEntryControls, provider::M0Owner};
use super::*;
use crate::{
    blocks::{BlockRuntime, InstalledM0Owner, ThreadState},
    memory::{
        domain::physical::PhysicalAddressSpace,
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
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
    block::{BlockProfile, CheckedMemoryProfile},
    context::ExecutionContext,
};
#[path = "fixture/inputs.rs"]
mod inputs;

const ADDRESS_SPACE: u64 = 71;
// This binding identifies newly authored synthetic inputs, not hardware authority.
const SOFTWARE_DECLARATION: &[u8] = br#"{"controls":"SCTLR/TCR/TTBR0/TTBR1/MAIR0, explicit own SP_EL0=2e0000/SP_EL1=2f0000,EL1h/DAIFmasked,VBAR0","cpu":"A64 EL1-only diagnostic subset; declared absent optional entry features,debug,SPE and closed asynchronous producers","id":"synthetic-software-m0-read8-v1","kind":"authored-synthetic-software-machine-declaration","layout":"Source100000/4B immutableRX guest rights, data200000/32B RO/NX guest rights; host source/dataNX; capacity0..400000 with holes unassigned","origin":"New source-code-generated instruction,32-byte RAM and complete GuestState; no captured original values/bytes or original execution claim","verification":"Synthetic independent expected load value/full784CPU/memory/control comparison; no original oracle verification"}"#;
const SOFTWARE_DECLARATION_SHA: &str =
    "985702de82cc4baead73e2382c9f9a355e780d8495e38c198a2d2a94a8adefe0";
const DECLARATION: EvidenceBinding = EvidenceBinding {
    id: "synthetic-software-m0-read8-v1",
    sha256: [
        0x98, 0x57, 0x02, 0xde, 0x82, 0xcc, 0x4b, 0xae, 0xad, 0x73, 0xe2, 0x38, 0x2c, 0x9f, 0x9a,
        0x35, 0x5e, 0x78, 0x0d, 0x84, 0x95, 0xe3, 0x8c, 0x19, 0x8a, 0x2d, 0x2a, 0x94, 0xa8, 0xad,
        0xef, 0xe0,
    ],
};

fn profile() -> ControlProfile {
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
            cpu_features: DECLARATION,
            implementation_choices: DECLARATION,
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
fn snapshot(
    memory: &crate::memory::domain::MemoryThread<MemoryControls>,
    address: u64,
    bytes: usize,
) -> Vec<u8> {
    memory
        .observation_loan()
        .unwrap()
        .snapshot(address, bytes)
        .unwrap()
}
fn state_bytes(state: &GuestState) -> Vec<u8> {
    let mut bytes = vec![0_u8; size_of::<GuestState>()];
    let mut put =
        |offset: usize, value: &[u8]| bytes[offset..offset + value.len()].copy_from_slice(value);
    for (i, v) in state.x.iter().enumerate() {
        put(
            std::mem::offset_of!(GuestState, x) + i * 8,
            &v.to_le_bytes(),
        );
    }
    put(
        std::mem::offset_of!(GuestState, sp),
        &state.sp.to_le_bytes(),
    );
    put(
        std::mem::offset_of!(GuestState, nzcv),
        &state.nzcv.to_le_bytes(),
    );
    put(
        std::mem::offset_of!(GuestState, reserved),
        &state.reserved.to_le_bytes(),
    );
    for (i, v) in state.v.iter().enumerate() {
        for (j, w) in v.iter().enumerate() {
            put(
                std::mem::offset_of!(GuestState, v) + i * 16 + j * 8,
                &w.to_le_bytes(),
            );
        }
    }
    put(
        std::mem::offset_of!(GuestState, fpcr),
        &state.fpcr.to_le_bytes(),
    );
    put(
        std::mem::offset_of!(GuestState, fpsr),
        &state.fpsr.to_le_bytes(),
    );
    bytes
}

fn system_controls(
    system: &SystemState,
    registers: &GuestState,
    controls: &crate::system::translation_controls::TranslationControls,
) -> serde_json::Value {
    let bank = controls.snapshot().unwrap().readbacks();
    let el1 = system.el1_registers();
    serde_json::json!({
        "pstate_low32": system.pstate(registers),
        "sp_el0": system.stack_pointer(crate::system::state::StackBank::El0, registers),
        "sp_el1": system.stack_pointer(crate::system::state::StackBank::El1, registers),
        "elr_el1": el1.elr(), "spsr_el1": el1.spsr(), "esr_el1": el1.esr(),
        "far_el1": el1.far(), "vbar_el1": el1.vbar(),
        "sctlr_el1": bank.sctlr_el1, "tcr_el1": bank.tcr_el1,
        "ttbr0_el1": bank.ttbr0_el1, "ttbr1_el1": bank.ttbr1_el1,
        "mair_el1": bank.mair_el1,
    })
}

#[test]
#[ignore = "actual translated native read; requires a fresh absolute output directory"]
fn synthetic_read8_full_state_and_owned_ram() {
    let root = std::path::PathBuf::from(
        std::env::var_os("STELA_M0_NATIVE_OUTPUT").expect("fresh output directory required"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).unwrap();
    // Validate the ACTUALLY consumed compiler and declaration before any PE
    // construction or guest data transaction; neither hash is access authority.
    let actual_compiler =
        stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes());
    assert_eq!(
        stela_core::sha256(SOFTWARE_DECLARATION),
        SOFTWARE_DECLARATION_SHA
    );
    std::fs::write(root.join("compiler-source-sha256.txt"), &actual_compiler).unwrap();
    std::fs::write(root.join("software-declaration.json"), SOFTWARE_DECLARATION).unwrap();
    std::fs::write(root.join("verification-scope.txt"), "Authored synthetic input/model and actual native execution; no original oracle equality or hardware control adoption.").unwrap();
    let before = inputs::before();
    assert_eq!(before.sp, inputs::SP_EL1);
    assert_eq!(before.x[20] + 8, inputs::READ_PA);
    std::fs::write(root.join("before-state.bin"), state_bytes(&before)).unwrap();
    let materialized = inputs::materialize_inputs(ADDRESS_SPACE).unwrap();
    let (binding, code) = materialized.into_parts();
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    assert_eq!(physical.layout().initialized.len(), 2);
    let mut system = SystemState::new(
        inputs::PSTATE_LOW32 & !0xf000_0000,
        inputs::SP_EL0,
        El1Registers::new(inputs::SOURCE_PC.0, inputs::PSTATE_LOW32, 0, 0, 0),
    )
    .unwrap();
    let initial_pstate = system.pstate(&before);
    let entry = EntryProfile::base(
        SystemEntryFeatures::declared_absent(),
        ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
    )
    .unwrap();
    let readbacks = RegisterValues {
        sctlr_el1: inputs::SCTLR_EL1,
        tcr_el1: 0,
        ttbr0_el1: 0,
        ttbr1_el1: 0,
        mair_el1: 0,
    };
    let runtime = BlockRuntime::new_with_profile(
        ADDRESS_SPACE,
        root.join("cache"),
        BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged),
    );
    // SAFETY: materialization created this NEW sole physical-role machine from
    // owned initialized extents. This synchronous fixture retains all original
    // resources and transfers publication/retirement ownership once. No other
    // PE, writer, DMA, debugger or asynchronous producer exists in this machine.
    let installed = unsafe {
        InstalledM0Owner::new(
            runtime,
            physical,
            code,
            entry,
            readbacks,
            profile(),
            &system,
            inputs::SOURCE_PC,
        )
    }
    .unwrap();
    let outcome = installed
        .into_executable_scope(&ConsumerKey(()), |runtime, sources, controls| {
            let scope = sources.source_scope().unwrap();
            let system_before = system_controls(&system, &before, controls);
            std::fs::write(
                root.join("system-controls-before.json"),
                serde_json::to_vec_pretty(&system_before).unwrap(),
            )
            .unwrap();
            assert_eq!(controls.snapshot().unwrap().readbacks(), readbacks);
            let policy = MemoryControls::new(
                LowerAddressProfile::new(48, false).unwrap(),
                true,
                false,
                true,
                TagCheckFaultMode::Synchronous,
                true,
            );
            let mut memory = scope.physical_space().domain().thread(policy);
            let source_before = snapshot(&memory, inputs::SOURCE_PC.0, inputs::SOURCE.len());
            let data_before = snapshot(&memory, inputs::DATA_PA, inputs::DATA.len());
            assert_eq!(source_before, inputs::SOURCE);
            assert_eq!(data_before, inputs::DATA);
            let events = EventDomain::new();
            let endpoint = events.register(false, None).unwrap();
            memory.bind_events(&endpoint.producer()).unwrap();
            let mut context = ExecutionContext::default();
            // SAFETY: complete producer universe of this NEW software PE; no source
            // creation or delivery path exists outside this retained registry.
            let mut asynchronous = unsafe {
                crate::blocks::retirement::software_async::SoftwareAsyncDomain::fresh_software_pe()
            };
            let pending = asynchronous.lease_no_sources().unwrap();
            // SAFETY: this declaration owns the sole actual debug controls for the
            // same fresh software PE. This test declares its own A64 LDR subset
            // and adopts no original emulator or hardware feature state.
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
                registers: before,
                pc: inputs::SOURCE_PC,
            };
            // SAFETY: every argument is an original field/resource of this one
            // consumed installed machine, retained through its sole PE lifetime.
            let result = {
                let mut backend = unsafe {
                    M0Owner::fresh_software(
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
                // SAFETY: this is the ONE actual PE construction; no copied ThreadState,
                // alternate control bank, replacement domain or subsequent reset exists.
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
                        verify_pair_alias_monitor: false,
                        stop_pc: Some(inputs::EXPECTED_PC),
                        block_budget: 1,
                    },
                );
                std::fs::write(root.join("actual-outcome.txt"), format!("{result:#?}")).unwrap();
                std::fs::write(
                    root.join("actual-state.bin"),
                    state_bytes(owner.registers()),
                )
                .unwrap();
                assert!(identity.same_pe(&owner.identity()));
                assert!(matches!(result.stop, OwnedStop::StopAddress), "{result:#?}");
                assert_eq!(owner.pc(), inputs::EXPECTED_PC);
                assert_eq!(owner.registers(), &inputs::expected());
                match result.last_m0_observation.as_ref().unwrap() {
                    M0Observation::Native {
                        report,
                        precommit_failure,
                        settlement_failure,
                        ..
                    } => {
                        assert!(report.invoked);
                        assert_eq!(report.completed_bytes, 8);
                        assert_eq!(
                            report.raw_carrier,
                            Some((
                                inputs::EXPECTED_PC.0,
                                stela_compiler::block::ExitKind::Fallthrough as u64
                            ))
                        );
                        assert!(report.callback_failure.is_none());
                        assert!(report.failure.is_none());
                        assert!(precommit_failure.is_none());
                        assert!(settlement_failure.is_none());
                    }
                    observation => panic!("unexpected actual observation: {observation:?}"),
                }
                assert_eq!(result.settled_prefixes.len(), 1);
                assert_eq!(result.settled_prefixes[0].completed_memory_bytes, 8);
                assert_eq!(result.settled_prefixes[0].consumed_source_bytes, 4);
                drop(owner);
                result
            };

            assert_eq!(context.version, ExecutionContext::default().version);
            assert!(context.memory.is_null());
            assert!(context.system.is_null());
            assert!(context.scalable.is_null());
            assert_eq!(system.pstate(&thread.registers), initial_pstate);
            let system_after = system_controls(&system, &thread.registers, controls);
            std::fs::write(
                root.join("system-controls-after.json"),
                serde_json::to_vec_pretty(&system_after).unwrap(),
            )
            .unwrap();
            assert_eq!(system_before, system_after);
            assert_eq!(controls.snapshot().unwrap().readbacks(), readbacks);
            let source_after = snapshot(&memory, inputs::SOURCE_PC.0, inputs::SOURCE.len());
            let data_after = snapshot(&memory, inputs::DATA_PA, inputs::DATA.len());
            std::fs::write(root.join("source-before.bin"), &source_before).unwrap();
            std::fs::write(root.join("source-after.bin"), &source_after).unwrap();
            std::fs::write(root.join("data-before.bin"), &data_before).unwrap();
            std::fs::write(root.join("data-after.bin"), &data_after).unwrap();
            assert_eq!(source_before, source_after);
            assert_eq!(data_before, data_after);
            result
        })
        .unwrap();
    assert!(matches!(outcome.stop, OwnedStop::StopAddress));
}
