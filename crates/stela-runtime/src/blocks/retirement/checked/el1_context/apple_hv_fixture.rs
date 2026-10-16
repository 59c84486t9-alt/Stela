//! Physical Apple-HV original observations through the existing sole CSE factory.
//! This test never adopts the hardware's CPU/control profile as runtime authority.
use super::*;

const HV_INPUTS_SHA256: &str = "e7531463afdaa6ecfb1b36d151a69e639d768cce3efc919c1dc8e67546963f19";
const HV_ORIGINAL_SHA256: &str = "eaa3e64b1f73f0b16937a26ab51d58193171b47f7b6e7bbb9687346db4df3929";
const HV_CASES: usize = 4;
const HV_RAM_PA: u64 = 0x20_0000;
const HV_SOURCE_PC: u64 = 0x10_0000;
const HV_SOURCE_PSTATE: u64 = 0xa000_03c5;
const HV_SOURCE_SCTLR: u64 = 0x30d0_0800;
const HV_AFTER_SCTLR: u64 = 0x30d0_0980;
const HV_PAGE_BYTES: usize = 16_384;
const HV_ADDRESS_SPACE_BASE: u64 = 900;
const NATIVE_ONLY_NOP: u32 = 0xd503_201f;

fn pinned_bytes(value: &Value) -> Vec<u8> {
    let path = Path::new(value["path"].as_str().unwrap());
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes.len() as u64, value["bytes"].as_u64().unwrap());
    assert_eq!(
        stela_core::sha256(&bytes),
        value["sha256"].as_str().unwrap()
    );
    bytes
}
fn frame_receipt(value: &Value) -> Value {
    serde_json::from_slice(&pinned_bytes(value)).unwrap()
}
fn original_register(frame: &Value, name: &str) -> u64 {
    let readback = &frame["sysregs"][name];
    assert_eq!(readback["status"].as_u64(), Some(0));
    u64::from_str_radix(
        readback["value"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap()
}
fn original_el1(frame: &Value) -> El1Registers {
    El1Registers::new(
        original_register(frame, "ELR_EL1"),
        original_register(frame, "SPSR_EL1"),
        original_register(frame, "ESR_EL1"),
        original_register(frame, "FAR_EL1"),
        original_register(frame, "VBAR_EL1"),
    )
}

fn native_system(system: &SystemState, registers: &GuestState, pc: GuestAddress) -> Value {
    let bank = system.el1_registers();
    json!({
        "pc": pc.0,
        "pstate": system.pstate(registers),
        "sp_el0": system.stack_pointer(StackBank::El0, registers),
        "sp_el1": system.stack_pointer(StackBank::El1, registers),
        "el1": {"ELR_EL1": bank.elr(), "SPSR_EL1": bank.spsr(),
            "ESR_EL1": bank.esr(), "FAR_EL1": bank.far(), "VBAR_EL1": bank.vbar()}
    })
}

#[test]
#[ignore = "requires coordinated current CSE producer and reviewed physical-original4 inputs"]
fn actual_four_apple_hv_originals_and_same_owner_effects() {
    let output = PathBuf::from(
        std::env::var_os("STELA_APPLE_HV_NATIVE_OUTPUT").expect("fresh absolute output"),
    );
    let inputs = PathBuf::from(
        std::env::var_os("STELA_APPLE_HV_NATIVE_INPUTS").expect("pinned original4 inputs"),
    );
    assert!(output.is_absolute() && inputs.is_absolute());
    std::fs::create_dir(&output).unwrap();
    let plan = pinned_json(&inputs, HV_INPUTS_SHA256);
    let original = pinned_json(
        Path::new(plan["original_receipt"]["path"].as_str().unwrap()),
        HV_ORIGINAL_SHA256,
    );
    assert_eq!(original["physical_originals"].as_u64(), Some(4));
    assert_eq!(original["native_comparisons"].as_u64(), Some(0));
    let rows = plan["rows"].as_array().unwrap();
    assert_eq!(rows.len(), HV_CASES);
    assert_eq!(plan["page_bytes"].as_u64(), Some(HV_PAGE_BYTES as u64));
    assert_eq!(plan["ram_pa"].as_u64(), Some(HV_RAM_PA));
    let mut results = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["index"].as_u64(), Some(index as u64));
        let case = output.join(row["name"].as_str().unwrap());
        std::fs::create_dir(&case).unwrap();
        let original_before = frame_receipt(&row["before_receipt"]);
        let original_after = frame_receipt(&row["after_receipt"]);
        let source_page = pinned_bytes(&row["source_page"]);
        let ram = pinned_bytes(&row["ram_before"]);
        let expected_ram = pinned_bytes(&row["ram_after"]);
        let before_bytes = pinned_bytes(&row["before_state"]);
        let expected_bytes = pinned_bytes(&row["after_state"]);
        let before = state_from_hex(
            &before_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        let expected = state_from_hex(
            &expected_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        assert_eq!(before_bytes.len(), STATE_BYTES);
        assert_eq!(expected_bytes.len(), STATE_BYTES);
        assert_eq!(source_page.len(), HV_PAGE_BYTES);
        assert_eq!(ram.len(), HV_PAGE_BYTES);
        assert_eq!(ram, expected_ram);
        let word = u32::try_from(row["word"].as_u64().unwrap()).unwrap();
        assert_eq!(&source_page[..WORD_BYTES], word.to_le_bytes());
        let pc = row["source_pc"].as_u64().unwrap();
        let target = row["target_pc"].as_u64().unwrap();
        let pstate = row["before_pstate"].as_u64().unwrap();
        let expected_pstate = row["after_pstate"].as_u64().unwrap();
        assert_eq!(pc, HV_SOURCE_PC);
        assert_eq!(pstate, HV_SOURCE_PSTATE);
        assert_eq!(u64::from(before.nzcv), pstate & NZCV_MASK);
        assert_ne!(before.nzcv, 0);
        for frame in [&original_before, &original_after] {
            assert_eq!(frame["all_required_readbacks_available"], true);
            assert_eq!(frame["handler_instructions_executed"], 0);
            assert_eq!(original_register(frame, "TCR_EL1"), 0);
            assert_eq!(original_register(frame, "MDSCR_EL1"), 0);
        }
        assert_eq!(
            original_register(&original_before, "SCTLR_EL1"),
            HV_SOURCE_SCTLR
        );
        assert_eq!(
            original_register(&original_after, "SCTLR_EL1"),
            HV_AFTER_SCTLR
        );
        // The original target was unmapped. This extra native-only NOP source
        // permits actual destination qualification and must never be executed.
        assert_eq!(row["original_target_unmapped"], true);
        assert_eq!(row["native_target_canary_not_original"], true);
        let target_source = decode_hex(row["native_target_canary_hex"].as_str().unwrap());
        assert_eq!(target_source, NATIVE_ONLY_NOP.to_le_bytes());
        let sp0 = original_register(&original_before, "SP_EL0");
        let sp1 = original_register(&original_before, "SP_EL1");
        let system =
            SystemState::new(pstate & !NZCV_MASK, sp0, original_el1(&original_before)).unwrap();
        let mut machine = SoftwareEl1Machine::new(SoftwareEl1Config {
            profile: SoftwareEl1Profile::PlatformV1,
            cache_directory: case.join("cache"),
            ram: SourceRamDeclaration {
                address_space: HV_ADDRESS_SPACE_BASE + index as u64,
                target: TargetCpu::Baseline,
                declared_capacity: vec![
                    PhysicalRamRange {
                        source_pa: pc,
                        bytes: HV_PAGE_BYTES as u64,
                    },
                    PhysicalRamRange {
                        source_pa: HV_RAM_PA,
                        bytes: HV_PAGE_BYTES as u64,
                    },
                    PhysicalRamRange {
                        source_pa: target & !(HV_PAGE_BYTES as u64 - 1),
                        bytes: HV_PAGE_BYTES as u64,
                    },
                ],
                initialized: vec![
                    extent(pc, source_page.clone(), true),
                    extent(target, target_source.clone(), true),
                    extent(HV_RAM_PA, ram.clone(), false),
                ],
            },
            thread: ThreadState {
                pc: GuestAddress(pc),
                registers: before.clone(),
            },
            system,
            translation: RegisterValues {
                sctlr_el1: 0,
                tcr_el1: 0,
                ttbr0_el1: 0,
                ttbr1_el1: 0,
                mair_el1: 0,
            },
        })
        .unwrap();
        machine.exception_fixture_canary = Some(HV_RAM_PA);
        let identification = machine.platform.as_ref().unwrap().identification();
        let identification_hash = identification.provenance().input_sha256().to_owned();
        let identification_values: Vec<_> = crate::system::identification::ALL_REGISTERS
            .iter()
            .map(|register| {
                (
                    format!("{register:?}"),
                    identification
                        .read(*register)
                        .map_err(|error| format!("{error:?}")),
                )
            })
            .collect();
        std::fs::write(case.join("before-native-identification.json"), serde_json::to_vec_pretty(&json!({"input_sha256":identification_hash,"values":identification_values,"matches_original_cpu_identity":false})).unwrap()).unwrap();
        std::fs::write(case.join("control-adaptation.json"), serde_json::to_vec_pretty(&json!({"original_before":original_before,"original_after":original_after,"actual_native_declared":plan["native_translation"],"relevant_subset_adaptation":plan["relevant_subset_adaptation"],"full_original_control_equality":false,"full_original_cpu_profile_equality":false})).unwrap()).unwrap();
        std::fs::write(
            case.join("original-row.json"),
            serde_json::to_vec_pretty(row).unwrap(),
        )
        .unwrap();
        std::fs::write(
            case.join("before-state.bin"),
            state_bytes(&machine.thread.registers),
        )
        .unwrap();
        std::fs::write(
            case.join("before-system.txt"),
            format!("{:#?}", machine.system),
        )
        .unwrap();
        std::fs::write(
            case.join("before-current-system.json"),
            serde_json::to_vec_pretty(&native_system(
                &machine.system,
                &machine.thread.registers,
                machine.thread.pc,
            ))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            case.join("immutable-original-source-page.bin"),
            &source_page,
        )
        .unwrap();
        std::fs::write(case.join("native-only-target-canary.bin"), &target_source).unwrap();
        {
            let memory = machine.memory.observation_loan().unwrap();
            let actual = memory.snapshot(HV_RAM_PA, ram.len()).unwrap();
            std::fs::write(case.join("before-ram.bin"), &actual).unwrap();
            assert_eq!(actual, ram);
        }
        assert_eq!(machine.thread.registers, before);
        assert_eq!(machine.system.pstate(&before), pstate);
        assert_eq!(machine.system.stack_pointer(StackBank::El0, &before), sp0);
        assert_eq!(machine.system.stack_pointer(StackBank::El1, &before), sp1);
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: Some(GuestAddress(target)),
                block_budget: BLOCK_BUDGET,
            })
            .unwrap();
        // Retain the complete actual result BEFORE checking any semantic result.
        std::fs::write(
            case.join("after-state.bin"),
            state_bytes(&report.thread.registers),
        )
        .unwrap();
        std::fs::write(
            case.join("after-system.txt"),
            format!("{:#?}", report.system),
        )
        .unwrap();
        std::fs::write(case.join("actual-owner.txt"), format!("stop={}\npc={:x}\naccounting={:?}\ncontext={:?}\nprobe={:?}\nbefore_controls={:?}\nafter_controls={:?}\nidentification={:?}\ncompiler={}\n",report.stop,report.thread.pc.0,report.accounting,report.context_observation,report.exception_fixture_probe,report.translation_before,report.translation,report.platform_identification_sha256,report.compiler_source_sha256)).unwrap();
        std::fs::write(
            case.join("after-current-system.json"),
            serde_json::to_vec_pretty(&native_system(
                &report.system,
                &report.thread.registers,
                report.thread.pc,
            ))
            .unwrap(),
        )
        .unwrap();
        for range in &report.ram {
            let path = case.join(format!(
                "after-ram-{:x}-{}.bin",
                range.source_pa, range.bytes
            ));
            match &range.captured_bytes {
                Ok(bytes) => std::fs::write(path, bytes).unwrap(),
                Err(error) => std::fs::write(path.with_extension("error.txt"), error).unwrap(),
            }
        }
        assert_eq!(report.stop, "StopAddress");
        assert_eq!(report.thread.pc, GuestAddress(target));
        assert_eq!(report.accounting.blocks_executed, 1);
        assert_eq!(report.thread.registers, expected);
        let expected_sp0 = original_register(&original_after, "SP_EL0");
        let expected_sp1 = original_register(&original_after, "SP_EL1");
        let inactive = if expected_pstate & PSTATE_MODE_MASK == PSTATE_EL1H {
            expected_sp0
        } else {
            expected_sp1
        };
        let expected_system = SystemState::new(
            expected_pstate & !NZCV_MASK,
            inactive,
            original_el1(&original_after),
        )
        .unwrap();
        assert_eq!(report.system, expected_system);
        assert_eq!(
            report.system.pstate(&report.thread.registers),
            expected_pstate
        );
        assert_eq!(
            report
                .system
                .stack_pointer(StackBank::El0, &report.thread.registers),
            expected_sp0
        );
        assert_eq!(
            report
                .system
                .stack_pointer(StackBank::El1, &report.thread.registers),
            expected_sp1
        );
        assert_eq!(
            report.platform_identification_sha256.as_deref(),
            Some(identification_hash.as_str())
        );
        assert_eq!(
            report.translation_before.as_ref().unwrap(),
            report.translation.as_ref().unwrap()
        );
        assert_eq!(
            *report.translation.as_ref().unwrap(),
            RegisterValues {
                sctlr_el1: 0,
                tcr_el1: 0,
                ttbr0_el1: 0,
                ttbr1_el1: 0,
                mair_el1: 0
            }
        );
        let actual = report.context_fixture_observation.as_ref().unwrap();
        assert_eq!(actual.instruction.instruction_pc, GuestAddress(pc));
        assert_eq!(actual.instruction.word, word);
        assert!(actual.native.invoked && actual.native.failure.is_none());
        assert!(matches!(actual.native.storage_after, Some(Ok(()))));
        assert_eq!(
            actual.native.raw_carrier,
            Some((pc, ExitKind::System as u64))
        );
        assert_eq!(
            actual.exception_result.as_ref().unwrap().as_ref().unwrap(),
            &target
        );
        assert_eq!(actual.actual_continuation, Some(GuestAddress(target)));
        assert!(actual.failure.is_none());
        let returning = row["canonical_id"] == "ERET_64E_branch_reg";
        let probe = report.exception_fixture_probe.as_ref().unwrap();
        assert!(probe.local_seeded && !probe.event_before);
        assert_eq!(*probe.local_after.as_ref().unwrap(), !returning);
        assert_eq!(probe.event_after, returning);
        assert_eq!(
            *probe.generation_after.as_ref().unwrap(),
            probe
                .generation_before
                .as_ref()
                .unwrap()
                .checked_add(1)
                .unwrap()
        );
        for range in &report.ram {
            let expected_bytes = if range.source_pa == pc {
                &source_page
            } else if range.source_pa == target {
                &target_source
            } else {
                assert_eq!(range.source_pa, HV_RAM_PA);
                &ram
            };
            assert_eq!(range.captured_bytes.as_ref().unwrap(), expected_bytes);
        }
        results.push(json!({"canonical_id":row["canonical_id"],"word":word,"full784_equal":true,"current_pstate_el1_sp_pc_equal":true,"original_source_ram_equal":true,"native_only_target_not_executed":true,"actual_same_owner_monitor_event_generation_checked":true,"hardware_monitor_event_observed":false,"full_original_cpu_control_identity":false,"platform_identification_sha256":report.platform_identification_sha256,"compiler_source_sha256":report.compiler_source_sha256}));
    }
    let compiled_sources = json!({
        "crates/stela-runtime/src/blocks/retirement/checked/el1_context/apple_hv_fixture.rs":
            stela_core::sha256(include_bytes!("apple_hv_fixture.rs")),
        "crates/stela-runtime/src/blocks/retirement/checked/el1_context/fixture.rs":
            stela_core::sha256(include_bytes!("fixture.rs"))
    });
    std::fs::write(output.join("report.json"),serde_json::to_vec_pretty(&json!({"kind":"actual_four_apple_hv_originals_native_cse_comparison_v1","compiled_sources_sha256":compiled_sources,"passed":true,"rows":results,"physical_original_comparisons":HV_CASES,"new_original_runs":0,"original_receipt_sha256":HV_ORIGINAL_SHA256,"fixture_source_sha256":stela_core::sha256(include_bytes!("apple_hv_fixture.rs")),"parent_fixture_sha256":stela_core::sha256(include_bytes!("fixture.rs")),"limits":plan["scope"]})).unwrap()).unwrap();
}
