//! Eight retained original observations through the CURRENT sole factory.
//! RAM, monitor, endpoint and publication assertions are actual current-machine
//! probes, separate from originals which did not observe those resources.
use super::*;
use crate::system::{
    pstate::NZCV_MASK,
    state::{El1Registers, PSTATE_EL1H, PSTATE_MODE_MASK, StackBank},
};
use serde_json::{Value, json};
use std::{
    mem::{offset_of, size_of},
    path::Path,
};
use stela_compiler::{GuestState, TargetCpu, block::ExitKind};
const INPUTS_SHA256: &str = "ec1553e029c20fb889389bad23d5d8bf6986c00e7cec6faf1ae736786682ef2c";
const COHORT_SHA256: &str = "245beff4641a1071272dda44feba264c0037cdff70fb1251d642c0f02ff456ca";
const CASES: usize = 8;
const ADDRESS_SPACE_BASE: u64 = 700;
const BLOCK_BUDGET: usize = 2;
const INPUT_FIELDS: usize = 19;
const STATE_BYTES: usize = 784;
const WORD_BYTES: usize = size_of::<u32>();
const QWORD_BYTES: usize = size_of::<u64>();
const RETURN_KIND: u64 = 2;
const ORIGINAL_SCTLR_EL1: u64 = 0x00c5_0838;
const SOURCE_CAPACITY_BASE: u64 = 0x4008_0000;
const SOURCE_CAPACITY_BYTES: u64 = 0x10000;
const DATA_CAPACITY_BYTES: u64 = 32;

#[derive(Debug)]
pub(super) struct ProbeObservation {
    pub(super) local_seeded: bool,
    pub(super) local_after: Result<bool, String>,
    pub(super) event_before: bool,
    pub(super) event_after: bool,
    pub(super) generation_before: Result<u64, String>,
    pub(super) generation_after: Result<u64, String>,
}
fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn state_from_hex(text: &str) -> GuestState {
    let b = decode_hex(text);
    assert_eq!(b.len(), STATE_BYTES);
    let q = |o| u64::from_le_bytes(b[o..o + QWORD_BYTES].try_into().unwrap());
    let d = |o| u32::from_le_bytes(b[o..o + WORD_BYTES].try_into().unwrap());
    GuestState {
        x: std::array::from_fn(|i| q(offset_of!(GuestState, x) + i * QWORD_BYTES)),
        sp: q(offset_of!(GuestState, sp)),
        nzcv: d(offset_of!(GuestState, nzcv)),
        reserved: d(offset_of!(GuestState, reserved)),
        v: std::array::from_fn(|i| {
            [
                q(offset_of!(GuestState, v) + i * size_of::<[u64; 2]>()),
                q(offset_of!(GuestState, v) + i * size_of::<[u64; 2]>() + QWORD_BYTES),
            ]
        }),
        fpcr: d(offset_of!(GuestState, fpcr)),
        fpsr: d(offset_of!(GuestState, fpsr)),
    }
}
fn state_bytes(state: &GuestState) -> Vec<u8> {
    let mut b = Vec::with_capacity(STATE_BYTES);
    for x in state.x {
        b.extend(x.to_le_bytes());
    }
    b.extend(state.sp.to_le_bytes());
    b.extend(state.nzcv.to_le_bytes());
    b.extend(state.reserved.to_le_bytes());
    for v in state.v {
        for x in v {
            b.extend(x.to_le_bytes());
        }
    }
    b.extend(state.fpcr.to_le_bytes());
    b.extend(state.fpsr.to_le_bytes());
    assert_eq!(b.len(), STATE_BYTES);
    b
}
fn pinned_json(path: &Path, expected: &str) -> Value {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(stela_core::sha256(&bytes), expected);
    serde_json::from_slice(&bytes).unwrap()
}
fn el1(value: &Value) -> El1Registers {
    let q = |name| value[name].as_u64().unwrap();
    El1Registers::new(
        q("ELR_EL1"),
        q("SPSR_EL1"),
        q("ESR_EL1"),
        q("FAR_EL1"),
        q("VBAR_EL1"),
    )
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

#[test]
#[ignore = "actual current eight-case native exception gate; reviewed source graph and fresh absolute output required"]
fn actual_basefour_eight_originals_and_same_owner_effects() {
    assert_eq!(size_of::<GuestState>(), STATE_BYTES);
    let output =
        PathBuf::from(std::env::var_os("STELA_EL1_EXCEPTION_OUTPUT").expect("fresh output"));
    let inputs =
        PathBuf::from(std::env::var_os("STELA_EL1_EXCEPTION_INPUTS").expect("pinned inputs"));
    assert!(output.is_absolute() && inputs.is_absolute());
    std::fs::create_dir(&output).unwrap();
    let plan = pinned_json(&inputs, INPUTS_SHA256);
    let cohort_path = Path::new(plan["cohort"]["path"].as_str().unwrap());
    let cohort = pinned_json(cohort_path, COHORT_SHA256);
    let rows = cohort["rows"].as_array().unwrap();
    let planned = plan["rows"].as_array().unwrap();
    assert_eq!(rows.len(), CASES);
    assert_eq!(planned.len(), CASES);
    let canary_pa = plan["canary_pa"].as_u64().unwrap();
    let canary = decode_hex(plan["canary_hex"].as_str().unwrap());
    assert_eq!(canary.len(), DATA_CAPACITY_BYTES as usize);
    let mut results = Vec::new();
    for (index, (row, selected)) in rows.iter().zip(planned).enumerate() {
        assert_eq!(selected["index"].as_u64().unwrap(), index as u64);
        assert_eq!(selected["cohort_index"], row["index"]);
        let case = output.join(selected["name"].as_str().unwrap());
        std::fs::create_dir(&case).unwrap();
        let original = pinned_json(
            Path::new(row["original_receipt"]["path"].as_str().unwrap()),
            row["original_receipt"]["sha256"].as_str().unwrap(),
        );
        assert_eq!(
            original["primary"]["before"]["state_hex"],
            row["before_state_hex"]
        );
        assert_eq!(
            original["primary"]["after"]["state_hex"],
            row["expected"]["state_hex"]
        );
        let elf = std::fs::read(row["source_elf"]["path"].as_str().unwrap()).unwrap();
        assert_eq!(
            stela_core::sha256(&elf),
            row["source_elf"]["sha256"].as_str().unwrap()
        );
        let fields = row["input_fields"].as_array().unwrap();
        assert_eq!(fields.len(), INPUT_FIELDS);
        let [
            kind,
            word,
            pc,
            pstate,
            sp0,
            sp1,
            elr,
            spsr,
            esr,
            far,
            vbar,
            original_tcr,
            original_mdscr,
            _pfr0,
            _pfr1,
            _optional,
            _dfr0,
            _oslsr,
            original_sctlr,
        ]: [u64; INPUT_FIELDS] = std::array::from_fn(|i| fields[i].as_u64().unwrap());
        assert_eq!(original_sctlr, ORIGINAL_SCTLR_EL1);
        assert_eq!(original_tcr, 0);
        assert_eq!(original_mdscr, 0);
        for (name, value) in [
            ("SCTLR_EL1", original_sctlr),
            ("TCR_EL1", original_tcr),
            ("MDSCR_EL1", original_mdscr),
        ] {
            let raw = decode_hex(
                original["primary"]["before"]["raw_register_hex"][name]
                    .as_str()
                    .unwrap(),
            );
            assert_eq!(u64::from_le_bytes(raw.try_into().unwrap()), value);
            assert_eq!(selected["original_controls"][name].as_u64().unwrap(), value);
        }
        std::fs::write(
            case.join("control-adaptation.json"),
            serde_json::to_vec_pretty(&json!({
                "original":selected["original_controls"],
                "actual_declared":selected["actual_declared_translation_controls"],
                "relevant_subset_adaptation":selected["relevant_subset_adaptation"],
                "full_original_control_equality":false,
                "full_original_cpu_profile_equality":false,
                "raw_original_readbacks":original["primary"]["before"]["raw_register_hex"],
            }))
            .unwrap(),
        )
        .unwrap();
        let source = decode_hex(row["runtime_source_hex"].as_str().unwrap());
        assert_eq!(source, (word as u32).to_le_bytes());
        let source_offset =
            usize::try_from(row["source_elf_instruction_offset"].as_u64().unwrap()).unwrap();
        assert_eq!(source, &elf[source_offset..source_offset + WORD_BYTES]);
        let target = row["expected"]["pc"].as_u64().unwrap();
        let target_source = decode_hex(selected["target_source_hex"].as_str().unwrap());
        let target_offset =
            usize::try_from(selected["target_source_offset"].as_u64().unwrap()).unwrap();
        assert_eq!(
            target_source,
            &elf[target_offset..target_offset + WORD_BYTES]
        );
        let before = state_from_hex(row["before_state_hex"].as_str().unwrap());
        let expected = state_from_hex(row["expected"]["state_hex"].as_str().unwrap());
        assert_eq!(u64::from(before.nzcv) & NZCV_MASK, pstate & NZCV_MASK);
        let inactive = if pstate & PSTATE_MODE_MASK == PSTATE_EL1H {
            sp0
        } else {
            sp1
        };
        let system = SystemState::new(
            pstate & !NZCV_MASK,
            inactive,
            El1Registers::new(elr, spsr, esr, far, vbar),
        )
        .unwrap();
        let mut machine = SoftwareEl1Machine::new(SoftwareEl1Config {
            profile: SoftwareEl1Profile::PlatformV1,
            cache_directory: case.join("cache"),
            ram: SourceRamDeclaration {
                address_space: ADDRESS_SPACE_BASE + index as u64,
                target: TargetCpu::Baseline,
                declared_capacity: vec![
                    PhysicalRamRange {
                        source_pa: SOURCE_CAPACITY_BASE,
                        bytes: SOURCE_CAPACITY_BYTES,
                    },
                    PhysicalRamRange {
                        source_pa: canary_pa,
                        bytes: DATA_CAPACITY_BYTES,
                    },
                ],
                initialized: vec![
                    extent(pc, source.clone(), true),
                    extent(target, target_source.clone(), true),
                    extent(canary_pa, canary.clone(), false),
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
        machine.exception_fixture_canary = Some(canary_pa);
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
        std::fs::write(case.join("immutable-source.bin"), &source).unwrap();
        std::fs::write(case.join("immutable-target-canary.bin"), &target_source).unwrap();
        std::fs::write(
            case.join("original-row.json"),
            serde_json::to_vec_pretty(row).unwrap(),
        )
        .unwrap();
        assert_eq!(machine.thread.registers, before);
        assert_eq!(machine.system.pstate(&before), pstate);
        {
            let memory = machine.memory.observation_loan().unwrap();
            let actual = memory.snapshot(canary_pa, canary.len()).unwrap();
            std::fs::write(case.join("before-ram.bin"), &actual).unwrap();
            assert_eq!(actual, canary);
        }
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: Some(GuestAddress(target)),
                block_budget: BLOCK_BUDGET,
            })
            .unwrap();
        // Save actual successes AND failures before any semantic assertion.
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
        std::fs::write(case.join("actual-owner.txt"),format!("stop={}\npc={:x}\naccounting={:?}\ncontext={:?}\nprobe={:?}\nbefore_controls={:?}\nafter_controls={:?}\ncompiler={}\n",report.stop,report.thread.pc.0,report.accounting,report.context_observation,report.exception_fixture_probe,report.translation_before,report.translation,report.compiler_source_sha256)).unwrap();
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
        let expected_pstate = row["expected"]["pstate"].as_u64().unwrap();
        let expected_sp0 = row["expected"]["sp_el0"].as_u64().unwrap();
        let expected_sp1 = row["expected"]["sp_el1"].as_u64().unwrap();
        let expected_inactive = if expected_pstate & PSTATE_MODE_MASK == PSTATE_EL1H {
            expected_sp0
        } else {
            expected_sp1
        };
        let expected_system = SystemState::new(
            expected_pstate & !NZCV_MASK,
            expected_inactive,
            el1(&row["expected"]["el1"]),
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
            report.translation_before.as_ref().unwrap(),
            report.translation.as_ref().unwrap()
        );
        let actual_controls = report.translation_before.as_ref().unwrap();
        assert_eq!(
            *actual_controls,
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
        assert_eq!(actual.instruction.word, word as u32);
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
        let probe = report.exception_fixture_probe.as_ref().unwrap();
        assert!(probe.local_seeded && !probe.event_before);
        assert_eq!(*probe.local_after.as_ref().unwrap(), kind != RETURN_KIND);
        assert_eq!(probe.event_after, kind == RETURN_KIND);
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
                &source
            } else if range.source_pa == target {
                &target_source
            } else {
                assert_eq!(range.source_pa, canary_pa);
                &canary
            };
            assert_eq!(range.captured_bytes.as_ref().unwrap(), expected_bytes);
        }
        results.push(json!({"index":index,"canonical_id":row["canonical_id"],"full784_equal":true,"whole_system_equal":true,"target_pc_equal":true,"current_ram_canaries_unchanged":true,"original_ram_observed":false,"actual_original_local_monitor_and_event":true,"actual_context_generation_advanced_once":true,"compiler_source_sha256":report.compiler_source_sha256,"original_controls":selected["original_controls"],"actual_declared_translation_controls":selected["actual_declared_translation_controls"],"relevant_subset_adaptation":selected["relevant_subset_adaptation"],"full_original_control_equality":false,"full_original_cpu_profile_equality":false}));
    }
    std::fs::write(output.join("report.json"),serde_json::to_vec_pretty(&json!({"passed":true,"rows":results,"original_comparisons":CASES,"new_original_runs":0,"profile":"current_fresh_software_el1_platform_v1","limits":plan["scope"]})).unwrap()).unwrap();
}

// Physical Apple-HV observations remain distinct from the retained QEMU cohort.
#[path = "apple_hv_fixture.rs"]
mod apple_hv_fixture;
