//! Bounded retained structured-load model inputs through the canonical owner.
use super::super::*;
use super::fixture::{ALL_ACCESS, EZT0, Fixture, RET_X30};
use super::pn::{
    CheckedPrefixCohort, MxcsrRestore, bind_checked_prefix, fixed_at_39, frame_load, read_mxcsr,
    retain_raw,
};
use crate::{
    memory::{
        backing::AccessPermissions,
        policy::{LowerAddressProfile, TagCheckFaultMode},
    },
    system::scalable_controls::{Implementation, Readbacks},
};
use serde_json::{Value, json};
use std::{fs, io::Write, path::Path};
use stela_compiler::{
    TargetCpu,
    aarch64::scalable::{
        ScalableMode, VectorLength,
        features::{ScalableFeature, ScalableFeatures},
        profile::ScalableControls,
    },
    context::memory::{MemoryImplementationProfile, MemoryRequirements, MemoryStatus},
    extended::ScalableProfile,
};
use stela_core::sha256;
const MANIFEST_SHA256: &str = "4a2a5f94df81b543f747d6fc35494d3d48a7b72bc0fe715e195499c03ba18e39";
const RAM_BYTES: usize = 8192;
const STRUCTURE_TAIL_START: usize = 47;
const STRUCTURE_TAIL_END_EXCLUSIVE: usize = 59;
fn number(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap()
}

#[test]
#[ignore = "requires the fixed retained Structure59 packet and fresh durable output path"]
fn qualified_structure59_retained_packet_contract() {
    run_structure(false);
}
#[test]
#[ignore = "requires fixed Structure59 inputs, checked source20 prefix evidence and fresh output"]
fn qualified_structure59_remaining_tail_47_through_58() {
    run_structure(true);
}
fn run_structure(tail_only: bool) {
    let packet = std::env::var("STELA_STRUCTURE_PACKET").unwrap();
    let packet = Path::new(&packet);
    let raw = fs::read(packet.join("manifest.json")).unwrap();
    assert_eq!(sha256(&raw), MANIFEST_SHA256);
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    for (name, identity) in manifest["files"].as_object().unwrap() {
        let data = fs::read(packet.join(name)).unwrap();
        assert_eq!(data.len() as u64, number(identity, "bytes"));
        assert_eq!(sha256(&data), identity["sha256"].as_str().unwrap());
    }
    let rows: Vec<Value> =
        serde_json::from_slice(&fs::read(packet.join("cases.json")).unwrap()).unwrap();
    assert_eq!(rows.len(), 59);
    let selection = if tail_only {
        STRUCTURE_TAIL_START..STRUCTURE_TAIL_END_EXCLUSIVE
    } else {
        0..rows.len()
    };
    let executed_rows = selection.len();
    let prior_checked_prefix =
        tail_only.then(|| bind_checked_prefix(CheckedPrefixCohort::Structure59));
    let inputs = fs::read(packet.join("inputs.bin")).unwrap();
    let expected = fs::read(packet.join("expected-frames.bin")).unwrap();
    let ram = fs::read(packet.join("ram-input.bin")).unwrap();
    let expected_ram = fs::read(packet.join("expected-ram.bin")).unwrap();
    let output = std::env::var("STELA_STRUCTURE_OUTPUT").unwrap();
    fs::create_dir(&output).unwrap();
    let mut transcript = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&output).join("responses.jsonl"))
        .unwrap();
    let mut counts = [0_usize; 5]; // completed, fault, entry decline, constructor refusal, unrepresentable
    for (index, row) in rows
        .iter()
        .enumerate()
        .skip(selection.start)
        .take(executed_rows)
    {
        assert_eq!(number(row, "run_index"), index as u64);
        assert_eq!(number(row, "required"), 199);
        let hex = row["source_hex"].as_str().unwrap();
        let source: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let words: Vec<u32> = source
            .as_chunks::<4>()
            .0
            .iter()
            .map(|p| u32::from_le_bytes(*p))
            .collect();
        assert_eq!(words.last(), Some(&RET_X30));
        let bytes = number(row, "svl_bytes") as usize;
        let length = VectorLength::from_bytes(bytes).unwrap();
        let target = if row["target_cpu"] == "x86_64-baseline" {
            TargetCpu::Baseline
        } else {
            assert_eq!(row["target_cpu"], "x86_64-baseline+atomic-load16");
            TargetCpu::AtomicLoad16
        };
        let mode = ScalableMode::new(true, false);
        let mut f = Fixture::new_program_at_with_lower_bits_and_data_rights(
            &words,
            number(row, "source_base"),
            number(&manifest, "ram_address"),
            bytes,
            target,
            target,
            None,
            2,
            mode,
            39,
            AccessPermissions {
                readable: true,
                writable: false,
                executable: false,
            },
        );
        let features = ScalableFeatures::of(ScalableFeature::Sme)
            .with(ScalableFeature::Sme2)
            .with(ScalableFeature::Sme2p1);
        let profile = ScalableProfile::new_with_features(
            length,
            mode,
            features,
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), true),
        )
        .unwrap();
        f.prepared = PreparedScalableLeaf::prepare(
            &source,
            GuestAddress(number(row, "source_base")),
            profile,
            target,
        )
        .unwrap();
        let requirements: MemoryRequirements =
            serde_json::from_value(row["expected_requirements"].clone()).unwrap();
        assert_eq!(f.prepared.identity().memory_requirements, requirements);
        assert_eq!(f.prepared.source(), source);
        assert_eq!(f.prepared.source_map().len(), words.len());
        for (offset, (pc, _)) in f.prepared.source_map().iter().enumerate() {
            assert_eq!(
                *pc,
                GuestAddress(number(row, "source_base") + offset as u64 * 4)
            );
        }
        let a = number(row, "frame_offset") as usize;
        let b = a + number(row, "frame_bytes") as usize;
        frame_load(&inputs[a..b], &mut f.registers, &mut f.scalable);
        let r = number(row, "ram_offset") as usize;
        let row_ram = &ram[r..r + RAM_BYTES];
        // SAFETY: private fixture initialization precedes every reservation and entry.
        unsafe { f.storage.write_bytes(row_ram) };
        let initial_registers = f.registers.clone();
        let initial_scalable = f.scalable.clone();
        let mut wanted_registers = f.registers.clone();
        let mut wanted_scalable = f.scalable.clone();
        frame_load(&expected[a..b], &mut wanted_registers, &mut wanted_scalable);
        let policy = &row["access_policy_overrides"];
        let alignment = policy
            .get("effective_sp_alignment")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        f.controls = fixed_at_39(&f, alignment);
        *f.memory.policy_mut() = MemoryControls::new(
            LowerAddressProfile::new(39, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let lengths = [16, 32, 64, 128, 256].map(|n| VectorLength::from_bytes(n).unwrap());
        let _restore = MxcsrRestore::set(number(row, "caller_mxcsr") as u32);
        let archived_phase = row["planned_current_phase"].as_str().unwrap();
        // The retained packet's authored prefix-refusal assumption was wrong:
        // ordinary ADD has known access and no guest memory quantity. Preserve
        // that archival phase, but check its unchanged original exit oracle.
        let phase = if archived_phase == "source_refusal" {
            assert!(matches!(index, 47 | 56 | 57));
            row["original_expected_exit"]["kind"].as_str().unwrap()
        } else {
            archived_phase
        };
        let actual;
        if phase == "unrepresentable_policy" {
            assert!(matches!(index, 52 | 55 | 58));
            assert!(
                policy
                    .get("implementation_profile")
                    .is_some_and(Value::is_null)
                    || policy
                        .get("effective_sp_alignment")
                        .is_some_and(Value::is_null)
            );
            actual = json!({"phase":"unrepresentable_policy","native_executed":false,
                "reason":"canonical fixed owners require explicit effective controls and select a supported declared implementation; this retained unknown policy is not expressible"});
            retain_raw(&mut transcript, index, &f, &actual);
            counts[4] += 1;
            wanted_registers = initial_registers;
            wanted_scalable = initial_scalable;
        } else if phase == "constructor_refusal" {
            let profile = match policy["implementation_profile"].as_str().unwrap() {
                "StreamingSveTagSuppression" => {
                    MemoryImplementationProfile::StreamingSveTagSuppression
                }
                "SmeTagSuppression" => MemoryImplementationProfile::SmeTagSuppression,
                other => panic!("unreviewed implementation {other}"),
            };
            assert!(matches!(
                Implementation::declared_sca16(&lengths, profile),
                Err(scalable_controls::Error::UnsupportedImplementationProfile)
            ));
            actual = json!({"phase":"constructor_refusal","error":"UnsupportedImplementationProfile","native_executed":false});
            retain_raw(&mut transcript, index, &f, &actual);
            counts[3] += 1;
            wanted_registers = initial_registers;
            wanted_scalable = initial_scalable;
        } else {
            let implementation = Implementation::declared_sca16(
                &lengths,
                MemoryImplementationProfile::ScalableTagChecks,
            )
            .unwrap();
            let access = ScalableControlOwner::new_declared_el10(
                &f.ids,
                Readbacks {
                    cpacr_el1: ALL_ACCESS,
                    smcr_el1: EZT0 | (bytes / 16 - 1) as u64,
                },
                implementation,
            )
            .unwrap();
            assert!(
                f.ids
                    .same_snapshot(f.controls.identification_snapshot().unwrap())
            );
            let before_policy = *f.memory.policy_mut();
            let system = f.system.clone();
            let pointers = (f.context.memory, f.context.scalable, f.context.system);
            // SAFETY: finite retained source and one actual pinned domain/Snapshot.
            // Canonical qualification, policy loan, native entry and finalizer stay live.
            let result = unsafe {
                f.controls.execute_scalable_leaf(
                    &access,
                    &f.prepared,
                    &mut f.system,
                    &mut f.registers,
                    &mut f.scalable,
                    &mut f.memory,
                    &mut f.context,
                )
            };
            actual = json!({"result":format!("{result:?}")});
            retain_raw(&mut transcript, index, &f, &actual);
            assert_eq!(*f.memory.policy_mut(), before_policy);
            assert_eq!(f.system, system);
            assert_eq!(
                (f.context.memory, f.context.scalable, f.context.system),
                pointers
            );
            let exit = result.unwrap();
            match phase {
                "completed" => {
                    assert_eq!(exit, ScalableLeafExit::Returned);
                    counts[0] += 1;
                }
                "declined" => {
                    assert_eq!(
                        exit,
                        ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
                    );
                    counts[2] += 1;
                }
                "fault" => {
                    let wanted = &row["original_expected_exit"];
                    assert_eq!(
                        exit,
                        ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
                            status: MemoryStatus::from_code(number(wanted, "status") as u32)
                                .unwrap(),
                            address: GuestAddress(number(wanted, "address")),
                            pc: GuestAddress(number(wanted, "pc")),
                            completed_bytes: number(wanted, "completed_bytes")
                        })
                    );
                    counts[1] += 1;
                }
                other => panic!("unreviewed phase {other}"),
            }
        }
        assert_eq!(read_mxcsr(), number(row, "caller_mxcsr") as u32);
        assert_eq!(
            f.registers, wanted_registers,
            "row {index} complete primary"
        );
        assert_eq!(
            format!("{:?}", f.scalable),
            format!("{wanted_scalable:?}"),
            "row {index} complete owned banks"
        );
        let wanted_ram = if matches!(phase, "unrepresentable_policy" | "constructor_refusal") {
            row_ram
        } else {
            &expected_ram[r..r + RAM_BYTES]
        };
        assert_eq!(f.storage.bytes(), wanted_ram, "row {index} complete RAM");
        writeln!(transcript,"{}",json!({"phase":"verified","run_index":index,"name":row["name"],"classification":phase,"archived_planned_phase":archived_phase,"original_expected_exit":row["original_expected_exit"],"actual":actual})).unwrap();
        transcript.flush().unwrap();
    }
    assert_eq!(
        counts,
        if tail_only {
            [2, 3, 2, 2, 3]
        } else {
            [44, 8, 2, 2, 3]
        }
    );
    fs::write(Path::new(&output).join("report.json"),serde_json::to_vec_pretty(&json!({"passed":true,"input_packet_rows":59,"rows":executed_rows,"executed_indices_inclusive":[selection.start,selection.end-1],"tail_only":tail_only,"prior_checked_prefix":prior_checked_prefix,"same_binary_full_group_pass":!tail_only,"qualified_entry_attempts":counts[0]+counts[1]+counts[2],"native_entries":counts[0]+counts[1],"completed":counts[0],"fault":counts[1],"entry_declined":counts[2],"source_refusal":0,"constructor_refusal":counts[3],"unrepresentable_policy":counts[4],"exact_prior_entry_expectations_checked":executed_rows-counts[3]-counts[4],"changed_or_unreachable_prior_entry_expectations":counts[3]+counts[4],"packet_manifest_sha256":MANIFEST_SHA256,"scope":"bounded current qualified-owner/model gate; no original, timing or coverage admission"})).unwrap()).unwrap();
}
