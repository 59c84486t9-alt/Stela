//! Fixed retained PN packet through the canonical CPU/process/Prepared owner.
//! The packet is a model oracle. Prior original observations are joined separately.
use super::super::*;
use super::fixture::{ALL_ACCESS, Fixture, RET_X30};
use crate::{
    memory::policy::{LowerAddressProfile, TagCheckFaultMode},
    system::{
        process_memory::{SCTLR_NATIVE_NORMAL_WB, SCTLR_SP_ALIGNMENT_EL0, SourceNormalWbDomain},
        scalable_controls::{Implementation, Readbacks},
    },
};
use serde_json::{Value, json};
use std::{fs, io::Write, path::Path, sync::Arc};
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

const REVIEWED_MANIFEST: &str = "32b2ffadd69f878de48fbe738af2f5bd489b7154dc7660d6c59ee05f6e631961";
const ORIGINAL128_MANIFEST: &str =
    "c32362ed1589175700f8a2bee93771a96914a86ebde3fb5bc16a55b5f553064c";
const PN_TAIL_START: usize = 148;
const PN_TAIL_END_EXCLUSIVE: usize = 164;
const VERIFIED_PREFIX_RECEIPT_SHA256: &str =
    "28d3c81b6160fb62809638b02aa360c97ac154d88032677b06ae3c0599f84580";
const VERIFIED_PN_RESPONSES_SHA256: &str =
    "e363900d982a0f540d189cad39e52e9bf386e7841196d428e8da69b94972d1ae";
const VERIFIED_STRUCTURE_RESPONSES_SHA256: &str =
    "5ca2147e5d16f591297822717e5c3c2142006f6af3e68a9817579e638673d773";
const SOURCE20_MANIFEST_SHA256: &str =
    "311ffe34765650678005b3276e3a22ad96501afd0fc19acfaa075508eb7451cd";
const VERIFIED_STRUCTURE_PREFIX_CASES: usize = 47;
const SOURCE20_BINARY_SHA256: &str =
    "2975455fed3e02af15781aa1118201d821c50620828a057b9952754958a55e71";

pub(super) enum CheckedPrefixCohort {
    Pn164,
    Structure59,
}
pub(super) fn bind_checked_prefix(cohort: CheckedPrefixCohort) -> Value {
    let receipt_path = std::env::var("STELA_SCALABLE_VERIFIED_PREFIX_RECEIPT").unwrap();
    let receipt_path = Path::new(&receipt_path);
    let bytes = fs::read(receipt_path).unwrap();
    assert_eq!(sha256(&bytes), VERIFIED_PREFIX_RECEIPT_SHA256);
    let receipt: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(receipt["source20_binary_sha256"], SOURCE20_BINARY_SHA256);
    let source20_manifest_path = receipt_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("source-union-20-native-workers-manifest-1.json");
    assert_eq!(
        sha256(&fs::read(source20_manifest_path).unwrap()),
        SOURCE20_MANIFEST_SHA256
    );
    assert_eq!(
        receipt["compiler_fingerprint"],
        sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes())
    );
    let (group, directory, count, wanted_counts, responses_sha) = match cohort {
        CheckedPrefixCohort::Pn164 => (
            "PN164",
            "pn164-output",
            PN_TAIL_START,
            [112, 36],
            VERIFIED_PN_RESPONSES_SHA256,
        ),
        CheckedPrefixCohort::Structure59 => (
            "Structure59",
            "structure59-output",
            VERIFIED_STRUCTURE_PREFIX_CASES,
            [42, 5],
            VERIFIED_STRUCTURE_RESPONSES_SHA256,
        ),
    };
    let item = receipt["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["group"] == group)
        .unwrap();
    assert_eq!(number(item, "verified_cases"), count as u64);
    assert_eq!(item["verified_indices"], json!([0, count - 1]));
    assert_eq!(
        item["all_verified_records_follow_full_primary_owned_banks_RAM_System_context_policy_MXCSR_assertions"],
        true
    );
    assert_eq!(item["responses_sha256"], responses_sha);
    let responses_path = receipt_path
        .parent()
        .unwrap()
        .join(directory)
        .join("responses.jsonl");
    let responses = fs::read(&responses_path).unwrap();
    assert_eq!(sha256(&responses), responses_sha);
    let verified: Vec<Value> = std::str::from_utf8(&responses)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| {
            record
                .get("classification")
                .and_then(Value::as_str)
                .is_some()
        })
        .collect();
    assert_eq!(verified.len(), count);
    let mut observed_counts = [0; 2];
    for (index, record) in verified.iter().enumerate() {
        assert_eq!(number(record, "run_index"), index as u64);
        match record["classification"].as_str().unwrap() {
            "completed" => observed_counts[0] += 1,
            "fault" => observed_counts[1] += 1,
            other => panic!("unreviewed checked prefix outcome {other}"),
        }
    }
    assert_eq!(observed_counts, wanted_counts);
    // Keep prior observations separate. None of these counts seed a new run.
    json!({"receipt_sha256":VERIFIED_PREFIX_RECEIPT_SHA256,"item":item,
        "responses_sha256":responses_sha,"source20_binary_sha256":SOURCE20_BINARY_SHA256,
        "compiler_fingerprint":receipt["compiler_fingerprint"],"source20_manifest_sha256":SOURCE20_MANIFEST_SHA256,
        "same_binary_full_group_pass":false})
}

const FRAME_HEADER: usize = 256;
const PRIMARY_BYTES: usize = 784;
const PRIMARY_V: usize = 264;
const SVCR_OFFSET: usize = 56;
const TPIDR2_OFFSET: usize = 64;
const FPMR_OFFSET: usize = 72;
const FRAME_VALID_OFFSET: usize = 44;
const REQUIRED_COMPONENTS: u32 = 199;
const RAM_BYTES: usize = 8192;
const ADDRESS_BITS: u8 = 39;

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn number(value: &Value, field: &str) -> u64 {
    value[field].as_u64().unwrap()
}
pub(super) fn frame_load(frame: &[u8], registers: &mut GuestState, scalable: &mut ScalableState) {
    assert_eq!(&frame[..8], b"STELASV1");
    assert_eq!(u32_at(frame, 8), 1);
    assert_eq!(u32_at(frame, 12), FRAME_HEADER as u32);
    assert_eq!(u64_at(frame, 16), frame.len() as u64);
    assert_eq!(u32_at(frame, FRAME_VALID_OFFSET), REQUIRED_COMPONENTS);
    assert_eq!(u64_at(frame, SVCR_OFFSET), 1);
    assert_eq!(scalable.mode(), ScalableMode::new(true, false));
    let primary = &frame[FRAME_HEADER..FRAME_HEADER + PRIMARY_BYTES];
    for (index, value) in registers.x.iter_mut().enumerate() {
        *value = u64_at(primary, index * 8);
    }
    registers.sp = u64_at(primary, 248);
    registers.nzcv = u32_at(primary, 256);
    registers.reserved = u32_at(primary, 260);
    registers.fpcr = u32_at(primary, 776);
    registers.fpsr = u32_at(primary, 780);
    let length = scalable.vector_length().bytes();
    let mut offset = FRAME_HEADER + PRIMARY_BYTES;
    for index in 0..32 {
        let z = &frame[offset..offset + length];
        assert_eq!(
            &primary[PRIMARY_V + index * 16..PRIMARY_V + (index + 1) * 16],
            &z[..16]
        );
        scalable.write_z(registers, index as u8, z).unwrap();
        offset += length;
    }
    for index in 0..16 {
        scalable
            .write_predicate(index, &frame[offset..offset + length / 8])
            .unwrap();
        offset += length / 8;
    }
    // FFR is diagnostic in the original packet, but the software owner has it:
    // preserve/check its exact supplied bytes without claiming an ARM observation.
    scalable
        .write_ffr(&frame[offset..offset + length / 8])
        .unwrap();
    scalable.set_tpidr2_el0(u64_at(frame, TPIDR2_OFFSET));
    scalable.set_fpmr(u64_at(frame, FPMR_OFFSET));
}

pub(super) struct MxcsrRestore(u32);
impl MxcsrRestore {
    pub(super) fn set(value: u32) -> Self {
        assert!([0x1f80, 0x3f80, 0x5f80, 0x7f80, 0x1fa5].contains(&value));
        let previous = read_mxcsr();
        // SAFETY: the four retained inputs use mandatory x86 SSE control bits.
        unsafe {
            std::arch::asm!("ldmxcsr [{p}]", p=in(reg)&value, options(nostack,preserves_flags,readonly))
        };
        Self(previous)
    }
}
impl Drop for MxcsrRestore {
    fn drop(&mut self) {
        // SAFETY: exact prior host value is restored, including on assertion unwind.
        unsafe {
            std::arch::asm!("ldmxcsr [{p}]", p=in(reg)&self.0, options(nostack,preserves_flags,readonly))
        };
    }
}
pub(super) fn read_mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: writes exactly one live u32 and changes no host control.
    unsafe {
        std::arch::asm!("stmxcsr [{p}]",p=in(reg)&mut value,options(nostack,preserves_flags))
    };
    value
}
pub(super) fn fixed_at_39(f: &Fixture, alignment: bool) -> FixedProcessMemoryControls {
    // SAFETY: reuse the fixture's actual retained pinned code/data views and
    // the same Arc domain. No new raw writer, substitute backing or RX claim.
    let source = unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&f.domain)) }
        .expect("fresh serialized fixture source generation");
    FixedProcessMemoryControls::new_with_identification(
        Arc::clone(&f.ids),
        SCTLR_NATIVE_NORMAL_WB | if alignment { SCTLR_SP_ALIGNMENT_EL0 } else { 0 },
        64 - u64::from(ADDRESS_BITS),
        ADDRESS_BITS,
        source,
    )
    .unwrap()
}

pub(super) fn retain_raw(transcript: &mut fs::File, index: usize, f: &Fixture, actual: &Value) {
    // This observation is flushed before outcome/state assertions, so a failed
    // comparison retains the actual native terminal and complete owned outputs.
    writeln!(
        transcript,
        "{}",
        json!({"phase":"raw_terminal", "run_index":index,
        "actual":actual,"identity":format!("{:?}",f.prepared.identity()),
        "source_map":format!("{:?}",f.prepared.source_map()),
        "primary":format!("{:?}",f.registers),"owned_scalable":format!("{:?}",f.scalable),
        "ram":f.storage.bytes(),"host_mxcsr":read_mxcsr()})
    )
    .unwrap();
    transcript.flush().unwrap();
}

#[test]
#[ignore = "requires the fixed reviewed PN packet and a fresh durable output path"]
fn qualified_pn164_retained_packet_contract() {
    run_packet(REVIEWED_MANIFEST, 164, [112, 36, 8, 0, 8], false, false);
}

#[test]
#[ignore = "requires the exact retained original128 packet and a fresh durable output path"]
fn qualified_pn128_exact_retained_originals() {
    run_packet(ORIGINAL128_MANIFEST, 128, [128, 0, 0, 0, 0], true, false);
}

#[test]
#[ignore = "requires fixed PN164 inputs, checked source20 prefix evidence and fresh output"]
fn qualified_pn164_remaining_tail_148_through_163() {
    run_packet(
        REVIEWED_MANIFEST,
        PN_TAIL_END_EXCLUSIVE,
        [0, 0, 8, 0, 8],
        false,
        true,
    );
}

fn run_packet(
    reviewed_manifest: &str,
    runs: usize,
    expected_counts: [usize; 5],
    originals: bool,
    tail_only: bool,
) {
    let packet = std::env::var("STELA_PN_PACKET").unwrap();
    let packet = Path::new(&packet);
    let manifest_bytes = fs::read(packet.join("manifest.json")).unwrap();
    assert_eq!(sha256(&manifest_bytes), reviewed_manifest);
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    for (name, identity) in manifest["files"].as_object().unwrap() {
        let data = fs::read(packet.join(name)).unwrap();
        assert_eq!(data.len() as u64, number(identity, "bytes"));
        assert_eq!(sha256(&data), identity["sha256"].as_str().unwrap());
    }
    assert_eq!(number(&manifest, "runs"), runs as u64);
    assert_eq!(manifest["target_cpu"], "x86_64-baseline+atomic-load16");
    assert_eq!(number(&manifest, "ram_bytes"), RAM_BYTES as u64);
    let rows: Vec<Value> =
        serde_json::from_slice(&fs::read(packet.join("cases.json")).unwrap()).unwrap();
    let inputs = fs::read(packet.join("inputs.bin")).unwrap();
    let expected = fs::read(packet.join("expected-frames.bin")).unwrap();
    let ram = fs::read(packet.join("ram-input.bin")).unwrap();
    let wanted_ram = fs::read(packet.join("expected-ram.bin")).unwrap();
    assert_eq!(rows.len(), runs);
    let selection = if tail_only {
        assert_eq!(runs, PN_TAIL_END_EXCLUSIVE);
        assert!(!originals);
        PN_TAIL_START..PN_TAIL_END_EXCLUSIVE
    } else {
        0..runs
    };
    let executed_rows = selection.len();
    let prior_checked_prefix = tail_only.then(|| bind_checked_prefix(CheckedPrefixCohort::Pn164));
    let original_frames = originals.then(|| fs::read(packet.join("original-frames.bin")).unwrap());
    let output = std::env::var("STELA_PN_OUTPUT").unwrap();
    fs::create_dir(&output).unwrap();
    let mut transcript = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(Path::new(&output).join("responses.jsonl"))
        .unwrap();
    let mut counts = [0_usize; 5]; // completed, fault, entry decline, source refusal, constructor refusal
    for (index, row) in rows
        .iter()
        .enumerate()
        .skip(selection.start)
        .take(executed_rows)
    {
        assert_eq!(number(row, "run_index"), index as u64);
        assert_eq!(number(row, "required"), u64::from(REQUIRED_COMPONENTS));
        let bytes = number(row, "svl_bytes") as usize;
        let source_hex = row["source_hex"].as_str().unwrap();
        let source: Vec<u8> = source_hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(source.len() % 4, 0);
        let words: Vec<u32> = source
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        assert_eq!(words.last(), Some(&RET_X30));
        let target = TargetCpu::AtomicLoad16;
        let mode = ScalableMode::new(true, false);
        let mut f = Fixture::new_program_at_with_lower_bits(
            &words,
            number(row, "source_base"),
            number(&manifest, "ram_address"),
            bytes,
            target,
            target,
            None,
            1,
            mode,
            ADDRESS_BITS,
        );
        let length = VectorLength::from_bytes(bytes).unwrap();
        let profile = ScalableProfile::new_with_features(
            length,
            mode,
            ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
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
        let frame_start = number(row, "frame_offset") as usize;
        let frame_end = frame_start + number(row, "frame_bytes") as usize;
        frame_load(
            &inputs[frame_start..frame_end],
            &mut f.registers,
            &mut f.scalable,
        );
        let ram_offset = row
            .get("ram_input_offset")
            .map_or(0, |v| v.as_u64().unwrap() as usize);
        let row_ram = &ram[ram_offset..ram_offset + RAM_BYTES];
        // SAFETY: no execution/reservation is live; this is initial private RAM setup.
        unsafe { f.storage.write_bytes(row_ram) };
        let before_registers = f.registers.clone();
        let before_scalable = format!("{:?}", f.scalable);
        let mut wanted_registers = f.registers.clone();
        let mut wanted_scalable = f.scalable.clone();
        frame_load(
            &expected[frame_start..frame_end],
            &mut wanted_registers,
            &mut wanted_scalable,
        );
        let alignment = row["policy"]["effective_sp_alignment"].as_bool().unwrap();
        f.controls = fixed_at_39(&f, alignment);
        *f.memory.policy_mut() = MemoryControls::new(
            LowerAddressProfile::new(ADDRESS_BITS, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let suppression = row["policy"]["implementation_profile"] == "StreamingSveTagSuppression";
        let lengths = [16, 32, 64, 128, 256].map(|bytes| VectorLength::from_bytes(bytes).unwrap());
        let implementation = Implementation::declared_sca16(
            &lengths,
            if suppression {
                MemoryImplementationProfile::StreamingSveTagSuppression
            } else {
                MemoryImplementationProfile::ScalableTagChecks
            },
        );
        let host = number(row, "caller_mxcsr") as u32;
        let _restore = MxcsrRestore::set(host);
        let classification;
        let actual;
        if suppression {
            assert!(matches!(
                implementation,
                Err(scalable_controls::Error::UnsupportedImplementationProfile)
            ));
            classification = "constructor_refusal";
            actual = json!({"error":"UnsupportedImplementationProfile","native_executed":false});
            counts[4] += 1;
            retain_raw(&mut transcript, index, &f, &actual);
            assert_eq!(f.registers, before_registers);
            assert_eq!(format!("{:?}", f.scalable), before_scalable);
            assert_eq!(f.storage.bytes(), row_ram);
        } else {
            let access = ScalableControlOwner::new_declared_el10(
                &f.ids,
                Readbacks {
                    cpacr_el1: ALL_ACCESS,
                    smcr_el1: (bytes / 16 - 1) as u64,
                },
                implementation.unwrap(),
            )
            .unwrap();
            assert!(
                f.ids
                    .same_snapshot(f.controls.identification_snapshot().unwrap())
            );
            let policy = *f.memory.policy_mut();
            let pointers = (f.context.memory, f.context.scalable, f.context.system);
            let system = f.system.clone();
            // SAFETY: finite retained source, one actual Snapshot/domain and pinned
            // fixture storage. The canonical entry owns qualification/finalization.
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
            let exit = result.unwrap();
            match row["expected_exit"]["kind"].as_str().unwrap() {
                "completed" => {
                    assert_eq!(exit, ScalableLeafExit::Returned);
                    classification = "completed";
                    counts[0] += 1;
                }
                "declined" => {
                    assert_eq!(
                        exit,
                        ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
                    );
                    classification = "entry_declined";
                    counts[2] += 1;
                }
                "fault" => {
                    let wanted = &row["expected_exit"];
                    let status = match wanted["fault_kind"].as_str().unwrap() {
                        "StackAlignment" => MemoryStatus::StackAlignment,
                        "Translation" => MemoryStatus::Translation,
                        other => panic!("unreviewed fault {other}"),
                    };
                    assert_eq!(
                        exit,
                        ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
                            status,
                            address: GuestAddress(number(wanted, "address")),
                            pc: GuestAddress(number(wanted, "pc")),
                            completed_bytes: number(wanted, "completed_bytes")
                        })
                    );
                    classification = "fault";
                    counts[1] += 1;
                }
                other => panic!("unreviewed outcome {other}"),
            }
            assert_eq!(*f.memory.policy_mut(), policy);
            assert_eq!(
                (f.context.memory, f.context.scalable, f.context.system),
                pointers
            );
            assert_eq!(f.system, system);
            assert_eq!(f.registers, wanted_registers, "row {index} primary");
            assert_eq!(
                format!("{:?}", f.scalable),
                format!("{wanted_scalable:?}"),
                "row {index} all owned banks"
            );
            let offset = number(row, "ram_offset") as usize;
            assert_eq!(
                f.storage.bytes(),
                wanted_ram[offset..offset + RAM_BYTES],
                "row {index} complete RAM"
            );
        }
        if let Some(frames) = &original_frames {
            compare_original_valid(&frames[frame_start..frame_end], &f);
        }
        assert_eq!(read_mxcsr(), host);
        let record = json!({"run_index":index,"name":row["name"],"classification":classification,
            "original_expected_exit":row["expected_exit"],"actual":actual,
            "identity":format!("{:?}",f.prepared.identity()),"source_map":format!("{:?}",f.prepared.source_map()),
            "primary_sha256":sha256(format!("{:?}",f.registers).as_bytes()),
            "owned_banks_sha256":sha256(format!("{:?}",f.scalable).as_bytes()),"ram_sha256":sha256(&f.storage.bytes()),
            "host_mxcsr":host});
        writeln!(transcript, "{}", record).unwrap();
        transcript.flush().unwrap();
    }
    assert_eq!(counts, expected_counts);
    fs::write(Path::new(&output).join("report.json"),serde_json::to_vec_pretty(&json!({
        "passed":true,"input_packet_rows":runs,"rows":executed_rows,"executed_indices_inclusive":[selection.start,selection.end-1],
        "tail_only":tail_only,"prior_checked_prefix":prior_checked_prefix,"same_binary_full_group_pass":!tail_only,
        "qualified_entry_attempts":executed_rows-counts[4],"native_entries":counts[0]+counts[1],
        "completed":counts[0],"fault":counts[1],"entry_declined":counts[2],"source_refusal":counts[3],"constructor_refusal":counts[4],
        "exact_prior_entry_expectations_checked":executed_rows-counts[3]-counts[4],"changed_or_unreachable_prior_entry_expectations":counts[3]+counts[4],
        "exact_original_valid_mask_199_rows_checked":if originals { runs } else { 0 },
        "packet_manifest_sha256":reviewed_manifest,
        "scope":"bounded current qualified-owner/model gate; no original recapture, timing or coverage admission"
    })).unwrap()).unwrap();
}

fn compare_original_valid(frame: &[u8], f: &Fixture) {
    assert_eq!(
        u32_at(frame, FRAME_VALID_OFFSET) & REQUIRED_COMPONENTS,
        REQUIRED_COMPONENTS
    );
    let mut primary = GuestState::default();
    let mut state = f.scalable.clone();
    frame_load(frame, &mut primary, &mut state);
    assert_eq!(f.registers, primary, "retained original primary mask");
    let length = f.scalable.vector_length().bytes();
    for index in 0..32 {
        let mut actual = vec![0; length];
        let mut wanted = vec![0; length];
        f.scalable.read_z(&f.registers, index, &mut actual).unwrap();
        state.read_z(&primary, index, &mut wanted).unwrap();
        assert_eq!(actual, wanted, "retained original Z{index}");
    }
    for index in 0..16 {
        let mut actual = vec![0; length / 8];
        let mut wanted = vec![0; length / 8];
        f.scalable.read_predicate(index, &mut actual).unwrap();
        state.read_predicate(index, &mut wanted).unwrap();
        assert_eq!(actual, wanted, "retained original P{index}");
    }
    assert_eq!(f.scalable.mode().svcr(), u64_at(frame, SVCR_OFFSET));
    assert_eq!(f.scalable.tpidr2_el0(), u64_at(frame, TPIDR2_OFFSET));
}
