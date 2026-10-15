//! Exact retained ARM subjects through the current qualified process entry.
//! Captured control/memory scopes remain separate from the current declared CPU.
use super::{Fixture, ScalableLeafExit, TargetCpu, stores::Frame};
use crate::system::state::SystemState;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};
use stela_compiler::{aarch64::scalable::ScalableMode, extended};

const RET_X30: u32 = 0xd65f_03c0;
const PRIMARY: u32 = 1;
const Z: u32 = 2;
const P: u32 = 4;
const FFR: u32 = 8;
const ZA: u32 = 16;
const ZT0: u32 = 32;
const SVCR: u32 = 64;
const TPIDR2: u32 = 128;
const FPMR: u32 = 256;
const ALL_COMPONENTS: u32 = PRIMARY | Z | P | FFR | ZA | ZT0 | SVCR | TPIDR2 | FPMR;
const RAM_BYTES: usize = 8192;
const FIXED_VECTOR_BYTES: usize = stela_compiler::aarch64::scalable::VECTOR_CHUNK_BYTES;
const CODE_PAGE_BYTES: usize = 4096;

#[derive(Deserialize)]
struct Mode {
    streaming: bool,
    za: bool,
}
#[derive(Deserialize, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Comparison {
    #[default]
    Original,
    ActiveSpOracleDiscrepancy,
    EmptySpImplementationChoice,
}
#[derive(Deserialize)]
struct CodePage {
    guest_base: u64,
    original_pre: Vec<u8>,
    original_post: Vec<u8>,
    native_pre: Vec<u8>,
    native_pre_sha256: String,
}
#[derive(Deserialize)]
struct OriginalCase {
    row_id: String,
    canonical_id: String,
    word: u32,
    source_pc: u64,
    ram_address: u64,
    svl_bytes: usize,
    mode: Mode,
    source_lower_bits: u8,
    original_valid_components: u32,
    required_components: u32,
    initial: Frame,
    original: Value,
    ram: Vec<u8>,
    original_ram: Vec<u8>,
    original_fault: Option<Value>,
    provenance: Value,
    #[serde(default)]
    comparison: Comparison,
    #[serde(default)]
    expected_native_exit: Option<Value>,
    #[serde(default)]
    expected_native_ram: Option<Vec<u8>>,
    #[serde(default)]
    code_page: Option<CodePage>,
    #[serde(default)]
    initial_pstate_misc: Option<u64>,
}

fn append(stream: &mut File, value: &Value) {
    serde_json::to_writer(&mut *stream, value).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.sync_all().unwrap();
}

fn compare_original(case: &OriginalCase, actual: &Value, svcr: u64) {
    let mask = case.required_components;
    assert_eq!(mask & !ALL_COMPONENTS, 0, "unknown original component mask");
    assert_ne!(mask & PRIMARY, 0, "original primary state is required");
    assert_eq!(
        case.original_valid_components & mask,
        mask,
        "requested original bank was not observed"
    );
    // Reserved/header values are copied fixture metadata, not observed
    // architectural components. Full native canaries check them separately.
    for key in ["x", "sp", "nzcv", "fpcr", "fpsr"] {
        assert_eq!(
            actual[key], case.original[key],
            "{} original primary {key}",
            case.row_id
        );
    }
    // PRIMARY includes all V aliases even if a future observer omits upper Z.
    let actual_v: Vec<_> = actual["z"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| Value::Array(z.as_array().unwrap()[..FIXED_VECTOR_BYTES].to_vec()))
        .collect();
    assert_eq!(
        Value::Array(actual_v),
        case.original["v"],
        "{} original V aliases",
        case.row_id
    );
    for (component, key) in [
        (Z, "z"),
        (P, "p"),
        (FFR, "ffr"),
        (ZA, "za"),
        (ZT0, "zt0"),
        (TPIDR2, "tpidr2"),
        (FPMR, "fpmr"),
    ] {
        if mask & component != 0 {
            assert_eq!(
                actual[key], case.original[key],
                "{} original {key}",
                case.row_id
            );
        }
    }
    if mask & SVCR != 0 {
        assert_eq!(
            json!(svcr),
            case.original["svcr"],
            "{} original SVCR",
            case.row_id
        );
    }
}

fn typed_exit(exit: &Result<ScalableLeafExit, super::ScalableExecutionError>) -> Value {
    match exit {
        Ok(ScalableLeafExit::Returned) => json!({"kind":"returned"}),
        Ok(ScalableLeafExit::MemoryFault(fault)) => json!({"kind":"fault",
            "status":format!("{:?}",fault.status),"address":fault.address.0,
            "pc":fault.pc.0,"completed_bytes":fault.completed_bytes}),
        other => json!({"kind":"unexpected","detail":format!("{other:?}")}),
    }
}

#[test]
#[ignore = "explicit reviewed saved-original selector with declared comparison limits"]
fn qualified_store_retained_original_subset() {
    let fixture_path = std::env::var("STELA_STORE_ORIGINAL_FIXTURES").unwrap();
    let expected_rows: usize = std::env::var("STELA_STORE_ORIGINAL_ROWS")
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (1..=820).contains(&expected_rows),
        "bounded saved selector required"
    );
    let cases: Vec<OriginalCase> = BufReader::new(File::open(fixture_path).unwrap())
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect();
    assert_eq!(cases.len(), expected_rows);
    let output = std::env::var("STELA_STORE_ORIGINAL_OUTPUT").unwrap();
    let output = Path::new(&output);
    std::fs::create_dir(output).expect("fresh immutable result directory required");
    let mut stream = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("observations.jsonl"))
        .unwrap();
    let mut original_matches = 0_usize;
    let mut active_sp_discrepancies = 0_usize;
    let mut empty_sp_choices = 0_usize;
    for (index, case) in cases.iter().enumerate() {
        assert!(
            case.mode.streaming && case.mode.za,
            "saved selector owns SM=1 ZA=1"
        );
        assert_eq!(case.ram.len(), RAM_BYTES);
        assert_eq!(case.original_ram.len(), RAM_BYTES);
        let target = TargetCpu::Cx16;
        let mode = ScalableMode::new(case.mode.streaming, case.mode.za);
        let mut fixture = if let Some(page) = &case.code_page {
            assert_eq!(
                page.original_pre, page.original_post,
                "saved original code page changed"
            );
            assert_eq!(page.original_pre.len(), CODE_PAGE_BYTES);
            assert_eq!(
                page.guest_base,
                case.source_pc & !(CODE_PAGE_BYTES as u64 - 1)
            );
            Fixture::new_program_at_with_original_code_page(
                &[case.word, RET_X30],
                case.source_pc,
                case.ram_address,
                case.svl_bytes,
                target,
                target,
                None,
                2,
                mode,
                case.source_lower_bits,
                &page.original_pre,
            )
        } else {
            Fixture::new_program_at_with_lower_bits(
                &[case.word, RET_X30],
                case.source_pc,
                case.ram_address,
                case.svl_bytes,
                target,
                target,
                None,
                2,
                mode,
                case.source_lower_bits,
            )
        };
        // No MOV prefix is added: every architectural register, including X3,
        // comes from the exact subject input. Only the observer SVC becomes RET.
        case.initial.import(&mut fixture);
        if let Some(pstate_misc) = case.initial_pstate_misc {
            // Actual saved SPSR projects the subject's EL0t mode and DAIF;
            // NZCV already came from the observed pre-frame. Inactive SP and
            // EL1 storage remain private canaries, not original observations.
            fixture.system = SystemState::new(pstate_misc, 0, *fixture.system.el1_registers())
                .expect("captured subject PSTATE must be representable");
        }
        let subject_pstate = fixture.system.pstate(&fixture.registers);
        // SAFETY: initialize before the first domain operation, with no live
        // reservation, publication, reader or competing writer.
        unsafe { fixture.storage.write_bytes(&case.ram) };
        if let Some(page) = &case.code_page {
            assert_eq!(fixture.storage.code_page(), page.native_pre);
            assert_eq!(stela_core::sha256(&page.native_pre), page.native_pre_sha256);
        }
        let exit = fixture.execute();
        let normalized_exit = typed_exit(&exit);
        let actual = Frame::observe(&fixture);
        let actual_value = serde_json::to_value(&actual).unwrap();
        let actual_ram = fixture.storage.bytes();
        let native_code_page = case.code_page.as_ref().map(|_| fixture.storage.code_page());
        let identity = fixture.prepared.identity();
        let emitted = extended::prepare_leaf(
            fixture.prepared.source(),
            identity.guest_base,
            identity.profile,
            target,
        )
        .unwrap();
        assert_eq!(
            stela_core::sha256(&emitted.native.x86_64_code),
            identity.native_sha256
        );
        assert_eq!(
            emitted.native.source_map.as_slice(),
            fixture.prepared.source_map()
        );
        assert_eq!(emitted.memory_requirements, identity.memory_requirements);
        assert_eq!(
            emitted.execution_requirements,
            identity.execution_requirements
        );
        let filename = format!("{index:03}-{:08x}.bin", case.word);
        let mut native_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(&filename))
            .unwrap();
        native_file.write_all(&emitted.native.x86_64_code).unwrap();
        native_file.sync_all().unwrap();
        append(
            &mut stream,
            &json!({
                "row_id":case.row_id,"canonical_id":case.canonical_id,"source_word":case.word,
                "source_pc":case.source_pc,"ram_address":case.ram_address,"svl_bytes":case.svl_bytes,
                "source_lower_bits":case.source_lower_bits,"original_valid_components":case.original_valid_components,
                "native_subject_pstate":subject_pstate,"native_post_pstate":fixture.system.pstate(&fixture.registers),
                "required_original_components":case.required_components,"original_provenance":case.provenance,
                "original_comparison_policy":format!("{:?}",case.comparison),"saved_original_fault":case.original_fault,
                "native_framing":"Exact subject word+RET, no MOV prefix; original word+SVC at same numeric PC. Each code page compares to its own preimage.",
                "native_exit":normalized_exit,"raw_native_exit":format!("{exit:?}"),"frame":actual_value,
                "ram":actual_ram,"native_code_page":native_code_page,
                "native_file":filename,"native_sha256":identity.native_sha256,
                "source_sha256":identity.source_sha256,"compiler_source_sha256":identity.compiler_source_sha256,
                "source_map":emitted.native.source_map.iter().map(|(pc,offset)|(pc.0,*offset)).collect::<Vec<_>>(),
                "memory_requirements":format!("{:?}",identity.memory_requirements),
                "per_pc_execution_requirements":format!("{:?}",identity.execution_requirements),
                "original_scope":case.provenance["original_memory_scope"],
                "current_scope":"Fresh declared WB/SCA16 same-domain entry; captured controls do not mint production authority."
            }),
        );
        let expected_exit = case
            .expected_native_exit
            .clone()
            .unwrap_or_else(|| json!({"kind":"returned"}));
        assert_eq!(
            normalized_exit, expected_exit,
            "{} exact native service outcome",
            case.row_id
        );
        match case.comparison {
            Comparison::Original => {
                compare_original(case, &actual_value, fixture.scalable.mode().svcr());
                assert_eq!(
                    actual_ram, case.original_ram,
                    "{} all original RAM",
                    case.row_id
                );
                original_matches += 1;
            }
            Comparison::ActiveSpOracleDiscrepancy => {
                // Actual EL0t/SA0=1/P7-active/SP%16=3 completed and wrote two
                // bytes. Source requires a fault: native follows source/model;
                // the unresolved original discrepancy remains explicit.
                assert_eq!(normalized_exit["status"], "StackAlignment");
                assert_ne!(case.original_ram, case.ram);
                active_sp_discrepancies += 1;
            }
            Comparison::EmptySpImplementationChoice => {
                // Original false-choice completion is allowed. This fixed
                // compiler declares CHECKSPNONEACTIVE=true and must fault.
                assert_eq!(normalized_exit["status"], "StackAlignment");
                assert_eq!(case.original_ram, case.ram);
                empty_sp_choices += 1;
            }
        }
        // Full current-native canaries include FFR even when the ARM observer
        // lacks that component. They never increase original validity masks.
        assert_eq!(
            actual, case.initial,
            "{} full native register canaries",
            case.row_id
        );
        if let Some(expected_ram) = &case.expected_native_ram {
            assert_eq!(
                &actual_ram, expected_ram,
                "{} source/model native RAM",
                case.row_id
            );
        } else {
            assert_eq!(
                case.comparison,
                Comparison::Original,
                "model-only controls require explicit native RAM expectation"
            );
        }
        if let Some(page) = &case.code_page {
            assert_eq!(
                native_code_page.as_ref().unwrap(),
                &page.native_pre,
                "{} native code unchanged against its own RET-framed preimage",
                case.row_id
            );
        }
        append(
            &mut stream,
            &json!({"row_id":case.row_id,"native_source_check_passed":true,
            "original_comparison":if case.comparison==Comparison::Original {"matched"} else {"not_claimed"},
            "original_comparison_policy":format!("{:?}",case.comparison),
            "original_components":if case.comparison==Comparison::Original {case.required_components} else {0},
            "native_canary_components":ALL_COMPONENTS,"ram_bytes":RAM_BYTES,"native_entries":1}),
        );
    }
    assert_eq!(
        original_matches + active_sp_discrepancies + empty_sp_choices,
        cases.len()
    );
    append(
        &mut stream,
        &json!({"summary":true,"rows":cases.len(),"original_matches":original_matches,
        "unresolved_active_sp_oracle_discrepancies":active_sp_discrepancies,
        "empty_sp_implementation_choice_mismatches":empty_sp_choices,
        "all_originals_matched":active_sp_discrepancies==0 && empty_sp_choices==0,
        "native_entries":cases.len()}),
    );
}
