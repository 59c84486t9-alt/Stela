//! Opt-in reproduction of externally retained original MTE frames.
//!
//! Run the ignored test with STELA_MTE_ORIGINALS pointing to a hash-bound corpus
//! manifest and STELA_MTE_NATIVE_OUTPUT naming a fresh output directory. Original
//! captures and conversion scripts remain external; execution uses production
//! BlockRuntime, Execution, SystemState and MemoryThread without expected outputs.
#[path = "tag_memory_corpus/backend.rs"]
mod backend;
#[path = "tag_memory_corpus/provenance.rs"]
mod provenance;

use anyhow::{Context, Result, ensure};
use provenance::{Corpus, Expected, Input, ValidatedFrame, hex, state_bytes, unhex};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use stela_compiler::{
    GuestAddress, TargetCpu,
    block::{BlockProfile, ExitKind, SYSTEM_BLOCK_ABI},
};
use stela_core::sha256;
use stela_runtime::blocks::BlockRuntime;

const ADDRESS_SPACE: u64 = 1;
const INSTRUCTION_BYTES: usize = std::mem::size_of::<u32>();
const MOV_RAX_IMMEDIATE: [u8; 2] = [0x48, 0xb8];
const MOV_EDX_IMMEDIATE: u8 = 0xba;
const RET: u8 = 0xc3;
const ENTRY_SOURCE: &str = include_str!("tag_memory_corpus.rs");
const SHARED_SOURCES: &[(&str, &str)] = &[
    (
        "crates/stela-compiler/src/lib.rs",
        include_str!("../../../stela-compiler/src/lib.rs"),
    ),
    (
        "crates/stela-compiler/src/block.rs",
        include_str!("../../../stela-compiler/src/block.rs"),
    ),
    (
        "crates/stela-compiler/src/block/system.rs",
        include_str!("../../../stela-compiler/src/block/system.rs"),
    ),
    (
        "crates/stela-compiler/src/aarch64.rs",
        include_str!("../../../stela-compiler/src/aarch64.rs"),
    ),
    (
        "crates/stela-compiler/src/aarch64/tag_memory.rs",
        include_str!("../../../stela-compiler/src/aarch64/tag_memory.rs"),
    ),
    (
        "crates/stela-compiler/src/extended.rs",
        include_str!("../../../stela-compiler/src/extended.rs"),
    ),
    (
        "crates/stela-compiler/src/x86_64.rs",
        include_str!("../../../stela-compiler/src/x86_64.rs"),
    ),
    (
        "crates/stela-compiler/src/x86_64/block.rs",
        include_str!("../../../stela-compiler/src/x86_64/block.rs"),
    ),
    (
        "crates/stela-compiler/src/context.rs",
        include_str!("../../../stela-compiler/src/context.rs"),
    ),
    (
        "crates/stela-compiler/src/context/memory.rs",
        include_str!("../../../stela-compiler/src/context/memory.rs"),
    ),
    (
        "crates/stela-runtime/tests/blocks.rs",
        include_str!("../blocks.rs"),
    ),
    (
        "crates/stela-runtime/tests/blocks/tag_memory_corpus.rs",
        ENTRY_SOURCE,
    ),
    (
        "crates/stela-runtime/tests/blocks/tag_memory_corpus/provenance.rs",
        include_str!("tag_memory_corpus/provenance.rs"),
    ),
    (
        "crates/stela-runtime/tests/blocks/tag_memory_corpus/backend.rs",
        include_str!("tag_memory_corpus/backend.rs"),
    ),
    (
        "crates/stela-runtime/src/lib.rs",
        include_str!("../../src/lib.rs"),
    ),
    (
        "crates/stela-runtime/src/blocks.rs",
        include_str!("../../src/blocks.rs"),
    ),
    (
        "crates/stela-runtime/src/execution.rs",
        include_str!("../../src/execution.rs"),
    ),
    (
        "crates/stela-runtime/src/system.rs",
        include_str!("../../src/system.rs"),
    ),
    (
        "crates/stela-runtime/src/system/execution.rs",
        include_str!("../../src/system/execution.rs"),
    ),
    (
        "crates/stela-runtime/src/system/state.rs",
        include_str!("../../src/system/state.rs"),
    ),
    (
        "crates/stela-runtime/src/system/pstate.rs",
        include_str!("../../src/system/pstate.rs"),
    ),
    (
        "crates/stela-runtime/src/system/access.rs",
        include_str!("../../src/system/access.rs"),
    ),
    (
        "crates/stela-runtime/src/memory.rs",
        include_str!("../../src/memory.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/access.rs",
        include_str!("../../src/memory/access.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/backing.rs",
        include_str!("../../src/memory/backing.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/domain.rs",
        include_str!("../../src/memory/domain.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/domain/profile.rs",
        include_str!("../../src/memory/domain/profile.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/domain/tag_transfer.rs",
        include_str!("../../src/memory/domain/tag_transfer.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/monitor.rs",
        include_str!("../../src/memory/monitor.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/policy.rs",
        include_str!("../../src/memory/policy.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/tags.rs",
        include_str!("../../src/memory/tags.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/tag_store.rs",
        include_str!("../../src/memory/tag_store.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/tag_transfer.rs",
        include_str!("../../src/memory/tag_transfer.rs"),
    ),
    (
        "crates/stela-runtime/src/memory/tag_execution.rs",
        include_str!("../../src/memory/tag_execution.rs"),
    ),
];

// Historical frame semantics are reused only while these reached leaves remain identical.
const UNCHANGED_SEMANTIC_SOURCES: &[&str] = &[
    "crates/stela-compiler/src/aarch64/tag_memory.rs",
    "crates/stela-compiler/src/block/system.rs",
    "crates/stela-compiler/src/x86_64/block.rs",
    "crates/stela-compiler/src/context.rs",
    "crates/stela-compiler/src/context/memory.rs",
    "crates/stela-runtime/src/system/execution.rs",
    "crates/stela-runtime/src/system/state.rs",
    "crates/stela-runtime/src/system/pstate.rs",
    "crates/stela-runtime/src/system/access.rs",
    "crates/stela-runtime/src/memory/access.rs",
    "crates/stela-runtime/src/memory/backing.rs",
    "crates/stela-runtime/src/memory/domain/profile.rs",
    "crates/stela-runtime/src/memory/domain/tag_transfer.rs",
    "crates/stela-runtime/src/memory/monitor.rs",
    "crates/stela-runtime/src/memory/policy.rs",
    "crates/stela-runtime/src/memory/tags.rs",
    "crates/stela-runtime/src/memory/tag_store.rs",
    "crates/stela-runtime/src/memory/tag_transfer.rs",
    "crates/stela-runtime/src/memory/tag_execution.rs",
];

// These two reviewed deltas contain only a blank-line removal and safety docs.
// Every new differing byte identity still needs an explicit hash-bound review.
const NONSEMANTIC_REVIEW_PATHS: &[&str] = &[
    "crates/stela-compiler/src/context.rs",
    "crates/stela-runtime/src/memory/backing.rs",
];

fn source_hashes(source_root: &Path) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for (relative, compiled) in SHARED_SOURCES {
        let actual = source_root.join(relative);
        let identity = sha256(compiled.as_bytes());
        ensure!(
            sha256(&std::fs::read(&actual)?) == identity,
            "compiled source changed: {relative}"
        );
        hashes.insert((*relative).to_owned(), identity);
    }
    Ok(hashes)
}
fn integer(row: &Value, key: &str) -> Result<u64> {
    row[key]
        .as_u64()
        .with_context(|| format!("missing observed {key}"))
}
fn string<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .with_context(|| format!("missing observed {key}"))
}
fn compare(frame: &ValidatedFrame, expected: &Expected, observed: &Value) -> Result<&'static str> {
    let input = &frame.execution;
    ensure!(
        observed["case_id"] == input.input.case_id && observed["status"] == expected.status,
        "runtime identity/status mismatch"
    );
    ensure!(
        unhex(string(observed, "state_at_exit_hex")?)? == state_bytes(&input.registers),
        "native exit changed State before service"
    );
    ensure!(
        integer(observed, "exit_pc")? == input.input.instruction_pc
            && integer(observed, "recovered_word")? == u64::from(input.input.word),
        "runtime recovered a different original instruction"
    );
    ensure!(
        observed["source_recovery"] == "BlockRuntime_registered_region_shared_decoder"
            && observed["exit_kind"] == "System",
        "wrong recovery owner"
    );
    ensure!(
        integer(observed, "source_address_space")? == ADDRESS_SPACE
            && integer(observed, "source_generation")? > 0
            && integer(observed, "source_region_base")? == input.input.instruction_pc
            && integer(observed, "source_region_bytes")? == INSTRUCTION_BYTES as u64
            && integer(observed, "consumed_bytes")? == INSTRUCTION_BYTES as u64
            && integer(observed, "native_blocks_executed")? == 1,
        "runtime boundary identity mismatch"
    );
    ensure!(
        integer(observed, "next_pc")?
            == input.input.instruction_pc
                + if expected.status == "success" {
                    INSTRUCTION_BYTES as u64
                } else {
                    0
                },
        "runtime committed an incorrect continuation"
    );
    ensure!(
        observed["unrelated_system_state_preserved"] == true,
        "service changed unrelated owned SystemState"
    );
    ensure!(
        string(observed, "state_hex")? == expected.state_hex,
        "post-service full State differs"
    );
    if input.input.kind == "IRG" {
        let generation = input
            .controls
            .generation
            .context("missing captured IRG generation")?;
        ensure!(
            integer(observed, "rgsr_at_exit")? == generation.rgsr
                && integer(observed, "gcr_at_exit")? == generation.gcr
                && observed["rgsr"].as_u64() == expected.rgsr
                && observed["gcr"].as_u64() == expected.gcr
                && integer(observed, "memory_service_calls")? == 0,
            "IRG control/memory effects differ"
        );
        return Ok("IRG_exact_original_State_RGSR_GCR");
    }
    ensure!(
        observed["rgsr"] == observed["rgsr_at_exit"] && observed["gcr"] == observed["gcr_at_exit"],
        "memory service changed generation controls/state"
    );
    if let Some(generation) = input.controls.generation {
        ensure!(
            integer(observed, "rgsr_at_exit")? == generation.rgsr
                && integer(observed, "gcr_at_exit")? == generation.gcr,
            "memory service entry differs from captured generation controls"
        );
    }
    ensure!(
        unhex(string(observed, "ram_at_exit_hex")?)? == input.ram
            && unhex(string(observed, "tags_at_exit_hex")?)? == input.tags,
        "native exit changed RAM/tags before service"
    );
    if expected.status == "success" {
        ensure!(
            observed["fault"].is_null() && observed["progress"].is_null(),
            "invented successful fault/progress"
        );
    } else {
        ensure!(
            observed["fault"]["class"] == expected.status,
            "fault class differs"
        );
        if matches!(expected.status.as_str(), "permission" | "translation") {
            let access = &observed["fault"]["access"];
            ensure!(
                access["address"] == expected.original_fault["far"]
                    && access["tag_checked"] == false
                    && access["privileged"] == input.controls.privileged
                    && integer(access, "required_alignment")?
                        == stela_runtime::memory::tags::TAG_GRANULE_BYTES as u64,
                "fault access differs from original authority"
            );
        }
    }
    if expected.status == "data_alignment" {
        ensure!(
            observed["fault"]["address"] == expected.original_fault["far"],
            "data alignment address differs from raw FAR"
        );
    }
    if frame.comparison.sp_oracle_excluded {
        ensure!(
            integer(&observed["fault"], "stack_pointer")? == input.registers.sp,
            "SP policy fault pointer differs from original input"
        );
        ensure!(
            observed["progress"] == json!([0, 0, 0]),
            "SP policy fault made memory progress"
        );
        ensure!(
            unhex(string(observed, "ram_hex")?)? == input.ram
                && unhex(string(observed, "tags_hex")?)? == input.tags,
            "SP policy fault changed memory"
        );
        return Ok("SP_oracle_policy_excluded");
    }
    if observed["ram_hex"].as_str() == expected.ram_hex.as_deref()
        && observed["tags_hex"].as_str() == expected.tags_hex.as_deref()
    {
        return Ok("exact_original_State_RAM_tags");
    }
    ensure!(
        frame.comparison.permitted_unknown
            && observed["ram_hex"].as_str() == expected.allowed_ram_hex.as_deref()
            && observed["tags_hex"].as_str() == expected.allowed_tags_hex.as_deref(),
        "unpermitted memory differences"
    );
    Ok("allowed_unknown_prefix_different_from_original_choice")
}
fn prepare(
    runtime: &mut BlockRuntime,
    pc: u64,
    word: u32,
    output: &mut impl Write,
) -> Result<Value> {
    runtime.register_code(GuestAddress(pc), word.to_le_bytes().to_vec())?;
    let prepared = runtime.prepare(GuestAddress(pc))?;
    let manifest = &prepared.prepared.manifest;
    ensure!(
        prepared.analysis.source_bytes == INSTRUCTION_BYTES
            && manifest.source_map == [(GuestAddress(pc), 0)]
            && manifest.identity.abi == SYSTEM_BLOCK_ABI
            && manifest.identity.target_cpu == TargetCpu::Baseline.id(),
        "actual native identity/source map differs"
    );
    let native = std::fs::read(prepared.prepared.directory.join("native.bin"))?;
    let mut recipe = MOV_RAX_IMMEDIATE.to_vec();
    recipe.extend(pc.to_le_bytes());
    recipe.push(MOV_EDX_IMMEDIATE);
    recipe.extend((ExitKind::System as u32).to_le_bytes());
    recipe.push(RET);
    ensure!(
        native == recipe
            && sha256(&native) == manifest.native_sha256
            && manifest.native_bytes == native.len(),
        "actual System body differs from reviewed baseline recipe"
    );
    let entry = json!({
        "pc": pc,
        "word": word,
        "native_hex": hex(&native),
        "compiled": prepared.prepared,
        "instructions_including_RET": 3,
        "bytes_including_RET": native.len(),
    });
    serde_json::to_writer(&mut *output, &entry)?;
    writeln!(output)?;
    Ok(entry)
}
fn historical_bridge(
    corpus: &Corpus,
    runtime: &mut BlockRuntime,
    native: &mut impl Write,
    sources: &BTreeMap<String, String>,
) -> Result<Option<(Value, Value)>> {
    let Some(history) = &corpus.manifest.historical_full_bridge else {
        return Ok(None);
    };
    let receipt: Value = serde_json::from_slice(&corpus.read(&history.receipt)?)?;
    let inspection: Value = serde_json::from_slice(&corpus.read(&history.native_inspection)?)?;
    let review: Value = serde_json::from_slice(&corpus.read(&history.review)?)?;
    let ledger: Value = serde_json::from_slice(&corpus.read(&history.source_ledger)?)?;
    ensure!(
        receipt["passed"] == true && review["bridge_complete"] == true,
        "historical bridge is not independently accepted"
    );
    for (asset, key) in [
        (&history.receipt, "full_original_bridge"),
        (&history.source_ledger, "foundation_source_ledger"),
        (&history.native_inspection, "actual_native_inspection"),
    ] {
        ensure!(
            review["evidence"][key]["sha256"] == corpus.manifest.assets[asset].sha256,
            "historical review does not bind {key}"
        );
    }
    let original_sources = ledger["files"]
        .as_object()
        .context("missing historical source identity ledger")?;
    let current_review: Value =
        serde_json::from_slice(&corpus.read(&history.current_source_review)?)?;
    ensure!(
        current_review["kind"] == "stela_mte_current_source_equivalence"
            && current_review["passed"] == true
            && current_review["historical_source_ledger_sha256"]
                == corpus.manifest.assets[&history.source_ledger].sha256
            && current_review["compiler_source_sha256"]
                == sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "current source equivalence review does not bind this compilation"
    );
    for (path, identity) in sources.iter().filter(|(path, _)| path.contains("/src/")) {
        let original = original_sources
            .get(path)
            .and_then(Value::as_str)
            .with_context(|| format!("historical source ledger omits {path}"))?;
        if original != identity {
            if NONSEMANTIC_REVIEW_PATHS.contains(&path.as_str()) {
                let delta = &current_review["nonsemantic_source_deltas"][path];
                let diff = delta["diff"]
                    .as_str()
                    .context("missing archived nonsemantic diff")?;
                ensure!(
                    delta["historical_sha256"] == original
                        && delta["current_sha256"] == *identity
                        && !diff.is_empty()
                        && delta["diff_sha256"] == sha256(diff.as_bytes()),
                    "nonsemantic source review does not bind {path}"
                );
            } else {
                ensure!(
                    !UNCHANGED_SEMANTIC_SOURCES.contains(&path.as_str())
                        && current_review["reviewed_parent_sources_sha256"][path] == *identity,
                    "historical semantics cannot be reused for changed source: {path}"
                );
            }
        }
    }
    let mut inspected_entries = BTreeMap::new();
    for entry in inspection["entries"]
        .as_array()
        .context("missing historical inspected entries")?
    {
        let key = (
            integer(entry, "pc")?,
            u32::try_from(integer(entry, "word")?)?,
        );
        ensure!(
            inspected_entries.insert(key, entry).is_none(),
            "duplicate inspected source identity"
        );
    }
    let entries = corpus.read(&history.native_entries)?;
    let mut seen = BTreeSet::new();
    let mut words = BTreeSet::new();
    let mut old_fingerprint = None;
    for line in entries
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let old: Value = serde_json::from_slice(line)?;
        let pc = integer(&old, "pc")?;
        let word = u32::try_from(integer(&old, "word")?)?;
        ensure!(
            seen.insert((pc, word)),
            "duplicate historical source identity"
        );
        words.insert(word);
        let inspected = inspected_entries
            .get(&(pc, word))
            .context("historical body absent from accepted inspection")?;
        ensure!(
            inspected["native_sha256"] == old["compiled"]["manifest"]["native_sha256"]
                && inspected["source_map"] == old["compiled"]["manifest"]["source_map"]
                && inspected["native_sha256"] == sha256(&unhex(string(&old, "native_hex")?)?),
            "historical native bytes/map differ from accepted actual inspection"
        );
        corpus.validate_original_word(pc, word)?;
        let actual = prepare(runtime, pc, word, native)?;
        ensure!(
            actual["native_hex"] == old["native_hex"]
                && actual["compiled"]["manifest"]["source_map"]
                    == old["compiled"]["manifest"]["source_map"]
                && old["compiled"]["manifest"]["identity"]["abi"] == SYSTEM_BLOCK_ABI
                && old["compiled"]["manifest"]["identity"]["target_cpu"]
                    == TargetCpu::Baseline.id(),
            "current emitted body does not preserve historical source/bytes/ABI"
        );
        let identity = old["compiled"]["manifest"]["identity"]["compiler_source_sha256"]
            .as_str()
            .context("missing historical fingerprint")?;
        ensure!(
            old_fingerprint
                .as_deref()
                .is_none_or(|prior| prior == identity),
            "historical fingerprint changed within corpus"
        );
        old_fingerprint = Some(identity.to_owned());
    }
    ensure!(
        inspection["unique_emitted_entries"].as_u64() == Some(seen.len() as u64)
            && inspected_entries.len() == seen.len(),
        "historical inspection entry count differs"
    );
    let counts = &receipt["counts"];
    let exact = integer(counts, "IRG_exact_original_State_RGSR_GCR")?
        + integer(counts, "exact_original_State_RAM_tags")?;
    let historical = json!({
        "provenance_distinct_original_frames": receipt["provenance_distinct_original_frames"],
        "exact_original_comparisons": exact,
        "counts": counts,
        "receipt_path": corpus.path(&history.receipt)?,
        "receipt_sha256": corpus.manifest.assets[&history.receipt].sha256,
        "compiler_source_sha256": old_fingerprint,
    });
    let current = json!({
        "compiler_source_sha256": sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "emitted_PC_word_entries": seen.len(),
        "unique_original_words": words.len(),
        "historical_native_entries_sha256": corpus.manifest.assets[&history.native_entries].sha256,
        "source_ledger_sha256": corpus.manifest.assets[&history.source_ledger].sha256,
        "review_sha256": corpus.manifest.assets[&history.review].sha256,
        "current_source_review_sha256": corpus.manifest.assets[&history.current_source_review].sha256,
        "historical_frame_execution_repeated": false,
        "scope": "compile-only actual source/map/body preservation; current native frame execution is reported separately",
    });
    Ok(Some((historical, current)))
}

#[test]
#[ignore = "requires an external hash-bound original MTE corpus and fresh output directory"]
fn tag_memory_original_corpus() -> Result<()> {
    let manifest = PathBuf::from(
        std::env::var_os("STELA_MTE_ORIGINALS")
            .context("set STELA_MTE_ORIGINALS to the external manifest")?,
    );
    let output = PathBuf::from(
        std::env::var_os("STELA_MTE_NATIVE_OUTPUT")
            .context("set STELA_MTE_NATIVE_OUTPUT to a fresh directory")?,
    );
    std::fs::create_dir(&output).context("native output directory must be fresh")?;
    let output = output.canonicalize()?;
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("missing compiled workspace root")?;
    let repository = source_root
        .ancestors()
        .find(|path| path.join(".git").exists())
        .context("cannot normalize compiled source to repository root")?;
    output
        .strip_prefix(repository)
        .context("native output must be within the repository")?;
    let sources = source_hashes(source_root)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_sha256 = sha256(&std::fs::read(&executable)?);
    let corpus = Corpus::load(&manifest)?;
    let mut runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE,
        output.join("runtime-cache"),
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    let mut native = BufWriter::new(std::fs::File::create_new(
        output.join("native-entries.jsonl"),
    )?);
    let history = historical_bridge(&corpus, &mut runtime, &mut native, &sources)?;
    let inputs = BufReader::new(std::fs::File::open(
        corpus.path(&corpus.manifest.normalized_inputs)?,
    )?)
    .lines();
    let mut expectations = BufReader::new(std::fs::File::open(
        corpus.path(&corpus.manifest.normalized_expected)?,
    )?)
    .lines();
    let mut observations = BufWriter::new(std::fs::File::create_new(
        output.join("observations.jsonl"),
    )?);
    let mut counts = BTreeMap::<String, u64>::new();
    let mut frames = 0;
    let mut case_ids = BTreeSet::new();
    for line in inputs {
        let input: Input = serde_json::from_str(&line?)?;
        let expected: Expected =
            serde_json::from_str(&expectations.next().context("missing expected frame")??)?;
        ensure!(
            case_ids.insert(input.case_id.clone()),
            "duplicate original case identity"
        );
        let frame = corpus.validate(input)?;
        corpus.validate_expected(&frame, &expected)?;
        prepare(
            &mut runtime,
            frame.execution.input.instruction_pc,
            frame.execution.input.word,
            &mut native,
        )?;
        let observed = backend::execute(&mut runtime, &frame.execution)?;
        let classification = compare(&frame, &expected, &observed)
            .with_context(|| format!("frame {}", frame.execution.input.case_id))?;
        *counts.entry(classification.into()).or_default() += 1;
        frames += 1;
        serde_json::to_writer(&mut observations, &observed)?;
        writeln!(observations)?;
    }
    ensure!(
        expectations.next().is_none() && frames == corpus.manifest.frame_count,
        "corpus row count differs"
    );
    native.flush()?;
    observations.flush()?;
    corpus.guard()?;
    ensure!(
        source_hashes(source_root)? == sources
            && sha256(&std::fs::read(&executable)?) == executable_sha256,
        "compiled sources/executable changed during reproduction"
    );
    let exact = counts
        .get("IRG_exact_original_State_RGSR_GCR")
        .copied()
        .unwrap_or(0)
        + counts
            .get("exact_original_State_RAM_tags")
            .copied()
            .unwrap_or(0);
    let mut artifacts = BTreeMap::new();
    for name in ["observations.jsonl", "native-entries.jsonl"] {
        let path = output.join(name);
        let bytes = std::fs::read(&path)?;
        artifacts.insert(
            name,
            json!({
                "path": path.strip_prefix(repository)?,
                "sha256": sha256(&bytes),
                "bytes": bytes.len(),
            }),
        );
    }
    let asset_hashes: BTreeMap<_, _> = corpus
        .manifest
        .assets
        .iter()
        .map(|(id, asset)| (id.clone(), asset.sha256.clone()))
        .collect();
    let mut report = json!({
        "kind": "tag_memory_original_corpus",
        "passed": true,
        "compiler_source_sha256": sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "abi": SYSTEM_BLOCK_ABI,
        "harness_source_sha256": sha256(ENTRY_SOURCE.as_bytes()),
        "shared_sources_sha256": sources,
        "compiled_source_root": source_root.strip_prefix(repository)?,
        "runtime_executable_path": executable.strip_prefix(repository)?,
        "runtime_executable_sha256": executable_sha256,
        "manifest_path": manifest,
        "manifest_sha256": corpus.manifest_sha256,
        "asset_sha256": asset_hashes,
        "artifacts": artifacts,
        "provenance_distinct_original_frames": frames,
        "fresh_exact_original_comparisons": exact,
        "fresh_native_blocks_executed": frames,
        "counts": counts,
        "success_progress": Value::Null,
        "whole_original_CPU_profile_equality_claim": false,
        "guest_exception_delivery_claim": false,
        "performance_claim": false,
        "address_profile": "actual captured T0SZ/TBI; reached-address equivalent to the historical broader lower region",
    });
    if let Some((historical, current)) = history {
        report["historical_full_bridge"] = historical;
        report["current_body_identity_bridge"] = current;
        report["evidence_basis"] = json!("fresh_pilot_plus_historical_verified_bodies_reused");
    } else {
        report["evidence_basis"] = json!("fresh_original_corpus");
    }
    let report_path = output.join("tag-memory-original-corpus-report.json");
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "report": report_path,
            "fresh_exact_original_comparisons": exact,
            "fresh_native_blocks_executed": frames,
            "counts": report["counts"],
        }))?
    );
    Ok(())
}
