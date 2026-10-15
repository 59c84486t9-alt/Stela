//! Batched PACGA verification against a separately captured original-ARM corpus.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use stela_compiler::{GuestAddress, GuestState, TargetCpu, block::BlockProfile};
use stela_core::sha256;
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    pauth,
};

const ADDRESS_SPACE: u64 = 73;
const CODE_BASE: u64 = 0x100000;
const CODE_STRIDE: u64 = 16;
const INSTRUCTION_BYTES: usize = 4;
const INPUT_HEADER_BYTES: usize = 8;
const INPUT_TRAILER_BYTES: usize = 8;
const RET: u32 = 0xd65f03c0;
const BLOCK_BUDGET: usize = 1;
const ORIGINAL_STATE_BYTES: usize = 784;
const PACGA_MASK: u32 = 0xffe0_fc00;
const PACGA_OPCODE: u32 = 0x9ac0_3000;

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + size_of::<u64>()].try_into().unwrap())
}
fn state(bytes: &[u8]) -> GuestState {
    let mut value = GuestState::default();
    for (index, register) in value.x.iter_mut().enumerate() {
        *register = word(bytes, index * size_of::<u64>());
    }
    value.sp = word(bytes, std::mem::offset_of!(GuestState, sp));
    value.nzcv = u32::from_le_bytes(
        bytes[std::mem::offset_of!(GuestState, nzcv)
            ..std::mem::offset_of!(GuestState, nzcv) + size_of::<u32>()]
            .try_into()
            .unwrap(),
    );
    value.reserved = u32::from_le_bytes(
        bytes[std::mem::offset_of!(GuestState, reserved)
            ..std::mem::offset_of!(GuestState, reserved) + size_of::<u32>()]
            .try_into()
            .unwrap(),
    );
    for (index, register) in value.v.iter_mut().enumerate() {
        *register = [
            word(
                bytes,
                std::mem::offset_of!(GuestState, v) + index * size_of::<[u64; 2]>(),
            ),
            word(
                bytes,
                std::mem::offset_of!(GuestState, v)
                    + index * size_of::<[u64; 2]>()
                    + size_of::<u64>(),
            ),
        ];
    }
    value.fpcr = u32::from_le_bytes(
        bytes[std::mem::offset_of!(GuestState, fpcr)
            ..std::mem::offset_of!(GuestState, fpcr) + size_of::<u32>()]
            .try_into()
            .unwrap(),
    );
    value.fpsr = u32::from_le_bytes(
        bytes[std::mem::offset_of!(GuestState, fpsr)
            ..std::mem::offset_of!(GuestState, fpsr) + size_of::<u32>()]
            .try_into()
            .unwrap(),
    );
    value
}
fn state_bytes(value: &GuestState) -> &[u8] {
    // SAFETY: repr(C) GuestState's complete 784-byte layout contains initialized integer fields,
    // including the explicit reserved word; its layout is checked by the workspace ABI tests.
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            size_of::<GuestState>(),
        )
    }
}
fn code(word: u32) -> Vec<u8> {
    [word, RET].into_iter().flat_map(u32::to_le_bytes).collect()
}
fn entry(index: usize) -> GuestAddress {
    GuestAddress(CODE_BASE + index as u64 * CODE_STRIDE)
}
fn runtime(cache: &Path, words: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE,
        cache.into(),
        BlockProfile::AppleArm64eSoftwarePauthV1,
        TargetCpu::Baseline,
    );
    for (index, word) in words.iter().enumerate() {
        runtime.register_code(entry(index), code(*word))?;
    }
    Ok(runtime)
}
fn execute(
    runtime: &mut BlockRuntime,
    context: &pauth::Context,
    cases: &[Value],
    inputs: &[u8],
    expected: &[u8],
    output: &Path,
    phase: &str,
) -> Result<Value> {
    let stride = INPUT_HEADER_BYTES + size_of::<GuestState>() + INPUT_TRAILER_BYTES;
    ensure!(inputs.len() == cases.len() * stride, "input record count");
    let mut native_states = fs::File::create(output.join(format!("{phase}-states.bin")))?;
    let mut compiled = 0;
    let mut disk = 0;
    let mut memory = 0;
    let mut rows = Vec::with_capacity(cases.len());
    for (index, case) in cases.iter().enumerate() {
        let function = case["function_index"].as_u64().context("case function")? as usize;
        ensure!(
            word(inputs, index * stride) as usize == function,
            "input function identity"
        );
        let start = index * stride + INPUT_HEADER_BYTES;
        let before = state(&inputs[start..start + size_of::<GuestState>()]);
        ensure!(
            sha256(state_bytes(&before))
                == case["initial_state_sha256"]
                    .as_str()
                    .context("initial hash")?,
            "raw input identity"
        );
        let mut thread = ThreadState {
            registers: before,
            pc: entry(function),
        };
        // SAFETY: synthetic trusted single PACGA blocks access only State and the bound key Context;
        // no guest RAM access, transfer or unknown source instruction can execute before the stop.
        let stop = GuestAddress(thread.pc.0 + INSTRUCTION_BYTES as u64);
        let result =
            unsafe { runtime.run_with_pauth(&mut thread, Some(stop), BLOCK_BUDGET, context)? };
        ensure!(
            result.reason == StopReason::StopAddress && result.blocks_executed == 1,
            "unexpected PACGA boundary"
        );
        ensure!(
            thread.pc == GuestAddress(entry(function).0 + INSTRUCTION_BYTES as u64),
            "continuation PC"
        );
        ensure!(
            result.pointer_authentication_events.len() == 1,
            "missing genuine helper event"
        );
        ensure!(
            state_bytes(&thread.registers)
                == &expected
                    [index * size_of::<GuestState>()..(index + 1) * size_of::<GuestState>()],
            "complete state mismatch at {phase}/{index}"
        );
        native_states.write_all(state_bytes(&thread.registers))?;
        compiled += result.compiled_blocks;
        disk += result.disk_cache_hits;
        memory += result.memory_cache_hits;
        rows.push(json!({"case":index,"function":function,"pc":thread.pc,"state_sha256":sha256(state_bytes(&thread.registers)),"outcome":result}));
    }
    native_states.flush()?;
    fs::write(
        output.join(format!("{phase}-outcomes.json")),
        serde_json::to_vec_pretty(&rows)?,
    )?;
    Ok(
        json!({"phase":phase,"cases":cases.len(),"compiled_blocks":compiled,"disk_cache_hits":disk,"memory_cache_hits":memory,"native_states_sha256":sha256(&fs::read(output.join(format!("{phase}-states.bin")))?)}),
    )
}
fn inspect(cache: &Path, words: &[u32], output: &Path) -> Result<Value> {
    let mut entries = BTreeMap::new();
    for path in fs::read_dir(cache)? {
        let path = path?.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() {
            continue;
        }
        let raw = fs::read(&manifest_path)?;
        let manifest: stela_runtime::Manifest = serde_json::from_slice(&raw)?;
        ensure!(!manifest.verified, "manifest cannot prove verification");
        ensure!(
            manifest.identity.abi == BlockProfile::AppleArm64eSoftwarePauthV1.abi(),
            "helper ABI identity"
        );
        ensure!(
            manifest.identity.target_cpu == TargetCpu::Baseline.id(),
            "baseline target identity"
        );
        let index = ((manifest.identity.guest_base - CODE_BASE) / CODE_STRIDE) as usize;
        ensure!(
            index < words.len() && manifest.identity.guest_base == entry(index).0,
            "cache guest identity"
        );
        ensure!(
            manifest.identity.source_sha256 == sha256(&words[index].to_le_bytes()),
            "cache exact subject hash"
        );
        ensure!(
            manifest.source_map == vec![(entry(index), 0)],
            "helper source-map extent"
        );
        ensure!(
            manifest.identity.compiler_source_sha256
                == sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
            "current compiler binding"
        );
        let bytes = fs::read(path.join("native.bin"))?;
        ensure!(
            bytes.len() == manifest.native_bytes && sha256(&bytes) == manifest.native_sha256,
            "native identity"
        );
        let source = code(words[index]);
        let checked = stela_runtime::prepare_block_for_target(
            &source,
            entry(index),
            &output.join("checked-artifacts"),
            BlockProfile::AppleArm64eSoftwarePauthV1,
            TargetCpu::detect(),
        )?;
        let checked_bytes = fs::read(checked.prepared.directory.join("native.bin"))?;
        ensure!(
            bytes == checked_bytes && checked.prepared.manifest.source_map == manifest.source_map,
            "checked/baseline body bridge"
        );
        entries.insert(index,json!({"word":words[index],"directory":path,"manifest_sha256":sha256(&raw),"manifest":manifest,"checked_manifest":checked.prepared.manifest,"native_hex":bytes.iter().map(|v|format!("{v:02x}")).collect::<String>()}));
    }
    ensure!(entries.len() == words.len(), "incomplete emitted inventory");
    fs::write(
        output.join("emission-inventory.json"),
        serde_json::to_vec_pretty(&entries)?,
    )?;
    Ok(json!({"actual_bodies":entries.len(),"baseline_checked_exact_byte_bridges":entries.len()}))
}
fn verify(corpus: &Path, output: &Path) -> Result<Value> {
    ensure!(size_of::<GuestState>() == ORIGINAL_STATE_BYTES, "guest ABI");
    ensure!(!output.exists(), "output must be fresh");
    fs::create_dir_all(output)?;
    let cases: Vec<Value> = serde_json::from_slice(&fs::read(corpus.join("cases.json"))?)?;
    let functions: Vec<Value> = serde_json::from_slice(&fs::read(corpus.join("functions.json"))?)?;
    let words: Vec<u32> = functions
        .iter()
        .map(|f| f["operations"][0]["word"].as_u64().unwrap() as u32)
        .collect();
    ensure!(
        words.iter().all(|word| word & PACGA_MASK == PACGA_OPCODE),
        "canonical PACGA-only corpus"
    );
    let profile: Value = serde_json::from_slice(&fs::read(corpus.join("profile.json"))?)?;
    let keys = &profile["keys"];
    let context = pauth::Context::new(
        ADDRESS_SPACE,
        pauth::Keys::from_words([0, 0], [0, 0], [0, 0], [0, 0]).with_generic_words([
            keys["APGAKeyLo_EL1"].as_u64().unwrap(),
            keys["APGAKeyHi_EL1"].as_u64().unwrap(),
        ]),
    );
    let inputs = fs::read(corpus.join("inputs.bin"))?;
    let expected = fs::read(corpus.join("expected-states.bin"))?;
    ensure!(
        expected.len() == cases.len() * size_of::<GuestState>(),
        "expected State count"
    );
    let cache = output.join("cache");
    let mut cold = runtime(&cache, &words)?;
    let mut phases = vec![];
    phases.push(execute(
        &mut cold, &context, &cases, &inputs, &expected, output, "cold",
    )?);
    phases.push(execute(
        &mut cold, &context, &cases, &inputs, &expected, output, "hot",
    )?);
    drop(cold);
    let mut disk = runtime(&cache, &words)?;
    phases.push(execute(
        &mut disk, &context, &cases, &inputs, &expected, output, "disk",
    )?);
    let mut aot = runtime(&output.join("aot-cache"), &words)?;
    for index in 0..words.len() {
        aot.prepare(entry(index))?;
    }
    phases.push(execute(
        &mut aot, &context, &cases, &inputs, &expected, output, "aot",
    )?);
    let emission = inspect(&cache, &words, output)?;
    let report = json!({"kind":"pacga-integrated-block-full-state-original","passed":true,"compiler_sha256":sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),"profile":context.profile_id(),"phases":phases,"emission":emission,"limits":["Genuine original fullState comparisons use frozen corpus; original RAM unchanged and PACGA performs no data access.","No complete process/application/hardware-key-identity or architectural exception delivery claim."]});
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

#[test]
#[ignore = "requires an independently captured PACGA original corpus and a fresh output path"]
fn generic_code_original_corpus() -> Result<()> {
    let corpus = PathBuf::from(
        std::env::var_os("STELA_PAUTH_ORIGINALS").context("STELA_PAUTH_ORIGINALS is required")?,
    );
    let output = PathBuf::from(
        std::env::var_os("STELA_PAUTH_NATIVE_OUTPUT")
            .context("STELA_PAUTH_NATIVE_OUTPUT is required")?,
    );
    let report = verify(&corpus, &output)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[path = "corpus/ldra.rs"]
mod ldra;
