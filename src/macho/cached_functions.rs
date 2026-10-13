//! Native probes of complete original cached register-only functions.
//! This deliberately supplies no cache data mappings or macOS process state.
use super::shared_cache_exports::CacheResolver;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{Decoder, Operation},
};
use stela_runtime::blocks::{BlockRuntime, StopReason, ThreadState};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct FunctionInput {
    pub symbol: String,
    pub cases: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registers {
    x: [u64; 31],
    sp: u64,
    nzcv: u32,
    reserved: u32,
}
impl Registers {
    fn guest(&self) -> GuestState {
        GuestState {
            x: self.x,
            sp: self.sp,
            nzcv: self.nzcv,
            reserved: self.reserved,
        }
    }
    fn observed(state: &GuestState) -> Self {
        Self {
            x: state.x,
            sp: state.sp,
            nzcv: state.nzcv,
            reserved: state.reserved,
        }
    }
}

#[derive(Deserialize)]
struct Case {
    name: String,
    initial: Registers,
}

fn profile(code: &[u8], entry: u64, stop_pc: u64) -> Result<Vec<GuestAddress>> {
    ensure!(
        !code.is_empty() && code.len().is_multiple_of(4) && code.len() <= 1024,
        "cached register-function probe requires 1..256 complete instructions"
    );
    ensure!(
        entry.is_multiple_of(4) && stop_pc.is_multiple_of(4),
        "unaligned cached function/stop address"
    );
    let end = entry
        .checked_add(code.len() as u64)
        .context("cached function extent overflow")?;
    ensure!(
        stop_pc < entry || stop_pc >= end,
        "stop address overlaps original function"
    );
    let mut returns = 0;
    let mut pcs = Vec::new();
    for (index, bytes) in code.as_chunks::<4>().0.iter().enumerate() {
        let pc = GuestAddress(entry + index as u64 * 4);
        let word = u32::from_le_bytes(*bytes);
        let operation = Decoder
            .lift(pc, word)
            .map_err(|error| {
                anyhow::anyhow!("cached function has unsupported semantics: {error:?}")
            })?
            .operation;
        match operation {
            Operation::Return => returns += 1,
            Operation::Branch { target }
            | Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. } => {
                ensure!(
                    target.0 >= entry && target.0 < end && target.0.is_multiple_of(4),
                    "cached register-function branch leaves its complete source extent"
                );
            }
            Operation::Bitfield(_)
            | Operation::ConditionalSelect(_)
            | Operation::IntegerMath(_)
            | Operation::AddSubRegister { .. }
            | Operation::AddSubCarry { .. }
            | Operation::LogicalRegister { .. }
            | Operation::LogicalImmediate { .. }
            | Operation::MoveWide { .. }
            | Operation::AddSub { .. }
            | Operation::Nop => {}
            // Includes literal loads hidden in the PC-relative operation family.
            _ => anyhow::bail!(
                "cached function requires memory, PC-relative or platform behavior outside the register-only probe"
            ),
        }
        pcs.push(pc);
    }
    ensure!(
        returns > 0 && code.ends_with(&0xd65f03c0u32.to_le_bytes()),
        "complete cached function interval must end in ordinary RET X30"
    );
    Ok(pcs)
}

fn read_cases(path: &Path, stop_pc: u64) -> Result<(Vec<Case>, String)> {
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 16 * 1024 * 1024,
        "case input must be a regular file of at most 16 MiB"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "case input grew beyond limit"
    );
    let cases: Vec<Case> = serde_json::from_slice(&bytes)?;
    ensure!(
        !cases.is_empty() && cases.len() <= 4096,
        "function requires 1..4096 cases"
    );
    let mut names = BTreeSet::new();
    for case in &cases {
        ensure!(
            !case.name.is_empty() && case.name.len() <= 256 && names.insert(case.name.as_str()),
            "case names must be distinct nonempty strings of at most 256 bytes"
        );
        ensure!(
            case.initial.nzcv & 0x0fff_ffff == 0,
            "case contains unmodeled NZCV bits"
        );
        ensure!(
            case.initial.x[30] == stop_pc,
            "case X30 must name the explicit return stop"
        );
    }
    Ok((cases, stela_core::sha256(&bytes)))
}

pub struct ProbeOptions<'a> {
    pub stop_pc: u64,
    pub block_budget: usize,
    pub cache_dir: &'a Path,
    pub aot: bool,
}

pub fn probe(
    input: &Path,
    image_path: &str,
    cache_base: Option<u64>,
    functions: &[FunctionInput],
    options: ProbeOptions<'_>,
) -> Result<Value> {
    let ProbeOptions {
        stop_pc,
        block_budget,
        cache_dir,
        aot,
    } = options;
    ensure!(
        !functions.is_empty() && functions.len() <= 16,
        "probe requires 1..16 named functions"
    );
    ensure!(
        (1..=1024).contains(&block_budget),
        "function block budget must be 1..1024"
    );
    let set = super::shared_cache::manifest_set(input)?;
    let preferred = set["files"][0]["header"]["shared_region_start"]
        .as_u64()
        .context("missing cache base")?;
    let mut resolver = CacheResolver::new(&set, cache_base.unwrap_or(preferred))?;
    let mut image = serde_json::to_value(resolver.image(image_path)?)?;
    let mut runtime = BlockRuntime::new(0x534f_5245_4341_4348, cache_dir.to_owned());
    let mut results = Vec::new();
    let mut symbols = BTreeSet::new();
    let mut total_cases = 0usize;
    // Validate every selected source/case profile before the first native call.
    let mut prepared = Vec::new();
    let mut registered = BTreeMap::new();
    for function in functions {
        ensure!(
            symbols.insert(function.symbol.as_str()),
            "duplicate requested function"
        );
        let resolution = resolver.resolve(image_path, &function.symbol, false)?;
        let snapshot = resolver.snapshot_resolved_function(&resolution)?;
        image["sources"] = serde_json::to_value(&snapshot.sources)?;
        let pcs = profile(&snapshot.bytes, snapshot.extent.address, stop_pc)?;
        let (cases, cases_sha256) = read_cases(&function.cases, stop_pc)?;
        total_cases = total_cases
            .checked_add(cases.len())
            .context("case count overflow")?;
        ensure!(total_cases <= 8192, "probe total exceeds 8192 cases");
        if let Some(bytes) = registered.get(&snapshot.extent.address) {
            ensure!(
                bytes == &snapshot.bytes,
                "aliased function snapshots differ"
            );
        } else {
            runtime.register_code(
                GuestAddress(snapshot.extent.address),
                snapshot.bytes.clone(),
            )?;
            registered.insert(snapshot.extent.address, snapshot.bytes.clone());
        }
        prepared.push((function, resolution, snapshot, pcs, cases, cases_sha256));
    }
    let aot_preparation = if aot {
        let roots: Vec<_> = registered.keys().copied().map(GuestAddress).collect();
        let discovery = runtime.discover(&roots, 4096)?;
        ensure!(
            discovery.issues.is_empty() && discovery.pending_entries.is_empty(),
            "vetted function AOT discovery left unresolved static paths"
        );
        Some(discovery)
    } else {
        None
    };
    for (function, resolution, snapshot, pcs, cases, cases_sha256) in prepared {
        let mut outputs = Vec::with_capacity(cases.len());
        let mut returned = 0;
        for case in cases {
            let mut state = ThreadState {
                registers: case.initial.guest(),
                pc: GuestAddress(snapshot.extent.address),
            };
            // SAFETY: all registered bytes have been vetted as modeled scalar
            // register operations, internal branches or ordinary RET X30. They
            // perform no guest RAM access, callbacks, syscalls or platform work.
            // The owned state and immutable code are exclusively borrowed, and
            // dispatch is bounded. GCS/BTI/PAC are outside this explicit probe.
            let outcome =
                unsafe { runtime.run(&mut state, Some(GuestAddress(stop_pc)), block_budget)? };
            let actual_return = outcome.reason == StopReason::StopAddress
                && outcome.last_exit
                    == Some((stop_pc, stela_compiler::block::ExitKind::Return as u64));
            returned += usize::from(actual_return);
            outputs.push(json!({"name":case.name,"initial":case.initial,
                "actual":Registers::observed(&state.registers),"pc":state.pc.0,
                "ordinary_return":actual_return,"outcome":outcome}));
        }
        let manifests = pcs
            .iter()
            .filter_map(|pc| runtime.loaded_manifest(*pc))
            .collect::<Vec<_>>();
        results.push(
            json!({"symbol":function.symbol,"cases_source":function.cases,
            "cases_sha256":cases_sha256,"cases":outputs,"returned_cases":returned,
            "snapshot":snapshot,"resolution":resolution,"native_block_manifests":manifests}),
        );
    }
    Ok(
        json!({"schema_version":1,"kind":"original_cached_register_function_native_probe",
        "source_sha256":set["source_sha256"],"cache_base":cache_base.unwrap_or(preferred),
        "image":image,"results":results,"total_cases":total_cases,"stop_pc":stop_pc,
        "aot_preparation":aot_preparation,
        "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "probe_source_sha256":stela_core::sha256(include_bytes!("cached_functions.rs")),
        "fixups_applied":false,"cache_data_mapped":false,"complete_binary_verified":false,
        "limits":"Complete original LC_FUNCTION_STARTS intervals under a scalar register-only research profile. Source instructions remain unchanged; x86 translations execute through BlockRuntime. No reconstructed dylib, source patch, host symbol, PAC stripping, cache fixups, RAM, initializer, process ABI or full application execution. Returned cases alone are not an independent behavior comparison."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn profile_refuses_hidden_memory_platform_and_outward_transfers() {
        for word in [
            0xf9400020, 0x58000000, 0xa9000000, 0xd503237f, 0xd4001001, 0xd61f0000, 0x94000000,
            0x14000100,
        ] {
            assert!(
                profile(&code(&[word, 0xd65f03c0]), 0x1000, 0x2000).is_err(),
                "{word:x}"
            );
        }
        // Unreachable source is still vetted before executing any case.
        assert!(profile(&code(&[0xd65f03c0, 0xf9400000, 0xd65f03c0]), 0x1000, 0x2000).is_err());
        assert!(profile(&code(&[0xd65f03c0]), 0x1000, 0x1000).is_err());
    }

    #[test]
    fn original_scalar_intervals_and_internal_control_flow_are_admitted() -> Result<()> {
        assert_eq!(
            profile(&code(&[0x7100001f, 0x5a805400, 0xd65f03c0]), 0x1000, 0x2000)?.len(),
            3
        );
        assert_eq!(
            profile(&code(&[0x14000001, 0xd65f03c0]), 0x1000, 0x2000)?.len(),
            2
        );
        assert!(profile(&code(&[0xd503201f]), 0x1000, 0x2000).is_err());
        Ok(())
    }
}
