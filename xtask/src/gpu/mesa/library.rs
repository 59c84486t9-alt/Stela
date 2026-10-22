//! Hosted library ownership uses the canonical parser and shared AIR inspector.
use super::{run, tools};
use anyhow::{Result, ensure};
use object::{Architecture, Object, ObjectSymbol};
use serde_json::{Value, json};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) fn build_input(evidence: &Path) -> Result<PathBuf> {
    let target = tools::root().join(".stela/gpu/build/metal-input");
    run(
        Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(tools::root())
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_INCREMENTAL", "0")
            .args(["build", "--release", "--locked", "-p", "stela-metal-input"]),
        evidence,
        "metal-input",
    )?;
    let path = target.join("release/libstela_metal_input.a");
    ensure!(path.is_file(), "missing hosted Metal input archive");
    Ok(path)
}

pub(super) fn verify(build: &Path, evidence: &Path, input: &Path, gpu: &Path) -> Result<Value> {
    let path = build.join("src/stela/stela_metal_assembly_test");
    let bytes = std::fs::read(&path)?;
    let binary = object::File::parse(bytes.as_slice())?;
    let host_arch = match env::consts::ARCH {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        _ => anyhow::bail!("unsupported hosted Metal assembler architecture"),
    };
    ensure!(
        binary.architecture() == host_arch,
        "wrong Metal assembler CPU ABI"
    );
    let symbols = binary
        .symbols()
        .filter_map(|s| s.name().ok().map(str::to_owned))
        .collect::<Vec<_>>();
    for required in [
        "_stela_metal_input_entry_metadata",
        "_stela_metal_assemble_archive",
        "_stela_air_inspect",
    ] {
        ensure!(
            symbols.iter().any(|s| s == required),
            "missing integrated {required}"
        );
    }
    ensure!(
        !symbols
            .iter()
            .any(|s| s == "_stela_air_to_nir" || s.starts_with("_nir_")),
        "local Metal library owner unexpectedly links NIR",
    );
    run(&mut Command::new(&path), evidence, "metal-library-assembly")?;
    Ok(json!({
        "scope":"Executed local C/Rust/LLVM ownership fixture; no private compiler invocation, Objective-C or GPU execution",
        "input_library":tools::binding(input)?,"binary":tools::binding(&path)?,
        "output":tools::binding(&evidence.join("metal-library-assembly.log"))?,
        "input_sources_sha256":super::source_binding(&gpu.join("metal/input"))?,
        "assembly_sources_sha256":super::source_binding(&gpu.join("metal/compiler"))?,
        "manifest":tools::binding(&gpu.join("metal/macos/library_manifest.h"))?,
    }))
}

/// Exercise the retained compiler result after its canonical input is destroyed.
/// The fixture independently recompiles NIR with the original backend and compares the
/// complete code and configuration; it never executes GPU machine code.
pub(super) fn verify_owned(
    build: &Path,
    evidence: &Path,
    vendor: &str,
    backend: &str,
    expected: usize,
    completion: &str,
) -> Result<Value> {
    let path = build.join(format!("src/stela/stela_{vendor}_air_compile_test"));
    let bytes = std::fs::read(&path)?;
    let binary = object::File::parse(bytes.as_slice())?;
    let symbols = binary
        .symbols()
        .filter_map(|s| s.name().ok())
        .collect::<Vec<_>>();
    for symbol in [
        format!("_stela_{vendor}_air_compile"),
        format!("_stela_{vendor}_air_destroy"),
        "_stela_air_to_nir".to_owned(),
        "_stela_metal_assemble_archive".to_owned(),
    ] {
        ensure!(
            symbols.contains(&symbol.as_str()),
            "missing actual owned-compiler provider {symbol}"
        );
    }
    let stage = format!("{vendor}-air-owned");
    run(&mut Command::new(&path), evidence, &stage)?;
    let log = evidence.join(format!("{stage}.log"));
    let output = std::fs::read_to_string(&log)?;
    let prefix = format!("owned-air-{backend} ");
    let records = output
        .lines()
        .filter(|l| l.starts_with(&prefix) && !l.contains(" hold="))
        .count();
    let holds = output
        .lines()
        .filter(|l| l.starts_with(&prefix) && l.contains(" hold="))
        .count();
    ensure!(
        records == expected && output.lines().last() == Some(completion),
        "incomplete owned {vendor} compiler fixture"
    );
    Ok(json!({
        "scope":"Executed hosted owned-compilation fixture: LLVM-generated inputs, original backend whole code/metadata oracle, lifetime and existing command-producer checks; no GPU execution or Metal pipeline object",
        "binary":tools::binding(&path)?,"output":tools::binding(&log)?,
        "owned_compiler_results":records,"unsupported_owned_fixture_results":holds,"hardware_executed":false,
    }))
}

/// The unchanged original two-entry AIR module passes through canonical
/// assembly and each owned compiler, with and without dynamic lengths.
pub(super) fn verify_shared(build: &Path, evidence: &Path, input: &Path) -> Result<Value> {
    let assembly = build.join("src/stela/stela_metal_assembly_test");
    run(
        Command::new(&assembly)
            .arg("--archive-pair")
            .arg(input)
            .args([
                "stela_threadgroup_static",
                "stela_threadgroup_dynamic",
                "9",
                "4",
                "1",
                "27",
                "2",
                "complete",
            ]),
        evidence,
        "metal-shared-assembly",
    )?;
    let mut compilers = Vec::new();
    for (vendor, backend, expected, refusals) in [
        ("amd", "aco", 16, 1),
        ("nv", "nak", 9, 9),
        ("intel", "intel", 22, 23),
    ] {
        let binary = build.join(format!("src/stela/stela_{vendor}_air_compile_test"));
        let static_stage = format!("{vendor}-air-owned-static");
        run(
            Command::new(&binary)
                .arg("--input")
                .arg(input)
                .arg("stela_threadgroup_static"),
            evidence,
            &static_stage,
        )?;
        let static_log = evidence.join(format!("{static_stage}.log"));
        let output = std::fs::read_to_string(&static_log)?;
        let prefix = format!("owned-air-{backend} ");
        ensure!(
            output
                .lines()
                .filter(|l| l.starts_with(&prefix) && !l.contains(" hold="))
                .count()
                == expected,
            "incomplete owned {vendor} static threadgroup matrix"
        );
        let dynamic_stage = format!("{vendor}-air-owned-dynamic-refusal");
        run(
            Command::new(&binary)
                .arg("--shared-refusal")
                .arg(input)
                .arg("stela_threadgroup_dynamic"),
            evidence,
            &dynamic_stage,
        )?;
        let dynamic_log = evidence.join(format!("{dynamic_stage}.log"));
        let output = std::fs::read_to_string(&dynamic_log)?;
        let observed = output.lines().filter(|l| {
            if vendor == "amd" {
                *l == "shared input explicitly refused: dynamic AS3 dispatch specialization unavailable"
            } else {
                l.starts_with(&prefix) && l.contains(" shared_refusal=")
            }
        }).count();
        ensure!(
            observed == refusals,
            "incomplete owned {vendor} missing dynamic specialization refusals"
        );
        compilers.push(
            json!({"vendor":vendor,"compiled":expected,"dynamic_refusals":refusals,
            "binary":tools::binding(&binary)?,"static_output":tools::binding(&static_log)?,
            "dynamic_output":tools::binding(&dynamic_log)?}),
        );
    }
    let dynamic = verify_dynamic_shared(build, evidence, input)?;
    Ok(
        json!({"backend":"owned-static-threadgroup","scope":"Canonical two-entry assembly, retained original compiler code/metadata and command-plan oracles; no hardware execution",
        "input":tools::binding(input)?,"assembly_binary":tools::binding(&assembly)?,
        "assembly_output":tools::binding(&evidence.join("metal-shared-assembly.log"))?,
        "compilers":compilers,"dynamic_specializations":dynamic,"hardware_executed":false}),
    )
}

pub(super) fn verify_threadgroup_values(build: &Path, evidence: &Path) -> Result<Value> {
    let binary = build.join("src/stela/stela_metal_threadgroup_test");
    let bytes = std::fs::read(&binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbols = object
        .symbols()
        .filter_map(|s| s.name().ok())
        .collect::<Vec<_>>();
    ensure!(
        symbols.contains(&"_stela_metal_threadgroup_normalize"),
        "missing value normalizer"
    );
    ensure!(
        !symbols
            .iter()
            .any(|s| s.starts_with("_LLVM") || s.starts_with("_nir_")),
        "threadgroup value owner unexpectedly depends on LLVM/NIR"
    );
    run(
        &mut Command::new(&binary),
        evidence,
        "metal-threadgroup-values",
    )?;
    let nir_binary = build.join("src/stela/stela_metal_threadgroup_nir_test");
    run(
        &mut Command::new(&nir_binary),
        evidence,
        "metal-threadgroup-nir",
    )?;
    Ok(
        json!({"scope":"Allocation-free value normalization plus actual LLVM/NIR regions, bounds and barrier semantics; synthetic input, no hardware execution",
        "binary":tools::binding(&binary)?,"output":tools::binding(&evidence.join("metal-threadgroup-values.log"))?,
        "nir_binary":tools::binding(&nir_binary)?,"nir_output":tools::binding(&evidence.join("metal-threadgroup-nir.log"))?}),
    )
}

fn verify_dynamic_shared(build: &Path, evidence: &Path, original: &Path) -> Result<Vec<Value>> {
    // Export the semantic fixture through its actual LLVM producer, rather than
    // maintaining a second bitcode fixture or interpreting the source ourselves.
    let mixed = evidence.join("multiple-threadgroups.bc");
    run(
        Command::new(build.join("src/stela/stela_metal_threadgroup_nir_test"))
            .arg("--export")
            .arg(&mixed),
        evidence,
        "metal-threadgroup-export",
    )?;
    let mut records = Vec::new();
    for (vendor, backend, expected) in
        [("amd", "aco", 16), ("nv", "nak", 9), ("intel", "intel", 22)]
    {
        let binary = build.join(format!("src/stela/stela_{vendor}_air_compile_test"));
        for (name, input, entry, workgroup, rows, compiled, holds, total) in [
            (
                "128",
                original,
                "stela_threadgroup_dynamic",
                "32",
                vec!["3:128"],
                expected,
                0,
                128,
            ),
            (
                "256",
                original,
                "stela_threadgroup_dynamic",
                "32",
                vec!["3:256"],
                expected,
                0,
                256,
            ),
            (
                "512",
                original,
                "stela_threadgroup_dynamic",
                "32",
                vec!["3:512"],
                expected,
                0,
                512,
            ),
            (
                "mixed",
                mixed.as_path(),
                "kernel",
                "64",
                vec!["3:256", "11:16", "7:128"],
                if vendor == "intel" { 20 } else { expected },
                if vendor == "intel" { 2 } else { 0 },
                403,
            ),
        ] {
            let stage = format!("{vendor}-air-owned-threadgroup-{name}");
            run(
                Command::new(&binary)
                    .arg("--threadgroup")
                    .arg(input)
                    .arg(entry)
                    .arg(workgroup)
                    .args(&rows),
                evidence,
                &stage,
            )?;
            let log = evidence.join(format!("{stage}.log"));
            let text = std::fs::read_to_string(&log)?;
            let prefix = format!("owned-threadgroup-{backend} ");
            let output = text
                .lines()
                .filter(|l| l.starts_with(&prefix))
                .collect::<Vec<_>>();
            ensure!(
                output.iter().filter(|l| !l.contains(" hold=")).count() == compiled
                    && output.iter().filter(|l| l.contains(" hold=")).count() == holds
                    && output.iter().filter(|l| !l.contains(" hold=")).all(|l| l
                        .split_whitespace()
                        .any(|field| field == format!("total_shared={total}"))),
                "incomplete {vendor} threadgroup specialization {name}"
            );
            records.push(json!({"vendor":vendor,"fixture":name,"compiled":compiled,"typed_holds":holds,
                "total_shared_bytes":total,"input":tools::binding(input)?,"binary":tools::binding(&binary)?,
                "output":tools::binding(&log)?,"hardware_executed":false}));
        }
    }
    Ok(records)
}

pub(super) fn verify_gen7_shared(build: &Path, evidence: &Path) -> Result<Value> {
    let binary = build.join("src/stela/stela_intel_air_compile_test");
    run(
        Command::new(&binary).arg("--gen7-shared"),
        evidence,
        "intel-gen7-shared",
    )?;
    let log = evidence.join("intel-gen7-shared.log");
    let text = std::fs::read_to_string(&log)?;
    ensure!(
        text.lines()
            .filter(|l| l.starts_with("guard ") && l.contains("typed_refusal_before_elk_compile=1"))
            .count()
            == 4
            && text
                .lines()
                .filter(|l| l.starts_with("owned-air-intel input=root-static-shared-guard "))
                .count()
                == 11,
        "incomplete Gen7 shared admission/original compiler fixture"
    );
    Ok(
        json!({"scope":"Synthetic static LLVM through actual canonical owned compiler; four Gen70 typed refusals and eleven aligned32/Gen75+ original code/progdata/ISA/command comparisons; no hardware execution",
        "binary":tools::binding(&binary)?,"output":tools::binding(&log)?}),
    )
}
