//! Explicit offline fixture specializations, not a production Metal parser.
use super::{parse_original_input, run as run_stage, tools};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path, process::Command};

#[derive(Default)]
pub(super) struct Evidence {
    pub probes: Vec<Value>,
    pub unsupported: Vec<Value>,
}

pub(super) fn run(
    build: &Path,
    evidence: &Path,
    inputs: &[Value],
    amd_llvm: bool,
) -> Result<Evidence> {
    let mut result = Evidence::default();
    if inputs.is_empty() {
        return Ok(result);
    }
    ensure!(
        inputs.len() == 3,
        "threadgroup fixtures need exactly three inputs"
    );
    let paths = inputs
        .iter()
        .map(|input| {
            input["snapshot"]["path"]
                .as_str()
                .context("missing threadgroup snapshot")
        })
        .collect::<Result<Vec<_>>>()?;
    let binary = build.join("src/stela/stela_nv_air_threadgroup_probe");
    let artifacts = evidence.join("nv-threadgroup-artifacts");
    fs::create_dir(&artifacts)?;
    run_stage(
        Command::new(&binary).args(&paths).arg(&artifacts),
        evidence,
        "nv-threadgroup",
    )?;
    let mut files = fs::read_dir(&artifacts)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    // Four shaders * nine targets, each with actual NIR/code/ASM/QMD/push bytes.
    ensure!(
        files.len() == 180,
        "incomplete NVIDIA threadgroup artifact set"
    );
    result.probes.push(json!({
        "backend": "nv-threadgroup", "binary": tools::binding(&binary)?,
        "output": tools::binding(&evidence.join("nv-threadgroup.log"))?,
        "artifacts": files.iter().map(|file| tools::binding(file)).collect::<Result<Vec<_>>>()?,
        "hardware_executed": false,
    }));
    let binary = build.join("src/stela/stela_intel_air_threadgroup_probe");
    for (name, index, entry, threads, shared, dynamic) in [
        (
            "apple-static",
            0,
            "stela_threadgroup_static",
            "32",
            "128",
            "none",
        ),
        (
            "apple-dynamic",
            0,
            "stela_threadgroup_dynamic",
            "32",
            "128",
            "3",
        ),
        ("llvm-static", 1, "kernel", "64", "256", "none"),
        ("llvm-dynamic", 2, "kernel", "64", "256", "7"),
    ] {
        let stage = format!("intel-threadgroup-{name}");
        run_stage(
            Command::new(&binary).args([
                "--input",
                paths[index],
                "--entry",
                entry,
                "--workgroup",
                threads,
                "--shared",
                shared,
                "--threadgroup-index",
                dynamic,
            ]),
            evidence,
            &stage,
        )?;
        let log = evidence.join(format!("{stage}.log"));
        let output = fs::read_to_string(&log)?;
        let provenance = parse_original_input(
            &output,
            entry,
            inputs[index]["snapshot"]["bytes"]
                .as_u64()
                .context("missing threadgroup input size")?,
        )?;
        let mut targets = Vec::new();
        let mut names = BTreeSet::new();
        let mut holds = Vec::new();
        for line in output.lines() {
            if let Some(raw) = line.strip_prefix("STELA_INTEL_THREADGROUP_OUTPUT ") {
                let record: Value = serde_json::from_str(raw)?;
                ensure!(
                    record["entry"] == entry
                        && record["hardware_executed"] == false
                        && record["code_bytes"].as_u64().is_some_and(|size| size > 0)
                        && names.insert(
                            record["target"]
                                .as_str()
                                .context("missing Intel target")?
                                .to_owned()
                        ),
                    "invalid Intel threadgroup output"
                );
                targets.push(record);
            } else if let Some(raw) = line.strip_prefix("STELA_INTEL_THREADGROUP_UNSUPPORTED ") {
                let record: Value = serde_json::from_str(raw)?;
                ensure!(
                    record["target"] == "nvl"
                        && record["entry"] == entry
                        && record["reason"] == "gfx35-dispatch-lane-mask-unqualified"
                        && record["hardware_executed"] == false,
                    "invalid Intel threadgroup hold"
                );
                holds.push(record);
            }
        }
        ensure!(
            targets.len() == 22 && holds.len() == 1,
            "incomplete Intel threadgroup target set"
        );
        result.unsupported.extend(holds);
        result.probes.push(json!({
            "backend": "intel-threadgroup", "fixture": name, "input_index": index,
            "entry": entry, "workgroup": threads, "shared_bytes": shared,
            "dynamic_index": dynamic, "binary": tools::binding(&binary)?,
            "output": tools::binding(&log)?, "provenance": provenance,
            "targets": targets, "hardware_executed": false,
        }));
    }
    if amd_llvm {
        let binary = build.join("src/stela/stela_amd_air_threadgroup_probe");
        run_stage(
            Command::new(&binary).args(&paths),
            evidence,
            "amd-threadgroup",
        )?;
        let log = evidence.join("amd-threadgroup.log");
        let output = fs::read_to_string(&log)?;
        let mut targets = Vec::new();
        for line in output.lines() {
            if let Some(raw) = line.strip_prefix("STELA_AMD_SHARED ") {
                let record: Value = serde_json::from_str(raw)?;
                ensure!(
                    record["physical_gpu_execution"] == false
                        && record["code_bytes"].as_u64().is_some_and(|size| size > 0)
                        && matches!(
                            record["instruction_view"].as_str(),
                            Some("binary-disassembly" | "original-aco-hardware-ir")
                        ),
                    "invalid AMD shared-memory compiler record"
                );
                targets.push(record);
            }
        }
        ensure!(
            targets.len() == 133,
            "incomplete AMD threadgroup target set"
        );
        result.probes.push(json!({
            "backend": "amd-threadgroup", "binary": tools::binding(&binary)?,
            "output": tools::binding(&log)?, "targets": targets,
            "hardware_executed": false,
        }));
    }
    for input in inputs {
        let path = Path::new(
            input["snapshot"]["path"]
                .as_str()
                .context("missing threadgroup input")?,
        );
        ensure!(
            tools::binding(path)? == input["snapshot"],
            "threadgroup snapshot changed during compilation"
        );
    }
    Ok(result)
}
