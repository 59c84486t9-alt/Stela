//! Offline render-stage qualification through original vendor compilers.
use super::{run, tools};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, process::Command};

/// Shared stage semantics always run; external Apple inputs remain optional,
/// immutable acceptance inputs rather than embedded source fixtures.
pub(super) fn verify(build: &Path, evidence: &Path, inputs: &[Value]) -> Result<Value> {
    let binary = build.join("src/stela/stela_air_stage_test");
    let mut command = Command::new(&binary);
    if !inputs.is_empty() {
        ensure!(inputs.len() == 2, "expected two render input snapshots");
        command
            .arg("--input")
            .arg(
                inputs[0]["snapshot"]["path"]
                    .as_str()
                    .context("triangle snapshot")?,
            )
            .arg("--texture")
            .arg(
                inputs[1]["snapshot"]["path"]
                    .as_str()
                    .context("texture snapshot")?,
            );
    }
    run(&mut command, evidence, "air-stage-semantics")?;
    let output = evidence.join("air-stage-semantics.log");
    ensure!(
        std::fs::read_to_string(&output)?.lines().last() == Some("AIR stage semantics passed"),
        "incomplete shared render semantics fixture"
    );
    let nvidia = if inputs.is_empty() {
        None
    } else {
        let binary = build.join("src/stela/stela_nv_air_render_probe");
        let artifacts = evidence.join("nv-render-artifacts");
        std::fs::create_dir(&artifacts)?;
        run(
            Command::new(&binary)
                .arg("--input")
                .arg(
                    inputs[0]["snapshot"]["path"]
                        .as_str()
                        .context("triangle snapshot")?,
                )
                .args([
                    "--vertex",
                    "vertexShader",
                    "--fragment",
                    "fragmentShader",
                    "--output",
                ])
                .arg(&artifacts),
            evidence,
            "nv-air-render",
        )?;
        let log = evidence.join("nv-air-render.log");
        let text = std::fs::read_to_string(&log)?;
        let records = text
            .lines()
            .filter_map(|line| line.strip_prefix("STELA_GPU_RENDER_TARGET "))
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            records.len() == 36,
            "incomplete NVIDIA VS/FS raster-key fixture"
        );
        let mut files = std::fs::read_dir(&artifacts)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort();
        ensure!(files.len() == 198, "incomplete NVIDIA render artifacts");
        Some(
            json!({"binary":tools::binding(&binary)?,"output":tools::binding(&log)?,
            "records":records,"artifacts":files.iter().map(|p|tools::binding(p)).collect::<Result<Vec<_>>>()?}),
        )
    };
    let intel = if inputs.is_empty() {
        None
    } else {
        let binary = build.join("src/stela/stela_intel_air_render_probe");
        let artifacts = evidence.join("intel-render-artifacts");
        let assembly = evidence.join("intel-render-isa.txt");
        std::fs::create_dir(&artifacts)?;
        run(
            Command::new(&binary)
                .arg(
                    inputs[0]["snapshot"]["path"]
                        .as_str()
                        .context("triangle snapshot")?,
                )
                .args(["vertexShader", "fragmentShader"])
                .arg(
                    inputs[1]["snapshot"]["path"]
                        .as_str()
                        .context("texture snapshot")?,
                )
                .arg("samplingShader")
                .env("STELA_RENDER_EVIDENCE", &artifacts)
                .env("STELA_RENDER_DISASSEMBLY", &assembly),
            evidence,
            "intel-air-render",
        )?;
        let log = evidence.join("intel-air-render.log");
        let text = std::fs::read_to_string(&log)?;
        let records = text
            .lines()
            .filter_map(|line| line.strip_prefix("STELA_RENDER_COMPILED "))
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let links = text
            .lines()
            .filter_map(|line| line.strip_prefix("STELA_RENDER_LINK "))
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let holds = text
            .lines()
            .filter_map(|line| line.strip_prefix("STELA_RENDER_HOLD "))
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            holds.len() == 1
                && holds[0]["target"] == "nvl"
                && holds[0]["reason"] == "Gen35-dispatch-execution-policy-unqualified",
            "unexpected Intel render hold fixture"
        );
        let modern = [
            "skl", "bxt", "kbl", "glk", "icl", "ehl", "tgl", "rkl", "dg1", "adl", "dg2", "mtl",
            "arl", "lnl", "bmg", "ptl", "nvl-u",
        ];
        let legacy = ["ivb", "byt", "hsw", "bdw", "chv"];
        let mut expected_records = BTreeSet::new();
        let mut expected_files = BTreeSet::new();
        let mut expected_links = BTreeSet::new();
        for (targets, backend) in [(&modern[..], "brw"), (&legacy[..], "elk")] {
            for &target in targets {
                expected_links.insert(target);
                for stage in ["vertex", "fragment"] {
                    expected_records.insert((target, stage, backend));
                    for kind in ["code", "progdata", "relocs", "constants"] {
                        expected_files.insert(format!("{target}-{stage}.{kind}"));
                    }
                    if backend == "elk" {
                        expected_files.insert(format!("{target}-{stage}.params"));
                    }
                }
            }
        }
        let record_keys = records
            .iter()
            .map(|record| -> Result<_> {
                ensure!(
                    record["bytes"].as_u64().is_some_and(|n| n > 0)
                        && record["whole_recapture_equal"] == true
                        && record["hardware_executed"] == false,
                    "invalid Intel render compiler result"
                );
                Ok((
                    record["target"].as_str().context("Intel render target")?,
                    record["stage"].as_str().context("Intel render stage")?,
                    record["backend"].as_str().context("Intel render backend")?,
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let link_keys = links
            .iter()
            .map(|link| link["target"].as_str().context("Intel VUE target"))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            record_keys == expected_records
                && records.len() == expected_records.len()
                && link_keys == expected_links
                && links.len() == expected_links.len(),
            "incomplete or duplicated Intel VS/FS compiler/VUE fixture"
        );
        let mut files = std::fs::read_dir(&artifacts)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort();
        let file_names = files
            .iter()
            .map(|path| -> Result<_> {
                ensure!(path.is_file(), "non-file Intel render artifact");
                Ok(path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("Intel render artifact filename")?
                    .to_owned())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            file_names == expected_files && std::fs::metadata(&assembly)?.len() > 0,
            "incomplete Intel render artifacts or ISA listing"
        );
        Some(
            json!({"binary":tools::binding(&binary)?,"output":tools::binding(&log)?,
            "records":records,"vue_links":links,"holds":holds,"isa_listing":tools::binding(&assembly)?,
            "artifacts":files.iter().map(|p|tools::binding(p)).collect::<Result<Vec<_>>>()?}),
        )
    };
    let amd = if inputs.is_empty() {
        None
    } else {
        let binary = build.join("src/stela/stela_amd_air_render_probe");
        run(
            Command::new(&binary)
                .arg("--input")
                .arg(
                    inputs[0]["snapshot"]["path"]
                        .as_str()
                        .context("triangle snapshot")?,
                )
                .args(["--vs", "vertexShader", "--fs", "fragmentShader"]),
            evidence,
            "amd-air-render",
        )?;
        let log = evidence.join("amd-air-render.log");
        let text = std::fs::read_to_string(&log)?;
        let summary = text
            .lines()
            .find(|line| line.starts_with("AMD render compiler fixtures="))
            .context("incomplete AMD VS/FS compiler fixture")?;
        Some(
            json!({"binary":tools::binding(&binary)?,"output":tools::binding(&log)?,"summary":summary}),
        )
    };
    Ok(
        json!({"scope":"Hosted stage semantics and optional unchanged Apple VS/FS original NAK/Intel/ACO compilation; no runtime pipeline, GPU execution or Metal capability qualification",
        "binary":tools::binding(&binary)?,"output":tools::binding(&output)?,"nvidia":nvidia,"intel":intel,"amd":amd}),
    )
}

/// Runs the owned NVIDIA render compiler's authored fixtures, normally and
/// with every allocation in its translation unit denied in turn. With the
/// Apple triangle, its NAK outputs must equal the direct oracle's
/// `nv-render-artifacts` byte for byte.
pub(super) fn verify_nv_owned(build: &Path, evidence: &Path, inputs: &[Value]) -> Result<Value> {
    let artifacts = evidence.join("nv-render-owned-artifacts");
    let mut runs = Vec::new();
    for variant in ["", "_alloc"] {
        let binary = build.join(format!("src/stela/stela_nv_air_render_owned{variant}"));
        let stage = format!("nv-air-render-owned{variant}");
        let mut command = Command::new(&binary);
        if !inputs.is_empty() && variant.is_empty() {
            std::fs::create_dir(&artifacts)?;
            command
                .arg("--input")
                .arg(
                    inputs[0]["snapshot"]["path"]
                        .as_str()
                        .context("triangle snapshot")?,
                )
                .args([
                    "--vertex",
                    "vertexShader",
                    "--fragment",
                    "fragmentShader",
                    "--output",
                ])
                .arg(&artifacts);
        }
        run(&mut command, evidence, &stage)?;
        let log = evidence.join(format!("{stage}.log"));
        let last = std::fs::read_to_string(&log)?
            .lines()
            .last()
            .map(str::to_owned);
        ensure!(
            last.as_deref()
                .is_some_and(|line| line.starts_with("owned_outputs=")
                    || line == "No external stage input requested; authored fixtures only"),
            "incomplete owned NVIDIA render fixture {stage}"
        );
        runs.push(json!({"binary":tools::binding(&binary)?,"output":tools::binding(&log)?,"summary":last}));
    }
    let mut compared = 0;
    if !inputs.is_empty() {
        let oracle = evidence.join("nv-render-artifacts");
        for entry in std::fs::read_dir(&artifacts)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .context("owned NVIDIA render artifact name")?;
            ensure!(
                std::fs::read(&path)? == std::fs::read(oracle.join(name))?,
                "owned NVIDIA render artifact {} differs from the NAK oracle",
                path.display()
            );
            compared += 1;
        }
        ensure!(
            compared > 0,
            "owned NVIDIA render compiler wrote no artifacts"
        );
    }
    Ok(
        json!({"scope":"Owned NVIDIA VS/FS compilation, upload image and argument table packing; no GPU allocation, upload or execution",
        "runs":runs,"oracle_equal_artifacts":compared}),
    )
}
