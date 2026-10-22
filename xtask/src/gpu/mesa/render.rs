//! Unchanged Apple VS/FS inputs through the original vendor compilers and
//! the owned render compilers. Without inputs only the Meson tests run.
use super::{Probes, artifacts, meson::Build, snapshot, tools};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub(super) fn verify(
    stela: &Build,
    probes: &mut Probes,
    evidence: &Path,
    inputs: &[Value],
) -> Result<Option<Value>> {
    let [triangle, texture] = inputs else {
        ensure!(inputs.is_empty(), "expected two render input snapshots");
        return Ok(None);
    };
    let (triangle, _) = snapshot(triangle)?;
    let (texture, _) = snapshot(texture)?;
    probes.run(
        stela
            .command("stela_air_stage_test")?
            .args(["--input", triangle, "--texture", texture]),
        evidence,
        "air-stage-semantics",
    )?;
    let stages = ["--vertex", "vertexShader", "--fragment", "fragmentShader"];

    let nv_artifacts = evidence.join("nv-render-artifacts");
    fs::create_dir(&nv_artifacts)?;
    let report = probes.run(
        stela
            .command("stela_nv_air_render_probe")?
            .args(["--input", triangle])
            .args(stages)
            .arg("--output")
            .arg(&nv_artifacts),
        evidence,
        "nv-air-render",
    )?;
    let nvidia = artifacts(&nv_artifacts, &report)?;

    let intel_artifacts = evidence.join("intel-render-artifacts");
    let assembly = evidence.join("intel-render-isa.txt");
    fs::create_dir(&intel_artifacts)?;
    let report = probes.run(
        stela
            .command("stela_intel_air_render_probe")?
            .args([
                triangle,
                "vertexShader",
                "fragmentShader",
                texture,
                "samplingShader",
            ])
            .env("STELA_RENDER_EVIDENCE", &intel_artifacts)
            .env("STELA_RENDER_DISASSEMBLY", &assembly),
        evidence,
        "intel-air-render",
    )?;
    let intel = artifacts(&intel_artifacts, &report)?;
    ensure!(
        fs::metadata(&assembly)?.len() > 0,
        "empty Intel ISA listing"
    );

    probes.run(
        stela.command("stela_amd_air_render_probe")?.args([
            "--input",
            triangle,
            "--vs",
            "vertexShader",
            "--fs",
            "fragmentShader",
        ]),
        evidence,
        "amd-air-render",
    )?;

    // The owned NVIDIA render compiler's NAK outputs must equal the oracle's.
    let owned_artifacts = evidence.join("nv-render-owned-artifacts");
    fs::create_dir(&owned_artifacts)?;
    let report = probes.run(
        stela
            .command("stela_nv_air_render_owned")?
            .args(["--input", triangle])
            .args(stages)
            .arg("--output")
            .arg(&owned_artifacts),
        evidence,
        "nv-air-render-owned",
    )?;
    let owned = artifacts(&owned_artifacts, &report)?;
    for name in &report.artifacts {
        ensure!(
            fs::read(owned_artifacts.join(name))? == fs::read(nv_artifacts.join(name))?,
            "owned NVIDIA render artifact {name} differs from the NAK oracle"
        );
    }

    // The owned Intel graphics package, normally and with each of its own
    // allocations denied in turn, against the Intel probe's artifacts.
    for variant in ["", "_alloc"] {
        probes.run(
            stela
                .command(&format!("stela_intel_air_graphics_test{variant}"))?
                .args([triangle, "vertexShader", "fragmentShader"])
                .arg(&intel_artifacts),
            evidence,
            &format!("intel-air-graphics-owned{variant}"),
        )?;
    }
    Ok(Some(json!({
        "nvidia": nvidia, "intel": intel, "intel_isa_listing": tools::binding(&assembly)?,
        "nvidia_owned": owned,
    })))
}
