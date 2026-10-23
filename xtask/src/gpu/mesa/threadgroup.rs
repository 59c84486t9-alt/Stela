//! Threadgroup fixtures: the original Apple two-entry module, then LLVM
//! static and dynamic WG64 modules. Offline compilation, never GPU execution.
use super::{Probes, artifacts, check_input, meson::Build, run, snapshot, tools};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub(super) fn verify(
    stela: &Build,
    probes: &mut Probes,
    evidence: &Path,
    inputs: &[Value],
) -> Result<Option<Value>> {
    if inputs.is_empty() {
        return Ok(None);
    }
    ensure!(
        inputs.len() == 3,
        "threadgroup fixtures need exactly three inputs"
    );
    let snapshots = inputs.iter().map(snapshot).collect::<Result<Vec<_>>>()?;
    let paths = snapshots.iter().map(|(path, _)| *path).collect::<Vec<_>>();
    let apple = paths[0];
    run(
        stela
            .command("stela_library_assembly_test")?
            .args(["--archive-pair", apple])
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
    // Export the semantic fixture through its actual LLVM producer, rather than
    // maintaining a second bitcode fixture or interpreting the source ourselves.
    let mixed = evidence.join("multiple-threadgroups.bc");
    run(
        stela
            .command("stela_threadgroup_nir_test")?
            .arg("--export")
            .arg(&mixed),
        evidence,
        "metal-threadgroup-export",
    )?;
    let mixed = mixed.to_str().context("export path")?;
    for test in stela.suite("stela-owned-air") {
        let name = &test.name;
        probes.run(
            &mut test.command(["--input", apple, "stela_threadgroup_static"]),
            evidence,
            &format!("{name}-static"),
        )?;
        probes.run(
            &mut test.command(["--shared-refusal", apple, "stela_threadgroup_dynamic"]),
            evidence,
            &format!("{name}-dynamic-refusal"),
        )?;
        // Each specialization's rows, whose total shared bytes (with
        // alignment) every compiled target must report.
        for (fixture, input, entry, workgroup, rows, total) in [
            (
                "128",
                apple,
                "stela_threadgroup_dynamic",
                "32",
                &["3:128"][..],
                128,
            ),
            (
                "256",
                apple,
                "stela_threadgroup_dynamic",
                "32",
                &["3:256"],
                256,
            ),
            (
                "512",
                apple,
                "stela_threadgroup_dynamic",
                "32",
                &["3:512"],
                512,
            ),
            (
                "mixed",
                mixed,
                "kernel",
                "64",
                &["3:256", "11:16", "7:128"],
                403,
            ),
        ] {
            let report = probes.run(
                &mut test.command(
                    ["--threadgroup", input, entry, workgroup]
                        .into_iter()
                        .chain(rows.iter().copied()),
                ),
                evidence,
                &format!("{name}-threadgroup-{fixture}"),
            )?;
            for (target, facts) in report.compiled() {
                ensure!(
                    facts
                        .as_ref()
                        .and_then(|facts| facts["total_shared"].as_u64())
                        == Some(total),
                    "{name} {fixture}/{target} does not share {total} bytes"
                );
            }
        }
    }

    let nv_artifacts = evidence.join("nv-threadgroup-artifacts");
    fs::create_dir(&nv_artifacts)?;
    let report = probes.run(
        stela
            .command("stela_nvidia_air_threadgroup_test")?
            .args(&paths)
            .arg(&nv_artifacts),
        evidence,
        "nv-threadgroup",
    )?;
    let nvidia = artifacts(&nv_artifacts, &report)?;

    for (fixture, index, entry, workgroup, shared, dynamic) in [
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
        let report = probes.run(
            stela.command("stela_intel_air_threadgroup_test")?.args([
                "--input",
                paths[index],
                "--entry",
                entry,
                "--workgroup",
                workgroup,
                "--shared",
                shared,
                "--threadgroup-index",
                dynamic,
            ]),
            evidence,
            &format!("intel-threadgroup-{fixture}"),
        )?;
        check_input(&report, entry, snapshots[index].1)?;
    }

    // The AMD shared-memory probe needs the retained LLVM backend.
    if stela.defines("stela_amd_air_threadgroup_test") {
        probes.run(
            stela
                .command("stela_amd_air_threadgroup_test")?
                .args(&paths),
            evidence,
            "amd-threadgroup",
        )?;
    }
    for (input, (path, _)) in inputs.iter().zip(&snapshots) {
        ensure!(
            tools::binding(Path::new(path))? == input["snapshot"],
            "threadgroup snapshot changed during compilation"
        );
    }
    Ok(Some(json!({"nvidia": nvidia})))
}
