//! Native host compiler builds. Device access and Metal are separate ports.
use super::support::{capture, evidence_directory, source_binding};
use crate::tools;
use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const LIBRARIES: &[&str] = &[
    "src/compiler/nir/libnir.a",
    "src/nouveau/compiler/libnak.a",
    "src/nouveau/compiler/libnak_rs.a",
    "src/nouveau/nil/libnil.a",
    "src/stela/libstela_nv_compute.a",
    "src/amd/compiler/libaco.a",
    "src/amd/common/libamd_compiler_support.a",
    "src/amd/common/libamd_command_support.a",
    "src/stela/libstela_amd_commands.a",
    "src/intel/dev/libintel_dev.a",
    "src/intel/compiler/gen/libintel_compiler_gen.a",
    "src/intel/compiler/brw/libintel_compiler.a",
    "src/intel/compiler/elk/libintel_compiler_elk.a",
    "src/intel/compiler/jay/libintel_compiler_jay.a",
];

const PROBES: &[(&str, &str)] = &[
    ("nak-codegen", "src/stela/stela_nak_probe"),
    ("aco-codegen", "src/stela/stela_aco_probe"),
    ("brw-codegen", "src/stela/stela_brw_probe"),
    ("elk-codegen", "src/stela/stela_elk_probe"),
];

fn tool(name: &str, local: &str) -> Result<PathBuf> {
    tools::which(name)
        .or_else(|| {
            let path = tools::root().join(".tools/gpu").join(local).join(name);
            path.is_file().then_some(path)
        })
        .with_context(|| format!("install {name} and put it in PATH"))
}

fn run(command: &mut Command, evidence: &Path, stage: &str) -> Result<()> {
    let path = evidence.join(format!("{stage}.log"));
    let log = File::create_new(&path)?;
    println!("GPU compilers {stage}: {}", path.display());
    let status = command
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status()
        .with_context(|| format!("cannot execute {command:?}"))?;
    ensure!(status.success(), "{stage} failed; see {}", path.display());
    Ok(())
}

fn inspect_archive(path: &Path) -> Result<Value> {
    let data = fs::read(path)?;
    let archive = ArchiveFile::parse(&*data)?;
    let mut formats = BTreeSet::new();
    let mut architectures = BTreeSet::new();
    let mut undefined = BTreeSet::new();
    let mut count = 0;
    for member in archive.members() {
        let member = member?;
        let object = object::File::parse(member.data(&*data)?)
            .with_context(|| format!("non-object member in {}", path.display()))?;
        ensure!(
            object.kind() == object::ObjectKind::Relocatable,
            "non-relocatable member in {}",
            path.display()
        );
        formats.insert(format!("{:?}", object.format()));
        architectures.insert(format!("{:?}", object.architecture()));
        for symbol in object.symbols().filter(|symbol| symbol.is_undefined()) {
            let name = symbol.name()?;
            if !name.is_empty() {
                undefined.insert(name.to_owned());
            }
        }
        count += 1;
    }
    ensure!(count > 0, "{} contains no objects", path.display());
    // The capability/format libraries must remain independent of Linux
    // device access. Inspect actual objects rather than only Meson options.
    if matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("libamd_compiler_support.a" | "libintel_dev.a")
    ) {
        for name in &undefined {
            let name = name.trim_start_matches('_');
            ensure!(
                !name.starts_with("drm") && name != "ioctl",
                "{} depends on device I/O through {name}",
                path.display()
            );
        }
    }
    Ok(json!({
        "binding": tools::binding(path)?, "objects": count,
        "formats": formats, "architectures": architectures,
        "undefined_symbols": undefined,
    }))
}

fn parse_targets(log: &str, backend: &str) -> Result<Vec<Value>> {
    let mut targets = Vec::new();
    let mut names = BTreeSet::new();
    for line in log.lines() {
        let Some(record) = line.strip_prefix("STELA_GPU_TARGET ") else {
            continue;
        };
        let record: Value = serde_json::from_str(record)?;
        ensure!(
            record["backend"] == backend,
            "wrong backend in codegen record"
        );
        let name = record["target"]
            .as_str()
            .context("codegen record has no target")?;
        ensure!(
            !name.is_empty() && names.insert(name.to_owned()),
            "empty or repeated codegen target"
        );
        match record["state"].as_str() {
            Some("compiled") => ensure!(
                record["bytes"].as_u64().is_some_and(|bytes| bytes > 0),
                "compiled target has no emitted code"
            ),
            Some("unsupported") => ensure!(
                record["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty()),
                "unsupported target has no reason"
            ),
            _ => anyhow::bail!("unknown codegen target state"),
        }
        targets.push(record);
    }
    ensure!(
        targets.iter().any(|record| record["state"] == "compiled"),
        "codegen probe emitted no compiled targets"
    );
    Ok(targets)
}

pub fn build(jobs: u16, require_all_targets: bool, llvm_library: Option<&Path>) -> Result<()> {
    let llvm_library = llvm_library.map(fs::canonicalize).transpose()?;
    let meson = tool("meson", "generators/bin")?;
    let ninja = tool("ninja", "generators/bin")?;
    let bindgen = tool("bindgen", "rust/bin")?;
    let cbindgen = tool("cbindgen", "rust/bin")?;
    let paths = [&meson, &ninja, &bindgen, &cbindgen]
        .iter()
        .filter_map(|path| path.parent())
        .map(Path::to_owned)
        .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default()))
        .collect::<Vec<_>>();
    let path = env::join_paths(paths)?;
    let gpu = tools::root().join("crates/stela-drivers/src/gpu");
    let source = gpu.join("common/mesa");
    let build = tools::root().join(".stela/gpu/build/mesa-host");
    let evidence = evidence_directory()?;
    let hash = source_binding(&source)?;
    let mut setup = Command::new(&meson);
    setup
        .current_dir(tools::root())
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args(["setup", "--wrap-mode=nodownload"])
        .arg(&build)
        .arg(&source)
        .args([
            "-Dstela-compilers=nvidia,amd,intel",
            "-Dplatforms=[]",
            "-Dgallium-drivers=[]",
            "-Dvulkan-drivers=[]",
            "-Dopengl=false",
            "-Dgles1=disabled",
            "-Dgles2=disabled",
            "-Degl=disabled",
            "-Dgbm=disabled",
            "-Dglx=disabled",
            "-Dllvm=disabled",
            "-Dvideo-codecs=",
            "-Dbuild-tests=false",
            "-Dintel-elk=true",
        ]);
    setup.arg(format!(
        "-Dstela-air-llvm-library={}",
        llvm_library
            .as_ref()
            .map_or_else(String::new, |path| path.display().to_string())
    ));
    if build.join("meson-private/coredata.dat").is_file() {
        setup.arg("--reconfigure");
    }
    run(&mut setup, &evidence, "setup")?;
    let mut compile = Command::new(&ninja);
    compile
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg("-C")
        .arg(&build)
        .arg(format!("-j{jobs}"))
        .args(LIBRARIES)
        .args(PROBES.iter().map(|(_, binary)| binary));
    compile.arg("src/stela/stela_amd_commands_probe");
    if llvm_library.is_some() {
        compile.args([
            "src/stela/stela_air_test",
            "src/stela/stela_air_brw_probe",
            "src/stela/stela_air_aco_probe",
            "src/stela/stela_nv_compute_probe",
        ]);
    }
    run(&mut compile, &evidence, "compile")?;
    run(
        &mut Command::new(build.join("src/stela/stela_amd_commands_probe")),
        &evidence,
        "amd-commands",
    )?;
    let mut probes = Vec::new();
    let mut unsupported = Vec::new();
    let mut compiled = 0;
    for (stage, binary) in PROBES {
        let mut probe = Command::new(build.join(binary));
        run(&mut probe, &evidence, stage)?;
        let log = evidence.join(format!("{stage}.log"));
        let backend = stage
            .strip_suffix("-codegen")
            .context("invalid probe stage")?;
        let targets = parse_targets(&fs::read_to_string(&log)?, backend)?;
        for target in &targets {
            if target["state"] == "compiled" {
                compiled += 1;
            } else {
                unsupported.push(target.clone());
            }
        }
        probes.push(json!({
            "stage": stage,
            "output": tools::binding(&evidence.join(format!("{stage}.log")))?,
            "binary": tools::binding(&build.join(binary))?,
            "targets": targets,
        }));
    }
    let mut air_probes = Vec::new();
    let compiler_unsupported = unsupported.len();
    let mut air_compiled = 0;
    if let Some(library) = &llvm_library {
        for (backend, binary) in [
            ("air-nak", "src/stela/stela_air_test"),
            ("air-brw", "src/stela/stela_air_brw_probe"),
            ("air-aco", "src/stela/stela_air_aco_probe"),
        ] {
            run(&mut Command::new(build.join(binary)), &evidence, backend)?;
            let log = evidence.join(format!("{backend}.log"));
            let targets = parse_targets(&fs::read_to_string(&log)?, backend)?;
            air_compiled += targets
                .iter()
                .filter(|record| record["state"] == "compiled")
                .count();
            unsupported.extend(
                targets
                    .iter()
                    .filter(|record| record["state"] == "unsupported")
                    .cloned(),
            );
            air_probes.push(json!({
                "stage": backend,
                "binary": tools::binding(&build.join(binary))?,
                "output": tools::binding(&log)?,
                "targets": targets,
            }));
        }
        // Bind the actual development-host compiler binary, not just its path.
        air_probes.push(json!({"llvm_library": tools::binding(library)?}));
        let binary = build.join("src/stela/stela_nv_compute_probe");
        run(&mut Command::new(&binary), &evidence, "nvidia-compute")?;
        air_probes.push(json!({
            "stage": "nvidia-compute-descriptor-and-launch",
            "binary": tools::binding(&binary)?,
            "output": tools::binding(&evidence.join("nvidia-compute.log"))?,
            "hardware_executed": false,
        }));
    }
    let libraries = LIBRARIES
        .iter()
        .map(|name| inspect_archive(&build.join(name)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        source_binding(&source)? == hash,
        "compiler source changed during the build; rerun against a stable tree"
    );
    let receipt = json!({
        "schema": 2, "stage": "native-host-shader-compiler-build",
        "stela_platform_port": false, "hardware_executed": false,
        "metal_frontend": false,
        "air_compute_compiler_subset": llvm_library.is_some(),
        "air_codegen_probes": air_probes,
        "source_tree_sha256": hash,
        "origin": serde_json::from_slice::<Value>(&fs::read(gpu.join("sources.json"))?)?,
        "host": {"os": env::consts::OS, "arch": env::consts::ARCH},
        "meson": capture(Command::new(&meson).arg("--version"))?,
        "setup": format!("{setup:?}"), "compile": format!("{compile:?}"),
        "libraries": libraries,
        "amd_command_probe": {
            "binary": tools::binding(&build.join("src/stela/stela_amd_commands_probe"))?,
            "output": tools::binding(&evidence.join("amd-commands.log"))?,
            "hardware_executed": false,
        },
        "codegen_probes": probes,
        "unsupported_fixture_targets": unsupported,
    });
    File::create_new(evidence.join("compilers.json"))?
        .write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    println!(
        "Native compiler fixtures: {compiled} compiled, {compiler_unsupported} unsupported; AIR fixtures: {air_compiled} compiled, {} unsupported.",
        unsupported.len() - compiler_unsupported
    );
    for target in &unsupported {
        println!(
            "  unsupported {}/{}: {}",
            target["backend"], target["target"], target["reason"]
        );
    }
    ensure!(
        !require_all_targets || unsupported.is_empty(),
        "some compiler fixture targets remain unsupported; see {}",
        evidence.join("compilers.json").display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codegen_evidence_keeps_unsupported_targets_distinct_from_emitted_code() {
        let good = "STELA_GPU_TARGET {\"backend\":\"brw\",\"target\":\"skl\",\"state\":\"compiled\",\"bytes\":112}\n";
        let unsupported = "STELA_GPU_TARGET {\"backend\":\"brw\",\"target\":\"nvl\",\"state\":\"unsupported\",\"reason\":\"dispatch-qualification\"}\n";
        let records =
            parse_targets(&format!("compiler diagnostics\n{good}{unsupported}"), "brw").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["state"], "unsupported");
        assert!(parse_targets(unsupported, "brw").is_err());
        assert!(parse_targets(&format!("{good}{good}"), "brw").is_err());
        assert!(parse_targets(&good.replace("112", "0"), "brw").is_err());
        assert!(parse_targets(good, "aco").is_err());
    }
}
