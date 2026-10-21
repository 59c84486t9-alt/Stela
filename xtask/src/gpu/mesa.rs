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
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const LIBRARIES: &[&str] = &[
    "src/stela/libstela_apple_source.a",
    "src/compiler/nir/libnir.a",
    "src/nouveau/compiler/libnak.a",
    "src/nouveau/compiler/libnak_rs.a",
    "src/nouveau/nil/libnil.a",
    "src/stela/libstela_nv_compute.a",
    "src/stela/libstela_nv_image.a",
    "src/amd/compiler/libaco.a",
    "src/amd/common/libamd_compiler_support.a",
    "src/amd/common/libamd_command_support.a",
    "src/stela/libstela_amd_commands.a",
    "src/stela/libstela_amd_buffer.a",
    "src/stela/libstela_amd_sampler.a",
    "src/stela/libstela_amd_surface.a",
    "src/stela/libstela_amd_image.a",
    "src/amd/addrlib/libaddrlib.a",
    "src/stela/libstela_amd_compute.a",
    "src/stela/libstela_intel_surface.a",
    "src/stela/libstela_intel_compute_native.a",
    "src/stela/libstela_intel_compute_policy.a",
    "src/stela/libstela_intel_gpgpu_native.a",
    "src/stela/libstela_intel_legacy_compute.a",
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
    let stderr_path = evidence.join(format!("{stage}.stderr.log"));
    let log = File::create_new(&path)?;
    let stderr = File::create_new(&stderr_path)?;
    println!("GPU compilers {stage}: {}", path.display());
    let status = command
        // Compiler diagnostics may arrive between chunks of a buffered JSON
        // record. Preserve both streams without corrupting machine-readable
        // stdout or discarding the original diagnostic bytes.
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .status()
        .with_context(|| format!("cannot execute {command:?}"))?;
    ensure!(
        status.success(),
        "{stage} failed; see {} and {}",
        path.display(),
        stderr_path.display()
    );
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
        Some(
            "libamd_compiler_support.a"
                | "libintel_dev.a"
                | "libstela_amd_surface.a"
                | "libstela_amd_image.a"
                | "libstela_intel_surface.a"
        )
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
    if path.file_name().and_then(|name| name.to_str()) == Some("libaddrlib.a") {
        ensure!(
            !undefined
                .iter()
                .any(|name| name.trim_start_matches('_') == "umoddi3"),
            "the public Addrlib host build must not import Apple's private compiler helper"
        );
    }
    if path.file_name().and_then(|name| name.to_str()) == Some("libstela_apple_source.a") {
        for name in &undefined {
            let name = name.trim_start_matches('_');
            ensure!(
                !name.starts_with("LLVM")
                    && !name.starts_with("MTL")
                    && !name.starts_with("IOService")
                    && !name.starts_with("IOConnect"),
                "the hosted source adapter must not import host LLVM or GPU object APIs: {name}"
            );
        }
    }
    Ok(json!({
        "binding": tools::binding(path)?, "objects": count,
        "formats": formats, "architectures": architectures,
        "undefined_symbols": undefined,
    }))
}

fn snapshot_air_inputs(inputs: &[PathBuf], evidence: &Path) -> Result<Vec<Value>> {
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let original = fs::canonicalize(input)?;
            let file = File::open(&original)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && (4..=MAX_BYTES).contains(&metadata.len()),
                "AIR input must be a regular raw bitcode file of 4..={MAX_BYTES} bytes"
            );
            // Bound the read even if another process grows the input. Probes
            // consume this immutable evidence copy, not a changing source path.
            let mut bytes = Vec::new();
            file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= MAX_BYTES as usize && bytes.starts_with(b"BC\xc0\xde"),
                "AIR input must contain bounded raw LLVM bitcode, not a wrapper or archive"
            );
            let snapshot = evidence.join(format!("air-input-{index}.bc"));
            File::create_new(&snapshot)?.write_all(&bytes)?;
            Ok(json!({"original_path": original, "snapshot": tools::binding(&snapshot)?}))
        })
        .collect()
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

fn parse_original_input(log: &str, entry: &str, bytes: u64) -> Result<Value> {
    let records = log
        .lines()
        .filter_map(|line| line.strip_prefix("STELA_AIR_INPUT "))
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        records.len() == 1,
        "probe must identify exactly one raw AIR input"
    );
    let record = &records[0];
    ensure!(
        record["origin"] == "raw_input_file"
            && record["entry"] == entry
            && record["bytes"] == bytes,
        "probe did not compile the requested raw AIR input/entry"
    );
    ensure!(
        record["blake3"].as_str().is_some_and(|hash| {
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        }),
        "probe did not hash its actual AIR input"
    );
    Ok(records.into_iter().next().expect("one record"))
}

fn parse_air_profile(log: &str, expected: super::AirFpProfile) -> Result<Value> {
    let records = log
        .lines()
        .filter_map(|line| line.strip_prefix("STELA_AIR_PROFILE "))
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        records.len() == 1,
        "probe must identify exactly one selected AIR floating-point profile"
    );
    let record = &records[0];
    ensure!(
        record["name"] == expected.name() && record["kind"] == expected.kind(),
        "probe did not use the requested AIR floating-point profile"
    );
    Ok(records.into_iter().next().expect("one record"))
}

fn parse_air_environments(
    log: &str,
    backend: &str,
    profile: super::AirFpProfile,
    targets: &[Value],
) -> Result<Vec<Value>> {
    let records = log
        .lines()
        .filter_map(|line| line.strip_prefix("STELA_AIR_ENVIRONMENT "))
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let compiled: BTreeSet<_> = targets
        .iter()
        .filter(|target| target["state"] == "compiled")
        .filter_map(|target| target["target"].as_str())
        .collect();
    let mut seen = BTreeSet::new();
    for record in &records {
        let target = record["target"].as_str().context("missing AIR target")?;
        ensure!(
            record["backend"] == backend
                && record["fp_profile"] == profile.kind()
                && record["nir_float_controls"]
                    .as_u64()
                    .is_some_and(|mode| u32::try_from(mode).is_ok())
                && compiled.contains(target)
                && seen.insert(target),
            "invalid or duplicate AIR environment for compiled target"
        );
    }
    ensure!(
        seen == compiled,
        "compiled AIR target omitted its environment"
    );
    Ok(records)
}

fn llvm_development_files(config: &Path, library: &Path) -> Result<Value> {
    let query = |args: &[&str]| capture(Command::new(config).args(args));
    let version = query(&["--version"])?;
    ensure!(
        version.starts_with("23."),
        "the AMD backend requires LLVM 23"
    );
    let headers = fs::canonicalize(query(&["--includedir"])?.trim())?;
    let linked = fs::canonicalize(query(&["--link-shared", "--libfiles"])?.trim())?;
    let shared = tools::binding(&linked)?;
    let supplied = tools::binding(library)?;
    ensure!(
        shared["sha256"] == supplied["sha256"] && shared["bytes"] == supplied["bytes"],
        "llvm-config and the AIR frontend must use the same LLVM shared library"
    );
    let rtti = query(&["--has-rtti"])?;
    ensure!(
        ["YES", "NO"].contains(&rtti.trim()),
        "unknown LLVM RTTI configuration"
    );
    Ok(json!({
        "config": tools::binding(config)?, "version": version.trim(),
        "headers": headers, "headers_sha256": source_binding(&headers)?,
        "shared_library": shared, "rtti": rtti.trim() == "YES",
    }))
}

pub fn build(
    jobs: u16,
    require_all_targets: bool,
    llvm_library: Option<&Path>,
    llvm_config: Option<&Path>,
    air_inputs: &[PathBuf],
    entry: Option<&str>,
    fp_profile: super::AirFpProfile,
) -> Result<()> {
    ensure!(
        air_inputs.is_empty() || (llvm_library.is_some() && entry.is_some()),
        "raw AIR inputs require --llvm-library and --entry"
    );
    let llvm_library = llvm_library.map(fs::canonicalize).transpose()?;
    let llvm_config = llvm_config.map(fs::canonicalize).transpose()?;
    let llvm_sdk = llvm_config
        .as_ref()
        .map(|config| {
            llvm_development_files(
                config,
                llvm_library
                    .as_deref()
                    .context("--llvm-config requires --llvm-library")?,
            )
        })
        .transpose()?;
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
    let external_inputs = || -> Result<Vec<Value>> {
        let mut paths = vec![
            "metal/compiler/apple_source.c",
            "metal/compiler/apple_source.h",
            "metal/compiler/apple_source_test.c",
            "nvidia/stela/hosted/image.c",
            "nvidia/stela/hosted/image.h",
            "nvidia/stela/tests/image.c",
            "amd/stela/buffer.c",
            "amd/stela/buffer.h",
            "amd/tests/buffer_test.c",
            "amd/stela/sampler.c",
            "amd/stela/sampler.h",
            "amd/tests/sampler_test.c",
            "amd/tests/sampler_policy_reference.h",
            "amd/tests/surface_host_test.c",
            "amd/stela/image.c",
            "amd/stela/image.h",
            "amd/tests/image_test.c",
            "amd/stela/compute.c",
            "amd/stela/compute.h",
            "amd/stela/compute_policy.c",
            "amd/stela/compute_policy.h",
            "amd/tests/compute_test.c",
            "amd/tests/compute_policy_reference.h",
            "intel/stela/hosted/surface.c",
            "intel/stela/hosted/surface.h",
            "intel/stela/tests/surface.c",
            "intel/stela/hosted/image.c",
            "intel/stela/hosted/image.h",
            "intel/stela/tests/image.c",
            "intel/stela/commands.h",
            "intel/stela/compute_dispatch.c",
            "intel/stela/compute_dispatch.h",
            "intel/stela/compute_dispatch_internal.h",
            "intel/stela/genxml_native.h",
            "intel/stela/dispatch/compute_pack.h",
            "intel/stela/dispatch/compute125.c",
            "intel/stela/dispatch/compute200.c",
            "intel/stela/dispatch/compute300.c",
            "intel/stela/dispatch/compute350.c",
            "intel/stela/hosted/compute.c",
            "intel/stela/hosted/compute.h",
            "intel/stela/hosted/fp_controls.h",
            "intel/stela/tests/compute_dispatch.c",
            "intel/stela/tests/compute_dispatch_mesa.c",
            "intel/stela/tests/compute_program.c",
            "intel/stela/dispatch.c",
            "intel/stela/dispatch.h",
            "intel/stela/dispatch_internal.h",
            "intel/stela/dispatch/pack.h",
            "intel/stela/dispatch/gen70.c",
            "intel/stela/dispatch/gen75.c",
            "intel/stela/dispatch/gen80.c",
            "intel/stela/dispatch/gen90.c",
            "intel/stela/dispatch/gen110.c",
            "intel/stela/dispatch/gen120.c",
            "intel/stela/hosted/legacy_compute.c",
            "intel/stela/hosted/legacy_compute.h",
            "intel/stela/hosted/legacy_compute_internal.h",
            "intel/stela/hosted/legacy_compute_pack.h",
            "intel/stela/hosted/legacy70.c",
            "intel/stela/hosted/legacy75.c",
            "intel/stela/hosted/legacy80.c",
            "intel/stela/hosted/legacy90.c",
            "intel/stela/hosted/legacy110.c",
            "intel/stela/hosted/legacy120.c",
            "intel/stela/tests/legacy_compute_program.c",
            "intel/stela/tests/legacy_elk_validate.c",
            "intel/stela/tests/legacy_elk_validate.h",
        ];
        if llvm_library.is_some() {
            paths.extend([
                "intel/stela/tests/air_brw_probe.c",
                "intel/stela/tests/air_elk_probe.c",
                "intel/stela/tests/air_probe_input.h",
                "intel/stela/tests/fp_controls.c",
                "intel/stela/tests/fp_controls_elk.c",
                "intel/stela/tests/fp_controls_elk.h",
                "amd/tests/air_probe_input.h",
            ]);
        }
        if llvm_sdk.is_some() {
            paths.extend([
                "amd/tests/air_llvm_probe.c",
                "amd/stela/llvm_float.c",
                "amd/stela/llvm_float.h",
                "amd/tests/llvm_float_test.c",
            ]);
        }
        paths
            .iter()
            .map(|name| tools::binding(&gpu.join(name)))
            .collect()
    };
    let external_sources = external_inputs()?;
    let cache = if let Some(sdk) = &llvm_sdk {
        format!(
            "mesa-host-llvm-{}-{}",
            &sdk["headers_sha256"]
                .as_str()
                .context("missing LLVM header hash")?[..16],
            &sdk["shared_library"]["sha256"]
                .as_str()
                .context("missing LLVM library hash")?[..16]
        )
    } else {
        "mesa-host".to_owned()
    };
    let build = tools::root().join(".stela/gpu/build").join(cache);
    let evidence = evidence_directory()?;
    let input_snapshots = snapshot_air_inputs(air_inputs, &evidence)?;
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
            "-Dvideo-codecs=",
            "-Dbuild-tests=false",
            "-Dintel-elk=true",
        ]);
    if let Some(config) = &llvm_config {
        setup
            .env("LLVM_CONFIG", config)
            .arg("-Dstela-amd-llvm=true");
    }
    setup.args([
        if llvm_sdk.is_some() {
            "-Dllvm=enabled"
        } else {
            "-Dllvm=disabled"
        },
        "-Dshared-llvm=enabled",
        "-Ddraw-use-llvm=false",
        if llvm_sdk.as_ref().is_some_and(|sdk| sdk["rtti"] == false) {
            "-Dcpp_rtti=false"
        } else {
            "-Dcpp_rtti=true"
        },
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
    let mut library_paths = LIBRARIES.to_vec();
    if llvm_sdk.is_some() {
        library_paths.push("src/amd/llvm/libamd_common_llvm.a");
        library_paths.push("src/stela/libstela_amd_llvm_float.a");
    }
    compile
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg("-C")
        .arg(&build)
        .arg(format!("-j{jobs}"))
        .args(&library_paths)
        .args(PROBES.iter().map(|(_, binary)| binary));
    compile.args([
        "src/stela/stela_apple_source_test",
        "src/stela/stela_nv_image_probe",
        "src/stela/stela_amd_commands_probe",
        "src/stela/stela_amd_buffer_probe",
        "src/stela/stela_amd_sampler_probe",
        "src/stela/stela_amd_surface_probe",
        "src/stela/stela_amd_image_probe",
        "src/stela/stela_amd_compute_probe",
        "src/stela/stela_intel_surface_probe",
        "src/stela/stela_intel_image_probe",
        "src/stela/stela_intel_compute_program_probe",
        "src/stela/stela_intel_legacy_compute_program_probe",
        "src/stela/stela_intel_compute_packet_probe",
        "src/stela/stela_intel_compute_packer_125_probe",
        "src/stela/stela_intel_compute_packer_200_probe",
        "src/stela/stela_intel_compute_packer_300_probe",
        "src/stela/stela_intel_compute_packer_350_probe",
    ]);
    if llvm_library.is_some() {
        compile.args([
            "src/stela/stela_air_test",
            "src/stela/stela_air_brw_probe",
            "src/stela/stela_air_elk_probe",
            "src/stela/stela_air_aco_probe",
            "src/stela/stela_air_ssbo_test",
            "src/stela/stela_nv_compute_probe",
            "src/stela/stela_intel_fp_controls_probe",
        ]);
        if !input_snapshots.is_empty() {
            compile.arg("src/stela/stela_air_input_nak_probe");
        }
        if llvm_sdk.is_some() {
            compile.arg("src/stela/stela_air_amd_llvm_probe");
            compile.arg("src/stela/stela_amd_llvm_float_probe");
        }
    }
    run(&mut compile, &evidence, "compile")?;
    run(
        &mut Command::new(build.join("src/stela/stela_amd_commands_probe")),
        &evidence,
        "amd-commands",
    )?;
    let source_boundary = build.join("src/stela/stela_apple_source_test");
    run(
        &mut Command::new(&source_boundary),
        &evidence,
        "apple-source-boundary",
    )?;
    let source_compiler_boundary = json!({
        "binary": tools::binding(&source_boundary)?,
        "output": tools::binding(&evidence.join("apple-source-boundary.log"))?,
        "private_compiler_executed": false, "hardware_executed": false,
    });
    let mut resource_probes = Vec::new();
    let mut resource_stages = vec![
        "nv_image",
        "amd_buffer",
        "amd_sampler",
        "amd_surface",
        "amd_image",
        "amd_compute",
        "intel_surface",
        "intel_image",
        "intel_compute_program",
        "intel_legacy_compute_program",
        "intel_compute_packet",
        "intel_compute_packer_125",
        "intel_compute_packer_200",
        "intel_compute_packer_300",
        "intel_compute_packer_350",
    ];
    if llvm_sdk.is_some() {
        resource_stages.push("amd_llvm_float");
    }
    if llvm_library.is_some() {
        resource_stages.push("intel_fp_controls");
    }
    for stage in resource_stages {
        let binary = build.join(format!("src/stela/stela_{stage}_probe"));
        run(&mut Command::new(&binary), &evidence, stage)?;
        resource_probes.push(json!({
            "stage": stage,
            "binary": tools::binding(&binary)?,
            "output": tools::binding(&evidence.join(format!("{stage}.log")))?,
            "hardware_executed": false,
        }));
    }
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
        let mut air_targets = vec![
            ("air-nak", "src/stela/stela_air_test"),
            ("air-brw", "src/stela/stela_air_brw_probe"),
            ("air-elk", "src/stela/stela_air_elk_probe"),
            ("air-aco", "src/stela/stela_air_aco_probe"),
        ];
        if llvm_sdk.is_some() {
            air_targets.push(("air-amd-llvm", "src/stela/stela_air_amd_llvm_probe"));
        }
        for (backend, binary) in air_targets {
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
        let binary = build.join("src/stela/stela_air_ssbo_test");
        run(&mut Command::new(&binary), &evidence, "air-ssbo")?;
        air_probes.push(json!({
            "stage": "air-ssbo-semantics-and-bounds",
            "binary": tools::binding(&binary)?,
            "output": tools::binding(&evidence.join("air-ssbo.log"))?,
            "hardware_executed": false,
        }));
        let binary = build.join("src/stela/stela_nv_compute_probe");
        run(&mut Command::new(&binary), &evidence, "nvidia-compute")?;
        air_probes.push(json!({
            "stage": "nvidia-compute-descriptor-and-launch",
            "binary": tools::binding(&binary)?,
            "output": tools::binding(&evidence.join("nvidia-compute.log"))?,
            "hardware_executed": false,
        }));
    }
    let mut original_input_probes = Vec::new();
    let mut original_unsupported = Vec::new();
    let mut original_compiled = 0;
    for (index, input) in input_snapshots.iter().enumerate() {
        let path = input["snapshot"]["path"]
            .as_str()
            .context("missing raw AIR snapshot path")?;
        let entry = entry.context("raw AIR requires an entry point")?;
        let bytes = input["snapshot"]["bytes"]
            .as_u64()
            .context("missing AIR size")?;
        let mut input_digest = None;
        let mut input_float_controls = None;
        let mut backends = vec![
            ("air-nak", "src/stela/stela_air_input_nak_probe"),
            ("air-aco", "src/stela/stela_air_aco_probe"),
            ("air-brw", "src/stela/stela_air_brw_probe"),
            ("air-elk", "src/stela/stela_air_elk_probe"),
        ];
        if llvm_sdk.is_some() {
            backends.push(("air-amd-llvm", "src/stela/stela_air_amd_llvm_probe"));
        }
        for (backend, binary) in backends {
            let stage = format!("original-{index}-{backend}");
            let binary = build.join(binary);
            let mut probe = Command::new(&binary);
            probe.args([
                "--input",
                path,
                "--entry",
                entry,
                "--fp-profile",
                fp_profile.name(),
            ]);
            run(&mut probe, &evidence, &stage)?;
            let log = evidence.join(format!("{stage}.log"));
            let output = fs::read_to_string(&log)?;
            let provenance = parse_original_input(&output, entry, bytes)?;
            let profile = parse_air_profile(&output, fp_profile)?;
            if let Some(previous) = &input_digest {
                ensure!(
                    previous == &provenance["blake3"],
                    "vendor probes read different AIR bytes"
                );
            } else {
                input_digest = Some(provenance["blake3"].clone());
            }
            let targets = parse_targets(&output, backend)?;
            let environments = parse_air_environments(&output, backend, fp_profile, &targets)?;
            for environment in &environments {
                let mode = environment["nir_float_controls"]
                    .as_u64()
                    .expect("validated float controls");
                if let Some(previous) = input_float_controls {
                    ensure!(
                        previous == mode,
                        "vendor probes requested different AIR float controls"
                    );
                } else {
                    input_float_controls = Some(mode);
                }
            }
            original_compiled += targets.iter().filter(|t| t["state"] == "compiled").count();
            original_unsupported.extend(
                targets
                    .iter()
                    .filter(|t| t["state"] == "unsupported")
                    .cloned(),
            );
            original_input_probes.push(json!({
                "input_index": index, "entry": entry, "stage": backend,
                "binary": tools::binding(&binary)?, "output": tools::binding(&log)?,
                "targets": targets, "hardware_executed": false,
                "provenance": provenance,
                "fp_profile": profile,
                "nir_environments": environments,
            }));
        }
        ensure!(
            tools::binding(Path::new(path))? == input["snapshot"],
            "AIR snapshot changed during compilation"
        );
    }
    let libraries = library_paths
        .iter()
        .map(|name| inspect_archive(&build.join(name)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        source_binding(&source)? == hash,
        "compiler source changed during the build; rerun against a stable tree"
    );
    ensure!(
        external_inputs()? == external_sources,
        "external GPU source changed during the build"
    );
    if let Some(config) = &llvm_config {
        ensure!(
            Some(llvm_development_files(
                config,
                llvm_library.as_deref().expect("validated LLVM library")
            )?) == llvm_sdk,
            "LLVM development inputs changed during the build"
        );
    }
    let mut stderr_paths = fs::read_dir(&evidence)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    stderr_paths.retain(|path| {
        path.file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".stderr.log"))
    });
    stderr_paths.sort();
    let stderr_logs = stderr_paths
        .iter()
        .map(|path| tools::binding(path))
        .collect::<Result<Vec<_>>>()?;
    let receipt = json!({
        "schema": 2, "stage": "native-host-shader-compiler-build",
        "stela_platform_port": false, "hardware_executed": false,
        "metal_frontend": false,
        "source_compiler_boundary": source_compiler_boundary,
        "air_compute_compiler_subset": llvm_library.is_some(),
        "amd_llvm_development_files": llvm_sdk,
        "air_codegen_probes": air_probes,
        "source_tree_sha256": hash,
        "stderr_logs": stderr_logs,
        "external_probe_sources": external_sources,
        "resource_probes": resource_probes,
        "original_air_inputs": input_snapshots,
        "air_fp_profile": fp_profile.name(),
        "original_air_probes": original_input_probes,
        "unsupported_input_targets": original_unsupported,
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
    if !input_snapshots.is_empty() {
        println!(
            "Unchanged raw AIR inputs: {} files, {original_compiled} compiled target fixtures, {} unsupported; no GPU execution.",
            input_snapshots.len(),
            original_unsupported.len()
        );
    }
    ensure!(
        !require_all_targets || (unsupported.is_empty() && original_unsupported.is_empty()),
        "some compiler fixture targets remain unsupported; see {}",
        evidence.join("compilers.json").display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn diagnostics_cannot_split_a_structured_probe_record() {
        let evidence = tempfile::tempdir().unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", r#"printf '%s' 'STELA_AIR_PROFILE {"name":"ieee",'; printf 'compiler diagnostic\n' >&2; printf '"kind":0}\n'"#]);
        run(&mut command, evidence.path(), "streams").unwrap();
        let stdout = fs::read_to_string(evidence.path().join("streams.log")).unwrap();
        assert!(parse_air_profile(&stdout, super::super::AirFpProfile::Ieee).is_ok());
        assert_eq!(
            fs::read_to_string(evidence.path().join("streams.stderr.log")).unwrap(),
            "compiler diagnostic\n"
        );
    }

    #[test]
    fn raw_air_snapshot_is_bounded_and_independent_of_the_source_path() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.bc");
        let evidence = temp.path().join("evidence");
        fs::create_dir(&evidence).unwrap();
        let bytes = b"BC\xc0\xdeoriginal";
        fs::write(&input, bytes).unwrap();
        let records = snapshot_air_inputs(std::slice::from_ref(&input), &evidence).unwrap();
        fs::write(&input, b"changed").unwrap();
        let snapshot = records[0]["snapshot"]["path"].as_str().unwrap();
        assert_eq!(fs::read(snapshot).unwrap(), bytes);
        assert_eq!(
            records[0]["snapshot"]["sha256"],
            stela_runtime::sha256(bytes)
        );
        assert!(snapshot_air_inputs(std::slice::from_ref(&input), temp.path()).is_err());
        File::create(&input)
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        assert!(snapshot_air_inputs(&[input], temp.path()).is_err());
    }

    #[test]
    fn original_air_evidence_cannot_substitute_a_source_fixture() {
        let record = format!(
            "STELA_AIR_INPUT {}\n",
            json!({"origin":"raw_input_file", "entry":"kernel", "bytes":4, "blake3":"0".repeat(64)})
        );
        assert!(parse_original_input(&record, "kernel", 4).is_ok());
        assert!(parse_original_input("STELA_GPU_TARGET {}", "kernel", 4).is_err());
        assert!(
            parse_original_input(
                &record.replace("raw_input_file", "original_fixture"),
                "kernel",
                4
            )
            .is_err()
        );
        assert!(parse_original_input(&record, "another_entry", 4).is_err());
        assert!(parse_original_input(&record, "kernel", 5).is_err());
        assert!(parse_original_input(&format!("{record}{record}"), "kernel", 4).is_err());
    }

    #[test]
    fn air_profile_evidence_cannot_substitute_or_omit_the_selected_environment() {
        use super::super::AirFpProfile;
        for profile in [AirFpProfile::Ieee, AirFpProfile::Apple32023Air29Msl41] {
            let record = format!(
                "STELA_AIR_PROFILE {}\n",
                json!({"name":profile.name(), "kind":profile.kind()})
            );
            assert!(parse_air_profile(&record, profile).is_ok());
            assert!(parse_air_profile("", profile).is_err());
            assert!(parse_air_profile(&format!("{record}{record}"), profile).is_err());
            assert!(
                parse_air_profile(&record.replace(profile.name(), "inferred"), profile).is_err()
            );
        }
        let ieee = "STELA_AIR_PROFILE {\"name\":\"ieee\",\"kind\":0}\n";
        assert!(parse_air_profile(ieee, AirFpProfile::Apple32023Air29Msl41).is_err());
        assert!(parse_air_profile(&ieee.replace(":0", ":1"), AirFpProfile::Ieee).is_err());
    }

    #[test]
    fn every_compiled_air_target_reports_its_actual_requested_controls() {
        use super::super::AirFpProfile;
        let targets = [
            json!({"target":"sm75", "state":"compiled"}),
            json!({"target":"future", "state":"unsupported"}),
        ];
        let record = "STELA_AIR_ENVIRONMENT {\"backend\":\"air-nak\",\"target\":\"sm75\",\"fp_profile\":0,\"nir_float_controls\":0}\n";
        let parse =
            |text: &str| parse_air_environments(text, "air-nak", AirFpProfile::Ieee, &targets);
        assert_eq!(parse(record).unwrap().len(), 1);
        assert!(parse("").is_err());
        assert!(parse(&format!("{record}{record}")).is_err());
        assert!(parse(&record.replace("sm75", "future")).is_err());
        assert!(parse(&record.replace("air-nak", "air-aco")).is_err());
        assert!(parse(&record.replace("\"fp_profile\":0", "\"fp_profile\":1")).is_err());
        assert!(
            parse(&record.replace("\"nir_float_controls\":0", "\"nir_float_controls\":-1"))
                .is_err()
        );
    }

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
