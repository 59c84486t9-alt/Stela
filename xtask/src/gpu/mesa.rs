//! Native host compiler builds. Device access and Metal are separate ports.
//!
//! Meson defines what is built and run: every target in
//! `gpu/compiler/meson.build` and every test in its suite `stela`; the tests
//! in its other suites also take this task's inputs. Probes report through
//! typed records (`record.rs`), so this task lists no targets or counts.
use super::support::{
    build_directory, capture, evidence_directory, gpu, source_binding, third_party, tool,
};
use crate::tools;
use anyhow::{Context, Result, ensure};
use meson::Build;
use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
use record::{Origin, Outcome, Record, Report};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::SystemTime,
};

mod library;
mod meson;
mod record;
mod render;
mod threadgroup;

/// The explicit macOS object test uses this same canonical Rust input owner.
/// Keep its build command and evidence in the existing implementation.
pub(super) fn build_metal_input(evidence: &Path) -> Result<PathBuf> {
    library::build_input_offline(evidence)
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

/// Every probe run with its checked records, and the targets they held.
#[derive(Default)]
struct Probes {
    runs: Vec<Value>,
    unsupported: Vec<Value>,
    compiled: usize,
    refused: usize,
}

impl Probes {
    /// Runs a probe and checks its outcomes against the expectations it made.
    fn run(&mut self, command: &mut Command, evidence: &Path, stage: &str) -> Result<Report> {
        let binary = PathBuf::from(command.get_program());
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        run(command, evidence, stage)?;
        let log = evidence.join(format!("{stage}.log"));
        let report = Report::parse(&fs::read_to_string(&log)?)
            .with_context(|| format!("{stage}: invalid records in {}", log.display()))?;
        self.compiled += report.count(Outcome::Compiled);
        self.refused += report.count(Outcome::Refused);
        for record in report.held() {
            let Record::Held { target, reason } = record else {
                unreachable!("held records only");
            };
            self.unsupported
                .push(json!({"stage": stage, "target": target, "reason": reason}));
        }
        self.runs.push(json!({
            "stage": stage, "args": args, "binary": tools::binding(&binary)?,
            "output": tools::binding(&log)?, "records": &report, "hardware_executed": false,
        }));
        Ok(report)
    }
}

/// Binds the files a probe wrote into `directory`, which must be exactly the
/// artifacts it recorded.
fn artifacts(directory: &Path, report: &Report) -> Result<Vec<Value>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        ensure!(entry.file_type()?.is_file(), "non-file artifact");
        names.insert(
            entry
                .file_name()
                .into_string()
                .ok()
                .context("artifact name")?,
        );
    }
    ensure!(
        !names.is_empty() && names == report.artifacts,
        "{} differs from the recorded artifacts",
        directory.display()
    );
    names
        .iter()
        .map(|name| tools::binding(&directory.join(name)))
        .collect()
}

fn inspect_archive(path: &Path, stela_library: bool) -> Result<Value> {
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
                undefined.insert(name.trim_start_matches('_').to_owned());
            }
        }
        count += 1;
    }
    ensure!(count > 0, "{} contains no objects", path.display());
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("archive name")?;
    // The libraries Stela's Meson definition builds must remain independent
    // of Linux device access. Inspect actual objects rather than only Meson
    // options. Upstream
    // archives keep device queries Stela never calls; libdrm is headers
    // only, so a live call into it cannot link.
    if stela_library {
        for symbol in &undefined {
            ensure!(
                !symbol.starts_with("drm") && symbol != "ioctl",
                "{name} depends on device I/O through {symbol}"
            );
        }
    }
    if name == "libaddrlib.a" {
        ensure!(
            !undefined.contains("umoddi3"),
            "the public Addrlib host build must not import Apple's private compiler helper"
        );
    }
    if name == "libstela_apple_source.a" {
        for symbol in &undefined {
            ensure!(
                !["LLVM", "MTL", "IOService", "IOConnect"]
                    .iter()
                    .any(|prefix| symbol.starts_with(prefix)),
                "the hosted source adapter must not import host LLVM or GPU object APIs: {symbol}"
            );
        }
    }
    Ok(json!({
        "binding": tools::binding(path)?, "objects": count,
        "formats": formats, "architectures": architectures,
        "undefined_symbols": undefined,
    }))
}

fn snapshot_air_inputs(inputs: &[PathBuf], evidence: &Path, prefix: &str) -> Result<Vec<Value>> {
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
            let snapshot = evidence.join(format!("{prefix}-{index}.bc"));
            File::create_new(&snapshot)?.write_all(&bytes)?;
            Ok(json!({"original_path": original, "snapshot": tools::binding(&snapshot)?}))
        })
        .collect()
}

/// The path and size of an input snapshot.
fn snapshot(input: &Value) -> Result<(&str, u64)> {
    Ok((
        input["snapshot"]["path"]
            .as_str()
            .context("missing AIR snapshot path")?,
        input["snapshot"]["bytes"]
            .as_u64()
            .context("missing AIR snapshot size")?,
    ))
}

/// Checks that a probe compiled the named unchanged input file.
fn check_input(report: &Report, entry: &str, bytes: u64) -> Result<String> {
    let (origin, actual, blake3, actual_entry) = report.input()?;
    ensure!(
        origin == Origin::RawInputFile && actual == bytes && actual_entry == entry,
        "probe did not compile the requested raw AIR input/entry"
    );
    ensure!(
        blake3.len() == 64 && blake3.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "probe did not hash its actual AIR input"
    );
    Ok(blake3.to_owned())
}

/// Compiles each raw AIR input through every probe in suite
/// `stela-air-input`. All read the same bytes and request the same controls.
fn compile_air_inputs(
    stela: &Build,
    probes: &mut Probes,
    evidence: &Path,
    inputs: &[Value],
    entry: Option<&str>,
    fp_profile: super::AirFpProfile,
) -> Result<()> {
    for (index, input) in inputs.iter().enumerate() {
        let (path, bytes) = snapshot(input)?;
        let entry = entry.context("raw AIR requires an entry point")?;
        let mut digest = None;
        let mut float_controls = None;
        for test in stela.suite("stela-air-input") {
            let stage = format!("original-{index}-{}", test.name);
            let mut command = test.command([
                "--input",
                path,
                "--entry",
                entry,
                "--fp-profile",
                fp_profile.name(),
            ]);
            let report = probes.run(&mut command, evidence, &stage)?;
            let blake3 = check_input(&report, entry, bytes)?;
            ensure!(
                *digest.get_or_insert_with(|| blake3.clone()) == blake3,
                "vendor probes read different AIR bytes"
            );
            ensure!(
                report.profile()? == (fp_profile.name(), fp_profile.kind()),
                "probe did not use the requested AIR floating-point profile"
            );
            for mode in report.environments(fp_profile.kind())?.into_values() {
                ensure!(
                    *float_controls.get_or_insert(mode) == mode,
                    "vendor probes requested different AIR float controls"
                );
            }
        }
        ensure!(digest.is_some(), "Meson defines no stela-air-input probes");
        ensure!(
            tools::binding(Path::new(path))? == input["snapshot"],
            "AIR snapshot changed during compilation"
        );
    }
    Ok(())
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

/// Binds the build's sources in Stela's tree, which must not have changed
/// since `started`.
fn bind_external(paths: &[PathBuf], started: SystemTime) -> Result<Vec<Value>> {
    paths
        .iter()
        .map(|path| {
            ensure!(
                fs::metadata(path)?.modified()? <= started,
                "{} changed during the build",
                path.display()
            );
            tools::binding(path)
        })
        .collect()
}

pub struct BuildOptions<'a> {
    pub jobs: u16,
    pub require_all_targets: bool,
    pub llvm_library: Option<&'a Path>,
    pub llvm_config: Option<&'a Path>,
    pub air_inputs: &'a [PathBuf],
    pub entry: Option<&'a str>,
    pub fp_profile: super::AirFpProfile,
    pub threadgroup_inputs: &'a [PathBuf],
    pub render_inputs: &'a [PathBuf],
}

pub fn build(options: BuildOptions<'_>) -> Result<()> {
    let BuildOptions {
        jobs,
        require_all_targets,
        llvm_library,
        llvm_config,
        air_inputs,
        entry,
        fp_profile,
        threadgroup_inputs,
        render_inputs,
    } = options;
    ensure!(
        air_inputs.is_empty() || (llvm_library.is_some() && entry.is_some()),
        "raw AIR inputs require --llvm-library and --entry"
    );
    ensure!(
        threadgroup_inputs.is_empty() || (threadgroup_inputs.len() == 3 && llvm_library.is_some()),
        "threadgroup fixtures require exactly three raw inputs and --llvm-library"
    );
    ensure!(
        render_inputs.is_empty() || (render_inputs.len() == 2 && llvm_library.is_some()),
        "render fixtures require triangle and texture raw inputs and --llvm-library"
    );
    let started = SystemTime::now();
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
    // Original ACO optionally invokes this original disassembler through PATH.
    // Bind its actual bytes rather than treating a successful IR fallback as
    // evidence that emitted machine code was decoded.
    let clrx_disassembler = llvm_sdk
        .as_ref()
        .and_then(|_| tools::which("clrxdisasm"))
        .map(|path| tools::binding(&path))
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
    let gpu = gpu();
    let source = third_party("mesa");
    let cache = if let Some(sdk) = &llvm_sdk {
        format!(
            "compilers-llvm-{}-{}",
            &sdk["headers_sha256"]
                .as_str()
                .context("missing LLVM header hash")?[..16],
            &sdk["shared_library"]["sha256"]
                .as_str()
                .context("missing LLVM library hash")?[..16]
        )
    } else {
        "compilers".to_owned()
    };
    let build = build_directory(&cache);
    let evidence = evidence_directory()?;
    let metal_input = if cfg!(target_os = "macos") && llvm_library.is_some() {
        Some(library::build_input(&evidence)?)
    } else {
        None
    };
    let input_snapshots = snapshot_air_inputs(air_inputs, &evidence, "air-input")?;
    let threadgroup_snapshots =
        snapshot_air_inputs(threadgroup_inputs, &evidence, "threadgroup-input")?;
    let render_snapshots = snapshot_air_inputs(render_inputs, &evidence, "render-input")?;
    let hash = source_binding(&source)?;
    let mut setup = Command::new(&meson);
    setup
        .current_dir(tools::root())
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        // Meson downloads the wraps the build names into gpu/subprojects.
        .arg("setup")
        .arg(&build)
        .arg(&gpu);
    if let Some(config) = &llvm_config {
        setup.env("LLVM_CONFIG", config).arg("-Damd-llvm=true");
    }
    setup.arg(
        if llvm_sdk.as_ref().is_some_and(|sdk| sdk["rtti"] == false) {
            "-Dcpp_rtti=false"
        } else {
            "-Dcpp_rtti=true"
        },
    );
    setup.arg(format!(
        "-Dair-llvm-library={}",
        llvm_library
            .as_ref()
            .map_or_else(String::new, |path| path.display().to_string())
    ));
    setup.arg(format!(
        "-Dmetal-input-library={}",
        metal_input
            .as_ref()
            .map_or_else(String::new, |p| p.display().to_string())
    ));
    if build.join("meson-private/coredata.dat").is_file() {
        setup.arg("--reconfigure");
    }
    run(&mut setup, &evidence, "setup")?;
    // The wraps Meson downloaded, which setup may just have fetched.
    let subprojects = gpu.join("subprojects");
    let wraps = source_binding(&subprojects)?;
    let stela = Build::load(&build, &gpu.join("compiler/meson.build"))?;
    let mut compile = Command::new(&ninja);
    compile
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg("-C")
        .arg(&build)
        .arg(format!("-j{jobs}"))
        .args(stela.outputs());
    run(&mut compile, &evidence, "compile")?;
    let inputs = stela.inputs(&ninja, &gpu)?;
    let external_sources = bind_external(&inputs.external, started)?;
    if metal_input.is_some() {
        library::check_boundaries(&stela)?;
    }
    let mut probes = Probes::default();
    for test in stela.suite("stela") {
        probes.run(&mut test.command::<_, &str>([]), &evidence, &test.name)?;
    }
    compile_air_inputs(
        &stela,
        &mut probes,
        &evidence,
        &input_snapshots,
        entry,
        fp_profile,
    )?;
    let render = render::verify(&stela, &mut probes, &evidence, &render_snapshots)?;
    let threadgroup = threadgroup::verify(&stela, &mut probes, &evidence, &threadgroup_snapshots)?;
    let libraries = inputs
        .archives
        .iter()
        .map(|archive| inspect_archive(archive, stela.builds(archive)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        source_binding(&source)? == hash && source_binding(&subprojects)? == wraps,
        "compiler source changed during the build; rerun against a stable tree"
    );
    ensure!(
        bind_external(&inputs.external, started)? == external_sources,
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
    if let Some(binding) = &clrx_disassembler {
        let path = binding["path"].as_str().context("missing CLRX tool path")?;
        ensure!(
            tools::binding(Path::new(path))? == *binding,
            "CLRX disassembler changed during compiler qualification"
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
    let metal_input = metal_input
        .as_ref()
        .map(|library| -> Result<Value> {
            Ok(json!({
                "library": tools::binding(library)?,
                "sources_sha256": source_binding(&gpu.join("metal/input"))?,
            }))
        })
        .transpose()?;
    let receipt = json!({
        "schema": 3, "stage": "native-host-shader-compiler-build",
        "stela_platform_port": false, "hardware_executed": false,
        "metal_frontend": false,
        "source_tree_sha256": hash,
        "subprojects_sha256": wraps,
        "external_sources": external_sources,
        "metal_input": metal_input,
        "amd_llvm_development_files": llvm_sdk,
        "llvm_library": llvm_library.as_deref().map(tools::binding).transpose()?,
        "optional_clrx_disassembler": clrx_disassembler,
        "air_fp_profile": fp_profile.name(),
        "original_air_inputs": input_snapshots,
        "render_inputs": render_snapshots,
        "render_artifacts": render,
        "threadgroup_inputs": threadgroup_snapshots,
        "threadgroup_artifacts": threadgroup,
        "probes": probes.runs,
        "unsupported_targets": probes.unsupported,
        "stderr_logs": stderr_logs,
        "origin": super::fetch::origins()?,
        "host": {"os": env::consts::OS, "arch": env::consts::ARCH},
        "meson": capture(Command::new(&meson).arg("--version"))?,
        "setup": format!("{setup:?}"), "compile": format!("{compile:?}"),
        "libraries": libraries,
    });
    File::create_new(evidence.join("compilers.json"))?
        .write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    println!(
        "Compiler fixtures: {} compiled, {} refused by design, {} unsupported; no GPU execution.",
        probes.compiled,
        probes.refused,
        probes.unsupported.len()
    );
    for target in &probes.unsupported {
        let field = |key| target[key].as_str().unwrap_or_default();
        println!(
            "  unsupported {}: {}: {}",
            field("stage"),
            field("target"),
            field("reason")
        );
    }
    ensure!(
        !require_all_targets || probes.unsupported.is_empty(),
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
        let mut command = Command::new("/bin/sh");
        command.args(["-c", r#"printf '%s' 'STELA_RECORD {"kind":"air_profile","name":"ieee",'; printf 'compiler diagnostic\n' >&2; printf '"fp_profile":0}\n'"#]);
        let mut probes = Probes::default();
        let report = probes
            .run(&mut command, evidence.path(), "streams")
            .unwrap();
        assert_eq!(report.profile().unwrap(), ("ieee", 0));
        assert_eq!(
            fs::read_to_string(evidence.path().join("streams.stderr.log")).unwrap(),
            "compiler diagnostic\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_runs_collect_held_targets_and_fail_on_unexpected_outcomes() {
        let evidence = tempfile::tempdir().unwrap();
        let mut probes = Probes::default();
        let script = |records: &str| {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", &format!("printf '%s\\n' {records}")]);
            command
        };
        let expect =
            r#"'STELA_RECORD {"kind":"expect","target":"nvl","outcome":"held","reason":"gen35"}'"#;
        let held = r#"'STELA_RECORD {"kind":"held","target":"nvl","reason":"gen35"}'"#;
        probes
            .run(
                &mut script(&format!("{expect} {held}")),
                evidence.path(),
                "held",
            )
            .unwrap();
        assert_eq!(probes.unsupported.len(), 1);
        assert!(
            probes
                .run(&mut script(expect), evidence.path(), "missing")
                .is_err()
        );
        assert!(
            probes
                .run(&mut script(held), evidence.path(), "unexpected")
                .is_err()
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
        let records =
            snapshot_air_inputs(std::slice::from_ref(&input), &evidence, "air-input").unwrap();
        fs::write(&input, b"changed").unwrap();
        let snapshot = records[0]["snapshot"]["path"].as_str().unwrap();
        assert_eq!(fs::read(snapshot).unwrap(), bytes);
        assert_eq!(
            records[0]["snapshot"]["sha256"],
            stela_formats::sha256(bytes)
        );
        assert!(
            snapshot_air_inputs(std::slice::from_ref(&input), temp.path(), "air-input").is_err()
        );
        File::create(&input)
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        assert!(snapshot_air_inputs(&[input], temp.path(), "air-input").is_err());
    }

    #[test]
    fn air_evidence_requires_unchanged_input() {
        let record = |origin: &str, entry: &str| {
            Report::parse(&format!(
                "STELA_RECORD {}\n",
                json!({"kind": "air_input", "origin": origin, "entry": entry,
                       "bytes": 4, "blake3": "0".repeat(64)})
            ))
            .unwrap()
        };
        assert!(check_input(&record("raw_input_file", "kernel"), "kernel", 4).is_ok());
        assert!(check_input(&record("original_fixture", "kernel"), "kernel", 4).is_err());
        assert!(check_input(&record("raw_input_file", "other"), "kernel", 4).is_err());
        assert!(check_input(&record("raw_input_file", "kernel"), "kernel", 5).is_err());
        assert!(check_input(&Report::default(), "kernel", 4).is_err());
    }

    #[test]
    fn artifact_directories_hold_exactly_the_recorded_files() {
        let temp = tempfile::tempdir().unwrap();
        let report = |names: &[&str]| {
            Report::parse(
                &names
                    .iter()
                    .map(|name| {
                        format!(
                            "STELA_RECORD {}\n",
                            json!({"kind": "artifact", "path": name})
                        )
                    })
                    .collect::<String>(),
            )
            .unwrap()
        };
        assert!(artifacts(temp.path(), &report(&[])).is_err());
        fs::write(temp.path().join("sm75.code"), b"x").unwrap();
        assert_eq!(
            artifacts(temp.path(), &report(&["sm75.code"]))
                .unwrap()
                .len(),
            1
        );
        assert!(artifacts(temp.path(), &report(&["sm75.code", "sm80.code"])).is_err());
        fs::write(temp.path().join("stray"), b"x").unwrap();
        assert!(artifacts(temp.path(), &report(&["sm75.code"])).is_err());
    }
}
