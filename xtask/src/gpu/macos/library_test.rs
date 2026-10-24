//! Explicit, host-only execution of the finite Objective-C object contract.
//! Neither the default macOS build nor vendor compiler tests call this task.
use super::{ABIS, LibraryTestOptions, dependencies, mach_o, run as sdk_run, sdk};
use crate::{gpu::{mesa, support::{evidence_directory, gpu}}, tools};
use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectKind, ObjectSymbol, read::archive::ArchiveFile};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use stela_runtime::sha256;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Debug)]
struct Inconclusive(String);

impl std::fmt::Display for Inconclusive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Inconclusive {}

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const INPUT_LIMIT: usize = 64 * 1024 * 1024;
const OUTPUT_LIMIT: usize = 1024 * 1024;
// Explicit external LLVM dylibs are regular files of at most 1 GiB.
const LLVM_LIMIT: usize = 1024 * 1024 * 1024;
const CASES: &[&str] = &[
    "baseline", "empty_values", "indexed_values", "named_values",
    "missing_name", "optional_error", "value_mutation", "owned_input",
    "async_values", "async_missing", "descriptor_values", "async_descriptor",
    "constructor_refusals", "descriptor_refusals", "archive_refusal",
    "function_library_ownership", "snapshot_ownership",
    "rename_variants", "rename_copy_and_empty", "async_rename", "native_descriptor_reference",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    outcome: String,
    detail: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Host {
    architecture: String,
    os_major: u32,
    os_version: String,
    os_build: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Device {
    name: String,
    registry_id: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Llvm {
    major: u32,
    minor: u32,
    patch: u32,
    loaded_path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Framework {
    symbol: String,
    loaded_path: String,
    image_uuid: String,
    header_bytes: u64,
    header_load_commands_sha256: String,
    digest_scope: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    original_sha256: String,
    module_sha256: String,
    raw_air_sha256: String,
    source_sha256: String,
    compiler_build_sha256: String,
    entry: String,
    raw_offset: u64,
    raw_bytes: u64,
    target: String,
    compiler_profile: u32,
    request_language: u32,
    request_fast_math: bool,
    air_major: u32,
    air_minor: u32,
    language_major: u32,
    language_minor: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorObservation {
    domain: String,
    code: i64,
    #[serde(deserialize_with = "Option::deserialize")]
    description: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionObservation {
    name: String,
    #[serde(deserialize_with = "Option::deserialize")]
    reason: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FunctionObservation {
    returned: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    name: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    function_type: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    options: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    error: Option<ErrorObservation>,
    #[serde(deserialize_with = "Option::deserialize")]
    exception: Option<ExceptionObservation>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparisonObservation {
    id: String,
    native: FunctionObservation,
    stela: FunctionObservation,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeReference {
    outcome: String,
    reason: String,
    input_sha256: String,
    dispatch_sha256: String,
    input_bytes: u64,
    entry: String,
    library_loaded: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    load_error: Option<ErrorObservation>,
    #[serde(deserialize_with = "Option::deserialize")]
    reference_exception: Option<ExceptionObservation>,
    observations: Vec<ComparisonObservation>,
    comparison_scope: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    suite: String,
    outcome: String,
    reason: String,
    cases: Vec<Case>,
    input_sha256: String,
    input_bytes: u64,
    entry: String,
    host: Host,
    #[serde(deserialize_with = "Option::deserialize")]
    device: Option<Device>,
    llvm: Llvm,
    #[serde(deserialize_with = "Option::deserialize")]
    frameworks: Option<Vec<Framework>>,
    #[serde(deserialize_with = "Option::deserialize")]
    provenance: Option<Provenance>,
    gpu_work_submitted: bool,
    guest_device_qualified: bool,
    full_api_completion: bool,
    first_party_outcome: String,
    #[serde(deserialize_with = "Option::deserialize")]
    native_descriptor_reference: Option<NativeReference>,
}

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut options = File::options();
    options.read(true);
    // A supplied FIFO must not block before its regular-file rejection.
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK);
    let file = options.open(path).with_context(|| format!("open {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "not a regular file: {}", path.display());
    ensure!(file.metadata()?.len() <= limit as u64, "file too large: {}", path.display());
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "file grew beyond bound: {}", path.display());
    Ok(bytes)
}

// Hash the same bounded regular-file capture used by ABI inspection; never
// reopen an explicit LLVM input through the unbounded general binding helper.
fn bounded_binding(path: &Path, limit: usize) -> Result<(Vec<u8>, Value)> {
    let bytes = bounded(path, limit)?;
    let binding = json!({"path":path,"bytes":bytes.len(),"sha256":sha256(&bytes)});
    Ok((bytes, binding))
}

fn hex256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_cases(cases: &[Case], outcome: &str) -> Result<()> {
    let mut ids = BTreeSet::new();
    for case in cases {
        ensure!(CASES.contains(&case.id.as_str()) && ids.insert(case.id.as_str()), "unknown/duplicate runtime case");
        ensure!(["PASS", "FAIL", "INCONCLUSIVE"].contains(&case.outcome.as_str()) && case.detail.len() <= 8192, "invalid runtime case result");
    }
    match outcome {
        "PASS" => ensure!(ids == CASES.iter().copied().collect() && cases.iter().all(|c| c.outcome == "PASS"), "runtime omitted/failed a required case"),
        "INCONCLUSIVE" => ensure!(!cases.iter().any(|c| c.outcome == "FAIL"), "inconclusive hides a failure"),
        "FAIL" => (),
        _ => bail!("unknown runtime outcome"),
    }
    Ok(())
}

fn validate_public_observation(value: &FunctionObservation) -> Result<()> {
    ensure!(value.name.as_ref().is_none_or(|name| name.len() <= 8192), "unbounded public function name");
    if !value.returned {
        ensure!(value.name.is_none() && value.function_type.is_none() && value.options.is_none(), "absent function has invented metadata");
    }
    // Keep an anomalous native nil/partial getter observation representable on
    // nonpass. A PASS below requires complete, matching genuine functions.
    if let Some(error) = &value.error {
        ensure!(error.domain.len() <= 8192 && error.description.as_ref().is_none_or(|value| value.len() <= 8192), "unbounded native error");
    }
    if let Some(exception) = &value.exception {
        ensure!(exception.name.len() <= 8192 && exception.reason.as_ref().is_none_or(|value| value.len() <= 8192), "unbounded native exception");
    }
    Ok(())
}

fn validate_reference(record: &Record) -> Result<()> {
    ensure!(["NOT_RUN", "PASS", "FAIL", "INCONCLUSIVE"].contains(&record.first_party_outcome.as_str()), "unknown first-party outcome");
    let Some(reference) = &record.native_descriptor_reference else {
        ensure!(record.outcome != "PASS", "v2 pass lacks mandatory native reference");
        return Ok(());
    };
    ensure!(record.first_party_outcome == "PASS", "native comparison hides incomplete first-party cases");
    ensure!(reference.input_sha256 == record.input_sha256 && reference.input_bytes == record.input_bytes && reference.entry == record.entry, "native reference input differs");
    ensure!(reference.comparison_scope == "public_function_presence_name_type_options;errors_observed_only", "unknown native comparison scope");
    ensure!(["PASS", "FAIL", "INCONCLUSIVE"].contains(&reference.outcome.as_str()), "unknown native reference outcome");
    if reference.library_loaded {
        ensure!(reference.dispatch_sha256 == record.input_sha256, "native dispatch input differs");
    }
    let expected = ["named_lookup", "descriptor", "descriptor_values", "rename", "rename_empty", "async_descriptor", "async_rename"];
    let mut ids = BTreeSet::new();
    for observation in &reference.observations {
        ensure!(expected.contains(&observation.id.as_str()) && ids.insert(observation.id.as_str()), "unknown/duplicate native observation");
        validate_public_observation(&observation.native)?;
        validate_public_observation(&observation.stela)?;
        if reference.outcome == "PASS" {
            let native = &observation.native;
            let stela = &observation.stela;
            ensure!(native.exception.is_none() && stela.exception.is_none() && native.returned && stela.returned && native.name.is_some() && native.name == stela.name && native.function_type == Some(3) && native.function_type == stela.function_type && native.options == Some(0) && native.options == stela.options, "native/Stela public observation differs");
            if observation.id == "named_lookup" {
                // Public MTLFunctionTypeKernel is 3; MTLB's compute TYPE is 2.
                ensure!(native.returned && native.function_type == Some(3), "native selected kernel prerequisite is absent");
            }
        }
    }
    match reference.outcome.as_str() {
        "PASS" => ensure!(record.outcome == "PASS" && reference.reason.is_empty() && reference.library_loaded && reference.reference_exception.is_none() && ids == expected.into_iter().collect(), "incomplete/contradictory native comparison pass"),
        "INCONCLUSIVE" => ensure!(record.outcome == "INCONCLUSIVE" && !reference.reason.is_empty(), "inconclusive comparison was misclassified"),
        "FAIL" => ensure!(record.outcome == "FAIL" && !reference.reason.is_empty(), "failed comparison was misclassified"),
        _ => bail!("unknown native reference outcome"),
    }
    Ok(())
}

fn validate(
    record: &Record,
    status: Option<i32>,
    architecture: &str,
    input: &[u8],
    entry: &str,
    llvm: &Value,
) -> Result<()> {
    ensure!(record.schema == 2 && record.suite == "stela-metal-library-objects-v2", "wrong runtime schema/suite");
    ensure!(record.input_sha256 == sha256(input) && record.input_bytes == input.len() as u64 && record.entry == entry, "runtime input identity differs");
    ensure!(record.host.architecture == architecture && !record.host.os_version.is_empty(), "runtime process ABI/OS identity differs");
    ensure!(!record.gpu_work_submitted && !record.guest_device_qualified && !record.full_api_completion, "runtime claims unqualified work");
    ensure!(record.llvm.major == 23, "runtime did not use LLVM23");
    let (_, loaded) = bounded_binding(&fs::canonicalize(&record.llvm.loaded_path)?, LLVM_LIMIT)?;
    ensure!(loaded["sha256"] == llvm["sha256"] && loaded["bytes"] == llvm["bytes"], "runtime loaded a different LLVM library");
    validate_cases(&record.cases, &record.outcome)?;
    validate_reference(record)?;
    if let Some(frameworks) = &record.frameworks {
        let mut symbols = BTreeSet::new();
        for framework in frameworks {
            ensure!(["NSStringFromClass", "CFGetTypeID", "MTLCreateSystemDefaultDevice"].contains(&framework.symbol.as_str()) && symbols.insert(framework.symbol.as_str()), "unknown/duplicate framework origin");
            ensure!(!framework.loaded_path.is_empty() && framework.image_uuid.len() == 32 && framework.image_uuid.bytes().all(|b| b.is_ascii_hexdigit()), "missing framework image identity");
            ensure!((32..=1024 * 1024 + 32).contains(&framework.header_bytes) && hex256(&framework.header_load_commands_sha256) && framework.digest_scope == "mach_header_64_and_load_commands_only", "invalid bounded framework header identity");
        }
        ensure!(symbols.len() == 3, "missing retained framework origin");
    }
    if let Some(p) = &record.provenance {
        ensure!(p.original_sha256 == record.input_sha256 && p.entry == entry && !p.target.is_empty(), "runtime shader identity differs");
        ensure!([&p.original_sha256, &p.module_sha256, &p.raw_air_sha256, &p.source_sha256, &p.compiler_build_sha256].into_iter().all(|v| hex256(v)), "invalid shader digest");
        ensure!(p.raw_bytes >= 4 && p.raw_offset <= input.len() as u64 && p.raw_bytes <= input.len() as u64 - p.raw_offset, "invalid runtime raw range");
        let raw = &input[p.raw_offset as usize..(p.raw_offset + p.raw_bytes) as usize];
        ensure!(sha256(raw) == p.raw_air_sha256, "runtime raw AIR digest differs");
        ensure!(p.compiler_profile == 0 && p.request_language == 0 && !p.request_fast_math && p.source_sha256 == "0".repeat(64), "precompiled input claims source compiler authentication");
        ensure!(p.air_major == 2 && p.language_major > 0, "invalid admitted language identity");
    }
    match record.outcome.as_str() {
        "PASS" => {
            ensure!(status == Some(0) && record.reason.is_empty(), "pass/exit disagreement");
            ensure!(record.host.os_major >= 26 && !record.host.os_build.is_empty() && record.device.is_some() && record.provenance.is_some() && record.frameworks.is_some(), "pass lacks actual device/provenance");
        }
        "INCONCLUSIVE" => {
            ensure!(status == Some(3) && !record.reason.is_empty(), "inconclusive/exit disagreement");
        }
        "FAIL" => ensure!(status == Some(1) && !record.reason.is_empty(), "failure/exit disagreement"),
        _ => bail!("unknown runtime outcome"),
    }
    Ok(())
}

fn exercise(options: LibraryTestOptions<'_>, evidence: &Path, receipt: &mut Value) -> Result<()> {
    ensure!(cfg!(target_os = "macos"), "Metal object runtime tests require macOS");
    let (architecture, abi) = match std::env::consts::ARCH {
        "x86_64" => ("x86_64", ABIS[2]),
        "aarch64" => ("aarch64", ABIS[1]),
        _ => bail!("unsupported host-process architecture"),
    };
    ensure!(!options.entry.is_empty() && options.entry.len() <= 4096 && !options.entry.contains('\0'), "invalid bounded entry name");
    ensure!(options.metallib.to_str().is_some() && options.llvm_library.to_str().is_some(), "input/dependency path is not UTF-8");
    receipt["request"] = json!({"metallib":options.metallib,"entry":options.entry,"llvm_library":options.llvm_library});
    let input_path = fs::canonicalize(options.metallib)?;
    ensure!(input_path.to_str().is_some(), "input path is not UTF-8");
    let input = bounded(&input_path, INPUT_LIMIT)?;
    ensure!(input.len() >= 4, "archive is too short");
    let snapshot = evidence.join("input.metallib");
    let mut file = File::options().create_new(true).write(true).open(&snapshot)?;
    file.write_all(&input)?;
    file.sync_all()?;
    drop(file);
    let mut permissions = fs::metadata(&snapshot)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&snapshot, permissions)?;
    receipt["input"] = json!({"caller_path":input_path,"snapshot":tools::binding(&snapshot)?,"entry":options.entry});
    receipt["host_process_architecture"] = json!(architecture);
    let llvm_path = fs::canonicalize(options.llvm_library)?;
    ensure!(llvm_path.to_str().is_some(), "LLVM path is not UTF-8");
    let (llvm_bytes, llvm) = bounded_binding(&llvm_path, LLVM_LIMIT)?;
    mach_o(&llvm_bytes, ObjectKind::Dynamic, abi)?;
    drop(llvm_bytes);
    receipt["llvm_library"] = llvm.clone();
    let sdk_root = fs::canonicalize(PathBuf::from(sdk(&["--show-sdk-path"])?.trim()))?;
    let compiler = PathBuf::from(sdk(&["--find", "clang"])?.trim());
    receipt["sdk"] = json!({"path":sdk_root,"version":sdk(&["--show-sdk-version"])?.trim(),"settings":tools::binding(&sdk_root.join("SDKSettings.json"))?});
    receipt["compiler"] = json!({"file":tools::binding(&compiler)?,"version":super::capture(Command::new(&compiler).arg("--version"))?});
    let gpu = gpu();
    let overlay = gpu.join("compiler/llvm/include");
    let llvm_headers = tools::root().join("third_party/llvm/llvm/include");
    ensure!(overlay.join("llvm/Config/llvm-config.h").is_file() && llvm_headers.join("llvm-c/Core.h").is_file(), "existing pinned LLVM headers/configuration are required; no fetch is performed");
    for path in [&gpu, &sdk_root, &overlay, &llvm_headers, evidence] {
        ensure!(!path.to_string_lossy().chars().any(char::is_whitespace), "dependency files require paths without whitespace: {}", path.display());
    }
    let mut link_inputs = Vec::new();
    for name in ["Foundation", "CoreFoundation", "Metal"] {
        let framework = sdk_root.join(format!("System/Library/Frameworks/{name}.framework"));
        let stub = [framework.join(format!("{name}.tbd")), framework.join(format!("Versions/A/{name}.tbd"))]
            .into_iter().find(|p| p.is_file()).with_context(|| format!("missing actual SDK link stub for {name}"))?;
        link_inputs.push(fs::canonicalize(stub)?);
    }
    receipt["framework_link_stubs"] = json!(link_inputs.iter().map(|p| tools::binding(p)).collect::<Result<Vec<_>>>()?);
    let canonical_sources = [gpu.join("metal/input/lib.rs"), gpu.join("metal/input/Cargo.toml"), gpu.join("metal/library.rs"), tools::root().join("Cargo.lock")];
    let canonical_preimages = canonical_sources.into_iter().map(|p| Ok((p.clone(), tools::binding(&p)?))).collect::<Result<Vec<_>>>()?;
    receipt["canonical_input_sources"] = json!(canonical_preimages.iter().map(|(_, binding)| binding).collect::<Vec<_>>());
    let archive = mesa::build_metal_input(evidence)?;
    let archive_bytes = fs::read(&archive)?;
    let parsed = ArchiveFile::parse(archive_bytes.as_slice())?;
    let mut found_input = false;
    let mut members = 0;
    for member in parsed.members() {
        let member = member?;
        let data = member.data(archive_bytes.as_slice())?;
        let (object, _) = mach_o(data, ObjectKind::Relocatable, abi)?;
        members += 1;
        found_input |= object.symbols().any(|s| s.is_definition() && s.name() == Ok("_stela_metal_input_open"));
    }
    ensure!(members > 0 && found_input, "canonical input archive lacks the host input implementation");
    receipt["canonical_input_archive"] = tools::binding(&archive)?;
    let build = evidence.join("host");
    fs::create_dir(&build)?;
    let target = format!("{}-apple-macos26.0", abi.0);
    let common: Vec<OsString> = vec!["-target".into(), target.into(), "-isysroot".into(), sdk_root.as_os_str().into(), "-O2".into(), "-Wall".into(), "-Wextra".into(), "-Werror".into()];
    let sources = [
        ("compiler/library_assembly.c", false),
        ("compiler/air_metadata.c", false),
        ("compiler/apple_source.c", false),
        ("metal/macos/library.m", true),
        ("metal/macos/tests/library_objects.m", true),
    ];
    let mut objects = Vec::new();
    let mut dependencies_bound = BTreeSet::new();
    let mut commands = Vec::new();
    let mut preimages = vec![
        (compiler.clone(), tools::binding(&compiler)?),
        (sdk_root.join("SDKSettings.json"), tools::binding(&sdk_root.join("SDKSettings.json"))?),
        (archive.clone(), tools::binding(&archive)?),
    ];
    preimages.extend(canonical_preimages);
    preimages.extend(link_inputs.into_iter().map(|p| Ok((p.clone(), tools::binding(&p)?))).collect::<Result<Vec<_>>>()?);
    for (relative, objc) in sources {
        let source = gpu.join(relative);
        let stem = source.file_stem().context("source stem")?;
        let object = build.join(stem).with_extension("o");
        let dep = build.join(stem).with_extension("d");
        let before = tools::binding(&source)?;
        preimages.push((source.clone(), before));
        let mut args = common.clone();
        if objc { args.extend(["-fobjc-arc", "-fblocks"].map(OsString::from)); }
        else { args.extend(["-std=c11", "-Wconversion"].map(OsString::from)); }
        args.extend(["-I".into(), overlay.as_os_str().into(), "-I".into(), llvm_headers.as_os_str().into()]);
        args.extend(["-MD".into(), "-MP".into(), "-MF".into(), dep.as_os_str().into(), "-c".into(), source.as_os_str().into(), "-o".into(), object.as_os_str().into()]);
        commands.push(json!({"tool":compiler,"argv":args}));
        receipt["build_commands"] = json!(commands);
        receipt["source_inputs"] = json!(preimages.iter().map(|(_, binding)| binding).collect::<Vec<_>>());
        sdk_run("clang", &args, &evidence.join("compile.log"))?;
        dependencies_bound.extend(dependencies(&build, dep.file_name().context("dependency name")?.to_str().context("dependency UTF-8")?)?);
        objects.push(object);
    }
    let executable = build.join("metal-library-test");
    let mut args = common;
    args.extend(objects.iter().map(|p| OsString::from(p.as_os_str())));
    args.extend([archive.as_os_str().into(), llvm_path.as_os_str().into()]);
    args.extend(["-framework", "Foundation", "-framework", "CoreFoundation", "-framework", "Metal", "-lresolv", "-liconv"].map(OsString::from));
    args.extend(["-Xlinker".into(), "-rpath".into(), "-Xlinker".into(), llvm_path.parent().context("LLVM parent")?.as_os_str().into()]);
    args.extend(["-o".into(), executable.as_os_str().into()]);
    commands.push(json!({"tool":compiler,"argv":args}));
    receipt["build_commands"] = json!(commands);
    sdk_run("clang", &args, &evidence.join("link.log"))?;
    let binary_bytes = fs::read(&executable)?;
    let (binary, subtype) = mach_o(&binary_bytes, ObjectKind::Executable, abi)?;
    let definitions = ["_STELAMetalCreateLibrary", "_STELAMetalCopyFunctionSnapshot", "_stela_metal_assemble_archive", "_stela_metal_input_open"];
    for name in definitions { ensure!(binary.symbols().any(|s| s.is_definition() && s.name() == Ok(name)), "runtime executable missing {name}"); }
    ensure!(!binary.symbols().any(|s| s.name().is_ok_and(|n| n.starts_with("_nir_") || n == "_stela_air_to_nir")), "unexpected NIR/backend link closure");
    preimages.push((executable.clone(), tools::binding(&executable)?));
    receipt["executable"] = json!({"file":tools::binding(&executable)?,"cpu_subtype_and_capabilities":subtype,"imports":binary.imports()?.into_iter().map(|i| Ok(json!({"name":std::str::from_utf8(i.name())?,"library":std::str::from_utf8(i.library())?}))).collect::<Result<Vec<_>>>()?});
    let bound_dependencies = dependencies_bound.iter().map(|p| tools::binding(p)).collect::<Result<Vec<_>>>()?;
    receipt["dependency_inputs"] = json!(bound_dependencies);
    preimages.extend(dependencies_bound.into_iter().zip(bound_dependencies));
    let stdout = evidence.join("runtime.stdout.json");
    let stderr = evidence.join("runtime.stderr.log");
    let runtime_args = [snapshot.as_os_str().to_owned(), options.entry.into(), sha256(&input).into()];
    receipt["runtime_argv"] = json!(runtime_args);
    receipt["runtime_stdout_path"] = json!(stdout);
    receipt["runtime_stderr_path"] = json!(stderr);
    let mut child = Command::new(&executable).args(&runtime_args).stdin(Stdio::null()).stdout(Stdio::from(File::create_new(&stdout)?)).stderr(Stdio::from(File::create_new(&stderr)?)).spawn()?;
    let status = match tools::wait(&mut child, Duration::from_secs(30)) {
        Ok(status) => status,
        Err(error) => { tools::stop(&mut child); return Err(error); }
    };
    receipt["runtime_exit"] = json!(status.and_then(|s| s.code()));
    receipt["runtime_timed_out"] = json!(status.is_none());
    let bytes = bounded(&stdout, OUTPUT_LIMIT)?;
    let diagnostics = bounded(&stderr, 8 * OUTPUT_LIMIT)?;
    receipt["runtime_stdout"] = json!({"path":stdout,"bytes":bytes.len(),"sha256":sha256(&bytes)});
    receipt["runtime_stderr"] = json!({"path":stderr,"bytes":diagnostics.len(),"sha256":sha256(&diagnostics)});
    ensure!(status.is_some(), "runtime timed out; child killed and reaped");
    for (path, before) in preimages { ensure!(tools::binding(&path)? == before, "source changed during runtime qualification: {}", path.display()); }
    ensure!(bounded_binding(&llvm_path, LLVM_LIMIT)?.1 == llvm, "LLVM changed during qualification");
    ensure!(bounded(&input_path, INPUT_LIMIT)? == input && bounded(&snapshot, INPUT_LIMIT)? == input, "input changed during qualification");
    let record: Record = serde_json::from_slice(&bytes).context("invalid strict runtime record")?;
    receipt["runtime_record"] = serde_json::to_value(&record)?;
    validate(&record, status.and_then(|s| s.code()), architecture, &input, options.entry, &llvm)?;
    if record.outcome == "INCONCLUSIVE" {
        return Err(anyhow::Error::new(Inconclusive(record.reason)));
    }
    ensure!(record.outcome == "PASS", "runtime {}: {} (nonpassing)", record.outcome, record.reason);
    Ok(())
}

pub(super) fn run(options: LibraryTestOptions<'_>) -> Result<()> {
    let evidence = evidence_directory()?;
    let mut receipt = json!({"schema":2,"suite":"stela-metal-library-objects-v2","scope":"Finite real host Objective-C library/function object semantics only","outcome":"FAIL","gpu_work_submitted":false,"guest_device_qualified":false,"full_api_completion":false});
    let result = exercise(options, &evidence, &mut receipt);
    if result.is_ok() { receipt["outcome"] = json!("PASS"); }
    else if result.as_ref().err().is_some_and(|e| e.downcast_ref::<Inconclusive>().is_some()) { receipt["outcome"] = json!("INCONCLUSIVE"); }
    if let Err(error) = &result { receipt["error"] = json!(format!("{error:#}")); }
    let path = evidence.join("metal-library-test.json");
    let mut file = File::create_new(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    println!("Metal object runtime qualification: {}", path.display());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Protocol data only: no LLVM, device, library or execution evidence.
    fn record_json() -> String {
        json!({
            "schema":2,"suite":"stela-metal-library-objects-v2","outcome":"INCONCLUSIVE",
            "reason":"protocol fixture only","cases":[],"input_sha256":"0".repeat(64),
            "input_bytes":4,"entry":"fixture","host":{"architecture":"x86_64","os_major":26,"os_version":"fixture","os_build":"fixture"},
            "device":null,"frameworks":null,"llvm":{"major":23,"minor":0,"patch":0,"loaded_path":"unused-protocol-fixture"},
            "provenance":null,"first_party_outcome":"NOT_RUN","native_descriptor_reference":null,"gpu_work_submitted":false,"guest_device_qualified":false,"full_api_completion":false
        }).to_string()
    }

    #[test]
    fn rejects_duplicate_and_unknown_fields_before_status_interpretation() {
        let original = record_json();
        assert!(serde_json::from_str::<Record>(&original).is_ok());
        for field in ["device", "frameworks", "provenance", "native_descriptor_reference"] {
            let missing = original.replace(&format!("\"{field}\":null,"), "");
            assert_ne!(original, missing);
            assert!(serde_json::from_str::<Record>(&missing).is_err());
        }
        let duplicate = format!("{{\"schema\":2,{}", &original[1..]);
        assert!(serde_json::from_str::<Record>(&duplicate).is_err());
        let duplicate_nullable = original.replace("\"device\":null", "\"device\":null,\"device\":null");
        assert_ne!(original, duplicate_nullable);
        assert!(serde_json::from_str::<Record>(&duplicate_nullable).is_err());
        let nested = original.replace("\"os_major\":26", "\"os_major\":26,\"os_major\":26");
        assert_ne!(original, nested);
        assert!(serde_json::from_str::<Record>(&nested).is_err());
        let unknown = format!("{{\"unexpected\":true,{}", &original[1..]);
        assert!(serde_json::from_str::<Record>(&unknown).is_err());
        let wrong_type = original.replace("\"input_bytes\":4", "\"input_bytes\":true");
        assert_ne!(original, wrong_type);
        assert!(serde_json::from_str::<Record>(&wrong_type).is_err());
    }

    fn complete() -> Vec<Case> {
        CASES.iter().map(|id| Case { id: (*id).to_owned(), outcome: "PASS".to_owned(), detail: String::new() }).collect()
    }

    #[test]
    fn refuses_missing_duplicate_unknown_and_nonpassing_case_sets() {
        assert!(validate_cases(&complete(), "PASS").is_ok());
        let mut missing = complete(); missing.pop();
        assert!(validate_cases(&missing, "PASS").is_err());
        let mut duplicate = complete(); duplicate[1].id = duplicate[0].id.clone();
        assert!(validate_cases(&duplicate, "PASS").is_err());
        let mut unknown = complete(); unknown[0].id = "unknown".to_owned();
        assert!(validate_cases(&unknown, "PASS").is_err());
        let mut failed = complete(); failed[0].outcome = "FAIL".to_owned();
        assert!(validate_cases(&failed, "PASS").is_err());
        assert!(validate_cases(&failed, "INCONCLUSIVE").is_err());
        let mut pending = complete(); pending[0].outcome = "INCONCLUSIVE".to_owned();
        assert!(validate_cases(&pending, "PASS").is_err());
        assert!(validate_cases(&[], "INCONCLUSIVE").is_ok());
        assert!(validate_cases(&[], "invented").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_directories_fifos_and_oversize_files() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let directory = tempfile::tempdir().unwrap();
        assert!(bounded(directory.path(), 4).is_err());
        let input = directory.path().join("input");
        fs::write(&input, b"valid").unwrap();
        assert_eq!(bounded(&input, 5).unwrap(), b"valid");
        assert!(bounded(&input, 4).is_err());
        let fifo = directory.path().join("fifo");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the owned temporary path is a live NUL-terminated C string;
        // the fixture creates only this user-owned FIFO and retains no pointer.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(bounded(&fifo, 4).is_err());
    }

    #[test]
    fn v1_records_and_missing_native_reference_cannot_qualify_v2() {
        let mut value: Value = serde_json::from_str(&record_json()).unwrap();
        value["schema"] = json!(1);
        value["suite"] = json!("stela-metal-library-objects-v1");
        value.as_object_mut().unwrap().remove("first_party_outcome");
        value.as_object_mut().unwrap().remove("native_descriptor_reference");
        assert!(serde_json::from_value::<Record>(value).is_err());
        let mut record: Record = serde_json::from_str(&record_json()).unwrap();
        record.outcome = "PASS".to_owned(); record.first_party_outcome = "PASS".to_owned();
        assert!(validate_reference(&record).is_err());
        record.schema = 1; record.suite = "stela-metal-library-objects-v1".to_owned();
        // Version refusal precedes any attempt to open the unused LLVM path.
        let error = validate(&record, Some(0), "x86_64", &[0; 4], "fixture", &Value::Null).unwrap_err();
        assert_eq!(error.to_string(), "wrong runtime schema/suite");
    }

    #[cfg(unix)]
    #[test]
    fn llvm_capture_rejects_directories_fifos_and_oversize_files() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let directory = tempfile::tempdir().unwrap();
        assert!(bounded_binding(directory.path(), LLVM_LIMIT).is_err());
        let library = directory.path().join("LLVM.dylib");
        fs::write(&library, b"capture").unwrap();
        let (bytes, binding) = bounded_binding(&library, LLVM_LIMIT).unwrap();
        assert_eq!(bytes, b"capture");
        assert_eq!(binding["sha256"], sha256(&bytes));
        assert_eq!(binding["bytes"], bytes.len());
        let oversize = directory.path().join("oversize.dylib");
        File::create(&oversize).unwrap().set_len(LLVM_LIMIT as u64 + 1).unwrap();
        assert!(bounded_binding(&oversize, LLVM_LIMIT).is_err());
        let fifo = directory.path().join("LLVM.fifo");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: this owned temporary NUL-terminated path remains live for
        // mkfifo; no pointer escapes and no external file is changed.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(bounded_binding(&fifo, LLVM_LIMIT).is_err());
    }

}
