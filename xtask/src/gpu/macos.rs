//! Kernel and user-space ABI compilation, without installing or loading a driver.
//! The SDK's own compiler and linker build each object directly; `-MD` records
//! the headers each one read, which the receipts bind.
mod library;
use super::support::{capture, evidence_directory, gpu, source_binding};
use crate::tools;
use anyhow::{Context, Result, ensure};
use object::{Architecture, BinaryFormat, Object, ObjectKind, ObjectSymbol};
use serde_json::json;
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Each component's ABIs: the architecture name, its object architecture and
/// its Mach-O CPU subtype.
const ABIS: [(&str, Architecture, u32); 3] = [
    (
        "arm64e",
        Architecture::Aarch64,
        object::macho::CPU_SUBTYPE_ARM64E,
    ),
    (
        "arm64",
        Architecture::Aarch64,
        object::macho::CPU_SUBTYPE_ARM64_ALL,
    ),
    (
        "x86_64",
        Architecture::X86_64,
        object::macho::CPU_SUBTYPE_X86_64_ALL,
    ),
];

fn sdk(arguments: &[&str]) -> Result<String> {
    capture(
        Command::new("xcrun")
            .args(["--sdk", "macosx"])
            .args(arguments),
    )
}

/// Runs one SDK tool, appending its output to `log`.
fn run(
    tool: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    log: &Path,
) -> Result<()> {
    let output = File::options().create(true).append(true).open(log)?;
    let status = Command::new(sdk(&["--find", tool])?.trim())
        .args(arguments)
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output))
        .status()?;
    ensure!(status.success(), "{tool} failed: {}", log.display());
    Ok(())
}

/// Parses a 64-bit Mach-O `kind` for `abi`, returning it with its CPU subtype
/// word, capability bits included.
fn mach_o<'data>(
    bytes: &'data [u8],
    kind: ObjectKind,
    (arch, architecture, subtype): (&str, Architecture, u32),
) -> Result<(object::File<'data>, u32)> {
    let file = object::File::parse(bytes)?;
    // object's sub_architecture() compares the whole subtype word; arm64e's
    // kernel ABI capability bits must be separated before comparing.
    let word = match &file {
        object::File::MachO64(macho) => {
            use object::read::macho::MachHeader;
            macho.macho_header().cpusubtype(macho.endian())
        }
        _ => anyhow::bail!("expected a 64-bit Mach-O for {arch}"),
    };
    ensure!(
        file.format() == BinaryFormat::MachO
            && file.kind() == kind
            && file.architecture() == architecture
            && word & !object::macho::CPU_SUBTYPE_MASK == subtype,
        "incorrect Mach-O ABI for {arch}"
    );
    Ok((file, word))
}

/// The kernel component's flags for `arch`.
fn kernel_flags(arch: &str, sdk_root: &Path) -> Vec<OsString> {
    let headers = sdk_root.join("System/Library/Frameworks/Kernel.framework/Headers");
    let mut flags: Vec<OsString> = vec![
        "-target".into(),
        format!("{arch}-apple-macos26.0").into(),
        "-isysroot".into(),
        sdk_root.into(),
        "-isystem".into(),
        headers.into(),
    ];
    flags.extend(
        [
            "-DKERNEL",
            "-mkernel",
            "-O2",
            "-fno-stack-protector",
            "-fno-stack-check",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Werror=sign-conversion",
            "-Werror=shorten-64-to-32",
            "-Werror=conditional-uninitialized",
            "-Wno-unused-parameter",
        ]
        .map(OsString::from),
    );
    let arch_flags: &[&str] = if arch == "x86_64" {
        &["-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float"]
    } else {
        &["-mgeneral-regs-only"]
    };
    flags.extend(arch_flags.iter().map(OsString::from));
    flags
}

/// Compiles the kernel component's units for `arch` into `output`.
fn kernel_component(
    source: &Path,
    sdk_root: &Path,
    arch: &str,
    output: &Path,
    log: &Path,
) -> Result<()> {
    fs::create_dir_all(output)?;
    for unit in ["memory", "task_memory"] {
        let mut arguments = kernel_flags(arch, sdk_root);
        arguments.extend(
            [
                "-fapple-kext",
                "-fno-exceptions",
                "-fno-rtti",
                "-std=gnu++17",
                "-MD",
                "-MP",
                "-c",
            ]
            .map(OsString::from),
        );
        arguments.push(source.join(format!("{unit}.cpp")).into());
        arguments.push("-o".into());
        arguments.push(output.join(format!("{unit}.o")).into());
        run("clang++", &arguments, log)?;
    }
    Ok(())
}

// Dependency files include the headers actually read by each target,
// including SDK headers. Hash these inputs rather than just an SDK label.
fn dependencies(directory: &Path, filename: &str) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    let text = fs::read_to_string(directory.join(filename))?;
    let text = text.replace("\\\n", " ");
    let (_, inputs) = text
        .lines()
        .next()
        .and_then(|line| line.split_once(':'))
        .context("missing native dependency rule")?;
    for path in inputs.split_whitespace() {
        paths.insert(fs::canonicalize(path)?);
    }
    Ok(paths)
}

fn inspect_component(
    path: &Path,
    abi: (&str, Architecture, u32),
    expected: &[&str],
    required: &[&str],
) -> Result<serde_json::Value> {
    let arch = abi.0;
    let bytes = fs::read(path)?;
    let (object, subtype) = mach_o(&bytes, ObjectKind::Relocatable, abi)?;
    let imports: BTreeSet<_> = object
        .symbols()
        .filter(|symbol| symbol.is_undefined())
        .map(|symbol| symbol.name().map(str::to_owned))
        .collect::<Result<_, _>>()?;
    ensure!(
        imports == expected.iter().map(|s| (*s).to_owned()).collect(),
        "unexpected kernel imports for {arch}: {imports:?}"
    );
    for required in required {
        ensure!(
            object
                .symbols()
                .any(|symbol| { symbol.is_definition() && symbol.name() == Ok(*required) }),
            "missing {required} for {arch}"
        );
    }
    Ok(
        json!({"architecture":arch,"cpu_subtype_and_capabilities":subtype,
        "format":"Mach-O relocatable kernel component", "artifact":tools::binding(path)?,
        "kernel_imports":imports}),
    )
}

/// Builds and runs the host-only ownership and error tests. No mock enters the
/// kernel component.
fn contract(source: &Path, sdk_root: &Path, output: &Path) -> Result<serde_json::Value> {
    fs::create_dir_all(output)?;
    let binary = output.join("task-memory-contract");
    let headers = sdk_root.join("System/Library/Frameworks/Kernel.framework/Headers");
    let mut arguments: Vec<OsString> = vec![
        "-std=gnu++17".into(),
        "-isysroot".into(),
        sdk_root.into(),
        "-idirafter".into(),
        headers.into(),
    ];
    arguments.extend(
        [
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wconversion",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-MD",
            "-MP",
        ]
        .map(OsString::from),
    );
    arguments.push(source.join("tests/task_memory_contract.cpp").into());
    arguments.push("-o".into());
    arguments.push(binary.as_os_str().into());
    run("clang++", &arguments, &output.join("compile.log"))?;
    let log = output.join("contract.log");
    let mut command = Command::new(&binary);
    fs::write(&log, capture(&mut command)?)?;
    Ok(
        json!({"scope":"Actual owner C++ with test-only original-service mocks under ASan/UBSan; no kernel page wiring or hardware",
        "command":format!("{command:?}"),"binary":tools::binding(&binary)?,
        "output":tools::binding(&log)?,"dependencies":dependencies(output,"task-memory-contract.d")?
            .iter().map(|p|tools::binding(p)).collect::<Result<Vec<_>>>()?}),
    )
}

pub fn build() -> Result<()> {
    ensure!(
        cfg!(target_os = "macos"),
        "this task requires Apple's macOS SDK"
    );
    let sdk_root = PathBuf::from(sdk(&["--show-sdk-path"])?.trim());
    let sdk_version = sdk(&["--show-sdk-version"])?;
    let clang = sdk(&["--find", "clang"])?;
    let compiler = capture(Command::new(clang.trim()).arg("--version"))?;
    let gpu = gpu();
    let source = gpu.join("iokit");
    let evidence = evidence_directory()?;
    for path in [&gpu, &sdk_root, &evidence] {
        ensure!(
            !path.to_string_lossy().chars().any(char::is_whitespace),
            "dependency files require paths without whitespace: {}",
            path.display()
        );
    }
    let mut artifacts = Vec::new();
    let mut inputs = BTreeSet::new();
    for abi in ABIS {
        let arch = abi.0;
        let directory = evidence.join(arch);
        let log = evidence.join(format!("macos-{arch}.log"));
        kernel_component(&source, &sdk_root, arch, &directory, &log)?;
        // Apple's x86 kernel headers redirect bzero to __bzero.
        let zero = if arch == "x86_64" {
            "___bzero"
        } else {
            "_bzero"
        };
        artifacts.push(inspect_component(
            &directory.join("memory.o"),
            abi,
            &["_IOFreeAligned", "_IOMallocAligned", zero],
            &["_stela_gpu_iokit_allocate_zeroed", "_stela_gpu_iokit_free"],
        )?);
        artifacts.push(inspect_component(
            &directory.join("task_memory.o"),
            abi,
            &[
                "__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task",
                "_kernel_task",
                "_panic",
                "_task_reference",
                "_task_deallocate",
            ],
            &[
                "__ZN5stela3gpu10TaskMemory7prepareEP4taskyyj",
                "__ZN5stela3gpu10TaskMemory23finish_after_quiescenceEb",
                "__ZN5stela3gpu10TaskMemoryD1Ev",
                "__ZN5stela3gpu10TaskMemoryD2Ev",
            ],
        )?);
        inputs.extend(dependencies(&directory, "memory.d")?);
        inputs.extend(dependencies(&directory, "task_memory.d")?);
    }
    let task_contract = contract(&source, &sdk_root, &evidence.join("task-contract"))?;
    let inputs = inputs
        .iter()
        .map(|path| tools::binding(path))
        .collect::<Result<Vec<_>>>()?;
    let receipt = evidence.join("macos.json");
    fs::write(
        &receipt,
        serde_json::to_vec_pretty(&json!({
            "schema": 1,
            "scope": "Original IOKit CPU allocation and task-owned prepared memory for the macOS frontend",
            "task_memory_contract":task_contract,
            "limits": "Compilation and relocatable linking only; not a loadable kext or macOS 27 ABI qualification, device initialization, DMA or Metal execution.",
            "sdk": { "path": sdk_root, "version": sdk_version.trim() },
            "compiler": compiler,
            "adapter_source_sha256": source_binding(&source)?,
            "task": tools::binding(&tools::root().join(file!()))?,
            "inputs": inputs,
            "artifacts": artifacts,
        }))?,
    )?;
    println!(
        "macOS GPU memory components built for three ABIs: {}",
        receipt.display()
    );
    library::build(&gpu, &sdk_root, sdk_version.trim(), &compiler, &evidence)
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn task_memory_preserves_original_service_ownership_and_failure_contracts() {
    let sdk_root = PathBuf::from(sdk(&["--show-sdk-path"]).unwrap().trim());
    let output = tempfile::tempdir().unwrap();
    contract(&gpu().join("iokit"), &sdk_root, output.path()).unwrap();
}
