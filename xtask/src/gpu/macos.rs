//! Kernel-ABI compilation, without installing or loading a driver.
use super::support::{capture, evidence_directory, source_binding};
use crate::tools;
use anyhow::{Context, Result, ensure};
use object::{Architecture, BinaryFormat, Object, ObjectKind, ObjectSymbol};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn sdk(arguments: &[&str]) -> Result<String> {
    capture(
        Command::new("xcrun")
            .args(["--sdk", "macosx"])
            .args(arguments),
    )
}

// Make's dependency files include the headers actually read by each target,
// including SDK headers. Hash these inputs rather than just an SDK label.
fn dependencies(directory: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    let text = fs::read_to_string(directory.join("memory.d"))?;
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

pub fn build() -> Result<()> {
    ensure!(
        cfg!(target_os = "macos"),
        "this task requires Apple's macOS SDK"
    );
    let sdk_root = PathBuf::from(sdk(&["--show-sdk-path"])?.trim());
    let sdk_version = sdk(&["--show-sdk-version"])?;
    let clang = sdk(&["--find", "clang"])?;
    let compiler = capture(Command::new(clang.trim()).arg("--version"))?;
    let gpu = tools::root().join("crates/stela-drivers/src/gpu");
    let source = gpu.join("macos");
    let evidence = evidence_directory()?;
    for path in [&gpu, &sdk_root, &evidence] {
        ensure!(
            !path.to_string_lossy().chars().any(char::is_whitespace),
            "kernel Make/dependency rules require paths without whitespace: {}",
            path.display()
        );
    }
    let mut artifacts = Vec::new();
    let mut inputs = BTreeSet::new();
    for (arch, architecture, subarchitecture) in [
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
    ] {
        let directory = evidence.join(arch);
        let log_path = evidence.join(format!("macos-{arch}.log"));
        let log = File::create(&log_path)?;
        let status = Command::new(tools::which("make").context("install make")?)
            .current_dir(tools::root())
            .arg("-f")
            .arg(source.join("Makefile"))
            .arg(format!("ARCH={arch}"))
            .arg(format!("BUILD={}", directory.display()))
            .arg(format!("SDKROOT={}", sdk_root.display()))
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .status()?;
        ensure!(
            status.success(),
            "kernel build failed: {}",
            log_path.display()
        );
        let path = directory.join("gpu-memory.o");
        let bytes = fs::read(&path)?;
        let object = object::File::parse(bytes.as_slice())?;
        // object 0.37's sub_architecture() compares the entire subtype word;
        // arm64e kernel ABI capability bits must be separated before comparing.
        let subtype = match &object {
            object::File::MachO64(file) => {
                use object::read::macho::MachHeader;
                file.macho_header().cpusubtype(file.endian())
            }
            _ => anyhow::bail!("expected a 64-bit Mach-O kernel object"),
        };
        ensure!(
            object.format() == BinaryFormat::MachO
                && object.kind() == ObjectKind::Relocatable
                && object.architecture() == architecture
                && subtype & !object::macho::CPU_SUBTYPE_MASK == subarchitecture,
            "incorrect kernel object ABI for {arch}"
        );
        let imports: BTreeSet<_> = object
            .symbols()
            .filter(|symbol| symbol.is_undefined())
            .map(|symbol| symbol.name().map(str::to_owned))
            .collect::<Result<_, _>>()?;
        // Apple's x86 kernel headers redirect bzero to __bzero.
        let zero = if arch == "x86_64" {
            "___bzero"
        } else {
            "_bzero"
        };
        let expected = ["_IOFreeAligned", "_IOMallocAligned", zero]
            .map(str::to_owned)
            .into_iter()
            .collect();
        ensure!(
            imports == expected,
            "unexpected kernel imports for {arch}: {imports:?}"
        );
        for required in ["_stela_gpu_iokit_allocate_zeroed", "_stela_gpu_iokit_free"] {
            ensure!(
                object
                    .symbols()
                    .any(|symbol| { symbol.is_definition() && symbol.name() == Ok(required) }),
                "missing {required} for {arch}"
            );
        }
        inputs.extend(dependencies(&directory)?);
        artifacts.push(json!({
            "architecture": arch,
            "cpu_subtype_and_capabilities": subtype,
            "format": "Mach-O relocatable kernel component",
            "artifact": tools::binding(&path)?,
            "kernel_imports": imports,
        }));
    }
    let inputs = inputs
        .iter()
        .map(|path| tools::binding(path))
        .collect::<Result<Vec<_>>>()?;
    let receipt = evidence.join("macos.json");
    fs::write(
        &receipt,
        serde_json::to_vec_pretty(&json!({
            "schema": 1,
            "scope": "IOKit CPU allocation adapter for native vendor ports",
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
    Ok(())
}
