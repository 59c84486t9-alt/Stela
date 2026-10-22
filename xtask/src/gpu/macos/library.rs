//! Link the actual user-space objects against the SDK's public frameworks.
use super::{dependencies, tools};
use crate::gpu::support::source_binding;
use anyhow::{Context, Result, ensure};
use object::{Architecture, BinaryFormat, Object, ObjectKind, ObjectSymbol};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::Path,
    process::{Command, Stdio},
};

pub(super) fn build(
    gpu: &Path,
    sdk_root: &Path,
    sdk_version: &str,
    compiler: &str,
    evidence: &Path,
) -> Result<()> {
    let source = gpu.join("metal/macos");
    let mut artifacts = Vec::new();
    let mut inputs = BTreeSet::new();
    for (arch, architecture, expected_subtype) in [
        (
            "arm64",
            Architecture::Aarch64,
            object::macho::CPU_SUBTYPE_ARM64_ALL,
        ),
        (
            "arm64e",
            Architecture::Aarch64,
            object::macho::CPU_SUBTYPE_ARM64E,
        ),
        (
            "x86_64",
            Architecture::X86_64,
            object::macho::CPU_SUBTYPE_X86_64_ALL,
        ),
    ] {
        let directory = evidence.join("metal").join(arch);
        let log_path = evidence.join(format!("metal-library-{arch}.log"));
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
            "Metal library build failed: {}",
            log_path.display()
        );
        let path = directory.join("libstela-metal-library.dylib");
        let bytes = fs::read(&path)?;
        let binary = object::File::parse(bytes.as_slice())?;
        let subtype = match &binary {
            object::File::MachO64(file) => {
                use object::read::macho::MachHeader;
                file.macho_header().cpusubtype(file.endian())
            }
            _ => anyhow::bail!("expected a 64-bit Mach-O Metal component"),
        };
        ensure!(
            binary.format() == BinaryFormat::MachO
                && binary.kind() == ObjectKind::Dynamic
                && binary.architecture() == architecture
                && subtype & !object::macho::CPU_SUBTYPE_MASK == expected_subtype,
            "incorrect Metal component ABI for {arch}"
        );
        for required in [
            "_STELAMetalCreateLibrary",
            "_STELAMetalCopyFunctionSnapshot",
        ] {
            ensure!(
                binary
                    .symbols()
                    .any(|s| s.is_definition() && s.name() == Ok(required)),
                "missing {required} for {arch}"
            );
        }
        // The SDK link resolves these to real frameworks. No private driver,
        // foreign-CPU Rust archive, LLVM or native hardware library is linked.
        let imports = binary
            .imports()?
            .into_iter()
            .map(|import| {
                Ok(json!({
                    "name": std::str::from_utf8(import.name())?,
                    "library": std::str::from_utf8(import.library())?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let forbidden = [
            "_IOServiceOpen",
            "_IOConnectCallMethod",
            "_stela_metal_input_open",
        ];
        ensure!(
            !binary
                .symbols()
                .any(|s| s.is_undefined() && s.name().is_ok_and(|name| forbidden.contains(&name))),
            "unexpected device or helper binding in Metal object"
        );
        inputs.extend(dependencies(&directory, "library.d")?);
        artifacts.push(
            json!({"architecture":arch,"cpu_subtype_and_capabilities":subtype,
            "artifact":tools::binding(&path)?,"framework_imports":imports}),
        );
    }
    let inputs = inputs
        .iter()
        .map(|path| tools::binding(path))
        .collect::<Result<Vec<_>>>()?;
    let receipt = evidence.join("metal-library.json");
    fs::write(
        &receipt,
        serde_json::to_vec_pretty(&json!({
            "schema":1,
            "scope":"Owned Metal library/function/reflection user-space components",
            "limits":"Compile and SDK link only. No Objective-C execution, registered MTLDevice, authenticated helper transport, pipeline, macOS27 runtime ABI or GPU qualification.",
            "sdk":{"path":sdk_root,"version":sdk_version},"compiler":compiler,
            "source_sha256":source_binding(&source)?,"task":tools::binding(&tools::root().join(file!()))?,
            "inputs":inputs,"artifacts":artifacts
        }))?,
    )?;
    println!(
        "Metal library components linked for three ABIs: {}",
        receipt.display()
    );
    Ok(())
}
