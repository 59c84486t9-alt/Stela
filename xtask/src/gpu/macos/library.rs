//! Link the actual user-space objects against the SDK's public frameworks.
use super::{dependencies, run, tools};
use crate::gpu::support::source_binding;
use anyhow::{Result, ensure};
use object::{Architecture, BinaryFormat, Object, ObjectKind, ObjectSymbol};
use serde_json::json;
use std::{collections::BTreeSet, ffi::OsString, fs, path::Path};

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
        let log = evidence.join(format!("metal-library-{arch}.log"));
        let path = directory.join("libstela-metal-library.dylib");
        fs::create_dir_all(&directory)?;
        let flags: Vec<OsString> = vec![
            "-target".into(),
            format!("{arch}-apple-macos26.0").into(),
            "-isysroot".into(),
            sdk_root.into(),
            "-O2".into(),
            "-fobjc-arc".into(),
            "-fblocks".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
        ];
        let object = directory.join("library.o");
        let mut compile = flags.clone();
        compile.extend(["-MD", "-MP", "-c"].map(OsString::from));
        compile.push(source.join("library.m").into());
        compile.push("-o".into());
        compile.push(object.as_os_str().into());
        run(
            "clang",
            &compile.iter().map(OsString::as_os_str).collect::<Vec<_>>(),
            &log,
        )?;
        let mut link = flags;
        link.push("-dynamiclib".into());
        link.push(object.into());
        link.extend(
            [
                "-framework",
                "Foundation",
                "-framework",
                "Metal",
                "-Wl,-install_name,@rpath/libstela-metal-library.dylib",
                "-o",
            ]
            .map(OsString::from),
        );
        link.push(path.as_os_str().into());
        run(
            "clang",
            &link.iter().map(OsString::as_os_str).collect::<Vec<_>>(),
            &log,
        )?;
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
