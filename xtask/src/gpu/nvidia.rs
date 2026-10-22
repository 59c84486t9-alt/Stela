//! Reproducible compilation of the vendor cores without installing Linux
//! modules. The unresolved symbol list is the platform port's work inventory.
use super::support::{NATIVE_TARGET, capture, evidence_directory, source_binding};
use crate::tools;
use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use object::{Object, ObjectSymbol};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use xz2::{
    stream::{Check, Stream},
    write::XzEncoder,
};

mod archive;
mod layout;
mod lut;
mod memory;
mod ordering;
mod page_geometry;
mod primitives;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Target {
    Stela,
    Linux,
}

impl Target {
    fn profile(self) -> &'static str {
        match self {
            Self::Stela => "stela-x86_64-coff-v1",
            Self::Linux => "linux-x86_64-clang-v1",
        }
    }
}

struct Toolchain {
    clang: PathBuf,
    clangxx: PathBuf,
    linker: PathBuf,
    objcopy: PathBuf,
    archiver: PathBuf,
}

impl Toolchain {
    fn discover() -> Result<Self> {
        let rustc = tools::which("rustc").context("rustc is not in PATH")?;
        let sysroot = capture(Command::new(&rustc).args(["--print", "sysroot"]))?;
        let version = capture(Command::new(&rustc).arg("-vV"))?;
        let host = version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .context("rustc did not report its host target")?;
        let directory = Path::new(sysroot.trim())
            .join("lib/rustlib")
            .join(host)
            .join("bin");
        let toolchain = Self {
            clang: tools::which("clang").context("install Clang")?,
            clangxx: tools::which("clang++").context("install Clang's C++ compiler")?,
            linker: directory.join("gcc-ld/ld.lld"),
            objcopy: directory.join("llvm-objcopy"),
            archiver: directory.join("llvm-ar"),
        };
        for path in [&toolchain.linker, &toolchain.objcopy, &toolchain.archiver] {
            ensure!(
                path.is_file(),
                "{} is missing; install llvm-tools-preview for the active Rust toolchain",
                path.display()
            );
        }
        Ok(toolchain)
    }
}

fn compress_shader(data: &[u8]) -> Result<Vec<u8>> {
    // Match the decoder's supported XZ profile: LZMA2 with no check field.
    let stream = Stream::new_easy_encoder(6, Check::None)?;
    let mut encoder = XzEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn prepare_shaders(source: &Path, output: &Path) -> Result<()> {
    for generation in ["turing", "ampere", "hopper", "blackwell", "gb20x"] {
        let source = source.join(format!("src/shaders/g_{generation}_shaders"));
        let destination = output.join(format!("{generation}_shaders.xz"));
        let compressed = compress_shader(&fs::read(&source)?)?;
        // Make owns embedding and linking; Rust supplies its compressed input.
        // Always replace it before make so a stale source timestamp cannot
        // suppress regeneration of the embedded shader object.
        fs::write(destination, compressed)?;
    }
    Ok(())
}

fn inspect(path: &Path) -> Result<(u64, String, BTreeSet<String>)> {
    let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let file = object::File::parse(&*data)?;
    ensure!(
        file.format() == object::BinaryFormat::Elf
            && file.architecture() == object::Architecture::X86_64
            && file.kind() == object::ObjectKind::Relocatable,
        "{} is not an x86-64 ELF relocatable object",
        path.display()
    );
    let imports = file
        .symbols()
        .filter(|symbol| symbol.is_undefined())
        .map(|symbol| symbol.name().map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let imports = imports
        .into_iter()
        .filter(|name| !name.is_empty())
        .collect();
    Ok((
        data.len() as u64,
        format!("{:x}", Sha256::digest(&data)),
        imports,
    ))
}

/// NVIDIA's FreeBSD interface layer includes a few FreeBSD kernel headers;
/// Stela's stand-ins apply only where the compiler's own system has none.
fn freebsd_headers(command: &mut Command, source: &Path) {
    command.arg("-idirafter").arg(source.join("stela/compat"));
}

pub fn build(jobs: u16, target: Target) -> Result<()> {
    let toolchain = Toolchain::discover()?;
    let gpu = tools::root().join("crates/stela-drivers/src/gpu");
    let source = gpu.join("nvidia");
    let source_hash = source_binding(&source)?;
    let compiler = capture(Command::new(&toolchain.clang).arg("--version"))?;
    let compilerxx = capture(Command::new(&toolchain.clangxx).arg("--version"))?;
    let linker = capture(Command::new(&toolchain.linker).arg("--version"))?;
    let archiver = capture(Command::new(&toolchain.archiver).arg("--version"))?;
    // The retained makefiles track header dependencies but not compiler or
    // option changes. Partition their cache by the full source/tool identity.
    let identity = format!(
        "{source_hash}\0{compiler}\0{compilerxx}\0{linker}\0{archiver}\0{}",
        target.profile()
    );
    let build_key = format!("{:x}", Sha256::digest(identity.as_bytes()));
    let build = tools::root()
        .join(".stela/gpu/build/nvidia")
        .join(target.profile())
        .join(&build_key);
    // The retained makefiles do not support whitespace in paths. Do not
    // silently split a compiler or output path into shell arguments.
    for path in [
        &source,
        &build,
        &toolchain.clang,
        &toolchain.clangxx,
        &toolchain.linker,
        &toolchain.objcopy,
        &toolchain.archiver,
    ] {
        ensure!(
            !path.to_string_lossy().chars().any(char::is_whitespace),
            "the native NVIDIA makefiles require paths without whitespace: {}",
            path.display()
        );
    }
    let evidence = evidence_directory()?;
    if target == Target::Stela {
        layout::verify(&toolchain.clang, &source, &evidence.join("record-layout"))?;
        lut::verify(&toolchain.clang, &source, &evidence.join("lut-layout"))?;
        memory::verify(&toolchain.clang, &source, &evidence.join("nvkms-memory"))?;
        primitives::verify(&toolchain.clang, &source, &evidence.join("cpu-primitives"))?;
        page_geometry::verify(&toolchain.clang, &source, &evidence.join("page-geometry"))?;
        ordering::verify(&toolchain.clang, &source, &evidence.join("ordering"))?;
    }
    for (component, subdirectory, reference_artifact) in [
        ("core", "src/nvidia", "nv-kernel.o"),
        ("modeset", "src/nvidia-modeset", "nv-modeset-kernel.o"),
    ] {
        let output = build.join(component);
        fs::create_dir_all(&output)?;
        let source_directory = source.join(subdirectory);
        if component == "modeset" {
            prepare_shaders(&source_directory, &output)?;
        }
        let log_path = evidence.join(format!("{component}.log"));
        let log = File::create(&log_path)?;
        let mut command = Command::new(tools::which("make").context("install make")?);
        command
            .current_dir(&source_directory)
            .arg(format!("-j{jobs}"))
            .arg("TARGET_ARCH=x86_64")
            .arg(format!("CC={}", toolchain.clang.display()))
            .arg(format!("CXX={}", toolchain.clangxx.display()))
            .arg(format!("LD={}", toolchain.linker.display()))
            .arg(format!("OBJCOPY={}", toolchain.objcopy.display()))
            .arg(format!("AR={}", toolchain.archiver.display()))
            .arg("NV_BUILD_USER=stela")
            .arg("NV_BUILD_HOST=native")
            // NVIDIA's ID string runs $(DATE); name the source instead of the time.
            .arg(format!("DATE=echo source-{source_hash}"))
            .arg(format!("OUTPUTDIR={}", output.display()))
            .arg(format!("OUTPUTDIR_ABSOLUTE={}", output.display()))
            .env_remove("MAKEFLAGS")
            .env_remove("CFLAGS")
            .env_remove("CXXFLAGS")
            .env_remove("CPPFLAGS")
            .env_remove("LDFLAGS")
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        match target {
            // NVIDIA's FreeBSD configuration is its Unix resource manager for
            // an OS that supplies its own kernel interface layer, as Stela's
            // port does. The fragment archives COFF objects for the UEFI link.
            Target::Stela => command
                .args(["-f", "Makefile", "-f"])
                .arg(source.join("stela/build").join(format!("{component}.mk")))
                .args(["stela-archive", "TARGET_OS=FreeBSD"])
                .arg(format!(
                    "EXTRA_CFLAGS=--target={NATIVE_TARGET} -mno-incremental-linker-compatible"
                )),
            Target::Linux => command.args([
                "all",
                "TARGET_OS=Linux",
                "EXTRA_CFLAGS=--target=x86_64-unknown-linux-gnu",
            ]),
        };
        println!("NVIDIA {component}: {}", log_path.display());
        let status = command
            .status()
            .with_context(|| format!("cannot execute {command:?}"))?;
        if !status.success() {
            bail!(
                "NVIDIA {component} failed with {status}; see {}",
                log_path.display()
            );
        }
        let artifact = match (target, component) {
            (Target::Stela, "core") => "libnv-kernel.a",
            (Target::Stela, _) => "libnv-modeset-kernel.a",
            (Target::Linux, _) => reference_artifact,
        };
        let path = output.join(artifact);
        let (bytes, sha256, imports, members) = match target {
            Target::Linux => {
                let (bytes, sha256, imports) = inspect(&path)?;
                (bytes, sha256, imports, None)
            }
            Target::Stela => {
                let report =
                    archive::inspect(&path, &source_directory.join("exports_link_command.txt"))?;
                (
                    report.bytes,
                    report.sha256,
                    report.imports,
                    Some(report.members),
                )
            }
        };
        ensure!(
            source_binding(&source)? == source_hash,
            "NVIDIA source changed during the build; rerun against a stable tree"
        );
        let receipt = json!({
            "schema": 1,
            "stage": match target {
                Target::Stela => "stela-coff-archive-compilation-only",
                Target::Linux => "linux-elf-core-compilation-only",
            },
            "stela_platform_port": false, "hardware_executed": false,
            "limits": "Core compilation only; not a complete OS-service port, final linked driver, GPU initialization or Metal execution. Archive imports conservatively include every retained member, before reachability analysis.",
            "origin": serde_json::from_slice::<serde_json::Value>(&fs::read(gpu.join("sources.json"))?)?,
            "source_tree_sha256": source_hash,
            "command": format!("{command:?}"),
            "compiler": compiler, "compilerxx": compilerxx, "linker": linker, "archiver": archiver,
            "build_key": build_key,
            "artifact": {"path": path, "bytes": bytes, "sha256": sha256, "members": members},
            "unresolved_symbols": imports,
        });
        let receipt_path = evidence.join(format!("{component}.json"));
        File::create_new(&receipt_path)?.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
        println!(
            "  {artifact}: {bytes} bytes, {} unresolved platform/runtime imports",
            imports.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn display_shader_compression_uses_the_supported_xz_profile() {
        let input: Vec<_> = (0..8192).map(|n| (n % 251) as u8).collect();
        let encoded = compress_shader(&input).unwrap();
        assert_eq!(&encoded[..6], b"\xfd7zXZ\0");
        assert_eq!(encoded[7], 0, "the driver decoder requires no check field");
        let mut decoded = Vec::new();
        xz2::read::XzDecoder::new(&*encoded)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn vendor_types_preserve_flags_and_host_addresses_on_both_abis() {
        let tools = Toolchain::discover().unwrap();
        let source = tools::root().join("crates/stela-drivers/src/gpu/nvidia");
        for (target, os) in [
            (NATIVE_TARGET, "-DNV_BSD"),
            ("x86_64-unknown-linux-gnu", "-DNV_LINUX"),
        ] {
            for (compiler, fixture, standard) in [
                (&tools.clangxx, "abi.cpp", "-std=c++20"),
                (&tools.clang, "abi.c", "-std=c11"),
            ] {
                let mut command = Command::new(compiler);
                command
                    .args(["-target", target, os, "-ffreestanding"])
                    .args([standard, "-fsyntax-only", "-Werror"])
                    .args(["-Wno-missing-field-initializers"])
                    .arg(source.join("stela/tests").join(fixture));
                for include in [
                    "src/common/sdk/nvidia/inc",
                    "src/nvidia/inc/kernel",
                    "src/nvidia/arch/nvalloc/unix/include",
                ] {
                    command.arg("-I").arg(source.join(include));
                }
                freebsd_headers(&mut command, &source);
                capture(&mut command).unwrap();
            }
        }
    }
}
