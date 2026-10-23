//! Hosted library ownership uses the canonical parser and shared AIR inspector.
use super::{build_directory, meson::Build, run, tools};
use anyhow::{Result, ensure};
use object::{Architecture, Object, ObjectSymbol};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) fn build_input(evidence: &Path) -> Result<PathBuf> {
    let target = build_directory("metal-input");
    run(
        Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(tools::root())
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_INCREMENTAL", "0")
            .args(["build", "--release", "--locked", "-p", "stela-metal-input"]),
        evidence,
        "metal-input",
    )?;
    let path = target.join("release/libstela_metal_input.a");
    ensure!(path.is_file(), "missing hosted Metal input archive");
    Ok(path)
}

/// Symbols an executable defines or imports.
fn symbols(path: &Path) -> Result<(Architecture, Vec<String>)> {
    let bytes = std::fs::read(path)?;
    let binary = object::File::parse(bytes.as_slice())?;
    let names = binary
        .symbols()
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect();
    Ok((binary.architecture(), names))
}

/// The Metal library assembler links no NIR and threadgroup value
/// normalization no LLVM or NIR: they own no compiler state.
pub(super) fn check_boundaries(stela: &Build) -> Result<()> {
    let (architecture, assembler) = symbols(&stela.executable("stela_library_assembly_test")?)?;
    let host = match env::consts::ARCH {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        _ => anyhow::bail!("unsupported hosted Metal assembler architecture"),
    };
    ensure!(architecture == host, "wrong Metal assembler CPU ABI");
    ensure!(
        !assembler
            .iter()
            .any(|s| s == "_stela_air_to_nir" || s.starts_with("_nir_")),
        "local Metal library owner unexpectedly links NIR",
    );
    let (_, values) = symbols(&stela.executable("stela_threadgroup_test")?)?;
    ensure!(
        !values
            .iter()
            .any(|s| s.starts_with("_LLVM") || s.starts_with("_nir_")),
        "threadgroup value owner unexpectedly depends on LLVM/NIR"
    );
    Ok(())
}
