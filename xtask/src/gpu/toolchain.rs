//! The pinned tools the GPU builds run, installed under `.tools/gpu`: Meson,
//! Ninja and Mesa's Python generator modules in a virtual environment, and the
//! Rust binding generators NAK's build calls.
use crate::tools::{self, exec};
use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

/// Mesa 26.2 needs Python 3.10 or newer for its generators.
const PYTHON_MINOR: u32 = 10;
/// The python-build-standalone CPython installed when no Python 3.10 or newer
/// is on PATH: release, version, and each host's archive SHA-256.
const STANDALONE_RELEASE: &str = "20261003";
const STANDALONE_VERSION: &str = "3.13.16";
const STANDALONE: [(&str, &str); 3] = [
    (
        "x86_64-apple-darwin",
        "b4dad38ba6a344555ccb71a1b08caad0a6c0dda88c5803658bc95bd7f04e9f5c",
    ),
    (
        "aarch64-apple-darwin",
        "9e01f63bbb08576cd9c8bc2d0564d098cb30c8453a0cd4bcf6aef458f6d2a147",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "4595c5589fff7bf0cb158d9a88a797e0d791fa33830770fcb7bf3f4b104feeae",
    ),
];
const PYTHON_PACKAGES: [&str; 5] = [
    "meson==1.11.2",
    "ninja==1.13.2",
    "Mako==1.4.3",
    "packaging==26.3",
    "PyYAML==6.0.3",
];
const RUST_PACKAGES: [&str; 2] = ["bindgen-cli@0.73.2", "cbindgen@0.29.4"];
/// The pins an installation was made from, beside it.
const STAMP: &str = "stela-pins";

fn directory() -> PathBuf {
    tools::root().join(".tools/gpu")
}

/// Installs whatever is missing or pinned differently, then returns.
pub fn install() -> Result<()> {
    let generators = directory().join("generators");
    let pins = PYTHON_PACKAGES.join("\n") + "\n";
    if fs::read_to_string(generators.join(STAMP)).ok().as_deref() != Some(pins.as_str()) {
        let python = generators.join("bin/python3");
        if !python.is_file() {
            exec(
                Command::new(base_python()?)
                    .args(["-m", "venv"])
                    .arg(&generators),
            )?;
        }
        exec(
            Command::new(&python)
                .args(["-m", "pip", "install", "-q", "--disable-pip-version-check"])
                .args(PYTHON_PACKAGES),
        )?;
        fs::write(generators.join(STAMP), pins)?;
    }
    let rust = directory().join("rust");
    let pins = RUST_PACKAGES.join("\n") + "\n";
    if fs::read_to_string(rust.join(STAMP)).ok().as_deref() != Some(pins.as_str()) {
        exec(
            tools::cargo()
                .args(["install", "--locked", "--quiet", "--root"])
                .arg(&rust)
                .args(RUST_PACKAGES),
        )?;
        fs::write(rust.join(STAMP), pins)?;
    }
    Ok(())
}

/// `STELA_GPU_PYTHON`, else the first Python 3.10 or newer on PATH, else the
/// pinned standalone CPython.
fn base_python() -> Result<PathBuf> {
    if let Some(python) = std::env::var_os("STELA_GPU_PYTHON") {
        return Ok(python.into());
    }
    for name in [
        "python3",
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
        "python3.10",
    ] {
        let Some(python) = tools::which(name) else {
            continue;
        };
        let check = format!("import sys; sys.exit(sys.version_info < (3, {PYTHON_MINOR}))");
        if Command::new(&python)
            .args(["-c", &check])
            .status()?
            .success()
        {
            return Ok(python);
        }
    }
    standalone_python()
}

/// Downloads and unpacks the pinned standalone CPython for this host into
/// `.tools/gpu/python`, checking its archive digest first.
fn standalone_python() -> Result<PathBuf> {
    let root = directory().join("python");
    let python = root.join("bin/python3");
    if python.is_file() {
        return Ok(python);
    }
    let host = format!(
        "{}-{}",
        std::env::consts::ARCH,
        match std::env::consts::OS {
            "macos" => "apple-darwin",
            "linux" => "unknown-linux-gnu",
            os => os,
        }
    );
    let Some((_, digest)) = STANDALONE.iter().find(|(target, _)| *target == host) else {
        bail!("install Python 3.{PYTHON_MINOR} or newer, or name one with STELA_GPU_PYTHON");
    };
    let name = format!(
        "cpython-{STANDALONE_VERSION}+{STANDALONE_RELEASE}-{host}-install_only_stripped.tar.gz"
    );
    let archive = directory().join(&name);
    fs::create_dir_all(directory())?;
    exec(
        Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&archive)
            .arg(format!(
                "https://github.com/astral-sh/python-build-standalone/releases/download/{STANDALONE_RELEASE}/{}",
                name.replace('+', "%2B")
            )),
    )?;
    let actual = format!("{:x}", Sha256::digest(fs::read(&archive)?));
    ensure!(
        actual == *digest,
        "{name} has SHA-256 {actual}, not {digest}"
    );
    // The archive's single top-level directory is `python`.
    exec(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(directory()),
    )?;
    fs::remove_file(&archive)?;
    ensure!(python.is_file(), "{name} has no bin/python3");
    Ok(python)
}
