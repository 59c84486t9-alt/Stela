//! Find matching boot files, or build them once from an available checkout.
use super::{Environment, read_efi};
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MISSING: &str = "matching boot files (stela.efi) are missing. Place the stela.efi built \
    from this source beside stela, pass --efi FILE, or run setup from the Stela source checkout \
    so it can build them";

fn checkout(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|root| {
            root.join("Cargo.toml").is_file()
                && root.join("crates/stela-boot/Cargo.toml").is_file()
                && root.join("xtask/Cargo.toml").is_file()
        })
        .map(Path::to_path_buf)
}

/// A compatible `stela.efi` beside the running executable.
fn bundled(environment: &Environment<'_>) -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?.parent()?.join("stela.efi");
    read_efi(environment, &path).is_ok().then_some(path)
}

fn source_root() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .and_then(|p| checkout(&p))
        .or_else(|| std::env::current_exe().ok().and_then(|p| checkout(&p)))
        .or_else(|| checkout(Path::new(env!("CARGO_MANIFEST_DIR"))))
}

fn runs(program: &OsString) -> bool {
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Before any prompt, confirm the boot files exist or can be built, so a
/// missing tool is reported before the wizard rather than after it.
pub(super) fn preflight(environment: &Environment<'_>) -> Result<()> {
    if bundled(environment).is_some() {
        return Ok(());
    }
    let root = source_root().context(MISSING)?;
    ensure!(
        runs(&"cargo".into()),
        "building stela.efi needs Rust's cargo on PATH; alternatively place stela.efi beside stela"
    );
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "clang".into());
    ensure!(
        runs(&compiler),
        "building stela.efi needs clang ({} was not found); install LLVM's clang or set CC, \
         or place a stela.efi built from this source beside stela",
        compiler.to_string_lossy()
    );
    ensure!(
        root.join("third_party/linux/.git").exists(),
        "building stela.efi needs the pinned Linux sources; run `cargo xtask gpu fetch` in {}",
        root.display()
    );
    Ok(())
}

/// The log lines that say why a build failed, rather than its progress.
fn failure(log: &Path) -> String {
    let text = fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    // Error lines, and each build-script panic with the message after it.
    let mut reasons = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("error") {
            reasons.push(*line);
        } else if line.contains("panicked at") {
            reasons.extend(lines.get(i + 1));
        }
    }
    reasons.dedup();
    reasons[reasons.len().saturating_sub(6)..].join("\n")
}

pub(super) fn resolve(environment: &Environment<'_>) -> Result<PathBuf> {
    if let Some(path) = bundled(environment) {
        return Ok(path);
    }
    let Some(root) = source_root() else {
        bail!("{MISSING}");
    };
    let progress = crate::progress::Phase::spinner("Preparing boot files");
    let build_dir = std::env::temp_dir().join("Stela/boot");
    let log_path = build_dir.join("setup-build.log");
    fs::create_dir_all(log_path.parent().unwrap())?;
    let log = fs::File::create(&log_path)?;
    let result = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--manifest-path",
            "crates/stela-boot/Cargo.toml",
            "--target",
            "x86_64-unknown-uefi",
            "--release",
        ])
        .arg("--target-dir")
        .arg(&build_dir)
        .current_dir(&root)
        .env("CARGO_BUILD_JOBS", "1")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status()
        .context(
            "preparing boot files needs Rust/Cargo; alternatively place stela.efi beside stela",
        )?;
    if !result.success() {
        drop(progress);
        bail!(
            "preparing boot files failed:\n{}\nFull log: {}",
            failure(&log_path),
            log_path.display()
        );
    }
    let path = build_dir.join("x86_64-unknown-uefi/release/stela.efi");
    read_efi(environment, &path)?;
    progress.finish();
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_discovery_requires_the_boot_and_task_workspaces() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("Cargo.toml"), "")?;
        assert_eq!(checkout(temp.path()), None);
        for path in ["crates/stela-boot", "xtask", "target/release"] {
            fs::create_dir_all(temp.path().join(path))?;
        }
        fs::write(temp.path().join("crates/stela-boot/Cargo.toml"), "")?;
        fs::write(temp.path().join("xtask/Cargo.toml"), "")?;
        assert_eq!(
            checkout(&temp.path().join("target/release")),
            Some(temp.path().to_owned())
        );
        Ok(())
    }

    #[test]
    fn a_failed_build_reports_its_errors_not_its_progress() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("build.log");
        fs::write(
            &log,
            "   Compiling uefi v0.41.0\nwarning: unused\nerror: failed to run custom build command for `stela-drivers`\n\nCaused by:\n  process didn't exit successfully\n  --- stderr\n  thread 'main' panicked at build/acpi.rs:43:9:\n  cannot run \"clang\" for ACPICA (program not found)\n",
        )?;
        let reason = failure(&log);
        assert!(
            reason.contains("failed to run custom build command"),
            "{reason}"
        );
        assert!(reason.contains("cannot run \"clang\""), "{reason}");
        assert!(!reason.contains("Compiling") && !reason.contains("warning"));
        Ok(())
    }
}
