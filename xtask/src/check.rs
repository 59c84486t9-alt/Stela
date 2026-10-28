//! The shared local and CI gate.
//!
//! Formatting reads only sources, so it runs beside everything else. Once
//! the GPU sources are fetched, two lanes run at once, each in its own
//! target directory: the UEFI target's Clippy in [`BOOT_TARGET_DIR`], and
//! the host's Clippy and test build in `target`. The tests then run alone.
//! A lane stops at its first failure; the gate fails if any part did, once
//! every part has finished.
use crate::tools::{cargo, exec};
use anyhow::{Context, Result, bail};
use std::{
    ffi::OsStr,
    io::Write,
    process::{Command, Stdio},
    thread,
};

pub const BOOT_MANIFEST: &str = "crates/stela-boot/Cargo.toml";
pub const BOOT_TARGET: &str = "x86_64-unknown-uefi";
pub const BOOT_TARGET_DIR: &str = "target/boot";
/// `.cargo/config.toml`'s flags for [`BOOT_TARGET`]: the soft-float target
/// takes the `aes` crate's software backend.
const BOOT_RUSTFLAGS: &str = "--cfg aes_force_soft";
const BOOT: [&str; 2] = ["--manifest-path", BOOT_MANIFEST];
const DENY: [&str; 3] = ["--", "-D", "warnings"];

pub fn run(fix: bool) -> Result<()> {
    if fix {
        exec(&mut command(["fmt", "--all"]))?;
        exec(command(["fmt"]).args(BOOT).arg("--all"))?;
    }
    let formatting = [
        command(["fmt", "--all", "--", "--check"]),
        command(["fmt", BOOT[0], BOOT[1], "--all", "--", "--check"]),
    ];
    let boot_lane = vec![
        // Cargo caps Clippy lints on dependencies of the boot package.
        // Select the runtime itself too, so its freestanding-only branches
        // are checked.
        uefi(["-p", "stela-runtime", "--no-default-features"]),
        uefi(BOOT),
        // Native GPU hooks are optional while their larger vendor ports are
        // in progress, but their C/Rust ABI and UEFI target still belong to
        // the gate.
        uefi([
            "-p",
            "stela-drivers",
            "--features",
            "nvidia-port,intel-port,amd-port",
        ]),
    ];
    // `--all-features` includes xtask's `native-acpi`, whose tests read the
    // fetched ACPICA sources.
    let test = ["test", "--workspace", "--all-features", "--locked"];
    let host_lane = vec![
        {
            let mut clippy = command(["clippy", "--workspace", "--all-targets"]);
            clippy.args(["--all-features", "--locked"]).args(DENY);
            clippy
        },
        {
            let mut build = command(test);
            build.arg("--no-run");
            build
        },
    ];
    let failures: Vec<String> = thread::scope(|scope| {
        let formatting: Vec<_> = formatting
            .into_iter()
            .map(|mut format| scope.spawn(move || buffered(&mut format)))
            .collect();
        // The GPU ports build against the pinned, patched upstream sources.
        let lanes = crate::gpu::fetch::fetch(false).map(|()| {
            let boot = scope.spawn(move || lane(boot_lane, buffered));
            let host = lane(host_lane, exec);
            let boot = boot.join().expect("the UEFI lane panicked");
            // The tests run once nothing else does: some time their fixtures
            // against the host's clock.
            [boot, host.and_then(|()| exec(&mut command(test)))]
        });
        let mut results: Vec<Result<()>> = formatting
            .into_iter()
            .map(|part| part.join().expect("formatting panicked"))
            .collect();
        match lanes {
            Ok(lanes) => results.extend(lanes),
            Err(error) => results.push(Err(error)),
        }
        results
            .into_iter()
            .filter_map(Result::err)
            .map(|error| format!("{error:#}"))
            .collect()
    });
    if !failures.is_empty() {
        bail!("the gate failed:\n{}", failures.join("\n"));
    }
    Ok(())
}

/// Cargo with `args`.
fn command<S: AsRef<OsStr>>(args: impl IntoIterator<Item = S>) -> Command {
    let mut command = cargo();
    command.args(args);
    command
}

/// Clippy of `args` for [`BOOT_TARGET`] in [`BOOT_TARGET_DIR`]. RUSTFLAGS
/// also denies warnings in the runtime crates the mount builds without
/// std; registry dependencies stay lint-capped. It replaces the target's
/// configured flags, so it repeats them. Every UEFI step takes the same
/// flags and directory, so each reuses the others' dependencies.
fn uefi<S: AsRef<OsStr>>(args: impl IntoIterator<Item = S>) -> Command {
    let mut clippy = command(["clippy"]);
    clippy
        .env("RUSTFLAGS", format!("{BOOT_RUSTFLAGS} -D warnings"))
        .args(args)
        .args(["--locked", "--target", BOOT_TARGET])
        .args(["--target-dir", BOOT_TARGET_DIR])
        .args(DENY);
    clippy
}

/// Run `commands` in order, stopping at the first that fails.
fn lane(commands: Vec<Command>, run: fn(&mut Command) -> Result<()>) -> Result<()> {
    for mut command in commands {
        run(&mut command)?;
    }
    Ok(())
}

/// Run `command` with its output held until it ends, so a part beside the
/// streaming lane prints whole.
fn buffered(command: &mut Command) -> Result<()> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("cannot start {:?}", command.get_program()))?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("{command:?} failed with {}", output.status);
    }
    Ok(())
}
