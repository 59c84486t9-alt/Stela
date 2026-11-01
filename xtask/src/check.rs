//! The shared local and CI gate.
//!
//! Formatting reads only sources, so it runs beside everything else. Once
//! the GPU sources are fetched, two lanes run at once, each in its own
//! target directory: the UEFI target's Clippy in [`BOOT_TARGET_DIR`], then
//! the other shipped hosts' ([`CROSS`]) and a compile for
//! [`RELEASE_HOST`] in [`CROSS_TARGET_DIR`], and the host's Clippy and test
//! build in `target`. The tests then run alone.
//! A lane stops at its first failure; the gate fails if any part did, once
//! every part has finished.
use crate::tools::{cargo, exec};
use anyhow::{Context, Result, bail};
use std::{
    ffi::OsStr,
    io::Write,
    iter,
    process::{Command, Stdio},
    thread,
};

pub const BOOT_MANIFEST: &str = "crates/stela-boot/Cargo.toml";
pub const BOOT_TARGET: &str = "x86_64-unknown-uefi";
pub const BOOT_TARGET_DIR: &str = "target/boot";
/// `.cargo/config.toml`'s flags for [`BOOT_TARGET`]: the soft-float target
/// takes the `aes` crate's software backend.
const BOOT_RUSTFLAGS: &str = "--cfg aes_force_soft --cfg chacha20_backend=\"soft\" --cfg aes_backend=\"soft\" --cfg polyval_backend=\"soft\" --cfg poly1305_backend=\"soft\"";
const BOOT: [&str; 2] = ["--manifest-path", BOOT_MANIFEST];
/// What `cargo fmt --all` of the workspace leaves out, each package alone:
/// `--all` would follow path dependencies into Mesa's generated crates, absent
/// until `gpu nvk` runs.
const FORMATTED_APART: [&str; 3] = [
    BOOT_MANIFEST,
    "crates/stela-mesa/Cargo.toml",
    "crates/stela-mesa/std/Cargo.toml",
];
/// The other hosts Stela ships for, with the packages Clippy checks there
/// without linking: macOS compiles installer and native preparation tools,
/// Windows the installer, and Apple silicon the isolated GPU maintenance
/// executable. The development tasks stay on this host.
const CROSS: [(&str, &[&str]); 3] = [
    (
        "x86_64-apple-darwin",
        &["--all-targets", "--workspace", "--exclude", "xtask"],
    ),
    (
        "x86_64-pc-windows-msvc",
        &["--all-targets", "-p", "stela-cli"],
    ),
    // Keep the ARM maintenance executable independent of the x86 engine.
    (
        "aarch64-apple-darwin",
        &["--all-targets", "-p", "stela-gpu-maintenance"],
    ),
];
const CROSS_TARGET_DIR: &str = "target/cross";
/// The host the release build runs on, which must compile the whole
/// workspace with no warnings, though only x86-64 runs the native paths.
const RELEASE_HOST: &str = "aarch64-apple-darwin";
const DENY: [&str; 3] = ["--", "-D", "warnings"];

pub fn run(fix: bool, nvk: bool) -> Result<()> {
    if fix {
        exec(&mut command(["fmt", "--all"]))?;
        for manifest in FORMATTED_APART {
            exec(&mut command(["fmt", "--manifest-path", manifest]))?;
        }
    }
    let formatting = iter::once(command(["fmt", "--all", "--", "--check"])).chain(
        FORMATTED_APART
            .map(|manifest| command(["fmt", "--manifest-path", manifest, "--", "--check"])),
    );
    let cross = install_targets();
    let mut boot_lane = vec![
        // Cargo caps Clippy lints on dependencies of the boot package.
        // Select each canonical hardware-data, execution and device owner
        // so its freestanding-only branches are checked directly.
        uefi(["-p", "stela-driver-core", "--no-default-features"]),
        uefi(["-p", "stela-soc-data", "--no-default-features"]),
        uefi(["-p", "stela-engine", "--no-default-features"]),
        uefi(["-p", "stela-soc", "--no-default-features"]),
        uefi(["-p", "stela-runtime", "--no-default-features"]),
        uefi(["-p", "stela-tls", "--no-default-features"]),
        uefi(["-p", "stela-boot-core", "--features", "native-acpi"]),
        uefi(BOOT),
        uefi([BOOT[0], BOOT[1], "--features", "diagnostics"]),
        uefi(["-p", "stela-driver-base", "--features", "native-acpi"]),
        uefi(["-p", "stela-driver-net", "--features", "native-acpi"]),
        uefi(["-p", "stela-driver-storage"]),
        uefi(["-p", "stela-driver-audio"]),
        // Native GPU hooks are optional while their larger vendor ports are
        // in progress, but their C/Rust ABI and UEFI target still belong to
        // the gate.
        uefi([
            "-p",
            "stela-driver-gpu",
            "--features",
            "nvidia-port,intel-port,amd-port",
        ]),
        uefi(["-p", "stela-drivers", "--features", "native-acpi"]),
    ];
    if nvk {
        boot_lane.push(uefi([
            "-p",
            "stela-driver-gpu",
            "--features",
            "metal-linked,nouveau-port",
        ]));
        let mut nvk_clippy = uefi([BOOT[0], BOOT[1], "--features", "nvk"]);
        // Mesa's unchanged path crates declare their upstream naming lint
        // policy in their manifests. Deny warnings on the mount itself;
        // Stela's driver owners are checked separately above.
        nvk_clippy.env("RUSTFLAGS", BOOT_RUSTFLAGS);
        boot_lane.push(nvk_clippy);
        let mut linked = command([
            "build",
            "--locked",
            "--manifest-path",
            BOOT_MANIFEST,
            "--features",
            "nvk",
            "--target",
            BOOT_TARGET,
            "--target-dir",
            BOOT_TARGET_DIR,
        ]);
        linked.env("CARGO_BUILD_JOBS", "8");
        boot_lane.push(linked);
    }
    boot_lane.extend(CROSS.map(|(target, packages)| {
        let mut clippy = command(["clippy", "--locked"]);
        clippy
            .args(packages)
            .args(["--target", target, "--target-dir", CROSS_TARGET_DIR])
            .args(DENY);
        clippy
    }));
    let mut release_host = command(["clippy", "--workspace", "--locked"]);
    release_host
        .args(["--target", RELEASE_HOST, "--target-dir", CROSS_TARGET_DIR])
        .args(DENY)
        // Nothing links, so build scripts' C objects go unused, and this host
        // has no Apple headers to compile them against.
        .env("CC_aarch64_apple_darwin", "true")
        .env("AR_aarch64_apple_darwin", "true");
    boot_lane.push(release_host);
    // `--all-features` includes xtask's `fetched-sources`, whose tests read
    // the fetched sources.
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
        let lanes = crate::gpu::fetch::fetch(false)
            .and_then(|()| {
                if nvk {
                    crate::gpu::build_nvk(8)?;
                }
                Ok(())
            })
            .map(|()| {
                let boot = scope.spawn(move || lane(boot_lane, buffered));
                let host = lane(host_lane, exec);
                let boot = boot.join().expect("the UEFI lane panicked");
                // The tests run once nothing else does: some time their fixtures
                // against the host's clock.
                [
                    boot,
                    host.and_then(|()| {
                        exec(&mut command(test))?;
                        // The all-feature suite selects the software crypto backend.
                        // Check the default selector independently as well.
                        exec(&mut command([
                            "test",
                            "--locked",
                            "-p",
                            "stela-crypto",
                            "--no-default-features",
                            "--lib",
                        ]))
                    }),
                ]
            });
        let mut results: Vec<Result<()>> = formatting
            .into_iter()
            .map(|part| part.join().expect("formatting panicked"))
            .collect();
        results.push(cross);
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

/// Add the [`CROSS`] targets rustup does not have yet.
fn install_targets() -> Result<()> {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("cannot run rustup, which installs the cross-check targets")?;
    let installed = String::from_utf8_lossy(&installed.stdout);
    for target in CROSS
        .map(|(target, _)| target)
        .into_iter()
        .chain([RELEASE_HOST])
    {
        if !installed.lines().any(|line| line.trim() == target) {
            exec(Command::new("rustup").args(["target", "add", target]))?;
        }
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
