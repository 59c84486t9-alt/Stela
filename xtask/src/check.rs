//! The shared local and CI gate.
use crate::tools::{cargo, exec};
use anyhow::Result;

pub const BOOT_MANIFEST: &str = "crates/stela-boot/Cargo.toml";
pub const BOOT_TARGET: &str = "x86_64-unknown-uefi";
pub const BOOT_TARGET_DIR: &str = "target/boot";
/// `.cargo/config.toml`'s flags for [`BOOT_TARGET`]: the soft-float target
/// takes the `aes` crate's software backend.
const BOOT_RUSTFLAGS: &str = "--cfg aes_force_soft";

pub fn run(fix: bool) -> Result<()> {
    let boot = ["--manifest-path", BOOT_MANIFEST];
    // The GPU ports build against the pinned, patched upstream sources.
    crate::gpu::fetch::fetch(false)?;
    if fix {
        exec(cargo().args(["fmt", "--all"]))?;
        exec(cargo().arg("fmt").args(boot).arg("--all"))?;
    }
    exec(cargo().args(["fmt", "--all", "--", "--check"]))?;
    exec(
        cargo()
            .arg("fmt")
            .args(boot)
            .args(["--all", "--", "--check"]),
    )?;
    exec(cargo().args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))?;
    // Cargo caps Clippy lints on dependencies of the boot package. Select the
    // runtime itself too, so its freestanding-only branches are checked.
    exec(
        cargo()
            .env("RUSTFLAGS", format!("{BOOT_RUSTFLAGS} -D warnings"))
            .args([
                "clippy",
                "-p",
                "stela-runtime",
                "--no-default-features",
                "--locked",
                "--target",
                BOOT_TARGET,
                "--target-dir",
                BOOT_TARGET_DIR,
                "--",
                "-D",
                "warnings",
            ]),
    )?;
    // RUSTFLAGS also denies warnings in the runtime crates the mount builds
    // without std; registry dependencies stay lint-capped. It replaces the
    // target's configured flags, so it repeats them.
    exec(
        cargo()
            .env("RUSTFLAGS", format!("{BOOT_RUSTFLAGS} -D warnings"))
            .arg("clippy")
            .args(boot)
            .args([
                "--locked",
                "--target",
                BOOT_TARGET,
                "--target-dir",
                BOOT_TARGET_DIR,
            ])
            .args(["--", "-D", "warnings"]),
    )?;
    // Native GPU hooks are optional while their larger vendor ports are in
    // progress, but their C/Rust ABI and UEFI target still belong to the gate.
    exec(cargo().args([
        "clippy",
        "-p",
        "stela-drivers",
        "--features",
        "nvidia-port,intel-port,amd-port",
        "--target",
        BOOT_TARGET,
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))?;
    exec(cargo().args(["test", "--workspace", "--all-features", "--locked"]))
}
