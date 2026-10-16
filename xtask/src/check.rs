//! The shared local and CI gate.
use crate::tools::{cargo, exec};
use anyhow::Result;

pub const BOOT_MANIFEST: &str = "crates/stela-boot/Cargo.toml";
pub const BOOT_TARGET: &str = "x86_64-unknown-none";
pub const BOOT_TARGET_DIR: &str = "target/boot";

pub fn run(fix: bool) -> Result<()> {
    let boot = ["--manifest-path", BOOT_MANIFEST];
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
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))?;
    // RUSTFLAGS also denies warnings in the runtime crates the mount builds
    // without std; registry dependencies stay lint-capped.
    exec(
        cargo()
            .env("RUSTFLAGS", "-D warnings")
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
    exec(cargo().args(["test", "--workspace", "--locked"]))
}
