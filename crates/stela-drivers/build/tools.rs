//! C tool selection shared by the native ports and ACPICA: clang unless the
//! caller chose a compiler through cc's standard environment, and the active
//! Rust toolchain's LLVM archiver for COFF objects.
use std::{env, path::PathBuf, process::Command};

/// Whether the caller chose a tool through cc's standard environment.
pub fn selected(tool: &str) -> bool {
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let names = [
        format!("{tool}_{target}"),
        format!("{tool}_{}", target.replace('-', "_")),
        format!("TARGET_{tool}"),
        tool.into(),
    ];
    for name in &names {
        println!("cargo:rerun-if-env-changed={name}");
    }
    names.iter().any(|name| env::var_os(name).is_some())
}

/// Apple's ar produces a BSD archive even for COFF inputs; the active Rust
/// toolchain's LLVM archiver does not.
pub fn rust_archiver() -> PathBuf {
    let output = Command::new(env::var_os("RUSTC").expect("Cargo supplies RUSTC"))
        .args(["--print", "sysroot"])
        .output()
        .expect("cannot locate the active Rust sysroot");
    assert!(output.status.success(), "rustc --print sysroot failed");
    let sysroot = String::from_utf8(output.stdout).expect("Rust sysroot is not UTF-8");
    let host = env::var("HOST").expect("Cargo supplies HOST");
    let archiver = PathBuf::from(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join(format!("bin/llvm-ar{}", env::consts::EXE_SUFFIX));
    assert!(
        archiver.is_file(),
        "install llvm-tools-preview for the active Rust toolchain"
    );
    archiver
}
