//! Native x86-64 tool selection shared by the physical GPU support libraries.
use std::{env, path::PathBuf, process::Command};

/// Upstream GPU sources are linked into `src/gpu` by `cargo xtask gpu fetch`.
pub fn require_sources() {
    assert!(
        std::path::Path::new("src/gpu/common/linux/include").is_dir(),
        "the upstream GPU sources are missing; run `cargo xtask gpu fetch`"
    );
}

pub fn configure() -> cc::Build {
    require_sources();
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86_64"),
        "the native physical GPU backends currently target x86-64"
    );
    let mut build = cc::Build::new();
    build
        .warnings_into_errors(true)
        .flag("-ffreestanding")
        .flag("-fno-stack-protector")
        .flag("-mno-red-zone")
        .flag("-mgeneral-regs-only");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("uefi") {
        // Apple's ar produces a BSD archive even for COFF inputs. Use the
        // active Rust toolchain's LLVM archiver for this cross-target build,
        // unless the caller selected an archiver through cc's normal inputs.
        let target = env::var("TARGET").expect("Cargo supplies TARGET");
        let selected = |tool: &str| {
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
        };
        if !selected("CC") {
            build.compiler("clang");
        }
        if !selected("AR") {
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
            build.archiver(archiver);
        }
    }
    build
}
