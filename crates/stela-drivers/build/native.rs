//! Native x86-64 tool selection shared by the physical GPU support libraries.
use std::{env, path::PathBuf, process::Command};

/// LP64 COFF with the Win64 calling convention; see `configure`.
pub const NATIVE_TARGET: &str = "x86_64-pc-cygwin";

/// Upstream GPU sources are linked into `src/gpu` by `cargo xtask gpu fetch`.
pub fn require_sources() {
    assert!(
        std::path::Path::new("src/gpu/common/linux/include").is_dir(),
        "the upstream GPU sources are missing; run `cargo xtask gpu fetch`"
    );
}

/// Stela's Linux environment for unchanged Linux sources: Kbuild's definition
/// and forced includes, and system include directories so upstream code keeps
/// Linux's warning profile rather than Stela's. `compat/overlay.yaml` puts each
/// shadow in place of the upstream header it replaces, however a source names
/// it. `generated` holds headers Linux's build generates, `drivers` the
/// upstream driver directories. `compat/` follows Linux's include trees for the
/// asm/ and generated/ headers that Linux's arch tree and build supply, then
/// the x86 uapi headers.
#[cfg(any(feature = "intel-port", feature = "amd-port"))]
pub fn linux_environment(
    build: &mut cc::Build,
    generated: Option<&std::path::Path>,
    drivers: &[&str],
) {
    let gpu = "src/gpu";
    let linux = format!("{gpu}/common/linux/include");
    build
        .flag("-ivfsoverlay")
        .flag(format!("{gpu}/compat/overlay.yaml"))
        .define("__KERNEL__", None)
        .flag("-include")
        .flag(format!("{linux}/linux/kconfig.h"))
        .flag("-include")
        .flag(format!("{linux}/linux/compiler_types.h"));
    if let Some(generated) = generated {
        build.flag("-isystem").flag(generated);
    }
    let directories = drivers.iter().map(|driver| format!("{gpu}/{driver}"));
    for directory in directories.chain([
        linux.clone(),
        format!("{linux}/uapi"),
        format!("{gpu}/compat"),
        format!("{gpu}/common/linux/arch/x86/include/uapi"),
    ]) {
        build.flag("-isystem").flag(directory);
    }
    // The overlay hides shadows from dependency tracking, so the whole
    // environment and the upstream trees it builds from are inputs.
    for path in [format!("{gpu}/compat"), linux] {
        println!("cargo:rerun-if-changed={path}");
    }
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
        // Upstream GPU code assumes LP64, as on Linux. Cygwin's target keeps
        // that data model while emitting COFF with the UEFI Win64 C ABI;
        // clang uses this last target over the one cc derives.
        build.flag(format!("--target={NATIVE_TARGET}"));
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
