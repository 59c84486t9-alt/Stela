//! Target ABI, compiler and sanitizer settings shared by native C consumers.
use crate::{rust_archiver, selected};
use std::env;

/// LP64 COFF with the Win64 calling convention; see `configure`.
pub const NATIVE_TARGET: &str = "x86_64-pc-cygwin";

/// Stela's own C is held to these as errors. Upstream code builds from system
/// include directories and keeps its own warning profile.
const WARNINGS: [&str; 4] = ["-Wall", "-Wextra", "-Wconversion", "-Wsign-conversion"];

/// The port's sources compiled for Cargo's target, freestanding as the mount
/// runs them.
pub fn configure() -> cc::Build {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86_64"),
        "the native C backends currently target x86-64"
    );
    let mut build = compiler();
    build
        .flag("-ffreestanding")
        .flag("-fno-stack-protector")
        .flag("-mno-red-zone")
        .flag("-mgeneral-regs-only");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("uefi") {
        // Native Linux code assumes LP64, as on Linux. Cygwin's target keeps
        // that data model while emitting COFF with the UEFI Win64 C ABI;
        // clang uses this last target over the one cc derives. Its large
        // frames must not call Cygwin's ___chkstk_ms, which the mount lacks,
        // and its objects carry no incremental-linker timestamps.
        build
            .flag(format!("--target={NATIVE_TARGET}"))
            .flag("-mno-stack-arg-probe")
            .flag("-mno-incremental-linker-compatible");
        if !selected("AR") {
            build.archiver(rust_archiver());
        }
    }
    build
}

/// The same sources compiled for this machine with sanitizers, for the C test
/// programs. `None` when Cargo cross-compiles: the programs cannot run then.
pub fn hosted() -> Option<cc::Build> {
    if env::var("TARGET").ok() != env::var("HOST").ok() {
        return None;
    }
    let mut build = compiler();
    build
        .cargo_metadata(false)
        .debug(true)
        .flag("-fsanitize=address,undefined")
        .flag("-fno-sanitize-recover=all")
        .flag("-fno-omit-frame-pointer");
    Some(build)
}

/// Clang for every target, unless the caller chose a compiler: the
/// upstream sources' warning profile (`-Wno-everything`) is clang's, and
/// GCC holds their headers to Stela's warnings.
pub fn compiler() -> cc::Build {
    let mut build = cc::Build::new();
    if !selected("CC") {
        build.compiler("clang");
    }
    build.std("gnu11").warnings_into_errors(true);
    for warning in WARNINGS {
        build.flag(warning);
    }
    build
}
