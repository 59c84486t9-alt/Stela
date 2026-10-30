//! Build the pinned freestanding ACPICA implementation only when requested,
//! from Linux's unchanged `drivers/acpi/acpica` with Stela's host header.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use stela_c_build::{rust_archiver, selected};

/// ACPICA's interpreter in the Linux submodule, and the headers it shares.
const ACPICA: &str = "../../third_party/linux/drivers/acpi/acpica";
const HEADERS: &str = "../../third_party/linux/include/acpi";

/// Make `source` visible at `link`: a symbolic link on Unix hosts, a copy
/// elsewhere, since Windows links need privileges a build cannot assume.
fn expose(source: &Path, link: &Path) {
    #[cfg(unix)]
    {
        let _ = fs::remove_file(link);
        std::os::unix::fs::symlink(fs::canonicalize(source).unwrap(), link)
            .expect("link ACPICA's headers");
    }
    #[cfg(not(unix))]
    {
        fn copy(from: &Path, to: &Path) {
            fs::create_dir_all(to).expect("create ACPICA's header copy");
            for entry in fs::read_dir(from).expect("read ACPICA's headers") {
                let entry = entry.unwrap();
                let target = to.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    fs::copy(entry.path(), target).expect("copy an ACPICA header");
                }
            }
        }
        let _ = fs::remove_dir_all(link);
        copy(source, link);
    }
}

pub fn build() {
    println!("cargo:rerun-if-env-changed=STELA_ACPI_SANITIZE");
    if env::var_os("CARGO_FEATURE_NATIVE_ACPI").is_none() {
        return;
    }
    let base = PathBuf::from("src/platform/acpi");
    assert!(
        Path::new(ACPICA).is_dir(),
        "{ACPICA} is missing; run `cargo xtask gpu fetch`"
    );
    for name in ["include", "bridge.c", "bridge.h", "libc.c"] {
        println!("cargo:rerun-if-changed={}", base.join(name).display());
    }
    println!("cargo:rerun-if-changed={ACPICA}");
    println!("cargo:rerun-if-changed={HEADERS}");
    let target = env::var("TARGET").unwrap();
    assert!(target.starts_with("x86_64-"), "native ACPI requires x86-64");
    let coff = target == "x86_64-unknown-uefi";
    let sanitize = env::var_os("STELA_ACPI_SANITIZE").is_some();
    assert!(!sanitize || !coff, "sanitizers are hosted test tools");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // ACPICA includes `acpi/...`; this root exposes Linux's `include/acpi`
    // alone, so no other Linux header can stand in for a C library one.
    let headers = out.join("acpica-include");
    fs::create_dir_all(&headers).unwrap();
    expose(Path::new(HEADERS), &headers.join("acpi"));
    // The debugger and resource dump are outside the configured interpreter.
    let mut sources: Vec<_> = fs::read_dir(ACPICA)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            !name.starts_with("db") && name != "rsdump.c"
        })
        .collect();
    sources.sort();
    sources.push(base.join("bridge.c"));
    sources.push(base.join("libc.c"));
    let mut build = cc::Build::new();
    if !selected("CC") {
        build.compiler("clang");
    }
    build
        .std("c11")
        .opt_level(2)
        .debug(false)
        .warnings(false)
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-fno-strict-aliasing")
        .flag("-fwrapv")
        .flag("-fno-stack-protector")
        .flag("-fno-asynchronous-unwind-tables")
        .flag("-fno-unwind-tables")
        .flag("-mno-red-zone")
        .flag("-mno-sse")
        .flag("-mno-sse2")
        .flag("-mno-mmx")
        .flag("-Werror=implicit-function-declaration")
        .define("STELA_ACPI", None)
        .define("ACPI_PCI_CONFIGURED", None)
        .include(&headers)
        .include(ACPICA)
        .include(base.join("include"))
        .include(&base)
        .files(&sources);
    if coff {
        // ACPICA's UEFI objects are COFF with the Win64 C ABI; clang uses
        // this last target over the one cc derives.
        build
            .flag("--target=x86_64-pc-windows-msvc")
            .flag("-mno-stack-arg-probe")
            .flag("-mno-incremental-linker-compatible");
        if !selected("AR") {
            build.archiver(rust_archiver());
        }
    }
    if sanitize {
        build
            .flag("-fsanitize=address,undefined")
            .flag("-fno-sanitize-recover=all")
            .flag("-fno-omit-frame-pointer");
    }
    build.compile("stela_acpica");
    if sanitize {
        // Rust links with -nodefaultlibs. Select this compiler's runtime explicitly
        // instead of accidentally mixing a different linker driver's sanitizer.
        let compiler = build.get_compiler();
        let print = |argument: &str| {
            let output = Command::new(compiler.path())
                .arg(argument)
                .output()
                .unwrap();
            assert!(output.status.success());
            PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
        };
        let runtime = if target == "x86_64-apple-darwin" {
            print("--print-resource-dir").join("lib/darwin/libclang_rt.asan_osx_dynamic.dylib")
        } else {
            print("--print-file-name=libclang_rt.asan-x86_64.so")
        };
        assert!(
            runtime.is_file(),
            "clang sanitizer runtime unavailable: {}",
            runtime.display()
        );
        println!("cargo:rustc-link-arg={}", runtime.display());
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            runtime.parent().unwrap().display()
        );
    }
}
