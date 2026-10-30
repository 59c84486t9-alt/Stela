use sha2::{Digest, Sha256};
use std::path::Path;
fn main() {
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"),
    );
    let upstream = manifest.join("../../third_party/mbedtls");
    let pins = upstream.join("stela-files.sha256");
    println!("cargo:rerun-if-changed={}", pins.display());
    for line in std::fs::read_to_string(&pins)
        .expect("pinned Mbed source manifest")
        .lines()
    {
        let (expected, relative) = line.split_once("  ").expect("source checksum and path");
        assert!(
            !relative.starts_with('/') && !relative.split('/').any(|part| part == ".."),
            "normalized source path"
        );
        let source = upstream.join(relative);
        let actual = format!(
            "{:x}",
            Sha256::digest(std::fs::read(&source).expect("vendored Mbed source"))
        );
        assert_eq!(actual, expected, "pinned source changed: {relative}");
        println!("cargo:rerun-if-changed={}", source.display());
    }
    let config = Path::new(".");
    let mut build = cc::Build::new();
    build
        .compiler("clang")
        .include(upstream.join("include"))
        .include(upstream.join("library"))
        .include(config)
        // Exact standard C declarations for this freestanding
        // backend, not a platform SDK or OS service implementation.
        .include(Path::new("include"))
        .flag("-ffreestanding")
        .define("MBEDTLS_CONFIG_FILE", "\"stela_mbedcrypto_config.h\"")
        .define("NDEBUG", None)
        .define("strcmp", "stela_mbedtls_strcmp")
        .flag("-mno-sse")
        .flag("-mno-sse2")
        .flag("-msoft-float")
        // Official CVE-2025-66442 mitigation: never enable the LLVM select
        // optimization that can turn constant-time C selections into branches.
        .flag("-mllvm")
        .flag("--disable-select-optimize=true")
        .flag("-fno-stack-protector")
        .flag("-ffunction-sections")
        .flag("-fdata-sections");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // LLVM COFF librarian; cross compilation needs no lib.exe SDK.
        build.archiver("llvm-lib");
    }
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "uefi" || target_os == "windows" {
        build
            // cc selects Windows COFF for the UEFI target's x64 Microsoft ABI.
            // UEFI supplies no Win32/MinGW OS or CRT; keep that object ABI,
            // but select Mbed's freestanding platform path, not Windows APIs.
            .flag("-U_WIN32")
            .flag("-U_WIN64")
            .flag("-UWIN32")
            .flag("-UWIN64")
            .flag("-U__WIN32__")
            .flag("-U__WIN64__")
            .flag("-U__MINGW32__")
            .flag("-U__MINGW64__")
            .flag("-mno-red-zone");
    }
    let mut sources: Vec<_> = std::fs::read_dir(upstream.join("library"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    sources.sort();
    for path in sources {
        if path.extension().is_some_and(|ext| ext == "c") {
            build.file(path);
        }
    }
    build.file("stela_mbed_kx.c").compile("stela_mbedcrypto");
    println!("cargo:rerun-if-changed=stela_mbed_kx.c");
    println!("cargo:rerun-if-changed=stela_mbed_kx.h");
    println!("cargo:rerun-if-changed=stela_alloc.h");
    println!("cargo:rerun-if-changed=include");
    println!(
        "cargo:rerun-if-changed={}",
        config.join("stela_mbedcrypto_config.h").display()
    );
}
