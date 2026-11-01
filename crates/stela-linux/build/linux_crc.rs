//! Linux's unchanged generic CRC library and its original host table generator.
//! All generated inputs and objects stay in Cargo's output directory.
use super::LINUX;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use stela_c_build::linux_build::{check_declarations, out_dir, run};

const SOURCES: [(&str, &str, &str); 2] = [
    ("lib/crc/crc32-main.c", "crc32", "lib/crc/crc32"),
    ("lib/bitrev.c", "bitrev", "lib/bitrev"),
];

/// Stage the original relative includes, then run the original generator for
/// HOST even when the CRC consumer targets UEFI. No source tree is written.
pub fn tables() -> PathBuf {
    for (source, _, _) in SOURCES {
        let source = PathBuf::from(LINUX).join(source);
        assert!(
            source.is_file(),
            "missing Linux CRC input {}",
            source.display()
        );
        println!("cargo:rerun-if-changed={}", source.display());
    }
    let staging = out_dir().join("linux-crc-generator");
    for (source, relative) in [
        (
            PathBuf::from(format!("{LINUX}/lib/crc/gen_crc32table.c")),
            "lib/crc/gen_crc32table.c",
        ),
        (
            PathBuf::from(format!("{LINUX}/include/linux/crc32poly.h")),
            "include/linux/crc32poly.h",
        ),
        (
            PathBuf::from("src/compat/generated/autoconf.h"),
            "include/generated/autoconf.h",
        ),
    ] {
        println!("cargo:rerun-if-changed={}", source.display());
        let bytes = fs::read(&source)
            .unwrap_or_else(|error| panic!("CRC generator input {}: {error}", source.display()));
        let destination = staging.join(relative);
        fs::create_dir_all(destination.parent().expect("staged input has a parent"))
            .expect("create the original CRC generator include layout");
        fs::write(destination, bytes).expect("stage unchanged CRC generator input");
    }
    let host = env::var("HOST").expect("Cargo supplies HOST");
    let generator = staging.join(format!("gen_crc32table{}", env::consts::EXE_SUFFIX));
    // This is upstream host C, not a kernel translation unit. Its original
    // main has unused argc/argv, so keep -Wall rather than add -Wextra.
    let mut build = cc::Build::new();
    // Clang, as for the port itself, unless the caller chose a host compiler:
    // MSVC's cl takes none of these GCC-style options.
    let chosen = [
        "HOST_CC",
        &format!("CC_{host}"),
        &format!("CC_{}", host.replace('-', "_")),
    ]
    .iter()
    .any(|name| env::var_os(name).is_some());
    if !chosen {
        build.compiler("clang");
    }
    run(build
        .host(&host)
        .target(&host)
        .cargo_metadata(false)
        .extra_warnings(false)
        .get_compiler()
        .to_command()
        .args(["-std=gnu11", "-O2", "-Wall", "-Werror"])
        .arg(staging.join("lib/crc/gen_crc32table.c"))
        .arg("-o")
        .arg(&generator));
    let output = Command::new(&generator)
        .output()
        .expect("run Linux's original CRC table generator");
    assert!(
        output.status.success() && !output.stdout.is_empty(),
        "Linux CRC table generator failed ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let tables = out_dir().join("linux-crc");
    fs::create_dir_all(&tables).expect("create the generated CRC table directory");
    fs::write(tables.join("crc32table.h"), output.stdout)
        .expect("write Linux's generated CRC tables");
    tables
}

/// Compile both unchanged common sources with their own Linux module metadata
/// and the caller's real hosted/native ABI. The caller archives these objects
/// with the other common Linux objects; no second CRC archive is introduced.
pub fn objects(build: &cc::Build, tables: &Path) -> Vec<PathBuf> {
    let mut objects = Vec::new();
    for (source, name, file) in SOURCES {
        let source = PathBuf::from(LINUX).join(source);
        assert!(
            source.is_file(),
            "missing Linux CRC input {}",
            source.display()
        );
        println!("cargo:rerun-if-changed={}", source.display());
        let mut upstream = build.clone();
        upstream
            .remove_flag("-Wconversion")
            .remove_flag("-Wsign-conversion")
            .flag("-Wno-sign-compare")
            .include(tables)
            .define("KBUILD_MODNAME", format!("\"{name}\"").as_str())
            .define("KBUILD_MODFILE", format!("\"{file}\"").as_str());
        check_declarations(&upstream, std::slice::from_ref(&source));
        objects.extend(upstream.file(source).compile_intermediates());
    }
    objects
}
