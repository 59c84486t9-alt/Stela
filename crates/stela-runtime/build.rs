//! Fingerprint the engine's compile-driver sources: with the compiler's own
//! fingerprint they make the persistent translation store's translator id
//! (`translations::translator_id`).
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// What decides the input the engine gives the compiler for a block: the
/// dispatch loop's fetch and compile, the chip's admission and checks, and
/// the store format itself.
const INPUTS: &[&str] = &[
    "src/machine/engine.rs",
    "src/machine/engine",
    "src/machine/chip.rs",
    "src/machine/chip",
    "src/machine/identification.rs",
    "src/translations.rs",
];

fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("readable source directory") {
            collect(&entry.expect("source entry").path(), files);
        }
    } else {
        files.push(path.to_owned());
    }
}

fn main() {
    // `host_memory`: guest memory on the host's POSIX mappings, which hosted
    // execution runs on. A std build elsewhere (Windows, for setup) has none
    // and refuses such requests, as the UEFI build does without boot RAM.
    println!("cargo::rustc-check-cfg=cfg(host_memory)");
    if std::env::var_os("CARGO_FEATURE_STD").is_some()
        && std::env::var_os("CARGO_CFG_UNIX").is_some()
    {
        println!("cargo::rustc-cfg=host_memory");
    }
    let mut files = Vec::new();
    for input in INPUTS {
        println!("cargo:rerun-if-changed={input}");
        collect(Path::new(input), &mut files);
    }
    files.sort();
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(&file).expect("readable source file"));
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("cargo:rustc-env=STELA_ENGINE_SOURCE_SHA256={digest}");
}
