//! Fingerprint the compiler sources so cached native code is bound to them.
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

const INPUTS: &[&str] = &[
    "Cargo.toml",
    "src",
    "../stela-state/Cargo.toml",
    "../stela-state/src",
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
    println!("cargo:rustc-env=STELA_COMPILER_SOURCE_SHA256={digest}");
}
