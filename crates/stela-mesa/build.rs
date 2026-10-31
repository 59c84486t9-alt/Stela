//! Links the archive `cargo xtask gpu nvk` builds.
use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by Cargo"));
    let directory = manifest.join("../../target/gpu/nvk");
    let archive = directory.join("libstela-nvk.a");
    assert!(
        archive.is_file(),
        "{} is missing: run `cargo xtask gpu nvk`",
        archive.display()
    );
    println!("cargo:rerun-if-changed={}", archive.display());
    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rustc-link-lib=static=stela-nvk");
}
