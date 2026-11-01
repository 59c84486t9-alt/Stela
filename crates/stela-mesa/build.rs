//! Links the archive `cargo xtask gpu nvk` builds.
use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by Cargo"));
    let directory = manifest.join("../../target/gpu/nvk");
    println!("cargo:rustc-link-search=native={}", directory.display());
    // Mesa links its Vulkan runtime and drivers whole: their entry points
    // meet in tables by weak reference, which pulls no member from an archive.
    for (name, kind) in [
        ("stela-vulkan", "static:+whole-archive"),
        ("stela-nvk", "static"),
        ("stela-llvm", "static"),
    ] {
        let archive = directory.join(format!("lib{name}.a"));
        assert!(
            archive.is_file(),
            "{} is missing: run `cargo xtask gpu nvk`",
            archive.display()
        );
        println!("cargo:rerun-if-changed={}", archive.display());
        println!("cargo:rustc-link-lib={kind}={name}");
    }
}
