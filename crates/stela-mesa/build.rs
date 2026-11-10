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
    // What turns NIR into machine code: the C archives (NVK, NIR and the
    // Vulkan runtime) and the Rust NAK and NIL build from, with the
    // toolchain. NVK's own pipeline cache UUID is the same for every build
    // (`compat/mesa/build_id.c`), so this keys the pipeline store instead.
    stela_fingerprint::emit(
        "STELA_MESA_COMPILER_SHA256",
        &[
            ".",
            "../../target/gpu/nvk/libstela-nvk.a",
            "../../target/gpu/nvk/libstela-vulkan.a",
            "../../target/gpu/nvk/build/src/compiler/rust/libcompiler.rlib.p",
            "../../target/gpu/nvk/build/src/nouveau/compiler/latencies",
            "../../target/gpu/nvk/build/src/nouveau/compiler/nak_bindings.rs",
            "../../target/gpu/nvk/build/src/nouveau/headers/lib.rs",
            "../../target/gpu/nvk/build/src/nouveau/nil/nil_bindings.rs",
            "../../third_party/mesa/src/compiler/rust",
            "../../third_party/mesa/src/nouveau/compiler",
            "../../third_party/mesa/src/nouveau/headers/nv_push_rs",
            "../../third_party/mesa/src/nouveau/nil",
            "../../third_party/mesa/src/nouveau/rust",
            "../../rust-toolchain.toml",
        ],
    );
}
