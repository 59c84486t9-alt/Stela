//! The hosted main thread runs on the `stela` process's main thread
//! (`stela_runtime::hosted`), which needs the stack every guest host thread
//! gets (16 MiB) rather than the linker's 8 MiB default.
//!
//! With `boot-image`, Cargo also builds the matching `stela.efi`, as
//! `cargo xtask boot build --release` does, for setup to embed. Stable
//! Cargo cannot build an artifact dependency for another target, so this
//! runs the boot workspace's own build.
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

const BOOT_TARGET: &str = "x86_64-unknown-uefi";

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bin=stela=-Wl,-stack_size,0x1000000");
    }
    if env::var_os("CARGO_FEATURE_BOOT_IMAGE").is_some() {
        boot_image();
    }
}

fn boot_image() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        root.join("third_party/linux/.git").exists(),
        "stela.efi builds from the pinned Linux sources; run `cargo xtask gpu fetch` first"
    );
    let target_dir = root.join("target/boot");
    let mut command = Command::new(env::var_os("CARGO").expect("Cargo supplies CARGO"));
    // `current_dir` selects `.cargo/config.toml`'s flags for the UEFI target.
    command
        .current_dir(&root)
        .args(["build", "--release", "--locked"])
        .args(["--manifest-path", "crates/stela-boot/Cargo.toml"])
        .args(["--target", BOOT_TARGET])
        .arg("--target-dir")
        .arg(&target_dir)
        // Cargo reads this script's stdout for its directives.
        .stdout(io::stderr());
    // What Cargo sets for this script and its own flags describe the host
    // build, not the boot one.
    for (name, _) in env::vars_os() {
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("CARGO_FEATURE_")
            || name.starts_with("CARGO_CFG_")
            || matches!(
                name,
                "CARGO_BUILD_TARGET"
                    | "CARGO_ENCODED_RUSTFLAGS"
                    | "CARGO_TARGET_DIR"
                    | "DEBUG"
                    | "HOST"
                    | "NUM_JOBS"
                    | "OPT_LEVEL"
                    | "OUT_DIR"
                    | "PROFILE"
                    | "RUSTC_WORKSPACE_WRAPPER"
                    | "RUSTFLAGS"
                    | "TARGET"
            )
        {
            command.env_remove(name);
        }
    }
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("cannot run Cargo for stela.efi: {error}"));
    assert!(
        status.success(),
        "building stela.efi failed (above); it needs clang (LLVM) on PATH, or CC naming a \
         clang, and the sources `cargo xtask gpu fetch` checks out"
    );
    let release = target_dir.join(BOOT_TARGET).join("release");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    fs::copy(release.join("stela.efi"), out.join("stela.efi")).expect("copy stela.efi");
    // The boot build's own dependency list names every local source and
    // build input; rebuild the image when one of them changes.
    let inputs = fs::read_to_string(release.join("stela.d")).expect("read stela.efi's inputs");
    for path in inputs_of(&inputs) {
        println!("cargo:rerun-if-changed={path}");
    }
    for path in [
        "crates/stela-boot/Cargo.toml",
        "crates/stela-boot/Cargo.lock",
        ".cargo/config.toml",
        "third_party/patches",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    for tool in ["CC", "AR"] {
        println!("cargo:rerun-if-env-changed={tool}");
    }
}

/// The prerequisites of a Makefile-style dependency file, whose paths
/// escape their spaces.
fn inputs_of(text: &str) -> Vec<String> {
    let Some((_, prerequisites)) = text.split_once(": ") else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    let mut path = String::new();
    let mut characters = prerequisites.trim().chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if characters.peek() == Some(&' ') => path.push(characters.next().unwrap()),
            ' ' | '\n' | '\r' => {
                if !path.is_empty() {
                    paths.push(std::mem::take(&mut path));
                }
            }
            _ => path.push(character),
        }
    }
    if !path.is_empty() {
        paths.push(path);
    }
    paths
}
