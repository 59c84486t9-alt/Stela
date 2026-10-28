//! The hosted main thread runs on the `stela` process's main thread
//! (`stela_runtime::hosted`), which needs the stack every guest host thread
//! gets (16 MiB) rather than the linker's 8 MiB default.
//!
//! With `STELA_EFI` naming a built `stela.efi`, as `cargo xtask dist`
//! sets it, `stela` embeds that image for setup to install (the
//! `stela_boot_image` cfg); without it setup takes `--efi FILE`.
use std::{env, fs, path::PathBuf};

const IMAGE: &str = "STELA_EFI";

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bin=stela=-Wl,-stack_size,0x1000000");
    }
    println!("cargo::rustc-check-cfg=cfg(stela_boot_image)");
    println!("cargo:rerun-if-env-changed={IMAGE}");
    let Some(image) = env::var_os(IMAGE).filter(|image| !image.is_empty()) else {
        return;
    };
    let image = PathBuf::from(image);
    println!("cargo:rerun-if-changed={}", image.display());
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    fs::copy(&image, out.join("stela.efi"))
        .unwrap_or_else(|error| panic!("cannot read {IMAGE} {}: {error}", image.display()));
    println!("cargo:rustc-cfg=stela_boot_image");
}
