//! With `STELA_EFI` naming a built `stela.efi`, as `cargo xtask dist`
//! sets it, `stela` embeds that image for setup to install (the
//! `stela_boot_image` cfg); without it setup takes `--efi FILE`.
use std::{env, fs, path::PathBuf};

const IMAGE: &str = "STELA_EFI";

fn main() {
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
