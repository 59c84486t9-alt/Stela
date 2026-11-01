//! `cargo xtask dist`: the release `stela` with its matching `stela.efi`
//! embedded. The boot image builds first, from the pinned sources `gpu
//! fetch` checks out; `stela-cli`'s build script then embeds the file
//! `STELA_EFI` names. The embedded image carries no debug sections: setup
//! keeps several versions on the USB's 200 MiB EFI partition.
use crate::tools::{cargo, exec, root};
use anyhow::Result;
use std::process::Command;

pub fn run(nvk: bool) -> Result<()> {
    crate::gpu::fetch::fetch(false)?;
    let built = crate::boot::build(true, nvk)?;
    let efi = built.with_file_name("stela-dist.efi");
    exec(
        Command::new("llvm-objcopy")
            .arg("--strip-debug")
            .arg(&built)
            .arg(&efi),
    )?;
    exec(
        cargo()
            .args(["build", "--release", "--locked", "-p", "stela-cli"])
            .env("STELA_EFI", &efi),
    )?;
    let release = root().join("target/release");
    println!("{}", release.join("stela").display());
    println!("{}", efi.display());
    Ok(())
}
