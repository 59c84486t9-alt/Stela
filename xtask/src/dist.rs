//! `cargo xtask dist`: the release `stela` with its matching `stela.efi`
//! embedded. The boot image builds first, from the pinned sources `gpu
//! fetch` checks out; `stela-cli`'s build script then embeds the file
//! `STELA_EFI` names. The embedded image carries no debug sections: setup
//! writes it beside the old one on the USB's 200 MiB EFI partition.
use crate::tools::{cargo, exec, root};
use anyhow::Result;

pub fn run() -> Result<()> {
    crate::preflight::run()?;
    crate::gpu::fetch::fetch(false)?;
    let built = crate::boot::build(true)?;
    let efi = built.with_file_name("stela-dist.efi");
    crate::boot::deploy_image(&built, &efi)?;
    let mut command = cargo();
    command
        .args(["build", "--release", "--locked", "-p", "stela-cli"])
        .env("STELA_EFI", &efi);
    crate::clang::toolset()?.apply(&mut command);
    exec(&mut command)?;
    let release = root().join("target/release");
    println!("{}", release.join("stela").display());
    println!("{}", efi.display());
    Ok(())
}
