//! `cargo xtask dist`: the release `stela` with its matching `stela.efi`
//! embedded. The boot image builds first, from the pinned sources `gpu
//! fetch` checks out; `stela-cli`'s build script then embeds the file
//! `STELA_EFI` names.
use crate::tools::{cargo, exec, root};
use anyhow::Result;

pub fn run() -> Result<()> {
    crate::gpu::fetch::fetch(false)?;
    let efi = crate::boot::build(true)?;
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
