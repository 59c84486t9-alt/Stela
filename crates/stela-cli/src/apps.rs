//! `stela apps`: a native launcher in `~/Applications/Stela` for each
//! arm64-only app, so it opens from Finder, the Dock, Spotlight and Open
//! With on an Intel Mac, where macOS refuses the original. The originals
//! are only read. Every launcher is recorded in `apps.json` and removed
//! only when it is still Stela's. `stelad` (`stelad.rs`) keeps them in sync.
//! See `docs/design/hosted-cli.md`.
#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod hosted;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) use hosted::{install_service, preferred_model, remove_service};

#[derive(Args)]
pub(crate) struct Apps {
    /// Also make a launcher for this arm64-only app kept elsewhere.
    #[arg(long, value_name = "APP")]
    add: Vec<PathBuf>,
    /// Remove the launcher of this app (its path, or its name).
    #[arg(long, value_name = "APP")]
    remove: Vec<String>,
    /// List the launchers, changing nothing.
    #[arg(long, conflicts_with_all = ["add", "remove", "uninstall"])]
    list: bool,
    /// Remove every launcher Stela made and the record; stelad makes none
    /// until `stela apps` runs again.
    #[arg(long, conflicts_with_all = ["add", "remove"])]
    uninstall: bool,
    /// Model this Mac (a product type, such as Mac15,10) in every hosted
    /// run without --model or STELA_MODEL: the launchers, stelad's
    /// translations and the terminal; `default` models the default board.
    #[arg(long, value_name = "PRODUCT", conflicts_with_all = ["add", "remove", "list", "uninstall"])]
    model: Option<String>,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Print only changes and warnings.
    #[arg(long, hide = true)]
    quiet: bool,
    /// Scan these folders instead of /Applications and ~/Applications
    /// (testing).
    #[arg(long, hide = true, value_name = "DIR")]
    scan: Vec<PathBuf>,
    /// Neither register launchers with LaunchServices nor unload a
    /// LaunchAgent (testing).
    #[arg(long, hide = true)]
    no_register: bool,
}

#[derive(Args)]
pub(crate) struct Stelad {}
