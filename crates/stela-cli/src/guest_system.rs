//! The guest system files hosted programs run against: the target build's
//! arm64e dyld and dyld shared cache, which the x86 host lacks, installed
//! once per user and build under `~/Library/Application Support/Stela`
//! (`stela install-system`) and found by `stela run` without any option.
//! See `docs/design/hosted-cli.md`.
mod install;

use crate::setup::host::{Host, System};
use crate::setup::{PINNED_BUILD, download_dir};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The product version of [`PINNED_BUILD`], the guest system's version.
pub(crate) const PINNED_VERSION: &str = "27.0.1";
/// Development override: a colon-separated list of guest roots.
pub(crate) const ROOT_VARIABLE: &str = "STELA_GUEST_ROOT";
/// The per-user Stela directory below the home directory.
const SUPPORT_DIRECTORY: &str = "Library/Application Support/Stela";
/// The guest root inside a build's directory.
const ROOT_DIRECTORY: &str = "root";
/// The install receipt beside it; an install without one is incomplete.
const RECEIPT: &str = "receipt.json";
/// The guest file the install must hold for a hosted exec to start.
const DYLD: &str = "usr/lib/dyld";
/// Where an IPSW the user already has is looked for below the home
/// directory, besides setup's download directory.
const DOWNLOADS: &str = "Downloads";

/// The home directory everything per-user lives under.
pub(crate) fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .context("HOME is not set, so Stela cannot find its files")
}

/// `~/Library/Application Support/Stela`.
pub(crate) fn support_directory() -> Result<PathBuf> {
    Ok(home()?.join(SUPPORT_DIRECTORY))
}

/// Where one build's guest system lives.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// `~/Library/Application Support/Stela`.
    base: PathBuf,
    build: String,
}

impl Layout {
    pub(crate) fn new(base: PathBuf, build: &str) -> Self {
        Self {
            base,
            build: build.to_owned(),
        }
    }

    /// The pinned build's layout under the user's home.
    pub(crate) fn pinned() -> Result<Self> {
        Ok(Self::new(support_directory()?, PINNED_BUILD))
    }

    /// The build's directory.
    pub(crate) fn directory(&self) -> PathBuf {
        self.base.join(&self.build)
    }

    /// The guest root `stela run` uses.
    pub(crate) fn root(&self) -> PathBuf {
        self.directory().join(ROOT_DIRECTORY)
    }

    pub(crate) fn receipt(&self) -> PathBuf {
        self.directory().join(RECEIPT)
    }

    /// The staging directory an install is written into before it is
    /// renamed into place.
    fn partial(&self) -> PathBuf {
        self.base.join(format!(".{}.partial", self.build))
    }

    /// The guest root when the install is complete.
    pub(crate) fn installed(&self) -> Result<Option<PathBuf>> {
        if !self.receipt().is_file() {
            return Ok(None);
        }
        let root = self.root();
        ensure!(
            root.join(DYLD).is_file(),
            "the macOS {} system files in {} are damaged; reinstall them with \
             `stela install-system --remove` and then `stela install-system`",
            self.build,
            self.directory().display()
        );
        Ok(Some(root))
    }
}

/// The guest roots for a run: `explicit` (`--root`) when given, else
/// `STELA_GUEST_ROOT`, else the installed system of the pinned build. Each
/// is the canonical path of its directory: the host kernel reports rooted
/// files by their real paths, and the guest's `O_NOFOLLOW_ANY` lookups
/// must meet no symbolic link above a root (such as `/var` or a linked
/// home directory).
pub(crate) fn roots(explicit: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let roots = if !explicit.is_empty() {
        explicit.to_vec()
    } else if let Some(list) = std::env::var_os(ROOT_VARIABLE).filter(|list| !list.is_empty()) {
        environment_roots(&list)?
    } else {
        let layout = Layout::pinned()?;
        match layout.installed()? {
            Some(root) => vec![root],
            None => return Err(not_installed(&layout)),
        }
    };
    roots
        .into_iter()
        .map(|root| {
            root.canonicalize()
                .with_context(|| format!("the guest root {} cannot be read", root.display()))
        })
        .collect()
}

/// `STELA_GUEST_ROOT`'s directories, each of which must exist.
fn environment_roots(list: &OsString) -> Result<Vec<PathBuf>> {
    let roots: Vec<PathBuf> = std::env::split_paths(list)
        .filter(|root| !root.as_os_str().is_empty())
        .collect();
    for root in &roots {
        ensure!(
            root.is_dir(),
            "{ROOT_VARIABLE} names {}, which is not a directory",
            root.display()
        );
    }
    Ok(roots)
}

/// Each board's kernel version (product type → XNU `version[]`) recorded by
/// the install receipt beside the first guest root that has one. Roots
/// without a receipt, and imported roots, which carry no kernelcache, give
/// none.
pub(crate) fn kernel_versions(roots: &[PathBuf]) -> Result<BTreeMap<String, String>> {
    for root in roots {
        let Some(path) = root.parent().map(|directory| directory.join(RECEIPT)) else {
            continue;
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let receipt: install::Receipt = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not an install receipt", path.display()))?;
        if receipt.kind == install::KIND && !receipt.kernels.is_empty() {
            return Ok(receipt
                .kernels
                .into_iter()
                .map(|kernel| (kernel.product_type, kernel.version))
                .collect());
        }
    }
    Ok(BTreeMap::new())
}

/// The error a run without guest system files stops with: what is missing
/// and the one command that installs it.
fn not_installed(layout: &Layout) -> anyhow::Error {
    let command = match find_ipsw() {
        Some(ipsw) => format!(
            "    stela install-system\n\n(it reads the macOS {PINNED_VERSION} restore image \
             {})",
            ipsw.display()
        ),
        None => format!(
            "    stela install-system --ipsw PATH/TO/UniversalMac_{PINNED_VERSION}_{PINNED_BUILD}_Restore.ipsw\n\n\
             (with the macOS {PINNED_VERSION} restore image you have; add --fetch instead of \
             --ipsw to download it from Apple)"
        ),
    };
    anyhow::anyhow!(
        "the macOS {PINNED_VERSION} ({PINNED_BUILD}) system files that arm64 programs run \
         against are not installed in {}. Install them once with:\n\n{command}",
        layout.directory().display()
    )
}

/// Whether `name` is a restore image file name of the pinned build.
fn pinned_ipsw_name(name: &str) -> bool {
    name.starts_with("UniversalMac_") && name.ends_with(&format!("_{PINNED_BUILD}_Restore.ipsw"))
}

/// The first pinned-build IPSW in setup's download directory or
/// [`DOWNLOADS`].
pub(crate) fn find_ipsw() -> Option<PathBuf> {
    let home = home().ok()?;
    [download_dir(), home.join(DOWNLOADS)]
        .into_iter()
        .find_map(|directory| {
            let mut found: Vec<PathBuf> = std::fs::read_dir(directory)
                .ok()?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| {
                    path.is_file()
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(pinned_ipsw_name)
                })
                .collect();
            found.sort();
            found.into_iter().next()
        })
}

#[derive(Args)]
pub(crate) struct InstallSystem {
    /// The macOS 27 restore image (IPSW) to read; found in
    /// ~/Library/Caches/Stela/images or ~/Downloads by default.
    #[arg(long, conflicts_with_all = ["fetch", "import"])]
    ipsw: Option<PathBuf>,
    /// Download the restore image from Apple first (about 27 GB).
    #[arg(long, conflicts_with = "import")]
    fetch: bool,
    /// A directory of the IPSW's recipient AEA keys, named
    /// HEADER-SHA256.pem; without it the keys are fetched from Apple's public
    /// key server.
    #[arg(long, value_name = "DIR")]
    aea_keys: Option<PathBuf>,
    /// Remove the installed system files.
    #[arg(long, conflicts_with_all = ["ipsw", "fetch", "import", "aea_keys"])]
    remove: bool,
    /// Report what would be installed, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Development: copy guest roots `stela extract-guest-files` made from
    /// the pinned build's images instead of reading an IPSW.
    #[arg(long, hide = true, value_name = "DIR")]
    import: Vec<PathBuf>,
}

impl InstallSystem {
    pub(crate) fn run(self) -> Result<()> {
        let layout = Layout::pinned()?;
        if self.remove {
            return remove(&layout, self.dry_run);
        }
        if let Some(root) = layout.installed()? {
            println!(
                "The macOS {PINNED_VERSION} ({PINNED_BUILD}) system files are installed in {}.",
                root.display()
            );
            return Ok(());
        }
        if !self.import.is_empty() {
            return install::from_roots(&layout, &self.import, self.dry_run);
        }
        let ipsw = match (self.ipsw, self.fetch) {
            (Some(ipsw), _) => ipsw,
            (None, true) if self.dry_run => {
                bail!("--dry-run with --fetch needs the image first; pass --ipsw")
            }
            (None, true) => crate::setup::fetch_image(
                &download_dir(),
                PINNED_BUILD,
                crate::setup::PINNED_MODEL,
            )?,
            (None, false) => find_ipsw().with_context(|| {
                format!(
                    "no macOS {PINNED_VERSION} ({PINNED_BUILD}) restore image found in {} or \
                     ~/Downloads; pass it with --ipsw PATH, or add --fetch to download it from \
                     Apple (about 27 GB)",
                    download_dir().display()
                )
            })?,
        };
        install::from_ipsw(&layout, &ipsw, self.aea_keys.as_deref(), self.dry_run)
    }
}

/// Remove the build's directory and any interrupted install of it.
fn remove(layout: &Layout, dry_run: bool) -> Result<()> {
    let directories: Vec<PathBuf> = [layout.directory(), layout.partial()]
        .into_iter()
        .filter(|directory| directory.exists())
        .collect();
    if directories.is_empty() {
        println!("No macOS {} system files are installed.", layout.build);
        return Ok(());
    }
    for directory in directories {
        if dry_run {
            println!("Would remove {}", directory.display());
        } else {
            std::fs::remove_dir_all(&directory)
                .with_context(|| format!("cannot remove {}", directory.display()))?;
            println!("Removed {}", directory.display());
        }
    }
    Ok(())
}

/// The free bytes of the file system holding `path`.
fn available_bytes(path: &Path) -> Result<u64> {
    Ok(System.volume(path)?.free_bytes)
}

/// `bytes` for people, in decimal gigabytes.
pub(crate) fn gigabytes(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1e9)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_keeps_each_build_in_its_own_directory() -> Result<()> {
        let base = tempfile::tempdir()?;
        let layout = Layout::new(base.path().to_owned(), "26A434");
        assert_eq!(layout.root(), base.path().join("26A434/root"));
        assert_eq!(layout.receipt(), base.path().join("26A434/receipt.json"));
        assert_eq!(layout.partial(), base.path().join(".26A434.partial"));
        assert_eq!(layout.installed()?, None);
        std::fs::create_dir_all(layout.root().join("usr/lib"))?;
        assert_eq!(layout.installed()?, None, "no receipt: incomplete");
        std::fs::write(layout.receipt(), "{}")?;
        let damaged = layout.installed().unwrap_err().to_string();
        assert!(damaged.contains("damaged"), "{damaged}");
        std::fs::write(layout.root().join(DYLD), b"dyld")?;
        assert_eq!(layout.installed()?, Some(layout.root()));
        Ok(())
    }

    /// A run's kernel versions are the ones the receipt beside its root
    /// records; a root without one gives none, and a damaged one fails.
    #[test]
    fn kernel_versions_come_from_the_receipt_beside_the_root() -> Result<()> {
        let base = tempfile::tempdir()?;
        let layout = Layout::new(base.path().to_owned(), "26A434");
        let roots = [layout.root()];
        assert!(kernel_versions(&roots)?.is_empty());
        let version = "Darwin Kernel Version 1.2.3: synthetic; root:test~1/RELEASE_TEST";
        let receipt = serde_json::json!({
            "kind": install::KIND,
            "schema_version": 1,
            "product_version": "1.2.3",
            "product_build": "26A434",
            "source": { "kind": "ipsw", "file_name": "test.ipsw", "bytes": 1 },
            "members": [],
            "files": [],
            "kernels": [{ "product_type": "Mac0,1", "member": "kernelcache.test", "version": version }],
        });
        std::fs::create_dir_all(layout.directory())?;
        std::fs::write(layout.receipt(), serde_json::to_vec(&receipt)?)?;
        assert_eq!(
            kernel_versions(&roots)?,
            BTreeMap::from([("Mac0,1".to_owned(), version.to_owned())])
        );
        std::fs::write(layout.receipt(), "{}")?;
        assert!(kernel_versions(&roots).is_err());
        Ok(())
    }

    #[test]
    fn environment_roots_split_on_colons_and_must_exist() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        let list = std::env::join_paths([first.path(), second.path()])?;
        assert_eq!(
            environment_roots(&list)?,
            [first.path().to_owned(), second.path().to_owned()]
        );
        let missing = std::env::join_paths([first.path(), &first.path().join("missing")])?;
        assert!(environment_roots(&missing).is_err());
        Ok(())
    }

    #[test]
    fn only_the_pinned_build_s_restore_images_are_found() {
        assert!(pinned_ipsw_name("UniversalMac_27.0.1_26A434_Restore.ipsw"));
        assert!(!pinned_ipsw_name("UniversalMac_26.0_25A354_Restore.ipsw"));
        assert!(!pinned_ipsw_name(
            "UniversalMac_27.0.1_26A434_Restore.ipsw.part"
        ));
    }

    #[test]
    fn free_space_is_read_from_the_file_system() -> Result<()> {
        let directory = tempfile::tempdir()?;
        assert!(available_bytes(directory.path())? > 0);
        assert_eq!(gigabytes(14_189_330_432), "14.2 GB");
        Ok(())
    }
}
