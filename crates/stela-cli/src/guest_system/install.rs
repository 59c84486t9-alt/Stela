//! Writing one build's guest system: from the IPSW's own members, or from
//! guest roots extracted earlier (development). Everything is written into
//! the layout's staging directory and renamed into place last, so an
//! install is either complete, with its receipt, or absent.
use super::{Layout, PINNED_VERSION, available_bytes, gigabytes};
use crate::restore::{self, aea, components, disk, payload::file_sha256};
use crate::setup::PINNED_MODEL;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use stela_runtime::payload::Purpose;

/// The receipt's `kind`.
const KIND: &str = "stela_guest_system";
const SCHEMA: u32 = 1;
/// The receipt `stela extract-guest-files` writes.
const EXTRACTION_KIND: &str = "guest_file_extraction";
/// A decrypted member needs at most this many halves of its encrypted
/// size while its files are copied (26A434's system volume: 1.26 times).
const DECRYPTED_HALVES: u64 = 3;
/// The prefix of the arm64e shared cache's files.
const SHARED_CACHE: &str = "System/Library/dyld/dyld_shared_cache_arm64e";

/// One BuildManifest component the install reads, and what it takes.
struct Part {
    component: &'static str,
    required: &'static [&'static str],
    shared_cache: bool,
}

/// The smaller member first, so a short disk fails before the large one.
const PARTS: [Part; 2] = [
    Part {
        component: "Cryptex1,SystemOS",
        required: &[],
        shared_cache: true,
    },
    Part {
        component: "OS",
        required: &["/usr/lib/dyld"],
        shared_cache: false,
    },
];

/// Where an install's files came from.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Source {
    Ipsw { file_name: String, bytes: u64 },
    Imported { roots: Vec<PathBuf> },
}

/// One member an install read.
#[derive(Debug, Serialize, Deserialize)]
struct Member {
    component: String,
    member: String,
    member_bytes: u64,
    aea_header_sha256: String,
    volume: Option<String>,
}

/// `receipt.json`.
#[derive(Debug, Serialize, Deserialize)]
struct Receipt {
    kind: String,
    schema_version: u32,
    product_version: String,
    product_build: String,
    source: Source,
    members: Vec<Member>,
    files: Vec<disk::Copied>,
}

/// A planned member: its component, archive path and size.
struct Planned<'a> {
    part: &'a Part,
    member: String,
    bytes: u64,
}

/// Install `layout`'s build from `ipsw`, reading each AEA member's key from
/// `keys` or from Apple's public key server.
pub(super) fn from_ipsw(
    layout: &Layout,
    ipsw: &Path,
    keys: Option<&Path>,
    dry_run: bool,
) -> Result<()> {
    ensure!(ipsw.is_file(), "{} is not a file", ipsw.display());
    let manifest = restore::archive::manifest(ipsw, None, false)
        .with_context(|| format!("{} is not a macOS restore image", ipsw.display()))?;
    ensure!(
        manifest.product_build == layout.build,
        "{} is macOS {} ({}), but this stela runs programs against macOS {PINNED_VERSION} ({})",
        ipsw.display(),
        manifest.product_version,
        manifest.product_build,
        layout.build
    );
    let profile = components::Profile::of(PINNED_MODEL)?;
    let identity = components::identity(&manifest, &profile, Purpose::Erase)?;
    let mut archive = zip::ZipArchive::new(File::open(ipsw)?)?;
    let mut planned = vec![];
    for part in &PARTS {
        let (_, component) = components::component(&manifest, &profile, identity, part.component)?;
        let bytes = archive
            .by_name(&component.path)
            .with_context(|| format!("the IPSW has no member {}", component.path))?
            .size();
        planned.push(Planned {
            part,
            member: component.path.clone(),
            bytes,
        });
    }
    println!(
        "Installing the macOS {} ({}) system files arm64 programs run against",
        manifest.product_version, manifest.product_build
    );
    println!("  from {}", ipsw.display());
    for plan in &planned {
        println!(
            "  {} ({}, {})",
            plan.part.component,
            plan.member,
            gigabytes(plan.bytes)
        );
    }
    println!("  into {}", layout.root().display());
    if dry_run {
        return Ok(());
    }
    let partial = stage(layout)?;
    let result = (|| {
        let mut members = vec![];
        let mut files = vec![];
        for plan in &planned {
            let (member, copied) =
                install_member(layout, &partial, ipsw, &mut archive, plan, keys)?;
            members.push(member);
            files.extend(copied);
        }
        let receipt = Receipt {
            kind: KIND.into(),
            schema_version: SCHEMA,
            product_version: manifest.product_version.clone(),
            product_build: manifest.product_build.clone(),
            source: Source::Ipsw {
                file_name: ipsw
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                bytes: fs::metadata(ipsw)?.len(),
            },
            members,
            files,
        };
        publish(layout, &partial, &receipt)
    })();
    finish(&partial, result)
}

/// Decrypt one member beside the install, copy its files into the staged
/// root, and delete the decrypted image.
fn install_member(
    layout: &Layout,
    partial: &Path,
    ipsw: &Path,
    archive: &mut zip::ZipArchive<File>,
    plan: &Planned<'_>,
    keys: Option<&Path>,
) -> Result<(Member, Vec<disk::Copied>)> {
    let needed = plan.bytes / 2 * DECRYPTED_HALVES;
    let free = available_bytes(partial)?;
    ensure!(
        free >= needed,
        "decrypting {} needs about {} free temporarily in {}, and {} is free",
        plan.part.component,
        gigabytes(needed),
        layout.base.display(),
        gigabytes(free)
    );
    let metadata = {
        let mut reader = archive.by_name(&plan.member)?;
        aea::inspect_stream(ipsw.join(&plan.member), plan.bytes, &mut reader)
            .with_context(|| format!("{} is not an AEA archive", plan.member))?
    };
    let pem = match keys {
        Some(directory) => {
            let path = directory.join(format!("{}.pem", metadata.header_sha256));
            fs::read_to_string(&path)
                .with_context(|| format!("no key for {} in {}", plan.member, directory.display()))?
        }
        None => {
            println!(
                "Fetching {}'s public decryption key from Apple ({})",
                plan.part.component,
                metadata.public_key_url.as_deref().unwrap_or("no URL")
            );
            String::from_utf8(aea::fetch_public_key(&metadata)?.body)?
        }
    };
    let image = partial.join(format!(
        "{}.dmg",
        plan.part
            .component
            .replace(|c: char| !c.is_ascii_alphanumeric(), "-")
    ));
    let decrypted = tempfile::TempPath::try_from_path(&image)?;
    {
        let reader = archive.by_name(&plan.member)?;
        let mut progress = Progress::new(reader, plan.bytes, plan.part.component);
        aea::decrypt_reader(&metadata, &pem, &mut progress, &image)
            .with_context(|| format!("cannot decrypt {}", plan.member))?;
        progress.done();
    }
    println!("Copying the files of {}", plan.part.component);
    let selection = disk::Selection {
        required: plan
            .part
            .required
            .iter()
            .map(|path| path.to_string())
            .collect(),
        optional: vec![],
        shared_cache: plan.part.shared_cache,
        volume: None,
    };
    let copy = disk::copy_into(&image, &partial.join(super::ROOT_DIRECTORY), &selection)?;
    drop(decrypted);
    Ok((
        Member {
            component: plan.part.component.into(),
            member: plan.member.clone(),
            member_bytes: plan.bytes,
            aea_header_sha256: metadata.header_sha256,
            volume: copy.volume,
        },
        copy.files,
    ))
}

/// Install `layout`'s build from guest roots with `extract-guest-files`
/// receipts, checking every file against its receipt.
pub(super) fn from_roots(layout: &Layout, roots: &[PathBuf], dry_run: bool) -> Result<()> {
    let mut sources = vec![];
    for root in roots {
        let receipt: serde_json::Value = stela_runtime::read_json(&root.join(super::RECEIPT))
            .with_context(|| format!("{} has no extraction receipt", root.display()))?;
        ensure!(
            receipt["kind"] == EXTRACTION_KIND,
            "{} is not a guest file extraction",
            root.display()
        );
        let files: Vec<disk::Copied> = serde_json::from_value(receipt["files"].clone())
            .with_context(|| format!("{}'s receipt lists no files", root.display()))?;
        sources.push((root.canonicalize()?, files));
    }
    let listed = |prefix: &str| {
        sources.iter().any(|(_, files)| {
            files
                .iter()
                .any(|file| file.path.trim_start_matches('/').starts_with(prefix))
        })
    };
    ensure!(
        listed(super::DYLD) && listed(SHARED_CACHE),
        "the roots must hold /{} and the arm64e shared cache",
        super::DYLD
    );
    println!(
        "Importing the macOS {PINNED_VERSION} ({}) system files into {}",
        layout.build,
        layout.root().display()
    );
    if dry_run {
        return Ok(());
    }
    let partial = stage(layout)?;
    let result = (|| {
        let root = partial.join(super::ROOT_DIRECTORY);
        let mut installed: Vec<disk::Copied> = vec![];
        for (source, files) in &sources {
            for file in files {
                let relative = file.path.trim_start_matches('/');
                ensure!(
                    restore::manifest::safe_member(relative),
                    "unsafe guest path {}",
                    file.path
                );
                if let Some(earlier) = installed.iter().find(|earlier| earlier.path == file.path) {
                    ensure!(earlier == file, "two roots hold different {}", file.path);
                    continue;
                }
                let destination = root.join(relative);
                fs::create_dir_all(destination.parent().context("guest path has no parent")?)?;
                fs::copy(source.join(relative), &destination)
                    .with_context(|| format!("cannot copy {}", file.path))?;
                let (bytes, sha256) = file_sha256(&destination)?;
                ensure!(
                    bytes == file.bytes && sha256 == file.sha256,
                    "{} in {} does not match its receipt",
                    file.path,
                    source.display()
                );
                installed.push(file.clone());
            }
        }
        let receipt = Receipt {
            kind: KIND.into(),
            schema_version: SCHEMA,
            product_version: PINNED_VERSION.into(),
            product_build: layout.build.clone(),
            source: Source::Imported {
                roots: sources.iter().map(|(root, _)| root.clone()).collect(),
            },
            members: vec![],
            files: installed,
        };
        publish(layout, &partial, &receipt)
    })();
    finish(&partial, result)
}

/// A fresh staging directory, replacing an interrupted install's.
fn stage(layout: &Layout) -> Result<PathBuf> {
    let partial = layout.partial();
    if partial.exists() {
        fs::remove_dir_all(&partial).with_context(|| {
            format!(
                "cannot remove the interrupted install {}",
                partial.display()
            )
        })?;
    }
    fs::create_dir_all(partial.join(super::ROOT_DIRECTORY))?;
    Ok(partial)
}

/// Write the receipt into the staging directory and rename it into place.
fn publish(layout: &Layout, partial: &Path, receipt: &Receipt) -> Result<()> {
    ensure!(
        partial
            .join(super::ROOT_DIRECTORY)
            .join(super::DYLD)
            .is_file(),
        "the install holds no /{}",
        super::DYLD
    );
    stela_runtime::write_json(&partial.join(super::RECEIPT), receipt)?;
    let directory = layout.directory();
    if directory.exists() {
        // Only an install without its receipt reaches here: incomplete.
        fs::remove_dir_all(&directory)?;
    }
    fs::rename(partial, &directory)?;
    println!(
        "Installed {} files ({}) in {}",
        receipt.files.len(),
        gigabytes(receipt.files.iter().map(|file| file.bytes).sum()),
        layout.root().display()
    );
    Ok(())
}

/// Remove the staging directory when the install failed.
fn finish(partial: &Path, result: Result<()>) -> Result<()> {
    if result.is_err() && partial.exists() {
        let _ = fs::remove_dir_all(partial);
    }
    result
}

/// A reader that shows how much of `total` it has read on a terminal.
struct Progress<R> {
    inner: R,
    total: u64,
    read: u64,
    shown: u64,
    label: &'static str,
    terminal: bool,
}

/// Percent steps between progress lines.
const PROGRESS_STEP: u64 = 1;

impl<R: Read> Progress<R> {
    fn new(inner: R, total: u64, label: &'static str) -> Self {
        let progress = Self {
            inner,
            total: total.max(1),
            read: 0,
            shown: 0,
            label,
            terminal: std::io::stderr().is_terminal(),
        };
        if progress.terminal {
            eprint!("Decrypting {label}: 0%");
        } else {
            eprintln!("Decrypting {label}");
        }
        progress
    }

    fn done(&self) {
        if self.terminal {
            eprintln!("\rDecrypting {}: done", self.label);
        }
    }
}

impl<R: Read> Read for Progress<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.read += count as u64;
        let percent = self.read * 100 / self.total;
        if self.terminal && percent >= self.shown + PROGRESS_STEP {
            self.shown = percent;
            eprint!("\rDecrypting {}: {percent}%", self.label);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An extraction root holding `files`, with its receipt.
    fn extraction(directory: &Path, files: &[(&str, &[u8])]) -> Result<()> {
        let mut listed = vec![];
        for (path, bytes) in files {
            let host = directory.join(path.trim_start_matches('/'));
            fs::create_dir_all(host.parent().unwrap())?;
            fs::write(&host, bytes)?;
            listed.push(disk::Copied {
                path: path.to_string(),
                bytes: bytes.len() as u64,
                sha256: stela_runtime::sha256(bytes),
            });
        }
        stela_runtime::write_json(
            &directory.join(super::super::RECEIPT),
            &serde_json::json!({"kind": EXTRACTION_KIND, "files": listed}),
        )
    }

    #[test]
    fn imported_roots_are_checked_against_their_receipts_and_published_whole() -> Result<()> {
        let work = tempfile::tempdir()?;
        let files = work.path().join("guest-files");
        let cache = work.path().join("shared-cache");
        extraction(
            &files,
            &[("/usr/lib/dyld", b"dyld"), ("/bin/echo", b"echo")],
        )?;
        extraction(
            &cache,
            &[("/System/Library/dyld/dyld_shared_cache_arm64e", b"cache")],
        )?;
        let layout = Layout::new(work.path().join("Stela"), "26A434");
        from_roots(&layout, &[files.clone(), cache.clone()], true)?;
        assert!(!layout.directory().exists(), "a dry run changes nothing");
        from_roots(&layout, &[files.clone(), cache.clone()], false)?;
        assert_eq!(layout.installed()?, Some(layout.root()));
        assert_eq!(fs::read(layout.root().join("bin/echo"))?, b"echo");
        assert!(!layout.partial().exists());
        let receipt: Receipt = stela_runtime::read_json(&layout.receipt())?;
        assert_eq!(
            (receipt.kind.as_str(), receipt.schema_version),
            (KIND, SCHEMA)
        );
        assert_eq!(receipt.files.len(), 3);
        assert!(matches!(receipt.source, Source::Imported { ref roots } if roots.len() == 2));
        Ok(())
    }

    #[test]
    fn a_root_that_differs_from_its_receipt_leaves_nothing_installed() -> Result<()> {
        let work = tempfile::tempdir()?;
        let files = work.path().join("guest-files");
        extraction(
            &files,
            &[
                ("/usr/lib/dyld", b"dyld"),
                ("/System/Library/dyld/dyld_shared_cache_arm64e", b"cache"),
            ],
        )?;
        fs::write(files.join("usr/lib/dyld"), b"changed")?;
        let layout = Layout::new(work.path().join("Stela"), "26A434");
        let error = from_roots(&layout, &[files], false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match its receipt"), "{error}");
        assert!(!layout.directory().exists() && !layout.partial().exists());
        Ok(())
    }

    #[test]
    fn roots_without_dyld_or_the_shared_cache_are_refused() -> Result<()> {
        let work = tempfile::tempdir()?;
        let files = work.path().join("guest-files");
        extraction(&files, &[("/usr/lib/dyld", b"dyld")])?;
        let layout = Layout::new(work.path().join("Stela"), "26A434");
        assert!(from_roots(&layout, &[files], false).is_err());
        Ok(())
    }

    #[test]
    fn an_image_of_another_build_is_refused_before_anything_is_written() -> Result<()> {
        let work = tempfile::tempdir()?;
        let ipsw = work.path().join("other.ipsw");
        restore::payload::synthetic_ipsw_of(&ipsw, "99Z999")?;
        let layout = Layout::new(work.path().join("Stela"), "26A434");
        let error = from_ipsw(&layout, &ipsw, None, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("99Z999"), "{error}");
        assert!(!layout.base.exists());
        Ok(())
    }

    #[test]
    fn progress_counts_what_it_reads() -> Result<()> {
        let mut progress = Progress::new(&b"0123456789"[..], 10, "test");
        let mut out = vec![];
        progress.read_to_end(&mut out)?;
        assert_eq!(progress.read, 10);
        assert_eq!(out, b"0123456789");
        Ok(())
    }
}
