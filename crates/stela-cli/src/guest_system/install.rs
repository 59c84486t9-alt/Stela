//! Writing one build's guest system: from the IPSW's own members, or from
//! guest roots extracted earlier (development). Everything is written into
//! the layout's staging directory and renamed into place last, so an
//! install is either complete, with its receipt, or absent.
pub(super) mod metadata;

use super::{Layout, available_bytes, gigabytes};
use crate::restore::{self, aea, components, disk, payload::file_sha256};
use crate::setup::PINNED_MODEL;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use stela_formats::payload::Purpose;

/// The receipt's `kind`.
pub(super) const KIND: &str = "stela_guest_system";
const SCHEMA: u32 = 1;
/// The receipt `stela-dev extract-guest-files` writes.
const EXTRACTION_KIND: &str = "guest_file_extraction";
/// A decrypted member needs at most this many halves of its encrypted
/// size while its files are copied (26A434's system volume: 1.26 times).
const DECRYPTED_HALVES: u64 = 3;
/// The BuildManifest component of a board's kernelcache.
const KERNEL_CACHE: &str = "KernelCache";
/// The erase identities, whose kernelcache a board's installed system boots.
const ERASE: &str = "Erase";
/// A kernelcache member's size limit, and its decoded payload's (the 26A434
/// kernelcaches decode to about 125 MB).
const KERNEL_MEMBER_LIMIT: u64 = 64 << 20;
const KERNEL_DECODED_LIMIT: u64 = 512 << 20;
/// The prefix of the arm64e shared cache's files.
const SHARED_CACHE: &str = "System/Library/dyld/dyld_shared_cache_arm64e";

/// The release files CoreFoundation (`_CFCopySystemVersionDictionary`) and
/// `sw_vers` read, the OS cryptex's before the system volume's: each
/// part's own copy, at its place in the guest, so the guest reports its
/// own release rather than the host's.
const SYSTEM_VERSION: &str = "/System/Library/CoreServices/SystemVersion.plist";
const RESTORE_VERSION: &str = "/System/Library/CoreServices/RestoreVersion.plist";

/// One BuildManifest component the install reads, and what it takes.
struct Part {
    component: &'static str,
    required: &'static [&'static str],
    shared_cache: bool,
    /// Where the guest mounts the component's volume: its required files
    /// go below it. The shared cache goes to the system volume's
    /// `/System/Library/dyld`, where dyld also looks.
    mount: &'static str,
}

/// The smaller member first, so a short disk fails before the large one.
const PARTS: [Part; 2] = [
    Part {
        component: "Cryptex1,SystemOS",
        required: &[SYSTEM_VERSION, RESTORE_VERSION],
        shared_cache: true,
        mount: "System/Cryptexes/OS",
    },
    Part {
        component: "OS",
        required: &["/usr/lib/dyld", SYSTEM_VERSION, RESTORE_VERSION],
        shared_cache: false,
        mount: "",
    },
];

/// Where an install's files came from.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Source {
    Ipsw {
        file_name: String,
        bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
    },
    Imported {
        roots: Vec<PathBuf>,
    },
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

/// One board's kernel: the kernelcache member its erase identity boots and
/// that kernelcache's XNU `version[]`, which a hosted process reports as
/// `kern.version` for that board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Kernel {
    pub(super) product_type: String,
    member: String,
    pub(super) version: String,
}

/// `receipt.json`.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Receipt {
    pub(super) kind: String,
    schema_version: u32,
    pub(super) product_version: String,
    product_build: String,
    source: Source,
    members: Vec<Member>,
    files: Vec<disk::Copied>,
    /// Each board's kernel, read from the IPSW; empty for imported roots,
    /// which carry no kernelcache.
    #[serde(default)]
    pub(super) kernels: Vec<Kernel>,
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
        manifest.product_build == layout.build.build,
        "{} is macOS {} ({}), not {}",
        ipsw.display(),
        manifest.product_version,
        manifest.product_build,
        layout.name()
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
        println!("Reading each board's kernel version");
        let kernels = kernels(&manifest, &mut archive)?;
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
                sha256: Some(file_sha256(ipsw)?.1),
            },
            members,
            files,
            kernels,
        };
        publish(layout, &partial, &receipt)
    })();
    finish(&partial, result)
}

/// Each erase identity's board and the `version[]` of the kernelcache it
/// boots, decoding each kernelcache member once.
fn kernels(
    manifest: &restore::manifest::RestoreManifest,
    archive: &mut zip::ZipArchive<File>,
) -> Result<Vec<Kernel>> {
    let mut versions = std::collections::BTreeMap::new();
    let mut kernels: Vec<Kernel> = vec![];
    for identity in &manifest.identities {
        let (Some(product_type), Some(component)) = (
            identity.product_type.as_ref(),
            identity.components.get(KERNEL_CACHE),
        ) else {
            continue;
        };
        if identity.restore_behavior.as_deref() != Some(ERASE)
            || kernels
                .iter()
                .any(|kernel| &kernel.product_type == product_type)
        {
            continue;
        }
        if !versions.contains_key(&component.path) {
            let mut container = vec![];
            archive
                .by_name(&component.path)
                .with_context(|| format!("the IPSW has no member {}", component.path))?
                .take(KERNEL_MEMBER_LIMIT + 1)
                .read_to_end(&mut container)?;
            ensure!(
                container.len() as u64 <= KERNEL_MEMBER_LIMIT,
                "{} is larger than a kernelcache",
                component.path
            );
            versions.insert(component.path.clone(), kernel_version(&container)?);
        }
        kernels.push(Kernel {
            product_type: product_type.clone(),
            member: component.path.clone(),
            version: versions[&component.path].clone(),
        });
    }
    ensure!(!kernels.is_empty(), "the IPSW names no board kernelcache");
    kernels.sort_by(|a, b| a.product_type.cmp(&b.product_type));
    Ok(kernels)
}

/// The `version[]` of a kernelcache IM4P container.
fn kernel_version(container: &[u8]) -> Result<String> {
    let (decoded, _) = stela_loader::im4p::decode(container, KERNEL_DECODED_LIMIT)
        .context("cannot decode the kernelcache")?;
    stela_loader::kernel_version::read(&decoded).map_err(|reason| anyhow::anyhow!(reason))
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
    let (volume, files) = copy_part(&image, &partial.join(super::ROOT_DIRECTORY), plan.part)?;
    drop(decrypted);
    Ok((
        Member {
            component: plan.part.component.into(),
            member: plan.member.clone(),
            member_bytes: plan.bytes,
            aea_header_sha256: metadata.header_sha256,
            volume,
        },
        files,
    ))
}

/// Copy `part`'s files out of its decrypted `image` into the guest `root`:
/// its required files below its mount, its shared cache into the system
/// volume. The copied files are listed by their guest paths.
fn copy_part(
    image: &Path,
    root: &Path,
    part: &Part,
) -> Result<(Option<String>, Vec<disk::Copied>)> {
    let selection = |required: &[&str], shared_cache: bool| disk::Selection {
        required: required.iter().map(|path| path.to_string()).collect(),
        optional: vec![],
        shared_cache,
        volume: None,
    };
    let mounted = !part.mount.is_empty();
    let copy = disk::copy_into(
        image,
        &root.join(part.mount),
        &selection(part.required, part.shared_cache && !mounted),
    )?;
    let mut files: Vec<disk::Copied> = copy
        .files
        .into_iter()
        .map(|mut file| {
            if mounted {
                file.path = format!("/{}{}", part.mount, file.path);
            }
            file
        })
        .collect();
    if part.shared_cache && mounted {
        files.extend(disk::copy_into(image, root, &selection(&[], true))?.files);
    }
    Ok((copy.volume, files))
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
        "Importing the {} system files into {}",
        layout.name(),
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
            product_version: layout.build.version.into(),
            product_build: layout.build.build.into(),
            source: Source::Imported {
                roots: sources.iter().map(|(root, _)| root.clone()).collect(),
            },
            members: vec![],
            files: installed,
            kernels: vec![],
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
                sha256: stela_formats::sha256(bytes),
            });
        }
        stela_runtime::write_json(
            &directory.join(super::super::RECEIPT),
            &serde_json::json!({"kind": EXTRACTION_KIND, "files": listed}),
        )
    }

    #[test]
    fn imports_verify_receipts_before_publication() -> Result<()> {
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
        let layout = Layout::new(work.path().join("Stela"), stela_formats::builds::DEFAULT);
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
    fn root_receipt_mismatch_blocks_installation() -> Result<()> {
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
        let layout = Layout::new(work.path().join("Stela"), stela_formats::builds::DEFAULT);
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
        let layout = Layout::new(work.path().join("Stela"), stela_formats::builds::DEFAULT);
        assert!(from_roots(&layout, &[files], false).is_err());
        Ok(())
    }

    #[test]
    fn build_mismatch_blocks_installation() -> Result<()> {
        let work = tempfile::tempdir()?;
        let ipsw = work.path().join("other.ipsw");
        restore::payload::synthetic_ipsw_of(&ipsw, "99Z999")?;
        let layout = Layout::new(work.path().join("Stela"), stela_formats::builds::DEFAULT);
        let error = from_ipsw(&layout, &ipsw, None, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("99Z999"), "{error}");
        assert!(!layout.base.exists());
        Ok(())
    }

    /// The OS cryptex's release files go below its mount, its shared cache
    /// into the system volume, each listed at its guest path.
    #[test]
    #[cfg(target_os = "macos")]
    fn cryptex_publishes_release_and_system_cache() -> Result<()> {
        let work = tempfile::tempdir()?;
        let volume = work.path().join("volume");
        for (path, text) in [
            (SYSTEM_VERSION, "system"),
            (RESTORE_VERSION, "restore"),
            ("/System/Library/dyld/dyld_shared_cache_arm64e", "cache"),
            (
                "/System/Library/dyld/dyld_shared_cache_arm64e.01",
                "cache 1",
            ),
            ("/System/Library/dyld/dyld_shared_cache_x86_64", "other"),
        ] {
            let file = volume.join(path.trim_start_matches('/'));
            fs::create_dir_all(file.parent().unwrap())?;
            fs::write(file, text)?;
        }
        let image = work.path().join("cryptex.dmg");
        let created = std::process::Command::new("/usr/bin/hdiutil")
            .args([
                "create",
                "-quiet",
                "-format",
                "UDRO",
                "-volname",
                "Cryptex",
                "-srcfolder",
            ])
            .arg(&volume)
            .arg(&image)
            .status()?;
        ensure!(created.success(), "hdiutil create failed");
        let root = work.path().join("root");
        let (_, files) = copy_part(&image, &root, &PARTS[0])?;
        let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/System/Cryptexes/OS/System/Library/CoreServices/SystemVersion.plist",
                "/System/Cryptexes/OS/System/Library/CoreServices/RestoreVersion.plist",
                "/System/Library/dyld/dyld_shared_cache_arm64e",
                "/System/Library/dyld/dyld_shared_cache_arm64e.01",
            ]
        );
        for path in paths {
            assert!(root.join(path.trim_start_matches('/')).is_file(), "{path}");
        }
        assert!(
            !root
                .join("System/Library/dyld/dyld_shared_cache_x86_64")
                .exists()
        );
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

    /// A synthetic kernelcache IM4P (DER short form: SEQUENCE of IA5 "IM4P",
    /// type and description and an OCTET STRING payload) yields its version.
    #[test]
    fn kernelcache_container_exposes_version() -> Result<()> {
        fn field(tag: u8, data: &[u8]) -> Vec<u8> {
            [vec![tag, data.len() as u8], data.to_vec()].concat()
        }
        const IA5: u8 = 0x16;
        const OCTETS: u8 = 0x04;
        const SEQUENCE: u8 = 0x30;
        let version = b"Darwin Kernel Version 1.0.0: synthetic; root:test~1/RELEASE_TEST";
        let payload = [&[0xa5; 8][..], version, &[0]].concat();
        let container = field(
            SEQUENCE,
            &[
                field(IA5, b"IM4P"),
                field(IA5, b"krnl"),
                field(IA5, b"synthetic"),
                field(OCTETS, &payload),
            ]
            .concat(),
        );
        assert_eq!(kernel_version(&container)?.as_bytes(), version.as_slice());
        assert!(kernel_version(&field(SEQUENCE, &field(IA5, b"IM4P"))).is_err());
        Ok(())
    }
}
