//! The restore payload a USB carries to `stela.efi`: one model's IPSW
//! members with their SHA-256s, the global `apticket` manifests and the
//! public AEA key responses, so an installation needs no network.
//!
//! [`inventory`] hashes members where they are. [`write`] lays the payload
//! out under `EFI/stela/images/<build>/`, as FAT32 slices or as the whole
//! IPSW, and writes `payload.json` last, so a volume without it holds no
//! payload.
use super::{aea, manifest};
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use stela_runtime::payload::{
    AeaKey, IdentitySet, KIND, Layout, MANIFEST_FILE, Member, PayloadManifest, Purpose,
    SourceImage, images_directory, slice_count, slice_path,
};
use zip::ZipArchive;

const BUILD_MANIFEST: &str = "BuildManifest.plist";
const BUFFER: usize = 4 * 1024 * 1024;

fn purpose(variant: &str) -> Purpose {
    if variant.contains("Erase") {
        Purpose::Erase
    } else if variant.contains("Upgrade") || variant.contains("Update") {
        Purpose::Update
    } else {
        Purpose::Installed
    }
}

/// Which members a model needs, before anything is hashed.
struct Selection {
    restore: manifest::RestoreManifest,
    device_class: String,
    identities: Vec<IdentitySet>,
    global_manifests: Vec<String>,
    names: Vec<String>,
}

fn select(archive: &mut ZipArchive<File>, model: &str) -> Result<Selection> {
    let mut bytes = Vec::new();
    archive
        .by_name(BUILD_MANIFEST)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "restore manifest exceeds 64 MiB"
    );
    let restore = manifest::inspect(&bytes, Some(model))?;
    let classes: BTreeSet<&str> = restore
        .identities
        .iter()
        .map(|identity| identity.device_class.as_str())
        .collect();
    let [device_class] = classes.into_iter().collect::<Vec<_>>()[..] else {
        bail!("{model} has identities for several device classes");
    };
    let device_class = device_class.to_owned();
    let identities: Vec<IdentitySet> = restore
        .identities
        .iter()
        .map(|identity| IdentitySet {
            index: identity.index,
            variant: identity.variant.clone(),
            purpose: purpose(&identity.variant),
            members: identity
                .components
                .values()
                .map(|component| component.path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        })
        .collect();
    let suffix = format!("/apticket.{device_class}.im4m");
    let global_manifests: Vec<String> = archive
        .file_names()
        .filter(|name| name.starts_with("Firmware/Manifests/") && name.ends_with(&suffix))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let names: Vec<String> = identities
        .iter()
        .flat_map(|identity| identity.members.iter().cloned())
        .chain(global_manifests.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for name in &names {
        ensure!(
            stela_runtime::payload::safe_path(name),
            "unsafe member {name}"
        );
        archive
            .by_name(name)
            .with_context(|| format!("the manifest names {name}, which the IPSW lacks"))?;
    }
    Ok(Selection {
        restore,
        device_class,
        identities,
        global_manifests,
        names,
    })
}

/// Stream one member through `sink`, returning its length and SHA-256.
fn stream(
    archive: &mut ZipArchive<File>,
    name: &str,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Member> {
    let mut member = archive.by_name(name)?;
    let expected = member.size();
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; BUFFER];
    loop {
        let count = member.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(
            total <= expected,
            "{name} is longer than its directory entry"
        );
        hash.update(&buffer[..count]);
        sink(&buffer[..count])?;
    }
    ensure!(total == expected, "{name} is truncated");
    Ok(Member {
        name: name.into(),
        bytes: total,
        sha256: hex::encode(hash.finalize()),
    })
}

/// Hash the named members on several threads; each opens the IPSW itself.
fn hash_members(image: &Path, names: &[String]) -> Result<Vec<Member>> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<Result<Vec<(usize, Member)>>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| -> Result<Vec<(usize, Member)>> {
                    let mut archive = ZipArchive::new(File::open(image)?)?;
                    let mut done = Vec::new();
                    loop {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(name) = names.get(index) else {
                            return Ok(done);
                        };
                        done.push((index, stream(&mut archive, name, |_| Ok(()))?));
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("hash worker panicked"))
            .collect()
    });
    let mut members: Vec<(usize, Member)> = Vec::new();
    for result in results {
        members.extend(result?);
    }
    members.sort_by_key(|(index, _)| *index);
    Ok(members.into_iter().map(|(_, member)| member).collect())
}

/// AEA metadata of each `.aea` member, read from the archive in place.
fn aea_metadata(
    archive: &mut ZipArchive<File>,
    image: &Path,
    names: &[String],
) -> Result<Vec<(String, aea::Metadata)>> {
    let mut found = Vec::new();
    for name in names.iter().filter(|name| name.ends_with(".aea")) {
        let mut member = archive.by_name(name)?;
        let length = member.size();
        let source = image.join(name);
        found.push((
            name.clone(),
            aea::inspect_stream(source, length, &mut member)?,
        ));
    }
    Ok(found)
}

fn fetch_keys(metadata: &[(String, aea::Metadata)]) -> Result<Vec<AeaKey>> {
    metadata
        .iter()
        .map(|(member, metadata)| {
            let key = aea::fetch_public_key(metadata)
                .with_context(|| format!("public AEA key for {member}"))?;
            let key_pem = String::from_utf8(key.body)?;
            Ok(AeaKey {
                member: member.clone(),
                header_sha256: metadata.header_sha256.clone(),
                url: key.request_url,
                key_sha256: stela_runtime::sha256(key_pem.as_bytes()),
                key_pem,
            })
        })
        .collect()
}

fn file_sha256(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; BUFFER];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok((total, hex::encode(hash.finalize())));
        }
        total += count as u64;
        hash.update(&buffer[..count]);
    }
}

fn manifest_for(
    image: &Path,
    selection: &Selection,
    layout: Layout,
    members: Vec<Member>,
    aea_keys: Vec<AeaKey>,
    (bytes, sha256): (u64, String),
) -> Result<PayloadManifest> {
    let manifest = PayloadManifest {
        schema_version: 1,
        kind: KIND.into(),
        product_version: selection.restore.product_version.clone(),
        product_build: selection.restore.product_build.clone(),
        model: selection.restore.identities[0]
            .product_type
            .clone()
            .context("identity has no product type")?,
        device_class: selection.device_class.clone(),
        source: SourceImage {
            file_name: image
                .file_name()
                .and_then(|name| name.to_str())
                .context("IPSW path has no UTF-8 file name")?
                .into(),
            bytes,
            sha256,
            build_manifest_sha256: selection.restore.manifest_sha256.clone(),
        },
        layout,
        members,
        identities: selection.identities.clone(),
        global_manifests: selection.global_manifests.clone(),
        aea_keys,
    };
    manifest
        .validate()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(manifest)
}

/// The `image-manifest --payload` report: member sets with SHA-256s, the
/// global manifests and each AEA member's key URL. Key material goes only
/// to `key_dir`, as 0600 files named by header SHA-256, never into the
/// report.
pub fn inventory(image: &Path, model: &str, key_dir: Option<&Path>) -> Result<serde_json::Value> {
    let mut archive = ZipArchive::new(File::open(image)?)?;
    let selection = select(&mut archive, model)?;
    let metadata = aea_metadata(&mut archive, image, &selection.names)?;
    let (ipsw, members) = std::thread::scope(|scope| {
        let whole = scope.spawn(|| file_sha256(image));
        let members = hash_members(image, &selection.names);
        (whole.join().expect("hash worker panicked"), members)
    });
    let mut keys = Vec::new();
    if let Some(directory) = key_dir {
        fs::create_dir_all(directory)?;
        for key in fetch_keys(&metadata)? {
            let path = directory.join(format!("{}.pem", key.header_sha256));
            if !path.exists() {
                let mut file = tempfile::NamedTempFile::new_in(directory)?;
                file.write_all(key.key_pem.as_bytes())?;
                file.as_file().sync_all()?;
                file.persist_noclobber(&path).map_err(|error| error.error)?;
            }
            keys.push(
                json!({"member": key.member, "header_sha256": key.header_sha256,
                "url": key.url, "key_sha256": key.key_sha256, "file": path}),
            );
        }
    }
    let manifest = manifest_for(
        image,
        &selection,
        Layout::Archive {
            path: images_directory(&selection.restore.product_build)
                + "/"
                + &image.file_name().unwrap().to_string_lossy(),
        },
        members?,
        Vec::new(),
        ipsw?,
    )?;
    Ok(json!({
        "payload": manifest,
        "aea": metadata.iter().map(|(member, metadata)| json!({
            "member": member, "header_sha256": metadata.header_sha256,
            "public_key_url": metadata.public_key_url})).collect::<Vec<_>>(),
        "aea_keys": keys,
        "limits": "Member SHA-256s are of the bytes in this IPSW; the BuildManifest's own digests are opaque and not reinterpreted. Key bodies are omitted from this report.",
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PayloadLayout {
    /// FAT32-safe slices of each member.
    Split,
    /// The whole IPSW, for volumes without FAT32's 4 GiB limit.
    Archive,
}

pub struct WriteOptions<'a> {
    pub image: &'a Path,
    pub model: &'a str,
    pub root: &'a Path,
    pub layout: PayloadLayout,
    pub slice_bytes: u64,
    pub fetch_keys: bool,
}

/// Write the payload under `root` and return a report.
pub fn write(options: &WriteOptions<'_>) -> Result<serde_json::Value> {
    let image = options.image;
    let mut archive = ZipArchive::new(File::open(image)?)?;
    let selection = select(&mut archive, options.model)?;
    let directory = options
        .root
        .join(images_directory(&selection.restore.product_build));
    let manifest_path = directory.join(MANIFEST_FILE);
    ensure!(
        !manifest_path.exists(),
        "{} exists; remove the old payload first",
        manifest_path.display()
    );
    let metadata = aea_metadata(&mut archive, image, &selection.names)?;
    let aea_keys = if options.fetch_keys {
        fetch_keys(&metadata)?
    } else {
        Vec::new()
    };
    fs::create_dir_all(&directory)?;
    let (layout, members, whole) = match options.layout {
        PayloadLayout::Split => {
            ensure!(
                (1..=stela_runtime::payload::MAX_SLICE_BYTES).contains(&options.slice_bytes),
                "slice size must be 1..=4 GiB-1"
            );
            let whole = std::thread::scope(|scope| {
                let whole = scope.spawn(|| file_sha256(image));
                let members = selection
                    .names
                    .iter()
                    .map(|name| write_slices(&mut archive, name, &directory, options.slice_bytes))
                    .collect::<Result<Vec<_>>>();
                (whole.join().expect("hash worker panicked"), members)
            });
            (
                Layout::Split {
                    slice_bytes: options.slice_bytes,
                },
                whole.1?,
                whole.0?,
            )
        }
        PayloadLayout::Archive => {
            let name = image.file_name().context("IPSW path has no file name")?;
            let copy = directory.join(name);
            ensure!(!copy.exists(), "{} exists", copy.display());
            let whole = copy_hashed(image, &copy)?;
            let members = hash_members(&copy, &selection.names)?;
            let path = format!(
                "{}/{}",
                images_directory(&selection.restore.product_build),
                name.to_str().context("IPSW file name is not UTF-8")?
            );
            (Layout::Archive { path }, members, whole)
        }
    };
    let manifest = manifest_for(image, &selection, layout, members, aea_keys, whole)?;
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    file.write_all(manifest.to_json().as_bytes())?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&manifest_path)
        .map_err(|error| error.error)?;
    Ok(json!({
        "manifest": manifest_path,
        "build": manifest.product_build,
        "model": manifest.model,
        "members": manifest.members.len(),
        "bytes": manifest.total_bytes(),
        "erase_bytes": manifest.erase_subset().map_err(|e| anyhow::anyhow!("{e}"))?.total_bytes(),
        "aea_keys": manifest.aea_keys.len(),
        "aea_members": metadata.len(),
        "ipsw_sha256": manifest.source.sha256,
    }))
}

fn write_slices(
    archive: &mut ZipArchive<File>,
    name: &str,
    directory: &Path,
    slice_bytes: u64,
) -> Result<Member> {
    let base = directory.join(name);
    fs::create_dir_all(base.parent().expect("member path has a parent"))?;
    let expected = archive.by_name(name)?.size();
    let count = slice_count(expected, slice_bytes);
    let paths: Vec<PathBuf> = (0..count)
        .map(|index| directory.join(slice_path(name, index)))
        .collect();
    for path in &paths {
        ensure!(!path.exists(), "{} exists", path.display());
    }
    let mut index = 0usize;
    let mut file = File::create(&paths[0])?;
    let mut in_slice = 0u64;
    let member = stream(archive, name, |mut chunk| {
        while !chunk.is_empty() {
            if in_slice == slice_bytes {
                file.sync_all()?;
                index += 1;
                file = File::create(&paths[index])?;
                in_slice = 0;
            }
            let take = chunk.len().min((slice_bytes - in_slice) as usize);
            file.write_all(&chunk[..take])?;
            in_slice += take as u64;
            chunk = &chunk[take..];
        }
        Ok(())
    })?;
    file.sync_all()?;
    ensure!(
        index + 1 == paths.len(),
        "{name} ended before its last slice"
    );
    Ok(member)
}

fn copy_hashed(from: &Path, to: &Path) -> Result<(u64, String)> {
    let mut input = File::open(from)?;
    let mut output = File::create_new(to)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; BUFFER];
    let mut total = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
        total += count as u64;
    }
    output.sync_all()?;
    Ok((total, hex::encode(hash.finalize())))
}

/// The synthetic IPSW's model, which no real BuildManifest uses.
pub const SYNTHETIC_MODEL: &str = "StelaTest1,1";
pub const SYNTHETIC_BUILD: &str = "STELA1";

/// Write a small IPSW-shaped archive with no Apple bytes, for tests and the
/// QEMU payload scenario. It has an Erase, an Update and an installed
/// identity for [`SYNTHETIC_MODEL`], one identity for another model, a
/// global manifest, stored and deflate members, and one ZIP64 member.
pub fn synthetic_ipsw(path: &Path) -> Result<()> {
    use zip::{CompressionMethod, write::SimpleFileOptions};
    let identity = |model: &str, class: &str, variant: &str, members: &[(&str, &str)]| {
        let entries: String = members
            .iter()
            .map(|(component, path)| {
                format!(
                    "<key>{component}</key><dict><key>Digest</key><data>AAECAw==</data>\
                     <key>Info</key><dict><key>Path</key><string>{path}</string></dict></dict>"
                )
            })
            .collect();
        format!(
            "<dict><key>Ap,ProductType</key><string>{model}</string><key>Info</key><dict>\
             <key>DeviceClass</key><string>{class}</string><key>Variant</key>\
             <string>{variant}</string></dict><key>Manifest</key><dict>{entries}</dict></dict>"
        )
    };
    let kernel = ("KernelCache", "kernelcache.release.stelatest");
    let os = ("OS", "Firmware/stelatest-os.dmg");
    let update = ("RestoreRamDisk", "stelatest-update.dmg");
    let identities = [
        identity(
            "Other1,1",
            "otherap",
            "Customer Erase Install (IPSW)",
            &[kernel],
        ),
        identity(
            SYNTHETIC_MODEL,
            "stelatestap",
            "Customer Erase Install (IPSW)",
            &[kernel, os],
        ),
        identity(
            SYNTHETIC_MODEL,
            "stelatestap",
            "Customer Upgrade Install (IPSW)",
            &[kernel, update],
        ),
        identity(SYNTHETIC_MODEL, "stelatestap", "macOS Customer", &[kernel]),
    ]
    .concat();
    let build_manifest = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>\
         <key>ProductVersion</key><string>0.0.1</string>\
         <key>ProductBuildVersion</key><string>{SYNTHETIC_BUILD}</string>\
         <key>SupportedProductTypes</key><array><string>{SYNTHETIC_MODEL}</string>\
         <string>Other1,1</string></array>\
         <key>BuildIdentities</key><array>{identities}</array></dict></plist>"
    );
    let os_bytes: Vec<u8> = (0..1_500_000u32)
        .map(|i| ((i / 7) ^ (i >> 11) ^ (i >> 17)) as u8)
        .collect();
    let mut writer = zip::ZipWriter::new(File::create_new(path)?);
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let members: [(&str, Vec<u8>, SimpleFileOptions); 6] = [
        (BUILD_MANIFEST, build_manifest.into_bytes(), deflated),
        (kernel.1, vec![0x5a; 70_000], stored.large_file(true)),
        (os.1, os_bytes, deflated),
        (update.1, b"update ramdisk".to_vec(), stored),
        (
            "Firmware/Manifests/restore/Customer/apticket.stelatestap.im4m",
            b"global".to_vec(),
            stored,
        ),
        ("Firmware/unrelated.bin", vec![1; 10], stored),
    ];
    for (name, bytes, options) in members {
        writer.start_file(name, options)?;
        writer.write_all(&bytes)?;
    }
    writer.finish()?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_runtime::payload::Purpose;

    fn options<'a>(image: &'a Path, root: &'a Path, layout: PayloadLayout) -> WriteOptions<'a> {
        WriteOptions {
            image,
            model: SYNTHETIC_MODEL,
            root,
            layout,
            slice_bytes: 400_000,
            fetch_keys: true,
        }
    }

    #[test]
    fn split_payloads_slice_members_and_record_every_identity() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("Synthetic.ipsw");
        synthetic_ipsw(&image)?;
        let root = dir.path().join("usb");
        let report = write(&options(&image, &root, PayloadLayout::Split))?;
        assert_eq!(report["members"], 4);
        let directory = root.join(images_directory(SYNTHETIC_BUILD));
        let manifest = PayloadManifest::parse(&fs::read(directory.join(MANIFEST_FILE))?).unwrap();
        assert_eq!(manifest.model, SYNTHETIC_MODEL);
        assert_eq!(manifest.device_class, "stelatestap");
        let purposes: Vec<(u32, Purpose)> = manifest
            .identities
            .iter()
            .map(|i| (i.index, i.purpose))
            .collect();
        assert_eq!(
            purposes,
            [
                (1, Purpose::Erase),
                (2, Purpose::Update),
                (3, Purpose::Installed)
            ]
        );
        assert_eq!(manifest.global_manifests.len(), 1);
        assert!(manifest.aea_keys.is_empty());
        assert_eq!(manifest.source.sha256, file_sha256(&image)?.1);
        // Each member's slices join back to its hashed bytes.
        let mut archive = ZipArchive::new(File::open(&image)?)?;
        for member in &manifest.members {
            let mut joined = Vec::new();
            for index in 0..slice_count(member.bytes, 400_000) {
                let slice = fs::read(directory.join(slice_path(&member.name, index)))?;
                assert!(slice.len() as u64 <= 400_000);
                joined.extend(slice);
            }
            let mut original = Vec::new();
            archive.by_name(&member.name)?.read_to_end(&mut original)?;
            assert_eq!(joined, original);
            assert_eq!(stela_runtime::sha256(&joined), member.sha256);
        }
        assert!(directory.join("Firmware/stelatest-os.dmg.003").exists());
        assert!(!directory.join("Firmware/unrelated.bin.000").exists());
        // A second write never replaces a payload.
        assert!(write(&options(&image, &root, PayloadLayout::Split)).is_err());
        Ok(())
    }

    #[test]
    fn archive_payloads_copy_the_ipsw_and_inventory_hashes_in_place() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("Synthetic.ipsw");
        synthetic_ipsw(&image)?;
        let root = dir.path().join("ntfs");
        write(&options(&image, &root, PayloadLayout::Archive))?;
        let directory = root.join(images_directory(SYNTHETIC_BUILD));
        let manifest = PayloadManifest::parse(&fs::read(directory.join(MANIFEST_FILE))?).unwrap();
        assert_eq!(
            manifest.layout,
            Layout::Archive {
                path: format!("{}/Synthetic.ipsw", images_directory(SYNTHETIC_BUILD))
            }
        );
        assert_eq!(
            fs::read(directory.join("Synthetic.ipsw"))?,
            fs::read(&image)?
        );
        let report = inventory(&image, SYNTHETIC_MODEL, None)?;
        assert_eq!(report["payload"]["members"], json!(manifest.members));
        assert!(inventory(&image, "Missing1,1", None).is_err());
        Ok(())
    }
}
