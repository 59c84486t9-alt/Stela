//! Metadata-only upgrades of a complete guest-system install. The original
//! receipt is immutable; the new sidecar is bound to its exact bytes.
use super::*;
use sha2::{Digest as _, Sha256};
use std::io::{Seek as _, SeekFrom, Write as _};

const FILE: &str = "kernel-versions.json";
const KIND: &str = "stela_guest_kernel_versions";
const MANIFEST_LIMIT: u64 = 64 << 20;

#[derive(Serialize, Deserialize)]
struct Versions {
    kind: String,
    schema_version: u32,
    product_build: String,
    receipt_sha256: String,
    source_sha256: String,
    manifest_sha256: String,
    kernels: Vec<Kernel>,
}

/// A published metadata upgrade must still belong to this exact receipt.
pub(in crate::guest_system) fn read(
    directory: &Path,
    receipt: &[u8],
) -> Result<Option<Vec<Kernel>>> {
    let path = directory.join(FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    let record: Versions = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not kernel-version metadata", path.display()))?;
    let original: Receipt = serde_json::from_slice(receipt)?;
    ensure!(
        record.kind == KIND
            && record.schema_version == SCHEMA
            && record.product_build == original.product_build
            && record.receipt_sha256 == stela_formats::sha256(receipt)
            && !record.kernels.is_empty()
            && [record.source_sha256, record.manifest_sha256]
                .iter()
                .all(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "{} does not match the installed receipt",
        path.display()
    );
    Ok(Some(record.kernels))
}

/// Validate source, installed inventory and all new metadata before publishing
/// one sidecar. No guest-system file or historical receipt is rewritten.
pub(in crate::guest_system) fn refresh(
    layout: &Layout,
    ipsw: Option<&Path>,
    dry_run: bool,
) -> Result<()> {
    let original = fs::read(layout.receipt())?;
    let receipt: Receipt = serde_json::from_slice(&original).context("invalid install receipt")?;
    ensure!(
        receipt.kind == super::KIND
            && receipt.schema_version == SCHEMA
            && receipt.product_build == layout.build.build
            && receipt.product_version == layout.build.version,
        "the installed receipt does not match {}",
        layout.name()
    );
    if !receipt.kernels.is_empty() || read(&layout.directory(), &original)?.is_some() {
        return Ok(());
    }
    let Source::Ipsw {
        file_name,
        bytes,
        sha256,
    } = &receipt.source
    else {
        return Ok(());
    };
    let Some(ipsw) = ipsw else {
        println!(
            "The installed receipt has no kernel versions; add --ipsw PATH to its original restore image to record them without reinstalling."
        );
        return Ok(());
    };
    let mut source = File::open(ipsw).with_context(|| format!("cannot read {}", ipsw.display()))?;
    ensure!(
        source.metadata()?.is_file()
            && source.metadata()?.len() == *bytes
            && ipsw.file_name().and_then(|name| name.to_str()) == Some(file_name.as_str()),
        "{} does not match the install's source name and size",
        ipsw.display()
    );
    // Older install receipts did not record the archive hash. In that case,
    // retain the independently downloaded archive's existing hash as the anchor.
    let expected_hash = match sha256 {
        Some(hash) => hash.clone(),
        None => {
            let mut name = ipsw.as_os_str().to_owned();
            name.push(".json");
            let download: serde_json::Value = stela_runtime::read_json(Path::new(&name))
                .context("the legacy install needs its original IPSW download receipt")?;
            ensure!(
                download["bytes"].as_u64() == Some(*bytes)
                    && download["image"]["build"].as_str() == Some(layout.build.build),
                "the IPSW download receipt does not match the installed build and size"
            );
            download["sha256"]
                .as_str()
                .context("the download receipt has no SHA-256")?
                .to_owned()
        }
    };
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let source_sha256 = hex::encode(hash.finalize());
    ensure!(
        source_sha256 == expected_hash,
        "the IPSW differs from its recorded SHA-256"
    );
    source.seek(SeekFrom::Start(0))?;
    let mut archive = zip::ZipArchive::new(source)?;
    let mut manifest_bytes = vec![];
    archive
        .by_name("BuildManifest.plist")?
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut manifest_bytes)?;
    ensure!(
        manifest_bytes.len() as u64 <= MANIFEST_LIMIT,
        "BuildManifest exceeds its limit"
    );
    let manifest = restore::manifest::inspect(&manifest_bytes, None)?;
    ensure!(
        manifest.product_build == receipt.product_build
            && manifest.product_version == receipt.product_version,
        "the IPSW build differs from the installed receipt"
    );
    let profile = components::Profile::of(PINNED_MODEL)?;
    let identity = components::identity(&manifest, &profile, Purpose::Erase)?;
    for part in &PARTS {
        let (_, component) = components::component(&manifest, &profile, identity, part.component)?;
        let installed = receipt
            .members
            .iter()
            .find(|member| member.component == part.component)
            .context("the installed receipt omits a system member")?;
        let mut member = archive.by_name(&component.path)?;
        let metadata = aea::inspect_stream(ipsw.join(&component.path), member.size(), &mut member)?;
        ensure!(
            installed.member == component.path
                && installed.member_bytes == member.size()
                && installed.aea_header_sha256 == metadata.header_sha256,
            "{} differs from the installed member identity",
            part.component
        );
    }
    ensure!(
        !receipt.files.is_empty(),
        "the installed receipt lists no files"
    );
    for file in &receipt.files {
        let relative = file.path.trim_start_matches('/');
        ensure!(
            restore::manifest::safe_member(relative),
            "unsafe installed path {}",
            file.path
        );
        let (bytes, hash) = file_sha256(&layout.root().join(relative))?;
        ensure!(
            bytes == file.bytes && hash == file.sha256,
            "{} differs from its installed hash",
            file.path
        );
    }
    let kernels = kernels(&manifest, &mut archive)?;
    let versions = Versions {
        kind: KIND.into(),
        schema_version: SCHEMA,
        product_build: layout.build.build.into(),
        receipt_sha256: stela_formats::sha256(&original),
        source_sha256,
        manifest_sha256: stela_formats::sha256(&manifest_bytes),
        kernels,
    };
    if dry_run {
        println!(
            "Would record {} board kernel versions in {}",
            versions.kernels.len(),
            layout.directory().join(FILE).display()
        );
        return Ok(());
    }
    publish(layout, &original, &versions)?;
    println!(
        "Recorded {} board kernel versions without reinstalling system files.",
        versions.kernels.len()
    );
    Ok(())
}

fn publish(layout: &Layout, original: &[u8], versions: &Versions) -> Result<()> {
    let mut pending = tempfile::NamedTempFile::new_in(layout.directory())?;
    serde_json::to_writer_pretty(&mut pending, versions)?;
    pending.write_all(b"\n")?;
    pending.as_file().sync_all()?;
    ensure!(
        fs::read(layout.receipt())? == original,
        "the install receipt changed during metadata validation"
    );
    pending.persist_noclobber(layout.directory().join(FILE))?;
    File::open(layout.directory())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _work: tempfile::TempDir,
        layout: Layout,
        source: PathBuf,
        original: Vec<u8>,
    }

    impl Fixture {
        fn new(build: &str) -> Result<Self> {
            let work = tempfile::tempdir()?;
            let layout = Layout::new(
                work.path().join("installed"),
                stela_formats::builds::DEFAULT,
            );
            fs::create_dir_all(layout.root().join("usr/lib"))?;
            fs::write(layout.root().join("usr/lib/dyld"), b"original dyld")?;
            let source = work.path().join("original.ipsw");
            let profile = components::Profile::of(PINNED_MODEL)?;
            let manifest = format!(
                r#"<?xml version="1.0"?><plist version="1.0"><dict>
                <key>ProductVersion</key><string>27.0.1</string>
                <key>ProductBuildVersion</key><string>{build}</string>
                <key>SupportedProductTypes</key><array><string>{PINNED_MODEL}</string></array>
                <key>BuildIdentities</key><array><dict>
                <key>Ap,ProductType</key><string>{PINNED_MODEL}</string>
                <key>ApChipID</key><string>{:#x}</string><key>ApBoardID</key><string>{:#x}</string>
                <key>Info</key><dict><key>DeviceClass</key><string>{}</string>
                <key>Variant</key><string>test</string><key>RestoreBehavior</key><string>Erase</string></dict>
                <key>Manifest</key><dict>
                <key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk</string></dict></dict>
                <key>KernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernel</string></dict></dict>
                <key>OS</key><dict><key>Info</key><dict><key>Path</key><string>os.aea</string></dict></dict>
                <key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>cache.aea</string></dict></dict>
                </dict></dict></array></dict></plist>"#,
                profile.chip_id, profile.board_id, profile.device_class
            );
            let header = [b"AEA1".as_slice(), &1u32.to_le_bytes(), &0u32.to_le_bytes()].concat();
            let aea = [header.clone(), vec![0]].concat();
            fn field(tag: u8, bytes: &[u8]) -> Vec<u8> {
                [vec![tag, bytes.len() as u8], bytes.to_vec()].concat()
            }
            let version = b"Darwin Kernel Version 1.0.0: synthetic; root:test~1/RELEASE_TEST\0";
            let kernel = field(
                0x30,
                &[
                    field(0x16, b"IM4P"),
                    field(0x16, b"krnl"),
                    field(0x16, b"test"),
                    field(0x04, &[&[0xa5; 8][..], version].concat()),
                ]
                .concat(),
            );
            let mut archive = zip::ZipWriter::new(File::create(&source)?);
            for (name, data) in [
                ("BuildManifest.plist", manifest.as_bytes()),
                ("kernel", kernel.as_slice()),
                ("os.aea", aea.as_slice()),
                ("cache.aea", aea.as_slice()),
            ] {
                archive.start_file(name, zip::write::SimpleFileOptions::default())?;
                archive.write_all(data)?;
            }
            archive.finish()?;
            let (bytes, hash) = file_sha256(&source)?;
            let receipt = Receipt {
                kind: super::super::KIND.into(),
                schema_version: SCHEMA,
                product_version: layout.build.version.into(),
                product_build: layout.build.build.into(),
                source: Source::Ipsw {
                    file_name: "original.ipsw".into(),
                    bytes,
                    sha256: Some(hash),
                },
                members: [("OS", "os.aea"), ("Cryptex1,SystemOS", "cache.aea")]
                    .map(|(component, member)| Member {
                        component: component.into(),
                        member: member.into(),
                        member_bytes: aea.len() as u64,
                        aea_header_sha256: stela_formats::sha256(&header),
                        volume: None,
                    })
                    .into(),
                files: vec![disk::Copied {
                    path: "/usr/lib/dyld".into(),
                    bytes: 13,
                    sha256: stela_formats::sha256(b"original dyld"),
                }],
                kernels: vec![],
            };
            stela_runtime::write_json(&layout.receipt(), &receipt)?;
            let original = fs::read(layout.receipt())?;
            Ok(Self {
                _work: work,
                layout,
                source,
                original,
            })
        }

        fn unchanged(&self) -> Result<()> {
            assert_eq!(fs::read(self.layout.receipt())?, self.original);
            assert_eq!(
                fs::read(self.layout.root().join("usr/lib/dyld"))?,
                b"original dyld"
            );
            assert!(!self.layout.directory().join(FILE).exists());
            Ok(())
        }
    }

    #[test]
    fn a_validated_upgrade_preserves_history_and_is_idempotent() -> Result<()> {
        let fixture = Fixture::new("26A434")?;
        refresh(&fixture.layout, Some(&fixture.source), true)?;
        fixture.unchanged()?;
        // A leftover interrupted staging file is neither authority nor a block
        // on a fresh publication.
        fs::write(
            fixture.layout.directory().join(".interrupted-metadata"),
            b"partial",
        )?;
        refresh(&fixture.layout, Some(&fixture.source), false)?;
        let path = fixture.layout.directory().join(FILE);
        let published = fs::read(&path)?;
        let kernels = read(&fixture.layout.directory(), &fixture.original)?.unwrap();
        assert_eq!(kernels.len(), 1);
        assert_eq!(kernels[0].product_type, PINNED_MODEL);
        assert!(kernels[0].version.contains("synthetic"));
        assert_eq!(
            crate::guest_system::kernel_versions(&[fixture.layout.root()])?[PINNED_MODEL],
            kernels[0].version
        );
        refresh(&fixture.layout, Some(Path::new("absent.ipsw")), false)?;
        assert_eq!(fs::read(path)?, published);
        assert_eq!(fs::read(fixture.layout.receipt())?, fixture.original);
        assert_eq!(
            fs::read(fixture.layout.root().join("usr/lib/dyld"))?,
            b"original dyld"
        );
        Ok(())
    }

    #[test]
    fn missing_changed_sources_and_wrong_builds_publish_nothing() -> Result<()> {
        let fixture = Fixture::new("26A434")?;
        refresh(&fixture.layout, None, false)?;
        fixture.unchanged()?;
        assert!(refresh(&fixture.layout, Some(Path::new("absent.ipsw")), false).is_err());
        fixture.unchanged()?;
        let mut bytes = fs::read(&fixture.source)?;
        bytes[0] ^= 1;
        fs::write(&fixture.source, bytes)?;
        assert!(
            refresh(&fixture.layout, Some(&fixture.source), false)
                .unwrap_err()
                .to_string()
                .contains("SHA-256")
        );
        fixture.unchanged()?;
        let wrong = Fixture::new("another-build")?;
        assert!(
            refresh(&wrong.layout, Some(&wrong.source), false)
                .unwrap_err()
                .to_string()
                .contains("build differs")
        );
        wrong.unchanged()?;
        Ok(())
    }

    #[test]
    fn damaged_inventory_and_receipts_are_never_repaired_by_metadata() -> Result<()> {
        let fixture = Fixture::new("26A434")?;
        fs::write(fixture.layout.root().join("usr/lib/dyld"), b"changed dyld!")?;
        assert!(
            refresh(&fixture.layout, Some(&fixture.source), false)
                .unwrap_err()
                .to_string()
                .contains("installed hash")
        );
        assert!(!fixture.layout.directory().join(FILE).exists());
        assert_eq!(fs::read(fixture.layout.receipt())?, fixture.original);
        fs::write(fixture.layout.receipt(), b"{\"kind\":")?;
        assert!(refresh(&fixture.layout, Some(&fixture.source), false).is_err());
        assert_eq!(fs::read(fixture.layout.receipt())?, b"{\"kind\":");
        assert!(!fixture.layout.directory().join(FILE).exists());
        Ok(())
    }

    #[test]
    fn legacy_sources_require_their_download_hash_and_published_metadata_is_bound() -> Result<()> {
        let fixture = Fixture::new("26A434")?;
        let mut receipt: serde_json::Value = serde_json::from_slice(&fixture.original)?;
        let hash = receipt["source"]["sha256"].take();
        stela_runtime::write_json(&fixture.layout.receipt(), &receipt)?;
        let original = fs::read(fixture.layout.receipt())?;
        assert!(refresh(&fixture.layout, Some(&fixture.source), false).is_err());
        stela_runtime::write_json(
            &fixture.source.with_extension("ipsw.json"),
            &serde_json::json!({
                "sha256": hash, "bytes": fs::metadata(&fixture.source)?.len(), "image": { "build": "26A434" }
            }),
        )?;
        refresh(&fixture.layout, Some(&fixture.source), false)?;
        assert!(read(&fixture.layout.directory(), &original)?.is_some());
        assert!(read(&fixture.layout.directory(), &fixture.original).is_err());
        let path = fixture.layout.directory().join(FILE);
        let record: Versions = stela_runtime::read_json(&path)?;
        fs::remove_file(path)?;
        fs::write(fixture.layout.receipt(), &fixture.original)?;
        assert!(publish(&fixture.layout, &original, &record).is_err());
        assert!(!fixture.layout.directory().join(FILE).exists());
        Ok(())
    }
}
