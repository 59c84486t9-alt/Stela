//! Vendor firmware provisioning for an exact native-driver requirement inventory.
//! Network/cache policy stays in the CLI; the loader validates pins/packages.
use anyhow::{Context, Result, ensure};
use reqwest::{blocking::Client, header, redirect::Policy};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use stela_loader::host_firmware::{
    self, MAX_MANIFEST_BYTES,
    recipes::{Artifact, Plan},
    requirements::Inventory,
};

pub(super) fn read_inventory(path: &Path) -> Result<Inventory> {
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_MANIFEST_BYTES as u64,
        "firmware requirement inventory exceeds its file budget"
    );
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(Inventory::parse(&bytes)?)
}

fn read_cached(path: &Path, artifact: &Artifact) -> Result<Vec<u8>> {
    ensure!(
        !fs::symlink_metadata(path)?.is_symlink(),
        "firmware cache object is a symlink"
    );
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() == artifact.length as u64,
        "firmware cache object length differs from its pin"
    );
    let mut bytes = vec![0; artifact.length];
    file.read_exact(&mut bytes)?;
    ensure!(
        file.read(&mut [0])? == 0,
        "firmware cache object grew during read"
    );
    artifact.verify(&bytes)?;
    Ok(bytes)
}

fn download(client: &Client, artifact: &Artifact) -> Result<Vec<u8>> {
    let mut response = client
        .get(artifact.url())
        .header(header::ACCEPT_ENCODING, "identity")
        .send()?
        .error_for_status()?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "firmware source redirected or returned an unexpected status"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n == artifact.length as u64),
        "firmware source length differs from its pin"
    );
    let mut bytes = Vec::with_capacity(artifact.length);
    response
        .by_ref()
        .take(artifact.length as u64 + 1)
        .read_to_end(&mut bytes)?;
    artifact.verify(&bytes)?;
    Ok(bytes)
}

fn cached(client: &Client, directory: &Path, artifact: &Artifact) -> Result<Vec<u8>> {
    let path = directory.join(artifact.sha256);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_cached(&path, artifact),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = download(client, artifact)?;
    fs::create_dir_all(directory)?;
    ensure!(
        !fs::symlink_metadata(directory)?.is_symlink(),
        "firmware cache directory is a symlink"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&path)
        .with_context(|| format!("cannot publish immutable firmware cache {}", path.display()))?;
    File::open(directory)?.sync_all()?;
    read_cached(&path, artifact)
}

pub(super) fn provision(
    inventory: &Path,
    destination: &Path,
    cache: &Path,
    dry_run: bool,
    mount_image: &[u8],
) -> Result<String> {
    let inventory = read_inventory(inventory)?;
    let plan = Plan::select(&inventory)?;
    host_firmware::MountLimits::from_image(mount_image)
        .context("stela.efi has no supported host firmware mount capability")?
        .check_lengths(
            plan.selections()
                .iter()
                .map(|selection| selection.recipe.image.length),
        )?;
    let previous = destination.join("manifest.json");
    if previous.try_exists()? {
        let mut bytes = Vec::new();
        File::open(&previous)?
            .take(MAX_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let previous = host_firmware::Manifest::parse(&bytes)?;
        for image in &previous.images {
            ensure!(
                inventory
                    .requests()
                    .iter()
                    .any(|request| request.name == image.name
                        && request.target.driver == image.target.driver
                        && request.target.hardware == image.target.hardware
                        && request.target.revision == image.target.revision
                        && request.target.board.as_deref() == image.target.board),
                "observed requirements do not cover installed firmware binding {}; refusing to remove it",
                image.name
            );
        }
    }
    let mut report = format!(
        "Host firmware: {} exact observed bindings, {} pinned image/license artifacts\n",
        plan.selections().len(),
        plan.artifacts().len()
    );
    for selection in plan.selections() {
        use std::fmt::Write as _;
        writeln!(
            report,
            "  {} {:?}: {} bytes SHA-256 {}",
            selection.request.name,
            selection.request.target,
            selection.recipe.image.length,
            selection.recipe.image.sha256
        )?;
    }
    if dry_run {
        report.push_str("Dry run: no downloads or writes.\n");
        return Ok(report);
    }
    let client = Client::builder()
        .user_agent(concat!("stela/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(120))
        .redirect(Policy::none())
        .build()?;
    let package = plan.package(|artifact| {
        cached(&client, cache, artifact)
            .map_err(|e| host_firmware::Error(format!("firmware provisioning: {e:#}")))
    })?;
    package.check_mount(mount_image)?;
    package.publish(destination)?;
    report.push_str("Published pinned firmware and accompanying redistribution notices.\n");
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_reuse_rechecks_exact_length_hash_and_symlink_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("object");
        let artifact = Artifact {
            source: "https://vendor.invalid",
            revision: "synthetic",
            member: "one.bin",
            length: 3,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        };
        fs::write(&path, b"abc").unwrap();
        assert_eq!(read_cached(&path, &artifact).unwrap(), b"abc");
        for bytes in [b"abd".as_slice(), b"ab", b"abcd"] {
            fs::write(&path, bytes).unwrap();
            assert!(read_cached(&path, &artifact).is_err());
        }
        #[cfg(unix)]
        {
            let alias = dir.path().join("alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(read_cached(&alias, &artifact).is_err());
        }
    }
    #[test]
    fn dry_run_plans_pins_without_cache_or_destination_writes() {
        let dir = tempfile::tempdir().unwrap();
        let inventory = dir.path().join("requests.json");
        fs::write(&inventory, br#"{"schema":1,"complete":true,"requirements":[{"name":"rtl_nic/rtl8168d-1.fw","target":{"driver":"realtek","hardware":"10ec:8168","revision":"xid-281","board":null},"minimum_bytes":4}]}"#).unwrap();
        let cache = dir.path().join("cache");
        let destination = dir.path().join("destination");
        let text = provision(
            &inventory,
            &destination,
            &cache,
            true,
            &host_firmware::MOUNT_CAPABILITY,
        ).unwrap();
        assert!(text.contains("1492 bytes"));
        assert!(!cache.exists());
        assert!(!destination.exists());
        fs::write(
            &inventory,
            br#"{"schema":1,"complete":false,"requirements":[]}"#,
        )
        .unwrap();
        assert!(provision(
            &inventory,
            &destination,
            &cache,
            true,
            &host_firmware::MOUNT_CAPABILITY,
        ).is_err());
    }

    #[test]
    fn transport_rejects_redirect_truncation_growth_and_wrong_digest() {
        use std::{net::TcpListener, thread};
        for (response, valid) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
                true,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nab",
                false,
            ),
            ("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcd", false),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
                false,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabd",
                false,
            ),
            (
                "HTTP/1.1 302 Found\r\nLocation: https://vendor.invalid/alternate\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let _ = socket.read(&mut [0; 4096]);
                let _ = socket.write_all(response.as_bytes());
            });
            let artifact = Artifact {
                source: Box::leak(format!("http://{address}").into_boxed_str()),
                revision: "synthetic-v1",
                member: "one.bin",
                length: 3,
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            };
            let client = Client::builder()
                .timeout(Duration::from_secs(2))
                .redirect(Policy::none())
                .build()
                .unwrap();
            assert_eq!(download(&client, &artifact).is_ok(), valid);
            server.join().unwrap();
        }
    }

    #[test]
    #[ignore = "downloads pinned vendor data; set STELA_FIRMWARE_TEST_OUTPUT to a fresh evidence directory"]
    fn pinned_vendor_provisioning_preserves_exact_bindings_and_redistribution_notices() {
        let output = std::path::PathBuf::from(
            std::env::var_os("STELA_FIRMWARE_TEST_OUTPUT")
                .expect("explicit fresh evidence directory"),
        );
        assert!(!output.exists(), "never overwrite historical evidence");
        fs::create_dir_all(&output).unwrap();
        let requests = [
            ("rtl_nic/rtl8168d-1.fw", "xid-281"), ("rtl_nic/rtl8168d-2.fw", "xid-280"),
            ("rtl_nic/rtl8168e-1.fw", "xid-2c1"), ("rtl_nic/rtl8168e-2.fw", "xid-2c0"),
            ("rtl_nic/rtl8168e-3.fw", "xid-2c8"), ("rtl_nic/rtl8168f-1.fw", "xid-480"),
            ("rtl_nic/rtl8168f-2.fw", "xid-481"), ("rtl_nic/rtl8411-1.fw", "xid-488"),
        ].map(|(name, revision)| serde_json::json!({"name":name,"target":{"driver":"realtek","hardware":"10ec:8168","revision":revision,"board":null},"minimum_bytes":4}));
        let inventory = output.join("synthetic-observed-requirements.json");
        fs::write(
            &inventory,
            serde_json::to_vec_pretty(
                &serde_json::json!({"schema":1,"complete":true,"requirements":requests}),
            )
            .unwrap(),
        )
        .unwrap();
        let destination = output.join("firmware");
        let cache = output.join("cache");
        let report = provision(
            &inventory,
            &destination,
            &cache,
            false,
            &host_firmware::MOUNT_CAPABILITY,
        ).unwrap();
        fs::write(output.join("provisioning.txt"), report).unwrap();
        let manifest_bytes = fs::read(destination.join("manifest.json")).unwrap();
        let manifest = host_firmware::Manifest::parse(&manifest_bytes).unwrap();
        let observed = read_inventory(&inventory).unwrap();
        assert_eq!(manifest.images.len(), 8);
        for (image, request) in manifest.images.iter().zip(observed.requests()) {
            assert_eq!(image.name, request.name);
            assert_eq!(image.target.revision, request.target.revision);
            assert_eq!(image.target.board, request.target.board.as_deref());
            let bytes = fs::read(destination.join(image.path)).unwrap();
            let recipe = Plan::select(&observed).unwrap();
            recipe
                .selections()
                .iter()
                .find(|selected| selected.request.name == image.name)
                .unwrap()
                .recipe
                .image
                .verify(&bytes)
                .unwrap();
        }
        let objects = destination
            .join(manifest.images[0].path)
            .parent()
            .unwrap()
            .to_path_buf();
        let notice = fs::read(objects.join("license-0.txt")).unwrap();
        assert_eq!(notice.len(), 219);
        assert!(
            String::from_utf8(notice)
                .unwrap()
                .contains("Realtek Semiconductor Corporation")
        );
        assert!(objects.join("provenance.json").is_file());
        assert_eq!(
            host_firmware::Package::read(&destination)
                .unwrap()
                .inventory(),
            (8, 22876)
        );
        let again = provision(
            &inventory,
            &destination,
            &cache,
            false,
            &host_firmware::MOUNT_CAPABILITY,
        ).unwrap();
        assert!(again.contains("Published pinned firmware"));
        assert_eq!(
            fs::read(destination.join("manifest.json")).unwrap(),
            manifest_bytes
        );
    }
}
