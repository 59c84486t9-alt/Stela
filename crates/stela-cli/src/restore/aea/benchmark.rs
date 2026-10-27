//! Opt-in native measurement against external, inventoried AEA inputs.
//! Authenticated plaintext is hashed and discarded; no image is changed.
use super::*;
use sha2::{Digest, Sha384};

#[derive(Default)]
struct Sink {
    hash: Sha384,
    bytes: u64,
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.hash.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "requires STELA_AEA_BENCH_IPSW, STELA_AEA_BENCH_INVENTORY and STELA_AEA_BENCH_MEMBER"]
fn native_stream_authentication_benchmark() -> Result<()> {
    let image = PathBuf::from(std::env::var("STELA_AEA_BENCH_IPSW")?);
    let inventory = PathBuf::from(std::env::var("STELA_AEA_BENCH_INVENTORY")?);
    let member = std::env::var("STELA_AEA_BENCH_MEMBER")?;
    let inventory_bytes = std::fs::read(&inventory)?;
    let payload: serde_json::Value = serde_json::from_slice(&inventory_bytes)?;
    let key = payload["aea_keys"]
        .as_array()
        .context("no inventoried AEA keys")?
        .iter()
        .find(|entry| entry["member"].as_str() == Some(member.as_str()))
        .context("member has no inventoried AEA key")?;
    let pem = key["key_pem"].as_str().context("no recipient key")?;
    let file = File::open(&image)?;
    ensure!(
        Some(file.metadata()?.len()) == payload["source"]["bytes"].as_u64(),
        "source size differs from inventory"
    );
    let mut archive = zip::ZipArchive::new(file)?;
    let mut manifest = Vec::new();
    archive
        .by_name("BuildManifest.plist")?
        .read_to_end(&mut manifest)?;
    ensure!(
        Some(sha256(&manifest).as_str()) == payload["source"]["build_manifest_sha256"].as_str(),
        "BuildManifest differs from inventory"
    );
    let manifest = plist::Value::from_reader(std::io::Cursor::new(manifest))?;
    let mut digests = BTreeSet::new();
    for identity in manifest
        .as_dictionary()
        .context("manifest dictionary")?
        .get("BuildIdentities")
        .and_then(plist::Value::as_array)
        .context("identities")?
    {
        let Some(components) = identity
            .as_dictionary()
            .and_then(|i| i.get("Manifest"))
            .and_then(plist::Value::as_dictionary)
        else {
            continue;
        };
        for component in components.values().filter_map(plist::Value::as_dictionary) {
            let path = component
                .get("Info")
                .and_then(plist::Value::as_dictionary)
                .and_then(|info| info.get("Path"))
                .and_then(plist::Value::as_string);
            if path == Some(member.as_str())
                && let Some(digest) = component.get("Digest").and_then(plist::Value::as_data)
            {
                digests.insert(hex::encode(digest));
            }
        }
    }
    let mut input = archive.by_name(&member)?;
    let encrypted_bytes = input.size();
    let metadata = inspect_stream(image.clone(), encrypted_bytes, &mut input)?;
    ensure!(
        Some(metadata.header_sha256.as_str()) == key["header_sha256"].as_str(),
        "AEA header differs from inventory"
    );
    drop(input);
    let archive_key = archive_key(&metadata, pem)?;
    let mut input = archive.by_name(&member)?;
    let mut sink = Sink::default();
    let started = std::time::Instant::now();
    let bytes = container::decrypt(&archive_key, &metadata.header_sha256, &mut input, &mut sink)?;
    let seconds = started.elapsed().as_secs_f64();
    ensure!(
        bytes == sink.bytes,
        "decrypted stream length differs from sink"
    );
    let digest = hex::encode(sink.hash.finalize());
    ensure!(
        digests.contains(&digest),
        "authenticated plaintext does not match an original BuildManifest component digest"
    );
    eprintln!(
        "{}",
        serde_json::json!({
            "kind": "native_authenticated_aea_stream_measurement",
            "input": image, "inventory": inventory,
            "inventory_sha256": sha256(&inventory_bytes), "member": member,
            "encrypted_bytes": encrypted_bytes, "plaintext_bytes": bytes,
            "seconds": seconds, "plaintext_bytes_per_second": bytes as f64 / seconds,
            "plaintext_sha384": digest, "manifest_digests": digests,
            "plaintext_matches_manifest_digest": digests.contains(&digest),
            "plaintext_retained": false, "asr_plain_source_qualified": false,
        })
    );
    Ok(())
}
