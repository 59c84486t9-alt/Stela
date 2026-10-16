use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub fn manifest(
    image: &Path,
    model: Option<&str>,
) -> Result<crate::apple::restore::RestoreManifest> {
    let mut archive = zip::ZipArchive::new(File::open(image)?)?;
    let member = archive.by_name("BuildManifest.plist")?;
    let mut bytes = vec![];
    member.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "restore manifest exceeds 64 MiB"
    );
    crate::apple::restore::inspect(&bytes, model)
}

pub fn extract(image: &Path, name: &str, output: &Path, maximum: u64) -> Result<serde_json::Value> {
    ensure!(
        crate::apple::restore::safe_member(name),
        "unsafe archive member name"
    );
    let mut receipt_name = output.as_os_str().to_owned();
    receipt_name.push(".json");
    let receipt_path = std::path::PathBuf::from(receipt_name);
    ensure!(
        !output.exists() && !receipt_path.exists(),
        "output or receipt exists"
    );
    let mut archive = zip::ZipArchive::new(File::open(image)?)?;
    let mut member = archive.by_name(name)?;
    ensure!(!member.is_dir(), "member is a directory");
    let expected = member.size();
    ensure!(expected <= maximum, "member exceeds --max-bytes");
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = member.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("member length overflow")?;
        ensure!(
            bytes <= expected && bytes <= maximum,
            "expanded member exceeds expected size"
        );
        hash.update(&buffer[..count]);
        pending.write_all(&buffer[..count])?;
    }
    ensure!(bytes == expected, "truncated member");
    pending.as_file().sync_all()?;
    let receipt = serde_json::json!({"schema_version":1,"archive":image.canonicalize()?.display().to_string(),"member":name,"bytes":bytes,"sha256":hex::encode(hash.finalize()),"zip_crc32_checked":true,
        "note":"Extraction and ZIP CRC only; see the archive download receipt for source-image verification. Manifest digests are not inferred or reinterpreted."});
    pending.persist_noclobber(output).map_err(|e| e.error)?;
    stela_core::write_json(&receipt_path, &receipt)?;
    Ok(receipt)
}
