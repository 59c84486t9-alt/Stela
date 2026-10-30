//! Read the manifest and extract members of a downloaded restore archive.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read, Seek, Write},
    path::Path,
};

const MANIFEST_LIMIT: u64 = 64 * 1024 * 1024;
/// Members up to this size are also read whole to describe their IM4P header.
const IM4P_HEADER_LIMIT: u64 = 256 * 1024 * 1024;

type Archive = zip::ZipArchive<File>;

/// A member's size and SHA-256, and its IM4P identity when it is one.
#[derive(Debug, Clone, Serialize)]
pub struct MemberDigest {
    pub bytes: u64,
    pub sha256: String,
    pub im4p_type: Option<String>,
    pub im4p_description: Option<String>,
}

fn read_limited<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
    maximum: u64,
) -> Result<Vec<u8>> {
    ensure!(
        super::manifest::safe_member(name),
        "unsafe archive member name"
    );
    let member = archive
        .by_name(name)
        .with_context(|| format!("archive has no member {name}"))?;
    ensure!(
        member.size() <= maximum,
        "member {name} exceeds {maximum} bytes"
    );
    let mut bytes = Vec::with_capacity(member.size() as usize);
    member.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "member {name} exceeds {maximum} bytes"
    );
    Ok(bytes)
}

pub fn has_member(image: &Path, name: &str) -> Result<bool> {
    Ok(zip::ZipArchive::new(File::open(image)?)?
        .index_for_name(name)
        .is_some())
}

/// Read one member whole, refusing members larger than `maximum`.
pub fn read_member(image: &Path, name: &str, maximum: u64) -> Result<Vec<u8>> {
    read_limited(
        &mut zip::ZipArchive::new(BufReader::with_capacity(1024 * 1024, File::open(image)?))?,
        name,
        maximum,
    )
}

fn hash_member(archive: &mut Archive, name: &str) -> Result<MemberDigest> {
    let size = archive.by_name(name)?.size();
    if size <= IM4P_HEADER_LIMIT {
        let bytes = read_limited(archive, name, IM4P_HEADER_LIMIT)?;
        let im4p = stela_loader::im4p::parse(&bytes).ok();
        return Ok(MemberDigest {
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
            im4p_type: im4p.as_ref().map(|i| i.payload_type.clone()),
            im4p_description: im4p.map(|i| i.description),
        });
    }
    let mut member = archive.by_name(name)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut bytes = 0u64;
    loop {
        let count = member.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        bytes += count as u64;
    }
    ensure!(bytes == size, "member {name} is truncated");
    Ok(MemberDigest {
        bytes,
        sha256: hex::encode(hash.finalize()),
        im4p_type: None,
        im4p_description: None,
    })
}

/// The manifest for `model`; with `hash_members`, every component member is
/// also read and hashed once (ZIP CRCs are checked while reading).
pub fn manifest(
    image: &Path,
    model: Option<&str>,
    hash_members: bool,
) -> Result<super::manifest::RestoreManifest> {
    let mut archive = zip::ZipArchive::new(File::open(image)?)?;
    let bytes = read_limited(&mut archive, "BuildManifest.plist", MANIFEST_LIMIT)?;
    let mut report = super::manifest::inspect(&bytes, model)?;
    if hash_members {
        let mut digests = BTreeMap::new();
        for identity in &mut report.identities {
            for component in identity.components.values_mut() {
                if !digests.contains_key(&component.path) {
                    let digest = hash_member(&mut archive, &component.path)?;
                    digests.insert(component.path.clone(), digest);
                }
                component.member = digests.get(&component.path).cloned();
            }
        }
    }
    Ok(report)
}

pub fn extract(image: &Path, name: &str, output: &Path, maximum: u64) -> Result<serde_json::Value> {
    ensure!(
        super::manifest::safe_member(name),
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
    stela_engine::write_json(&receipt_path, &receipt)?;
    Ok(receipt)
}
