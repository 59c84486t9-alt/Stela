//! Atomic JSON files for manifests, receipts and ledgers.
use anyhow::{Context, Result};
use serde::Serialize;
use std::{fs::File, io::Write, path::Path};

/// Write `value` as pretty JSON, replacing `path` atomically. Readers see the
/// old or the new file; durability across power loss is not promised.
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_reader(File::open(path)?).context("read JSON")
}
