//! Atomic JSON files for manifests, receipts and ledgers.
use crate::{Result, error::Io};
use serde::Serialize;
use std::{fs::File, io::Write, path::Path};

pub(crate) fn pretty_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Write `value` as pretty JSON, replacing `path` atomically. Readers see the
/// old or the new file; durability across power loss is not promised.
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).io("create a JSON file's directory")?;
    let bytes = pretty_bytes(value)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent).io("create a temporary JSON file")?;
    tmp.write_all(&bytes).io("write a JSON file")?;
    tmp.persist(path)
        .map_err(|e| e.error)
        .io("replace a JSON file")?;
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_reader(
        File::open(path).io("open a JSON file")?,
    )?)
}
