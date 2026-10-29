//! Host-owned durable FDR storage. The loader identifies one preallocated
//! file; the engine writes only its existing FAT clusters through host drivers.
use super::bundle::Bytes;
use crate::Result;
use crate::{firmware, handoff::Region, output, paging::PAGE};
use alloc::boxed::Box;
use sha2::Digest;
use stela_contracts::refuse;
use stela_crypto::Sha256;
use stela_drivers::block::{BlockDevice, Shared};
use stela_runtime::{
    pc::{boot_log, fat32::Fat32, fdr_store, gpt::Guid},
    restore::{self, answers::FdrCommit, fdr::Diagnostic},
};

pub const STATE_FILE: &str = stela_runtime::restore::fdr::STATE_FILE;
const MAGIC: &[u8; 8] = b"STLFDRH1";
const HEADER: usize = 80;

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub struct Placement<'a> {
    pub partition: Guid,
    pub path: &'a str,
    pub diagnostic: &'a [u8],
    snapshot: Option<[u8; 32]>,
}

impl<'a> Placement<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER || &bytes[..8] != MAGIC {
            return Err(refuse!("invalid FDR storage placement"));
        }
        let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word")) as usize;
        let path_end = HEADER
            .checked_add(word(24))
            .ok_or(refuse!("FDR placement overflow"))?;
        let end = path_end
            .checked_add(word(28))
            .ok_or(refuse!("FDR placement overflow"))?;
        if end != bytes.len() || word(64) > 1 {
            return Err(refuse!("invalid FDR placement length/flags"));
        }
        let path = core::str::from_utf8(
            bytes
                .get(HEADER..path_end)
                .ok_or(refuse!("FDR path bounds"))?,
        )
        .map_err(|_| refuse!("FDR path is not UTF-8"))?;
        if !stela_formats::payload::safe_path(path) {
            return Err(refuse!("invalid FDR state file path"));
        }
        Ok(Self {
            partition: Guid(bytes[8..24].try_into().expect("GUID")),
            path,
            diagnostic: &bytes[path_end..end],
            snapshot: (word(64) == 1).then(|| bytes[32..64].try_into().expect("digest")),
        })
    }
}

/// One existing handoff slot carries placement plus selected diagnostic. No
/// extra file slot is consumed, and committed state keeps the seed identity.
pub fn prepare(partition: [u8; 16], path: &str, seed: &[u8], image: &[u8]) -> Result<Region> {
    let initial = Diagnostic::decode(seed).map_err(|error| refuse!("FDR seed: {error}", %error))?;
    let snapshot = fdr_store::read_image(image)
        .map_err(|error| refuse!("FDR stored state: {error}", %error))?;
    if let Some(snapshot) = &snapshot {
        let stored = Diagnostic::decode(snapshot)
            .map_err(|error| refuse!("FDR stored binding: {error}", %error))?;
        if !initial.same_identity(&stored) {
            return Err(refuse!("FDR stored state belongs to another machine/build"));
        }
    }
    let diagnostic = snapshot.as_deref().unwrap_or(seed);
    let bytes = HEADER + path.len() + diagnostic.len();
    let physical = firmware::pages(bytes.div_ceil(PAGE))?;
    // SAFETY: fresh loader pages, kept for the whole boot.
    let buffer = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, bytes) };
    buffer.fill(0);
    buffer[..8].copy_from_slice(MAGIC);
    buffer[8..24].copy_from_slice(&partition);
    buffer[24..28].copy_from_slice(&(path.len() as u32).to_le_bytes());
    buffer[28..32].copy_from_slice(&(diagnostic.len() as u32).to_le_bytes());
    if let Some(snapshot) = &snapshot {
        buffer[32..64].copy_from_slice(&digest(snapshot));
        buffer[64..68].copy_from_slice(&1u32.to_le_bytes());
    }
    buffer[HEADER..HEADER + path.len()].copy_from_slice(path.as_bytes());
    buffer[HEADER + path.len()..].copy_from_slice(diagnostic);
    output::arguments(format_args!(
        "FDR STORAGE loaded committed={} bytes={}; file={path}\n",
        snapshot.is_some(),
        diagnostic.len()
    ));
    Ok(Region {
        physical: physical as u64,
        bytes: bytes as u64,
    })
}

pub fn writer(partition: Box<dyn BlockDevice>, placement: &Placement<'_>) -> Result<FdrCommit> {
    let block = u64::from(partition.identity().block_size);
    let mut volume =
        Fat32::open(Bytes::new(partition)).map_err(|error| refuse!("FDR FAT: {error}", %error))?;
    let file = volume
        .file(placement.path)
        .map_err(|error| refuse!("FDR state file: {error}", %error))?;
    if file.bytes != fdr_store::FILE_BYTES as u64 {
        return Err(refuse!("FDR state file must be exactly 4 MiB"));
    }
    let runs = boot_log::file_runs(&file, block, fdr_store::FILE_BYTES as u64)
        .map_err(|error| refuse!("FDR state extents: {error}", %error))?;
    let partition = volume.into_inner().into_inner();
    let mut device = Shared::new(partition)
        .runs(runs)
        .map_err(|error| refuse!("FDR state view: {error}", %error))?;
    let mut journal = fdr_store::Journal::open(&mut device)
        .map_err(|error| refuse!("FDR journal: {error}", %error))?;
    let actual = journal.snapshot().map(digest);
    if actual != placement.snapshot {
        return Err(refuse!(
            "FDR state changed between firmware and engine reads"
        ));
    }
    Ok(Box::new(move |bytes| {
        journal.commit(&mut device, bytes).map_err(|error| {
            restore::Error::Transport(refuse!("FDR durable commit: {error}", %error))
        })?;
        output::arguments(format_args!(
            "FDR COMMIT durable bytes={} sha256={} flushed/readback verified\n",
            bytes.len(),
            stela_formats::sha256(bytes)
        ));
        Ok(())
    }))
}
