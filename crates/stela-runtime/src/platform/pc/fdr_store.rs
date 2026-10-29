//! Durable, bounded FDR host-response storage in a preallocated file view.
//!
//! Two independent slots keep the previous commit while the next payload,
//! then its header, are flushed. Checksums detect damage; they authenticate
//! neither the records nor their author. The caller supplies an exclusive
//! block-device view of exactly [`FILE_BYTES`], never a whole filesystem.
use alloc::{vec, vec::Vec};
use core::fmt;
use sha2::Digest;
use stela_crypto::Sha256;
use stela_drivers::block::{BlockDevice, BlockError};

pub const FILE_BYTES: usize = 4 << 20;
pub const MAX_PAYLOAD: usize = 1 << 20;
const SLOT_BYTES: usize = FILE_BYTES / 2;
const HEADER_BYTES: usize = 4096;
const MAGIC: &[u8; 8] = b"STELAFDR";
const VERSION: u32 = 1;
const HEADER_DIGEST: usize = 64;
const HEADER_RECORD: usize = HEADER_DIGEST + 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    ImageSize {
        bytes: usize,
    },
    BlockSize(u32),
    DeviceSize {
        blocks: u64,
        block_size: u32,
    },
    PayloadSize {
        bytes: usize,
    },
    /// Nonblank storage without a valid slot, or ambiguous generations.
    Corrupt,
    SequenceExhausted,
    /// A preceding failed commit may have reached storage. Reopen first.
    NeedsReopen,
    /// The reopened device does not hold the state this journal loaded.
    Changed,
    Readback,
    Device(BlockError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageSize { bytes } => {
                write!(f, "FDR journal has {bytes} bytes; needs {FILE_BYTES}")
            }
            Self::BlockSize(size) => write!(f, "FDR journal does not support {size}-byte sectors"),
            Self::DeviceSize { blocks, block_size } => write!(
                f,
                "FDR journal device has {blocks} sectors of {block_size} bytes; needs {FILE_BYTES} bytes"
            ),
            Self::PayloadSize { bytes } => {
                write!(f, "FDR payload has {bytes} bytes; needs 1..={MAX_PAYLOAD}")
            }
            Self::Corrupt => f.write_str("FDR journal is damaged or has ambiguous generations"),
            Self::SequenceExhausted => f.write_str("FDR journal sequence is exhausted"),
            Self::NeedsReopen => f.write_str("FDR journal must be reopened after a failed commit"),
            Self::Changed => f.write_str("FDR journal changed since it was opened"),
            Self::Readback => f.write_str("FDR journal readback does not match the commit"),
            Self::Device(error) => write!(f, "FDR journal device: {error}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<BlockError> for Error {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Record {
    slot: usize,
    sequence: u64,
    payload: Vec<u8>,
}

/// One exclusive journal session. A failed write/flush/readback requires
/// reopening: its header may have committed even though no acknowledgement
/// was returned. `snapshot` keeps the last successfully acknowledged state.
#[derive(Debug)]
pub struct Journal {
    record: Option<Record>,
    needs_reopen: bool,
}

impl Journal {
    pub fn open(device: &mut dyn BlockDevice) -> Result<Self, Error> {
        Ok(Self {
            record: read_device(device)?,
            needs_reopen: false,
        })
    }

    pub fn snapshot(&self) -> Option<&[u8]> {
        self.record.as_ref().map(|record| record.payload.as_slice())
    }

    /// Return success only after both flushes and independent readback.
    pub fn commit(&mut self, device: &mut dyn BlockDevice, bytes: &[u8]) -> Result<(), Error> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
            return Err(Error::PayloadSize { bytes: bytes.len() });
        }
        let block = geometry(device)?;
        if device.identity().read_only {
            return Err(BlockError::ReadOnly.into());
        }
        let sequence = self
            .record
            .as_ref()
            .map_or(Some(1), |record| record.sequence.checked_add(1))
            .ok_or(Error::SequenceExhausted)?;
        // Refuse stale sessions and unexpected backing data before mutation.
        if read_device(device)? != self.record {
            return Err(Error::Changed);
        }
        let slot = self.record.as_ref().map_or(0, |record| 1 - record.slot);
        let offset = slot * SLOT_BYTES;
        let mut payload = vec![0; bytes.len().div_ceil(block) * block];
        payload[..bytes.len()].copy_from_slice(bytes);
        let header = encode_header(sequence, bytes);
        // Even an error from the first write can have changed the medium.
        self.needs_reopen = true;
        device.write(((offset + HEADER_BYTES) / block) as u64, &payload)?;
        device.flush()?;
        device.write((offset / block) as u64, &header)?;
        device.flush()?;
        let mut readback = vec![0; SLOT_BYTES];
        device.read((offset / block) as u64, &mut readback)?;
        let record = decode_slot(slot, &readback).ok_or(Error::Readback)?;
        if record.sequence != sequence || record.payload != bytes {
            return Err(Error::Readback);
        }
        self.record = Some(record);
        self.needs_reopen = false;
        Ok(())
    }
}

/// Read the same format from firmware file bytes before ExitBootServices.
/// An entirely zero file is uninitialized. Damage never becomes empty state.
pub fn read_image(bytes: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    Ok(select(bytes)?.map(|record| record.payload))
}

/// Build a first committed image for atomic publication by a host file tool.
/// Seeding before boot leaves a valid old slot during the first guest commit.
pub fn initial_image(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::PayloadSize {
            bytes: payload.len(),
        });
    }
    let mut image = vec![0; FILE_BYTES];
    image[..HEADER_BYTES].copy_from_slice(&encode_header(1, payload));
    image[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
    Ok(image)
}

fn geometry(device: &dyn BlockDevice) -> Result<usize, Error> {
    let identity = device.identity();
    if !matches!(identity.block_size, 512 | 4096) {
        return Err(Error::BlockSize(identity.block_size));
    }
    let block = identity.block_size as usize;
    if identity.blocks != (FILE_BYTES / block) as u64 {
        return Err(Error::DeviceSize {
            blocks: identity.blocks,
            block_size: identity.block_size,
        });
    }
    Ok(block)
}

fn read_device(device: &mut dyn BlockDevice) -> Result<Option<Record>, Error> {
    geometry(device)?;
    let mut image = vec![0; FILE_BYTES];
    device.read(0, &mut image)?;
    select(&image)
}

fn select(bytes: &[u8]) -> Result<Option<Record>, Error> {
    if bytes.len() != FILE_BYTES {
        return Err(Error::ImageSize { bytes: bytes.len() });
    }
    match (
        decode_slot(0, &bytes[..SLOT_BYTES]),
        decode_slot(1, &bytes[SLOT_BYTES..]),
    ) {
        (Some(a), Some(b)) if a.sequence == b.sequence => Err(Error::Corrupt),
        (Some(a), Some(b)) => Ok(Some(if a.sequence > b.sequence { a } else { b })),
        (Some(record), None) | (None, Some(record)) => Ok(Some(record)),
        (None, None) if bytes.iter().all(|&byte| byte == 0) => Ok(None),
        (None, None) => Err(Error::Corrupt),
    }
}

// Header, little endian: magic[8], version:u32, header_bytes:u32,
// sequence:u64, payload_bytes:u64, SHA256(payload)[32], SHA256(header)[32].
// The header digest field is zeroed for hashing; remaining bytes are zero.
fn encode_header(sequence: u64, payload: &[u8]) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    header[16..24].copy_from_slice(&sequence.to_le_bytes());
    header[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    header[32..64].copy_from_slice(&Sha256::digest(payload));
    let digest = header_hash(&header);
    header[HEADER_DIGEST..HEADER_RECORD].copy_from_slice(&digest);
    header
}

fn header_hash(header: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(&header[..HEADER_DIGEST]);
    hash.update([0; 32]);
    hash.update(&header[HEADER_RECORD..]);
    hash.finalize().into()
}

fn decode_slot(slot: usize, bytes: &[u8]) -> Option<Record> {
    let header = &bytes[..HEADER_BYTES];
    if &header[..8] != MAGIC
        || header[8..12] != VERSION.to_le_bytes()
        || header[12..16] != (HEADER_BYTES as u32).to_le_bytes()
        || header[HEADER_RECORD..].iter().any(|&byte| byte != 0)
        || header_hash(header) != header[HEADER_DIGEST..HEADER_RECORD]
    {
        return None;
    }
    let sequence = u64::from_le_bytes(header[16..24].try_into().ok()?);
    let length = u64::from_le_bytes(header[24..32].try_into().ok()?);
    if sequence == 0 || length == 0 || length > MAX_PAYLOAD as u64 {
        return None;
    }
    let payload = &bytes[HEADER_BYTES..HEADER_BYTES + length as usize];
    if Sha256::digest(payload)[..] != header[32..64] {
        return None;
    }
    Some(Record {
        slot,
        sequence,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests;
