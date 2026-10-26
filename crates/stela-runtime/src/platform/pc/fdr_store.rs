//! Durable, bounded FDR host-response storage in a preallocated file view.
//!
//! Two independent slots retain the previous commit while the next payload,
//! then its header, are flushed. Checksums detect damage; they authenticate
//! neither the records nor their author. The caller supplies an exclusive
//! block-device view of exactly [`FILE_BYTES`], never a whole filesystem.
use alloc::{vec, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};
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
mod tests {
    use super::*;
    use stela_drivers::block::{Identity, RamDisk};

    fn disk(block: u32) -> RamDisk {
        RamDisk::new("FDR", FILE_BYTES as u64 / u64::from(block), block)
    }

    #[test]
    fn alternates_and_reopens_with_both_sector_sizes_and_payload_bounds() {
        let initial = initial_image(b"seed").unwrap();
        assert_eq!(read_image(&initial).unwrap(), Some(b"seed".to_vec()));
        assert!(initial_image(&[]).is_err());
        assert!(initial_image(&vec![0; MAX_PAYLOAD + 1]).is_err());
        for block in [512, 4096] {
            let mut device = disk(block);
            let mut journal = Journal::open(&mut device).unwrap();
            assert_eq!(journal.snapshot(), None);
            assert_eq!(read_image(&device.bytes).unwrap(), None);
            for payload in [vec![1], vec![2; MAX_PAYLOAD], vec![3; 513]] {
                journal.commit(&mut device, &payload).unwrap();
                assert_eq!(journal.snapshot(), Some(payload.as_slice()));
                assert_eq!(
                    Journal::open(&mut device).unwrap().snapshot(),
                    Some(payload.as_slice())
                );
                assert_eq!(read_image(&device.bytes).unwrap(), Some(payload));
            }
            assert_eq!(device.flushes, 6);
        }
    }

    #[test]
    fn corruption_recovers_a_valid_older_slot_but_never_becomes_empty() {
        let mut device = disk(512);
        let mut journal = Journal::open(&mut device).unwrap();
        journal.commit(&mut device, b"older").unwrap();
        journal.commit(&mut device, b"newer").unwrap();
        let valid = device.bytes.clone();
        // Every header field, reserved area, checksum and payload is covered.
        for byte in [0, 8, 12, 16, 24, 32, 64, 96, HEADER_BYTES - 1, HEADER_BYTES] {
            let mut damaged = valid.clone();
            damaged[SLOT_BYTES + byte] ^= 1;
            assert_eq!(read_image(&damaged).unwrap(), Some(b"older".to_vec()));
            damaged[byte] ^= 1;
            assert_eq!(read_image(&damaged), Err(Error::Corrupt));
        }
        let mut nonblank = vec![0; FILE_BYTES];
        nonblank[FILE_BYTES - 1] = 1;
        assert_eq!(read_image(&nonblank), Err(Error::Corrupt));
        // A valid checksum cannot legalize an empty/oversized/zero-sequence record.
        for (sequence, length) in [(0_u64, 5), (1, 0), (1, MAX_PAYLOAD as u64 + 1)] {
            let mut damaged = valid.clone();
            damaged[SLOT_BYTES..].fill(0);
            damaged[16..24].copy_from_slice(&sequence.to_le_bytes());
            damaged[24..32].copy_from_slice(&length.to_le_bytes());
            let digest = header_hash(&damaged[..HEADER_BYTES]);
            damaged[HEADER_DIGEST..HEADER_RECORD].copy_from_slice(&digest);
            assert_eq!(read_image(&damaged), Err(Error::Corrupt));
        }
        let mut ambiguous = valid;
        let first = ambiguous[..SLOT_BYTES].to_vec();
        ambiguous[SLOT_BYTES..].copy_from_slice(&first);
        assert_eq!(read_image(&ambiguous), Err(Error::Corrupt));
    }

    #[test]
    fn refuses_geometry_readonly_oversize_and_stale_sessions_without_writes() {
        let mut device = disk(512);
        let mut journal = Journal::open(&mut device).unwrap();
        for payload in [vec![], vec![0; MAX_PAYLOAD + 1]] {
            assert_eq!(
                journal.commit(&mut device, &payload),
                Err(Error::PayloadSize {
                    bytes: payload.len()
                })
            );
        }
        device.identity.read_only = true;
        assert!(Journal::open(&mut device).is_ok());
        assert_eq!(
            journal.commit(&mut device, b"x"),
            Err(Error::Device(BlockError::ReadOnly))
        );
        device.identity.read_only = false;
        let mut other = Journal::open(&mut device).unwrap();
        other.commit(&mut device, b"other session").unwrap();
        let before = device.bytes.clone();
        assert_eq!(journal.commit(&mut device, b"stale"), Err(Error::Changed));
        assert_eq!(device.bytes, before);
        device.identity.blocks -= 1;
        assert!(matches!(
            Journal::open(&mut device),
            Err(Error::DeviceSize { .. })
        ));
        device.identity.blocks += 2;
        assert!(matches!(
            Journal::open(&mut device),
            Err(Error::DeviceSize { .. })
        ));
        for block in [0, 256, 1000, 8192] {
            device.identity.block_size = block;
            assert!(
                matches!(Journal::open(&mut device), Err(Error::BlockSize(size)) if size == block)
            );
        }
        assert_eq!(read_image(&[0; 512]), Err(Error::ImageSize { bytes: 512 }));
    }

    #[test]
    fn sequence_overflow_refuses_without_touching_the_medium() {
        let mut device = disk(512);
        device.bytes[..HEADER_BYTES].copy_from_slice(&encode_header(u64::MAX, b"last"));
        device.bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(b"last");
        let before = device.bytes.clone();
        let mut journal = Journal::open(&mut device).unwrap();
        assert_eq!(
            journal.commit(&mut device, b"next"),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(device.bytes, before);
        assert_eq!(device.flushes, 0);
    }

    #[derive(Clone, Copy)]
    enum Fault {
        Before(usize),
        After(usize),
        /// A torn write has partly reached stable storage when power fails.
        Torn {
            phase: usize,
            bytes: usize,
        },
        Readback,
        BadReadback,
    }

    struct PowerDisk {
        cache: RamDisk,
        durable: Vec<u8>,
        fault: Option<Fault>,
        phase: usize,
        reads: usize,
        events: Vec<&'static str>,
    }

    impl PowerDisk {
        fn seeded(block: u32) -> Self {
            let mut cache = disk(block);
            let mut journal = Journal::open(&mut cache).unwrap();
            journal.commit(&mut cache, b"first").unwrap();
            journal.commit(&mut cache, b"previous").unwrap();
            Self {
                durable: cache.bytes.clone(),
                cache,
                fault: None,
                phase: 0,
                reads: 0,
                events: Vec::new(),
            }
        }

        fn arm(&mut self, fault: Fault) {
            self.fault = Some(fault);
            self.phase = 0;
            self.reads = 0;
            self.events.clear();
        }

        fn lost_power(&mut self) {
            self.cache.bytes.copy_from_slice(&self.durable);
            self.fault = None;
        }

        fn failure() -> BlockError {
            BlockError::Device { status: 0xfdfd }
        }
    }

    impl BlockDevice for PowerDisk {
        fn identity(&self) -> &Identity {
            self.cache.identity()
        }

        fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), BlockError> {
            self.events.push("read");
            self.reads += 1;
            if self.reads == 2 && matches!(self.fault, Some(Fault::Readback)) {
                return Err(Self::failure());
            }
            self.cache.read(lba, bytes)?;
            if self.reads == 2 && matches!(self.fault, Some(Fault::BadReadback)) {
                bytes[HEADER_BYTES] ^= 1;
            }
            Ok(())
        }

        fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), BlockError> {
            self.events.push("write");
            let phase = self.phase;
            self.phase += 1;
            if matches!(self.fault, Some(Fault::Before(n)) if n == phase) {
                return Err(Self::failure());
            }
            if let Some(Fault::Torn {
                phase: n,
                bytes: count,
            }) = self.fault
                && n == phase
            {
                let offset = lba as usize * self.identity().block_size as usize;
                let count = count.min(bytes.len());
                self.durable[offset..offset + count].copy_from_slice(&bytes[..count]);
                return Err(Self::failure());
            }
            self.cache.write(lba, bytes)?;
            if matches!(self.fault, Some(Fault::After(n)) if n == phase) {
                return Err(Self::failure());
            }
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.events.push("flush");
            let phase = self.phase;
            self.phase += 1;
            if matches!(self.fault, Some(Fault::Before(n)) if n == phase) {
                return Err(Self::failure());
            }
            self.durable.copy_from_slice(&self.cache.bytes);
            if matches!(self.fault, Some(Fault::After(n)) if n == phase) {
                return Err(Self::failure());
            }
            Ok(())
        }
    }

    #[test]
    fn loss_before_and_after_every_write_and_flush_keeps_a_complete_generation() {
        for block in [512, 4096] {
            for phase in 0..4 {
                for fault in [Fault::Before(phase), Fault::After(phase)] {
                    let mut device = PowerDisk::seeded(block);
                    let mut journal = Journal::open(&mut device).unwrap();
                    device.arm(fault);
                    assert!(journal.commit(&mut device, b"new commit").is_err());
                    assert_eq!(journal.snapshot(), Some(b"previous".as_slice()));
                    assert_eq!(
                        journal.commit(&mut device, b"retry"),
                        Err(Error::NeedsReopen)
                    );
                    device.lost_power();
                    let expected: &[u8] = if matches!(fault, Fault::After(3)) {
                        b"new commit"
                    } else {
                        b"previous"
                    };
                    assert_eq!(
                        Journal::open(&mut device).unwrap().snapshot(),
                        Some(expected)
                    );
                    assert_eq!(
                        read_image(&device.durable).unwrap(),
                        Some(expected.to_vec())
                    );
                }
            }
        }
    }

    #[test]
    fn torn_payload_or_header_never_displaces_the_previous_valid_generation() {
        for block in [512, 4096] {
            for phase in [0, 2] {
                for count in [0, 1, 24, 64, 80, 96, 512, 2048, 4095] {
                    let mut device = PowerDisk::seeded(block);
                    let mut journal = Journal::open(&mut device).unwrap();
                    device.arm(Fault::Torn {
                        phase,
                        bytes: count,
                    });
                    let payload = vec![b'n'; 8193];
                    assert!(journal.commit(&mut device, &payload).is_err());
                    device.lost_power();
                    let actual = read_image(&device.durable).unwrap().unwrap();
                    // A header whose entire nonzero/checksummed record reached
                    // storage can already be valid, despite the write error.
                    assert!(actual == b"previous" || actual == payload);
                    if phase == 0 || count < HEADER_RECORD {
                        assert_eq!(actual, b"previous");
                    }
                }
            }
        }
    }

    #[test]
    fn readback_failure_never_acknowledges_a_durable_commit_and_retry_reopens() {
        for fault in [Fault::Readback, Fault::BadReadback] {
            let mut device = PowerDisk::seeded(4096);
            let mut journal = Journal::open(&mut device).unwrap();
            device.arm(fault);
            assert!(
                journal
                    .commit(&mut device, b"durable but unacknowledged")
                    .is_err()
            );
            assert_eq!(
                device.events,
                ["read", "write", "flush", "write", "flush", "read"]
            );
            assert_eq!(journal.snapshot(), Some(b"previous".as_slice()));
            assert_eq!(
                journal.commit(&mut device, b"retry"),
                Err(Error::NeedsReopen)
            );
            device.lost_power();
            assert_eq!(
                Journal::open(&mut device).unwrap().snapshot(),
                Some(b"durable but unacknowledged".as_slice())
            );
        }
    }

    #[test]
    fn interruption_of_the_first_commit_does_not_relabel_nonblank_bytes_as_empty() {
        let mut device = PowerDisk::seeded(512);
        device.cache.bytes.fill(0);
        device.durable.fill(0);
        let mut journal = Journal::open(&mut device).unwrap();
        device.arm(Fault::After(1));
        assert!(journal.commit(&mut device, b"first interrupted").is_err());
        device.lost_power();
        assert_eq!(read_image(&device.durable), Err(Error::Corrupt));
        assert!(matches!(Journal::open(&mut device), Err(Error::Corrupt)));
    }

    #[test]
    fn the_engine_finds_the_state_file_by_its_short_name_and_reads_its_runs() {
        use crate::{
            payload::ReadAt,
            platform::pc::{
                boot_log,
                fat32::{Fat32, tests::Volume},
            },
        };
        let image = initial_image(b"seed").unwrap();
        let mut volume = Volume::new();
        let efi = volume.directory(2, 0, b"EFI        ");
        let stela = volume.directory(efi, 0, b"STELA      ");
        let install = volume.directory(stela, 0, b"INSTALL    ");
        let build = volume.directory(install, 0, b"26A434     ");
        // Fragmented, as a volume may place it: the second half comes first.
        let clusters = volume.allocate(FILE_BYTES as u64);
        let (first, second) = clusters.split_at(clusters.len() / 2);
        let order: Vec<u32> = second.iter().chain(first).copied().collect();
        volume.file_in(build, 0, b"FDRSTATEBIN", &image, &order);
        // The path the loader hands the engine, as `engine::fdr::writer` opens it.
        let path = format!(
            "EFI/stela/install/26A434/{}",
            crate::restore::fdr::STATE_FILE
        );
        let mut fat = Fat32::open(volume.disk).unwrap();
        let file = fat.file(&path).unwrap();
        assert_eq!(file.bytes, FILE_BYTES as u64);
        let runs = boot_log::file_runs(&file, 512, FILE_BYTES as u64).unwrap();
        assert_eq!(runs.len(), 2);
        let mut disk = fat.into_inner();
        let mut bytes = Vec::new();
        for (block, count) in runs {
            let mut run = vec![0; count as usize * 512];
            disk.read_at(block * 512, &mut run).unwrap();
            bytes.extend(run);
        }
        assert_eq!(read_image(&bytes).unwrap(), Some(b"seed".to_vec()));
    }
}
