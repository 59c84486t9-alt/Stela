//! The persistent boot log: `stela.efi`'s output kept on the machine-state
//! partition, so a bare-metal run leaves a log to read after the machine
//! reboots.
//!
//! The region starts at [`OFFSET`] of the partition, after the NOR image and
//! the SEP's state, and is [`LOG_BYTES`] long; a partition of at least
//! [`PARTITION_BYTES`] holds it. Its first [`HEADER_BYTES`] are the header:
//!
//! | Offset | Bytes | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `STELALOG` |
//! | 8 | 4 | version, 1 |
//! | 12 | 4 | reserved, zero |
//! | 16 | 8 | `head`: every byte ever appended, monotonic |
//! | 24 | 8 | `boots`: boots that opened the log |
//! | 32 | 8 | `ring_bytes`: the region less the header |
//! | 40 | 32 | SHA-256 of bytes 0..40 |
//!
//! The ring follows the header. Stream byte `i` lives at
//! `ring[i % ring_bytes]`, so the valid stream is
//! `[head.saturating_sub(ring_bytes), head)`. A blank or invalid header is a
//! fresh log, reported by its [`HeaderError`]; [`read`] refuses it.
//!
//! [`Writer`] opens the log once per boot, counts the boot and appends a
//! `=== STELA BOOT n ===` line. Appends wait in a bounded [`Pending`]
//! buffer; a flush writes the changed ring blocks, makes them durable, then
//! writes the header and makes it durable, so the header never counts bytes
//! the ring does not hold. Once the ring has wrapped, an interrupted flush can
//! leave the bytes it wrote in place of the oldest ones the old header still
//! counts, at most the bytes of that one flush.
//!
//! A file preallocated on a FAT32 volume can hold a log too: a machine-state
//! file (`--nor-file`) laid out as the partition is, or the USB's own log
//! (`stela_loader::mount_interface::BOOT_LOG_FILE`), [`LOG_BYTES`] of the
//! region alone. Writes reach its blocks directly, never the volume's
//! directory or FAT: [`file_runs`] gives the block-aligned runs of its
//! clusters, wherever they lie, that hold the bytes its layout needs.
use super::fat32;
use alloc::{collections::VecDeque, format, vec, vec::Vec};
use core::{
    convert::Infallible,
    fmt::{self, Write as _},
};
use sha2::Digest;
use stela_crypto::Sha256;
use stela_drivers::block::{BlockDevice, BlockError, Finished, Request};
use {crate::machine::apple::sep_state, stela_soc_data::nor::CAPACITY};

/// Where the region starts in the machine-state partition.
pub const OFFSET: u64 = CAPACITY as u64 + sep_state::BYTES;
/// The region: the header and the ring.
pub const LOG_BYTES: u64 = 4 << 20;
/// The smallest machine-state partition that holds the log.
pub const PARTITION_BYTES: u64 = OFFSET + LOG_BYTES;
pub const HEADER_BYTES: u64 = 4096;
/// The ring of a [`LOG_BYTES`] region.
pub const RING_BYTES: u64 = LOG_BYTES - HEADER_BYTES;
/// The bound of a pending buffer between flushes.
pub const PENDING_BYTES: usize = 1 << 20;
pub const MAGIC: &[u8; 8] = b"STELALOG";
pub const VERSION: u32 = 1;
/// The header fields the checksum covers.
const FIELDS: usize = 40;
const RECORD: usize = FIELDS + 32;

/// Why a region holds no log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// All zeros: no boot has written a log here.
    Blank,
    /// The region does not start with `STELALOG`.
    NotALog,
    Version(u32),
    /// Reserved header bytes are not zero.
    Reserved,
    Checksum,
    /// The header's ring is not the one this region holds.
    RingSize {
        recorded: u64,
        region: u64,
    },
    /// The region is too short for the header and a ring.
    Short {
        bytes: u64,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blank => f.write_str("the log region is blank"),
            Self::NotALog => f.write_str("the log region holds no STELALOG header"),
            Self::Version(version) => {
                write!(f, "the log header is version {version}, not {VERSION}")
            }
            Self::Reserved => f.write_str("the log header's reserved bytes are not zero"),
            Self::Checksum => f.write_str("the log header's checksum does not match"),
            Self::RingSize { recorded, region } => write!(
                f,
                "the log header records a {recorded:#x}-byte ring; the region holds {region:#x}"
            ),
            Self::Short { bytes } => write!(
                f,
                "the log region holds {bytes:#x} bytes, no more than its {HEADER_BYTES:#x}-byte header"
            ),
        }
    }
}

impl core::error::Error for HeaderError {}

/// Why a file cannot stand in for the machine-state partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileError {
    /// A run of its clusters starts or ends off a block boundary.
    Misaligned { offset: u64, block: u64 },
    /// It holds fewer than the `needed` bytes in whole blocks.
    Short { bytes: u64, needed: u64 },
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misaligned { offset, block } => write!(
                f,
                "the file has bytes from {offset:#x}, not on a {block}-byte block boundary"
            ),
            Self::Short { bytes, needed } => write!(
                f,
                "the file holds {bytes:#x} bytes in whole blocks; it needs {needed:#x}"
            ),
        }
    }
}

/// Why the device does not hold what a flush stored ([`Writer::verify`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unkept {
    Read(BlockError),
    Header(HeaderError),
    /// The stored header counts other bytes than the flush wrote.
    Head {
        stored: u64,
        written: u64,
    },
}

impl fmt::Display for Unkept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "the header cannot be read back: {error}"),
            Self::Header(error) => {
                write!(f, "the header read back is not the one written: {error}")
            }
            Self::Head { stored, written } => write!(
                f,
                "the header read back counts {stored:#x} bytes; {written:#x} were written"
            ),
        }
    }
}

impl core::error::Error for Unkept {}

/// The runs of `file`'s blocks that hold its first `needed` bytes, each a
/// first block and a count, in order: `file` is on a partition of
/// `block`-byte blocks and holds [`PARTITION_BYTES`] for a machine-state
/// file, [`LOG_BYTES`] for a log file.
pub fn file_runs(
    file: &fat32::File,
    block: u64,
    needed: u64,
) -> Result<Vec<(u64, u64)>, FileError> {
    let (mut runs, mut bytes) = (Vec::<(u64, u64)>::new(), 0);
    // Where the last run ended inside a block, which no next run can follow.
    let mut partial = None;
    for extent in &file.extents {
        if bytes >= needed {
            break;
        }
        if let Some(offset) =
            partial.or((!extent.offset.is_multiple_of(block)).then_some(extent.offset))
        {
            return Err(FileError::Misaligned { offset, block });
        }
        let count = (extent.bytes / block).min((needed - bytes).div_ceil(block));
        if !extent.bytes.is_multiple_of(block) {
            partial = Some(extent.offset + extent.bytes);
        }
        let first = extent.offset / block;
        match runs.last_mut() {
            Some((start, blocks)) if *start + *blocks == first => *blocks += count,
            _ => runs.push((first, count)),
        }
        bytes += count * block;
    }
    if bytes < needed {
        return Err(FileError::Short { bytes, needed });
    }
    Ok(runs)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    head: u64,
    boots: u64,
    ring_bytes: u64,
}

impl Header {
    /// `block` with the header at its start and zeros after it.
    fn encode(&self, block: &mut [u8]) {
        block.fill(0);
        block[..8].copy_from_slice(MAGIC);
        block[8..12].copy_from_slice(&VERSION.to_le_bytes());
        block[16..24].copy_from_slice(&self.head.to_le_bytes());
        block[24..32].copy_from_slice(&self.boots.to_le_bytes());
        block[32..40].copy_from_slice(&self.ring_bytes.to_le_bytes());
        let digest = Sha256::digest(&block[..FIELDS]);
        block[FIELDS..RECORD].copy_from_slice(&digest);
    }

    /// The header at the start of `bytes`, for a region whose ring holds
    /// `ring_bytes`.
    fn decode(bytes: &[u8], ring_bytes: u64) -> Result<Self, HeaderError> {
        if bytes.iter().all(|&byte| byte == 0) {
            return Err(HeaderError::Blank);
        }
        if bytes.len() < RECORD || &bytes[..8] != MAGIC {
            return Err(HeaderError::NotALog);
        }
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != VERSION {
            return Err(HeaderError::Version(version));
        }
        if Sha256::digest(&bytes[..FIELDS])[..] != bytes[FIELDS..RECORD] {
            return Err(HeaderError::Checksum);
        }
        if bytes[12..16] != [0; 4] {
            return Err(HeaderError::Reserved);
        }
        let header = Self {
            head: u64_at(16),
            boots: u64_at(24),
            ring_bytes: u64_at(32),
        };
        if header.ring_bytes != ring_bytes {
            return Err(HeaderError::RingSize {
                recorded: header.ring_bytes,
                region: ring_bytes,
            });
        }
        Ok(header)
    }
}

/// The line that stands for bytes an overflow dropped.
struct DroppedLine {
    bytes: [u8; 64],
    len: usize,
}

impl DroppedLine {
    fn new(dropped: u64) -> Self {
        let mut line = Self {
            bytes: [0; 64],
            len: 0,
        };
        let _ = writeln!(line, "[boot log dropped {dropped} bytes]");
        line
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Write for DroppedLine {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Bytes waiting for a flush, at most the storage's length. An overflow
/// drops the oldest and counts them; [`Pending::drain`] puts a
/// `[boot log dropped N bytes]` line in their place. Several logs can read
/// the same bytes instead, each from its own position
/// ([`Pending::copy_since`]).
pub struct Pending<S> {
    storage: S,
    start: usize,
    len: usize,
    dropped: u64,
    /// Every byte pushed, held or not.
    pushed: u64,
}

impl<S> Pending<S> {
    pub const fn new(storage: S) -> Self {
        Self {
            storage,
            start: 0,
            len: 0,
            dropped: 0,
            pushed: 0,
        }
    }
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Pending<S> {
    pub fn push(&mut self, mut bytes: &[u8]) {
        self.pushed += bytes.len() as u64;
        let capacity = self.storage.as_ref().len();
        if capacity == 0 {
            self.dropped += bytes.len() as u64;
            return;
        }
        if bytes.len() >= capacity {
            self.dropped += (self.len + bytes.len() - capacity) as u64;
            self.start = 0;
            self.len = 0;
            bytes = &bytes[bytes.len() - capacity..];
        } else if self.len + bytes.len() > capacity {
            let excess = self.len + bytes.len() - capacity;
            self.start = (self.start + excess) % capacity;
            self.len -= excess;
            self.dropped += excess as u64;
        }
        let at = (self.start + self.len) % capacity;
        let first = bytes.len().min(capacity - at);
        let storage = self.storage.as_mut();
        storage[at..at + first].copy_from_slice(&bytes[..first]);
        storage[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.len += bytes.len();
    }

    /// Nothing waits, and nothing was dropped.
    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.dropped == 0
    }

    /// The bytes [`Pending::drain`] would hand over.
    pub fn bytes(&self) -> usize {
        self.len
            + if self.dropped == 0 {
                0
            } else {
                DroppedLine::new(self.dropped).len
            }
    }

    /// The position after every byte pushed so far.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    /// Hand `sink` the bytes pushed since position `from` (an earlier
    /// [`Pending::pushed`]) and keep them, after a dropped-bytes line for
    /// those no longer held; the position reached.
    pub fn copy_since<E>(
        &self,
        from: u64,
        mut sink: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<u64, E> {
        let oldest = self.pushed - self.len as u64;
        if from < oldest {
            sink(DroppedLine::new(oldest - from).as_bytes())?;
        }
        let skip = from.saturating_sub(oldest).min(self.len as u64) as usize;
        let storage = self.storage.as_ref();
        let start = (self.start + skip) % storage.len().max(1);
        let len = self.len - skip;
        let first = len.min(storage.len() - start);
        if first != 0 {
            sink(&storage[start..start + first])?;
        }
        if len > first {
            sink(&storage[..len - first])?;
        }
        Ok(self.pushed)
    }

    /// Hand every pending byte to `sink` in order, after the dropped-bytes
    /// line when an overflow dropped any, and empty the buffer.
    pub fn drain<E>(&mut self, mut sink: impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        let (dropped, start, len) = (self.dropped, self.start, self.len);
        (self.dropped, self.start, self.len) = (0, 0, 0);
        if dropped != 0 {
            sink(DroppedLine::new(dropped).as_bytes())?;
        }
        let storage = self.storage.as_ref();
        let first = len.min(storage.len() - start);
        if first != 0 {
            sink(&storage[start..start + first])?;
        }
        if len > first {
            sink(&storage[..len - first])?;
        }
        Ok(())
    }
}

/// The ring on the device and its block at the head, kept in memory.
struct Ring {
    block: usize,
    ring_bytes: u64,
    head: u64,
    /// The ring block holding stream position `head`: its bytes before
    /// `head % block` are the stream's newest, those after are the oldest
    /// once the ring has wrapped.
    tail: Vec<u8>,
    /// `tail` holds bytes the device does not.
    dirty: bool,
    /// The ring has wrapped and `tail`'s block still holds oldest stream
    /// bytes past the head that `tail` lacks: read before it is written.
    unread: bool,
}

impl Ring {
    /// The device block of the ring block holding stream position `at`.
    fn lba(&self, at: u64) -> u64 {
        HEADER_BYTES / self.block as u64 + (at % self.ring_bytes) / self.block as u64
    }

    /// Copy `bytes` to the ring at the head; each block they fill joins
    /// `writes`, consecutive blocks one write. `remaining` counts this
    /// store's bytes still to come: a block they will overwrite whole is
    /// not read first.
    fn stage(&mut self, mut bytes: &[u8], remaining: &mut usize, writes: &mut Vec<(u64, Vec<u8>)>) {
        while !bytes.is_empty() {
            let offset = (self.head % self.block as u64) as usize;
            let count = (self.block - offset).min(bytes.len());
            self.tail[offset..offset + count].copy_from_slice(&bytes[..count]);
            self.head += count as u64;
            self.dirty = true;
            bytes = &bytes[count..];
            *remaining -= count;
            if self.head.is_multiple_of(self.block as u64) {
                join(writes, self.lba(self.head - 1), &self.tail, self.block);
                self.dirty = false;
                // The next block holds the oldest stream bytes once the ring
                // has wrapped; keep those this store does not overwrite.
                self.unread = self.head >= self.ring_bytes && *remaining < self.block;
                self.tail.fill(0);
            }
        }
    }
}

/// Add block `lba`'s `bytes` to `writes`, joining the last write when it
/// ends just before.
fn join(writes: &mut Vec<(u64, Vec<u8>)>, lba: u64, bytes: &[u8], block: usize) {
    match writes.last_mut() {
        Some((first, data)) if *first + (data.len() / block) as u64 == lba => {
            data.extend_from_slice(bytes);
        }
        _ => writes.push((lba, bytes.to_vec())),
    }
}

/// A step of a store ([`Writer::begin_store`]), each a request the last
/// one's completion lets go: the ring's bytes, then the header.
enum Step {
    /// Ring blocks from this one; `tail` when the last is the head's.
    Blocks {
        lba: u64,
        data: Vec<u8>,
        tail: bool,
    },
    /// The head's block, for the oldest bytes `tail` lacks.
    ReadTail,
    /// The head's block.
    Tail,
    Header,
}

/// The log of one boot: appends wait in memory until a flush stores them.
pub struct Writer {
    ring: Ring,
    boots: u64,
    /// The head the header on the device records.
    durable: Option<u64>,
    fresh: Option<HeaderError>,
    pending: Pending<Vec<u8>>,
    /// The store in progress: its steps to come and the one running.
    steps: VecDeque<Step>,
    running: Option<Step>,
}

impl Writer {
    /// Open the log `device` holds whole (a [`LOG_BYTES`] window of the
    /// machine-state partition), count this boot and append its marker
    /// line. A blank or invalid header starts a fresh log ([`Writer::fresh`]).
    pub fn open(device: &mut dyn BlockDevice) -> Result<Self, BlockError> {
        Self::with_pending(device, PENDING_BYTES, true)
    }

    /// Open the log again later in the same boot, as the system engine does
    /// after the loader wrote it: the boot is not counted again and gets no
    /// second marker line.
    pub fn resume(device: &mut dyn BlockDevice) -> Result<Self, BlockError> {
        Self::with_pending(device, PENDING_BYTES, false)
    }

    fn with_pending(
        device: &mut dyn BlockDevice,
        pending: usize,
        new_boot: bool,
    ) -> Result<Self, BlockError> {
        let identity = device.identity();
        let block = identity.block_size as usize;
        if block == 0 || !(HEADER_BYTES as usize).is_multiple_of(block) {
            return Err(BlockError::Unsupported(
                "the boot log needs blocks that divide its 4 KiB header",
            ));
        }
        if identity.read_only {
            return Err(BlockError::ReadOnly);
        }
        let bytes = identity.blocks.saturating_mul(block as u64);
        if bytes <= HEADER_BYTES {
            return Err(BlockError::Unsupported("the boot log region holds no ring"));
        }
        let ring_bytes = bytes - HEADER_BYTES;
        let mut first = vec![0; block];
        device.read(0, &mut first)?;
        let (header, fresh) = match Header::decode(&first, ring_bytes) {
            Ok(header) => (header, None),
            Err(error) => (
                Header {
                    head: 0,
                    boots: 0,
                    ring_bytes,
                },
                Some(error),
            ),
        };
        let mut ring = Ring {
            block,
            ring_bytes,
            head: header.head,
            tail: vec![0; block],
            dirty: false,
            unread: false,
        };
        let head = header.head;
        let offset = (head % block as u64) as usize;
        if offset != 0 || head >= ring_bytes {
            device.read(ring.lba(head), &mut ring.tail)?;
        }
        // A boot that stopped mid-line gets its line ended first.
        let last = match (head, offset) {
            (0, _) => b'\n',
            (_, 0) => {
                let mut previous = vec![0; block];
                device.read(ring.lba(head - 1), &mut previous)?;
                previous[block - 1]
            }
            _ => ring.tail[offset - 1],
        };
        let mut writer = Self {
            ring,
            boots: header.boots.saturating_add(u64::from(new_boot)),
            durable: fresh.is_none().then_some(head),
            fresh,
            pending: Pending::new(vec![0; pending]),
            steps: VecDeque::new(),
            running: None,
        };
        if last != b'\n' {
            writer.append(b"\n");
        }
        if new_boot {
            writer.append(format!("=== STELA BOOT {} ===\n", writer.boots).as_bytes());
        }
        Ok(writer)
    }

    /// Read the header back and check that it records the last flush: a
    /// device that accepts writes and keeps none fails here.
    pub fn verify(&self, device: &mut dyn BlockDevice) -> Result<(), Unkept> {
        let mut block = vec![0; self.ring.block];
        device.read(0, &mut block).map_err(Unkept::Read)?;
        let stored = Header::decode(&block, self.ring.ring_bytes).map_err(Unkept::Header)?;
        let written = self.durable.unwrap_or_default();
        if stored.head != written || stored.boots != self.boots {
            return Err(Unkept::Head {
                stored: stored.head,
                written,
            });
        }
        Ok(())
    }

    /// Why the log started fresh this boot, if it did.
    pub fn fresh(&self) -> Option<&HeaderError> {
        self.fresh.as_ref()
    }

    /// This boot's number.
    pub fn boots(&self) -> u64 {
        self.boots
    }

    /// Every byte appended so far, including those still pending.
    pub fn head(&self) -> u64 {
        self.ring.head + self.pending.bytes() as u64
    }

    pub fn ring_bytes(&self) -> u64 {
        self.ring.ring_bytes
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.pending.push(bytes);
    }

    /// Store the pending bytes, the caller waiting: [`Self::begin_store`]
    /// with each request run to completion.
    pub fn flush(&mut self, device: &mut dyn BlockDevice) -> Result<(), BlockError> {
        if !self.begin_store() {
            return Ok(());
        }
        while let Some(request) = self.next_request() {
            self.completed(request.run(device))?;
        }
        Ok(())
    }

    /// Whether a store has requests left ([`Self::next_request`]).
    pub fn storing(&self) -> bool {
        self.running.is_some() || !self.steps.is_empty()
    }

    /// Begin storing the pending bytes; whether there are any. The store
    /// is the ring's blocks, each durable once written, then the header,
    /// durable too: a header never names bytes the device lacks, and no
    /// cache is flushed whole. Bytes appended meanwhile wait for the next.
    pub fn begin_store(&mut self) -> bool {
        if self.storing() {
            return true;
        }
        let mut remaining = self.pending.bytes();
        if remaining == 0 && self.durable == Some(self.ring.head) {
            return false;
        }
        let mut writes = Vec::new();
        let ring = &mut self.ring;
        let Ok(()) = self.pending.drain(|bytes| {
            ring.stage(bytes, &mut remaining, &mut writes);
            Ok::<_, Infallible>(())
        });
        // The head's partial block joins the ring's writes unless its old
        // bytes must be read first.
        let mut tail = false;
        if ring.dirty && !ring.unread {
            join(&mut writes, ring.lba(ring.head), &ring.tail, ring.block);
            tail = true;
        }
        let count = writes.len();
        for (index, (lba, data)) in writes.into_iter().enumerate() {
            let tail = tail && index + 1 == count;
            self.steps.push_back(Step::Blocks { lba, data, tail });
        }
        if ring.unread {
            self.steps.push_back(Step::ReadTail);
        }
        if ring.dirty && !tail {
            self.steps.push_back(Step::Tail);
        }
        self.steps.push_back(Step::Header);
        true
    }

    /// The store's next request once the last one completed
    /// ([`Self::completed`]); `None` when it has no more.
    pub fn next_request(&mut self) -> Option<Request> {
        if self.running.is_some() {
            return None;
        }
        let ring = &self.ring;
        let step = self.steps.pop_front()?;
        let (request, step) = match step {
            Step::Blocks { lba, data, tail } => (
                Request::Write {
                    lba,
                    data,
                    durable: true,
                },
                Step::Blocks {
                    lba,
                    data: Vec::new(),
                    tail,
                },
            ),
            Step::ReadTail => (
                Request::Read {
                    lba: ring.lba(ring.head),
                    bytes: ring.block,
                },
                Step::ReadTail,
            ),
            Step::Tail => (
                Request::Write {
                    lba: ring.lba(ring.head),
                    data: ring.tail.clone(),
                    durable: true,
                },
                Step::Tail,
            ),
            Step::Header => {
                let mut block = vec![0; ring.block];
                Header {
                    head: ring.head,
                    boots: self.boots,
                    ring_bytes: ring.ring_bytes,
                }
                .encode(&mut block);
                let request = Request::Write {
                    lba: 0,
                    data: block,
                    durable: true,
                };
                (request, Step::Header)
            }
        };
        self.running = Some(step);
        Some(request)
    }

    /// The running request finished with `finished`. A failure ends the
    /// store: the next starts over from what the device then holds.
    pub fn completed(&mut self, finished: Finished) -> Result<(), BlockError> {
        let step = self.running.take();
        let data = match finished {
            Ok(data) => data,
            Err(error) => {
                self.steps.clear();
                return Err(error);
            }
        };
        let ring = &mut self.ring;
        match step {
            Some(Step::Blocks { tail: true, .. }) | Some(Step::Tail) => ring.dirty = false,
            Some(Step::ReadTail) => {
                // The bytes before the head are this store's; keep the old
                // ones after it.
                let old = data.ok_or(BlockError::Protocol("a log read returned no data"))?;
                let offset = (ring.head % ring.block as u64) as usize;
                ring.tail[offset..].copy_from_slice(&old[offset..]);
                ring.unread = false;
            }
            Some(Step::Header) => self.durable = Some(ring.head),
            Some(Step::Blocks { .. }) | None => {}
        }
        Ok(())
    }
}

/// A region's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub boots: u64,
    pub head: u64,
    pub ring_bytes: u64,
    /// The valid stream, oldest byte first.
    pub stream: Vec<u8>,
}

impl Log {
    /// The stream bytes the ring has overwritten.
    pub fn overwritten(&self) -> u64 {
        self.head.saturating_sub(self.ring_bytes)
    }
}

/// The log a whole region holds, its stream in order. A blank or invalid
/// header is refused by name.
pub fn read(region: &[u8]) -> Result<Log, HeaderError> {
    let bytes = region.len() as u64;
    if bytes <= HEADER_BYTES {
        return Err(HeaderError::Short { bytes });
    }
    let (header, ring) = region.split_at(HEADER_BYTES as usize);
    let ring_bytes = bytes - HEADER_BYTES;
    let Header { head, boots, .. } = Header::decode(header, ring_bytes)?;
    let start = head.saturating_sub(ring_bytes);
    let len = (head - start) as usize;
    let at = (start % ring_bytes) as usize;
    let first = len.min(ring.len() - at);
    let mut stream = Vec::with_capacity(len);
    stream.extend_from_slice(&ring[at..at + first]);
    stream.extend_from_slice(&ring[..len - first]);
    Ok(Log {
        boots,
        head,
        ring_bytes,
        stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec::Vec};
    use stela_drivers::block::{Identity, RamDisk};

    /// A RAM disk that records its transfers and can fail from a given
    /// write on.
    struct Recorder {
        disk: RamDisk,
        /// Each write's block and each flush (`None`), in order.
        events: Vec<Option<u64>>,
        reads: usize,
        writes_left: Option<usize>,
        /// Accept writes and keep none, as a device that loses them.
        dropping: bool,
    }

    impl Recorder {
        /// A disk with a write cache, so each durable write is followed
        /// by a flush.
        fn new(region: u64, block: u32) -> Self {
            let mut disk = RamDisk::new("log", region / u64::from(block), block);
            disk.identity.features.write_cache = true;
            Self {
                disk,
                events: Vec::new(),
                reads: 0,
                writes_left: None,
                dropping: false,
            }
        }

        fn log(&self) -> Result<Log, HeaderError> {
            read(&self.disk.bytes)
        }
    }

    impl BlockDevice for Recorder {
        fn identity(&self) -> &Identity {
            self.disk.identity()
        }

        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.reads += 1;
            self.disk.read(lba, buffer)
        }

        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            if let Some(left) = self.writes_left.as_mut() {
                if *left == 0 {
                    return Err(BlockError::Timeout);
                }
                *left -= 1;
            }
            self.events.push(Some(lba));
            if self.dropping {
                return Ok(());
            }
            self.disk.write(lba, data)
        }

        fn flush_cache(&mut self) -> Result<(), BlockError> {
            self.events.push(None);
            self.disk.flush_cache()
        }
    }

    fn text(log: &Log) -> String {
        String::from_utf8(log.stream.clone()).unwrap()
    }

    #[test]
    fn a_device_that_keeps_no_writes_fails_the_check() {
        let mut disk = Recorder::new(HEADER_BYTES + 4096, 512);
        let mut writer = Writer::open(&mut disk).unwrap();
        writer.flush(&mut disk).unwrap();
        assert_eq!(writer.verify(&mut disk), Ok(()));
        writer.append(b"more\n");
        disk.dropping = true;
        writer.flush(&mut disk).unwrap();
        assert_eq!(
            writer.verify(&mut disk),
            Err(Unkept::Head {
                stored: 0x15,
                written: 0x1a
            })
        );
        let mut blank = Recorder::new(HEADER_BYTES + 4096, 512);
        blank.dropping = true;
        let mut writer = Writer::open(&mut blank).unwrap();
        writer.flush(&mut blank).unwrap();
        assert_eq!(
            writer.verify(&mut blank),
            Err(Unkept::Header(HeaderError::Blank))
        );
    }

    #[test]
    fn a_resumed_log_continues_the_same_boot() {
        let mut disk = Recorder::new(HEADER_BYTES + 4 * 4096, 512);
        let mut loader = Writer::open(&mut disk).unwrap();
        loader.append(b"before the takeover\n");
        loader.flush(&mut disk).unwrap();
        let mut engine = Writer::resume(&mut disk).unwrap();
        assert_eq!(engine.boots(), 1);
        engine.append(b"after it\n");
        engine.flush(&mut disk).unwrap();
        let log = disk.log().unwrap();
        assert_eq!(log.boots, 1);
        assert_eq!(
            text(&log),
            "=== STELA BOOT 1 ===\nbefore the takeover\nafter it\n"
        );
    }

    #[test]
    fn boots_append_markers_on_512_and_4096_byte_blocks() {
        for block in [512, 4096] {
            let mut disk = Recorder::new(HEADER_BYTES + 4 * 4096, block);
            let mut writer = Writer::open(&mut disk).unwrap();
            assert_eq!(writer.fresh(), Some(&HeaderError::Blank));
            assert_eq!(writer.boots(), 1);
            writer.append(b"first line\n");
            writer.flush(&mut disk).unwrap();
            assert_eq!(
                text(&disk.log().unwrap()),
                "=== STELA BOOT 1 ===\nfirst line\n"
            );
            // Small flushes rewrite the tail block from memory, never
            // reading it back.
            let reads = disk.reads;
            for _ in 0..20 {
                writer.append(b"0123456789abcdef");
                writer.flush(&mut disk).unwrap();
            }
            assert_eq!(disk.reads, reads, "{block}-byte blocks");
            // A flush with nothing new writes nothing.
            let events = disk.events.len();
            writer.flush(&mut disk).unwrap();
            assert_eq!(disk.events.len(), events);
            // The next boot counts itself and ends the unfinished line.
            writer.append(b"cut off");
            writer.flush(&mut disk).unwrap();
            let mut again = Writer::open(&mut disk).unwrap();
            assert_eq!(again.fresh(), None);
            assert_eq!(again.boots(), 2);
            again.flush(&mut disk).unwrap();
            let log = disk.log().unwrap();
            assert_eq!(log.boots, 2);
            assert_eq!(log.head, log.stream.len() as u64);
            assert!(
                text(&log).ends_with("cut off\n=== STELA BOOT 2 ===\n"),
                "{}",
                text(&log)
            );
            assert_eq!(log.stream.len(), 21 + 11 + 320 + 7 + 1 + 21);
        }
    }

    #[test]
    fn the_ring_wraps_and_the_reader_keeps_order() {
        for block in [512, 4096] {
            // A two-block ring.
            let ring = 2 * u64::from(block);
            let mut disk = Recorder::new(HEADER_BYTES + ring, block);
            let mut writer = Writer::open(&mut disk).unwrap();
            let mut stream: Vec<u8> = b"=== STELA BOOT 1 ===\n".to_vec();
            for line in 0..(3 * ring / 10) {
                let bytes = format!("line {line:04}\n");
                stream.extend_from_slice(bytes.as_bytes());
                writer.append(bytes.as_bytes());
                if line % 7 == 0 {
                    writer.flush(&mut disk).unwrap();
                }
            }
            writer.flush(&mut disk).unwrap();
            let log = disk.log().unwrap();
            assert_eq!(log.head, stream.len() as u64);
            assert_eq!(log.overwritten(), stream.len() as u64 - ring);
            assert_eq!(log.stream, stream[stream.len() - ring as usize..]);
            // A boot opening a wrapped log keeps the oldest bytes of its
            // tail block.
            let mut again = Writer::open(&mut disk).unwrap();
            again.flush(&mut disk).unwrap();
            stream.extend_from_slice(b"=== STELA BOOT 2 ===\n");
            assert_eq!(
                disk.log().unwrap().stream,
                stream[stream.len() - ring as usize..]
            );
        }
    }

    #[test]
    fn the_reader_orders_a_wrapped_region() {
        let ring = 16u64;
        let mut region = vec![0u8; (HEADER_BYTES + ring) as usize];
        Header {
            head: ring + 5,
            boots: 3,
            ring_bytes: ring,
        }
        .encode(&mut region[..HEADER_BYTES as usize]);
        // Stream bytes 5..21: 16..21 wrapped to ring 0..5.
        for at in 5..ring + 5 {
            region[(HEADER_BYTES + at % ring) as usize] = b'a' + at as u8;
        }
        let log = read(&region).unwrap();
        assert_eq!(log.boots, 3);
        assert_eq!(log.overwritten(), 5);
        let expected: Vec<u8> = (5..ring + 5).map(|at| b'a' + at as u8).collect();
        assert_eq!(log.stream, expected);
    }

    #[test]
    fn the_header_is_written_last_so_an_interrupted_flush_keeps_the_old_stream() {
        for block in [512, 4096] {
            let mut disk = Recorder::new(HEADER_BYTES + 8 * 4096, block);
            let mut writer = Writer::open(&mut disk).unwrap();
            writer.append(b"kept\n");
            writer.flush(&mut disk).unwrap();
            let before = disk.log().unwrap();
            // Each flush ends with: data, flush, header, flush.
            let header = disk.events.len() - 2;
            assert_eq!(disk.events[header], Some(0));
            assert_eq!(disk.events[header - 1], None);
            assert_eq!(&disk.events[header + 1..], &[None]);
            assert!(disk.events[..header - 1].iter().all(|e| *e != Some(0)));
            // Data fills three blocks, one write; the device fails before
            // the header.
            writer.append(&vec![b'x'; 3 * block as usize]);
            disk.writes_left = Some(1);
            assert_eq!(writer.flush(&mut disk), Err(BlockError::Timeout));
            assert_eq!(disk.log().unwrap(), before);
        }
    }

    #[test]
    fn a_pending_overflow_is_reported_in_the_stream() {
        let mut pending = Pending::new([0u8; 8]);
        pending.push(b"abc");
        pending.push(b"defgh");
        pending.push(b"ij");
        assert_eq!(pending.bytes(), 8 + "[boot log dropped 2 bytes]\n".len());
        let mut out = Vec::new();
        pending
            .drain(|bytes| {
                out.extend_from_slice(bytes);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(out, b"[boot log dropped 2 bytes]\ncdefghij");
        assert!(pending.is_empty());
        pending.push(b"0123456789AB");
        let mut out = Vec::new();
        pending
            .drain(|bytes| {
                out.extend_from_slice(bytes);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(out, b"[boot log dropped 4 bytes]\n456789AB");

        // Logs that read the same bytes from their own positions.
        let mut pending = Pending::new([0u8; 8]);
        let copy = |pending: &Pending<[u8; 8]>, from| {
            let mut out = Vec::new();
            let at = pending
                .copy_since(from, |bytes| {
                    out.extend_from_slice(bytes);
                    Ok::<_, ()>(())
                })
                .unwrap();
            (at, out)
        };
        pending.push(b"abcdef");
        assert_eq!(copy(&pending, 0), (6, b"abcdef".to_vec()));
        pending.push(b"ghij");
        assert_eq!(copy(&pending, 6), (10, b"ghij".to_vec()));
        assert_eq!(
            copy(&pending, 0),
            (10, b"[boot log dropped 2 bytes]\ncdefghij".to_vec())
        );
        assert_eq!(copy(&pending, 10), (10, Vec::new()));

        // The writer's own buffer between flushes.
        let mut disk = Recorder::new(HEADER_BYTES + 4 * 4096, 512);
        let mut writer = Writer::with_pending(&mut disk, 64, true).unwrap();
        for line in 0..10 {
            writer.append(format!("line {line:02}\n").as_bytes());
        }
        writer.flush(&mut disk).unwrap();
        // The marker (21 bytes) and 10 lines of 8 bytes; 64 are kept.
        assert_eq!(
            text(&disk.log().unwrap()),
            "[boot log dropped 37 bytes]\n\
             line 02\nline 03\nline 04\nline 05\nline 06\nline 07\nline 08\nline 09\n"
        );
    }

    #[test]
    fn a_blank_or_invalid_header_starts_a_fresh_log_and_the_reader_refuses_it() {
        let mut disk = Recorder::new(HEADER_BYTES + 4096, 512);
        assert_eq!(disk.log(), Err(HeaderError::Blank));
        let mut writer = Writer::open(&mut disk).unwrap();
        writer.append(b"old boot\n");
        writer.flush(&mut disk).unwrap();
        let good = disk.disk.bytes.clone();

        let damage = |offset: usize| {
            let mut bytes = good.clone();
            bytes[offset] ^= 0x5a;
            bytes
        };
        let mut wrong_version = good.clone();
        wrong_version[8] = 2;
        let digest = Sha256::digest(&wrong_version[..FIELDS]);
        wrong_version[FIELDS..RECORD].copy_from_slice(&digest);
        let mut other_ring = good.clone();
        other_ring[32..40].copy_from_slice(&8192u64.to_le_bytes());
        let digest = Sha256::digest(&other_ring[..FIELDS]);
        other_ring[FIELDS..RECORD].copy_from_slice(&digest);
        let cases = [
            (damage(0), HeaderError::NotALog),
            (damage(16), HeaderError::Checksum),
            (damage(FIELDS + 3), HeaderError::Checksum),
            (wrong_version, HeaderError::Version(2)),
            (
                other_ring,
                HeaderError::RingSize {
                    recorded: 8192,
                    region: 4096,
                },
            ),
        ];
        for (bytes, error) in cases {
            disk.disk.bytes = bytes;
            assert_eq!(disk.log(), Err(error.clone()));
            let mut writer = Writer::open(&mut disk).unwrap();
            assert_eq!(writer.fresh(), Some(&error));
            assert_eq!(writer.boots(), 1);
            writer.flush(&mut disk).unwrap();
            // The old ring bytes are not taken as log data.
            assert_eq!(text(&disk.log().unwrap()), "=== STELA BOOT 1 ===\n");
        }
        assert_eq!(
            read(&good[..HEADER_BYTES as usize]),
            Err(HeaderError::Short {
                bytes: HEADER_BYTES
            })
        );
    }

    #[test]
    fn unsupported_geometry_is_refused() {
        let mut big = RamDisk::new("log", 4, 8192);
        assert!(matches!(
            Writer::open(&mut big),
            Err(BlockError::Unsupported(_))
        ));
        let mut tiny = RamDisk::new("log", 8, 512);
        assert!(matches!(
            Writer::open(&mut tiny),
            Err(BlockError::Unsupported(_))
        ));
        assert_eq!(PARTITION_BYTES, 0xc1_0000);
        assert_eq!(OFFSET, 0x81_0000);
    }

    #[test]
    fn a_file_gives_the_block_runs_of_its_clusters_that_hold_the_layout() {
        use stela_formats::payload::pieces::Extent;
        let file = |extents: &[(u64, u64)]| fat32::File {
            bytes: extents.iter().map(|e| e.1).sum(),
            extents: extents
                .iter()
                .map(|&(offset, bytes)| Extent { offset, bytes })
                .collect(),
        };
        let size = 16 << 20;
        assert_eq!(
            file_runs(&file(&[(0x10_0000, size)]), 512, PARTITION_BYTES),
            Ok(vec![(0x800, PARTITION_BYTES / 512)])
        );
        // Scattered clusters give their runs in file order, adjacent ones
        // joined, up to the bytes the layout needs.
        assert_eq!(
            file_runs(
                &file(&[
                    (0x20_0000, 0x1000),
                    (0x20_1000, 0x1000),
                    (0x10_0000, 0x1000),
                    (0x40_0000, size)
                ]),
                512,
                PARTITION_BYTES
            ),
            Ok(vec![
                (0x1000, 16),
                (0x800, 8),
                (0x2000, (PARTITION_BYTES - 0x3000) / 512)
            ])
        );
        assert_eq!(
            file_runs(&file(&[]), 512, PARTITION_BYTES),
            Err(FileError::Short {
                bytes: 0,
                needed: PARTITION_BYTES
            })
        );
        assert_eq!(
            file_runs(&file(&[(0x10_0200, size)]), 4096, PARTITION_BYTES),
            Err(FileError::Misaligned {
                offset: 0x10_0200,
                block: 4096
            })
        );
        // A run may not end inside a block when another follows it.
        assert_eq!(
            file_runs(&file(&[(0, 0x1200), (0x8000, size)]), 4096, PARTITION_BYTES),
            Err(FileError::Misaligned {
                offset: 0x1200,
                block: 4096
            })
        );
        // A partial last block does not count.
        assert_eq!(
            file_runs(
                &file(&[(0, PARTITION_BYTES + 0x800)]),
                4096,
                PARTITION_BYTES
            ),
            Ok(vec![(0, PARTITION_BYTES / 4096)])
        );
        assert_eq!(
            file_runs(&file(&[(0, PARTITION_BYTES - 1)]), 512, PARTITION_BYTES),
            Err(FileError::Short {
                bytes: PARTITION_BYTES - 512,
                needed: PARTITION_BYTES
            })
        );
        // A log file needs only the region.
        assert_eq!(
            file_runs(&file(&[(0, LOG_BYTES)]), 512, LOG_BYTES),
            Ok(vec![(0, LOG_BYTES / 512)])
        );
    }
}
