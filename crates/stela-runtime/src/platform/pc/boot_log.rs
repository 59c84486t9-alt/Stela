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
use super::block::{BlockDevice, BlockError};
use crate::machine::apple::{nor::CAPACITY, sep_state};
use alloc::{format, vec, vec::Vec};
use core::fmt::{self, Write as _};
use sha2::{Digest, Sha256};

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
/// `[boot log dropped N bytes]` line in their place.
pub struct Pending<S> {
    storage: S,
    start: usize,
    len: usize,
    dropped: u64,
}

impl<S> Pending<S> {
    pub const fn new(storage: S) -> Self {
        Self {
            storage,
            start: 0,
            len: 0,
            dropped: 0,
        }
    }
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Pending<S> {
    pub fn push(&mut self, mut bytes: &[u8]) {
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
}

impl Ring {
    /// The device block of the ring block holding stream position `at`.
    fn lba(&self, at: u64) -> u64 {
        HEADER_BYTES / self.block as u64 + (at % self.ring_bytes) / self.block as u64
    }

    /// Copy `bytes` to the ring at the head, writing each block they fill.
    /// `remaining` counts this flush's bytes still to come: a block they
    /// will overwrite whole is not read first.
    fn stage(
        &mut self,
        device: &mut dyn BlockDevice,
        mut bytes: &[u8],
        remaining: &mut usize,
    ) -> Result<(), BlockError> {
        while !bytes.is_empty() {
            let offset = (self.head % self.block as u64) as usize;
            let count = (self.block - offset).min(bytes.len());
            self.tail[offset..offset + count].copy_from_slice(&bytes[..count]);
            self.head += count as u64;
            self.dirty = true;
            bytes = &bytes[count..];
            *remaining -= count;
            if self.head.is_multiple_of(self.block as u64) {
                device.write(self.lba(self.head - 1), &self.tail)?;
                self.dirty = false;
                // The next block holds the oldest stream bytes once the ring
                // has wrapped; keep those this flush does not overwrite.
                if self.head >= self.ring_bytes && *remaining < self.block {
                    device.read(self.lba(self.head), &mut self.tail)?;
                } else {
                    self.tail.fill(0);
                }
            }
        }
        Ok(())
    }
}

/// The log of one boot: appends wait in memory until a flush stores them.
pub struct Writer {
    ring: Ring,
    boots: u64,
    /// The head the header on the device records.
    durable: Option<u64>,
    fresh: Option<HeaderError>,
    pending: Pending<Vec<u8>>,
}

impl Writer {
    /// Open the log `device` holds whole (a [`LOG_BYTES`] window of the
    /// machine-state partition), count this boot and append its marker
    /// line. A blank or invalid header starts a fresh log ([`Writer::fresh`]).
    pub fn open(device: &mut dyn BlockDevice) -> Result<Self, BlockError> {
        Self::with_pending(device, PENDING_BYTES)
    }

    fn with_pending(device: &mut dyn BlockDevice, pending: usize) -> Result<Self, BlockError> {
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
            boots: header.boots.saturating_add(1),
            durable: fresh.is_none().then_some(head),
            fresh,
            pending: Pending::new(vec![0; pending]),
        };
        if last != b'\n' {
            writer.append(b"\n");
        }
        writer.append(format!("=== STELA BOOT {} ===\n", writer.boots).as_bytes());
        Ok(writer)
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

    /// Store the pending bytes: ring blocks first, then the header.
    pub fn flush(&mut self, device: &mut dyn BlockDevice) -> Result<(), BlockError> {
        self.flush_from(device, &mut Pending::new([0u8; 0]))
    }

    /// Store this writer's pending bytes, then those `more` holds, in that
    /// order: ring blocks first, durably, then the header, durably.
    pub fn flush_from<S: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        device: &mut dyn BlockDevice,
        more: &mut Pending<S>,
    ) -> Result<(), BlockError> {
        let mut remaining = self.pending.bytes() + more.bytes();
        if remaining == 0 && self.durable == Some(self.ring.head) {
            return Ok(());
        }
        let ring = &mut self.ring;
        self.pending
            .drain(|bytes| ring.stage(device, bytes, &mut remaining))?;
        more.drain(|bytes| ring.stage(device, bytes, &mut remaining))?;
        if ring.dirty {
            device.write(ring.lba(ring.head), &ring.tail)?;
            ring.dirty = false;
        }
        device.flush()?;
        let mut block = vec![0; ring.block];
        Header {
            head: ring.head,
            boots: self.boots,
            ring_bytes: ring.ring_bytes,
        }
        .encode(&mut block);
        device.write(0, &block)?;
        device.flush()?;
        self.durable = Some(ring.head);
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
    use crate::platform::pc::block::{Identity, tests::RamDisk};
    use alloc::{string::String, vec::Vec};

    /// A RAM disk that records its transfers and can fail from a given
    /// write on.
    struct Recorder {
        disk: RamDisk,
        /// Each write's block and each flush (`None`), in order.
        events: Vec<Option<u64>>,
        reads: usize,
        writes_left: Option<usize>,
    }

    impl Recorder {
        fn new(region: u64, block: u32) -> Self {
            Self {
                disk: RamDisk::new("log", region / u64::from(block), block),
                events: Vec::new(),
                reads: 0,
                writes_left: None,
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
            self.disk.write(lba, data)
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.events.push(None);
            self.disk.flush()
        }
    }

    fn text(log: &Log) -> String {
        String::from_utf8(log.stream.clone()).unwrap()
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
            // Data fills three blocks; the device fails before the header.
            writer.append(&vec![b'x'; 3 * block as usize]);
            disk.writes_left = Some(3);
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

        // The writer's own buffer between flushes.
        let mut disk = Recorder::new(HEADER_BYTES + 4 * 4096, 512);
        let mut writer = Writer::with_pending(&mut disk, 64).unwrap();
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
        assert_eq!(PARTITION_BYTES, 0x51_0000);
        assert_eq!(OFFSET, 0x11_0000);
    }
}
