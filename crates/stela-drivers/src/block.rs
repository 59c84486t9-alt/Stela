//! Block devices addressed by logical block, with explicit errors.
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    cell::UnsafeCell,
    fmt,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};

mod profile;
pub use profile::{ActiveCallback, CallbackActivity, CallbackCounts, CallbackStats};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// The transfer is not a whole number of blocks.
    Misaligned {
        bytes: usize,
        block_size: u32,
    },
    /// The transfer reaches past the last block.
    OutOfRange {
        lba: u64,
        blocks: u64,
        capacity: u64,
    },
    /// The device refuses writes.
    ReadOnly,
    /// The device reported a failure with this controller status.
    Device {
        status: u32,
    },
    /// A SCSI command failed with this sense data.
    Sense(Sense),
    /// A SCSI command failed and no sense data said why.
    CheckCondition,
    /// The storage transport broke its own protocol.
    Protocol(&'static str),
    /// The device did not complete in time.
    Timeout,
    /// The DMA pages are exhausted.
    NoDmaMemory,
    Dma(crate::bus::dma::AllocationError),
    /// The device needs something these drivers do not implement.
    Unsupported(&'static str),
}

/// SCSI sense data (SPC-5 4.4): sense key, additional sense code and its
/// qualifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sense {
    pub key: u8,
    pub asc: u8,
    pub ascq: u8,
}

impl Sense {
    pub const NOT_READY: u8 = 0x02;
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    pub const UNIT_ATTENTION: u8 = 0x06;
    /// ASC 04h: logical unit not ready; 25h: logical unit not supported;
    /// 28h/29h: medium changed, power on or reset; 3Ah: medium not present;
    /// 3Fh: target operating conditions changed.
    pub const NOT_READY_CAUSE: u8 = 0x04;
    pub const UNSUPPORTED_UNIT: u8 = 0x25;
    pub const MEDIUM_CHANGED: u8 = 0x28;
    pub const RESET_OCCURRED: u8 = 0x29;
    pub const MEDIUM_NOT_PRESENT: u8 = 0x3a;
    pub const CONDITIONS_CHANGED: u8 = 0x3f;
    /// ASC 04h/02h: an initializing command (START STOP UNIT) is required.
    pub const INITIALIZING_COMMAND_REQUIRED: u8 = 0x02;
    /// ASC 3Fh/0Eh: the reported LUN inventory changed.
    pub const LUNS_CHANGED: u8 = 0x0e;
    /// Sense keys (SPC-5 4.4.2) that `scsi_check_sense` and sd's completion
    /// treat apart.
    pub const RECOVERED_ERROR: u8 = 0x01;
    pub const MEDIUM_ERROR: u8 = 0x03;
    pub const HARDWARE_ERROR: u8 = 0x04;
    pub const DATA_PROTECT: u8 = 0x07;
    pub const ABORTED_COMMAND: u8 = 0x0b;

    /// Fixed (70h/71h) or descriptor (72h/73h) format sense data.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let (key, asc, ascq) = match bytes.first()? & 0x7f {
            0x70 | 0x71 if bytes.len() >= 14 && bytes[7] >= 6 => (bytes[2], bytes[12], bytes[13]),
            0x72 | 0x73 if bytes.len() >= 8 => (bytes[1], bytes[2], bytes[3]),
            _ => return None,
        };
        Some(Self {
            key: key & 0x0f,
            asc,
            ascq,
        })
    }

    /// `scsi_check_sense` for current sense from a unit with no blacklist
    /// flags and no expected reset: whether it is NEEDS_RETRY.
    pub fn needs_retry(self) -> bool {
        match self.key {
            Self::ABORTED_COMMAND => {
                // DIF errors and command duration limit aborts complete.
                self.asc != 0x10 && !(self.asc == 0x2e && (0x01..=0x03).contains(&self.ascq))
            }
            Self::NOT_READY | Self::UNIT_ATTENTION => {
                // Becoming ready, an ALUA transition, or another LUN changed.
                self.asc == Self::NOT_READY_CAUSE && matches!(self.ascq, 0x01 | 0x0a)
                    || self.key == Self::UNIT_ATTENTION
                        && self.asc == Self::CONDITIONS_CHANGED
                        && self.ascq == Self::LUNS_CHANGED
            }
            // Unrecovered read errors, unreadable address marks and missing
            // records complete.
            Self::MEDIUM_ERROR => !matches!(self.asc, 0x11 | 0x13 | 0x14),
            _ => false,
        }
    }

    /// sd's completion of a command left with this sense, as
    /// `scsi_io_completion_nz_result` and `scsi_io_completion_action` treat
    /// it: a UNIT ATTENTION is a media change on a removable unit and a
    /// power glitch or bus reset on a fixed one.
    pub fn completion(self, removable: bool) -> SenseCompletion {
        match self.key {
            Self::RECOVERED_ERROR => SenseCompletion::Done,
            Self::UNIT_ATTENTION if removable => SenseCompletion::MediaChanged,
            Self::UNIT_ATTENTION => SenseCompletion::Retry(0),
            Self::NOT_READY if self.asc == Self::NOT_READY_CAUSE => match self.ascq {
                0x01 | 0x04..=0x09 | 0x11 | 0x14 | 0x1a | 0x1b | 0x1d => {
                    SenseCompletion::Retry(DEVICE_BUSY_DELAY_US)
                }
                0x0a => SenseCompletion::Retry(ALUA_TRANSITION_DELAY_US),
                _ => SenseCompletion::Fail,
            },
            _ => SenseCompletion::Fail,
        }
    }
}

/// sd's requeue delays: a busy device blocks its queue for
/// `SCSI_DEFAULT_DEVICE_BLOCKED` runs `SCSI_QUEUE_DELAY` (3 ms) apart, and
/// an ALUA transition waits `ALUA_TRANSITION_REPREP_DELAY`.
const DEVICE_BUSY_DELAY_US: u64 = 3 * 3_000;
const ALUA_TRANSITION_DELAY_US: u64 = 1_000_000;

/// What sd does with a command that ended with sense data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenseCompletion {
    /// A recovered error is success.
    Done,
    /// Requeue after this delay.
    Retry(u64),
    /// The removable unit's medium may have changed: fail, and refuse access
    /// until it is revalidated (`sdev->changed`).
    MediaChanged,
    Fail,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misaligned { bytes, block_size } => {
                write!(
                    f,
                    "{bytes} bytes is not a multiple of {block_size}-byte blocks"
                )
            }
            Self::OutOfRange {
                lba,
                blocks,
                capacity,
            } => write!(f, "blocks {lba}+{blocks} exceed capacity {capacity}"),
            Self::ReadOnly => f.write_str("device is read-only"),
            Self::Device { status } => write!(f, "device status {status:#x}"),
            Self::Sense(sense) => write!(
                f,
                "sense key {:#x}, ASC/ASCQ {:02x}/{:02x}",
                sense.key, sense.asc, sense.ascq
            ),
            Self::CheckCondition => f.write_str("command failed without sense data"),
            Self::Protocol(what) => write!(f, "transport protocol violation: {what}"),
            Self::Timeout => f.write_str("device timeout"),
            Self::NoDmaMemory => f.write_str("DMA pages exhausted"),
            Self::Dma(error) => write!(f, "DMA allocation: {error:?}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    VirtioBlk,
    Nvme,
    Ahci,
    /// USB mass storage (Bulk-Only) behind an xHCI controller.
    Usb,
    /// The engine's own memory ([`Volatile`]).
    Ram,
    /// A file in the firmware's file system, while boot services run.
    Firmware,
    /// Native SD or MMC/eMMC user-area storage behind a checked card host.
    SdMmc,
}

/// What a device reports about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub transport: Transport,
    /// The PCI function, and the NVMe namespace or AHCI port behind it.
    pub location: String,
    pub model: String,
    /// The serial number without padding; empty when the device has none.
    pub serial: String,
    pub blocks: u64,
    pub block_size: u32,
    pub read_only: bool,
    pub features: Features,
}

/// What a device does besides reading and writing, as it reports it: what
/// Linux's drivers declare in their queue limits (`struct queue_limits`).
/// Drivers report the device's own settings and never change them; the
/// block layer ([`Request::plan`]) turns each request into the commands the
/// device takes, so neither a driver nor a caller decides flush policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    /// A volatile write cache, enabled: a completed write is durable only
    /// after a flush. Without one a flush sends nothing.
    pub write_cache: bool,
    /// Writes may complete only once durable (Force Unit Access), so a
    /// durable write needs no flush of the whole cache.
    pub fua: bool,
    /// The most bytes one command moves; 0 for no limit.
    pub max_transfer: usize,
    /// Discard (NVMe Deallocate, ATA TRIM, SCSI UNMAP): the most blocks one
    /// command takes.
    pub discard: Option<u64>,
    /// Write Zeroes: the most blocks one command takes, and whether the
    /// device deallocates the blocks it zeroes when allowed to.
    pub write_zeroes: Option<WriteZeroes>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteZeroes {
    pub blocks: u64,
    pub unmap: bool,
}

impl Identity {
    pub fn bytes(&self) -> u64 {
        self.blocks * u64::from(self.block_size)
    }

    /// The number of blocks in a `bytes`-long transfer at `lba`, after
    /// checking alignment and range.
    pub fn check(&self, lba: u64, bytes: usize) -> Result<u64, BlockError> {
        let block_size = self.block_size as usize;
        if !bytes.is_multiple_of(block_size) {
            return Err(BlockError::Misaligned {
                bytes,
                block_size: self.block_size,
            });
        }
        let blocks = (bytes / block_size) as u64;
        match lba.checked_add(blocks) {
            Some(end) if end <= self.blocks => Ok(blocks),
            _ => Err(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.blocks,
            }),
        }
    }

    pub fn check_write(&self, lba: u64, bytes: usize) -> Result<u64, BlockError> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        self.check(lba, bytes)
    }
}

/// What a caller asks of a disk, at the device's own blocks. The block
/// layer carries it out with the commands the device takes
/// ([`Request::plan`]), as Linux's does for a bio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Read {
        lba: u64,
        bytes: usize,
    },
    /// `durable`: complete only once the write survives power loss.
    Write {
        lba: u64,
        data: Vec<u8>,
        durable: bool,
    },
    /// Make every completed write durable.
    Flush,
    /// Let the device deallocate the blocks; what they then read is
    /// unspecified. A device without discard refuses it.
    Discard {
        lba: u64,
        blocks: u64,
    },
    /// Zero the blocks; `unmap` lets a device that can deallocate them.
    WriteZeroes {
        lba: u64,
        blocks: u64,
        unmap: bool,
    },
}

/// One command of a device's class ([`BlockDevice::start`]), at the
/// device's own blocks: what [`Request::plan`] makes of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Read {
        lba: u64,
        bytes: usize,
    },
    Write {
        lba: u64,
        data: Vec<u8>,
        fua: bool,
    },
    /// The device's cache flush.
    Flush,
    Discard {
        lba: u64,
        blocks: u64,
    },
    WriteZeroes {
        lba: u64,
        blocks: u64,
        unmap: bool,
    },
}

/// The kinds of command a disk's I/O accounting tells apart, as Linux's
/// `/proc/diskstats` does: Write Zeroes counts as a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
    Flush,
    Discard,
}

impl Direction {
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Flush, Self::Discard];

    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Discard => "discard",
        }
    }
}

/// One [`Direction`]'s accounting: a `/proc/diskstats` group's fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Commands completed, and requests merged into another before it ran.
    pub ios: u64,
    pub merges: u64,
    pub bytes: u64,
    /// Counter ticks from each command's submission to its completion.
    pub ticks: u64,
}

/// A [`Shared`] disk's I/O accounting since it was shared, as Linux's
/// `/proc/diskstats`, in time-stamp counter ticks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// By [`Direction`].
    pub directions: [Counts; 4],
    /// Ticks with a command at the device (`io_ticks`).
    pub busy: u64,
    /// The most commands at the device at once.
    pub deepest: usize,
    /// Optional callback observations, enabled explicitly on the shared disk.
    /// Direct work can be nested in advance; these are not additive CPU times.
    pub callbacks: Option<CallbackStats>,
}

impl Command {
    /// What the accounting counts `self` as, and the bytes it moves.
    fn accounted(&self, block: usize) -> (Direction, u64) {
        match self {
            Self::Read { bytes, .. } => (Direction::Read, *bytes as u64),
            Self::Write { data, .. } => (Direction::Write, data.len() as u64),
            Self::Flush => (Direction::Flush, 0),
            Self::Discard { blocks, .. } => (Direction::Discard, blocks * block as u64),
            Self::WriteZeroes { blocks, .. } => (Direction::Write, blocks * block as u64),
        }
    }

    /// Check `self` against `identity`, a view of a larger device, and move
    /// it to the blocks from `first`.
    pub fn within(self, identity: &Identity, first: u64) -> Result<Self, BlockError> {
        let block = identity.block_size as usize;
        let span = |blocks: u64| {
            usize::try_from(blocks)
                .ok()
                .and_then(|b| b.checked_mul(block))
        };
        Ok(match self {
            Self::Read { lba, bytes } => {
                identity.check(lba, bytes)?;
                Self::Read {
                    lba: first + lba,
                    bytes,
                }
            }
            Self::Write { lba, data, fua } => {
                identity.check_write(lba, data.len())?;
                Self::Write {
                    lba: first + lba,
                    data,
                    fua,
                }
            }
            Self::Flush => Self::Flush,
            Self::Discard { lba, blocks } => {
                identity.check_write(
                    lba,
                    span(blocks).ok_or_else(|| range(identity, lba, blocks))?,
                )?;
                Self::Discard {
                    lba: first + lba,
                    blocks,
                }
            }
            Self::WriteZeroes { lba, blocks, unmap } => {
                identity.check_write(
                    lba,
                    span(blocks).ok_or_else(|| range(identity, lba, blocks))?,
                )?;
                Self::WriteZeroes {
                    lba: first + lba,
                    blocks,
                    unmap,
                }
            }
        })
    }
}

fn range(identity: &Identity, lba: u64, blocks: u64) -> BlockError {
    BlockError::OutOfRange {
        lba,
        blocks,
        capacity: identity.blocks,
    }
}

/// The bytes Write Zeroes writes at a time on a device without it.
const ZEROES_BYTES: usize = 1024 * 1024;

/// A validated request, split as commands are consumed. Range operations
/// keep their remaining extent here instead of allocating one descriptor
/// for every part of the disk.
struct Plan {
    request: Request,
    features: Features,
    block: usize,
    piece: usize,
    done: u64,
    written: bool,
    flushed: bool,
}

impl Plan {
    fn new(request: Request, identity: &Identity) -> Result<Self, BlockError> {
        match &request {
            Request::Read { lba, bytes } => {
                identity.check(*lba, *bytes)?;
            }
            Request::Write { lba, data, .. } => {
                identity.check_write(*lba, data.len())?;
            }
            Request::Discard { lba, blocks } | Request::WriteZeroes { lba, blocks, .. } => {
                if matches!(request, Request::Discard { .. }) && identity.features.discard.is_none()
                {
                    return Err(BlockError::Unsupported("the device takes no discard"));
                }
                if identity.read_only {
                    return Err(BlockError::ReadOnly);
                }
                if lba
                    .checked_add(*blocks)
                    .is_none_or(|end| end > identity.blocks)
                {
                    return Err(BlockError::OutOfRange {
                        lba: *lba,
                        blocks: *blocks,
                        capacity: identity.blocks,
                    });
                }
            }
            Request::Flush => {}
        }
        let block = identity.block_size as usize;
        let piece = match identity.features.max_transfer / block * block {
            0 => usize::MAX,
            bytes => bytes,
        };
        Ok(Self {
            request,
            features: identity.features,
            block,
            piece,
            done: 0,
            written: false,
            flushed: false,
        })
    }
}

impl Iterator for Plan {
    type Item = (usize, Command);

    fn next(&mut self) -> Option<Self::Item> {
        let limit = |blocks| if blocks == 0 { u64::MAX } else { blocks };
        let command = match &mut self.request {
            Request::Read { lba, bytes } => {
                let offset = self.done as usize;
                if offset >= *bytes {
                    return None;
                }
                let bytes = self.piece.min(*bytes - offset);
                self.done += bytes as u64;
                return Some((
                    offset,
                    Command::Read {
                        lba: *lba + (offset / self.block) as u64,
                        bytes,
                    },
                ));
            }
            Request::Write { lba, data, durable } => {
                let offset = self.done as usize;
                if offset < data.len() || !self.written {
                    let bytes = self.piece.min(data.len() - offset);
                    let part = if offset == 0 && bytes == data.len() {
                        core::mem::take(data)
                    } else {
                        data[offset..offset + bytes].to_vec()
                    };
                    self.done += bytes as u64;
                    self.written = true;
                    Command::Write {
                        lba: *lba + (offset / self.block) as u64,
                        data: part,
                        fua: *durable && self.features.write_cache && self.features.fua,
                    }
                } else if *durable
                    && self.features.write_cache
                    && !self.features.fua
                    && !self.flushed
                {
                    self.flushed = true;
                    Command::Flush
                } else {
                    return None;
                }
            }
            Request::Flush => {
                if !self.features.write_cache || self.flushed {
                    return None;
                }
                self.flushed = true;
                Command::Flush
            }
            Request::Discard { lba, blocks } => {
                if self.done >= *blocks {
                    return None;
                }
                let blocks = limit(self.features.discard.expect("validated discard"))
                    .min(*blocks - self.done);
                let lba = *lba + self.done;
                self.done += blocks;
                Command::Discard { lba, blocks }
            }
            Request::WriteZeroes { lba, blocks, unmap } => {
                if self.done >= *blocks {
                    return None;
                }
                let at = *lba + self.done;
                if let Some(zeroes) = self.features.write_zeroes {
                    let blocks = limit(zeroes.blocks).min(*blocks - self.done);
                    self.done += blocks;
                    Command::WriteZeroes {
                        lba: at,
                        blocks,
                        unmap: *unmap && zeroes.unmap,
                    }
                } else {
                    let per = (self.piece.min(ZEROES_BYTES) / self.block).max(1) as u64;
                    let blocks = per.min(*blocks - self.done);
                    self.done += blocks;
                    Command::Write {
                        lba: at,
                        data: vec![0; blocks as usize * self.block],
                        fua: false,
                    }
                }
            }
        };
        Some((0, command))
    }
}

type Commands = core::iter::Peekable<core::iter::Flatten<alloc::vec::IntoIter<Plan>>>;

impl Request {
    /// The commands that carry out `self` on a device with `identity`'s
    /// features, each with its byte offset in a read's data, as Linux's
    /// block layer splits a bio at the device's limits and turns its flush
    /// flags into commands (`blk-flush.c`): a durable write is written with
    /// Force Unit Access, or followed by a flush where the device has a
    /// write cache and no FUA, and is a plain write without a cache; a flush
    /// sends nothing without a cache. Write Zeroes falls back to writing
    /// zeros, as `blkdev_issue_zeroout` does.
    pub fn plan(self, identity: &Identity) -> Result<Vec<(usize, Command)>, BlockError> {
        Ok(Plan::new(self, identity)?.collect())
    }

    /// Run `self` on `device` to completion, the caller waiting.
    pub fn run(self, device: &mut (impl BlockDevice + ?Sized)) -> Finished {
        let plan = Plan::new(self, device.identity())?;
        let read = match &plan.request {
            Self::Read { bytes, .. } => Some(*bytes),
            _ => None,
        };
        let mut data = read.map(|bytes| vec![0; bytes]);
        for (offset, command) in plan {
            if let (Some(data), Command::Read { lba, bytes }) = (data.as_mut(), &command) {
                device.read(*lba, &mut data[offset..offset + bytes])?;
            } else {
                device.execute(command)?;
            }
        }
        Ok(data)
    }
}

/// A started request's result: the bytes a read returned.
pub type Finished = Result<Option<Vec<u8>>, BlockError>;

/// A request in progress on a device, which never waits for it: its
/// commands run as the device has room, those before a flush together, a
/// flush alone once they completed, as Linux's flush sequence orders them.
/// A device that runs no queued commands runs each where it is polled.
pub struct Submission {
    commands: Commands,
    /// The started commands: each tag, a read's offset in the data, and
    /// whether it is a flush.
    running: Vec<(u32, usize, bool)>,
    data: Option<Vec<u8>>,
    failed: Option<BlockError>,
}

/// New commands admitted by one polling call, including synchronous execution.
const POLL_ADMISSIONS: usize = 64;

impl Submission {
    pub fn new(request: Request, identity: &Identity) -> Result<Self, BlockError> {
        let plan = Plan::new(request, identity)?;
        let data = match &plan.request {
            Request::Read { bytes, .. } => Some(vec![0; *bytes]),
            _ => None,
        };
        Ok(Self {
            commands: vec![plan].into_iter().flatten().peekable(),
            running: Vec::new(),
            data,
            failed: None,
        })
    }

    /// `requests` as one: each one's commands after the last one's, which
    /// may run together. Only a lone read returns its data.
    pub fn batch(requests: Vec<Request>, identity: &Identity) -> Result<Self, BlockError> {
        if let [Request::Read { .. }] = requests.as_slice() {
            return Self::new(requests.into_iter().next().unwrap(), identity);
        }
        let mut plans = Vec::with_capacity(requests.len());
        for request in requests {
            if let Request::Read { .. } = request {
                return Err(BlockError::Protocol("a read in a batch of requests"));
            }
            plans.push(Plan::new(request, identity)?);
        }
        Ok(Self {
            commands: plans.into_iter().flatten().peekable(),
            running: Vec::new(),
            data: None,
            failed: None,
        })
    }

    /// Collect the device's completions of this request's commands and
    /// start those that may run; the request's result once every command
    /// has completed. A failure starts no more commands and ends the
    /// request once the running ones have completed.
    ///
    /// Admit at most 64 new commands per call, respecting a queued device's
    /// depth and keeping at most 64 tags. Completion collection and an
    /// entered synchronous execution may take longer than the caller's slice.
    pub fn poll(&mut self, device: &mut (impl BlockDevice + ?Sized)) -> Option<Finished> {
        let mut index = 0;
        while index < self.running.len() {
            let (tag, offset, _) = self.running[index];
            let Some(result) = device.finish(tag) else {
                index += 1;
                continue;
            };
            self.running.swap_remove(index);
            self.completed(offset, result);
        }
        let depth = device.depth();
        let capacity = depth.min(POLL_ADMISSIONS);
        let mut admitted = 0;
        while self.failed.is_none() && admitted < POLL_ADMISSIONS {
            let Some((_, command)) = self.commands.peek() else {
                break;
            };
            let flush = matches!(command, Command::Flush);
            if (flush && !self.running.is_empty()) || self.running.iter().any(|run| run.2) {
                break;
            }
            if depth == 0 {
                if !self.running.is_empty() {
                    break;
                }
                let (offset, command) = self.commands.next().unwrap();
                admitted += 1;
                let result = device.execute(command);
                self.completed(offset, result);
                continue;
            }
            if self.running.len() >= capacity || !device.room() {
                break;
            }
            let (offset, command) = self.commands.next().unwrap();
            admitted += 1;
            match device.start(command) {
                Ok(tag) => self.running.push((tag, offset, flush)),
                Err(error) => self.failed = Some(error),
            }
        }
        if !self.running.is_empty() || (self.failed.is_none() && self.commands.peek().is_some()) {
            return None;
        }
        Some(match self.failed.take() {
            Some(error) => Err(error),
            None => Ok(self.data.take()),
        })
    }

    fn completed(&mut self, offset: usize, result: Finished) {
        match result {
            Ok(Some(bytes)) => {
                if let Some(data) = self.data.as_mut() {
                    data[offset..offset + bytes.len()].copy_from_slice(&bytes);
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.failed.get_or_insert(error);
            }
        }
    }
}

/// A disk or a view of one. Transfers are whole blocks. A driver implements
/// the commands its device reports ([`Features`]); callers reach them through
/// the block layer's requests ([`Request`], [`Self::flush`], [`Submission`]),
/// which send a device only commands it takes.
///
/// The synchronous methods return once the device completed the command. A
/// device that runs commands without its caller waiting ([`Self::depth`])
/// takes them with [`Self::start`], each under a tag, and gives each result
/// at [`Self::finish`], which never waits.
pub trait BlockDevice {
    fn identity(&self) -> &Identity;
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError>;
    /// A plain write: durable once flushed, or at once without a write
    /// cache ([`Features::write_cache`]).
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError>;

    /// The device's cache flush, which the block layer sends only to a
    /// device reporting a write cache.
    fn flush_cache(&mut self) -> Result<(), BlockError> {
        Err(BlockError::Unsupported("the device reports no write cache"))
    }

    /// A write that completes once durable, for a device reporting
    /// [`Features::fua`].
    fn write_fua(&mut self, _lba: u64, _data: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::Unsupported(
            "the device takes no Force Unit Access",
        ))
    }

    /// Discard, for a device reporting [`Features::discard`].
    fn discard(&mut self, _lba: u64, _blocks: u64) -> Result<(), BlockError> {
        Err(BlockError::Unsupported("the device takes no discard"))
    }

    /// Write Zeroes, for a device reporting [`Features::write_zeroes`].
    fn write_zeroes(&mut self, _lba: u64, _blocks: u64, _unmap: bool) -> Result<(), BlockError> {
        Err(BlockError::Unsupported("the device takes no Write Zeroes"))
    }

    /// Make every completed write durable: the device's cache flush, or
    /// nothing without a cache.
    fn flush(&mut self) -> Result<(), BlockError> {
        Request::Flush.run(self).map(drop)
    }

    /// Prepare the device for the PC restarting, or turning off when
    /// `power_off`: make writes durable and give the device the notice its
    /// class expects before power goes away.
    fn shutdown(&mut self, _power_off: bool) -> Result<(), BlockError> {
        self.flush()
    }

    /// Run `command`, the caller waiting.
    fn execute(&mut self, command: Command) -> Finished {
        match command {
            Command::Read { lba, bytes } => {
                let mut data = vec![0; bytes];
                self.read(lba, &mut data).map(|()| Some(data))
            }
            Command::Write { lba, data, fua } => if fua {
                self.write_fua(lba, &data)
            } else {
                self.write(lba, &data)
            }
            .map(|()| None),
            Command::Flush => self.flush_cache().map(|()| None),
            Command::Discard { lba, blocks } => self.discard(lba, blocks).map(|()| None),
            Command::WriteZeroes { lba, blocks, unmap } => {
                self.write_zeroes(lba, blocks, unmap).map(|()| None)
            }
        }
    }

    /// How many commands the device runs without its caller waiting; 0 for
    /// one that runs each where it is asked.
    fn depth(&self) -> usize {
        0
    }

    /// Whether [`Self::start`] takes a command now.
    fn room(&self) -> bool {
        false
    }

    /// Submit `command` and return its tag.
    fn start(&mut self, _command: Command) -> Result<u32, BlockError> {
        Err(BlockError::Unsupported(
            "the device runs no queued commands",
        ))
    }

    /// Command `tag`'s result once the device has completed it.
    fn finish(&mut self, _tag: u32) -> Option<Finished> {
        None
    }

    /// Whether a started command's completion waits for [`Self::finish`]:
    /// a look at memory the device writes, never at a register.
    fn posted(&self) -> bool {
        false
    }

    /// Whether the device sends its host's completion signal
    /// ([`crate::Handoff::completion`]) as it completes a command, waking
    /// the core that looks for completions.
    fn signals(&self) -> bool {
        false
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for Box<D> {
    fn identity(&self) -> &Identity {
        (**self).identity()
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        (**self).read(lba, buffer)
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        (**self).write(lba, data)
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        (**self).flush_cache()
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        (**self).write_fua(lba, data)
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        (**self).discard(lba, blocks)
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        (**self).write_zeroes(lba, blocks, unmap)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        (**self).flush()
    }

    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        (**self).shutdown(power_off)
    }

    fn execute(&mut self, command: Command) -> Finished {
        (**self).execute(command)
    }

    fn depth(&self) -> usize {
        (**self).depth()
    }

    fn room(&self) -> bool {
        (**self).room()
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        (**self).start(command)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        (**self).finish(tag)
    }

    fn posted(&self) -> bool {
        (**self).posted()
    }

    fn signals(&self) -> bool {
        (**self).signals()
    }
}

/// ASCII from a fixed-width identify field, trimmed of padding.
pub(crate) fn ascii(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| match byte {
            0x20..=0x7e => *byte as char,
            _ => '?',
        })
        .collect();
    String::from(text.trim())
}

/// One disk several owners share, each through its own [`Window`]: the
/// disk's request queue. The owners may run on different processors at once
/// (a guest's storage on any PE, the host's NOR and log stores on another),
/// so each reaches the disk under its lock, which no one holds while the
/// device works on queued commands: the owners' commands wait in order, the
/// device runs as many as it has room for, and whichever owner next looks
/// for a result collects every completed one and starts those waiting
/// ([`Window::finish`]). Consecutive waiting reads, or writes, of adjoining
/// blocks go to the device as one command, as Linux's block layer merges
/// them.
#[derive(Clone)]
pub struct Shared(Arc<Disk>);

struct Disk {
    held: AtomicBool,
    profile_callbacks: AtomicBool,
    activity: profile::Activity,
    device: UnsafeCell<Box<dyn BlockDevice>>,
    requests: UnsafeCell<Requests>,
}

/// The owners' commands, by ticket: those waiting in order with the
/// counter when each was submitted, those the device runs and the results
/// no owner has taken yet; and the disk's accounting, with the counter
/// when the device last went from idle to running a command.
#[derive(Default)]
struct Requests {
    waiting: VecDeque<(u32, Command, u64)>,
    running: Vec<Merged>,
    finished: BTreeMap<u32, Finished>,
    next: u32,
    stats: Stats,
    busy_since: u64,
}

/// A device command and the tickets merged into it: each ticket's offset
/// and length in a read's data. What the accounting counts it as, and when
/// its first ticket was submitted.
struct Merged {
    tag: u32,
    tickets: Vec<(u32, usize, usize)>,
    accounted: (Direction, u64),
    submitted: u64,
}

// SAFETY: a device reaches the disk only through its own state and the
// controller's registers, not through anything of the processor that made
// it, and `Shared::lock` lets one processor at a time reach it.
unsafe impl Send for Disk {}
// SAFETY: as for `Send`; every access holds the lock.
unsafe impl Sync for Disk {}

/// The disk, held until dropped.
struct Held<'a>(&'a Disk);

impl Deref for Held<'_> {
    type Target = Box<dyn BlockDevice>;
    fn deref(&self) -> &Self::Target {
        // SAFETY: the lock is held, so no other reference to the device lives.
        unsafe { &*self.0.device.get() }
    }
}

impl DerefMut for Held<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as for `deref`.
        unsafe { &mut *self.0.device.get() }
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

/// `next` joined to the end of `command` when it continues it, within the
/// device's transfer limit: both reads, or both writes asking the same
/// durability. The joined length of `next` in a read's data, or `None`.
fn merge(command: &mut Command, next: &Command, block: usize, limit: usize) -> Option<usize> {
    let limit = if limit == 0 { usize::MAX } else { limit };
    match (command, next) {
        (
            Command::Read { lba, bytes },
            Command::Read {
                lba: at,
                bytes: more,
            },
        ) if *lba + (*bytes / block) as u64 == *at && *bytes + more <= limit => {
            *bytes += more;
            Some(*more)
        }
        (
            Command::Write { lba, data, fua },
            Command::Write {
                lba: at,
                data: more,
                fua: also,
            },
        ) if fua == also
            && *lba + (data.len() / block) as u64 == *at
            && data.len() + more.len() <= limit =>
        {
            data.extend_from_slice(more);
            Some(0)
        }
        _ => None,
    }
}

impl Held<'_> {
    fn requests(&mut self) -> &mut Requests {
        // SAFETY: the lock is held; the requests are apart from the device.
        unsafe { &mut *self.0.requests.get() }
    }

    /// Whether no command waits or runs: a transfer may reach the device
    /// directly.
    fn idle(&mut self) -> bool {
        let requests = self.requests();
        requests.running.is_empty() && requests.waiting.is_empty()
    }

    /// Queue `command`; its ticket.
    fn submit(&mut self, command: Command) -> u32 {
        let requests = self.requests();
        let ticket = requests.next;
        requests.next = requests.next.wrapping_add(1);
        requests
            .waiting
            .push_back((ticket, command, crate::Clock::ticks()));
        self.advance();
        ticket
    }

    /// Count a command `accounted` as, with `merges` requests joined into
    /// it, submitted at `submitted` and completed at `now`.
    fn account(
        &mut self,
        (direction, bytes): (Direction, u64),
        merges: u64,
        submitted: u64,
        now: u64,
    ) {
        let counts = &mut self.requests().stats.directions[direction as usize];
        counts.ios += 1;
        counts.merges += merges;
        counts.bytes += bytes;
        counts.ticks += now.wrapping_sub(submitted);
    }

    /// Run `run` on the device, which runs nothing else meanwhile, as one
    /// command `accounted` as and submitted at `submitted`.
    fn direct<T>(
        &mut self,
        accounted: (Direction, u64),
        submitted: u64,
        run: impl FnOnce(&mut Box<dyn BlockDevice>) -> T,
    ) -> T {
        let observing = self.0.profile_callbacks.load(Ordering::Relaxed);
        let started = crate::Clock::ticks();
        let disk = self.0;
        let _active = observing.then(|| disk.activity.direct.enter(started));
        let result = run(self);
        let now = crate::Clock::ticks();
        let stats = &mut self.requests().stats;
        stats.busy += now.wrapping_sub(started);
        stats.deepest = stats.deepest.max(1);
        if observing {
            self.requests()
                .stats
                .callbacks
                .get_or_insert_default()
                .direct
                .record(now.wrapping_sub(started), profile::Work::default());
        }
        self.account(accounted, 0, submitted, now);
        result
    }

    /// The disk's accounting, its device's time running a command so far
    /// included.
    fn stats(&mut self) -> Stats {
        let requests = self.requests();
        let mut stats = requests.stats;
        if !requests.running.is_empty() {
            stats.busy += crate::Clock::ticks().wrapping_sub(requests.busy_since);
        }
        stats
    }

    /// Collect the device's completed commands, then start those waiting
    /// while it has room. A device that takes no queued commands runs each
    /// here, its caller waiting.
    fn advance(&mut self) {
        let observing = self.0.profile_callbacks.load(Ordering::Relaxed);
        let started = observing.then(crate::Clock::ticks);
        let disk = self.0;
        let _active = started.map(|ticks| disk.activity.advance.enter(ticks));
        let mut work = profile::Work::default();
        self.advance_inner(&mut work);
        if let Some(started) = started {
            let elapsed = crate::Clock::ticks().wrapping_sub(started);
            self.requests()
                .stats
                .callbacks
                .get_or_insert_default()
                .advance
                .record(elapsed, work);
        }
    }

    fn advance_inner(&mut self, work: &mut profile::Work) {
        let mut index = 0;
        while index < self.requests().running.len() {
            let tag = self.requests().running[index].tag;
            let Some(result) = self.finish(tag) else {
                index += 1;
                continue;
            };
            work.finishes = work.finishes.saturating_add(1);
            let merged = self.requests().running.swap_remove(index);
            let now = crate::Clock::ticks();
            let merges = merged.tickets.len() as u64 - 1;
            self.account(merged.accounted, merges, merged.submitted, now);
            let requests = self.requests();
            if requests.running.is_empty() {
                requests.stats.busy += now.wrapping_sub(requests.busy_since);
            }
            let finished = &mut self.requests().finished;
            for (ticket, offset, bytes) in merged.tickets {
                let part = match &result {
                    Ok(Some(data)) => Ok(Some(data[offset..offset + bytes].to_vec())),
                    other => other.clone(),
                };
                finished.insert(ticket, part);
            }
        }
        let queued = self.depth() > 0;
        let (block, limit) = {
            let identity = self.identity();
            (identity.block_size as usize, identity.features.max_transfer)
        };
        loop {
            if queued && !self.room() {
                return;
            }
            let Some((ticket, mut command, submitted)) = self.requests().waiting.pop_front() else {
                return;
            };
            if !queued {
                let accounted = command.accounted(block);
                let result = self.direct(accounted, submitted, |device| device.execute(command));
                self.requests().finished.insert(ticket, result);
                continue;
            }
            let first = match &command {
                Command::Read { bytes, .. } => *bytes,
                _ => 0,
            };
            let mut tickets = vec![(ticket, 0, first)];
            let mut offset = first;
            while let Some((next, following, _)) = self.requests().waiting.front() {
                let Some(bytes) = merge(&mut command, following, block, limit) else {
                    break;
                };
                tickets.push((*next, offset, bytes));
                offset += bytes;
                self.requests().waiting.pop_front();
            }
            let accounted = command.accounted(block);
            work.starts = work.starts.saturating_add(1);
            match self.start(command) {
                Ok(tag) => {
                    let requests = self.requests();
                    if requests.running.is_empty() {
                        requests.busy_since = crate::Clock::ticks();
                    }
                    requests.running.push(Merged {
                        tag,
                        tickets,
                        accounted,
                        submitted,
                    });
                    requests.stats.deepest = requests.stats.deepest.max(requests.running.len());
                }
                Err(error) => {
                    for (ticket, ..) in tickets {
                        self.requests().finished.insert(ticket, Err(error.clone()));
                    }
                }
            }
        }
    }

    /// Ticket `ticket`'s result, once it has one.
    fn take(&mut self, ticket: u32) -> Option<Finished> {
        self.advance();
        self.requests().finished.remove(&ticket)
    }
}

impl Shared {
    pub fn new(device: Box<dyn BlockDevice>) -> Self {
        Self(Arc::new(Disk {
            held: AtomicBool::new(false),
            profile_callbacks: AtomicBool::new(false),
            activity: profile::Activity::default(),
            device: UnsafeCell::new(device),
            requests: UnsafeCell::new(Requests::default()),
        }))
    }

    /// Observe callback wall time from subsequent operations. Default off;
    /// disabling keeps earlier observations and adds no timing reads.
    pub fn set_callback_profile(&self, enabled: bool) {
        self.0.profile_callbacks.store(enabled, Ordering::Relaxed);
    }

    /// Bounded observations without taking the disk's lock or touching a driver.
    /// Enabled samples bracket independent generation/start reads with counters;
    /// disabling adds no counter reads. None means profiling is disabled.
    /// Activity never grants completion, DMA or quiescence permission.
    pub fn callback_activity(&self) -> Option<CallbackActivity> {
        if !self.0.profile_callbacks.load(Ordering::Relaxed) {
            return None;
        }
        let observed_before_ticks = crate::Clock::ticks();
        let advance = self.0.activity.advance.snapshot();
        let direct = self.0.activity.direct.snapshot();
        let observed_after_ticks = crate::Clock::ticks();
        Some(CallbackActivity {
            observed_before_ticks,
            observed_after_ticks,
            advance,
            direct,
        })
    }

    /// Callback observations with one try-lock and no counter read.
    /// None means disabled, not yet observed, or currently held by an owner.
    /// This snapshot grants no DMA, mapping or quiescence permission.
    pub fn callback_stats(&self) -> Option<CallbackStats> {
        if !self.0.profile_callbacks.load(Ordering::Relaxed)
            || self
                .0
                .held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        Held(&self.0).requests().stats.callbacks
    }

    /// The disk, once no other owner is using it.
    fn lock(&self) -> Held<'_> {
        while self
            .0
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Held(&self.0)
    }

    /// Run `command` to completion, the caller waiting: at once while no
    /// queued command is ahead of it, else in its turn.
    fn run(&self, command: Command) -> Finished {
        let ticket = {
            let mut disk = self.lock();
            if disk.idle() {
                let accounted = command.accounted(disk.identity().block_size as usize);
                return disk.direct(accounted, crate::Clock::ticks(), |device| {
                    device.execute(command)
                });
            }
            disk.submit(command)
        };
        loop {
            if let Some(result) = self.lock().take(ticket) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// The disk's I/O accounting since it was shared.
    pub fn stats(&self) -> Stats {
        self.lock().stats()
    }

    /// Whether `other` shares this same disk.
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Shut the disk down, as [`BlockDevice::shutdown`]; once for all its
    /// windows, after every queued command.
    pub fn shutdown(&self, power_off: bool) -> Result<(), BlockError> {
        let mut disk = self.lock();
        while !disk.idle() {
            disk.advance();
            core::hint::spin_loop();
        }
        disk.shutdown(power_off)
    }

    /// Every block, as a device of its own.
    pub fn whole(&self) -> Window {
        let identity = self.lock().identity().clone();
        Window {
            disk: self.clone(),
            first: 0,
            identity,
            started: Vec::new(),
        }
    }

    /// The `blocks` blocks from `first`, as a device of their own.
    pub fn window(&self, first: u64, blocks: u64) -> Result<Window, BlockError> {
        let mut identity = self.lock().identity().clone();
        match first.checked_add(blocks) {
            Some(end) if end <= identity.blocks => (),
            _ => return Err(range(&identity, first, blocks)),
        }
        identity.blocks = blocks;
        Ok(Window {
            disk: self.clone(),
            first,
            identity,
            started: Vec::new(),
        })
    }

    /// The blocks of `runs`, each a first block and a count, in order, as
    /// one device: a file's clusters where they lie on the disk.
    pub fn runs(&self, runs: Vec<(u64, u64)>) -> Result<Runs, BlockError> {
        let mut identity = self.lock().identity().clone();
        let mut blocks = 0u64;
        for &(first, count) in &runs {
            match first.checked_add(count) {
                Some(end) if end <= identity.blocks => blocks += count,
                _ => return Err(range(&identity, first, count)),
            }
        }
        identity.blocks = blocks;
        Ok(Runs {
            disk: self.clone(),
            runs,
            identity,
        })
    }
}

/// The commands a [`Window`] keeps in its disk's queue at most.
const WINDOW_DEPTH: usize = 64;

/// A run of blocks of a [`Shared`] disk.
pub struct Window {
    disk: Shared,
    first: u64,
    identity: Identity,
    /// The tickets of this window's started commands not yet finished.
    started: Vec<u32>,
}

impl Window {
    /// The disk this window is part of.
    pub fn shared(&self) -> &Shared {
        &self.disk
    }

    fn run(&self, command: Command) -> Result<(), BlockError> {
        let command = command.within(&self.identity, self.first)?;
        self.disk.run(command).map(drop)
    }
}

impl BlockDevice for Window {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        let mut disk = self.disk.lock();
        if disk.idle() {
            let accounted = (Direction::Read, buffer.len() as u64);
            let lba = self.first + lba;
            return disk.direct(accounted, crate::Clock::ticks(), |device| {
                device.read(lba, buffer)
            });
        }
        drop(disk);
        let command = Command::Read {
            lba: self.first + lba,
            bytes: buffer.len(),
        };
        let data = self.disk.run(command)?;
        buffer.copy_from_slice(&data.ok_or(BlockError::Protocol("a read returned no data"))?);
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let mut disk = self.disk.lock();
        if disk.idle() {
            let accounted = (Direction::Write, data.len() as u64);
            let lba = self.first + lba;
            return disk.direct(accounted, crate::Clock::ticks(), |device| {
                device.write(lba, data)
            });
        }
        drop(disk);
        self.run(Command::Write {
            lba,
            data: data.to_vec(),
            fua: false,
        })
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.run(Command::Flush)
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.run(Command::Write {
            lba,
            data: data.to_vec(),
            fua: true,
        })
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.run(Command::Discard { lba, blocks })
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        self.run(Command::WriteZeroes { lba, blocks, unmap })
    }

    /// Every window takes queued commands: its disk runs them in turn.
    fn depth(&self) -> usize {
        WINDOW_DEPTH
    }

    fn room(&self) -> bool {
        self.started.len() < WINDOW_DEPTH
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let command = command.within(&self.identity, self.first)?;
        if !self.room() {
            return Err(BlockError::Protocol("the disk window queue is full"));
        }
        let ticket = self.disk.lock().submit(command);
        self.started.push(ticket);
        Ok(ticket)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        let finished = self.disk.lock().take(tag)?;
        self.started.retain(|&ticket| ticket != tag);
        Some(finished)
    }

    /// One of this window's commands has a result, or the disk has posted
    /// a completion: another window's results never count.
    fn posted(&self) -> bool {
        let mut disk = self.disk.lock();
        let finished = &disk.requests().finished;
        self.started
            .iter()
            .any(|ticket| finished.contains_key(ticket))
            || disk.posted()
    }

    fn signals(&self) -> bool {
        self.disk.lock().signals()
    }
}

/// Runs of blocks of a [`Shared`] disk, one after another as one device.
pub struct Runs {
    disk: Shared,
    runs: Vec<(u64, u64)>,
    identity: Identity,
}

impl Runs {
    /// The disk's blocks for `blocks` blocks from `lba`, which
    /// [`Identity::check`] has kept inside the device: each piece's first
    /// disk block, and its first block and count in the transfer.
    fn pieces(&self, lba: u64, blocks: u64) -> Vec<(u64, usize, usize)> {
        let (mut start, mut pieces) = (0, Vec::new());
        let end = lba + blocks;
        for &(first, count) in &self.runs {
            let (from, to) = (lba.max(start), end.min(start + count));
            if from < to {
                pieces.push((
                    first + from - start,
                    (from - lba) as usize,
                    (to - from) as usize,
                ));
            }
            start += count;
        }
        pieces
    }

    /// Write `data` at `lba` piece by piece, each in its turn among the
    /// disk's queued commands.
    fn write_pieces(&mut self, lba: u64, data: &[u8], fua: bool) -> Result<(), BlockError> {
        let blocks = self.identity.check_write(lba, data.len())?;
        let size = self.identity.block_size as usize;
        for (at, from, count) in self.pieces(lba, blocks) {
            self.disk.run(Command::Write {
                lba: at,
                data: data[from * size..(from + count) * size].to_vec(),
                fua,
            })?;
        }
        Ok(())
    }

    /// `command` for each piece of `blocks` blocks from `lba`.
    fn each(
        &mut self,
        lba: u64,
        blocks: u64,
        command: impl Fn(u64, u64) -> Command,
    ) -> Result<(), BlockError> {
        let size = self.identity.block_size as usize;
        self.identity.check_write(lba, blocks as usize * size)?;
        for (at, _, count) in self.pieces(lba, blocks) {
            self.disk.run(command(at, count as u64))?;
        }
        Ok(())
    }
}

impl BlockDevice for Runs {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Each piece in its turn among the disk's queued commands.
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let blocks = self.identity.check(lba, buffer.len())?;
        let size = self.identity.block_size as usize;
        for (at, from, count) in self.pieces(lba, blocks) {
            let part = &mut buffer[from * size..(from + count) * size];
            let command = Command::Read {
                lba: at,
                bytes: part.len(),
            };
            let data = self.disk.run(command)?;
            part.copy_from_slice(&data.ok_or(BlockError::Protocol("a read returned no data"))?);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write_pieces(lba, data, false)
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write_pieces(lba, data, true)
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.disk.run(Command::Flush).map(drop)
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.each(lba, blocks, |lba, blocks| Command::Discard { lba, blocks })
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        self.each(lba, blocks, |lba, blocks| Command::WriteZeroes {
            lba,
            blocks,
            unmap,
        })
    }
}

/// Sequential read-ahead over a device that takes queued commands, as an
/// operating system's page cache reads a file ahead: [`ReadAhead::pump`]
/// keeps `depth` chunks after the last read in memory or in flight, never
/// waiting, and a read finds them in memory. A read memory lacks reads the
/// device directly and starts the read-ahead over after it.
pub struct ReadAhead {
    device: Box<dyn BlockDevice>,
    /// Blocks per read-ahead request, and requests kept ahead.
    chunk: u64,
    depth: usize,
    /// Chunks read ahead, by first block.
    ready: BTreeMap<u64, Vec<u8>>,
    /// The first block of the next chunk to read ahead.
    next: u64,
    /// The first block a reader may still want.
    wanted: u64,
    /// The chunks being read, by first block.
    running: Vec<(u64, Submission)>,
}

impl ReadAhead {
    /// Read `device` ahead in requests of `chunk_bytes`, keeping `depth`.
    pub fn new(device: Box<dyn BlockDevice>, chunk_bytes: usize, depth: usize) -> Self {
        let block = u64::from(device.identity().block_size.max(1));
        Self {
            chunk: (chunk_bytes as u64 / block).max(1),
            depth,
            ready: BTreeMap::new(),
            next: 0,
            wanted: 0,
            running: Vec::new(),
            device,
        }
    }

    /// Collect completed read-aheads and submit the next; never waits. A
    /// device without queued commands is read only when asked.
    pub fn pump(&mut self) {
        if self.device.depth() == 0 {
            return;
        }
        let block = self.device.identity().block_size as u64;
        let mut index = 0;
        while index < self.running.len() {
            let Some(finished) = self.running[index].1.poll(&mut *self.device) else {
                index += 1;
                continue;
            };
            let (first, _) = self.running.swap_remove(index);
            // A failed read-ahead is read again when asked, directly.
            if let Ok(Some(data)) = finished
                && first + data.len() as u64 / block > self.wanted
            {
                self.ready.insert(first, data);
            }
        }
        let blocks = self.device.identity().blocks;
        while self.ready.len() + self.running.len() < self.depth
            && self.next < blocks
            && self.device.room()
        {
            let count = self.chunk.min(blocks - self.next);
            let request = Request::Read {
                lba: self.next,
                bytes: (count * block) as usize,
            };
            let Ok(mut submission) = Submission::new(request, self.device.identity()) else {
                return;
            };
            if let Some(Err(_)) = submission.poll(&mut *self.device) {
                return;
            }
            self.running.push((self.next, submission));
            self.next += count;
        }
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let block = self.device.identity().block_size as usize;
        let blocks = (buffer.len() / block) as u64;
        // Chunks wholly before this read are not read again.
        while let Some((&first, data)) = self.ready.first_key_value() {
            if first + (data.len() / block) as u64 > lba {
                break;
            }
            self.ready.pop_first();
        }
        let mut at = 0;
        while at < blocks {
            let want = lba + at;
            let found = self
                .ready
                .range(..=want)
                .next_back()
                .filter(|(first, data)| **first + (data.len() / block) as u64 > want)
                .map(|(first, data)| (*first, data));
            let Some((first, data)) = found else {
                break;
            };
            let from = (want - first) as usize * block;
            let count = (data.len() - from).min((blocks - at) as usize * block);
            let to = at as usize * block;
            buffer[to..to + count].copy_from_slice(&data[from..from + count]);
            at += (count / block) as u64;
        }
        self.wanted = lba + blocks;
        if at < blocks {
            // A miss: read the rest here and read ahead from its end, unless
            // a read in flight already covers it.
            let to = at as usize * block;
            self.device.read(lba + at, &mut buffer[to..])?;
            self.ready.clear();
            if !self.running.iter().any(|(first, _)| *first == self.wanted) {
                self.next = self.wanted;
            }
        } else if self.running.is_empty() && self.ready.is_empty() {
            self.next = self.next.max(self.wanted);
        }
        Ok(())
    }
}

/// A [`ReadAhead`] shared by its reader and whoever pumps it.
#[derive(Clone)]
pub struct Ahead {
    pub inner: alloc::rc::Rc<core::cell::RefCell<ReadAhead>>,
    identity: Identity,
}

impl Ahead {
    pub fn new(ahead: ReadAhead) -> Self {
        let identity = ahead.device.identity().clone();
        Self {
            inner: alloc::rc::Rc::new(core::cell::RefCell::new(ahead)),
            identity,
        }
    }

    pub fn pump(&self) {
        self.inner.borrow_mut().pump();
    }
}

impl BlockDevice for Ahead {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        self.inner.borrow_mut().read(lba, buffer)
    }

    fn write(&mut self, _lba: u64, _data: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

/// Engine memory as a disk that keeps nothing past power-off. Blocks read
/// as zeros until written; a written chunk takes [`Volatile::CHUNK`] bytes
/// of the heap, at most `limit` bytes in all, and a write that needs more
/// refuses whole. Writing zeros where nothing was written takes nothing.
pub struct Volatile {
    identity: Identity,
    chunks: BTreeMap<u64, Box<[u8]>>,
    limit: usize,
}

impl Volatile {
    pub const BLOCK: u32 = 4096;
    pub const CHUNK: usize = 64 * 1024;

    /// A `bytes`-long disk, a nonzero whole number of chunks, named
    /// `serial`, that may keep at most `limit` written bytes.
    pub fn new(serial: &str, bytes: u64, limit: usize) -> Result<Self, BlockError> {
        if bytes == 0 || !bytes.is_multiple_of(Self::CHUNK as u64) {
            return Err(BlockError::Unsupported(
                "a RAM-backed disk is a nonzero whole number of 64 KiB chunks",
            ));
        }
        Ok(Self {
            identity: Identity {
                transport: Transport::Ram,
                location: String::from("engine memory"),
                model: String::from("Stela volatile disk"),
                serial: String::from(serial),
                blocks: bytes / u64::from(Self::BLOCK),
                block_size: Self::BLOCK,
                read_only: false,
                features: Features {
                    discard: Some(0),
                    write_zeroes: Some(WriteZeroes {
                        blocks: 0,
                        unmap: true,
                    }),
                    ..Features::default()
                },
            },
            chunks: BTreeMap::new(),
            limit,
        })
    }

    /// The chunks a checked `len`-byte transfer at `lba` touches: each
    /// chunk's index, the offset in it, and the range of the transfer.
    fn pieces(lba: u64, len: usize) -> impl Iterator<Item = (u64, usize, core::ops::Range<usize>)> {
        let start = lba * u64::from(Self::BLOCK);
        let mut done = 0;
        core::iter::from_fn(move || {
            (done < len).then(|| {
                let at = start + done as u64;
                let within = (at % Self::CHUNK as u64) as usize;
                let n = (Self::CHUNK - within).min(len - done);
                let piece = (at / Self::CHUNK as u64, within, done..done + n);
                done += n;
                piece
            })
        })
    }
}

impl BlockDevice for Volatile {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        for (chunk, within, range) in Self::pieces(lba, buffer.len()) {
            let n = range.len();
            match self.chunks.get(&chunk) {
                Some(bytes) => buffer[range].copy_from_slice(&bytes[within..within + n]),
                None => buffer[range].fill(0),
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let written = |range: &core::ops::Range<usize>| data[range.clone()].iter().any(|&b| b != 0);
        let new = Self::pieces(lba, data.len())
            .filter(|(chunk, _, range)| !self.chunks.contains_key(chunk) && written(range))
            .count();
        if (self.chunks.len() + new) * Self::CHUNK > self.limit {
            return Err(BlockError::Unsupported(
                "the RAM-backed disk has used all the memory it may take",
            ));
        }
        for (chunk, within, range) in Self::pieces(lba, data.len()) {
            let n = range.len();
            if let Some(bytes) = self.chunks.get_mut(&chunk) {
                bytes[within..within + n].copy_from_slice(&data[range]);
            } else if written(&range) {
                let mut bytes = vec![0; Self::CHUNK].into_boxed_slice();
                bytes[within..within + n].copy_from_slice(&data[range]);
                self.chunks.insert(chunk, bytes);
            }
        }
        Ok(())
    }

    /// Zeroed chunks give their memory back.
    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.write_zeroes(lba, blocks, true)
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, _unmap: bool) -> Result<(), BlockError> {
        let len = usize::try_from(blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(Self::BLOCK as usize))
            .ok_or_else(|| range(&self.identity, lba, blocks))?;
        self.identity.check_write(lba, len)?;
        for (chunk, within, range) in Self::pieces(lba, len) {
            if range.len() == Self::CHUNK {
                self.chunks.remove(&chunk);
            } else if let Some(bytes) = self.chunks.get_mut(&chunk) {
                bytes[within..within + range.len()].fill(0);
            }
        }
        Ok(())
    }
}

/// A RAM disk for the partition and selection tests.
#[cfg(any(test, feature = "ram-disk"))]
pub struct RamDisk {
    pub identity: Identity,
    pub bytes: Vec<u8>,
    pub flushes: usize,
}

#[cfg(any(test, feature = "ram-disk"))]
impl RamDisk {
    pub fn new(serial: &str, blocks: u64, block_size: u32) -> Self {
        Self {
            identity: Identity {
                transport: Transport::VirtioBlk,
                location: String::from("test"),
                model: String::from("RAM"),
                serial: String::from(serial),
                blocks,
                block_size,
                read_only: false,
                features: Features::default(),
            },
            bytes: vec![0; (blocks * u64::from(block_size)) as usize],
            flushes: 0,
        }
    }

    fn span(&self, lba: u64, bytes: usize) -> core::ops::Range<usize> {
        let start = (lba * u64::from(self.identity.block_size)) as usize;
        start..start + bytes
    }
}

#[cfg(any(test, feature = "ram-disk"))]
impl BlockDevice for RamDisk {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        buffer.copy_from_slice(&self.bytes[self.span(lba, buffer.len())]);
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let span = self.span(lba, data.len());
        self.bytes[span].copy_from_slice(data);
        Ok(())
    }

    /// Counted, for a test that reports a write cache.
    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.flushes += 1;
        Ok(())
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write(lba, data)
    }
}

#[cfg(test)]
mod tests;
