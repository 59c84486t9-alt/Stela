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

mod layers;
mod shared;
#[cfg(any(test, feature = "ram-disk"))]
pub use layers::RamDisk;
pub use layers::{Ahead, ReadAhead, Runs, Volatile};
pub use shared::{Shared, Window};
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

    /// The commands the device runs for this submission now.
    pub fn started(&self) -> usize {
        self.running.len()
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
pub fn ascii(bytes: &[u8]) -> String {
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

#[cfg(test)]
mod tests;
