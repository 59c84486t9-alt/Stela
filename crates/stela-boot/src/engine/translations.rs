//! `stela.efi`'s persistent translation store: the pack file `stela setup`
//! makes room for in `stela/store` on the boot USB's FAT32 data partition.
//!
//! The file is a journal (`stela_formats::journal`) of pack segments and of
//! used-key lists, one per boot (`translations::pack`): an update writes
//! only into space the newest commit does not use and then commits, so a
//! write cut by a power loss, a panic or a forced stop leaves the previous
//! content whole.
//!
//! Before boot services end, [`read`] finds the volume with `store.cfg`,
//! gives this translator the preallocated spare file when it has no pack
//! yet, reads the newest commit's segments and lists, as many segments as
//! this PC's RAM budget holds (the newest first), and notes the volume's GPT
//! partition. The engine reads blocks from the segments ([`install`]), a
//! key's record merged from all that hold it, and keeps the stored form of
//! each block it compiles anew. While the guest runs, [`step`] writes those
//! entries to the file as new segments and, every few boots, merges the
//! segments and lists into one, a bounded step at a time on processors whose
//! guest waits; when the guest restarts or powers off, [`write`] writes what
//! is left and this boot's used-key list. The pack is a cache: every failure
//! leaves the boot running without a store, or without writing it.
//!
//! When every PE runs on its own host core (the default), their machines
//! share the store ([`Shared`]), split by page key into parts behind locks
//! of their own, and it keeps the blocks any of them compiled for the others
//! to install ([`share`]).
use super::bundle::Bytes;
use super::store_file::{Direct, Held, Queued, Staged};
use crate::{firmware, handoff::Region, output, paging::PAGE};
use alloc::{boxed::Box, collections::BTreeMap, format, string::String, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use stela_boot_core::host_memory::PACK_FLOOR;
use stela_crypto::{Sha256, digest::Digest as _};
use stela_drivers::block::BlockDevice;
use stela_engine::machine::Offer;
use stela_engine::machine::Translations;
use stela_engine::machine::engine::StoreEvent;
use stela_engine::translations;
use stela_engine::translations::Digest;
use stela_engine::translations::Record;
use stela_engine::translations::pack;
use stela_engine::translations::pack::{
    DecodedRecord, Delta, Layout, MAX_SEGMENTS, MAX_USED_KEYS, MAX_USED_LISTS, Merge, Pack,
    StagedOffer, Store, UsedKeys,
};
use stela_formats::journal::{self, Blob, Change, Commit, DATA_START, Execution, SLOT_BYTES, Step};
use stela_formats::payload::pieces::Extent;
use stela_runtime::pc::fat32::Fat32;
use stela_runtime::pc::gpt::Guid;
use stela_runtime::translation_store;
use uefi::{
    CString16, boot,
    proto::{
        device_path::{DevicePath, DevicePathNodeEnum, media::PartitionSignature},
        media::{
            file::{Directory, File as _, FileAttribute, FileInfo, FileMode, RegularFile},
            fs::SimpleFileSystem,
        },
    },
};

/// The handoff file holding the store's placement and what was read of its
/// pack file.
pub const FILE: &str = "translations";
/// The store's directory on its volume, and `stela setup`'s bound there.
pub(super) const DIRECTORY: &str = "stela\\store";
const CONFIG: &str = "store.cfg";
const BYTES_KEY: &str = "bytes";
const CONFIG_LIMIT: usize = 256;
/// A pack file's name: the first bytes of its translator id in hex, an 8.3
/// name the FAT32 reader finds.
const NAME_BYTES: usize = 4;
const PACK_EXTENSION: &str = "pak";
/// A blank, preallocated pack file `stela setup` keeps beside the packs: a
/// new translator's pack takes it by rename. The boot never grows a file,
/// which the firmware does by writing every byte.
const SPARE: &str = "spare.bin";
/// The pack is read in steps of this many bytes, each shown as progress.
const PROGRESS_STEP: usize = 16 << 20;
/// The journal's domain, and the kinds of its blobs: pack segments and
/// used-key lists.
const DOMAIN: [u8; 8] = pack::JOURNAL_DOMAIN;
const SEGMENT: u32 = pack::SEGMENT_BLOB;
const USED: u32 = pack::USED_BLOB;
/// The placement record at the start of the handoff file: magic, the bound
/// the engine writes within, partition GUID, flags, the commit's entry
/// count and the file's size. The commit's slot ([`SLOT_BYTES`], zeros for
/// none), the bytes held of each entry and those bytes, each from an 8-byte
/// boundary, follow.
const PLACEMENT_MAGIC: [u8; 8] = *b"STLTSTO2";
const PLACEMENT_BYTES: usize = 64;
/// The pack file holds the bound's bytes and its volume's partition is
/// known: the engine may write it.
const WRITABLE: u32 = 1;
/// A segment was left out or cut to the budget: a merge would lose what
/// was not read, so none runs.
const PARTIAL: u32 = 2;
/// The words of the buffer a renamed file's `FileInfo` is built in: its
/// fixed fields and an 8.3 name.
const FILE_INFO_WORDS: usize = 64;

/// The pack file's name in the store's directory.
fn pack_name(translator: &Digest) -> String {
    format!("{}.{PACK_EXTENSION}", hex(&translator.0[..NAME_BYTES]))
}

/// The pack file's path, with `separator` between components.
fn pack_path(translator: &Digest, separator: &str) -> String {
    format!(
        "{}{separator}{}",
        DIRECTORY.replace('\\', separator),
        pack_name(translator)
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn open(root: &mut Directory, path: &str, mode: FileMode) -> Option<RegularFile> {
    let path = CString16::try_from(path).ok()?;
    root.open(&path, mode, FileAttribute::empty())
        .ok()?
        .into_regular_file()
}

/// Read `buffer.len()` bytes from the current file position.
pub(super) fn read_exact(file: &mut RegularFile, buffer: &mut [u8]) -> Option<()> {
    let mut done = 0;
    while done < buffer.len() {
        let count = file.read(&mut buffer[done..]).ok()?;
        if count == 0 {
            return None;
        }
        done += count;
    }
    Some(())
}

/// `buffer.len()` bytes from `offset`.
fn read_at(file: &mut RegularFile, offset: u64, buffer: &mut [u8]) -> Option<()> {
    file.set_position(offset).ok()?;
    read_exact(file, buffer)
}

/// `store.cfg`'s bound.
pub(super) fn bound(root: &mut Directory) -> Option<u64> {
    let mut file = open(root, &format!("{DIRECTORY}\\{CONFIG}"), FileMode::Read)?;
    let mut text = vec![0; CONFIG_LIMIT];
    let mut done = 0;
    while done < text.len() {
        let count = file.read(&mut text[done..]).ok()?;
        if count == 0 {
            break;
        }
        done += count;
    }
    core::str::from_utf8(&text[..done])
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix(BYTES_KEY)?.trim().parse().ok())
}

/// The GPT partition GUID of the volume on `handle`.
pub(crate) fn partition(handle: uefi::Handle) -> Option<[u8; 16]> {
    // SAFETY: the path is only read, while no driver changes this handle.
    let path = unsafe {
        boot::open_protocol::<DevicePath>(
            boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    path.node_iter().find_map(|node| match node.as_enum() {
        Ok(DevicePathNodeEnum::MediaHardDrive(drive)) => match drive.partition_signature() {
            PartitionSignature::Guid(guid) => Some(guid.to_bytes()),
            _ => None,
        },
        _ => None,
    })
}

/// What the loader read of the store's pack segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackRead {
    /// No pack yet, or one the engine would discard.
    None,
    /// All of the segments' `0` bytes.
    Whole(u64),
    /// `read` of their `held` bytes: the newest segments, and of the next
    /// the records that end within this PC's budget.
    Part { read: u64, held: u64 },
    /// None of it: this PC's budget holds less than the newest segment's
    /// index, or none at all. The pack stays on the volume, unwritten, for
    /// a PC with more RAM.
    Skipped,
}

/// The store the loader found: the handoff file's pages, whether the engine
/// can write its pack file, and what of the pack it read.
pub struct Opened {
    pub region: Region,
    pub writable: bool,
    pub pack: PackRead,
}

/// The store on the first volume with `store.cfg`, as the handoff file's
/// pages: run before boot services end, with no volume opened exclusively.
/// `budget` is the most of the pack this PC's RAM holds
/// (`host_memory::pack_budget`); the pack is read within it and the engine
/// merges it within it, so that it does not grow past what the next boot on
/// this PC can read. `None` when no volume has a store.
pub fn read(budget: u64) -> Option<Opened> {
    let translator = translations::translator_id();
    for handle in boot::find_handles::<SimpleFileSystem>().ok()? {
        let Ok(mut volume) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let Ok(mut root) = volume.open_volume() else {
            continue;
        };
        // The file's size, which `stela setup` allocated.
        let Some(bound) = bound(&mut root) else {
            continue;
        };
        let limit = bound.min(budget);
        let path = pack_path(&translator, "\\");
        if open(&mut root, &path, FileMode::Read).is_none() {
            claim_spare(&mut root, &translator);
        }
        // A read-only volume's pack is read and never written; a missing
        // one leaves the boot's translations in memory.
        let opened = open(&mut root, &path, FileMode::ReadWrite)
            .map(|file| (file, true))
            .or_else(|| open(&mut root, &path, FileMode::Read).map(|file| (file, false)));
        let partition = partition(handle);
        let reading = output::now();
        let (loaded, size, allocated) = match opened {
            Some((mut file, writable)) => {
                let size = file
                    .get_boxed_info::<FileInfo>()
                    .map_or(0, |info| info.file_size());
                let loaded = read_journal(&mut file, &translator, size, limit)?;
                (loaded, size, writable && size >= bound)
            }
            None => (blank()?, 0, false),
        };
        let (read, held) = match loaded.pack {
            PackRead::None | PackRead::Skipped => (0, 0),
            PackRead::Whole(bytes) => (bytes, bytes),
            PackRead::Part { read, held } => (read, held),
        };
        output::arguments(format_args!(
            "TRANSLATIONS {path} bound={bound} budget={budget} file={size} segments={} of {} \
             lists={} pack={read} held={held} skipped={} allocated={allocated} partition={} \
             read_ms={}\n",
            loaded.segments.0,
            loaded.segments.1,
            loaded.lists,
            loaded.pack == PackRead::Skipped,
            partition.is_some(),
            output::millis_since(reading)
        ));
        // Below the floor, or with its pack left for a larger PC, the boot
        // keeps its translations in memory.
        let writable = allocated
            && partition.is_some()
            && limit >= PACK_FLOOR
            && loaded.pack != PackRead::Skipped;
        let flags = if writable { WRITABLE } else { 0 } | if loaded.partial { PARTIAL } else { 0 };
        // SAFETY: the exclusive loader allocation starts with the placement
        // header, which `read_journal` and `blank` left zero.
        let placement = unsafe {
            core::slice::from_raw_parts_mut(loaded.region.physical as *mut u8, PLACEMENT_BYTES)
        };
        placement[..8].copy_from_slice(&PLACEMENT_MAGIC);
        placement[8..16].copy_from_slice(&limit.to_le_bytes());
        placement[16..32].copy_from_slice(&partition.unwrap_or_default());
        placement[32..36].copy_from_slice(&flags.to_le_bytes());
        placement[40..48].copy_from_slice(&size.to_le_bytes());
        return Some(Opened {
            region: loaded.region,
            writable,
            pack: loaded.pack,
        });
    }
    None
}

/// Give `translator` the spare pack file by renaming it, when the store
/// has one: the file keeps its preallocated clusters.
fn claim_spare(root: &mut Directory, translator: &Digest) {
    let Some(mut file) = open(root, &format!("{DIRECTORY}\\{SPARE}"), FileMode::ReadWrite) else {
        return;
    };
    let Ok(info) = file.get_boxed_info::<FileInfo>() else {
        return;
    };
    let Ok(name) = CString16::try_from(pack_name(translator).as_str()) else {
        return;
    };
    let mut storage = vec![0u64; FILE_INFO_WORDS];
    // SAFETY: the words' bytes, 8-byte aligned as FileInfo requires.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 8)
    };
    let Ok(renamed) = FileInfo::new(
        bytes,
        info.file_size(),
        info.physical_size(),
        *info.create_time(),
        *info.last_access_time(),
        *info.modification_time(),
        info.attribute(),
        &name,
    ) else {
        return;
    };
    let claimed = file.set_info(renamed).is_ok() && file.flush().is_ok();
    output::arguments(format_args!(
        "TRANSLATIONS spare {} as {name}\n",
        if claimed { "taken" } else { "refused" }
    ));
}

/// What [`read_journal`] read: the handoff region (its placement left
/// zero), the segments read of those committed, the used-key lists read,
/// and whether a segment was left out or cut.
struct Loaded {
    region: Region,
    pack: PackRead,
    segments: (usize, usize),
    lists: usize,
    partial: bool,
}

/// A handoff region of a placement and a blank commit slot.
fn blank() -> Option<Loaded> {
    let bytes = PLACEMENT_BYTES + SLOT_BYTES as usize;
    let physical = firmware::pages(bytes.div_ceil(PAGE)).ok()?;
    // SAFETY: firmware returned this exclusive allocation of `bytes` or more.
    unsafe { (physical as *mut u8).write_bytes(0, bytes) };
    Some(Loaded {
        region: Region {
            physical: physical as u64,
            bytes: bytes as u64,
        },
        pack: PackRead::None,
        segments: (0, 0),
        lists: 0,
        partial: false,
    })
}

/// Read the newest commit of the pack file of `size` bytes directly into
/// the handoff region: every used-key list, checked, and the segments, the
/// newest first, while they fit `limit`; of the first that does not, its
/// records that end within what is left, its index trimmed to name only
/// them (`translation_store::within`). Segments are not checked whole here:
/// a pack checks its index, and each record its own bytes when first used.
/// `None` only when no memory is left for the region.
fn read_journal(
    file: &mut RegularFile,
    translator: &Digest,
    size: u64,
    limit: u64,
) -> Option<Loaded> {
    let mut slots = vec![0; DATA_START as usize];
    let commit = if size >= DATA_START && read_exact(file, &mut slots).is_some() {
        journal::candidates(&slots, DOMAIN, size).into_iter().next()
    } else {
        None
    };
    drop(slots);
    let entries: &[journal::Entry] = match &commit {
        Some(commit) if commit.key == translator.0 => &commit.entries,
        _ => &[],
    };
    // What to hold of each entry: every list, and segments within the room
    // the lists leave, the newest first.
    let mut held: Vec<u64> = vec![0; entries.len()];
    let lists: u64 = entries
        .iter()
        .filter(|entry| entry.kind == USED)
        .map(|entry| entry.length)
        .sum();
    let mut room = limit.saturating_sub(lists);
    let mut partial = false;
    let mut trimmed: Option<(usize, Vec<u8>)> = None;
    for (index, entry) in entries.iter().enumerate().rev() {
        match entry.kind {
            USED => held[index] = entry.length,
            SEGMENT if partial => {}
            SEGMENT if entry.length <= room => {
                held[index] = entry.length;
                room -= entry.length;
            }
            SEGMENT => {
                partial = true;
                if let Some((length, prefix)) = segment_within(file, entry, translator, room) {
                    held[index] = length;
                    trimmed = Some((index, prefix));
                }
            }
            _ => {}
        }
    }
    let blobs: usize = held
        .iter()
        .map(|&length| (length as usize).next_multiple_of(8))
        .sum();
    let head = PLACEMENT_BYTES + SLOT_BYTES as usize + 8 * entries.len();
    let bytes = head + blobs;
    let pages = bytes.div_ceil(PAGE);
    let physical = firmware::pages(pages).ok()?;
    // SAFETY: firmware returned this exclusive allocation of `bytes` or
    // more. Initialize it before taking a mutable slice.
    let region = unsafe {
        let start = physical as *mut u8;
        start.write_bytes(0, bytes);
        core::slice::from_raw_parts_mut(start, bytes)
    };
    if let Some(commit) = &commit {
        region[PLACEMENT_BYTES..PLACEMENT_BYTES + SLOT_BYTES as usize]
            .copy_from_slice(&commit.encode());
    }
    region[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    let total = blobs >> 20;
    let mut at = head;
    let mut done = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let length = held[index] as usize;
        if length == 0 {
            continue;
        }
        let blob = &mut region[at..at + length];
        let mut from = 0;
        if let Some((_, prefix)) = trimmed.as_ref().filter(|(trim, _)| *trim == index) {
            blob[..prefix.len()].copy_from_slice(prefix);
            from = prefix.len();
        }
        let mut whole = true;
        for part in blob[from..].chunks_mut(PROGRESS_STEP) {
            if read_at(file, entry.offset + from as u64, part).is_none() {
                whole = false;
                break;
            }
            from += part.len();
            done += part.len();
            crate::status::progress(&format!("{} of {total} MB", done >> 20));
        }
        whole &= match entry.kind {
            USED => Sha256::digest(&*blob)[..] == entry.digest,
            _ => true,
        };
        if !whole {
            partial |= entry.kind == SEGMENT;
            held[index] = 0;
        } else if trimmed.as_ref().is_some_and(|(trim, _)| *trim == index) {
            translation_store::trim(blob);
        }
        at += length.next_multiple_of(8);
    }
    for (index, &length) in held.iter().enumerate() {
        let at = head - 8 * (entries.len() - index);
        region[at..at + 8].copy_from_slice(&length.to_le_bytes());
    }
    let segment = |index: usize| entries[index].kind == SEGMENT;
    let (mut read, mut whole, mut segments, mut committed) = (0, 0, 0, 0);
    for (index, &length) in held.iter().enumerate().filter(|(index, _)| segment(*index)) {
        committed += 1;
        whole += entries[index].length;
        if length != 0 {
            segments += 1;
            read += length;
        }
    }
    let pack = match () {
        () if committed == 0 => PackRead::None,
        () if segments == 0 => PackRead::Skipped,
        () if partial => PackRead::Part { read, held: whole },
        () => PackRead::Whole(read),
    };
    Some(Loaded {
        region: Region {
            physical: physical as u64,
            bytes: bytes as u64,
        },
        pack,
        segments: (segments, committed),
        lists: held
            .iter()
            .enumerate()
            .filter(|&(index, &length)| !segment(index) && length != 0)
            .count(),
        partial,
    })
}

/// Of the segment `entry` names, the bytes that hold its records ending
/// within `room`, and its header and index: `None` when none does or its
/// index fails the checks `Pack::parse` makes.
fn segment_within(
    file: &mut RegularFile,
    entry: &journal::Entry,
    translator: &Digest,
    room: u64,
) -> Option<(u64, Vec<u8>)> {
    let mut header = [0; pack::HEADER_BYTES];
    read_at(file, entry.offset, &mut header)?;
    let prefix_length = pack::prefix_bytes(&header, translator).ok()?;
    if prefix_length as u64 > room || prefix_length as u64 > entry.length {
        return None;
    }
    let mut prefix = vec![0; prefix_length];
    prefix[..header.len()].copy_from_slice(&header);
    read_exact(file, &mut prefix[header.len()..])?;
    let within = translation_store::within(&prefix, translator, room).ok()?;
    (within.records != 0 && within.length <= entry.length).then_some((within.length, prefix))
}

/// The boot's translator and the store's partition. Its parts ([`PARTS`])
/// hold the store itself.
struct Boot {
    translator: Digest,
    partition: Option<Box<dyn BlockDevice>>,
}

/// The parts a boot's store is split into by page key, each behind a lock
/// of its own, so that PEs looking up, sharing and offering blocks of
/// different pages do not wait for each other.
const PARTS: usize = 16;

/// A spin lock that counts how often it was found held and how long its
/// waiters spun.
#[repr(align(64))]
struct Lock<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
    acquired: AtomicU64,
    contended: AtomicU64,
    spun: AtomicU64,
}
// SAFETY: `with` holds `held` for every access to `value`.
unsafe impl<T> Sync for Lock<T> {}

impl<T> Lock<T> {
    const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
            acquired: AtomicU64::new(0),
            contended: AtomicU64::new(0),
            spun: AtomicU64::new(0),
        }
    }

    /// Run `f` on the value, alone. No interrupt handler reaches it.
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            let started = output::now();
            while self
                .held
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                while self.held.load(Ordering::Relaxed) {
                    core::hint::spin_loop();
                }
            }
            self.contended.fetch_add(1, Ordering::Relaxed);
            self.spun
                .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
        }
        self.acquired.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `held` excludes every other access until it is released.
        let result = f(unsafe { &mut *self.value.get() });
        self.held.store(false, Ordering::Release);
        result
    }
}

static BOOT: Lock<Option<Boot>> = Lock::new(None);
static STORES: [Lock<Option<Store<'static>>>; PARTS] = [const { Lock::new(None) }; PARTS];

/// The part of the store that holds the page whose bytes hash to `key`.
fn part(key: &Digest) -> &'static Lock<Option<Store<'static>>> {
    &STORES[usize::from(key.0[2]) % PARTS]
}

/// Keep the store's capabilities off the locks' cache lines so a PE can
/// skip operations that have no backing without contending with its users.
#[repr(align(64))]
struct Available {
    capabilities: AtomicU8,
    /// A preflight limit for staging. Admission checks the live store bound.
    shared_bound: AtomicUsize,
    /// The fetch pages the machines keep in all ([`Translations::kept_pages`]).
    kept_pages: AtomicUsize,
}

static AVAILABLE: Available = Available {
    capabilities: AtomicU8::new(0),
    shared_bound: AtomicUsize::new(0),
    kept_pages: AtomicUsize::new(0),
};
const READ_PACK: u8 = 1 << 0;
const WRITE_PACK: u8 = 1 << 1;
const SHARE_BLOCKS: u8 = 1 << 2;

fn available(capabilities: u8) -> bool {
    AVAILABLE.capabilities.load(Ordering::Acquire) & capabilities != 0
}

/// What the machines' use of the store cost, beyond the parts' counters:
/// fetch pages read and hashed for their records and the engine counter
/// ticks that took, shared blocks found but not installed, and the TSC
/// ticks record lookups took through the store and decoding records.
struct Costs {
    page_reads: AtomicU64,
    page_ticks: AtomicU64,
    shared_rejected: AtomicU64,
    lookups: AtomicU64,
    lookup_ticks: AtomicU64,
    decode_ticks: AtomicU64,
}

static COSTS: Costs = Costs {
    page_reads: AtomicU64::new(0),
    page_ticks: AtomicU64::new(0),
    shared_rejected: AtomicU64::new(0),
    lookups: AtomicU64::new(0),
    lookup_ticks: AtomicU64::new(0),
    decode_ticks: AtomicU64::new(0),
};

/// What the store keeps beyond its pack, for an engine heap of `heap` bytes:
/// entries added during the boot, decoded records, and the fetch pages the
/// machines keep (a page and its bookkeeping
/// take about 4.5 KiB).
fn bounds(heap: usize) -> (pack::Bounds, usize) {
    const MIB: usize = 1 << 20;
    let defaults = pack::Bounds::default();
    let bounds = pack::Bounds {
        added: (heap / 32).clamp(defaults.added, 512 * MIB),
        decoded: (heap / 64).clamp(defaults.decoded, 128 * MIB),
    };
    (bounds, (heap / 64 / (4608)).max(4096))
}

/// Make `parts` the store's, over the segments read, sharing up to
/// `shared` bytes of blocks across PEs.
fn install_parts(translator: Digest, segments: Vec<Pack<'static>>, shared: usize) {
    let (bounds, kept_pages) = bounds(crate::ALLOCATOR.usage().total);
    AVAILABLE.kept_pages.store(kept_pages, Ordering::Release);
    for lock in &STORES {
        let evicted = lock.with(|store| {
            let store = store.get_or_insert_with(|| Store::over(translator, segments.clone()));
            store.share(shared / PARTS);
            store.set_bounds(bounds.share(PARTS))
        });
        drop(evicted);
    }
}

/// The engine's view of the boot's store, from any PE's machine.
pub struct Shared;

impl Shared {
    fn publish_shared(offer: Offer) {
        let bound = AVAILABLE.shared_bound.load(Ordering::Acquire) / PARTS;
        let lock = part(&offer.key());
        let Some(mut staged) = StagedOffer::new(offer, bound) else {
            return;
        };
        let retired = lock.with(|store| store.as_mut()?.accept_shared(&mut staged));
        drop(retired);
    }

    /// Keep the offer's stored form, made before the lock is taken, and
    /// share its block.
    fn publish_writable(offer: Offer) {
        let bound = AVAILABLE.shared_bound.load(Ordering::Acquire) / PARTS;
        let entry = offer.entry();
        let lock = part(&offer.key());
        lock.with(|store| {
            if let Some(store) = store {
                store.keep(&offer, entry);
            }
        });
        let Some(mut staged) = StagedOffer::new(offer, bound) else {
            return;
        };
        let retired = lock.with(|store| store.as_mut()?.accept_shared(&mut staged));
        drop(retired);
    }
}

impl Translations for Shared {
    /// The pack bytes outlive the lock, so other PEs can reach the store
    /// while a record is decoded. A writer also tracks absent keys.
    fn record(&mut self, key: &Digest) -> Option<alloc::sync::Arc<Record>> {
        if !available(READ_PACK | WRITE_PACK) {
            return None;
        }
        let started = output::now();
        COSTS.lookups.fetch_add(1, Ordering::Relaxed);
        let lock = part(key);
        let lookup = lock.with(|store| {
            let store = store.as_mut()?;
            if let Some(record) = store.cached_record(key) {
                return Some(Ok(record));
            }
            match store.stored(key) {
                Some(stored) => Some(Err((
                    stored,
                    *store.translator(),
                    store.take_decode_scratch(stored),
                ))),
                None => {
                    store.looked_up(key, false, false);
                    None
                }
            }
        });
        let (stored, translator, mut scratch) = match lookup {
            Some(Ok(record)) => {
                COSTS
                    .lookup_ticks
                    .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
                return Some(record);
            }
            Some(Err(source)) => source,
            None => {
                COSTS
                    .lookup_ticks
                    .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
                return None;
            }
        };
        let decoding = output::now();
        let decoded = DecodedRecord::decode(stored, &translator, key, &mut scratch);
        COSTS
            .decode_ticks
            .fetch_add(output::now().wrapping_sub(decoding), Ordering::Relaxed);
        let evicted = lock.with(|store| {
            let store = store.as_mut()?;
            Some(store.finish_decode(key, stored, &decoded, &mut scratch))
        });
        drop(evicted);
        COSTS
            .lookup_ticks
            .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
        decoded.ok().map(DecodedRecord::into_record)
    }

    fn prepared(
        &mut self,
        key: &Digest,
        pc: u64,
        context: &Digest,
    ) -> Option<alloc::sync::Arc<stela_engine::machine::engine::SharedTranslation>> {
        if !available(SHARE_BLOCKS) {
            return None;
        }
        part(key).with(|store| store.as_mut()?.prepared(key, pc, context))
    }

    fn offer(&mut self, offer: Offer) {
        let capabilities = AVAILABLE.capabilities.load(Ordering::Acquire);
        if capabilities & WRITE_PACK != 0 {
            Self::publish_writable(offer);
        } else if capabilities & SHARE_BLOCKS != 0 {
            Self::publish_shared(offer);
        }
    }

    fn lend(&mut self, offer: Offer) {
        if available(SHARE_BLOCKS) {
            Self::publish_shared(offer);
        }
    }

    fn note(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::PageRead { ticks } => {
                COSTS.page_reads.fetch_add(1, Ordering::Relaxed);
                COSTS.page_ticks.fetch_add(ticks, Ordering::Relaxed);
            }
            StoreEvent::SharedRejected => {
                COSTS.shared_rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn kept_pages(&mut self) -> Option<usize> {
        match AVAILABLE.kept_pages.load(Ordering::Acquire) {
            0 => None,
            pages => Some(pages),
        }
    }
}

/// The store the engine uses, if the loader read one or the PEs share one.
pub fn store() -> Option<&'static mut Shared> {
    available(READ_PACK | WRITE_PACK | SHARE_BLOCKS).then(|| Box::leak(Box::new(Shared)))
}

/// Share compiled blocks between PEs, keeping up to `bound` bytes of buffers
/// and cache metadata in the loader's store or a store for this boot. Allocator
/// overhead and shared immutable preparation storage are outside this budget.
pub fn share(bound: usize) {
    BOOT.with(|boot| {
        let translator = boot
            .get_or_insert_with(|| Boot {
                translator: translations::translator_id(),
                partition: None,
            })
            .translator;
        install_parts(translator, Vec::new(), bound);
        AVAILABLE.shared_bound.store(bound, Ordering::Release);
        if bound != 0 {
            AVAILABLE
                .capabilities
                .fetch_or(SHARE_BLOCKS, Ordering::Release);
        } else {
            AVAILABLE
                .capabilities
                .fetch_and(!SHARE_BLOCKS, Ordering::Release);
        }
    });
}

/// Make the store of the handoff file `contents` the engine's: the GPT
/// partition to open for writing it, when it can be written.
pub fn install(contents: &'static [u8]) -> Option<Guid> {
    let head = PLACEMENT_BYTES + SLOT_BYTES as usize;
    if contents.len() < head || contents[..8] != PLACEMENT_MAGIC {
        return None;
    }
    let field = |at: usize| u64::from_le_bytes(contents[at..at + 8].try_into().expect("a field"));
    let word = |at: usize| u32::from_le_bytes(contents[at..at + 4].try_into().expect("a word"));
    let (limit, flags, count, size) = (field(8), word(32), word(36) as usize, field(40));
    let translator = translations::translator_id();
    let slot = &contents[PLACEMENT_BYTES..head];
    let committed = (0..2).find_map(|index| Commit::decode(slot, index, DOMAIN, size));
    let mut segments = Vec::new();
    let mut used = Vec::new();
    let mut discarded = 0;
    if let Some(commit) = committed
        .as_ref()
        .filter(|commit| commit.key == translator.0 && commit.entries.len() == count)
    {
        let mut at = head + 8 * count;
        for (index, entry) in commit.entries.iter().enumerate() {
            let length = usize::try_from(field(head + 8 * index)).ok()?;
            let bytes = contents.get(at..at.checked_add(length)?)?;
            at += length.next_multiple_of(8);
            match entry.kind {
                SEGMENT if length != 0 => match Pack::parse(bytes, &translator) {
                    Ok(pack) => segments.push(pack),
                    Err(error) => {
                        output::arguments(format_args!(
                            "TRANSLATIONS segment discarded: {error:?}\n"
                        ));
                        discarded += 1;
                    }
                },
                USED if length != 0 => match UsedKeys::parse(bytes, &translator) {
                    Some(list) => used.push(list),
                    None => discarded += 1,
                },
                _ => {}
            }
        }
    }
    let partial = flags & PARTIAL != 0;
    output::arguments(format_args!(
        "TRANSLATIONS pack segments={} records={} bytes={} lists={} discarded={discarded} \
         partial={partial}\n",
        segments.len(),
        segments.iter().map(Pack::records).sum::<usize>(),
        segments.iter().map(Pack::bytes).sum::<usize>(),
        used.len(),
    ));
    let readable = if segments.is_empty() { 0 } else { READ_PACK };
    let writer = Writer {
        translator,
        limit,
        file_bytes: size,
        committed,
        extents: None,
        segments: segments.clone(),
        used,
        partial,
        merged: false,
        added_keys: Vec::new(),
        task: Task::Idle,
        queued: Queued::default(),
        next_delta: 0,
        delta_interval: super::host::COUNTER_HZ * FIRST_DELTA_SECONDS,
        failed: false,
        stats: Stats::default(),
    };
    WRITER.holding(true, |slot| *slot = Some(writer));
    BOOT.with(|boot| {
        for lock in &STORES {
            let old = lock.with(Option::take);
            drop(old);
        }
        install_parts(translator, segments, 0);
        *boot = Some(Boot {
            translator,
            partition: None,
        });
        AVAILABLE.shared_bound.store(0, Ordering::Release);
        AVAILABLE.capabilities.store(readable, Ordering::Release);
    });
    let partition = Guid(contents[16..32].try_into().expect("a GUID"));
    (flags & WRITABLE != 0).then_some(partition)
}

/// Whether the store's partition is staged ([`super::storage::try_stage`]):
/// its commands then queue, and processors step its I/O in bounded steps.
static PARTITION_STAGED: AtomicBool = AtomicBool::new(false);

/// Keep `partition`, the store's volume, for the writes, staged when a
/// slot is free, and find the pack file's device extents while its drivers
/// may still be called directly: the writes while the guest runs only
/// queue.
pub fn set_partition(partition: Box<dyn BlockDevice>) {
    let partition = match super::storage::try_stage(partition) {
        Ok(staged) => {
            PARTITION_STAGED.store(true, Ordering::Release);
            staged
        }
        Err(unstaged) => unstaged,
    };
    let translator = BOOT.with(|boot| {
        let boot = boot.as_mut()?;
        boot.partition = Some(partition);
        AVAILABLE
            .capabilities
            .fetch_or(WRITE_PACK, Ordering::Release);
        Some(boot.translator)
    });
    let Some(translator) = translator else {
        return;
    };
    let extents = with_store_file(&pack_name(&translator), |_, extents| extents.to_vec());
    WRITER.with(|writer| match extents {
        Ok(extents) => writer.extents = Some(extents),
        Err(error) => {
            output::arguments(format_args!(
                "TRANSLATIONS written only at a stop: {error}\n"
            ));
        }
    });
}

/// Run `f` on the store's partition with the device extents of `name`, a
/// file in the store's directory. Only while the engine may write the
/// store.
pub fn with_store_file<R>(
    name: &str,
    f: impl FnOnce(&mut dyn BlockDevice, &[Extent]) -> R,
) -> Result<R, String> {
    BOOT.with(|boot| {
        let boot = boot.as_mut().ok_or("no translation store")?;
        let partition = boot
            .partition
            .take()
            .ok_or("the store's partition is not open")?;
        let mut volume = Fat32::open(Bytes::new(partition)).map_err(|error| format!("{error}"))?;
        let file = volume.file(&format!("{}/{name}", DIRECTORY.replace('\\', "/")));
        let mut device = volume.into_inner().into_inner();
        let result = file
            .map(|file| f(&mut *device, &file.extents))
            .map_err(|error| format!("{error}"));
        boot.partition = Some(device);
        result
    })
}

/// Lend the store's partition to `f` while the guest runs, for background
/// writes: staged, so `f` only queues commands (`BlockDevice::start`) and
/// takes results (`finish`), never waiting for the disk. The pack file and
/// the pipeline store share it. `None` when it is absent, lent, or not
/// staged.
pub fn lend_staged_partition<R>(f: impl FnOnce(&mut dyn BlockDevice) -> R) -> Option<R> {
    if !PARTITION_STAGED.load(Ordering::Acquire) {
        return None;
    }
    BOOT.with(|boot| {
        let partition = boot.as_mut()?.partition.as_deref_mut()?;
        Some(f(partition))
    })
}

/// Milliseconds of `ticks` TSC ticks.
fn millis(ticks: u64) -> u64 {
    output::millis_since(output::now().wrapping_sub(ticks))
}

/// Report what the store did and cost this boot: lookups and their causes,
/// shared misses by reason, stored forms kept and checked, and lock waits.
fn report(counters: &pack::Counters) {
    let costs = &COSTS;
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    output::arguments(format_args!(
        "TRANSLATIONS lookups={} repeated={} cached={} decoded={} lookup_ms={} decode_ms={} \
         pages={} page_ms={}\n",
        load(&costs.lookups),
        counters.repeated,
        counters.cached,
        counters.decoded,
        millis(load(&costs.lookup_ticks)),
        millis(load(&costs.decode_ticks)),
        load(&costs.page_reads),
        load(&costs.page_ticks) / (super::host::COUNTER_HZ / 1000),
    ));
    output::arguments(format_args!(
        "TRANSLATIONS shared hits={} rejected={} absent={} other_context={} evicted={} \
         in_flight={}\n",
        counters.shared_hits,
        load(&costs.shared_rejected),
        counters.shared_absent,
        counters.shared_other_context,
        counters.shared_evicted,
        counters.shared_in_flight,
    ));
    let (mut acquired, mut contended, mut spun) = (0, 0, 0);
    for lock in &STORES {
        acquired += load(&lock.acquired);
        contended += load(&lock.contended);
        spun += load(&lock.spun);
    }
    let checks = stela_engine::machine::entry_checks();
    output::arguments(format_args!(
        "TRANSLATIONS added={} unstorable={} unkept={} checked={} differed={} loaded={} \
         absent={} invalid={} locks acquired={acquired} contended={contended} spin_ms={}\n",
        counters.added,
        counters.unstorable,
        counters.unkept,
        checks.checked,
        checks.differed,
        counters.loaded,
        counters.absent,
        counters.invalid,
        millis(spun),
    ));
}

/// Segments or used-key lists at which a boot merges them.
const MERGE_AT: usize = 4;
/// The first new segment's delay, which doubles with each, up to the last:
/// a boot's compiling comes in bursts, mostly early, and the segments a
/// file holds are few ([`MAX_SEGMENTS`]).
const FIRST_DELTA_SECONDS: u64 = 60;
const LAST_DELTA_SECONDS: u64 = 32 * 60;
/// How long a step may take, in microseconds, and the work it does between
/// looks at the clock (records encoded, page keys merged, records indexed).
const STEP_MICROS: u64 = 1000;
const STEP_WORK: usize = 32;
/// The bytes a step copies of a new segment, and the most a write step
/// queues.
const COPY_BYTES: u64 = 1 << 20;
const PIECE_BYTES: u64 = 512 << 10;

/// The writer of the pack file while the guest runs and at a stop.
struct Writer {
    translator: Digest,
    /// The bound a merged segment stays within: what this PC can read.
    limit: u64,
    file_bytes: u64,
    committed: Option<Commit>,
    /// The file's device extents, found while the drivers may be called.
    extents: Option<Vec<Extent>>,
    /// The segments read and those this boot wrote, oldest first, and the
    /// used-key lists read: a merge's input.
    segments: Vec<Pack<'static>>,
    used: Vec<UsedKeys>,
    /// A segment was not read whole: no merge runs.
    partial: bool,
    /// This boot's merge ran or was tried: its segment is not in memory, so
    /// no other follows.
    merged: bool,
    /// The keys of the entries this boot took for its segments: with those
    /// it found, its used keys. More than a list names counts every key.
    added_keys: Vec<Digest>,
    task: Task,
    /// The staged commands of the write in flight.
    queued: Queued,
    /// Host counter value before which no new segment starts, and the delay
    /// after the next.
    next_delta: u64,
    delta_interval: u64,
    /// A write failed: the file is not written again this boot.
    failed: bool,
    stats: Stats,
}

/// What the writer did while the guest ran.
#[derive(Default)]
struct Stats {
    steps: u64,
    longest: u64,
    deltas: u64,
    delta_records: u64,
    delta_bytes: u64,
    merges: u64,
    abandoned: u64,
}

/// The writer's work in progress.
enum Task {
    Idle,
    /// A new segment of the entries taken, being laid out.
    Delta(Box<Delta>),
    /// The new segment, being copied into memory the boot keeps for a
    /// merge.
    Copy {
        layout: Layout<'static>,
        bytes: Vec<u8>,
    },
    Merge(Box<Merge<'static>>),
    Write {
        execution: Box<Execution<'static>>,
        done: Done,
    },
}

/// What a finished write leaves.
enum Done {
    Segment(Pack<'static>),
    Merge,
}

static WRITER: Held<Writer> = Held::new();

/// The keys found valid by every part of the store, with `added`: the
/// boot's used keys so far, as a list.
fn used_now(added: &[Digest]) -> Vec<u8> {
    let translator = translations::translator_id();
    if added.len() > MAX_USED_KEYS {
        return UsedKeys::encode_every(&translator);
    }
    let mut keys: Vec<Digest> = added.to_vec();
    for lock in &STORES {
        lock.with(|store| {
            if let Some(store) = store {
                keys.extend(store.used_keys().copied());
            }
        });
    }
    UsedKeys::encode(&translator, keys.iter())
}

impl Writer {
    /// The committed blobs of `kind` of this translator.
    fn count(&self, kind: u32) -> usize {
        self.committed
            .as_ref()
            .filter(|commit| commit.key == self.translator.0)
            .map_or(0, |commit| {
                commit
                    .entries
                    .iter()
                    .filter(|entry| entry.kind == kind)
                    .count()
            })
    }

    /// Note the keys of entries taken for a segment.
    fn note_added(&mut self, added: &BTreeMap<Digest, Record>) {
        if self.added_keys.len() <= MAX_USED_KEYS {
            self.added_keys.extend(added.keys().copied());
        }
    }

    /// Start a merge when the file holds enough segments or lists, else a
    /// segment of the entries added when its time came.
    fn begin(&mut self, now: u64) {
        let segments = self.count(SEGMENT);
        if !self.merged && !self.partial && (segments >= MERGE_AT || self.count(USED) >= MERGE_AT) {
            self.merged = true;
            // Beside the file's content, so its commit keeps that content
            // until the merged segment is whole.
            let free = journal::largest_free(
                self.committed.as_ref(),
                DOMAIN,
                self.translator.0,
                self.file_bytes,
            );
            let protect = UsedKeys::parse(&used_now(&self.added_keys), &self.translator);
            let mut merge = Merge::new(
                self.translator,
                self.segments.iter().copied().map(Into::into).collect(),
                self.used.clone(),
                self.limit.min(free),
            );
            if let Some(protect) = protect {
                merge = merge.protect(protect);
            }
            self.task = Task::Merge(Box::new(merge));
            return;
        }
        if self.next_delta == 0 {
            self.next_delta = now + self.delta_interval;
        }
        // One segment stays free for the stop's.
        if now < self.next_delta || segments + 1 >= MAX_SEGMENTS {
            return;
        }
        let added = take_added();
        if added.is_empty() {
            self.next_delta = now + super::host::COUNTER_HZ * 10;
            return;
        }
        self.next_delta = now + self.delta_interval;
        self.delta_interval =
            (self.delta_interval * 2).min(super::host::COUNTER_HZ * LAST_DELTA_SECONDS);
        self.note_added(&added);
        self.stats.delta_records += added.len() as u64;
        self.task = Task::Delta(Box::new(Delta::new(self.translator, added)));
    }

    /// Plan writing `change`, which must commit once beside the file's
    /// content: else it is left out.
    fn plan(&mut self, change: Change<'static>, what: &str) -> Option<Box<Execution<'static>>> {
        let plan = journal::plan(
            self.committed.as_ref(),
            DOMAIN,
            self.translator.0,
            self.file_bytes,
            change,
        );
        let commits = plan
            .steps
            .iter()
            .filter(|step| matches!(step, Step::Commit(_)))
            .count();
        if !plan.dropped.is_empty() || commits > 1 {
            output::arguments(format_args!(
                "TRANSLATIONS {what} not written: no room beside the content of a file of {} \
                 bytes\n",
                self.file_bytes
            ));
            self.stats.abandoned += 1;
            return None;
        }
        Some(Box::new(Execution::new(plan)))
    }

    /// The task that writes `change` ([`Self::plan`]) and then leaves
    /// `done`.
    fn write(&mut self, change: Change<'static>, done: Done, what: &str) -> Task {
        match self.plan(change, what) {
            Some(execution) => Task::Write { execution, done },
            None => Task::Idle,
        }
    }

    /// A write finished: its commit is the file's newest.
    fn finish(&mut self, execution: &Execution<'static>, done: Done) {
        if let Some(last) = execution.last() {
            self.committed = Some(last);
        }
        match done {
            Done::Segment(pack) => {
                self.stats.deltas += 1;
                self.stats.delta_bytes += pack.bytes() as u64;
                self.segments.push(pack);
            }
            Done::Merge => {
                self.stats.merges += 1;
                self.segments.clear();
                self.used.clear();
            }
        }
    }

    /// Carry the work forward until `deadline` (a host counter value), or
    /// until a write queued its piece.
    fn work(&mut self, now: u64, deadline: u64) -> Result<(), String> {
        if matches!(self.task, Task::Idle) {
            self.begin(now);
        }
        loop {
            self.task = match core::mem::replace(&mut self.task, Task::Idle) {
                Task::Idle => return Ok(()),
                Task::Delta(mut delta) => {
                    if delta.step(STEP_WORK) {
                        match delta.finish() {
                            Some(layout) => Task::Copy {
                                bytes: Vec::with_capacity(layout.bytes() as usize),
                                layout,
                            },
                            None => Task::Idle,
                        }
                    } else {
                        Task::Delta(delta)
                    }
                }
                Task::Copy { layout, mut bytes } => {
                    let at = bytes.len();
                    let take = (layout.bytes() - at as u64).min(COPY_BYTES) as usize;
                    bytes.resize(at + take, 0);
                    layout.read_at(at as u64, &mut bytes[at..]);
                    if (bytes.len() as u64) < layout.bytes() {
                        Task::Copy { layout, bytes }
                    } else {
                        drop(layout);
                        // Kept for the boot: a merge reads it.
                        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
                        match Pack::parse(bytes, &self.translator) {
                            Ok(pack) => {
                                let change = Change {
                                    replace: Vec::new(),
                                    remove: Vec::new(),
                                    blobs: vec![Blob::new(SEGMENT, bytes)],
                                };
                                self.write(change, Done::Segment(pack), "segment")
                            }
                            Err(error) => return Err(format!("a new segment: {error:?}")),
                        }
                    }
                }
                Task::Merge(mut merge) => {
                    if merge.step(STEP_WORK) {
                        let merged = merge.finish();
                        output::arguments(format_args!(
                            "TRANSLATIONS merged records={} bytes={} evicted={} expired={} \
                             invalid={}\n",
                            merged.layout.records(),
                            merged.layout.bytes(),
                            merged.evicted,
                            merged.expired,
                            merged.invalid
                        ));
                        let change = Change {
                            replace: vec![SEGMENT, USED],
                            remove: Vec::new(),
                            blobs: vec![Blob::new(SEGMENT, merged.layout)],
                        };
                        self.write(change, Done::Merge, "merge")
                    } else {
                        Task::Merge(merge)
                    }
                }
                Task::Write {
                    mut execution,
                    done,
                } => {
                    let Some(extents) = self.extents.as_deref() else {
                        return Err(String::from("no extents"));
                    };
                    let queued = &mut self.queued;
                    let advanced = lend_staged_partition(|device| {
                        let mut target = Staged {
                            device,
                            extents,
                            queued,
                        };
                        execution.advance(&mut target, PIECE_BYTES)
                    });
                    match advanced {
                        Some(Ok(true)) => self.finish(&execution, done),
                        Some(Err(error)) => return Err(error),
                        None | Some(Ok(false)) => self.task = Task::Write { execution, done },
                    }
                    return Ok(());
                }
            };
            if super::host::fresh_counter() >= deadline {
                return Ok(());
            }
        }
    }

    fn fail(&mut self, error: &str) {
        output::arguments(format_args!("TRANSLATIONS not written: {error}\n"));
        self.task = Task::Idle;
        self.failed = true;
    }
}

/// The entries every part of the store added since the last take.
fn take_added() -> BTreeMap<Digest, Record> {
    let mut added = BTreeMap::new();
    for lock in &STORES {
        let mut part = lock.with(|store| store.as_mut().map(Store::take_added).unwrap_or_default());
        added.append(&mut part);
    }
    added
}

/// While the guest runs, from a processor whose guest waits and that holds
/// no device lock: carry the pack file's writer forward for a bounded time
/// ([`STEP_MICROS`]). Never waits for the disk.
pub fn step() {
    if !available(WRITE_PACK) {
        return;
    }
    let started = super::host::fresh_counter();
    WRITER.try_with(|writer| {
        if writer.failed || writer.extents.is_none() {
            return;
        }
        let idle = matches!(writer.task, Task::Idle);
        let deadline = started + super::host::COUNTER_HZ * STEP_MICROS / 1_000_000;
        if let Err(error) = writer.work(started, deadline) {
            writer.fail(&error);
        }
        if !idle || !matches!(writer.task, Task::Idle) {
            let took = super::host::fresh_counter().wrapping_sub(started);
            writer.stats.steps += 1;
            writer.stats.longest = writer.stats.longest.max(took);
        }
    });
}

/// At a quiescent point (the guest restarts or powers off): finish a new
/// segment's write in flight, then write a segment of the entries left and
/// this boot's used-key list. A merge not yet committed is left: its input
/// stays in the file.
pub fn write() {
    AVAILABLE.capabilities.store(0, Ordering::SeqCst);
    AVAILABLE.shared_bound.store(0, Ordering::Release);
    let mut parts = STORES.iter().filter_map(|lock| lock.with(Option::take));
    let store = parts.next().map(|mut store| {
        for part in parts {
            store.absorb(part);
        }
        store
    });
    if let Some(store) = &store {
        report(&store.counters);
    }
    let writer = WRITER.holding(true, Option::take).flatten();
    if let (Some(mut store), Some(mut writer)) = (store, writer)
        && BOOT.with(|boot| boot.as_ref().is_some_and(|boot| boot.partition.is_some()))
        && !writer.failed
    {
        write_last(&mut writer, &mut store);
    }
    let boot = BOOT.with(Option::take);
    drop(boot);
}

/// The stop's writes ([`write`]).
fn write_last(writer: &mut Writer, store: &mut Store<'static>) {
    let started = output::now();
    let name = pack_name(&writer.translator);
    let run = |execution: &mut Execution<'static>| {
        with_store_file(&name, |device, extents| {
            let mut target = Direct { device, extents };
            while !execution.advance(&mut target, PIECE_BYTES)? {}
            Ok::<(), String>(())
        })
        .and_then(|done| done)
    };
    // What the run left: a segment's write is finished, one being made is
    // written with the rest, a merge is left.
    let mut pending: Vec<Layout<'static>> = Vec::new();
    match core::mem::replace(&mut writer.task, Task::Idle) {
        Task::Write {
            mut execution,
            done: done @ Done::Segment(_),
        } => match run(&mut execution) {
            Ok(()) => writer.finish(&execution, done),
            Err(error) => return writer.fail(&error),
        },
        Task::Delta(delta) => pending.extend(delta.finish()),
        Task::Copy { layout, .. } => pending.push(layout),
        Task::Merge(_) | Task::Write { .. } => {
            output::arguments(format_args!("TRANSLATIONS merge left for the next boot\n"));
            writer.stats.abandoned += 1;
        }
        Task::Idle => {}
    }
    let stats = &writer.stats;
    output::arguments(format_args!(
        "TRANSLATIONS writer steps={} longest_us={} segments={} records={} bytes={} merges={} \
         abandoned={}\n",
        stats.steps,
        stats.longest * 1_000_000 / super::host::COUNTER_HZ,
        stats.deltas,
        stats.delta_records,
        stats.delta_bytes,
        stats.merges,
        stats.abandoned
    ));
    let added = store.take_added();
    writer.note_added(&added);
    let records = added.len();
    pending.extend(Delta::new(writer.translator, added).finish());
    let mut change = Change::default();
    let room = MAX_SEGMENTS.saturating_sub(writer.count(SEGMENT));
    let lost: usize = pending.iter().skip(room).map(Layout::records).sum();
    for layout in pending.into_iter().take(room) {
        change.blobs.push(Blob::new(SEGMENT, layout));
    }
    let lists = writer.count(USED) < MAX_USED_LISTS;
    if lists {
        let list = if writer.added_keys.len() > MAX_USED_KEYS {
            UsedKeys::encode_every(&writer.translator)
        } else {
            UsedKeys::encode(
                &writer.translator,
                store.used_keys().chain(&writer.added_keys),
            )
        };
        change.blobs.push(Blob::new(USED, list));
    }
    let bytes: u64 = change.blobs.iter().map(Blob::length).sum();
    let Some(mut execution) = writer.plan(change, "stop") else {
        return;
    };
    match run(&mut execution) {
        Ok(()) => {
            if let Some(last) = execution.last() {
                writer.committed = Some(last);
            }
            output::arguments(format_args!(
                "TRANSLATIONS written segments={} lists={} records={records} lost={lost} \
                 bytes={bytes} ms={}\n",
                writer.count(SEGMENT),
                writer.count(USED),
                output::millis_since(started)
            ));
        }
        Err(error) => writer.fail(&error),
    }
}
