//! `stela.efi`'s translation store (`docs/design/runtime.md`, "Persistent
//! translation store"): the pack `stela setup` makes room for in
//! `stela/store` on the boot USB's FAT32 data partition.
//!
//! Before boot services end, [`read`] finds the volume with `store.cfg`,
//! allocates this translator's pack file to the bound there (through the
//! firmware's FAT driver, which grows it), reads the pack it holds and
//! notes the volume's GPT partition. The engine reads blocks from the pack
//! ([`install`]) and, when the guest restarts or powers off, proves the
//! blocks it compiled anew and rewrites the pack in place over the file's
//! clusters ([`write`]), found by Stela's own FAT32 reader on the
//! partition the storage drivers opened. Every failure leaves the boot
//! running without a store, or without writing it.
//!
//! When every PE runs on its own host core (the default), their machines
//! share the store, behind one lock ([`Shared`]), and it keeps the blocks
//! any of them compiled for the others to install ([`share`]).
use super::bundle::Bytes;
use crate::{firmware, handoff::Region, output, paging::PAGE};
use alloc::{boxed::Box, format, string::String, vec};
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_drivers::block::BlockDevice;
use stela_engine::machine::Offer;
use stela_engine::machine::Translations;
use stela_engine::translations;
use stela_engine::translations::Digest;
use stela_engine::translations::Record;
use stela_engine::translations::pack;
use stela_engine::translations::pack::Pack;
use stela_engine::translations::pack::Store;
use stela_runtime::pc::fat32::Fat32;
use stela_runtime::pc::gpt::Guid;
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

/// The handoff file holding the store's placement and its pack.
pub const FILE: &str = "translations";
/// The store's directory on its volume, and `stela setup`'s bound there.
const DIRECTORY: &str = "stela\\store";
const CONFIG: &str = "store.cfg";
const BYTES_KEY: &str = "bytes";
const CONFIG_LIMIT: usize = 256;
/// A pack's file name: the first bytes of its translator id in hex, an 8.3
/// name the FAT32 reader finds.
const NAME_BYTES: usize = 4;
const PACK_EXTENSION: &str = "pak";
/// A blank, preallocated pack file `stela setup` keeps beside the packs: a
/// new translator's pack takes it by rename. The boot never grows a file,
/// which the firmware does by writing every byte.
const SPARE: &str = "spare.bin";
/// The pack is read in steps of this many bytes, each shown as progress.
const PROGRESS_STEP: usize = 16 << 20;
/// The largest pack the boot holds in memory and writes: the bound of
/// `store.cfg` is cut to it.
const MAX_PACK_BYTES: u64 = 1 << 30;
/// The placement record at the start of the handoff file: magic, bound,
/// partition GUID, flags, pack bytes; the pack follows.
const PLACEMENT_MAGIC: [u8; 8] = *b"STLTSTOR";
const PLACEMENT_BYTES: usize = 64;
/// The pack file holds the bound's bytes and its volume's partition is
/// known: the engine may rewrite it.
const WRITABLE: u32 = 1;
/// The words of the buffer a renamed file's `FileInfo` is built in: its
/// fixed fields and an 8.3 name.
const FILE_INFO_WORDS: usize = 64;

/// The pack file's path, with `separator` between components.
fn pack_path(translator: &Digest, separator: &str) -> String {
    let name = format!("{}.{PACK_EXTENSION}", hex(&translator.0[..NAME_BYTES]));
    format!("{}{separator}{name}", DIRECTORY.replace('\\', separator))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn open(root: &mut Directory, path: &str, mode: FileMode) -> Option<RegularFile> {
    let path = CString16::try_from(path).ok()?;
    root.open(&path, mode, FileAttribute::empty())
        .ok()?
        .into_regular_file()
}

/// Read `buffer.len()` bytes from the current file position.
fn read_exact(file: &mut RegularFile, buffer: &mut [u8]) -> Option<()> {
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

/// `store.cfg`'s bound.
fn bound(root: &mut Directory) -> Option<u64> {
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

/// The store on the first volume with `store.cfg`, as the handoff file's
/// pages, and whether the engine can rewrite its pack: run before boot
/// services end, with no volume opened exclusively. `None` when no volume
/// has a store.
pub fn read() -> Option<(Region, bool)> {
    let translator = translations::translator_id();
    for handle in boot::find_handles::<SimpleFileSystem>().ok()? {
        let Ok(mut volume) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let Ok(mut root) = volume.open_volume() else {
            continue;
        };
        let Some(bound) = bound(&mut root) else {
            continue;
        };
        let bound = bound.min(MAX_PACK_BYTES);
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
        let (pack, allocated) = match opened {
            Some((mut file, writable)) => {
                let allocated = writable
                    && file
                        .get_boxed_info::<FileInfo>()
                        .is_ok_and(|info| info.file_size() >= bound);
                (read_pack(&mut file, &translator, bound), allocated)
            }
            None => (None, false),
        };
        output::arguments(format_args!(
            "TRANSLATIONS {path} bound={bound} pack={} allocated={allocated} partition={}\n",
            pack.as_ref()
                .map_or(0, |region| region.bytes - PLACEMENT_BYTES as u64),
            partition.is_some()
        ));
        let region = match pack {
            Some(region) => region,
            None => Region {
                physical: firmware::pages(1).ok()? as u64,
                bytes: PLACEMENT_BYTES as u64,
            },
        };
        let flags = if allocated && partition.is_some() {
            WRITABLE
        } else {
            0
        };
        // SAFETY: the exclusive loader allocation starts with space for
        // the placement header. Initialize it before taking a mutable slice.
        let placement = unsafe {
            let start = region.physical as *mut u8;
            start.write_bytes(0, PLACEMENT_BYTES);
            core::slice::from_raw_parts_mut(start, PLACEMENT_BYTES)
        };
        placement[..8].copy_from_slice(&PLACEMENT_MAGIC);
        placement[8..16].copy_from_slice(&bound.to_le_bytes());
        placement[16..32].copy_from_slice(&partition.unwrap_or_default());
        placement[32..36].copy_from_slice(&flags.to_le_bytes());
        let pack_bytes = region.bytes - PLACEMENT_BYTES as u64;
        placement[40..48].copy_from_slice(&pack_bytes.to_le_bytes());
        return Some((region, flags & WRITABLE != 0));
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
    let Ok(name) = CString16::try_from(pack_path(translator, "/").rsplit('/').next().unwrap_or(""))
    else {
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

/// Read a checked pack directly into its final handoff region.
fn read_pack(file: &mut RegularFile, translator: &Digest, bound: u64) -> Option<Region> {
    let mut header = [0; pack::HEADER_BYTES];
    read_exact(file, &mut header)?;
    let prefix_len = pack::prefix_bytes(&header, translator).ok()?;
    if prefix_len as u64 > bound {
        return None;
    }
    let mut prefix = vec![0; prefix_len];
    prefix[..header.len()].copy_from_slice(&header);
    read_exact(file, &mut prefix[header.len()..])?;
    let length = Pack::length(&prefix, translator).ok()?;
    if length > bound {
        return None;
    }
    let length = length as usize;
    let bytes = PLACEMENT_BYTES + length;
    let pages = bytes.div_ceil(PAGE);
    let physical = firmware::pages(pages).ok()?;
    // SAFETY: firmware returned this exclusive allocation and `bytes` fits
    // in it. Initialize the pack range before borrowing it as a slice.
    let pack = unsafe {
        let start = (physical as *mut u8).add(PLACEMENT_BYTES);
        start.write_bytes(0, length);
        core::slice::from_raw_parts_mut(start, length)
    };
    pack[..prefix_len].copy_from_slice(&prefix);
    let total = length >> 20;
    for (index, part) in pack[prefix_len..].chunks_mut(PROGRESS_STEP).enumerate() {
        if read_exact(file, part).is_none() {
            let start = NonNull::new(physical as *mut u8).expect("firmware allocation");
            // SAFETY: the pack slice is no longer used and these are the
            // original base and page count of the loader allocation.
            let _ = unsafe { boot::free_pages(start, pages) };
            return None;
        }
        let done = (prefix_len + index * PROGRESS_STEP + part.len()) >> 20;
        crate::status::progress(&format!("{done} of {total} MB"));
    }
    Some(Region {
        physical: physical as u64,
        bytes: bytes as u64,
    })
}

/// The boot's store, the bound and the partition it is written to.
struct Boot {
    store: Store<'static>,
    bound: u64,
    path: String,
    partition: Option<Box<dyn BlockDevice>>,
}

/// The boot's store, which every PE's machine reaches in turn.
struct Cell {
    held: AtomicBool,
    boot: UnsafeCell<Option<Boot>>,
}
// SAFETY: `with_boot` holds `held` for every access.
unsafe impl Sync for Cell {}
static BOOT: Cell = Cell {
    held: AtomicBool::new(false),
    boot: UnsafeCell::new(None),
};

/// Run `f` on the boot's store, alone. No interrupt handler reaches it.
fn with_boot<R>(f: impl FnOnce(&mut Option<Boot>) -> R) -> R {
    while BOOT
        .held
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `held` excludes every other access until it is released.
    let result = f(unsafe { &mut *BOOT.boot.get() });
    BOOT.held.store(false, Ordering::Release);
    result
}

/// The engine's view of the boot's store, from any PE's machine.
pub struct Shared;

impl Translations for Shared {
    /// The record, decoded while the other PEs reach the store: the pack's
    /// bytes outlive the lock.
    fn record(&mut self, key: &Digest) -> Option<alloc::sync::Arc<Record>> {
        let (bytes, translator) = with_boot(|boot| {
            let store = &boot.as_ref()?.store;
            Some((store.stored(key), *store.translator()))
        })?;
        let record = bytes.and_then(|bytes| Record::decode(bytes, &translator, key).ok());
        with_boot(|boot| {
            if let Some(boot) = boot {
                boot.store.looked_up(key, bytes.is_some(), record.is_some());
            }
        });
        record.map(alloc::sync::Arc::new)
    }

    fn prepared(
        &mut self,
        key: &Digest,
        pc: u64,
        context: &Digest,
    ) -> Option<alloc::sync::Arc<stela_engine::machine::engine::SharedTranslation>> {
        with_boot(|boot| boot.as_mut()?.store.prepared(key, pc, context))
    }

    fn offer(&mut self, offer: Offer) {
        with_boot(|boot| {
            if let Some(boot) = boot {
                boot.store.offer(offer);
            }
        });
    }

    fn lend(&mut self, offer: Offer) {
        with_boot(|boot| {
            if let Some(boot) = boot {
                boot.store.lend(offer);
            }
        });
    }
}

/// The store the engine uses, if the loader read one or the PEs share one.
pub fn store() -> Option<&'static mut Shared> {
    with_boot(|boot| boot.is_some()).then(|| Box::leak(Box::new(Shared)))
}

/// Share compiled blocks between PEs, keeping up to `bound` bytes of buffers
/// and cache metadata in the loader's store or a store for this boot. Allocator
/// overhead and shared immutable preparation storage are outside this budget.
pub fn share(bound: usize) {
    with_boot(|boot| {
        let boot = boot.get_or_insert_with(|| Boot {
            store: Store::new(translations::translator_id(), None).0,
            bound: 0,
            path: String::new(),
            partition: None,
        });
        boot.store.share(bound);
    });
}

/// Make the store of the handoff file `contents` the engine's: the GPT
/// partition to open for writing it, when it can be written.
pub fn install(contents: &'static [u8]) -> Option<Guid> {
    if contents.len() < PLACEMENT_BYTES || contents[..8] != PLACEMENT_MAGIC {
        return None;
    }
    let field = |at: usize| u64::from_le_bytes(contents[at..at + 8].try_into().expect("a field"));
    let bound = field(8);
    let flags = u32::from_le_bytes(contents[32..36].try_into().expect("a word"));
    let pack_bytes = usize::try_from(field(40)).ok()?;
    let pack = contents.get(PLACEMENT_BYTES..PLACEMENT_BYTES + pack_bytes)?;
    let translator = translations::translator_id();
    let (store, error) = Store::new(translator, (!pack.is_empty()).then_some(pack));
    match (store.pack(), error) {
        (Some(pack), _) => output::arguments(format_args!(
            "TRANSLATIONS pack records={} bytes={}\n",
            pack.records(),
            pack.bytes()
        )),
        (None, Some(error)) => {
            output::arguments(format_args!("TRANSLATIONS pack discarded: {error:?}\n"))
        }
        (None, None) => output::arguments(format_args!("TRANSLATIONS no pack yet\n")),
    }
    with_boot(|boot| {
        *boot = Some(Boot {
            store,
            bound,
            path: pack_path(&translator, "/"),
            partition: None,
        })
    });
    let partition = Guid(contents[16..32].try_into().expect("a GUID"));
    (flags & WRITABLE != 0).then_some(partition)
}

/// Keep `partition`, the store's volume, for [`write`].
pub fn set_partition(partition: Box<dyn BlockDevice>) {
    with_boot(|boot| {
        if let Some(boot) = boot {
            boot.partition = Some(partition);
        }
    });
}

/// At a quiescent point (the guest restarts or powers off): prove the
/// blocks compiled anew and rewrite the pack in place.
pub fn write() {
    let Some(Boot {
        mut store,
        bound,
        path,
        partition: Some(partition),
    }) = with_boot(Option::take)
    else {
        return;
    };
    let counters = store.counters;
    output::arguments(format_args!(
        "TRANSLATIONS proving {} blocks (loaded={} absent={} invalid={} dropped={})\n",
        store.pending(),
        counters.loaded,
        counters.absent,
        counters.invalid,
        counters.dropped
    ));
    // Proof recompiles the original and both relocation probes; stop while
    // the heap still has room for the layout and the write.
    let started = output::now();
    let planned = store.plan(bound, || !crate::ALLOCATOR.low());
    let heap = crate::ALLOCATOR.usage();
    output::arguments(format_args!(
        "TRANSLATIONS planned records={} bytes={} ms={} live={} carved={} total={}\n",
        planned.layout.records(),
        planned.layout.bytes(),
        output::millis_since(started),
        heap.live,
        heap.carved,
        heap.total
    ));
    let started = output::now();
    let mut volume = match Fat32::open(Bytes::new(partition)) {
        Ok(volume) => volume,
        Err(error) => {
            output::arguments(format_args!("TRANSLATIONS not written: {error}\n"));
            return;
        }
    };
    let file = match volume.file(&path) {
        Ok(file) => file,
        Err(error) => {
            output::arguments(format_args!("TRANSLATIONS not written: {error}\n"));
            return;
        }
    };
    let mut device = volume.into_inner().into_inner();
    output::arguments(format_args!(
        "TRANSLATIONS writing extents={}\n",
        file.extents.len()
    ));
    match stela_runtime::translation_store::write_in_place(
        &mut *device,
        &file.extents,
        &planned.layout,
    ) {
        Ok(()) => output::arguments(format_args!(
            "TRANSLATIONS written records={} bytes={} proven={} unprovable={} unproven={} \
             evicted={} ms={}\n",
            planned.layout.records(),
            planned.layout.bytes(),
            planned.proven,
            planned.unprovable,
            planned.unproven,
            planned.evicted,
            output::millis_since(started)
        )),
        Err(error) => output::arguments(format_args!("TRANSLATIONS not written: {error:?}\n")),
    }
}
