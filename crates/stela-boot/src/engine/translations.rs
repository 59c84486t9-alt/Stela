//! `stela.efi`'s translation store (`docs/design/runtime.md`, "Persistent
//! translation store"): the pack `stela setup` makes room for in
//! `EFI/stela/store` on a FAT32 volume of the boot USB.
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
use super::bundle::Bytes;
use crate::{firmware, handoff::Region, output, paging::PAGE};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::cell::UnsafeCell;
use stela_runtime::{
    pc::{block::BlockDevice, fat32::Fat32, gpt::Guid},
    translations::{
        self, Digest,
        pack::{self, Pack, Store},
    },
};
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
const DIRECTORY: &str = "EFI\\stela\\store";
const CONFIG: &str = "store.cfg";
const BYTES_KEY: &str = "bytes";
const CONFIG_LIMIT: usize = 256;
/// A pack's file name: the first bytes of its translator id in hex, an 8.3
/// name the FAT32 reader finds.
const NAME_BYTES: usize = 4;
const PACK_EXTENSION: &str = "pak";
/// The largest pack the boot holds in memory and writes: the bound of
/// `store.cfg` is cut to it.
const MAX_PACK_BYTES: u64 = 512 << 20;
/// The placement record at the start of the handoff file: magic, bound,
/// partition GUID, flags, pack bytes; the pack follows.
const PLACEMENT_MAGIC: [u8; 8] = *b"STLTSTOR";
const PLACEMENT_BYTES: usize = 64;
/// The pack file holds the bound's bytes and its volume's partition is
/// known: the engine may rewrite it.
const WRITABLE: u32 = 1;
/// The words of the buffer a grown file's `FileInfo` is built in: its fixed
/// fields and an 8.3 name.
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

/// Read `buffer.len()` bytes of `file` from `offset`.
fn read_at(file: &mut RegularFile, offset: u64, buffer: &mut [u8]) -> Option<()> {
    file.set_position(offset).ok()?;
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
fn partition(handle: uefi::Handle) -> Option<[u8; 16]> {
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
        // A read-only volume's pack is read and never written.
        let (mut file, writable) = match open(&mut root, &path, FileMode::CreateReadWrite) {
            Some(file) => (file, true),
            None => match open(&mut root, &path, FileMode::Read) {
                Some(file) => (file, false),
                None => {
                    output::arguments(format_args!("TRANSLATIONS {path} cannot be opened\n"));
                    return None;
                }
            },
        };
        let partition = partition(handle);
        let allocated = writable && allocate(&mut file, bound);
        let pack = read_pack(&mut file, &translator, bound);
        output::arguments(format_args!(
            "TRANSLATIONS {path} bound={bound} pack={} allocated={allocated} partition={}\n",
            pack.as_ref().map_or(0, Vec::len),
            partition.is_some()
        ));
        let pack = pack.unwrap_or_default();
        let bytes = PLACEMENT_BYTES + pack.len();
        let physical = firmware::pages(bytes.div_ceil(PAGE)).ok()?;
        // SAFETY: fresh pages Stela owns for the whole boot, never freed.
        let region = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, bytes) };
        let flags = if allocated && partition.is_some() {
            WRITABLE
        } else {
            0
        };
        region[..PLACEMENT_BYTES].fill(0);
        region[..8].copy_from_slice(&PLACEMENT_MAGIC);
        region[8..16].copy_from_slice(&bound.to_le_bytes());
        region[16..32].copy_from_slice(&partition.unwrap_or_default());
        region[32..36].copy_from_slice(&flags.to_le_bytes());
        region[40..48].copy_from_slice(&(pack.len() as u64).to_le_bytes());
        region[PLACEMENT_BYTES..].copy_from_slice(&pack);
        let region = Region {
            physical: physical as u64,
            bytes: bytes as u64,
        };
        return Some((region, flags & WRITABLE != 0));
    }
    None
}

/// Grow `file` to `bound` bytes: whether it holds them.
fn allocate(file: &mut RegularFile, bound: u64) -> bool {
    let Ok(info) = file.get_boxed_info::<FileInfo>() else {
        return false;
    };
    if info.file_size() >= bound {
        return true;
    }
    let mut storage = vec![0u64; FILE_INFO_WORDS];
    // SAFETY: the words' bytes, 8-byte aligned as FileInfo requires.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 8)
    };
    let Ok(grown) = FileInfo::new(
        bytes,
        bound,
        info.physical_size(),
        *info.create_time(),
        *info.last_access_time(),
        *info.modification_time(),
        info.attribute(),
        info.file_name(),
    ) else {
        return false;
    };
    file.set_info(grown).is_ok() && file.flush().is_ok()
}

/// The pack at the start of `file`, when its index is valid and it fits
/// the bound.
fn read_pack(file: &mut RegularFile, translator: &Digest, bound: u64) -> Option<Vec<u8>> {
    let mut header = vec![0; pack::HEADER_BYTES];
    read_at(file, 0, &mut header)?;
    let prefix = pack::prefix_bytes(&header, translator).ok()?;
    let mut bytes = vec![0; prefix];
    read_at(file, 0, &mut bytes)?;
    let length = Pack::length(&bytes, translator).ok()?;
    if length > bound {
        return None;
    }
    bytes.resize(length as usize, 0);
    read_at(file, prefix as u64, &mut bytes[prefix..])?;
    Some(bytes)
}

/// The boot's store, the bound and the partition it is written to.
struct Boot {
    store: Store<'static>,
    bound: u64,
    path: String,
    partition: Option<Box<dyn BlockDevice>>,
}

/// One PE runs the engine and its host at a time.
struct Cell(UnsafeCell<Option<Boot>>);
// SAFETY: the engine runs on one host CPU; nothing else reaches the store.
unsafe impl Sync for Cell {}
static BOOT: Cell = Cell(UnsafeCell::new(None));

fn boot_state() -> &'static mut Option<Boot> {
    // SAFETY: as for `Cell`: one CPU, and no reference outlives a call.
    unsafe { &mut *BOOT.0.get() }
}

/// The store the engine uses, if the loader read one.
pub fn store() -> Option<&'static mut Store<'static>> {
    boot_state().as_mut().map(|boot| &mut boot.store)
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
    *boot_state() = Some(Boot {
        store,
        bound,
        path: pack_path(&translator, "/"),
        partition: None,
    });
    let partition = Guid(contents[16..32].try_into().expect("a GUID"));
    (flags & WRITABLE != 0).then_some(partition)
}

/// Keep `partition`, the store's volume, for [`write`].
pub fn set_partition(partition: Box<dyn BlockDevice>) {
    if let Some(boot) = boot_state() {
        boot.partition = Some(partition);
    }
}

/// At a quiescent point (the guest restarts or powers off): prove the
/// blocks compiled anew and rewrite the pack in place.
pub fn write() {
    let Some(Boot {
        mut store,
        bound,
        path,
        partition: Some(partition),
    }) = boot_state().take()
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
    let planned = store.plan(bound);
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
    match pack::write_in_place(&mut *device, &file.extents, &planned.layout) {
        Ok(()) => output::arguments(format_args!(
            "TRANSLATIONS written records={} bytes={} proven={} unprovable={} evicted={}\n",
            planned.layout.records(),
            planned.layout.bytes(),
            planned.proven,
            planned.unprovable,
            planned.evicted
        )),
        Err(error) => output::arguments(format_args!("TRANSLATIONS not written: {error:?}\n")),
    }
}
