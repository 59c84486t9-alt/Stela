//! The USB's own boot log, [`BOOT_LOG_FILE`] beside Stela on its volume,
//! which `stela setup` preallocates contiguous: the loader writes it through
//! the firmware's file system from its first line until boot services end
//! ([`open`]), and the system engine writes on to the same blocks through
//! Stela's own drivers ([`resume`]), so the stick keeps the whole run.
use crate::{
    engine::{bundle::Bytes, translations},
    output::{self, Log},
};
use alloc::{boxed::Box, format, string::String};
use stela_drivers::block::{BlockDevice, BlockError, Identity, Shared, Transport};
use stela_loader::mount_interface::BOOT_LOG_FILE;
use stela_runtime::pc::{
    boot_log::{self, LOG_BYTES, Writer},
    fat32::Fat32,
    gpt::Guid,
};
use uefi::{
    CString16, Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::{
        ProtocolPointer,
        loaded_image::LoadedImage,
        media::{
            file::{File as _, FileAttribute, FileInfo, FileMode, RegularFile},
            fs::SimpleFileSystem,
        },
    },
};

/// The blocks the firmware's file is addressed in.
const BLOCK: u32 = 512;

/// Open the log on the volume Stela was loaded from, when it has one, and
/// return that partition's GUID, which the system engine opens it by.
pub fn open() -> Option<Guid> {
    let (device, partition) = match firmware_file() {
        Ok(opened) => opened,
        Err(why) => {
            output::arguments(format_args!("BOOT LOG FILE off: {why}\n"));
            return None;
        }
    };
    let mut device: Box<dyn BlockDevice> = Box::new(device);
    match Writer::open(&mut *device) {
        Ok(writer) => {
            report(&writer, "firmware");
            output::add_log(writer, device, Log::Firmware);
            partition
        }
        Err(error) => {
            output::arguments(format_args!("BOOT LOG FILE off: {error}\n"));
            None
        }
    }
}

/// Write on to the loader's log in its file on `partition`, the volume
/// [`open`] found it on.
pub fn resume(partition: Box<dyn BlockDevice>) {
    if let Err(why) = engine_file(partition) {
        output::arguments(format_args!("BOOT LOG FILE off: {why}\n"));
    }
}

fn report(writer: &Writer, through: &str) {
    if let Some(reason) = writer.fresh() {
        output::arguments(format_args!("BOOT LOG FILE fresh: {reason}\n"));
    }
    output::arguments(format_args!(
        "BOOT LOG FILE {BOOT_LOG_FILE} through the {through} boot={} head={:#x}\n",
        writer.boots(),
        writer.head()
    ));
}

/// `handle`'s `P`, shared with whoever else holds it.
fn shared<P: ProtocolPointer + ?Sized>(handle: Handle) -> Option<ScopedProtocol<P>> {
    // SAFETY: used only for queries and file access while boot services
    // run; no driver on `handle` is replaced while it is held.
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

fn firmware_file() -> Result<(FileDevice, Option<Guid>), &'static str> {
    let device = shared::<LoadedImage>(boot::image_handle())
        .ok_or("no loaded image")?
        .device()
        .ok_or("Stela was not loaded from a volume")?;
    let mut volume =
        shared::<SimpleFileSystem>(device).ok_or("Stela's volume has no file system")?;
    let mut root = volume
        .open_volume()
        .map_err(|_| "Stela's volume cannot be opened")?;
    let path = CString16::try_from(BOOT_LOG_FILE).map_err(|_| "the log's path is not UCS-2")?;
    let mut file = root
        .open(&path, FileMode::ReadWrite, FileAttribute::empty())
        .ok()
        .and_then(|file| file.into_regular_file())
        .ok_or("Stela's volume has no \\EFI\\stela\\boot.log")?;
    let size = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| "the log file's size cannot be read")?
        .file_size();
    if size < LOG_BYTES {
        return Err("\\EFI\\stela\\boot.log is shorter than the log");
    }
    let identity = Identity {
        transport: Transport::Firmware,
        location: String::from(BOOT_LOG_FILE),
        model: String::new(),
        serial: String::new(),
        blocks: LOG_BYTES / u64::from(BLOCK),
        block_size: BLOCK,
        read_only: false,
    };
    Ok((
        FileDevice { identity, file },
        translations::partition(device).map(Guid),
    ))
}

fn engine_file(partition: Box<dyn BlockDevice>) -> Result<(), String> {
    let block = u64::from(partition.identity().block_size);
    let mut volume = Fat32::open(Bytes::new(partition)).map_err(|error| format!("{error}"))?;
    let file = volume
        .file(&BOOT_LOG_FILE.replace('\\', "/"))
        .map_err(|error| format!("{error}"))?;
    let (first, _) =
        boot_log::file_blocks(&file, block, LOG_BYTES).map_err(|error| format!("{error}"))?;
    let partition = volume.into_inner().into_inner();
    let mut device: Box<dyn BlockDevice> = Box::new(
        Shared::new(partition)
            .window(first, LOG_BYTES / block)
            .map_err(|error| format!("{error}"))?,
    );
    let writer = Writer::resume(&mut *device).map_err(|error| format!("{error}"))?;
    report(&writer, "USB driver");
    output::add_log(writer, device, Log::Usb);
    Ok(())
}

/// The log file as blocks, through the firmware's file system.
struct FileDevice {
    identity: Identity,
    file: RegularFile,
}

impl FileDevice {
    fn seek(&mut self, lba: u64, bytes: usize) -> Result<(), BlockError> {
        if !bytes.is_multiple_of(BLOCK as usize) {
            return Err(BlockError::Misaligned {
                bytes,
                block_size: BLOCK,
            });
        }
        let blocks = (bytes / BLOCK as usize) as u64;
        if lba.saturating_add(blocks) > self.identity.blocks {
            return Err(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.identity.blocks,
            });
        }
        self.file
            .set_position(lba * u64::from(BLOCK))
            .map_err(|error| failed(error.status()))
    }
}

fn failed(status: uefi::Status) -> BlockError {
    BlockError::Device {
        status: status.0 as u32,
    }
}

impl BlockDevice for FileDevice {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.seek(lba, buffer.len())?;
        let mut done = 0;
        while done < buffer.len() {
            match self.file.read(&mut buffer[done..]) {
                Ok(0) => return Err(failed(uefi::Status::END_OF_FILE)),
                Ok(count) => done += count,
                Err(error) => return Err(failed(error.status())),
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.seek(lba, data.len())?;
        self.file
            .write(data)
            .map_err(|error| failed(error.status()))
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.file.flush().map_err(|error| failed(error.status()))
    }
}
