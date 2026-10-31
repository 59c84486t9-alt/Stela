//! The flash of the machine's board devices, on the machine-state partition.
//!
//! A Mac's USB-C controllers run firmware from flash of their own, which a
//! restore updates from its ramdisk. An installed system does not carry those
//! images: on 26A434 neither the System volume's root snapshot, the Recovery
//! BaseSystem, Preboot nor the SystemOS cryptex holds `USB-C_HPM,47.bin`. So
//! the image a boot bundle carries (`stela_loader::boot_bundle::Inputs`) stays
//! here, as it stays on the board, for the boots whose bundle is built from the
//! disk.
//!
//! The region starts at [`OFFSET`] of the partition, after the boot log, and
//! is [`BYTES`] long; a partition of at least [`PARTITION_BYTES`] holds it.
//! Its first [`HEADER_BYTES`] are the header, little-endian:
//!
//! | Offset | Bytes | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `STELABRD` |
//! | 8 | 4 | version, 1 |
//! | 12 | 4 | `count`: the images |
//! | 16 | [`ENTRY_BYTES`] × `count` | each image's name, zero-padded in [`NAME_BYTES`], its offset and length as `u32` and its SHA-256 |
//! | 4064 | 32 | SHA-256 of bytes 0..4064 |
//!
//! The images follow at block-aligned offsets from the region's start. A
//! blank header is an empty flash. [`Flash::keep`] writes only images that
//! differ, the images first and the header after them, each durable; an
//! interrupted write leaves images that fail their hash, which [`Flash::read`]
//! reports, and the next bundle that carries them writes them again.
use alloc::{format, string::String, vec, vec::Vec};
use core::fmt;
use stela_crypto::Sha256;
use stela_crypto::digest::Digest;
use stela_drivers::block::{BlockDevice, BlockError};

/// Where the region starts in the machine-state partition.
pub const OFFSET: u64 = super::boot_log::PARTITION_BYTES;
/// The region's bytes.
pub const BYTES: u64 = 2 << 20;
/// The smallest machine-state partition that holds the region.
pub const PARTITION_BYTES: u64 = OFFSET + BYTES;
pub const HEADER_BYTES: usize = 4096;
const MAGIC: &[u8; 8] = b"STELABRD";
const VERSION: u32 = 1;
const NAME_BYTES: usize = 56;
const ENTRY_BYTES: usize = NAME_BYTES + 8 + 32;
const ENTRIES: usize = 16;
/// The hashed part of the header.
const FIELDS: usize = HEADER_BYTES - 32;
const MAXIMUM_ENTRIES: usize = (FIELDS - ENTRIES) / ENTRY_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The header or an image is not what was written.
    Invalid(&'static str),
    /// The images do not fit the region.
    Full(String),
    Device(BlockError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::Full(reason) => f.write_str(reason),
            Self::Device(error) => write!(f, "{error}"),
        }
    }
}

impl From<BlockError> for Error {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

/// The images the flash holds, by the guest's file names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flash {
    images: Vec<(String, Vec<u8>)>,
}

fn block_size(device: &dyn BlockDevice) -> Result<usize, Error> {
    let block = device.identity().block_size as usize;
    if block == 0 || !HEADER_BYTES.is_multiple_of(block) {
        return Err(Error::Invalid(
            "the device's blocks do not divide the region's header",
        ));
    }
    Ok(block)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

impl Flash {
    /// The flash on `device`, the region alone.
    pub fn read(device: &mut dyn BlockDevice) -> Result<Self, Error> {
        let block = block_size(device)?;
        let mut header = vec![0; HEADER_BYTES];
        device.read(0, &mut header)?;
        if header.iter().all(|&byte| byte == 0) {
            return Ok(Self::default());
        }
        if &header[..8] != MAGIC || u32_at(&header, 8) != VERSION {
            return Err(Error::Invalid("the region is not board flash"));
        }
        if Sha256::digest(&header[..FIELDS])[..] != header[FIELDS..] {
            return Err(Error::Invalid("the board flash header fails its hash"));
        }
        let count = u32_at(&header, 12) as usize;
        if count > MAXIMUM_ENTRIES {
            return Err(Error::Invalid(
                "the board flash header lists too many images",
            ));
        }
        let mut images = Vec::with_capacity(count);
        for entry in header[ENTRIES..]
            .as_chunks::<ENTRY_BYTES>()
            .0
            .iter()
            .take(count)
        {
            let (name, rest) = entry.split_at(NAME_BYTES);
            let end = name
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(NAME_BYTES);
            let name = core::str::from_utf8(&name[..end])
                .map_err(|_| Error::Invalid("a board flash image's name is not text"))?;
            let (offset, length) = (u32_at(rest, 0) as usize, u32_at(rest, 4) as usize);
            let aligned = length.next_multiple_of(block);
            if !offset.is_multiple_of(block)
                || offset < HEADER_BYTES
                || offset as u64 + aligned as u64 > BYTES
            {
                return Err(Error::Invalid(
                    "a board flash image lies outside the region",
                ));
            }
            let mut bytes = vec![0; aligned];
            device.read((offset / block) as u64, &mut bytes)?;
            bytes.truncate(length);
            if Sha256::digest(&bytes)[..] != rest[8..] {
                return Err(Error::Invalid("a board flash image fails its hash"));
            }
            images.push((name.into(), bytes));
        }
        Ok(Self { images })
    }

    pub fn images(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.images
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
    }

    pub fn image(&self, name: &str) -> Option<&[u8]> {
        self.images()
            .find(|(held, _)| *held == name)
            .map(|(_, bytes)| bytes)
    }

    /// Keep `images`, each replacing the image of its name, and store the
    /// flash on `device` when that changed it. Returns whether it did.
    pub fn keep(
        &mut self,
        device: &mut dyn BlockDevice,
        images: &[(String, &[u8])],
    ) -> Result<bool, Error> {
        let block = block_size(device)?;
        let mut updated = self.clone();
        for (name, bytes) in images {
            if self.image(name) == Some(*bytes) {
                continue;
            }
            updated.images.retain(|(held, _)| held != name);
            updated.images.push((name.clone(), bytes.to_vec()));
        }
        if updated == *self {
            return Ok(false);
        }
        let (header, body) = updated.encode(block)?;
        device.write((HEADER_BYTES / block) as u64, &body)?;
        device.flush()?;
        device.write(0, &header)?;
        device.flush()?;
        *self = updated;
        Ok(true)
    }

    /// The header and the images that follow it.
    fn encode(&self, block: usize) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if self.images.len() > MAXIMUM_ENTRIES {
            return Err(Error::Full(format!(
                "{} images do not fit the header's {MAXIMUM_ENTRIES}",
                self.images.len()
            )));
        }
        let mut header = vec![0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&(self.images.len() as u32).to_le_bytes());
        let mut body = Vec::new();
        for ((name, bytes), entry) in self
            .images
            .iter()
            .zip(header[ENTRIES..].as_chunks_mut::<ENTRY_BYTES>().0)
        {
            if name.len() > NAME_BYTES {
                return Err(Error::Full(format!("{name} is longer than a name")));
            }
            let offset = HEADER_BYTES + body.len();
            body.extend_from_slice(bytes);
            body.resize(body.len().next_multiple_of(block), 0);
            if (HEADER_BYTES + body.len()) as u64 > BYTES {
                return Err(Error::Full(format!(
                    "{name} does not fit the region's {BYTES:#x} bytes"
                )));
            }
            let (field, rest) = entry.split_at_mut(NAME_BYTES);
            field[..name.len()].copy_from_slice(name.as_bytes());
            rest[..4].copy_from_slice(&(offset as u32).to_le_bytes());
            rest[4..8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            rest[8..].copy_from_slice(&Sha256::digest(bytes));
        }
        let digest = Sha256::digest(&header[..FIELDS]);
        header[FIELDS..].copy_from_slice(&digest);
        Ok((header, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::block::RamDisk;

    const NAME: &str = "USB-C_HPM,47.bin";

    fn disk() -> RamDisk {
        RamDisk::new("state", BYTES / 512, 512)
    }

    #[test]
    fn a_blank_region_is_an_empty_flash() {
        assert_eq!(Flash::read(&mut disk()), Ok(Flash::default()));
    }

    #[test]
    fn an_image_survives_and_is_not_written_again() {
        let mut disk = disk();
        let image = vec![0x5a; 1000];
        let images = [(String::from(NAME), image.as_slice())];
        let mut flash = Flash::default();
        assert_eq!(flash.keep(&mut disk, &images), Ok(true));
        let mut read = Flash::read(&mut disk).unwrap();
        assert_eq!(read.image(NAME), Some(image.as_slice()));
        assert_eq!(read.image("USB-C_HPM,48.bin"), None);
        let stored = disk.bytes.clone();
        assert_eq!(read.keep(&mut disk, &images), Ok(false));
        assert!(disk.bytes == stored);
    }

    #[test]
    fn a_new_image_replaces_the_one_of_its_name_and_keeps_the_others() {
        let mut disk = disk();
        let (old, other, new) = (vec![1; 700], vec![2; 700], vec![3; 900]);
        let mut flash = Flash::default();
        flash
            .keep(
                &mut disk,
                &[(NAME.into(), old.as_slice()), ("other".into(), &other)],
            )
            .unwrap();
        flash
            .keep(&mut disk, &[(NAME.into(), new.as_slice())])
            .unwrap();
        let read = Flash::read(&mut disk).unwrap();
        assert_eq!(read.image(NAME), Some(new.as_slice()));
        assert_eq!(read.image("other"), Some(other.as_slice()));
    }

    #[test]
    fn an_interrupted_write_reads_as_invalid_and_the_next_bundle_repairs_it() {
        let mut disk = disk();
        let image = vec![7; 1000];
        let images = [(String::from(NAME), image.as_slice())];
        Flash::default().keep(&mut disk, &images).unwrap();
        disk.bytes[HEADER_BYTES] ^= 1;
        assert_eq!(
            Flash::read(&mut disk),
            Err(Error::Invalid("a board flash image fails its hash"))
        );
        Flash::default().keep(&mut disk, &images).unwrap();
        assert_eq!(
            Flash::read(&mut disk).unwrap().image(NAME),
            Some(image.as_slice())
        );
    }

    #[test]
    fn foreign_bytes_and_a_torn_header_refuse() {
        let mut disk = disk();
        disk.bytes[0] = 1;
        assert_eq!(
            Flash::read(&mut disk),
            Err(Error::Invalid("the region is not board flash"))
        );
        let mut disk = self::disk();
        Flash::default()
            .keep(&mut disk, &[(NAME.into(), &[1, 2, 3][..])])
            .unwrap();
        disk.bytes[20] ^= 1;
        assert_eq!(
            Flash::read(&mut disk),
            Err(Error::Invalid("the board flash header fails its hash"))
        );
    }

    #[test]
    fn images_beyond_the_region_refuse_without_a_write() {
        let mut disk = disk();
        let image = vec![1; BYTES as usize];
        assert!(matches!(
            Flash::default().keep(&mut disk, &[(NAME.into(), image.as_slice())]),
            Err(Error::Full(_))
        ));
        assert!(disk.bytes.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn the_region_fits_the_tail_of_an_apple_region() {
        assert_eq!(PARTITION_BYTES, 0xe1_0000);
    }
}
