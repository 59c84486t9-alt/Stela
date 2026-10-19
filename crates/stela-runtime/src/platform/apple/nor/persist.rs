//! The NOR image on a host partition, so NVRAM survives reboots.
//!
//! The partition's first [`CAPACITY`] bytes hold the image as the die
//! stores it. An all-zero region is a partition never used for NOR (a new
//! GPT partition reads as zeros) and receives a fresh image; any other
//! content must hold a valid NVRAM bank, so a wrong partition is refused
//! instead of overwritten. Committed changes are stored by erase sector.
use super::{CAPACITY, Image, SECTOR_SIZE};
use crate::platform::pc::block::BlockDevice;
use alloc::{format, string::String, vec};

/// The image `device` holds, and whether it was blank and has just been
/// initialized.
pub fn load(device: &mut dyn BlockDevice) -> Result<(Image, bool), String> {
    let block_size = sector_blocks(device)?.1;
    let mut bytes = vec![0; CAPACITY];
    device
        .read(0, &mut bytes)
        .map_err(|error| format!("NOR partition read: {error}"))?;
    if bytes.iter().all(|&b| b == 0) {
        let image = Image::fresh();
        device
            .write(0, image.bytes())
            .and_then(|()| device.flush())
            .map_err(|error| format!("NOR partition initialization: {error}"))?;
        return Ok((image, true));
    }
    let image = Image::from_bytes(bytes).map_err(String::from)?;
    image.current_bank().map_err(|_| {
        format!(
            "the NOR partition ({block_size}-byte blocks) is neither blank nor a NOR image \
             with a valid NVRAM bank"
        )
    })?;
    Ok((image, false))
}

/// Store the sector at `offset`, durably.
pub fn store(device: &mut dyn BlockDevice, offset: usize, sector: &[u8]) -> Result<(), String> {
    let (per_sector, block_size) = sector_blocks(device)?;
    if !offset.is_multiple_of(SECTOR_SIZE) || sector.len() != SECTOR_SIZE || offset >= CAPACITY {
        return Err("a NOR store is one whole sector inside the image".into());
    }
    let lba = (offset / SECTOR_SIZE) as u64 * per_sector;
    device
        .write(lba, sector)
        .and_then(|()| device.flush())
        .map_err(|error| {
            format!("NOR partition write at {offset:#x} ({block_size}-byte blocks): {error}")
        })
}

/// Save `bank` into `image`'s next NVRAM bank ([`Image::save_bank`]) and
/// store every sector it changed; returns the bank written.
pub fn save_bank(
    device: &mut dyn BlockDevice,
    image: &mut Image,
    bank: &[u8],
) -> Result<u32, String> {
    let (written, sectors) = image.save_bank(bank).map_err(String::from)?;
    for offset in sectors {
        let sector = image.bytes()[offset..offset + SECTOR_SIZE].to_vec();
        store(device, offset, &sector)?;
    }
    Ok(written)
}

/// Blocks per sector and the block size; the partition must hold the image
/// in whole sectors.
fn sector_blocks(device: &dyn BlockDevice) -> Result<(u64, u32), String> {
    let identity = device.identity();
    let block_size = identity.block_size;
    if block_size == 0 || !SECTOR_SIZE.is_multiple_of(block_size as usize) {
        return Err(format!(
            "NOR partition block size {block_size} does not divide a sector"
        ));
    }
    if identity.read_only || identity.blocks * u64::from(block_size) < CAPACITY as u64 {
        return Err("the NOR partition is read-only or smaller than the 1 MiB image".into());
    }
    Ok(((SECTOR_SIZE / block_size as usize) as u64, block_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::pc::block::tests::RamDisk;

    #[test]
    fn a_blank_partition_is_initialized_and_sectors_persist() {
        let mut disk = RamDisk::new("nor", 2048, 512);
        let (image, fresh) = load(&mut disk).unwrap();
        assert!(fresh);
        assert_eq!(&disk.bytes[..CAPACITY], image.bytes());
        let mut sector = vec![0xff; SECTOR_SIZE];
        sector[0] = 0x42;
        store(&mut disk, 0x2000, &sector).unwrap();
        let (again, fresh) = load(&mut disk).unwrap();
        assert!(!fresh);
        assert_eq!(again.bytes()[0x2000], 0x42);
        assert!(store(&mut disk, 0x2001, &sector).is_err());
        assert!(store(&mut disk, CAPACITY, &sector).is_err());
    }

    #[test]
    fn a_saved_bank_goes_to_the_next_bank_and_survives_a_reload() {
        use super::super::nvram::{Partition, Variables};
        let mut disk = RamDisk::new("nor", 2048, 512);
        let (mut image, _) = load(&mut disk).unwrap();
        let mut variables = Variables::parse(image.bank(0).unwrap()).unwrap();
        variables
            .set(Partition::System, b"boot-volume", b"x:y:z")
            .unwrap();
        let bank = variables.encode().unwrap();
        assert_eq!(save_bank(&mut disk, &mut image, &bank).unwrap(), 1);
        let (again, _) = load(&mut disk).unwrap();
        assert_eq!(again.current_bank().unwrap(), 1);
        assert_eq!(again.bank(1).unwrap(), bank.as_slice());
        // An older or equal generation is refused.
        assert!(save_bank(&mut disk, &mut image, &bank).is_err());
    }

    #[test]
    fn foreign_and_small_partitions_are_refused() {
        let mut foreign = RamDisk::new("x", 2048, 512);
        foreign.bytes[7] = 1;
        assert!(load(&mut foreign).is_err());
        assert_eq!(foreign.bytes[7], 1);
        assert!(load(&mut RamDisk::new("small", 100, 512)).is_err());
        assert!(load(&mut RamDisk::new("odd", 4096, 3000)).is_err());
    }
}
