//! The NOR image on a host partition, so NVRAM survives reboots.
//!
//! The partition's first [`CAPACITY`] bytes hold the image as the die
//! stores it. An all-zero region is a partition never used for NOR (a new
//! GPT partition reads as zeros) and receives a fresh image; any other
//! content must identify a NOR image ([`Image::boot_bank`]), so a wrong
//! partition is refused. Damaged banks remain unchanged: boot firmware
//! supplies an empty proxy until the guest saves. Committed changes are
//! stored by erase sector.
use super::{CAPACITY, Image, SECTOR_SIZE};
use crate::Result;
use alloc::{vec, vec::Vec};
use stela_contracts::refuse;
use stela_drivers::block::{BlockDevice, Identity, Request};

/// The image `device` holds, and whether it was blank and has just been
/// initialized.
pub fn load(device: &mut dyn BlockDevice) -> Result<(Image, bool)> {
    let block_size = sector_blocks(device.identity())?.1;
    let mut bytes = vec![0; CAPACITY];
    device
        .read(0, &mut bytes)
        .map_err(|error| refuse!("NOR partition read: {error}", ?error))?;
    if bytes.iter().all(|&b| b == 0) {
        let image = Image::fresh();
        device
            .write(0, image.bytes())
            .and_then(|()| device.flush())
            .map_err(|error| refuse!("NOR partition initialization: {error}", ?error))?;
        return Ok((image, true));
    }
    let image = Image::from_bytes(bytes)?;
    image.boot_bank().map_err(|_| {
        refuse!(
            "the NOR partition ({block_size}-byte blocks) is neither blank nor an identifiable \
             NOR image",
            block_size
        )
    })?;
    Ok((image, false))
}

/// Store the sector at `offset`, durably.
pub fn store(device: &mut dyn BlockDevice, offset: usize, sector: &[u8]) -> Result<()> {
    let block_size = device.identity().block_size;
    request(device.identity(), offset, sector.to_vec())?
        .run(device)
        .map(drop)
        .map_err(|error| {
            refuse!(
                "NOR partition write at {offset:#x} ({block_size}-byte blocks): {error}",
                offset,
                block_size,
                ?error
            )
        })
}

/// The durable write that stores `sector`, at `offset`, on a device of
/// `identity`.
pub fn request(identity: &Identity, offset: usize, sector: Vec<u8>) -> Result<Request> {
    let per_sector = sector_blocks(identity)?.0;
    if !offset.is_multiple_of(SECTOR_SIZE) || sector.len() != SECTOR_SIZE || offset >= CAPACITY {
        return Err(refuse!("a NOR store is one whole sector inside the image"));
    }
    Ok(Request::Write {
        lba: (offset / SECTOR_SIZE) as u64 * per_sector,
        data: sector,
        durable: true,
    })
}

/// Save `bank` into `image`'s next NVRAM bank ([`Image::save_bank`]) and
/// store every sector it changed; returns the bank written.
pub fn save_bank(device: &mut dyn BlockDevice, image: &mut Image, bank: &[u8]) -> Result<u32> {
    let (written, sectors) = image.save_bank(bank)?;
    for offset in sectors {
        let sector = image.bytes()[offset..offset + SECTOR_SIZE].to_vec();
        store(device, offset, &sector)?;
    }
    Ok(written)
}

/// Blocks per sector and the block size; the partition must hold the image
/// in whole sectors.
fn sector_blocks(identity: &Identity) -> Result<(u64, u32)> {
    let block_size = identity.block_size;
    if block_size == 0 || !SECTOR_SIZE.is_multiple_of(block_size as usize) {
        return Err(refuse!(
            "NOR partition block size {block_size} does not divide a sector",
            block_size
        ));
    }
    if identity.read_only || identity.blocks * u64::from(block_size) < CAPACITY as u64 {
        return Err(refuse!(
            "the NOR partition is read-only or smaller than the 8 MiB image"
        ));
    }
    Ok(((SECTOR_SIZE / block_size as usize) as u64, block_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::block::RamDisk;

    #[test]
    fn a_blank_partition_is_initialized_and_sectors_persist() {
        let mut disk = RamDisk::new("nor", CAPACITY as u64 / 512, 512);
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
        let mut disk = RamDisk::new("nor", CAPACITY as u64 / 512, 512);
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
        let mut foreign = RamDisk::new("x", CAPACITY as u64 / 512, 512);
        foreign.bytes[7] = 1;
        assert!(load(&mut foreign).is_err());
        assert_eq!(foreign.bytes[7], 1);
        assert!(load(&mut RamDisk::new("small", 100, 512)).is_err());
        assert!(load(&mut RamDisk::new("odd", 4096, 3000)).is_err());
    }

    #[test]
    fn loading_torn_banks_preserves_disk_bytes_until_the_guest_syncs() {
        let mut disk = RamDisk::new("nor", CAPACITY as u64 / 512, 512);
        let (image, _) = load(&mut disk).unwrap();
        let first = super::super::ANVRAM.0 as usize;
        // Neither bank validates: bank 0 has an incomplete payload; bank
        // 1 was erased before an interrupted program wrote its header.
        disk.bytes[first + 256..first + super::super::nvram::BANK_SIZE].fill(0xff);
        let before = disk.bytes.clone();
        let (loaded, fresh) = load(&mut disk).unwrap();
        assert!(!fresh);
        assert!(loaded.current_bank().is_err());
        assert_eq!(
            loaded.boot_bank().unwrap().1,
            super::super::nvram::empty_bank()
        );
        assert_eq!(loaded.bytes(), before);
        assert_eq!(disk.bytes, before);
        assert_ne!(loaded, image);
    }
}
