//! The SEP nonce store on a host partition: Stela's stand-in for xART's
//! gigalocker, which the real SEP keeps on effaceable NAND. This reuses the
//! NOR-persistence pattern ([`super::super::super::nor::persist`]): the
//! partition holds two generation-stamped banks, an update writes the idle
//! bank and flushes, and the newest valid bank wins. That gives the
//! [`Backend`] contract an atomic, durable compare-and-replace of the head and
//! record together, and detects rollback to an older *bank*.
//!
//! Limit: a medium that is rolled back as a whole (both banks together)
//! cannot be distinguished here, exactly as `store`'s HMAC cannot. True
//! anti-rollback needs a monotonic secret the host does not have; this adapter
//! provides durability and torn-write/older-bank protection only.
use super::{Backend, Head};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use sha2::{Digest, Sha256};
use stela_drivers::block::BlockDevice;

const MAGIC: &[u8; 8] = b"STXARTB1";
const GENERATION: core::ops::Range<usize> = 8..16;
const LENGTH: core::ops::Range<usize> = 16..20;
const CHECKSUM: core::ops::Range<usize> = 20..52;
/// Record bytes begin after magic, generation, length and the bank checksum.
const RECORD: usize = 52;
const BANKS: u64 = 2;
/// One bank. Holds the store's largest record (`store::MAX_BYTES`, ~5.4 KiB)
/// with room to spare; a whole bank is written each commit so updates are
/// block-aligned and torn writes fail the bank checksum.
pub const BANK_BYTES: usize = 0x2000;
const MAX_RECORD: usize = BANK_BYTES - RECORD;

/// The checksum guards a bank against torn writes; the record inside carries
/// its own HMAC, which `store` verifies and binds to the generation.
fn checksum(header: &[u8], record: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(&header[..CHECKSUM.start]);
    hash.update(record);
    hash.finalize().into()
}

fn parse(bank: &[u8]) -> Option<Head> {
    if &bank[..MAGIC.len()] != MAGIC {
        return None;
    }
    let length = u32::from_be_bytes(bank[LENGTH].try_into().unwrap()) as usize;
    if length > MAX_RECORD {
        return None;
    }
    let record = &bank[RECORD..RECORD + length];
    if bank[CHECKSUM] != checksum(bank, record) {
        return None;
    }
    Some(Head {
        generation: u64::from_be_bytes(bank[GENERATION].try_into().unwrap()),
        record: record.to_vec(),
    })
}

fn build(head: &Head) -> Result<Vec<u8>, &'static str> {
    if head.record.len() > MAX_RECORD {
        return Err("SEP nonce record exceeds the host bank");
    }
    let mut bank = vec![0u8; BANK_BYTES];
    bank[..MAGIC.len()].copy_from_slice(MAGIC);
    bank[GENERATION].copy_from_slice(&head.generation.to_be_bytes());
    bank[LENGTH].copy_from_slice(&(head.record.len() as u32).to_be_bytes());
    bank[RECORD..RECORD + head.record.len()].copy_from_slice(&head.record);
    let sum = checksum(&bank, &head.record);
    bank[CHECKSUM].copy_from_slice(&sum);
    Ok(bank)
}

/// A nonce store kept on `device`. Owns the two banks; nothing else may share
/// the partition.
pub struct HostStore {
    device: Box<dyn BlockDevice>,
    blocks_per_bank: u64,
    /// The durable newest bank: its generation and index, once known.
    newest: Option<(u64, u64)>,
}

impl HostStore {
    /// Bind to a partition whose geometry can hold two banks. First
    /// provisioning and reopening are the store's decision ([`super::Nonces`]).
    pub fn new(device: Box<dyn BlockDevice>) -> Result<Self, String> {
        let identity = device.identity();
        let block = identity.block_size as usize;
        if block == 0 || !BANK_BYTES.is_multiple_of(block) {
            return Err(format!(
                "xART partition block size {block} does not divide a {BANK_BYTES}-byte bank"
            ));
        }
        let blocks_per_bank = (BANK_BYTES / block) as u64;
        if identity.read_only || identity.blocks < blocks_per_bank * BANKS {
            return Err("the xART partition is read-only or smaller than two banks".into());
        }
        Ok(Self {
            device,
            blocks_per_bank,
            newest: None,
        })
    }

    /// Hand the backing device back, for a reopen across a simulated reboot.
    #[cfg(test)]
    pub fn into_device(self) -> Box<dyn BlockDevice> {
        self.device
    }

    fn read_bank(&mut self, index: u64) -> Result<Vec<u8>, &'static str> {
        let mut bank = vec![0u8; BANK_BYTES];
        self.device
            .read(index * self.blocks_per_bank, &mut bank)
            .map_err(|_| "SEP nonce store bank read failed")?;
        Ok(bank)
    }
}

impl Backend for HostStore {
    fn load(&mut self) -> Result<Option<Head>, &'static str> {
        let mut best: Option<(u64, u64, Head)> = None;
        let mut any_bytes = false;
        for index in 0..BANKS {
            let bank = self.read_bank(index)?;
            any_bytes |= bank.iter().any(|&byte| byte != 0);
            if let Some(head) = parse(&bank)
                && best.as_ref().is_none_or(|(g, _, _)| head.generation > *g)
            {
                best = Some((head.generation, index, head));
            }
        }
        match best {
            Some((generation, index, head)) => {
                self.newest = Some((generation, index));
                Ok(Some(head))
            }
            None if any_bytes => {
                Err("the xART partition is neither blank nor a valid SEP nonce store")
            }
            None => {
                self.newest = None;
                Ok(None)
            }
        }
    }

    fn commit(&mut self, expected: u64, next: Head) -> Result<(), &'static str> {
        if self.newest.map_or(0, |(g, _)| g) != expected {
            return Err("SEP nonce store durable head does not match the expected generation");
        }
        if next.generation != expected + 1 {
            return Err("SEP nonce store commit must advance the generation by one");
        }
        // Write the idle bank, so a torn write cannot destroy the live one.
        let target = self.newest.map_or(0, |(_, index)| index ^ 1);
        let bank = build(&next)?;
        self.device
            .write(target * self.blocks_per_bank, &bank)
            .map_err(|_| "SEP nonce store bank write failed")?;
        self.device
            .flush()
            .map_err(|_| "SEP nonce store bank flush failed")?;
        self.newest = Some((next.generation, target));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Nonces;
    use super::*;
    use crate::platform::apple::sep::keys::Roots;
    use stela_drivers::block::RamDisk;

    fn roots() -> Roots {
        Roots::provisioned([9; 32], [8; 32], 0xa5a5_0003).unwrap()
    }
    fn entropy(bytes: &mut [u8]) -> Result<(), &'static str> {
        bytes.fill(0x5a);
        Ok(())
    }
    fn disk() -> RamDisk {
        // Four banks of room, 512-byte blocks.
        RamDisk::new("xart", (BANK_BYTES as u64 / 512) * 4, 512)
    }

    #[test]
    fn a_blank_partition_provisions_and_survives_reopen_across_banks() {
        let mut store = Nonces::provision(&roots(), HostStore::new(Box::new(disk())).unwrap())
            .expect("blank partition provisions");
        let nonce = store.generate(7, &mut entropy).unwrap();
        store.commit_firmware([3; 48]).unwrap();
        // Several updates, so both banks are exercised and the newest wins.
        store.generate(9, &mut entropy).unwrap();
        store.invalidate(9).unwrap();

        let device = store.into_backend().into_device();
        let reopened = Nonces::open(&roots(), HostStore::new(device).unwrap()).expect("reopen");
        assert_eq!(reopened.read(7), Ok(nonce));
        assert_eq!(reopened.firmware(), Ok(Some([3; 48])));
        assert!(reopened.read(9).is_err());
        // A different machine root cannot open this store.
        let device = reopened.into_backend().into_device();
        assert!(
            Nonces::open(
                &Roots::provisioned([1; 32], [8; 32], 0xa5a5_0003).unwrap(),
                HostStore::new(device).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn the_newest_bank_wins_and_a_torn_bank_falls_back() {
        let mut store =
            Nonces::provision(&roots(), HostStore::new(Box::new(disk())).unwrap()).unwrap();
        let first = store.generate(1, &mut entropy).unwrap();
        store.generate(2, &mut entropy).unwrap(); // generation now spans both banks
        let mut device = store.into_backend().into_device();
        // Corrupt the newest bank's checksum; load must fall back to the older
        // valid bank rather than treat the store as foreign.
        let mut both = [vec![0u8; BANK_BYTES], vec![0u8; BANK_BYTES]];
        device.read(0, &mut both[0]).unwrap();
        device.read(BANK_BYTES as u64 / 512, &mut both[1]).unwrap();
        let newest = if u64::from_be_bytes(both[0][GENERATION].try_into().unwrap())
            > u64::from_be_bytes(both[1][GENERATION].try_into().unwrap())
        {
            0
        } else {
            1
        };
        let mut torn = both[newest].clone();
        torn[CHECKSUM.start] ^= 1;
        device
            .write(newest as u64 * (BANK_BYTES as u64 / 512), &torn)
            .unwrap();
        let reopened = Nonces::open(&roots(), HostStore::new(device).unwrap()).unwrap();
        // The surviving bank is the one before slot 2 was added: slot 1 only.
        assert_eq!(reopened.read(1), Ok(first));
    }

    #[test]
    fn a_foreign_partition_and_a_tiny_partition_refuse() {
        let mut foreign = disk();
        foreign.bytes[100] = 0x42;
        let mut backend = HostStore::new(Box::new(foreign)).unwrap();
        assert!(matches!(backend.load(), Err(reason) if reason.contains("neither blank")));
        assert!(HostStore::new(Box::new(RamDisk::new("small", 4, 512))).is_err());
        assert!(HostStore::new(Box::new(RamDisk::new("odd", 1024, 3000))).is_err());
    }
}
