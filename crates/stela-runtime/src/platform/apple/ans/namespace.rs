//! Namespace records from `/arm-io/ans` `namespaces`: three little-endian
//! u32s, namespace ID, Apple type and logical block count (0 uses the
//! remaining medium). `AppleEmbeddedNVMeController::SetNamespacesStruct`
//! (26A434 file 0x3db1a64) checks a multiple of 12 and prefixes the record
//! count. `CreateNamespaces` (0x3db5718) sends those records with admin 0xc6;
//! `DetermineNamespaces` (0x3db50c0) reads Identify byte 0x180 as the type and
//! byte 8 as the capacity. `CheckNameSpaceSizeMismatch` (0x3dc1038) exempts
//! namespace 1 and checks the others against those block counts.
//!
//! Stela's medium layout is an explicit choice, not a recovered Apple NAND
//! layout: fixed namespaces follow the growable namespace, all in DT order,
//! in one selected host partition. Logical blocks are 4 KiB (one LBA format,
//! no metadata); host blocks may be 512 B or 4 KiB. No auxiliary namespace is
//! volatile and no namespace can address bytes outside that partition.
use crate::platform::pc::block::{BlockDevice, BlockError};
use alloc::vec::Vec;

pub const BLOCK_BYTES: u32 = 4096;
const RECORD_BYTES: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    pub id: u32,
    pub kind: u32,
    pub blocks: u32,
}

impl Description {
    pub fn decode(property: &[u8]) -> Result<Vec<Self>, &'static str> {
        if property.is_empty() || !property.len().is_multiple_of(RECORD_BYTES) {
            return Err("ANS namespaces must be nonempty 12-byte records");
        }
        let mut records = Vec::new();
        for record in property.as_chunks::<RECORD_BYTES>().0 {
            let word = |offset| u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap());
            let entry = Self {
                id: word(0),
                kind: word(4),
                blocks: word(8),
            };
            if entry.id as usize != records.len() + 1 || entry.kind >= 16 {
                return Err("ANS namespaces require consecutive IDs and a four-bit type");
            }
            records.push(entry);
        }
        if records.len() > 255 {
            return Err("ANS has more than 255 namespaces");
        }
        Ok(records)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Namespace {
    pub description: Description,
    pub first: u64,
    pub blocks: u64,
}

pub(super) struct Medium {
    pub device: alloc::boxed::Box<dyn BlockDevice>,
    pub namespaces: Vec<Namespace>,
    host_blocks_per_lba: u64,
}

impl Medium {
    pub fn new(
        device: alloc::boxed::Box<dyn BlockDevice>,
        descriptions: &[Description],
    ) -> Result<Self, &'static str> {
        let id = device.identity();
        if !matches!(id.block_size, 512 | BLOCK_BYTES) {
            return Err("ANS backing block size must be 512 or 4096 bytes");
        }
        if descriptions.is_empty() || descriptions.len() > 255 {
            return Err("ANS requires one to 255 namespaces");
        }
        let ratio = u64::from(BLOCK_BYTES / id.block_size);
        if !id.blocks.is_multiple_of(ratio) {
            return Err("ANS partition capacity must be a multiple of 4096 bytes");
        }
        let total = id.blocks / ratio;
        let mut fixed = 0u64;
        let mut grow = 0;
        for (i, description) in descriptions.iter().enumerate() {
            if description.id as usize != i + 1 || description.kind >= 16 {
                return Err("ANS namespace IDs/types are invalid");
            }
            if description.blocks == 0 {
                grow += 1;
            }
            fixed = fixed
                .checked_add(u64::from(description.blocks))
                .ok_or("ANS namespace size overflow")?;
        }
        if grow > 1
            || fixed > total
            || (grow == 1 && fixed == total)
            || (grow == 0 && fixed != total)
        {
            return Err("ANS namespace sizes do not fit the selected partition");
        }
        let mut first = 0;
        let namespaces = descriptions
            .iter()
            .map(|&description| {
                let blocks = if description.blocks == 0 {
                    total - fixed
                } else {
                    u64::from(description.blocks)
                };
                let namespace = Namespace {
                    description,
                    first,
                    blocks,
                };
                first += blocks;
                namespace
            })
            .collect();
        Ok(Self {
            device,
            namespaces,
            host_blocks_per_lba: ratio,
        })
    }

    pub fn namespace(&self, id: u32) -> Option<Namespace> {
        id.checked_sub(1)
            .and_then(|i| self.namespaces.get(i as usize))
            .copied()
    }

    pub fn address(&self, id: u32, lba: u64, blocks: u64) -> Option<u64> {
        let namespace = self.namespace(id)?;
        (lba.checked_add(blocks)? <= namespace.blocks)
            .then(|| (namespace.first + lba) * self.host_blocks_per_lba)
    }

    pub fn read(&mut self, id: u32, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let blocks = buffer.len() as u64 / u64::from(BLOCK_BYTES);
        let address = self
            .address(id, lba, blocks)
            .ok_or(BlockError::Unsupported("ANS namespace range"))?;
        self.device.read(address, buffer)
    }

    pub fn write(&mut self, id: u32, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        let blocks = data.len() as u64 / u64::from(BLOCK_BYTES);
        let address = self
            .address(id, lba, blocks)
            .ok_or(BlockError::Unsupported("ANS namespace range"))?;
        self.device.write(address, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::pc::block::tests::RamDisk;
    use alloc::boxed::Box;

    #[test]
    fn records_and_persistent_partition_extents() {
        let records = [
            Description {
                id: 1,
                kind: 1,
                blocks: 0,
            },
            Description {
                id: 2,
                kind: 8,
                blocks: 3,
            },
        ];
        let bytes: Vec<_> = records
            .iter()
            .flat_map(|d| [d.id, d.kind, d.blocks])
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(Description::decode(&bytes).unwrap(), records);
        assert!(Description::decode(&bytes[..23]).is_err());
        for block_size in [512, 4096] {
            let disk = RamDisk::new("medium", 10 * 4096 / u64::from(block_size), block_size);
            let mut medium = Medium::new(Box::new(disk), &records).unwrap();
            assert_eq!(medium.namespace(1).unwrap().blocks, 7);
            assert_eq!(medium.namespace(2).unwrap().first, 7);
            medium.write(2, 0, &[0x5a; 4096]).unwrap();
            let mut data = [0; 4096];
            medium.read(2, 0, &mut data).unwrap();
            assert_eq!(data, [0x5a; 4096]);
            medium.read(1, 6, &mut data).unwrap();
            assert_eq!(data, [0; 4096]);
            assert_eq!(medium.address(1, 7, 1), None);
            assert_eq!(medium.address(2, 3, 1), None);
            assert_eq!(medium.address(2, u64::MAX, 1), None);
            assert_eq!(medium.address(0, 0, 1), None);
        }
    }

    #[test]
    fn insufficient_ambiguous_or_unaligned_backing_refuses() {
        let disk = || Box::new(RamDisk::new("", 8, 512)) as alloc::boxed::Box<dyn BlockDevice>;
        let d = |id, blocks| Description {
            id,
            kind: 1,
            blocks,
        };
        for records in [
            alloc::vec![],
            alloc::vec![d(1, 2)],
            alloc::vec![d(1, 0), d(2, 0)],
            alloc::vec![d(2, 0)],
        ] {
            assert!(Medium::new(disk(), &records).is_err());
        }
        assert!(Medium::new(Box::new(RamDisk::new("", 9, 512)), &[d(1, 0)]).is_err());
    }
}
