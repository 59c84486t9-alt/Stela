//! DeviceTree namespace records, independent of a backing medium or driver.
//! The execution model assigns and erases medium extents separately.
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

pub const BLOCK_BYTES: u32 = 4096;
const RECORD_BYTES: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    pub id: u32,
    pub kind: u32,
    pub blocks: u32,
}

impl Description {
    pub fn decode(property: &[u8]) -> Result<Vec<Self>> {
        if property.is_empty() || !property.len().is_multiple_of(RECORD_BYTES) {
            return Err(refuse!("ANS namespaces must be nonempty 12-byte records"));
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
                return Err(refuse!(
                    "ANS namespaces require consecutive IDs and a four-bit type"
                ));
            }
            records.push(entry);
        }
        if records.len() > 255 {
            return Err(refuse!("ANS has more than 255 namespaces"));
        }
        Ok(records)
    }
}
