//! `obj_phys_t`, the header every APFS object starts with, and its Fletcher
//! 64 checksum (Apple File System Reference, "Objects").
use super::{Result, u32_at, u64_at};

/// `MAX_CKSUM_SIZE`.
pub const CHECKSUM_BYTES: usize = 8;
/// `sizeof(obj_phys_t)`.
pub const HEADER_BYTES: usize = 32;

pub const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x0000_0001;
pub const OBJECT_TYPE_BTREE: u32 = 0x0000_0002;
pub const OBJECT_TYPE_BTREE_NODE: u32 = 0x0000_0003;
pub const OBJECT_TYPE_OMAP: u32 = 0x0000_000b;
pub const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0000_000c;
pub const OBJECT_TYPE_FS: u32 = 0x0000_000d;
pub const OBJECT_TYPE_INTEGRITY_META: u32 = 0x0000_001e;

/// `OBJECT_TYPE_MASK`: the type is the low 16 bits of `o_type`.
pub const OBJECT_TYPE_MASK: u32 = 0x0000_ffff;
pub const OBJ_VIRTUAL: u32 = 0x0000_0000;
pub const OBJ_EPHEMERAL: u32 = 0x8000_0000;
pub const OBJ_PHYSICAL: u32 = 0x4000_0000;
pub const OBJ_STORAGETYPE_MASK: u32 = 0xc000_0000;
pub const OBJ_ENCRYPTED: u32 = 0x1000_0000;

/// How an object identifier is resolved to a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Looked up in an object map.
    Virtual,
    /// The identifier is the block address.
    Physical,
    /// Lives in the checkpoint data area.
    Ephemeral,
}

impl Storage {
    /// The storage kind encoded in an `o_type` or tree-type field.
    pub fn of(type_field: u32) -> Self {
        match type_field & OBJ_STORAGETYPE_MASK {
            OBJ_PHYSICAL => Self::Physical,
            OBJ_EPHEMERAL => Self::Ephemeral,
            _ => Self::Virtual,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub checksum: u64,
    pub oid: u64,
    pub xid: u64,
    /// `o_type` with its flags.
    pub type_field: u32,
    pub subtype: u32,
}

impl Header {
    pub fn parse(block: &[u8]) -> Result<Self> {
        Ok(Self {
            checksum: u64_at(block, 0)?,
            oid: u64_at(block, 8)?,
            xid: u64_at(block, 16)?,
            type_field: u32_at(block, 24)?,
            subtype: u32_at(block, 28)?,
        })
    }

    pub fn object_type(&self) -> u32 {
        self.type_field & OBJECT_TYPE_MASK
    }

    pub fn encrypted(&self) -> bool {
        self.type_field & OBJ_ENCRYPTED != 0
    }
}

/// The Fletcher 64 checksum APFS stores in `o_cksum`: 32-bit words of the
/// object after the checksum field, summed modulo 2^32 - 1, then folded so
/// the whole object sums to zero.
pub fn fletcher64(object: &[u8]) -> u64 {
    const MODULUS: u64 = 0xffff_ffff;
    let mut sum1 = 0u64;
    let mut sum2 = 0u64;
    for word in object[CHECKSUM_BYTES..].as_chunks::<4>().0 {
        sum1 = (sum1 + u64::from(u32::from_le_bytes(*word))) % MODULUS;
        sum2 = (sum2 + sum1) % MODULUS;
    }
    let check1 = MODULUS - ((sum1 + sum2) % MODULUS);
    let check2 = MODULUS - ((sum1 + check1) % MODULUS);
    (check2 << 32) | check1
}

/// Whether a whole-block object carries its correct checksum. An all-zero
/// block is never valid.
pub fn checksum_valid(object: &[u8]) -> bool {
    object.len() >= HEADER_BYTES
        && object.iter().any(|&b| b != 0)
        && u64::from_le_bytes(object[..CHECKSUM_BYTES].try_into().unwrap()) == fletcher64(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn checksums_round_trip_and_detect_corruption() {
        let mut block = vec![0u8; 4096];
        block[8..16].copy_from_slice(&7u64.to_le_bytes());
        block[24..28].copy_from_slice(&(OBJ_PHYSICAL | OBJECT_TYPE_OMAP).to_le_bytes());
        let sum = fletcher64(&block);
        block[..8].copy_from_slice(&sum.to_le_bytes());
        assert!(checksum_valid(&block));
        let header = Header::parse(&block).unwrap();
        assert_eq!(header.object_type(), OBJECT_TYPE_OMAP);
        assert_eq!(Storage::of(header.type_field), Storage::Physical);
        block[100] ^= 1;
        assert!(!checksum_valid(&block));
        assert!(!checksum_valid(&vec![0u8; 4096]));
    }
}
