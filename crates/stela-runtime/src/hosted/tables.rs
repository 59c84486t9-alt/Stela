//! The hosted PE's stage 1: an identity map of the whole 47-bit EL0 range,
//! so a guest virtual address is the guest physical address and both are the
//! host virtual address native code reaches. Every 1 GiB block is EL0
//! read/write and executable, never privileged-executable: the host's own
//! page protections and mappings decide each access, and a refused native
//! access becomes the guest's level-3 fault ([`super::host`]).
//!
//! The 4 KiB granule with T0SZ 17 walks from level 0 (bits 46:39) to level 1
//! blocks (bits 38:30). XNU uses the 16 KiB granule (`TCR_EL1_16KB`); the
//! granule is invisible at EL0, whose page size comes from the commpage.
use anyhow::{Result, ensure};

/// The guest's EL0 virtual address width: XNU arm64 `T0SZ_BOOT` 17.
pub const ADDRESS_BITS: u32 = 47;
pub const T0SZ: u64 = 64 - ADDRESS_BITS as u64;
const GRANULE: usize = 4096;
const ENTRIES: usize = GRANULE / 8;
const BLOCK_SHIFT: u32 = 30;
const LEVEL0_SHIFT: u32 = 39;
const LEVEL0_ENTRIES: usize = 1 << (ADDRESS_BITS - LEVEL0_SHIFT);
const TABLE_BYTES: usize = (1 + LEVEL0_ENTRIES) * GRANULE;
/// VMSAv8-64 descriptor fields.
const VALID: u64 = 1;
const TABLE: u64 = 1 << 1;
const BLOCK: u64 = 0;
/// AttrIndx 0: MAIR_EL1 attribute 0, Normal Write-Back.
const ATTRIBUTE_NORMAL: u64 = 0;
/// AP[2:1] = 0b01: read/write at EL1 and EL0.
const ACCESS_EL0_READ_WRITE: u64 = 1 << 6;
/// SH = 0b11: Inner Shareable.
const INNER_SHAREABLE: u64 = 3 << 8;
const ACCESS_FLAG: u64 = 1 << 10;
/// PXN: EL1 never executes guest memory.
const PRIVILEGED_EXECUTE_NEVER: u64 = 1 << 53;

/// The translation tables, in host memory the guest never maps.
pub struct Tables {
    base: *mut u64,
}

impl Tables {
    pub fn new() -> Result<Self> {
        // SAFETY: a fresh private anonymous mapping owned by this value.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                TABLE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        ensure!(
            base != libc::MAP_FAILED,
            "cannot map the translation tables: {}",
            std::io::Error::last_os_error()
        );
        let base = base.cast::<u64>();
        let root = base as u64;
        for index in 0..LEVEL0_ENTRIES {
            let table = root + ((1 + index) * GRANULE) as u64;
            // SAFETY: inside the mapping just made.
            unsafe { base.add(index).write(table | TABLE | VALID) };
            for block in 0..ENTRIES {
                let address = ((index << (LEVEL0_SHIFT - BLOCK_SHIFT)) + block) as u64;
                let descriptor = (address << BLOCK_SHIFT)
                    | PRIVILEGED_EXECUTE_NEVER
                    | ACCESS_FLAG
                    | INNER_SHAREABLE
                    | ACCESS_EL0_READ_WRITE
                    | ATTRIBUTE_NORMAL << 2
                    | BLOCK
                    | VALID;
                // SAFETY: inside the mapping just made.
                unsafe {
                    base.add((1 + index) * ENTRIES + block).write(descriptor);
                }
            }
        }
        Ok(Self { base })
    }

    /// TTBR0_EL1: the level 0 table's address (ASID 0).
    pub fn root(&self) -> u64 {
        self.base as u64
    }

    pub fn contains(&self, address: u64, bytes: usize) -> bool {
        let start = self.base as u64;
        address < start + TABLE_BYTES as u64 && address.saturating_add(bytes as u64) > start
    }

    /// Copy table bytes for the engine's walker, or false outside them.
    pub fn read(&self, address: u64, buffer: &mut [u8]) -> bool {
        let start = self.base as u64;
        let Some(offset) = address.checked_sub(start) else {
            return false;
        };
        if offset as usize + buffer.len() > TABLE_BYTES {
            return false;
        }
        // SAFETY: inside the mapping, into a distinct buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.base as *const u8).add(offset as usize),
                buffer.as_mut_ptr(),
                buffer.len(),
            );
        }
        true
    }
}

impl Drop for Tables {
    fn drop(&mut self) {
        // SAFETY: the mapping this value made.
        unsafe { libc::munmap(self.base.cast(), TABLE_BYTES) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_blocks_cover_the_el0_range() {
        let tables = Tables::new().unwrap();
        let mut word = [0u8; 8];
        assert!(tables.read(tables.root(), &mut word));
        let level0 = u64::from_le_bytes(word);
        assert_eq!(level0 & 3, TABLE | VALID);
        let address = 0x1_8000_0000u64;
        let level1 = (level0 & !0xfff) + 8 * ((address >> BLOCK_SHIFT) & (ENTRIES as u64 - 1));
        assert!(tables.read(level1, &mut word));
        let block = u64::from_le_bytes(word);
        assert_eq!(block & 3, VALID);
        assert_eq!(block & 0x0000_ffff_c000_0000, address);
        assert_ne!(block & ACCESS_EL0_READ_WRITE, 0);
        assert!(!tables.read(tables.root() + TABLE_BYTES as u64, &mut word));
        assert!(tables.contains(tables.root() + 8, 8));
    }
}
