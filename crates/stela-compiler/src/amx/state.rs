//! The AMX register file: eight X rows, eight Y rows and a 64-row Z grid of
//! 64 bytes each (corsix/amx `RegisterFile.md`). Native kernels address it by
//! these fixed byte offsets.

/// Bytes per X, Y or Z row.
pub const ROW_BYTES: usize = 64;
pub const X_ROWS: usize = 8;
pub const Y_ROWS: usize = 8;
pub const Z_ROWS: usize = 64;
/// X and Y are each a 512-byte circular buffer.
pub const POOL_BYTES: usize = X_ROWS * ROW_BYTES;
pub const X_OFFSET: usize = 0;
pub const Y_OFFSET: usize = X_OFFSET + POOL_BYTES;
pub const Z_OFFSET: usize = Y_OFFSET + POOL_BYTES;
pub const REGISTER_BYTES: usize = Z_OFFSET + Z_ROWS * ROW_BYTES;

/// One thread's live AMX registers. Disabled state has no register file.
#[repr(C, align(128))]
#[derive(Clone, PartialEq, Eq)]
pub struct AmxRegisters {
    pub x: [[u8; ROW_BYTES]; X_ROWS],
    pub y: [[u8; ROW_BYTES]; Y_ROWS],
    pub z: [[u8; ROW_BYTES]; Z_ROWS],
}

impl AmxRegisters {
    /// The state `set` establishes.
    pub const fn zeroed() -> Self {
        Self {
            x: [[0; ROW_BYTES]; X_ROWS],
            y: [[0; ROW_BYTES]; Y_ROWS],
            z: [[0; ROW_BYTES]; Z_ROWS],
        }
    }

    /// The 64 X bytes at a pool byte offset, wrapping at 512 (`load_xy_reg`).
    pub fn x_operand(&self, offset: u64) -> [u8; ROW_BYTES] {
        pool_row(&self.x, offset)
    }

    /// The 64 Y bytes at a pool byte offset, wrapping at 512.
    pub fn y_operand(&self, offset: u64) -> [u8; ROW_BYTES] {
        pool_row(&self.y, offset)
    }

    pub fn as_bytes(&self) -> &[u8; REGISTER_BYTES] {
        // SAFETY: repr(C) with only u8 arrays: no padding, and the size is
        // REGISTER_BYTES (checked below).
        unsafe { &*(self as *const Self).cast() }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; REGISTER_BYTES] {
        // SAFETY: as above; every byte pattern is a valid register file.
        unsafe { &mut *(self as *mut Self).cast() }
    }
}

impl core::fmt::Debug for AmxRegisters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmxRegisters").finish_non_exhaustive()
    }
}

pub(crate) fn pool_row(pool: &[[u8; ROW_BYTES]; 8], offset: u64) -> [u8; ROW_BYTES] {
    let flat = pool.as_flattened();
    let start = offset as usize % POOL_BYTES;
    let first = (POOL_BYTES - start).min(ROW_BYTES);
    let mut row = [0; ROW_BYTES];
    row[..first].copy_from_slice(&flat[start..start + first]);
    row[first..].copy_from_slice(&flat[..ROW_BYTES - first]);
    row
}

const _: () = assert!(size_of::<AmxRegisters>() == REGISTER_BYTES);
const _: () = assert!(core::mem::offset_of!(AmxRegisters, y) == Y_OFFSET);
const _: () = assert!(core::mem::offset_of!(AmxRegisters, z) == Z_OFFSET);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_view_follows_the_published_layout() {
        let mut registers = AmxRegisters::zeroed();
        registers.x[7][63] = 1;
        registers.y[0][0] = 2;
        registers.z[63][63] = 3;
        let bytes = registers.as_bytes();
        assert_eq!(bytes.len(), 5 * 1024);
        assert_eq!(bytes[POOL_BYTES - 1], 1);
        assert_eq!(bytes[Y_OFFSET], 2);
        assert_eq!(bytes[REGISTER_BYTES - 1], 3);
        registers.as_bytes_mut()[Z_OFFSET] = 4;
        assert_eq!(registers.z[0][0], 4);
        // Operands wrap around the 512-byte pools.
        let x = registers.x_operand(POOL_BYTES as u64 - 1);
        assert_eq!((x[0], x[1]), (1, 0));
        assert_eq!(registers.y_operand(POOL_BYTES as u64 - 64)[0], 0);
        assert_eq!(registers.y_operand(POOL_BYTES as u64 - 63)[63], 2);
    }
}
