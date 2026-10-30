//! AES version, address-field and key-disable register geometry.
//! The command FIFO, key material, DMA and cipher execution are device-owned.
use crate::Result;
use stela_contracts::refuse;
/// The driver's `address-width` when the ADT gives none.
pub const DEFAULT_ADDRESS_WIDTH: u32 = 36;
/// The first `aes-version` with a DKey range.
pub const DKEY_VERSION: u32 = 5;
/// The widest `address-width` with 8-bit high address fields.
pub const NARROW_ADDRESS_WIDTH: u32 = 40;
/// The `address-width` whose high address fields are 10 bits wide.
pub const WIDE_ADDRESS_WIDTH: u32 = 42;
pub const WIDE_HIGH: u32 = 0x3ff;
pub const NARROW_HIGH: u32 = 0xff;
pub const DKEY_DISTRIBUTE_V6: u64 = 0x8;
/// The DKey distribution register: write one, wait for bit 0 to clear.
pub const DKEY_DISTRIBUTE_V5: u64 = 0x4;

/// What the ADT states about one engine (`/arm-io/aes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// `aes-version`.
    pub version: u32,
    /// `address-width`, or [`DEFAULT_ADDRESS_WIDTH`].
    pub address_width: u32,
    pub key_disable: KeyDisable,
}

/// The key-disable range's ADT layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDisable {
    /// Bytes of the range (`reg[1]`).
    pub bytes: u64,
    /// `sioaesdisable-offset`, the per-key bit word, or 0.
    pub word: u32,
    /// `sioaesdisableuid1-offset`, `-gid0-` and `-gid1-`, each key's own
    /// word when the ADT names one.
    pub keys: [Option<u32>; 3],
}

impl Config {
    /// Whether the engine has a DKey range (`reg[2]`).
    pub fn has_dkey(&self) -> bool {
        self.version >= DKEY_VERSION
    }

    /// Refuses a version, width or key-disable layout no established
    /// driver contract covers.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.version, 0..=3 | 5 | 6) {
            return Err(refuse!("AES aes-version without an established layout"));
        }
        if self.address_width > NARROW_ADDRESS_WIDTH && self.address_width != WIDE_ADDRESS_WIDTH {
            return Err(refuse!(
                "AES address-width without an established address field width"
            ));
        }
        let disable = &self.key_disable;
        let words = core::iter::once(Some(disable.word)).chain(disable.keys);
        for (index, offset) in words.clone().enumerate() {
            let Some(offset) = offset else { continue };
            if !offset.is_multiple_of(4) || u64::from(offset) + 4 > disable.bytes {
                return Err(refuse!(
                    "AES key-disable word outside its range or unaligned"
                ));
            }
            if words
                .clone()
                .skip(index + 1)
                .any(|other| other == Some(offset))
            {
                return Err(refuse!("AES key-disable words overlap"));
            }
        }
        Ok(())
    }

    pub fn high_mask(&self) -> u32 {
        if self.address_width == WIDE_ADDRESS_WIDTH {
            WIDE_HIGH
        } else {
            NARROW_HIGH
        }
    }

    pub fn dkey_distribute(&self) -> u64 {
        if self.version > DKEY_VERSION {
            DKEY_DISTRIBUTE_V6
        } else {
            DKEY_DISTRIBUTE_V5
        }
    }
}
