//! Immutable SART register/entry geometry from the original SPTM layout tables.
//! This describes placement and encoding, never live DMA permissions, kept
//! power, a hardware mapping, outstanding work or an execution owner.
use crate::Result;
use stela_contracts::refuse;
/// Largest supported layout, version4.
pub const MAX_ENTRIES: usize = 24;
pub const PAGE: u64 = 4096;
/// Default version3 channel register offsets; no channel state is implied.
pub const THROTTLES: [u64; 3] = [0x8014, 0x801c, 0x8024];
pub const STATUS: [u64; 3] = [0x8010, 0x8018, 0x8020];
const BASE: u64 = 0x40;
const SIZE: u64 = 0x80;
const WIDE: u32 = (1 << 30) - 1;
const NARROW: u32 = (1 << 24) - 1;
const ALLOW: u32 = read_write([0, 2, 4, 6, 7]);
const fn read_write(bits: [u32; 5]) -> u32 {
    3 << bits[0] | 3 << bits[1] | 3 << bits[2] | 1 << bits[3] | 1 << bits[4]
}

/// Where a SART's entry and throttle registers sit in `reg[0]`, and how an
/// entry's fields pack into them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    entries: usize,
    base: u64,
    /// The SIZE words' offset, or `None` when SIZE is CONFIG's low bits.
    size: Option<u64>,
    size_mask: u32,
    base_mask: u32,
    allow: u32,
    channels: usize,
    throttles: [u64; 4],
    status: [u64; 4],
}

impl Layout {
    pub const fn entries(&self) -> usize {
        self.entries
    }
    pub const fn permission_mask(&self) -> u32 {
        self.allow
    }
    pub const fn base_mask(&self) -> u32 {
        self.base_mask
    }
    pub const fn size_mask(&self) -> u32 {
        self.size_mask
    }
    pub fn throttle_offsets(&self) -> &[u64] {
        &self.throttles[..self.channels]
    }
    pub fn status_offsets(&self) -> &[u64] {
        &self.status[..self.channels]
    }

    /// `sart-version` 3 with its own throttle layout and no offset.
    pub const V3: Self = Self {
        entries: 16,
        base: BASE,
        size: Some(SIZE),
        size_mask: WIDE,
        base_mask: WIDE,
        allow: ALLOW,
        channels: 3,
        throttles: [THROTTLES[0], THROTTLES[1], THROTTLES[2], 0],
        status: [STATUS[0], STATUS[1], STATUS[2], 0],
    };

    /// The layout SPTM's tables give `sart-version`, `sart-throttle-version`
    /// and `sart-throttle-offset`. Every version has CONFIG words from 0 and
    /// unshifted PADDR words, each 4 bytes apart. Versions 3 and 4 have 16
    /// and 24 entries, PADDR words from 0x40 and 0x60, SIZE words from 0x80
    /// and 0xc0, 30-bit PADDR and SIZE fields, and permissions at CONFIG
    /// bits 0, 2, 4, 6 and 7. Versions 1 and 2 have 16 entries, PADDR words
    /// from 0x40 and 24-bit PADDR fields, but no SIZE words: SIZE is
    /// CONFIG's low 19 or 24 bits, and the permissions sit at bits 22, 24,
    /// 26, 29 and 30 or 24, 26, 28, 30 and 31. Their entry write (T8103
    /// 0xfffffff0270cb6b0) stores CONFIG with the permissions alone, then
    /// PADDR, then CONFIG again with SIZE in its low bits.
    pub fn new(version: u32, throttle_version: u32, offset: u32) -> Result<Self> {
        let (entries, base, size, size_mask, base_mask, allow) = match version {
            1 => (
                16,
                BASE,
                None,
                (1 << 19) - 1,
                NARROW,
                read_write([22, 24, 26, 29, 30]),
            ),
            2 => (
                16,
                BASE,
                None,
                NARROW,
                NARROW,
                read_write([24, 26, 28, 30, 31]),
            ),
            3 => (16, BASE, Some(SIZE), WIDE, WIDE, ALLOW),
            4 => (24, 0x60, Some(0xc0), WIDE, WIDE, ALLOW),
            _ => return Err(refuse!("SART entry layout other than versions 1 to 4")),
        };
        let (channels, throttles, status) = match throttle_version {
            1 => (3, [0x4014, 0x401c, 0x4024, 0], [0x4010, 0x4018, 0x4020, 0]),
            2 | 3 => (3, [0x8014, 0x801c, 0x8024, 0], [0x8010, 0x8018, 0x8020, 0]),
            4 => (
                4,
                [0x8008, 0x800c, 0x8014, 0x801c],
                [0x8000, 0x8004, 0x8010, 0x8018],
            ),
            _ => return Err(refuse!("SART throttle layout other than versions 1 to 4")),
        };
        if !offset.is_multiple_of(4) {
            return Err(refuse!("SART throttle offset is not word aligned"));
        }
        let at = |words: [u64; 4]| words.map(|word| word + u64::from(offset));
        Ok(Self {
            entries,
            base,
            size,
            size_mask,
            base_mask,
            allow,
            channels,
            throttles: at(throttles),
            status: at(status),
        })
    }

    /// The bytes of `reg[0]` the registers need.
    pub fn register_bytes(&self) -> u64 {
        self.throttles[..self.channels]
            .iter()
            .chain(&self.status[..self.channels])
            .map(|&word| word + 4)
            .chain([self.size.unwrap_or(self.base) + 4 * self.entries as u64])
            .max()
            .expect("a layout has registers")
    }

    pub fn throttle(&self, offset: u64) -> Option<usize> {
        self.throttles[..self.channels]
            .iter()
            .position(|&word| word == offset)
    }

    /// The entry and field (0 CONFIG, 1 PADDR, 2 SIZE) at `offset`.
    pub fn entry(&self, offset: u64) -> Option<(usize, usize)> {
        if !offset.is_multiple_of(4) {
            return None;
        }
        [Some(0), Some(self.base), self.size]
            .iter()
            .enumerate()
            .find_map(|(field, &start)| {
                let index = offset.checked_sub(start?)? / 4;
                (index < self.entries as u64).then_some((index as usize, field))
            })
    }

    /// An entry's permission bits and SIZE.
    pub fn decode(&self, config: u32, size: u32) -> (u32, u32) {
        match self.size {
            Some(_) => (config, size),
            None => (config & !self.size_mask, config & self.size_mask),
        }
    }
}

/// How an entry's SIZE counts its pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bounds {
    /// SIZE is the last page's index: SIZE + 1 pages.
    Inclusive,
    /// SIZE is the page count (`exclusive-bounds`).
    Exclusive,
}
