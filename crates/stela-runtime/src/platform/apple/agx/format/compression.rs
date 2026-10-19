//! Lossless framebuffer compression: the metadata (acceleration) buffer
//! (Public: Mesa `layout.c` `ail_initialize_compression`, `layout.h` and
//! `libagx/compression.cl`).
//!
//! - Metadata holds 8 bytes per 16x16-sample tile, one mode byte per 8x4
//!   subtile, addressed fully twiddled: X and Y interleave up to the smaller
//!   power-of-two dimension, the rest of the major axis is linear above.
//! - Multisampled images stretch into samples: 4x doubles both axes, 2x
//!   the height (`ail_effective_width_sa`).
//! - A level is allocated in the metadata while its larger aligned side is
//!   at least 16 samples, and consulted ("logically compressed") while its
//!   smaller side is; each allocated level holds the power-of-two padded
//!   tile grid rounded to a 128-byte line, and layers are the whole chain
//!   apart.
//! - Modes are known for two states per element size: uncompressed (the
//!   tile reads from the body as an ordinary image) and solid (each subtile
//!   reads its colour from a copy at the start of the tile in the body).
//!   Any other mode, and tiles mixing modes, refuse by name.

use alloc::vec::Vec;

/// Bytes of metadata per 16x16 tile.
pub const TILE_METADATA_BYTES: u64 = 8;
/// Samples on a side of a compression tile.
pub const TILE_SAMPLES: u32 = 16;
/// Solid-colour copies at the start of a tile (one per 8x4 subtile).
pub const SOLID_COPIES: u32 = 8;
const CACHELINE: u64 = 128;

/// Mesa `AIL_COMP_*`: the (uncompressed, solid) subtile modes of an
/// element size in bytes (per sample).
pub fn subtile_modes(element_bytes: u32) -> Option<(u8, u8)> {
    Some(match element_bytes {
        1 => (0x1f, 0x60),
        2 => (0x3f, 0x01),
        4 => (0x7f, 0x03),
        8 | 16 => (0xff, 0x07),
        _ => return None,
    })
}

/// A whole tile's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileMode {
    Uncompressed,
    Solid,
}

/// The metadata of one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compression {
    /// Metadata of the descriptor's layer 0.
    pub base: u64,
    pub layer_stride: u64,
    samples: u32,
    width_px: u32,
    height_px: u32,
    levels: Vec<u64>,
    modes: (u8, u8),
}

/// The tile of a sample: its metadata address and its pixel origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tile {
    pub metadata: u64,
    pub origin: (u32, u32),
    /// The tile's extent in pixels.
    pub size: (u32, u32),
}

fn effective(width: u32, height: u32, samples: u32) -> (u32, u32) {
    (
        width * if samples == 4 { 2 } else { 1 },
        height * if samples >= 2 { 2 } else { 1 },
    )
}

fn minify(value: u32, level: u32) -> u32 {
    (value >> level).max(1)
}

impl Compression {
    pub fn new(
        base: u64,
        width_px: u32,
        height_px: u32,
        levels: u32,
        samples: u32,
        element_bytes: u32,
    ) -> Result<Self, &'static str> {
        let modes = subtile_modes(element_bytes)
            .ok_or("a compressed image whose element size has no recorded modes")?;
        let (w_sa, h_sa) = effective(width_px, height_px, samples);
        if w_sa < TILE_SAMPLES || h_sa < TILE_SAMPLES {
            return Err("a compressed image smaller than one compression tile");
        }
        let (mut w, mut h) = (
            w_sa.next_multiple_of(TILE_SAMPLES),
            h_sa.next_multiple_of(TILE_SAMPLES),
        );
        let largest = w.max(h);
        let mut offsets = Vec::new();
        let mut offset = 0u64;
        for level in 0..levels {
            if minify(largest, level) < TILE_SAMPLES {
                break;
            }
            offsets.push(offset);
            let w_tl = w.next_power_of_two().div_ceil(TILE_SAMPLES);
            let h_tl = h.next_power_of_two().div_ceil(TILE_SAMPLES);
            offset += (u64::from(w_tl) * u64::from(h_tl) * TILE_METADATA_BYTES)
                .next_multiple_of(CACHELINE);
            w = w.div_ceil(2);
            h = h.div_ceil(2);
        }
        Ok(Compression {
            base,
            layer_stride: offset,
            samples,
            width_px,
            height_px,
            levels: offsets,
            modes,
        })
    }

    /// Whether `level` consults the metadata.
    pub fn logically_compressed(&self, level: u32) -> bool {
        let (w, h) = effective(self.width_px, self.height_px, self.samples);
        (level as usize) < self.levels.len() && minify(w.min(h), level) >= TILE_SAMPLES
    }

    /// Mesa `index_metadata`.
    fn index(x: u32, y: u32, width_tl: u32, height_tl: u32) -> u64 {
        let major = if width_tl > height_tl { x } else { y };
        let minor = width_tl.min(height_tl);
        let bits = 32 - minor.saturating_sub(1).leading_zeros();
        let mask = (1u32 << bits) - 1;
        let interleaved =
            super::layout::space_bits(x & mask) | super::layout::space_bits(y & mask) << 1;
        interleaved + (u64::from(major & !mask) << bits)
    }

    /// The tile holding sample `sample` of pixel (`x`, `y`) of `level` in
    /// `layer`, when the level consults the metadata.
    pub fn tile(&self, level: u32, x: u32, y: u32, layer: u32, sample: u32) -> Option<Tile> {
        if !self.logically_compressed(level) {
            return None;
        }
        let (w_px, h_px) = (minify(self.width_px, level), minify(self.height_px, level));
        let (w_sa, h_sa) = effective(w_px, h_px, self.samples);
        let (x_sa, y_sa) = match self.samples {
            4 => (2 * x + (sample & 1), 2 * y + (sample >> 1 & 1)),
            2 => (x, 2 * y + (sample & 1)),
            _ => (x, y),
        };
        let (tx, ty) = (x_sa / TILE_SAMPLES, y_sa / TILE_SAMPLES);
        let index = Self::index(
            tx,
            ty,
            w_sa.div_ceil(TILE_SAMPLES),
            h_sa.div_ceil(TILE_SAMPLES),
        );
        let metadata = self.base
            + u64::from(layer) * self.layer_stride
            + self.levels[level as usize]
            + index * TILE_METADATA_BYTES;
        let size = match self.samples {
            4 => (TILE_SAMPLES / 2, TILE_SAMPLES / 2),
            2 => (TILE_SAMPLES, TILE_SAMPLES / 2),
            _ => (TILE_SAMPLES, TILE_SAMPLES),
        };
        Some(Tile {
            metadata,
            origin: (tx * size.0, ty * size.1),
            size,
        })
    }

    /// Classify a tile's eight mode bytes.
    pub fn mode(&self, metadata: u64) -> Result<TileMode, &'static str> {
        let replicate = |mode: u8| u64::from(mode) * 0x0101_0101_0101_0101;
        if metadata == replicate(self.modes.0) {
            Ok(TileMode::Uncompressed)
        } else if metadata == replicate(self.modes.1) {
            Ok(TileMode::Solid)
        } else {
            Err(
                "a compression tile whose modes are neither all uncompressed nor all solid (unrecorded)",
            )
        }
    }

    /// The metadata word marking a tile uncompressed.
    pub fn uncompressed_word(&self) -> u64 {
        u64::from(self.modes.0) * 0x0101_0101_0101_0101
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_and_tiles_follow_the_ail_rules() {
        // 64x32 RGBA8, single-sampled, mipmapped: level 0 is 4x2 tiles
        // (padded 4x2), 64 bytes -> one line; levels 1 (2x1) and 2 (1x1, its
        // larger side still 16) take a line each.
        let c = Compression::new(0x1000, 64, 32, 7, 1, 4).unwrap();
        assert_eq!(c.levels, [0, 128, 256]);
        assert_eq!(c.layer_stride, 384);
        assert!(c.logically_compressed(1) && !c.logically_compressed(2));
        // Tile (1, 1): interleaved over the minor (2-tile) side, then x's
        // high bits linear above: index 3.
        let tile = c.tile(0, 20, 20, 0, 0).unwrap();
        assert_eq!(tile.metadata, 0x1000 + 3 * 8);
        assert_eq!(tile.origin, (16, 16));
        // Tile (3, 0): x bit 1 above the one interleaved bit pair: index 4 + 1.
        assert_eq!(c.tile(0, 48, 0, 0, 0).unwrap().metadata, 0x1000 + 5 * 8);
        assert_eq!(c.tile(0, 0, 0, 1, 0).unwrap().metadata, 0x1000 + 384);
    }

    #[test]
    fn modes_classify_whole_tiles_only() {
        let c = Compression::new(0, 16, 16, 1, 1, 4).unwrap();
        assert_eq!(c.mode(0x7f7f_7f7f_7f7f_7f7f), Ok(TileMode::Uncompressed));
        assert_eq!(c.mode(0x0303_0303_0303_0303), Ok(TileMode::Solid));
        assert!(c.mode(0x0303_0303_0303_037f).is_err());
        // 4x multisampling: a tile covers 8x8 pixels.
        let msaa = Compression::new(0, 16, 16, 1, 4, 4).unwrap();
        assert_eq!(msaa.tile(0, 9, 1, 0, 3).unwrap().origin, (8, 0));
    }
}
