//! Image layouts: where an element of a level and layer lives (Public: Mesa
//! `layout/layout.c`, `layout.h` and `tiling.cc`, ported rule for rule).
//!
//! - Linear: one level, rows `stride` bytes apart, layers `layer_stride`.
//! - Twiddled: each level padded to powers of two and tiled in square tiles
//!   of its smaller side; elements within a tile are in Z order (x bits at
//!   even positions, y bits at odd).
//! - GPU: levels whose dimensions hold a whole page-sized tile (16 KiB:
//!   128x128 elements of one byte .. 16x16 of 64) use that tile, the rest
//!   form a power-of-two tail with square tiles; Z order within tiles, rows
//!   of tiles across the level's stride.
//! - Levels are allocated for the whole chain of `log2(max(w, h)) + 1` when
//!   the image is mipmapped, each starting on a 128-byte line; layers are
//!   the chain's size apart, rounded to a page when page-aligned.
//! - A multisampled element holds its samples together.

use super::descriptor::Tiling;
use alloc::vec::Vec;

/// Mesa `AIL_CACHELINE` and `AIL_PAGESIZE`.
const CACHELINE: u64 = 128;
const PAGE: u64 = 16384;

/// The shape a layout needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub tiling: Tiling,
    pub width: u32,
    pub height: u32,
    /// Depth of a 3D image (1 otherwise): it lengthens the mip chain
    /// (Mesa `mipmapped_z`); slices are addressed as layers.
    pub depth: u32,
    /// Block width and height in pixels, and bytes per element (including
    /// every sample).
    pub block: (u32, u32, u32),
    /// Block-compressed (BC/ETC/ASTC): mip padding rounds before minifying.
    pub block_compressed: bool,
    /// The full mip chain is allocated.
    pub mipmapped: bool,
    pub page_aligned_layers: bool,
    /// Linear only.
    pub linear_stride: u64,
    pub linear_layer_stride: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Level {
    offset: u64,
    tile: (u32, u32),
    stride_el: u32,
}

/// A computed layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    shape: Shape,
    levels: Vec<Level>,
    pub layer_stride: u64,
}

fn minify(value: u32, level: u32) -> u32 {
    (value >> level).max(1)
}

fn align(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

/// Mesa `ail_get_max_tile_size`.
fn max_tile(bytes: u32) -> Option<(u32, u32)> {
    Some(match bytes {
        1 => (128, 128),
        2 => (128, 64),
        4 => (64, 64),
        8 => (64, 32),
        16 => (32, 32),
        32 => (32, 16),
        64 => (16, 16),
        _ => return None,
    })
}

/// Mesa `ail_space_bits`: spread `x`'s bits to the even positions.
pub fn space_bits(x: u32) -> u64 {
    (0..16).fold(0u64, |accum, i| accum | u64::from(x >> i & 1) << (2 * i))
}

impl Layout {
    pub fn new(shape: Shape) -> Result<Self, &'static str> {
        let (bw, bh, bytes) = shape.block;
        let w_el = shape.width.div_ceil(bw);
        let h_el = shape.height.div_ceil(bh);
        let levels = if shape.mipmapped {
            32 - shape
                .width
                .max(shape.height)
                .max(shape.depth)
                .leading_zeros()
        } else {
            1
        };
        let mut out = Vec::new();
        let end = match shape.tiling {
            Tiling::Linear => {
                if levels != 1 {
                    return Err("a mipmapped linear image");
                }
                out.push(Level {
                    offset: 0,
                    tile: (1, 1),
                    stride_el: w_el,
                });
                let layer_stride = shape.linear_layer_stride.unwrap_or(align(
                    shape.linear_stride * u64::from(shape.height),
                    CACHELINE,
                ));
                return Ok(Layout {
                    shape,
                    levels: out,
                    layer_stride,
                });
            }
            Tiling::Twiddled => {
                let mut offset = 0u64;
                for l in 0..levels {
                    let alloc_w = minify(w_el.next_power_of_two(), l);
                    let alloc_h = minify(h_el.next_power_of_two(), l);
                    let (logical_w, logical_h) = if shape.block_compressed {
                        (alloc_w, alloc_h)
                    } else {
                        (
                            minify(w_el, l).next_power_of_two(),
                            minify(h_el, l).next_power_of_two(),
                        )
                    };
                    let minor = logical_w.min(logical_h);
                    out.push(Level {
                        offset,
                        tile: (minor, minor),
                        stride_el: logical_w,
                    });
                    offset = align(
                        offset + u64::from(bytes) * u64::from(alloc_w) * u64::from(alloc_h),
                        CACHELINE,
                    );
                }
                // Twiddled layers are always page-aligned (Mesa).
                return Ok(Layout {
                    shape,
                    levels: out,
                    layer_stride: align(offset, PAGE),
                });
            }
            Tiling::Gpu => gpu_levels(&shape, w_el, h_el, levels, &mut out)?,
        };
        let layer_stride = if shape.page_aligned_layers {
            align(end, PAGE)
        } else {
            end
        };
        Ok(Layout {
            shape,
            levels: out,
            layer_stride,
        })
    }

    pub fn levels(&self) -> u32 {
        self.levels.len() as u32
    }

    /// Width and height of `level` in elements.
    pub fn level_size_el(&self, level: u32) -> (u32, u32) {
        let (bw, bh, _) = self.shape.block;
        (
            minify(self.shape.width, level).div_ceil(bw),
            minify(self.shape.height, level).div_ceil(bh),
        )
    }

    /// The byte offset of element (`x`, `y`) of `level` in `layer`.
    pub fn offset(&self, level: u32, x: u32, y: u32, layer: u32) -> Result<u64, &'static str> {
        let entry = self
            .levels
            .get(level as usize)
            .ok_or("a level past the image's mip chain")?;
        let bytes = u64::from(self.shape.block.2);
        let base = u64::from(layer) * self.layer_stride + entry.offset;
        if self.shape.tiling == Tiling::Linear {
            return Ok(base + u64::from(y) * self.shape.linear_stride + u64::from(x) * bytes);
        }
        let (tw, th) = entry.tile;
        let tiles_per_row = entry.stride_el.div_ceil(tw);
        let tile = u64::from(y / th) * u64::from(tiles_per_row) + u64::from(x / tw);
        let within = space_bits(x % tw) | space_bits(y % th) << 1;
        Ok(base + (tile * u64::from(tw) * u64::from(th) + within) * bytes)
    }

    /// The tile size of `level` in elements.
    pub fn tile(&self, level: u32) -> (u32, u32) {
        self.levels[level as usize].tile
    }
}

/// Mesa `ail_initialize_gpu_tiled`; returns the end of the chain.
fn gpu_levels(
    shape: &Shape,
    w_el: u32,
    h_el: u32,
    levels: u32,
    out: &mut Vec<Level>,
) -> Result<u64, &'static str> {
    let (bw, bh, bytes) = shape.block;
    let tile = max_tile(bytes).ok_or("a GPU-tiled element size with no tile size")?;
    let stx = w_el.div_ceil(tile.0);
    let sty = h_el.div_ceil(tile.1);
    let sarea = stx * sty;
    let mut pot_level = 0;
    let (mut pot_w, mut pot_h) = (bw * w_el, bh * h_el);
    loop {
        if pot_w.div_ceil(bw) < tile.0 || pot_h.div_ceil(bh) < tile.1 {
            break;
        }
        pot_w = minify(pot_w, 1);
        pot_h = minify(pot_h, 1);
        pot_level += 1;
    }
    let mut offset = 0u64;
    let stride = |l: u32| minify(shape.width, l).div_ceil(bw);
    for l in 0..pot_level.min(levels) {
        let mut tiles = sarea >> (2 * l);
        let mask = (1u32 << l) - 1;
        let pad_left = stx & mask != 0;
        let pad_bottom = sty & mask != 0;
        if pad_left {
            tiles += sty >> l;
        }
        if pad_bottom {
            tiles += stx >> l;
        }
        if pad_left && pad_bottom {
            tiles += 1;
        }
        let mut stride_el = stride(l);
        if shape.block_compressed && pad_left {
            stride_el += 1;
        }
        out.push(Level {
            offset,
            tile,
            stride_el,
        });
        offset = align(
            offset + u64::from(bytes) * u64::from(tiles) * u64::from(tile.0 * tile.1),
            CACHELINE,
        );
    }
    let (mut potw, mut poth) = if shape.block_compressed {
        (
            minify(w_el.next_power_of_two(), pot_level),
            minify(h_el.next_power_of_two(), pot_level),
        )
    } else {
        (
            minify(w_el, pot_level).next_power_of_two(),
            minify(h_el, pot_level).next_power_of_two(),
        )
    };
    for l in pot_level..levels {
        let side = if shape.block_compressed {
            potw.min(poth).next_power_of_two()
        } else {
            minify(w_el.min(h_el), l).next_power_of_two()
        };
        out.push(Level {
            offset,
            tile: (side, side),
            stride_el: stride(l),
        });
        offset = align(
            offset + u64::from(bytes) * u64::from(potw) * u64::from(poth),
            CACHELINE,
        );
        potw = minify(potw, 1);
        poth = minify(poth, 1);
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(tiling: Tiling, width: u32, height: u32, bytes: u32, mipmapped: bool) -> Shape {
        Shape {
            tiling,
            width,
            height,
            depth: 1,
            block: (1, 1, bytes),
            block_compressed: false,
            mipmapped,
            page_aligned_layers: false,
            linear_stride: u64::from(width * bytes),
            linear_layer_stride: None,
        }
    }

    #[test]
    fn z_order_interleaves_within_a_tile() {
        let layout = Layout::new(shape(Tiling::Gpu, 64, 64, 4, false)).unwrap();
        assert_eq!(layout.tile(0), (64, 64));
        assert_eq!(layout.offset(0, 1, 0, 0), Ok(4));
        assert_eq!(layout.offset(0, 0, 1, 0), Ok(8));
        assert_eq!(layout.offset(0, 3, 3, 0), Ok(15 * 4));
    }

    #[test]
    fn gpu_tiles_rows_of_page_tiles_then_a_power_of_two_tail() {
        // 200x100 RGBA8: 64x64 tiles, 4x2 of them at level 0.
        let layout = Layout::new(shape(Tiling::Gpu, 200, 100, 4, true)).unwrap();
        assert_eq!(layout.levels(), 8);
        // Element (64, 0) starts the second tile.
        assert_eq!(layout.offset(0, 64, 0, 0), Ok(64 * 64 * 4));
        // Row 64 starts the second row of tiles.
        assert_eq!(layout.offset(0, 0, 64, 0), Ok(4 * 64 * 64 * 4));
        // Level 1 (100x50) is below one tile in height: the tail begins.
        assert_eq!(layout.offset(1, 0, 0, 0), Ok(8 * 64 * 64 * 4));
        assert_eq!(layout.tile(1), (64, 64));
        assert_eq!(layout.tile(2), (32, 32));
    }

    #[test]
    fn twiddled_and_linear_layouts() {
        let layout = Layout::new(shape(Tiling::Twiddled, 8, 4, 4, true)).unwrap();
        assert_eq!(layout.tile(0), (4, 4));
        assert_eq!(layout.offset(0, 4, 0, 0), Ok(16 * 4));
        assert_eq!(layout.offset(1, 0, 0, 0), Ok(128));
        assert_eq!(layout.layer_stride, 16384);
        let linear = Layout::new(shape(Tiling::Linear, 10, 3, 4, false)).unwrap();
        assert_eq!(linear.offset(0, 2, 1, 1), Ok(linear.layer_stride + 40 + 8));
        assert!(Layout::new(shape(Tiling::Linear, 10, 3, 4, true)).is_err());
    }
}
