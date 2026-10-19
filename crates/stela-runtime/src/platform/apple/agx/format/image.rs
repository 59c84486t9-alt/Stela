//! Images as the texture unit and the PBE reach them: a descriptor's
//! dimensions, texel format, layout and compression resolved into element
//! reads and writes.
//!
//! - Width and height are level 0's (Mesa `libagx_txs` minifies from
//!   them); a texture's `Depth` counts layers, cubes (six faces each) or 3D
//!   slices, a PBE's `Layers` counts 2D layers or slices.
//! - 3D slices are addressed as layers of the layout, each level minifying
//!   the depth (Mesa `ail_get_layer_level_B`).
//! - A multisampled element holds its samples together, sample `s` at
//!   `s` element sizes in.
//! - Compressed images consult the metadata on logically compressed levels
//!   ([`super::compression`]); a write into a solid tile first expands the
//!   colour over the tile and marks it uncompressed, as Mesa's decompress
//!   kernel does.

use super::compression::{Compression, SOLID_COPIES, Tile, TileMode};
use super::descriptor::{Dimension, Pbe, Texture, Tiling};
use super::layout::{Layout, Shape};
use super::texel::{Format, Texel};
use crate::platform::apple::agx::isa::machine::{Fault, Memory};
use alloc::vec;

/// Why an image access failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    Fault(Fault),
    Refused(&'static str),
}

impl From<Fault> for ImageError {
    fn from(fault: Fault) -> Self {
        ImageError::Fault(fault)
    }
}

impl From<&'static str> for ImageError {
    fn from(reason: &'static str) -> Self {
        ImageError::Refused(reason)
    }
}

/// A texel's place: level, pixel, layer (or 3D slice) and sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct At {
    pub level: u32,
    pub x: u32,
    pub y: u32,
    pub layer: u32,
    pub sample: u32,
}

impl At {
    pub fn new(level: u32, x: u32, y: u32, layer: u32, sample: u32) -> Self {
        At {
            level,
            x,
            y,
            layer,
            sample,
        }
    }
}

/// A resolved image.
#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    pub dimension: Dimension,
    pub format: Format,
    pub width: u32,
    pub height: u32,
    /// Depth of level 0 for 3D images; 2D layers otherwise (cube faces
    /// counted singly).
    pub layers: u32,
    pub samples: u32,
    pub first_level: u32,
    pub last_level: u32,
    base: u64,
    layout: Layout,
    compression: Option<Compression>,
    /// Block width and height in pixels, and bytes per sample.
    block: (u32, u32, u32),
}

/// What [`Image::new`] needs from either descriptor.
struct Parts {
    dimension: Dimension,
    tiling: Tiling,
    format: Format,
    width: u32,
    height: u32,
    layers: u32,
    samples: u32,
    mipmapped: bool,
    page_aligned_layers: bool,
    linear_stride: u32,
    linear_layer_stride: Option<u64>,
    acceleration_buffer: Option<u64>,
    compressed: bool,
    base: u64,
    first_level: u32,
    last_level: u32,
}

fn minify(value: u32, level: u32) -> u32 {
    (value >> level).max(1)
}

impl Image {
    pub fn from_texture(t: &Texture) -> Result<Self, &'static str> {
        let layers = if t.dimension.cube() {
            t.depth * 6
        } else {
            t.depth
        };
        Self::new(Parts {
            dimension: t.dimension,
            tiling: t.tiling,
            format: Format {
                channels: t.channels,
                ty: t.ty,
                srgb: t.srgb,
                srgb_2_channel: t.srgb_2_channel,
            },
            width: t.width,
            height: t.height,
            layers,
            samples: t.samples,
            mipmapped: t.mipmapped,
            page_aligned_layers: t.page_aligned_layers,
            linear_stride: t.linear_stride,
            linear_layer_stride: t.linear_layer_stride,
            acceleration_buffer: t.acceleration_buffer,
            compressed: t.compressed,
            base: t.address,
            first_level: t.first_level,
            last_level: t.last_level,
        })
    }

    pub fn from_pbe(p: &Pbe) -> Result<Self, &'static str> {
        Self::new(Parts {
            dimension: p.dimension,
            tiling: p.tiling,
            format: Format {
                channels: p.channels,
                ty: p.ty,
                srgb: p.srgb,
                srgb_2_channel: false,
            },
            width: p.width,
            height: p.height,
            layers: p.layers,
            samples: p.samples,
            mipmapped: p.mipmapped,
            page_aligned_layers: p.page_aligned_layers,
            linear_stride: p.linear_stride,
            linear_layer_stride: p.linear_layer_stride,
            acceleration_buffer: p.acceleration_buffer,
            compressed: p.compressed,
            base: p.buffer,
            first_level: p.level,
            last_level: p.level,
        })
    }

    fn new(parts: Parts) -> Result<Self, &'static str> {
        let (bw, bh, bytes) = parts.format.block()?;
        let depth = if parts.dimension == Dimension::D3 {
            parts.layers
        } else {
            1
        };
        let layout = Layout::new(Shape {
            tiling: parts.tiling,
            width: parts.width,
            height: parts.height,
            depth,
            block: (bw, bh, bytes * parts.samples),
            block_compressed: bw > 1,
            mipmapped: parts.mipmapped,
            page_aligned_layers: parts.page_aligned_layers,
            linear_stride: u64::from(parts.linear_stride),
            linear_layer_stride: parts.linear_layer_stride,
        })?;
        if parts.last_level < parts.first_level || parts.last_level >= layout.levels() {
            return Err("a level range past the image's allocated mip chain");
        }
        let compression = match (parts.compressed, parts.acceleration_buffer) {
            (false, _) => None,
            (true, None) => return Err("a compressed image without its acceleration buffer"),
            (true, Some(_)) if parts.tiling == Tiling::Linear || bw > 1 => {
                return Err("compression of a linear or block-compressed image");
            }
            (true, Some(base)) => Some(Compression::new(
                base,
                parts.width,
                parts.height,
                layout.levels(),
                parts.samples,
                bytes,
            )?),
        };
        Ok(Image {
            dimension: parts.dimension,
            format: parts.format,
            width: parts.width,
            height: parts.height,
            layers: parts.layers,
            samples: parts.samples,
            first_level: parts.first_level,
            last_level: parts.last_level,
            base: parts.base,
            layout,
            compression,
            block: (bw, bh, bytes),
        })
    }

    /// Width, height and depth (3D) or layer count of `level`, in pixels.
    pub fn level_size(&self, level: u32) -> (u32, u32, u32) {
        let depth = if self.dimension == Dimension::D3 {
            minify(self.layers, level)
        } else {
            self.layers
        };
        (minify(self.width, level), minify(self.height, level), depth)
    }

    fn element(
        &self,
        level: u32,
        x: u32,
        y: u32,
        layer: u32,
        sample: u32,
    ) -> Result<u64, ImageError> {
        let (bw, bh, bytes) = self.block;
        let offset = self.layout.offset(level, x / bw, y / bh, layer)?;
        Ok(self.base + offset + u64::from(sample) * u64::from(bytes))
    }

    fn compression_tile(
        &self,
        level: u32,
        x: u32,
        y: u32,
        layer: u32,
        sample: u32,
    ) -> Option<(&Compression, Tile)> {
        let compression = self.compression.as_ref()?;
        compression
            .tile(level, x, y, layer, sample)
            .map(|tile| (compression, tile))
    }

    /// A solid tile's colour (per-sample bytes), checking every copy agrees.
    fn solid(
        &self,
        memory: &mut dyn Memory,
        level: u32,
        tile: &Tile,
        layer: u32,
    ) -> Result<vec::Vec<u8>, ImageError> {
        let bytes = self.block.2 as usize;
        let start = self.element(level, tile.origin.0, tile.origin.1, layer, 0)?;
        let copies = (SOLID_COPIES * self.samples) as usize;
        let mut buffer = vec![0u8; bytes * copies];
        memory.read(start, &mut buffer)?;
        let (first, rest) = buffer.split_at(bytes);
        if rest.chunks(bytes).any(|copy| copy != first) {
            return Err(ImageError::Refused(
                "a solid compression tile whose colour copies differ (unrecorded)",
            ));
        }
        Ok(first.to_vec())
    }

    /// The texel `at`, in bounds.
    pub fn read(&self, memory: &mut dyn Memory, at: At) -> Result<Texel, ImageError> {
        let At {
            level,
            x,
            y,
            layer,
            sample,
        } = at;
        let (bw, bh, bytes) = self.block;
        if let Some((compression, tile)) = self.compression_tile(level, x, y, layer, sample) {
            let mut word = [0u8; 8];
            memory.read(tile.metadata, &mut word)?;
            if compression.mode(u64::from_le_bytes(word))? == TileMode::Solid {
                return Ok(self
                    .format
                    .decode(&self.solid(memory, level, &tile, layer)?)?);
            }
        }
        let mut buffer = [0u8; 16];
        let buffer = &mut buffer[..bytes as usize];
        memory.read(self.element(level, x, y, layer, sample)?, buffer)?;
        if bw > 1 {
            Ok(self.format.decode_block(buffer, (x % bw, y % bh))?)
        } else {
            Ok(self.format.decode(buffer)?)
        }
    }

    /// Store component values (in memory order) `at`, in bounds.
    pub fn write(
        &self,
        memory: &mut dyn Memory,
        at: At,
        value: [f64; 4],
    ) -> Result<(), ImageError> {
        let At {
            level,
            x,
            y,
            layer,
            sample,
        } = at;
        let (bw, _, bytes) = self.block;
        if bw > 1 {
            return Err(ImageError::Refused("a store into a block-compressed image"));
        }
        if let Some((compression, tile)) = self.compression_tile(level, x, y, layer, sample) {
            let mut word = [0u8; 8];
            memory.read(tile.metadata, &mut word)?;
            if compression.mode(u64::from_le_bytes(word))? == TileMode::Solid {
                self.expand(memory, level, &tile, layer)?;
                memory.write(
                    tile.metadata,
                    &compression.uncompressed_word().to_le_bytes(),
                )?;
            }
        }
        let mut buffer = [0u8; 16];
        let buffer = &mut buffer[..bytes as usize];
        self.format.encode(value, buffer)?;
        memory.write(self.element(level, x, y, layer, sample)?, buffer)?;
        Ok(())
    }

    /// Write a solid tile's colour to every sample it covers.
    fn expand(
        &self,
        memory: &mut dyn Memory,
        level: u32,
        tile: &Tile,
        layer: u32,
    ) -> Result<(), ImageError> {
        let colour = self.solid(memory, level, tile, layer)?;
        let (w, h, _) = self.level_size(level);
        for y in tile.origin.1..(tile.origin.1 + tile.size.1).min(h) {
            for x in tile.origin.0..(tile.origin.0 + tile.size.0).min(w) {
                for sample in 0..self.samples {
                    memory.write(self.element(level, x, y, layer, sample)?, &colour)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::apple::agx::format::layout::space_bits;
    use crate::platform::apple::agx::format::texel::{channels, ty};
    use alloc::collections::BTreeMap;

    /// Sparse byte memory.
    #[derive(Default)]
    pub(crate) struct Bytes(pub BTreeMap<u64, u8>);

    impl Memory for Bytes {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = self.0.get(&(address + i as u64)).copied().unwrap_or(0);
            }
            Ok(())
        }

        fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
            for (i, byte) in data.iter().enumerate() {
                self.0.insert(address + i as u64, *byte);
            }
            Ok(())
        }
    }

    pub(crate) fn rgba8_texture(tiling: Tiling, width: u32, height: u32, address: u64) -> Texture {
        Texture {
            dimension: Dimension::D2,
            tiling,
            channels: channels::R8G8B8A8,
            ty: ty::UNORM,
            swizzle: [0, 1, 2, 3].map(super::super::descriptor::Channel::Component),
            width,
            height,
            first_level: 0,
            last_level: 0,
            samples: 1,
            address,
            mipmapped: false,
            compressed: false,
            srgb: false,
            srgb_2_channel: false,
            depth: 1,
            page_aligned_layers: false,
            linear_stride: width * 4,
            linear_layer_stride: None,
            acceleration_buffer: None,
        }
    }

    #[test]
    fn writes_read_back_through_the_layout() {
        let image = Image::from_texture(&rgba8_texture(Tiling::Gpu, 32, 32, 0x10_0000)).unwrap();
        let mut memory = Bytes::default();
        image
            .write(&mut memory, At::new(0, 3, 2, 0, 0), [1.0, 0.0, 0.2, 1.0])
            .unwrap();
        // One 32x32 tail tile in Z order: x bits even, y bits odd.
        let offset = (space_bits(3) | space_bits(2) << 1) * 4;
        assert_eq!(memory.0.get(&(0x10_0000 + offset)), Some(&255));
        assert_eq!(memory.0.get(&(0x10_0000 + offset + 2)), Some(&51));
        let texel = image.read(&mut memory, At::new(0, 3, 2, 0, 0)).unwrap();
        assert_eq!(texel.value, [1.0, 0.0, 51.0 / 255.0, 1.0]);
    }

    #[test]
    fn solid_tiles_read_their_colour_and_expand_on_write() {
        let mut t = rgba8_texture(Tiling::Gpu, 32, 32, 0x10_0000);
        t.compressed = true;
        t.acceleration_buffer = Some(0x20_0000);
        let image = Image::from_texture(&t).unwrap();
        let mut memory = Bytes::default();
        // Tile 0 solid with eight copies of opaque green; tile 1 uncompressed.
        memory
            .write(0x20_0000, &0x0303_0303_0303_0303u64.to_le_bytes())
            .unwrap();
        memory
            .write(0x20_0008, &0x7f7f_7f7f_7f7f_7f7fu64.to_le_bytes())
            .unwrap();
        for copy in 0..8 {
            memory
                .write(0x10_0000 + copy * 4, &[0, 255, 0, 255])
                .unwrap();
        }
        assert_eq!(
            image
                .read(&mut memory, At::new(0, 15, 15, 0, 0))
                .unwrap()
                .value,
            [0.0, 1.0, 0.0, 1.0]
        );
        assert_eq!(
            image
                .read(&mut memory, At::new(0, 16, 0, 0, 0))
                .unwrap()
                .value,
            [0.0, 0.0, 0.0, 0.0]
        );
        image
            .write(&mut memory, At::new(0, 5, 5, 0, 0), [1.0, 0.0, 0.0, 1.0])
            .unwrap();
        let mut word = [0u8; 8];
        memory.read(0x20_0000, &mut word).unwrap();
        assert_eq!(u64::from_le_bytes(word), 0x7f7f_7f7f_7f7f_7f7f);
        assert_eq!(
            image
                .read(&mut memory, At::new(0, 15, 15, 0, 0))
                .unwrap()
                .value,
            [0.0, 1.0, 0.0, 1.0]
        );
        assert_eq!(
            image
                .read(&mut memory, At::new(0, 5, 5, 0, 0))
                .unwrap()
                .value,
            [1.0, 0.0, 0.0, 1.0]
        );
        // Mixed modes refuse.
        memory
            .write(0x20_0000, &0x0303_0303_0303_037fu64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            image.read(&mut memory, At::new(0, 0, 0, 0, 0)),
            Err(ImageError::Refused(_))
        ));
    }
}
