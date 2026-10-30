//! Sparse textures: sparse-residency images over the pages of a sparse heap.
//!
//! A sparse heap (`MTLHeapTypeSparse`) is one allocation divided into pages
//! of the sparse tile size. Its textures are sparse-residency color images
//! with no memory of their own. Mapping a tile takes a free page of the heap
//! and binds it; unmapping returns the page. The levels from
//! `firstMipmapInTail` on form each slice's mip tail (one tail for every
//! slice when the driver says so), which maps as a unit whenever a region of
//! a tail level maps. A map that finds the heap full leaves the remaining
//! tiles unmapped, as Metal does. Updates take effect in command-buffer
//! order: the device turns them into sparse binds between segments when the
//! command buffer commits, or, for an indirect update, once the host has
//! read the arguments the GPU copied.
use super::{
    abi::{
        ResourceOptions, SparseTextureMappingMode, SparseTextureRegionAlignmentMode, StorageMode,
        SwizzleChannels, TextureType, TextureUsage,
    },
    capabilities::Capabilities,
    error::{Error, Result, ensure, require},
    pixel_format::PixelFormat,
    resource::{self, TextureDescriptor, TexturePlan},
    upload::Upload,
    vulkan::{
        ImageAspects, ImageCreate,
        command::{SparseBind, Subresource},
        object::{Image, ImageInfo, Memory, SparseImageRequirements},
    },
};
use alloc::{collections::BTreeMap, vec::Vec};

/// `MTLRegion`, in pixels or in tiles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SparseRegion {
    pub origin: [u64; 3],
    pub size: [u64; 3],
}

impl SparseRegion {
    fn end(&self, axis: usize) -> Result<u64> {
        self.origin[axis]
            .checked_add(self.size[axis])
            .ok_or(Error::Invalid("region extends past the address space"))
    }
}

/// `convertSparsePixelRegions:toTileRegions:withTileSize:alignmentMode:numRegions:`.
/// Outward regions cover every tile a pixel region touches; inward regions
/// only the tiles it covers completely, which may be none.
pub fn pixel_to_tile_regions(
    regions: &[SparseRegion],
    tile: [u64; 3],
    alignment: SparseTextureRegionAlignmentMode,
) -> Result<Vec<SparseRegion>> {
    ensure(tile.iter().all(|&size| size > 0), "tile sizes are nonzero")?;
    regions
        .iter()
        .map(|region| {
            let mut tiles = SparseRegion::default();
            for (axis, &size) in tile.iter().enumerate() {
                let (start, end) = (region.origin[axis], region.end(axis)?);
                let (first, last) = match alignment {
                    SparseTextureRegionAlignmentMode::Outward => (start / size, end.div_ceil(size)),
                    SparseTextureRegionAlignmentMode::Inward => (start.div_ceil(size), end / size),
                };
                tiles.origin[axis] = first;
                tiles.size[axis] = last.saturating_sub(first);
            }
            Ok(tiles)
        })
        .collect()
}

/// `convertSparseTileRegions:toPixelRegions:withTileSize:numRegions:`.
pub fn tile_to_pixel_regions(
    regions: &[SparseRegion],
    tile: [u64; 3],
) -> Result<Vec<SparseRegion>> {
    let scale = |value: u64, axis: usize| {
        value
            .checked_mul(tile[axis])
            .ok_or(Error::Invalid("region extends past the address space"))
    };
    regions
        .iter()
        .map(|region| {
            let mut pixels = SparseRegion::default();
            for axis in 0..3 {
                pixels.origin[axis] = scale(region.origin[axis], axis)?;
                pixels.size[axis] = scale(region.size[axis], axis)?;
            }
            Ok(pixels)
        })
        .collect()
}

/// The plan of a texture on a sparse heap and its tile size in texels.
pub fn texture(
    capabilities: &Capabilities,
    descriptor: &TextureDescriptor,
) -> Result<(TexturePlan, [u64; 3])> {
    ensure(
        descriptor.options.storage_mode == StorageMode::Private,
        "sparse textures use private storage",
    )?;
    require(
        descriptor.pixel_format.describe().is_color(),
        "sparse depth and stencil textures",
    )?;
    let tile = capabilities
        .sparse_tile_size(
            descriptor.texture_type,
            descriptor.pixel_format,
            descriptor.sample_count,
        )
        .ok_or(Error::Unsupported(
            "sparse textures of this type and format",
        ))?;
    let mut plan = resource::texture(capabilities, descriptor)?;
    plan.image.flags |= ImageCreate::SPARSE_BINDING | ImageCreate::SPARSE_RESIDENCY;
    Ok((plan, [tile.width, tile.height, tile.depth]))
}

/// A representative sparse texture of a heap's storage: the heap's memory
/// takes a type this texture accepts, and the heap's textures must accept
/// all of them.
pub fn probe(capabilities: &Capabilities, options: ResourceOptions) -> Result<ImageInfo> {
    let descriptor = TextureDescriptor {
        texture_type: TextureType::D2,
        pixel_format: PixelFormat::Rgba8Unorm,
        width: 256,
        height: 256,
        depth: 1,
        mipmap_level_count: 1,
        sample_count: 1,
        array_length: 1,
        options,
        usage: TextureUsage::SHADER_READ,
        swizzle: SwizzleChannels::IDENTITY,
    };
    Ok(texture(capabilities, &descriptor)?.0.image)
}

/// A sparse texture's tiles and mip tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseLayout {
    /// Texels per tile.
    pub tile: [u64; 3],
    /// `firstMipmapInTail`: the level count when no level is in the tail.
    pub first_mip_in_tail: u64,
    /// `tailSizeInBytes`: one slice's tail, or the shared tail.
    pub tail_bytes: u64,
    tail_offset: u64,
    tail_stride: u64,
    single_tail: bool,
    /// Each level's extent in texels.
    levels: Vec<[u64; 3]>,
    slices: u64,
    page_bytes: u64,
}

impl SparseLayout {
    pub fn new(
        descriptor: &TextureDescriptor,
        tile: [u64; 3],
        requirements: &SparseImageRequirements,
        page_bytes: u64,
    ) -> Result<Self> {
        require(
            requirements.granularity.map(u64::from) == tile,
            "non-standard sparse block shapes",
        )?;
        let levels: Vec<_> = (0..descriptor.mipmap_level_count)
            .map(|level| descriptor.level_extent(level))
            .collect();
        let first_mip_in_tail = u64::from(requirements.mip_tail_first_lod).min(levels.len() as u64);
        let tail_bytes = if first_mip_in_tail < levels.len() as u64 {
            requirements.mip_tail_size
        } else {
            0
        };
        ensure(
            tail_bytes.is_multiple_of(page_bytes),
            "mip tails hold whole sparse blocks",
        )?;
        Ok(Self {
            tile,
            first_mip_in_tail,
            tail_bytes,
            tail_offset: requirements.mip_tail_offset,
            tail_stride: requirements.mip_tail_stride,
            single_tail: requirements.single_mip_tail,
            levels,
            slices: descriptor.slice_count(),
            page_bytes,
        })
    }

    /// A level's extent in tiles.
    fn tiles(&self, level: u64) -> [u64; 3] {
        let extent = self.levels[level as usize];
        core::array::from_fn(|axis| extent[axis].div_ceil(self.tile[axis]))
    }

    fn pages(&self, tile: Tile) -> usize {
        match tile {
            Tile::Block { .. } => 1,
            Tile::Tail { .. } => (self.tail_bytes / self.page_bytes) as usize,
        }
    }
}

/// The pages of a sparse heap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparsePages {
    page_bytes: u64,
    count: u32,
    /// Free pages, the lowest last.
    free: Vec<u32>,
}

impl SparsePages {
    pub fn new(size: u64, page_bytes: u64) -> Self {
        let count = (size / page_bytes) as u32;
        Self {
            page_bytes,
            count,
            free: (0..count).rev().collect(),
        }
    }

    /// `count` pages, or none when fewer are free.
    fn take(&mut self, count: usize) -> Option<Vec<u32>> {
        let start = self.free.len().checked_sub(count)?;
        Some(self.free.drain(start..).rev().collect())
    }

    fn give(&mut self, pages: Vec<u32>) {
        self.free.extend(pages.into_iter().rev());
    }

    /// Bytes behind mapped tiles (`usedSize`).
    pub fn used_bytes(&self) -> u64 {
        u64::from(self.count - self.free.len() as u32) * self.page_bytes
    }

    /// Bytes still free to map (`maxAvailableSizeWithAlignment:`).
    pub fn free_bytes(&self) -> u64 {
        self.free.len() as u64 * self.page_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Tile {
    Block {
        level: u32,
        slice: u32,
        at: [u32; 3],
    },
    /// A slice's mip tail; slice 0 when one tail serves every slice.
    Tail { slice: u32 },
}

/// One region of `updateTextureMappings:mode:regions:mipLevels:slices:numRegions:`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingUpdate {
    pub level: u64,
    pub slice: u64,
    /// The region in tiles; any region of a tail level is the whole tail.
    pub region: SparseRegion,
}

/// `sizeof(MTLMapIndirectArguments)`.
pub const MAP_INDIRECT_ARGUMENTS_BYTES: usize = 32;

impl MappingUpdate {
    /// `MTLMapIndirectArguments`: the region's origin and size in tiles,
    /// then its level and slice, as `uint32_t`s.
    pub fn from_indirect(arguments: &[u8; MAP_INDIRECT_ARGUMENTS_BYTES]) -> Self {
        let words = arguments.as_chunks::<4>().0;
        let word = |index: usize| u64::from(u32::from_le_bytes(words[index]));
        Self {
            level: word(6),
            slice: word(7),
            region: SparseRegion {
                origin: [word(0), word(1), word(2)],
                size: [word(3), word(4), word(5)],
            },
        }
    }
}

/// A resource state encoder's recorded operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mapping {
    Request(MappingRequest),
    /// `updateTextureMapping:mode:indirectBuffer:indirectBufferOffset:`:
    /// the GPU copies the `MTLMapIndirectArguments` to `arguments`, in
    /// host-visible memory.
    Indirect {
        image: Image,
        mode: SparseTextureMappingMode,
        arguments: Upload,
    },
}

/// A resource state encoder's operation on sparse textures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappingRequest {
    /// `updateTextureMappings:…` and `updateTextureMapping:…`.
    Update {
        image: Image,
        mode: SparseTextureMappingMode,
        updates: Vec<MappingUpdate>,
    },
    /// `moveTextureMappingsFromTexture:sourceSlice:sourceLevel:sourceOrigin:sourceSize:toTexture:destinationSlice:destinationLevel:destinationOrigin:`,
    /// with a size in pixels.
    Move {
        source: MoveEnd,
        destination: MoveEnd,
        size: [u64; 3],
    },
}

/// One texture's side of a mapping move: a tile-aligned pixel origin in
/// one level and slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoveEnd {
    pub image: Image,
    pub level: u64,
    pub slice: u64,
    pub origin: [u64; 3],
}

/// A sparse texture's mapped tiles and the heap pages behind them.
#[derive(Clone, Debug)]
pub struct SparseTexture {
    pub image: Image,
    pub layout: SparseLayout,
    mapped: BTreeMap<Tile, Vec<u32>>,
}

impl SparseTexture {
    pub fn new(image: Image, layout: SparseLayout) -> Self {
        Self {
            image,
            layout,
            mapped: BTreeMap::new(),
        }
    }

    /// The tiles a region of tiles covers, in z, y, x order; a tail level
    /// names its slice's tail.
    fn tiles(&self, update: &MappingUpdate) -> Result<Vec<Tile>> {
        let layout = &self.layout;
        ensure(
            update.level < layout.levels.len() as u64,
            "mipmap level beyond the texture",
        )?;
        ensure(update.slice < layout.slices, "slice beyond the texture")?;
        if update.level >= layout.first_mip_in_tail {
            let slice = if layout.single_tail { 0 } else { update.slice };
            return Ok(alloc::vec![Tile::Tail {
                slice: slice as u32
            }]);
        }
        let limit = layout.tiles(update.level);
        let (origin, mut end) = (update.region.origin.map(|value| value as u32), [0; 3]);
        for axis in 0..3 {
            let last = update.region.end(axis)?;
            ensure(last <= limit[axis], "region beyond the level's tiles")?;
            end[axis] = last as u32;
        }
        let mut tiles = Vec::new();
        for z in origin[2]..end[2] {
            for y in origin[1]..end[1] {
                for x in origin[0]..end[0] {
                    tiles.push(Tile::Block {
                        level: update.level as u32,
                        slice: update.slice as u32,
                        at: [x, y, z],
                    });
                }
            }
        }
        Ok(tiles)
    }

    /// Fails as [`Self::update`] would, without changing anything.
    pub fn check_update(&self, update: &MappingUpdate) -> Result<()> {
        self.tiles(update).map(drop)
    }

    /// Fails as a move with this end would, without changing anything.
    pub fn check_move(&self, end: &MoveEnd, size: [u64; 3]) -> Result<usize> {
        self.region_tiles(end, size).map(|tiles| tiles.len())
    }

    /// The binds giving `tile` the pages `pages` (`None` unbinds).
    fn bind(&self, tile: Tile, pages: Option<&[u32]>, memory: Memory) -> Vec<SparseBind> {
        let layout = &self.layout;
        let page =
            |index: usize| pages.map(|pages| (memory, u64::from(pages[index]) * layout.page_bytes));
        match tile {
            Tile::Block { level, slice, at } => {
                let extent = layout.levels[level as usize];
                let offset: [u64; 3] =
                    core::array::from_fn(|axis| u64::from(at[axis]) * layout.tile[axis]);
                alloc::vec![SparseBind::Block {
                    image: self.image,
                    subresource: Subresource {
                        aspects: ImageAspects::COLOR,
                        mip_level: level,
                        base_array_layer: slice,
                        layer_count: 1,
                    },
                    offset: offset.map(|value| value as i32),
                    extent: core::array::from_fn(|axis| {
                        layout.tile[axis].min(extent[axis] - offset[axis]) as u32
                    }),
                    memory: page(0),
                }]
            }
            Tile::Tail { slice } => {
                let base = layout.tail_offset + u64::from(slice) * layout.tail_stride;
                (0..layout.pages(tile))
                    .map(|index| SparseBind::Opaque {
                        image: self.image,
                        offset: base + index as u64 * layout.page_bytes,
                        size: layout.page_bytes,
                        memory: page(index),
                    })
                    .collect()
            }
        }
    }

    /// Maps or unmaps the tiles of `update`. Mapped tiles stay mapped and
    /// unmapped tiles stay unmapped; a full heap ends the map.
    pub fn update(
        &mut self,
        mode: SparseTextureMappingMode,
        update: &MappingUpdate,
        heap: &mut SparsePages,
        memory: Memory,
        binds: &mut Vec<SparseBind>,
    ) -> Result<()> {
        for tile in self.tiles(update)? {
            match mode {
                SparseTextureMappingMode::Map => {
                    if self.mapped.contains_key(&tile) {
                        continue;
                    }
                    let Some(pages) = heap.take(self.layout.pages(tile)) else {
                        break;
                    };
                    binds.extend(self.bind(tile, Some(&pages), memory));
                    self.mapped.insert(tile, pages);
                }
                SparseTextureMappingMode::Unmap => {
                    if let Some(pages) = self.mapped.remove(&tile) {
                        binds.extend(self.bind(tile, None, memory));
                        heap.give(pages);
                    }
                }
            }
        }
        Ok(())
    }

    /// The tiles of a move's tile-aligned pixel region.
    fn region_tiles(&self, end: &MoveEnd, size: [u64; 3]) -> Result<Vec<Tile>> {
        let MoveEnd {
            level,
            slice,
            origin,
            ..
        } = *end;
        let layout = &self.layout;
        ensure(
            level < layout.levels.len() as u64,
            "mipmap level beyond the texture",
        )?;
        let extent = layout.levels[level as usize];
        let mut region = SparseRegion::default();
        for axis in 0..3 {
            let end = origin[axis]
                .checked_add(size[axis])
                .filter(|&end| end <= extent[axis])
                .ok_or(Error::Invalid("region beyond the level"))?;
            ensure(
                origin[axis].is_multiple_of(layout.tile[axis])
                    && (end.is_multiple_of(layout.tile[axis]) || end == extent[axis]),
                "moved regions are tile aligned",
            )?;
            region.origin[axis] = origin[axis] / layout.tile[axis];
            region.size[axis] = end.div_ceil(layout.tile[axis]) - region.origin[axis];
        }
        self.tiles(&MappingUpdate {
            level,
            slice,
            region,
        })
    }

    /// Unbinds the tiles of a move's source region and returns their pages.
    pub fn take_region(
        &mut self,
        source: &MoveEnd,
        size: [u64; 3],
        memory: Memory,
        binds: &mut Vec<SparseBind>,
    ) -> Result<Vec<Option<Vec<u32>>>> {
        let tiles = self.region_tiles(source, size)?;
        Ok(tiles
            .into_iter()
            .map(|tile| {
                let pages = self.mapped.remove(&tile);
                if pages.is_some() {
                    binds.extend(self.bind(tile, None, memory));
                }
                pages
            })
            .collect())
    }

    /// Gives the tiles of a move's destination region the source's pages:
    /// a destination tile ends up mapped exactly when its source tile was,
    /// and pages it held before return to the heap.
    pub fn place_region(
        &mut self,
        destination: &MoveEnd,
        size: [u64; 3],
        moved: Vec<Option<Vec<u32>>>,
        heap: &mut SparsePages,
        memory: Memory,
        binds: &mut Vec<SparseBind>,
    ) -> Result<()> {
        let tiles = self.region_tiles(destination, size)?;
        ensure(
            tiles.len() == moved.len(),
            "moves cover the same tiles in both textures",
        )?;
        for (tile, pages) in tiles.into_iter().zip(moved) {
            ensure(
                pages
                    .as_ref()
                    .is_none_or(|pages| pages.len() == self.layout.pages(tile)),
                "moved mip tails match in size",
            )?;
            let previous = self.mapped.remove(&tile);
            if previous.is_none() && pages.is_none() {
                continue;
            }
            if let Some(previous) = previous {
                heap.give(previous);
            }
            binds.extend(self.bind(tile, pages.as_deref(), memory));
            if let Some(pages) = pages {
                self.mapped.insert(tile, pages);
            }
        }
        Ok(())
    }

    /// Returns every mapped page to the heap, for destruction.
    pub fn release(&mut self, heap: &mut SparsePages) {
        for (_, pages) in core::mem::take(&mut self.mapped) {
            heap.give(pages);
        }
    }
}

#[cfg(test)]
mod tests;
