//! `MTLBlitCommandEncoder`.
//!
//! Copies map to Vulkan transfer commands with Metal's byte strides
//! converted to Vulkan's texel strides; fills split unaligned edges into
//! copies from upload memory; mipmap generation is a chain of linear blits.
//! Hints with no Vulkan counterpart in the general image layout
//! (`optimizeContentsFor*Access`) record nothing, and fences need no
//! commands because the hazard tracker orders the queue.
use super::{BufferRef, CommandBuffer, Encoder, Resolver};
use crate::gpu::metal::{
    abi::BlitOption,
    error::{Error, Result, ensure},
    hazard::Use,
    pixel_format::{Description, Kind},
    resource::TextureDescriptor,
    vulkan::{
        Access, Filter, ImageAspects, PipelineStages,
        command::{BufferCopy, BufferImageCopy, Command, ImageBlit, ImageCopy, Subresource},
        object::Image,
    },
};
use alloc::vec::Vec;

pub(super) const TRANSFER: Use = Use::new(
    PipelineStages::ALL_TRANSFER,
    Access::TRANSFER_READ.union(Access::TRANSFER_WRITE),
);

/// A texture as a blit sees it.
#[derive(Clone, Copy, Debug)]
pub struct BlitTexture<'a> {
    pub image: Image,
    pub descriptor: &'a TextureDescriptor,
}

/// A texel region of one slice and level: `MTLOrigin` and `MTLSize`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub slice: u64,
    pub level: u64,
    pub origin: [u64; 3],
    pub size: [u64; 3],
}

/// A buffer's side of a buffer-texture copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferLayout {
    pub buffer: BufferRef,
    pub offset: u64,
    pub bytes_per_row: u64,
    /// Zero for single-image copies.
    pub bytes_per_image: u64,
}

impl BlitTexture<'_> {
    fn description(&self) -> &'static Description {
        self.descriptor.pixel_format.describe()
    }

    /// Validates `region` and returns its subresource, offset and extent.
    fn region(
        &self,
        region: &Region,
        aspects: ImageAspects,
    ) -> Result<(Subresource, [i32; 3], [u32; 3])> {
        ensure(
            region.level < self.descriptor.mipmap_level_count,
            "level beyond the texture's mipmaps",
        )?;
        ensure(
            region.slice < self.descriptor.slice_count(),
            "slice beyond the texture",
        )?;
        let size = self.descriptor.level_extent(region.level);
        let block = self.description().block;
        let block_size = [u64::from(block.width), u64::from(block.height), 1];
        for axis in 0..3 {
            let end = region.origin[axis].checked_add(region.size[axis]);
            ensure(
                end.is_some_and(|end| end <= size[axis]),
                "region extends past the texture",
            )?;
            ensure(
                region.origin[axis].is_multiple_of(block_size[axis]),
                "regions start on block boundaries",
            )?;
            ensure(
                region.size[axis].is_multiple_of(block_size[axis])
                    || region.origin[axis] + region.size[axis] == size[axis],
                "regions cover whole blocks",
            )?;
        }
        let subresource = Subresource {
            aspects,
            mip_level: region.level as u32,
            base_array_layer: region.slice as u32,
            layer_count: 1,
        };
        Ok((
            subresource,
            region.origin.map(|origin| origin as i32),
            region.size.map(|size| size as u32),
        ))
    }

    /// The aspect a copy reads or writes; combined depth-stencil formats
    /// need a blit option naming one.
    fn copy_aspect(&self, options: BlitOption) -> Result<ImageAspects> {
        let description = self.description();
        match description.kind {
            Kind::Color(_) => {
                ensure(
                    options.is_empty(),
                    "blit options apply to depth-stencil textures",
                )?;
                Ok(ImageAspects::COLOR)
            }
            Kind::Depth => Ok(ImageAspects::DEPTH),
            Kind::Stencil => Ok(ImageAspects::STENCIL),
            Kind::DepthStencil => {
                let depth = options.contains(BlitOption::DEPTH_FROM_DEPTH_STENCIL);
                let stencil = options.contains(BlitOption::STENCIL_FROM_DEPTH_STENCIL);
                match (depth, stencil) {
                    (true, false) => Ok(ImageAspects::DEPTH),
                    (false, true) => Ok(ImageAspects::STENCIL),
                    _ => Err(Error::Invalid("depth-stencil copies name one aspect")),
                }
            }
        }
    }

    /// Bytes of one block of `aspect` in a buffer.
    fn block_bytes(&self, aspect: ImageAspects) -> u64 {
        match (self.descriptor.pixel_format.describe().kind, aspect) {
            (Kind::DepthStencil | Kind::Stencil, ImageAspects::STENCIL) => 1,
            (Kind::DepthStencil, _) => 4,
            _ => u64::from(self.description().block.bytes),
        }
    }
}

impl CommandBuffer {
    pub(super) fn blit(&mut self) -> Result<()> {
        ensure(
            matches!(self.encoder, Encoder::Blit),
            "no blit command encoder is encoding",
        )
    }

    pub fn begin_blit(&mut self) -> Result<()> {
        self.idle()?;
        self.encoder = Encoder::Blit;
        Ok(())
    }

    /// `copyFromBuffer:sourceOffset:toBuffer:destinationOffset:size:`.
    pub fn copy_buffer(
        &mut self,
        src: BufferRef,
        src_offset: u64,
        dst: BufferRef,
        dst_offset: u64,
        size: u64,
    ) -> Result<()> {
        self.blit()?;
        let src_offset = src.at(src_offset, size)?;
        let dst_offset = dst.at(dst_offset, size)?;
        if size == 0 {
            return Ok(());
        }
        self.recorder.access(TRANSFER);
        self.recorder.push(Command::CopyBuffer {
            src: src.buffer,
            dst: dst.buffer,
            regions: alloc::vec![BufferCopy {
                src_offset,
                dst_offset,
                size
            }],
        });
        Ok(())
    }

    /// `copyFromBuffer:…toTexture:…options:`.
    pub fn copy_buffer_to_texture(
        &mut self,
        src: BufferLayout,
        dst: BlitTexture,
        region: Region,
        options: BlitOption,
    ) -> Result<()> {
        self.blit()?;
        let copy = buffer_image_copy(&src, &dst, &region, options)?;
        self.recorder.access(TRANSFER);
        self.recorder.push(Command::CopyBufferToImage {
            src: src.buffer.buffer,
            dst: dst.image,
            regions: alloc::vec![copy],
        });
        Ok(())
    }

    /// `copyFromTexture:…toBuffer:…options:`.
    pub fn copy_texture_to_buffer(
        &mut self,
        src: BlitTexture,
        region: Region,
        dst: BufferLayout,
        options: BlitOption,
    ) -> Result<()> {
        self.blit()?;
        let copy = buffer_image_copy(&dst, &src, &region, options)?;
        self.recorder.access(TRANSFER);
        self.recorder.push(Command::CopyImageToBuffer {
            src: src.image,
            dst: dst.buffer.buffer,
            regions: alloc::vec![copy],
        });
        Ok(())
    }

    /// `copyFromTexture:sourceSlice:sourceLevel:sourceOrigin:sourceSize:toTexture:…`.
    pub fn copy_texture(
        &mut self,
        src: BlitTexture,
        src_region: Region,
        dst: BlitTexture,
        dst_slice: u64,
        dst_level: u64,
        dst_origin: [u64; 3],
    ) -> Result<()> {
        self.blit()?;
        check_copy_compatible(&src, &dst)?;
        let aspects = src.description().image_aspects();
        let (src_subresource, src_offset, extent) = src.region(&src_region, aspects)?;
        // Compressed-to-uncompressed copies scale the extent by the blocks.
        let (src_block, dst_block) = (src.description().block, dst.description().block);
        let size = [
            src_region.size[0] / u64::from(src_block.width) * u64::from(dst_block.width),
            src_region.size[1] / u64::from(src_block.height) * u64::from(dst_block.height),
            src_region.size[2],
        ];
        let dst_region = Region {
            slice: dst_slice,
            level: dst_level,
            origin: dst_origin,
            size,
        };
        let (dst_subresource, dst_offset, _) = dst.region(&dst_region, aspects)?;
        if extent.contains(&0) {
            return Ok(());
        }
        self.recorder.access(TRANSFER);
        self.recorder.push(Command::CopyImage {
            src: src.image,
            dst: dst.image,
            regions: alloc::vec![ImageCopy {
                src: src_subresource,
                src_offset,
                dst: dst_subresource,
                dst_offset,
                extent
            }],
        });
        Ok(())
    }

    /// `copyFromTexture:sourceSlice:sourceLevel:toTexture:destinationSlice:destinationLevel:sliceCount:levelCount:`.
    #[allow(clippy::too_many_arguments)]
    pub fn copy_texture_slices(
        &mut self,
        src: BlitTexture,
        src_slice: u64,
        src_level: u64,
        dst: BlitTexture,
        dst_slice: u64,
        dst_level: u64,
        slice_count: u64,
        level_count: u64,
    ) -> Result<()> {
        self.blit()?;
        check_copy_compatible(&src, &dst)?;
        let aspects = src.description().image_aspects();
        let mut regions = Vec::new();
        for level in 0..level_count {
            let size = src.descriptor.level_extent(src_level + level);
            ensure(
                dst.descriptor.level_extent(dst_level + level) == size,
                "copied levels have equal sizes",
            )?;
            for slice in 0..slice_count {
                let region = |slice, level| Region {
                    slice,
                    level,
                    origin: [0; 3],
                    size,
                };
                let (src, src_offset, extent) =
                    src.region(&region(src_slice + slice, src_level + level), aspects)?;
                let (dst, dst_offset, _) =
                    dst.region(&region(dst_slice + slice, dst_level + level), aspects)?;
                regions.push(ImageCopy {
                    src,
                    src_offset,
                    dst,
                    dst_offset,
                    extent,
                });
            }
        }
        if regions.is_empty() {
            return Ok(());
        }
        self.recorder.access(TRANSFER);
        self.recorder.push(Command::CopyImage {
            src: src.image,
            dst: dst.image,
            regions,
        });
        Ok(())
    }

    /// `fillBuffer:range:value:`. Vulkan fills whole aligned words, so
    /// unaligned edges are copied from upload memory.
    pub fn fill_buffer(
        &mut self,
        resolver: &mut dyn Resolver,
        buffer: BufferRef,
        start: u64,
        length: u64,
        value: u8,
    ) -> Result<()> {
        self.blit()?;
        let begin = buffer.at(start, length)?;
        if length == 0 {
            return Ok(());
        }
        let end = begin + length;
        let (aligned_begin, aligned_end) = (begin.next_multiple_of(4).min(end), end / 4 * 4);
        self.recorder.access(TRANSFER);
        if aligned_end > aligned_begin {
            let data = u32::from_ne_bytes([value; 4]);
            let size = aligned_end - aligned_begin;
            self.recorder.push(Command::FillBuffer {
                buffer: buffer.buffer,
                offset: aligned_begin,
                size,
                data,
            });
        }
        let edges = if aligned_end > aligned_begin {
            [(begin, aligned_begin), (aligned_end, end)]
        } else {
            [(begin, end), (end, end)]
        };
        for (from, to) in edges.into_iter().filter(|(from, to)| to > from) {
            let upload =
                self.recorder
                    .upload(resolver, &alloc::vec![value; (to - from) as usize], 4)?;
            let region = BufferCopy {
                src_offset: upload.offset,
                dst_offset: from,
                size: to - from,
            };
            self.recorder.push(Command::CopyBuffer {
                src: upload.buffer,
                dst: buffer.buffer,
                regions: alloc::vec![region],
            });
        }
        Ok(())
    }

    /// `generateMipmapsForTexture:`: each level is a linear blit of the one
    /// above, ordered by a barrier.
    pub fn generate_mipmaps(&mut self, texture: BlitTexture, filterable: bool) -> Result<()> {
        self.blit()?;
        let description = texture.description();
        ensure(
            matches!(description.kind, Kind::Color(numeric) if !numeric.is_integer())
                && !description.is_compressed(),
            "mipmaps are generated for uncompressed float color textures",
        )?;
        ensure(
            filterable,
            "mipmap generation needs a filterable, renderable format",
        )?;
        let layers = texture.descriptor.slice_count() as u32;
        for level in 1..texture.descriptor.mipmap_level_count {
            let bounds = |size: [u64; 3]| [[0; 3], size.map(|size| size as i32)];
            let subresource = |level: u64| Subresource {
                aspects: ImageAspects::COLOR,
                mip_level: level as u32,
                base_array_layer: 0,
                layer_count: layers,
            };
            self.recorder.access(TRANSFER);
            self.recorder.push(Command::BlitImage {
                src: texture.image,
                dst: texture.image,
                regions: alloc::vec![ImageBlit {
                    src: subresource(level - 1),
                    src_bounds: bounds(texture.descriptor.level_extent(level - 1)),
                    dst: subresource(level),
                    dst_bounds: bounds(texture.descriptor.level_extent(level)),
                }],
                filter: Filter::Linear,
            });
        }
        Ok(())
    }

    /// `synchronizeResource:` for a managed buffer, or a managed texture the
    /// CPU reads with host image copies: GPU writes become visible to the
    /// host once the command buffer completes.
    pub fn synchronize(&mut self) -> Result<()> {
        self.blit()?;
        if let Some(barrier) = self.recorder.hazards.host() {
            self.recorder.push(Command::Barrier(barrier));
        }
        Ok(())
    }

    /// `synchronizeTexture:slice:level:` for a managed texture whose CPU copy
    /// is a staging buffer: the region is copied there, then published.
    pub fn synchronize_texture(
        &mut self,
        texture: BlitTexture,
        staging: BufferLayout,
        region: Region,
    ) -> Result<()> {
        self.copy_texture_to_buffer(texture, region, staging, BlitOption::EMPTY)?;
        self.synchronize()
    }
}

/// Metal copies between textures of one format, sRGB pairs or equal block
/// sizes and sample counts.
fn check_copy_compatible(src: &BlitTexture, dst: &BlitTexture) -> Result<()> {
    let (from, to) = (src.descriptor, dst.descriptor);
    ensure(
        from.sample_count == to.sample_count,
        "copied textures share a sample count",
    )?;
    let (a, b) = (src.description(), dst.description());
    let same = from.pixel_format == to.pixel_format
        || from.pixel_format.srgb_pair() == Some(to.pixel_format);
    ensure(
        same || (a.is_color() && b.is_color() && a.block.bytes == b.block.bytes),
        "copied textures have compatible pixel formats",
    )
}

/// Converts Metal's byte strides to Vulkan's texel strides.
fn buffer_image_copy(
    layout: &BufferLayout,
    texture: &BlitTexture,
    region: &Region,
    options: BlitOption,
) -> Result<BufferImageCopy> {
    let aspect = texture.copy_aspect(options)?;
    let (subresource, offset, extent) = texture.region(region, aspect)?;
    let block = texture.description().block;
    let block_bytes = texture.block_bytes(aspect);
    let rows = region.size[1].div_ceil(u64::from(block.height));
    let row_bytes = region.size[0].div_ceil(u64::from(block.width)) * block_bytes;
    ensure(
        layout.bytes_per_row >= row_bytes,
        "bytesPerRow is smaller than a row",
    )?;
    ensure(
        layout.bytes_per_row.is_multiple_of(block_bytes),
        "bytesPerRow is a multiple of the block size",
    )?;
    let image_bytes = if region.size[2] > 1 || layout.bytes_per_image != 0 {
        ensure(
            layout.bytes_per_image >= layout.bytes_per_row * rows,
            "bytesPerImage is smaller than an image",
        )?;
        ensure(
            layout.bytes_per_image.is_multiple_of(layout.bytes_per_row),
            "bytesPerImage is a multiple of bytesPerRow",
        )?;
        layout.bytes_per_image
    } else {
        layout.bytes_per_row * rows
    };
    let alignment = if aspect == ImageAspects::COLOR {
        block_bytes
    } else {
        4
    };
    ensure(
        layout.offset.is_multiple_of(block_bytes),
        "buffer offsets are multiples of the block size",
    )?;
    let last_image = (region.size[2].max(1) - 1) * image_bytes;
    let bytes = last_image + (rows.max(1) - 1) * layout.bytes_per_row + row_bytes;
    let buffer_offset = layout.buffer.at(layout.offset, bytes)?;
    if !buffer_offset.is_multiple_of(alignment) {
        return Err(Error::Unsupported(
            "depth and stencil copies at offsets that are not multiples of four",
        ));
    }
    Ok(BufferImageCopy {
        buffer_offset,
        buffer_row_length: (layout.bytes_per_row / block_bytes * u64::from(block.width)) as u32,
        buffer_image_height: (image_bytes / layout.bytes_per_row * u64::from(block.height)) as u32,
        subresource,
        offset,
        extent,
    })
}
