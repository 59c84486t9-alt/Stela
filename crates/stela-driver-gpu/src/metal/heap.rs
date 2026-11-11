//! `MTLHeap`: one Vulkan memory allocation that resources are placed in.
//!
//! Automatic heaps place resources with a first-fit allocator over the
//! heap's free ranges, which `makeAliasable` returns early so later
//! resources may alias them. Placement heaps take the application's offsets
//! unchanged, so aliasing is the application's choice. Sparse heaps back
//! sparse textures page by page and need the sparse texture path.
use super::{
    abi::{HeapType, ResourceOptions, SparsePageSize, StorageMode},
    capabilities::{ApiFeatures, Capabilities},
    error::{Error, Result, ensure, require},
    resource,
    vulkan::object::MemoryRequest,
};
use alloc::vec::Vec;

/// The page a Mac rounds a heap's capacity up to: a heap of 100 bytes
/// holds 16 KiB of resources there, and `currentAllocatedSize` says so.
pub const PAGE: u64 = 16_384;

/// The alignment a Mac answers for every heap texture the Apple layout
/// covers ([`apple_texture`]).
const APPLE_ALIGNMENT: u64 = 128;

/// `MTLHeapDescriptor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapDescriptor {
    pub size: u64,
    pub options: ResourceOptions,
    pub heap_type: HeapType,
    pub sparse_page_size: SparsePageSize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapPlan {
    pub size: u64,
    pub memory: MemoryRequest,
}

pub fn heap(
    capabilities: &Capabilities,
    descriptor: &HeapDescriptor,
    api: ApiFeatures,
) -> Result<HeapPlan> {
    ensure(descriptor.size > 0, "heap size must be nonzero")?;
    require(api.contains(ApiFeatures::HEAPS), "heaps")?;
    match descriptor.options.storage_mode {
        StorageMode::Private | StorageMode::Shared => {}
        StorageMode::Managed => return Err(Error::Invalid("heaps cannot use managed storage")),
        StorageMode::Memoryless => {
            return Err(Error::Invalid("heaps cannot use memoryless storage"));
        }
    }
    if descriptor.heap_type == HeapType::Sparse {
        require(api.contains(ApiFeatures::SPARSE_TEXTURES), "sparse heaps")?;
        let page = capabilities
            .sparse_tile_bytes(descriptor.sparse_page_size)
            .ok_or(Error::Unsupported("sparse page size"))?;
        ensure(
            descriptor.size.is_multiple_of(page),
            "sparse heaps hold whole pages",
        )?;
    }
    require(
        descriptor.size <= capabilities.limits.max_buffer_length,
        "heap size",
    )?;
    Ok(HeapPlan {
        size: descriptor.size,
        memory: resource::memory(descriptor.options)?,
    })
}

/// `MTLSizeAndAlign`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SizeAndAlign {
    pub size: u64,
    pub align: u64,
}

impl SizeAndAlign {
    /// Metal reports the Vulkan requirement's size rounded up to its alignment,
    /// so consecutive placements stay aligned.
    pub fn from_requirements(size: u64, alignment: u64) -> Option<Self> {
        let align = alignment.max(1);
        align
            .is_power_of_two()
            .then(|| size.checked_next_multiple_of(align))
            .flatten()
            .map(|size| Self { size, align })
    }
}

/// `heapTextureSizeAndAlignWithDescriptor:` as a Mac answers it for a
/// one-sample, one-slice 2D texture of an uncompressed color format whose
/// texels are 1, 2, 4, 8 or 16 bytes, private or shared; `None` for any
/// other, which the device answers with its own layout.
///
/// Measured on an M1 Pro (macOS 27) over those formats, sizes 1 to 512 in
/// each dimension and both mip counts. A
/// level whose dimensions both reach the format's 16 KiB tile (128x128 at
/// one byte, 128x64 at two, 64x64 at four, 64x32 at eight, 32x32 at
/// sixteen) pads its ceiling-halved size to whole tiles; the first level
/// below that pads its size to powers of two and the smaller levels halve
/// those; each level is a multiple of 128 bytes. Compressible textures
/// (some usage, neither shader write nor pixel format views, both base
/// dimensions 16 or more) add metadata: per level whose ceiling-halved size
/// reaches 16 in either dimension, its power-of-two texel count over 32,
/// in multiples of 128 bytes. The rule matches every one-level answer and
/// about nine in ten mipmapped ones: mip chains with a level two tiles or
/// more across differ by a few percent.
pub fn apple_texture(descriptor: &resource::TextureDescriptor) -> Option<SizeAndAlign> {
    use super::abi::{TextureType, TextureUsage};
    let description = descriptor.pixel_format.describe();
    let block = description.block;
    let simple = descriptor.texture_type == TextureType::D2
        && descriptor.sample_count <= 1
        && descriptor.array_length <= 1
        && descriptor.depth <= 1
        && description.is_color()
        && !description.is_compressed()
        && descriptor.pixel_format.planes().is_none()
        && (block.width, block.height) == (1, 1)
        && matches!(
            descriptor.options.storage_mode,
            StorageMode::Private | StorageMode::Shared
        );
    let (tile_width, tile_height) = match block.bytes {
        1 => (128, 128),
        2 => (128, 64),
        4 => (64, 64),
        8 => (64, 32),
        16 => (32, 32),
        _ => return None,
    };
    if !simple || descriptor.width == 0 || descriptor.height == 0 {
        return None;
    }
    let bytes = u64::from(block.bytes);
    let (width, height) = (descriptor.width, descriptor.height);
    let levels = descriptor.mipmap_level_count.max(1);
    let compressible = !descriptor.usage.is_empty()
        && !descriptor
            .usage
            .intersects(TextureUsage::SHADER_WRITE | TextureUsage::PIXEL_FORMAT_VIEW)
        && width >= 16
        && height >= 16;
    let mut size = 0u64;
    // The first level below a tile, whose power-of-two size the smaller
    // levels halve.
    let mut small: Option<(u64, u64, u64)> = None;
    for level in 0..levels {
        let (floor_width, floor_height) = ((width >> level).max(1), (height >> level).max(1));
        let ceil_width = width.div_ceil(1 << level.min(63)).max(1);
        let ceil_height = height.div_ceil(1 << level.min(63)).max(1);
        let texels = if small.is_none() && floor_width >= tile_width && floor_height >= tile_height
        {
            ceil_width.next_multiple_of(tile_width) * ceil_height.next_multiple_of(tile_height)
        } else {
            let (first, base_width, base_height) =
                *small.get_or_insert((level, floor_width, floor_height));
            let shift = level - first;
            (base_width.next_power_of_two() >> shift).max(1)
                * (base_height.next_power_of_two() >> shift).max(1)
        };
        size = size.checked_add((texels.checked_mul(bytes)?).next_multiple_of(APPLE_ALIGNMENT))?;
        if compressible && (ceil_width >= 16 || ceil_height >= 16) {
            let pixels = ceil_width.next_power_of_two() * ceil_height.next_power_of_two();
            size += pixels.div_ceil(32).next_multiple_of(APPLE_ALIGNMENT);
        }
    }
    Some(SizeAndAlign {
        size,
        align: APPLE_ALIGNMENT,
    })
}

/// First-fit placement within an automatic heap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeapAllocator {
    size: u64,
    /// Free ranges as (offset, length), sorted and never adjacent.
    free: Vec<(u64, u64)>,
}

impl HeapAllocator {
    pub fn new(size: u64) -> Self {
        Self {
            size,
            free: if size == 0 {
                Vec::new()
            } else {
                alloc::vec![(0, size)]
            },
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Bytes currently placed or aliasable-but-alive (`usedSize`).
    pub fn used(&self) -> u64 {
        self.size - self.free.iter().map(|(_, length)| length).sum::<u64>()
    }

    /// `maxAvailableSizeWithAlignment:`.
    pub fn max_available(&self, alignment: u64) -> u64 {
        let alignment = alignment.max(1);
        self.free
            .iter()
            .filter_map(|&(offset, length)| {
                let start = offset.checked_next_multiple_of(alignment)?;
                (offset + length).checked_sub(start)
            })
            .max()
            .unwrap_or(0)
    }

    /// Places `size` bytes at an `alignment` boundary; `None` when no free
    /// range fits.
    pub fn allocate(&mut self, size: u64, alignment: u64) -> Option<u64> {
        if size == 0 || !alignment.max(1).is_power_of_two() {
            return None;
        }
        let alignment = alignment.max(1);
        let (index, start) =
            self.free
                .iter()
                .enumerate()
                .find_map(|(index, &(offset, length))| {
                    let start = offset.checked_next_multiple_of(alignment)?;
                    let end = start.checked_add(size)?;
                    (end <= offset + length).then_some((index, start))
                })?;
        let (offset, length) = self.free[index];
        let end = start + size;
        let after = (end, offset + length - end);
        match (start > offset, after.1 > 0) {
            (true, true) => {
                self.free[index] = (offset, start - offset);
                self.free.insert(index + 1, after);
            }
            (true, false) => self.free[index] = (offset, start - offset),
            (false, true) => self.free[index] = after,
            (false, false) => {
                self.free.remove(index);
            }
        }
        Some(start)
    }

    /// Takes exactly `offset..offset + size` when all of it is free.
    pub fn take(&mut self, offset: u64, size: u64) -> bool {
        let Some(end) = offset.checked_add(size).filter(|_| size > 0) else {
            return false;
        };
        let Some(index) = self
            .free
            .iter()
            .position(|&(start, length)| start <= offset && end <= start + length)
        else {
            return false;
        };
        let (start, length) = self.free[index];
        let after = (end, start + length - end);
        match (offset > start, after.1 > 0) {
            (true, true) => {
                self.free[index] = (start, offset - start);
                self.free.insert(index + 1, after);
            }
            (true, false) => self.free[index] = (start, offset - start),
            (false, true) => self.free[index] = after,
            (false, false) => {
                self.free.remove(index);
            }
        }
        true
    }

    /// Returns `offset..offset + size` to the heap, coalescing neighbors.
    /// Fails when the range is outside the heap or already free.
    pub fn free(&mut self, offset: u64, size: u64) -> Result<()> {
        let end = offset
            .checked_add(size)
            .filter(|&end| size > 0 && end <= self.size);
        let end = end.ok_or(Error::Invalid("range outside the heap"))?;
        let index = self.free.partition_point(|&(free, _)| free < offset);
        let overlaps_before = index > 0 && {
            let (previous, length) = self.free[index - 1];
            previous + length > offset
        };
        let overlaps_after = self.free.get(index).is_some_and(|&(next, _)| next < end);
        ensure(!overlaps_before && !overlaps_after, "range is already free")?;

        let merge_before = index > 0 && {
            let (previous, length) = self.free[index - 1];
            previous + length == offset
        };
        let merge_after = self.free.get(index).is_some_and(|&(next, _)| next == end);
        match (merge_before, merge_after) {
            (true, true) => {
                let (_, next_length) = self.free.remove(index);
                self.free[index - 1].1 += size + next_length;
            }
            (true, false) => self.free[index - 1].1 += size,
            (false, true) => self.free[index] = (offset, self.free[index].1 + size),
            (false, false) => self.free.insert(index, (offset, size)),
        }
        Ok(())
    }
}

/// Checks an application-chosen placement in a placement heap.
pub fn placement(heap_size: u64, offset: u64, requirement: SizeAndAlign) -> Result<()> {
    ensure(
        offset.is_multiple_of(requirement.align),
        "placement offset is not aligned",
    )?;
    ensure(
        offset
            .checked_add(requirement.size)
            .is_some_and(|end| end <= heap_size),
        "resource extends past the heap",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::{
        abi::{SwizzleChannels, TextureType, TextureUsage},
        pixel_format::PixelFormat,
        resource::TextureDescriptor,
    };

    fn apple(format: PixelFormat, width: u64, height: u64, mips: bool, usage: TextureUsage) -> u64 {
        let levels = if mips {
            64 - width.max(height).leading_zeros() as u64
        } else {
            1
        };
        let descriptor = TextureDescriptor {
            texture_type: TextureType::D2,
            pixel_format: format,
            width,
            height,
            depth: 1,
            mipmap_level_count: levels,
            sample_count: 1,
            array_length: 1,
            options: descriptor(StorageMode::Private, HeapType::Automatic).options,
            usage,
            swizzle: SwizzleChannels::IDENTITY,
        };
        let answer = apple_texture(&descriptor).unwrap();
        assert_eq!(answer.align, 128);
        answer.size
    }

    /// `heapTextureSizeAndAlignWithDescriptor:` as an M1 Pro answers it
    /// (macOS 27), for read usage (compressible) and read-write usage.
    #[test]
    fn heap_textures_answer_the_macs_sizes() {
        use PixelFormat::*;
        let read = TextureUsage::SHADER_READ;
        let write = read | TextureUsage::SHADER_WRITE;
        let measured = [
            (R8Unorm, 1, 1, false, 128, 128),
            (R8Unorm, 1, 1, true, 128, 128),
            (R8Unorm, 8, 8, false, 128, 128),
            (R8Unorm, 8, 8, true, 512, 512),
            (Rg8Unorm, 16, 16, false, 640, 512),
            (Rg8Unorm, 16, 16, true, 1152, 1024),
            (Bgra8Unorm, 188, 77, false, 99_328, 98_304),
            (Bgra8Unorm, 188, 77, true, 143_744, 142_208),
            (Bgra8Unorm, 184, 74, false, 99_328, 98_304),
            (R16Float, 188, 77, false, 66_560, 65_536),
            (R16Float, 188, 77, true, 89_216, 87_680),
            (R16Float, 184, 74, false, 66_560, 65_536),
            (Bgr10A2Unorm, 64, 64, false, 16_512, 16_384),
            (Bgr10A2Unorm, 64, 64, true, 22_528, 22_144),
            (Rgba16Float, 320, 160, false, 413_696, 409_600),
            (Rgba16Float, 368, 148, false, 495_616, 491_520),
            (Rgba8Unorm, 512, 512, false, 1_056_768, 1_048_576),
            (Rgba8Unorm, 512, 512, true, 1_409_536, 1_398_400),
            (Rgba32Float, 33, 17, false, 32_896, 32_768),
            (Rgba32Float, 33, 17, true, 44_032, 43_776),
        ];
        for (format, width, height, mips, compressed, plain) in measured {
            let label = alloc::format!("{format:?} {width}x{height} mips={mips}");
            assert_eq!(
                apple(format, width, height, mips, read),
                compressed,
                "{label}"
            );
            assert_eq!(apple(format, width, height, mips, write), plain, "{label}");
        }
        // No usage named, or views of other formats, leave textures
        // uncompressed.
        assert_eq!(apple(Bgra8Unorm, 16, 16, false, TextureUsage::EMPTY), 1024);
        let views = read | TextureUsage::PIXEL_FORMAT_VIEW;
        assert_eq!(apple(Bgra8Unorm, 188, 77, false, views), 98_304);
    }

    /// Textures of other kinds take the device's own layout.
    #[test]
    fn other_textures_have_no_mac_answer() {
        let mut descriptor = TextureDescriptor {
            texture_type: TextureType::D2Array,
            pixel_format: PixelFormat::Bgra8Unorm,
            width: 64,
            height: 64,
            depth: 1,
            mipmap_level_count: 1,
            sample_count: 1,
            array_length: 3,
            options: descriptor(StorageMode::Private, HeapType::Automatic).options,
            usage: TextureUsage::SHADER_READ,
            swizzle: SwizzleChannels::IDENTITY,
        };
        assert_eq!(apple_texture(&descriptor), None);
        descriptor.texture_type = TextureType::D2;
        descriptor.array_length = 1;
        assert!(apple_texture(&descriptor).is_some());
        descriptor.pixel_format = PixelFormat::Depth32Float;
        assert_eq!(apple_texture(&descriptor), None);
    }

    /// `take` claims an exact free range, and only a free one.
    #[test]
    fn take_claims_exact_free_ranges() {
        let mut heap = HeapAllocator::new(4096);
        assert!(heap.take(1024, 1024));
        assert!(!heap.take(1536, 128));
        assert_eq!(heap.allocate(1024, 1024), Some(0));
        assert_eq!(heap.allocate(1024, 1024), Some(2048));
        assert!(heap.take(3072, 1024));
        assert!(!heap.take(0, 1));
        heap.free(1024, 1024).unwrap();
        assert_eq!(heap.used(), 3072);
    }
    use crate::metal::{
        abi::{CpuCacheMode, HazardTrackingMode},
        nvidia::fixture::capabilities,
    };

    fn descriptor(storage_mode: StorageMode, heap_type: HeapType) -> HeapDescriptor {
        HeapDescriptor {
            size: 1 << 20,
            options: ResourceOptions {
                cpu_cache_mode: CpuCacheMode::DefaultCache,
                storage_mode,
                hazard_tracking_mode: HazardTrackingMode::Untracked,
            },
            heap_type,
            sparse_page_size: SparsePageSize::Size64,
        }
    }

    #[test]
    fn heaps_use_private_or_shared_memory() {
        let capabilities = capabilities();
        let api = ApiFeatures::IMPLEMENTED;
        assert!(
            heap(
                &capabilities,
                &descriptor(StorageMode::Private, HeapType::Automatic),
                api
            )
            .is_ok()
        );
        assert!(
            heap(
                &capabilities,
                &descriptor(StorageMode::Shared, HeapType::Placement),
                api
            )
            .is_ok()
        );
        assert!(matches!(
            heap(
                &capabilities,
                &descriptor(StorageMode::Managed, HeapType::Automatic),
                api
            ),
            Err(Error::Invalid(_))
        ));
        if !api.contains(ApiFeatures::SPARSE_TEXTURES) {
            assert_eq!(
                heap(
                    &capabilities,
                    &descriptor(StorageMode::Private, HeapType::Sparse),
                    api
                ),
                Err(Error::Unsupported("sparse heaps"))
            );
        }
    }

    #[test]
    fn sizes_round_up_to_their_alignment() {
        assert_eq!(
            SizeAndAlign::from_requirements(100, 256),
            Some(SizeAndAlign {
                size: 256,
                align: 256
            })
        );
        assert_eq!(
            SizeAndAlign::from_requirements(0x1_0000, 0x1_0000)
                .unwrap()
                .size,
            0x1_0000
        );
        assert_eq!(SizeAndAlign::from_requirements(1, 3), None);
        assert_eq!(
            placement(
                4096,
                256,
                SizeAndAlign {
                    size: 256,
                    align: 256
                }
            ),
            Ok(())
        );
        assert!(
            placement(
                4096,
                128,
                SizeAndAlign {
                    size: 256,
                    align: 256
                }
            )
            .is_err()
        );
        assert!(
            placement(
                4096,
                3840 + 256,
                SizeAndAlign {
                    size: 256,
                    align: 256
                }
            )
            .is_err()
        );
    }

    #[test]
    fn first_fit_respects_alignment_and_coalesces_on_free() {
        let mut heap = HeapAllocator::new(4096);
        assert_eq!(heap.allocate(100, 1), Some(0));
        assert_eq!(heap.allocate(256, 256), Some(256));
        assert_eq!(heap.allocate(50, 1), Some(100));
        assert_eq!(heap.used(), 4096 - (256 - 150) - (4096 - 512));
        assert_eq!(heap.max_available(1024), 3072);

        heap.free(256, 256).unwrap();
        heap.free(0, 100).unwrap();
        assert_eq!(heap.allocate(256, 256), Some(256), "freed space is reused");
        heap.free(256, 256).unwrap();
        heap.free(100, 50).unwrap();
        assert_eq!(heap.used(), 0);
        assert_eq!(heap.max_available(1), 4096);
        assert_eq!(heap.allocate(4096, 4096), Some(0));
        assert_eq!(heap.allocate(1, 1), None);
    }

    #[test]
    fn double_and_out_of_range_frees_are_refused() {
        let mut heap = HeapAllocator::new(1024);
        let offset = heap.allocate(128, 64).unwrap();
        heap.free(offset, 128).unwrap();
        assert!(heap.free(offset, 128).is_err());
        assert!(heap.free(1000, 100).is_err());
        assert!(heap.free(0, 0).is_err());
        let a = heap.allocate(512, 1).unwrap();
        assert!(heap.free(a + 256, 512).is_err(), "overlaps the free tail");
        assert_eq!(heap.allocate(0, 1), None);
        assert_eq!(heap.allocate(1, 3), None);
    }
}
