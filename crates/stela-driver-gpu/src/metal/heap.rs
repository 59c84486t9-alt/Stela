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
        StorageMode::Memoryless => return Err(Error::Unsupported("memoryless storage")),
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
