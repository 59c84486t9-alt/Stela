//! `vkQueueBindSparse` batches of a segment's sparse binds.
use super::{failure, handle, objects};
use crate::gpu::metal::{error::Result, vulkan::command::SparseBind};
use alloc::{collections::BTreeMap, vec::Vec};
use ash::vk;

/// What one bind binds: a block of a subresource or an opaque range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Range {
    Block {
        mip_level: u32,
        array_layer: u32,
        offset: [i32; 3],
    },
    Opaque(u64),
}

/// One batch's binds grouped per image. A range bound more than once in
/// the batch keeps its last binding, which is the state the Metal layer
/// left it in.
#[derive(Default)]
pub(super) struct SparseBatch {
    blocks: BTreeMap<u64, Vec<vk::SparseImageMemoryBind>>,
    opaque: BTreeMap<u64, Vec<vk::SparseMemoryBind>>,
}

impl SparseBatch {
    pub(super) fn new(binds: &[SparseBind]) -> Self {
        let mut last = BTreeMap::new();
        for bind in binds {
            let key = match *bind {
                SparseBind::Block {
                    image,
                    subresource,
                    offset,
                    ..
                } => (
                    image.0,
                    Range::Block {
                        mip_level: subresource.mip_level,
                        array_layer: subresource.base_array_layer,
                        offset,
                    },
                ),
                SparseBind::Opaque { image, offset, .. } => (image.0, Range::Opaque(offset)),
            };
            last.insert(key, *bind);
        }
        let memory = |memory: Option<(crate::gpu::metal::vulkan::object::Memory, u64)>| {
            memory.map_or((vk::DeviceMemory::null(), 0), |(memory, offset)| {
                (handle(memory.0), offset)
            })
        };
        let mut batch = Self::default();
        for bind in last.into_values() {
            match bind {
                SparseBind::Block {
                    image,
                    subresource,
                    offset,
                    extent,
                    memory: backing,
                } => {
                    let (memory, memory_offset) = memory(backing);
                    batch
                        .blocks
                        .entry(image.0)
                        .or_default()
                        .push(vk::SparseImageMemoryBind {
                            subresource: vk::ImageSubresource {
                                aspect_mask: objects::aspects(subresource.aspects),
                                mip_level: subresource.mip_level,
                                array_layer: subresource.base_array_layer,
                            },
                            offset: objects::offset(offset),
                            extent: objects::extent(extent),
                            memory,
                            memory_offset,
                            flags: vk::SparseMemoryBindFlags::empty(),
                        });
                }
                SparseBind::Opaque {
                    image,
                    offset,
                    size,
                    memory: backing,
                } => {
                    let (memory, memory_offset) = memory(backing);
                    batch
                        .opaque
                        .entry(image.0)
                        .or_default()
                        .push(vk::SparseMemoryBind {
                            resource_offset: offset,
                            size,
                            memory,
                            memory_offset,
                            flags: vk::SparseMemoryBindFlags::empty(),
                        });
                }
            }
        }
        batch
    }

    /// Binds the batch once every timeline in `waits` reaches its value,
    /// then signals `signal`.
    pub(super) fn submit(
        &self,
        device: &ash::Device,
        queue: vk::Queue,
        waits: &[(vk::Semaphore, u64)],
        signal: (vk::Semaphore, u64),
    ) -> Result<()> {
        let images: Vec<_> = self
            .blocks
            .iter()
            .map(|(&image, binds)| {
                vk::SparseImageMemoryBindInfo::default()
                    .image(handle(image))
                    .binds(binds)
            })
            .collect();
        let opaque: Vec<_> = self
            .opaque
            .iter()
            .map(|(&image, binds)| {
                vk::SparseImageOpaqueMemoryBindInfo::default()
                    .image(handle(image))
                    .binds(binds)
            })
            .collect();
        let wait_semaphores: Vec<_> = waits.iter().map(|&(semaphore, _)| semaphore).collect();
        let wait_values: Vec<_> = waits.iter().map(|&(_, value)| value).collect();
        let (signal_semaphores, signal_values) = ([signal.0], [signal.1]);
        let mut timeline = vk::TimelineSemaphoreSubmitInfo::default()
            .wait_semaphore_values(&wait_values)
            .signal_semaphore_values(&signal_values);
        let info = vk::BindSparseInfo::default()
            .wait_semaphores(&wait_semaphores)
            .image_binds(&images)
            .image_opaque_binds(&opaque)
            .signal_semaphores(&signal_semaphores)
            .push_next(&mut timeline);
        // SAFETY: every image is a live sparse image, every memory a live
        // allocation of a type the image accepts, and the queue supports
        // sparse binding; the arrays outlive the call.
        unsafe { device.queue_bind_sparse(queue, &[info], vk::Fence::null()) }.map_err(failure)
    }
}
