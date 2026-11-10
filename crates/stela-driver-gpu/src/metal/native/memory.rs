//! The memory behind the [`Memory`] values the Metal layer holds: whole
//! `VkDeviceMemory` allocations (heaps, imports and resources in memory of
//! their own) and places in [blocks](super::blocks). The values are the
//! backend's own numbers, never Vulkan handles, so a place and a whole
//! allocation cannot be confused.
use super::{
    Mapping,
    blocks::{Blocks, Place, Purpose, Source},
    zero::{FILL_ALIGN, Zeroing},
};
use crate::metal::vulkan::{MemoryProperties, object::Memory, physical::MemoryType};
use alloc::collections::BTreeMap;
use ash::vk::{self, Handle};
use core::ptr::NonNull;

/// What one [`Memory`] value names.
#[derive(Clone, Copy, Debug)]
pub(super) enum Allocation {
    /// A `VkDeviceMemory` of its own; `resource` when a buffer or image
    /// took it in place of a block's.
    Whole {
        memory: vk::DeviceMemory,
        resource: bool,
    },
    Placed(Place),
}

/// Where a [`Memory`] value's bytes are.
#[derive(Clone, Copy, Debug)]
pub(super) struct Resolved {
    pub memory: vk::DeviceMemory,
    /// The offset of its first byte in `memory`.
    pub offset: u64,
    /// The bytes of a place; `None` for a whole allocation.
    pub size: Option<u64>,
}

pub(super) struct Memories {
    entries: BTreeMap<u64, Allocation>,
    next: u64,
    pub blocks: Blocks<vk::DeviceMemory>,
}

impl Memories {
    /// The memories of a device of `bufferImageGranularity` `granularity`.
    pub(super) fn new(granularity: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            next: 1,
            blocks: Blocks::new(granularity),
        }
    }

    pub(super) fn insert(&mut self, allocation: Allocation) -> Memory {
        let value = self.next;
        self.next += 1;
        self.entries.insert(value, allocation);
        Memory(value)
    }

    pub(super) fn remove(&mut self, memory: Memory) -> Option<Allocation> {
        self.entries.remove(&memory.0)
    }

    pub(super) fn resolve(&self, memory: Memory) -> Option<Resolved> {
        match *self.entries.get(&memory.0)? {
            Allocation::Whole { memory, .. } => Some(Resolved {
                memory,
                offset: 0,
                size: None,
            }),
            Allocation::Placed(place) => Some(Resolved {
                memory: self.blocks.memory(place.block)?.0,
                offset: place.offset,
                size: Some(place.size),
            }),
        }
    }
}

/// Allocates the memory of one request: mapped whole when it says so, and,
/// for a resource taking memory of its own, dedicated to the resource
/// `dedicated` names. Other unmapped memory gets the fill buffers that zero
/// what new resources take of it.
pub(super) struct Allocator<'a> {
    pub device: &'a ash::Device,
    pub types: &'a [MemoryType],
    pub mappings: &'a mut BTreeMap<u64, Mapping>,
    pub zeroing: &'a mut Zeroing,
    pub mapped: bool,
    pub dedicated: Option<vk::MemoryDedicatedAllocateInfo<'static>>,
}

impl Allocator<'_> {
    fn map(&mut self, memory: vk::DeviceMemory, size: u64, index: u32) -> Result<(), vk::Result> {
        // SAFETY: `memory` was just allocated from a host-visible type (a
        // mapped request requires one) and is not mapped yet.
        let pointer = unsafe {
            self.device
                .map_memory(memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
        }?;
        let pointer =
            NonNull::new(pointer.cast::<u8>()).ok_or(vk::Result::ERROR_MEMORY_MAP_FAILED)?;
        let coherent = self.types[index as usize]
            .properties
            .contains(MemoryProperties::HOST_COHERENT);
        self.mappings.insert(
            memory.as_raw(),
            Mapping {
                pointer,
                size,
                coherent,
            },
        );
        Ok(())
    }
}

impl Source for Allocator<'_> {
    type Memory = vk::DeviceMemory;
    type Error = vk::Result;

    fn allocate(
        &mut self,
        memory_type: u32,
        size: u64,
        purpose: Purpose,
    ) -> Result<vk::DeviceMemory, vk::Result> {
        let mut flags =
            vk::MemoryAllocateFlagsInfo::default().flags(vk::MemoryAllocateFlags::DEVICE_ADDRESS);
        let mut dedicated = self.dedicated.filter(|_| purpose == Purpose::Own);
        // Fill buffers cover such memory whole, in `FILL_ALIGN`s.
        let filled = !self.mapped && dedicated.is_none();
        let allocation = if filled {
            size.next_multiple_of(FILL_ALIGN)
        } else {
            size
        };
        let mut info = vk::MemoryAllocateInfo::default()
            .allocation_size(allocation)
            .memory_type_index(memory_type)
            .push_next(&mut flags);
        if let Some(dedicated) = dedicated.as_mut() {
            info = info.push_next(dedicated);
        }
        // SAFETY: the allocate info and its chain outlive the call.
        let memory = unsafe { self.device.allocate_memory(&info, None) }?;
        if self.mapped
            && let Err(error) = self.map(memory, size, memory_type)
        {
            // SAFETY: nothing uses the memory just allocated.
            unsafe { self.device.free_memory(memory, None) };
            return Err(error);
        }
        if filled {
            self.zeroing
                .cover(self.device, memory, memory_type, allocation);
        }
        // Memory dedicated to a resource has no fill buffers: a dedicated
        // buffer is filled through itself, and images are cleared.
        Ok(memory)
    }

    fn free(&mut self, memory: vk::DeviceMemory) {
        self.mappings.remove(&memory.as_raw());
        self.zeroing.forget(self.device, memory);
        // SAFETY: memory is freed once nothing the GPU may still run uses
        // it: the Metal device destroys a whole allocation, or releases the
        // last place in a block, only after every submission that could use
        // it completed, and the backend frees the remaining blocks only
        // after the device idles.
        unsafe { self.device.free_memory(memory, None) };
    }
}
