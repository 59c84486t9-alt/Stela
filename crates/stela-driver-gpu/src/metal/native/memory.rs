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

/// The bytes an allocation of `size` takes: unmapped memory not dedicated
/// to a resource gets fill buffers, which cover it whole in `FILL_ALIGN`s
/// ([`filled`]).
pub(super) fn allocation_bytes(size: u64, filled: bool) -> u64 {
    if filled {
        size.next_multiple_of(FILL_ALIGN)
    } else {
        size
    }
}

/// Whether memory gets fill buffers: unmapped and dedicated to no resource.
/// A dedicated buffer is filled through itself, and images are cleared.
pub(super) fn filled(mapped: bool, dedicated: bool) -> bool {
    !mapped && !dedicated
}

/// A new `VkDeviceMemory` of `bytes` of `memory_type`, dedicated to the
/// resource `dedicated` names, and mapped whole when `mapped`: what the
/// turn's allocations and the jobs that allocate outside it share. Its
/// address, when mapped.
pub(super) fn allocate_raw(
    device: &ash::Device,
    memory_type: u32,
    bytes: u64,
    dedicated: Option<vk::MemoryDedicatedAllocateInfo<'static>>,
    mapped: bool,
) -> Result<(vk::DeviceMemory, Option<NonNull<u8>>), vk::Result> {
    let mut flags =
        vk::MemoryAllocateFlagsInfo::default().flags(vk::MemoryAllocateFlags::DEVICE_ADDRESS);
    let mut dedicated = dedicated;
    let mut info = vk::MemoryAllocateInfo::default()
        .allocation_size(bytes)
        .memory_type_index(memory_type)
        .push_next(&mut flags);
    if let Some(dedicated) = dedicated.as_mut() {
        info = info.push_next(dedicated);
    }
    // SAFETY: the allocate info and its chain outlive the call.
    let memory = unsafe { device.allocate_memory(&info, None) }?;
    if !mapped {
        return Ok((memory, None));
    }
    // SAFETY: `memory` was just allocated from a host-visible type (a mapped
    // request requires one) and is not mapped yet.
    let pointer =
        unsafe { device.map_memory(memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty()) }
            .and_then(|pointer| {
                NonNull::new(pointer.cast::<u8>()).ok_or(vk::Result::ERROR_MEMORY_MAP_FAILED)
            });
    match pointer {
        Ok(pointer) => Ok((memory, Some(pointer))),
        Err(error) => {
            // SAFETY: nothing uses the memory just allocated.
            unsafe { device.free_memory(memory, None) };
            Err(error)
        }
    }
}

/// The host mapping of `size` bytes of `memory_type` at `pointer`.
pub(super) fn mapping(
    types: &[MemoryType],
    memory_type: u32,
    pointer: NonNull<u8>,
    size: u64,
) -> Mapping {
    let coherent = types[memory_type as usize]
        .properties
        .contains(MemoryProperties::HOST_COHERENT);
    Mapping {
        pointer,
        size,
        coherent,
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
        let dedicated = self.dedicated.filter(|_| purpose == Purpose::Own);
        let filled = filled(self.mapped, dedicated.is_some());
        let allocation = allocation_bytes(size, filled);
        let (memory, pointer) =
            allocate_raw(self.device, memory_type, allocation, dedicated, self.mapped)?;
        if let Some(pointer) = pointer {
            self.mappings.insert(
                memory.as_raw(),
                mapping(self.types, memory_type, pointer, size),
            );
        }
        if filled {
            self.zeroing
                .cover(self.device, memory, memory_type, allocation);
        }
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
