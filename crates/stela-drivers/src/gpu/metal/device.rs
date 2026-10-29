//! `MTLDevice`: Metal objects over a Vulkan [`Backend`].
//!
//! The device owns every Metal object as a slab entry named by a typed id,
//! with the Vulkan objects behind it. Destroying an object releases its
//! descriptors and Vulkan objects only after the last submitted command
//! buffer that could use it completes. Resources are in [`resources`],
//! pipelines in [`pipelines`], indirect command buffers in [`indirect`] and
//! command submission in [`queue`].
use super::{
    binding::{DescriptorHeap, HeapArray, HeapLayout, ResourceId},
    capabilities::{ApiFeatures, Capabilities, Platform},
    error::{Error, Result},
    shader::Compiler,
    vulkan::{
        backend::{Backend, Descriptor, Object, requirements},
        object::{Memory, Semaphore},
    },
};
use alloc::vec::Vec;

mod execution_sets;
pub mod indirect;
pub mod pipelines;
pub mod queue;
pub mod resources;

/// A slab of objects addressed by index; freed slots are reused.
#[derive(Debug)]
struct Slab<T> {
    entries: Vec<Option<T>>,
    free: Vec<u32>,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }
}

impl<T> Slab<T> {
    fn insert(&mut self, value: T) -> u32 {
        match self.free.pop() {
            Some(index) => {
                self.entries[index as usize] = Some(value);
                index
            }
            None => {
                self.entries.push(Some(value));
                self.entries.len() as u32 - 1
            }
        }
    }

    fn get(&self, index: u32) -> Result<&T> {
        self.entries
            .get(index as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid("unknown or destroyed object"))
    }

    fn get_mut(&mut self, index: u32) -> Result<&mut T> {
        self.entries
            .get_mut(index as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Invalid("unknown or destroyed object"))
    }

    fn remove(&mut self, index: u32) -> Result<T> {
        let value = self.entries.get_mut(index as usize).and_then(Option::take);
        let value = value.ok_or(Error::Invalid("unknown or destroyed object"))?;
        self.free.push(index);
        Ok(value)
    }
}

macro_rules! ids {
    ($($(#[$meta:meta])* $name:ident;)*) => {$(
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name(pub u32);
    )*};
}

ids! {
    BufferId;
    TextureId;
    SamplerId;
    HeapId;
    FunctionId;
    RenderPipelineId;
    ComputePipelineId;
    EventId;
    CounterBufferId;
}

pub struct Device<B: Backend, C: Compiler> {
    backend: B,
    compiler: C,
    capabilities: Capabilities,
    descriptors: DescriptorHeap,
    /// The universal queue's timeline: command buffer `n` signals `n`.
    timeline: Semaphore,
    submitted: u64,
    completed: u64,
    /// A submission failed; nothing pending will complete.
    lost: bool,
    /// Objects waiting for a serial to complete, in serial order.
    deferred: Vec<(u64, Object)>,
    allocated: u64,
    resources: resources::Resources,
    pipelines: pipelines::Pipelines,
    execution_sets: execution_sets::ExecutionSets,
    indirect: Slab<indirect::IndirectObject>,
    /// A function's module may set or copy indirect commands' barriers, so
    /// any GPU-resident buffer's commands may have them.
    command_barriers: bool,
    queue: queue::Queue,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// Opens the device, refusing Vulkan devices that lack a feature the
    /// binding ABI or command model relies on.
    pub fn new(mut backend: B, compiler: C, platform: &Platform) -> Result<Self> {
        let physical = backend.physical_device();
        if let Some(missing) = requirements(&physical.features)
            .iter()
            .find(|requirement| !requirement.present)
        {
            return Err(Error::Unsupported(missing.name));
        }
        let capabilities = Capabilities::derive(
            physical,
            platform,
            compiler.features(),
            ApiFeatures::IMPLEMENTED,
        );
        let layout = HeapLayout::new(&physical.limits);
        let timeline = backend.create_semaphore(0)?;
        Ok(Self {
            backend,
            compiler,
            capabilities,
            descriptors: DescriptorHeap::new(layout),
            timeline,
            submitted: 0,
            completed: 0,
            lost: false,
            deferred: Vec::new(),
            allocated: 0,
            resources: resources::Resources::default(),
            pipelines: pipelines::Pipelines::default(),
            execution_sets: execution_sets::ExecutionSets::default(),
            indirect: Slab::default(),
            command_barriers: false,
            queue: queue::Queue::default(),
        })
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }

    /// `currentAllocatedSize`.
    pub fn current_allocated_size(&self) -> u64 {
        self.allocated
    }

    /// Writes `descriptor` into a fresh heap index.
    fn descriptor(&mut self, descriptor: Descriptor) -> Result<u32> {
        let index = self.descriptors.allocate(descriptor.array())?;
        self.backend.write_descriptor(index, descriptor);
        Ok(index)
    }

    /// Destroys `object` once every command buffer submitted so far
    /// completes.
    fn defer(&mut self, object: Object) {
        if self.submitted <= self.completed {
            self.backend.destroy(object);
        } else {
            self.deferred.push((self.submitted, object));
        }
    }

    /// Frees the descriptors of `id` after the submitted work completes.
    fn release_id(&mut self, id: ResourceId, arrays: [HeapArray; 2]) {
        let runs = [(id.low(), 1), (id.high_index(), id.high_count())];
        for ((first, length), array) in runs.into_iter().zip(arrays) {
            if first != super::binding::NULL_DESCRIPTOR {
                self.descriptors
                    .release_run(array, first, length, self.submitted);
            }
        }
    }

    fn release_memory(&mut self, memory: Memory, bytes: u64) {
        self.allocated -= bytes;
        self.defer(Object::Memory(memory));
    }
}

#[cfg(test)]
pub(crate) mod tests;
