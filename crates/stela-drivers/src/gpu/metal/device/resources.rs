//! Buffers, textures, samplers and heaps.
use super::{BufferId, Device, HeapId, SamplerId, Slab, TextureId};
use crate::gpu::metal::{
    abi::{HeapType, ResourceOptions, StorageMode, TextureType},
    binding::{HeapArray, ResourceId},
    command_buffer::BufferRef,
    error::{Error, Result, ensure},
    heap::{self, HeapAllocator, HeapDescriptor, SizeAndAlign},
    pass::AttachmentView,
    resource::{
        self, CpuAccess, ShaderViews, TextureDescriptor, TexturePlan, TextureViewDescriptor,
    },
    sampler::{self, SamplerDescriptor},
    shader::Compiler,
    vulkan::{
        backend::{Backend, Descriptor, Object},
        command::BufferImageCopy,
        object::{Buffer, BufferView, Image, ImageView, ImageViewInfo, Memory, Sampler},
    },
};
use alloc::vec::Vec;

const TEXTURE_ARRAYS: [HeapArray; 2] = [HeapArray::SampledImages, HeapArray::StorageImages];
const TEXEL_BUFFER_ARRAYS: [HeapArray; 2] = [
    HeapArray::UniformTexelBuffers,
    HeapArray::StorageTexelBuffers,
];

/// Where a resource's memory came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backing {
    /// Its own allocation of this many bytes.
    Owned(u64),
    /// Placed in a heap; automatic heaps return the range on destruction
    /// unless the resource was made aliasable.
    Heap {
        heap: HeapId,
        offset: u64,
        size: u64,
        aliasable: bool,
    },
    /// Aliases a buffer's memory (linear textures and texture buffers).
    Buffer(BufferId),
}

#[derive(Debug)]
struct BufferObject {
    buffer: Buffer,
    memory: Memory,
    memory_offset: u64,
    address: u64,
    length: u64,
    options: ResourceOptions,
    backing: Backing,
    /// Textures over this buffer, which keep it alive.
    dependents: u32,
}

#[derive(Debug)]
struct TextureObject {
    image: Option<Image>,
    descriptor: TextureDescriptor,
    id: ResourceId,
    views: Vec<ImageView>,
    texel_views: Vec<BufferView>,
    attachment_views: Vec<(AttachmentView<()>, ImageView)>,
    cpu_access: CpuAccess,
    backing: Backing,
    /// The texture's own allocation, when `backing` is `Owned`.
    memory: Option<Memory>,
    /// The texture this one views; views keep their parent alive.
    parent: Option<TextureId>,
    dependents: u32,
}

#[derive(Debug)]
struct SamplerObject {
    descriptor: SamplerDescriptor,
    samplers: Vec<Sampler>,
    id: ResourceId,
    /// LOD-clamped variants: (min, max, sampler id).
    clamped: Vec<(f32, f32, ResourceId)>,
    references: u32,
}

#[derive(Debug)]
struct HeapObject {
    descriptor: HeapDescriptor,
    memory: Memory,
    allocator: Option<HeapAllocator>,
    resources: u32,
}

#[derive(Debug, Default)]
pub(super) struct Resources {
    buffers: Slab<BufferObject>,
    textures: Slab<TextureObject>,
    samplers: Slab<SamplerObject>,
    heaps: Slab<HeapObject>,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newBufferWithLength:options:`.
    pub fn new_buffer(&mut self, length: u64, options: ResourceOptions) -> Result<BufferId> {
        let plan = resource::buffer(&self.capabilities, length, options)?;
        let allocation = self.backend.create_buffer(&plan.info, plan.memory)?;
        self.allocated += allocation.allocated;
        Ok(BufferId(self.resources.buffers.insert(BufferObject {
            buffer: allocation.buffer,
            memory: allocation.memory,
            memory_offset: 0,
            address: allocation.address,
            length,
            options,
            backing: Backing::Owned(allocation.allocated),
            dependents: 0,
        })))
    }

    pub fn buffer(&self, id: BufferId) -> Result<BufferRef> {
        let buffer = self.resources.buffers.get(id.0)?;
        Ok(BufferRef {
            buffer: buffer.buffer,
            offset: 0,
            address: buffer.address,
            length: buffer.length,
        })
    }

    /// The memory behind a buffer's `contents`, for the platform to map.
    pub fn buffer_memory(&self, id: BufferId) -> Result<(Memory, u64, u64)> {
        let buffer = self.resources.buffers.get(id.0)?;
        ensure(
            buffer.options.storage_mode != StorageMode::Private,
            "private buffers have no contents",
        )?;
        Ok((buffer.memory, buffer.memory_offset, buffer.length))
    }

    /// `didModifyRange:` of a managed buffer.
    pub fn did_modify_range(&mut self, id: BufferId, offset: u64, length: u64) -> Result<()> {
        let buffer = self.resources.buffers.get(id.0)?;
        ensure(
            buffer.options.storage_mode == StorageMode::Managed,
            "didModifyRange: is for managed buffers",
        )?;
        ensure(
            offset
                .checked_add(length)
                .is_some_and(|end| end <= buffer.length),
            "range extends past the buffer",
        )?;
        let (memory, base) = (buffer.memory, buffer.memory_offset);
        self.backend.flush_memory(memory, base + offset, length)
    }

    /// Makes GPU writes to a managed buffer visible to the CPU after the
    /// command buffer that synchronized it completes.
    pub fn invalidate_buffer(&mut self, id: BufferId) -> Result<()> {
        let buffer = self.resources.buffers.get(id.0)?;
        let (memory, offset, length) = (buffer.memory, buffer.memory_offset, buffer.length);
        self.backend.invalidate_memory(memory, offset, length)
    }

    pub fn destroy_buffer(&mut self, id: BufferId) -> Result<()> {
        ensure(
            self.resources.buffers.get(id.0)?.dependents == 0,
            "textures still alias the buffer",
        )?;
        let buffer = self.resources.buffers.remove(id.0)?;
        self.defer(Object::Buffer(buffer.buffer));
        self.release_backing(buffer.backing, Some(buffer.memory))
    }

    /// `newTextureWithDescriptor:`.
    pub fn new_texture(&mut self, descriptor: &TextureDescriptor) -> Result<TextureId> {
        let plan = resource::texture(&self.capabilities, descriptor)?;
        let (image, memory, bytes) = self.backend.create_image(&plan.image, plan.memory)?;
        self.allocated += bytes;
        self.finish_texture(
            image,
            descriptor,
            &plan,
            Backing::Owned(bytes),
            Some(memory),
        )
    }

    fn finish_texture(
        &mut self,
        image: Image,
        descriptor: &TextureDescriptor,
        plan: &TexturePlan,
        backing: Backing,
        memory: Option<Memory>,
    ) -> Result<TextureId> {
        let (id, views) = match self.shader_views(image, &plan.views) {
            Ok(created) => created,
            Err(error) => {
                self.backend.destroy(Object::Image(image));
                self.release_backing(backing, memory)?;
                return Err(error);
            }
        };
        let texture = TextureObject {
            image: Some(image),
            descriptor: *descriptor,
            id,
            views,
            texel_views: Vec::new(),
            attachment_views: Vec::new(),
            cpu_access: plan.cpu_access,
            backing,
            memory,
            parent: None,
            dependents: 0,
        };
        Ok(TextureId(self.resources.textures.insert(texture)))
    }

    /// Creates the sampled and storage views and their descriptors.
    fn shader_views(
        &mut self,
        image: Image,
        views: &ShaderViews,
    ) -> Result<(ResourceId, Vec<ImageView>)> {
        let mut created = Vec::new();
        let mut indices = [super::super::binding::NULL_DESCRIPTOR; 2];
        for (slot, info) in [views.sampled, views.storage].into_iter().enumerate() {
            let Some(info) = info else { continue };
            let view = self.backend.create_image_view(image, &info)?;
            created.push(view);
            let descriptor = if slot == 0 {
                Descriptor::SampledImage(view)
            } else {
                Descriptor::StorageImage(view)
            };
            indices[slot] = self.descriptor(descriptor)?;
        }
        Ok((ResourceId::new(indices[0], indices[1]), created))
    }

    /// `gpuResourceID` of a texture.
    pub fn texture_resource_id(&self, id: TextureId) -> Result<ResourceId> {
        Ok(self.resources.textures.get(id.0)?.id)
    }

    pub fn texture_descriptor(&self, id: TextureId) -> Result<&TextureDescriptor> {
        Ok(&self.resources.textures.get(id.0)?.descriptor)
    }

    /// The texture's image, for blits.
    pub fn texture_image(&self, id: TextureId) -> Result<Image> {
        let texture = self.resources.textures.get(id.0)?;
        texture
            .image
            .ok_or(Error::Invalid("texture buffers are not images"))
    }

    /// `newTextureViewWithPixelFormat:textureType:levels:slices:swizzle:`.
    pub fn new_texture_view(
        &mut self,
        parent: TextureId,
        view: &TextureViewDescriptor,
    ) -> Result<TextureId> {
        let texture = self.resources.textures.get(parent.0)?;
        let image = texture
            .image
            .ok_or(Error::Invalid("texture buffers have no views"))?;
        let mut descriptor = texture.descriptor;
        let root = texture.parent.unwrap_or(parent);
        let views = resource::texture_view(&self.capabilities, &descriptor, view)?;
        let (id, created) = self.shader_views(image, &views)?;
        descriptor.pixel_format = view.pixel_format;
        descriptor.texture_type = view.texture_type;
        descriptor.swizzle = view.swizzle;
        self.resources.textures.get_mut(root.0)?.dependents += 1;
        let view = TextureObject {
            image: Some(image),
            descriptor,
            id,
            views: created,
            texel_views: Vec::new(),
            attachment_views: Vec::new(),
            cpu_access: CpuAccess::None,
            backing: Backing::Owned(0),
            memory: None,
            parent: Some(root),
            dependents: 0,
        };
        Ok(TextureId(self.resources.textures.insert(view)))
    }

    /// `newTextureWithDescriptor:offset:bytesPerRow:` on a buffer: a linear
    /// texture, or a texture buffer for `MTLTextureTypeTextureBuffer`.
    pub fn new_texture_from_buffer(
        &mut self,
        buffer_id: BufferId,
        descriptor: &TextureDescriptor,
        offset: u64,
        bytes_per_row: u64,
    ) -> Result<TextureId> {
        let buffer = self.resources.buffers.get(buffer_id.0)?;
        let (vk_buffer, memory, memory_offset, length) = (
            buffer.buffer,
            buffer.memory,
            buffer.memory_offset,
            buffer.length,
        );
        let texture = if descriptor.texture_type == TextureType::TextureBuffer {
            let info = resource::texture_buffer(
                &self.capabilities,
                descriptor.pixel_format,
                descriptor.width,
                descriptor.usage,
                length,
                offset,
            )?;
            let view = self.backend.create_buffer_view(vk_buffer, &info)?;
            let usage = descriptor.usage;
            let read = if usage.is_empty()
                || usage.contains(crate::gpu::metal::abi::TextureUsage::SHADER_READ)
            {
                self.descriptor(Descriptor::UniformTexelBuffer(view))?
            } else {
                super::super::binding::NULL_DESCRIPTOR
            };
            let write = if usage.contains(crate::gpu::metal::abi::TextureUsage::SHADER_WRITE) {
                self.descriptor(Descriptor::StorageTexelBuffer(view))?
            } else {
                super::super::binding::NULL_DESCRIPTOR
            };
            TextureObject {
                image: None,
                descriptor: *descriptor,
                id: ResourceId::new(read, write),
                views: Vec::new(),
                texel_views: alloc::vec![view],
                attachment_views: Vec::new(),
                cpu_access: CpuAccess::Linear,
                backing: Backing::Buffer(buffer_id),
                memory: None,
                parent: None,
                dependents: 0,
            }
        } else {
            let plan = resource::linear_texture(
                &self.capabilities,
                descriptor,
                length,
                offset,
                bytes_per_row,
            )?;
            let image =
                self.backend
                    .create_placed_image(&plan.image, memory, memory_offset + offset)?;
            let (id, views) = match self.shader_views(image, &plan.views) {
                Ok(created) => created,
                Err(error) => {
                    self.backend.destroy(Object::Image(image));
                    return Err(error);
                }
            };
            TextureObject {
                image: Some(image),
                descriptor: *descriptor,
                id,
                views,
                texel_views: Vec::new(),
                attachment_views: Vec::new(),
                cpu_access: CpuAccess::Linear,
                backing: Backing::Buffer(buffer_id),
                memory: None,
                parent: None,
                dependents: 0,
            }
        };
        self.resources.buffers.get_mut(buffer_id.0)?.dependents += 1;
        Ok(TextureId(self.resources.textures.insert(texture)))
    }

    /// The view a render pass attaches, created on first use and kept with
    /// the texture.
    pub fn attachment_view(
        &mut self,
        id: TextureId,
        view: AttachmentView<()>,
    ) -> Result<ImageView> {
        let texture = self.resources.textures.get(id.0)?;
        if let Some(&(_, cached)) = texture
            .attachment_views
            .iter()
            .find(|(key, _)| *key == view)
        {
            return Ok(cached);
        }
        let image = texture
            .image
            .ok_or(Error::Invalid("texture buffers are not attachments"))?;
        let format = resource::vulkan_format(texture.descriptor.pixel_format)?;
        let info = ImageViewInfo {
            view_type: view.view_type,
            format,
            components: [crate::gpu::metal::vulkan::ComponentSwizzle::Identity; 4],
            range: view.range,
            usage: if texture.descriptor.pixel_format.describe().is_color() {
                crate::gpu::metal::vulkan::ImageUsage::COLOR_ATTACHMENT
            } else {
                crate::gpu::metal::vulkan::ImageUsage::DEPTH_STENCIL_ATTACHMENT
            },
        };
        let created = self.backend.create_image_view(image, &info)?;
        self.resources
            .textures
            .get_mut(id.0)?
            .attachment_views
            .push((view, created));
        Ok(created)
    }

    /// `replaceRegion:mipmapLevel:slice:withBytes:bytesPerRow:bytesPerImage:`
    /// with tightly packed bytes, for textures the CPU can write.
    pub fn replace_region(
        &mut self,
        id: TextureId,
        region: &BufferImageCopy,
        bytes: &[u8],
    ) -> Result<()> {
        let texture = self.resources.textures.get(id.0)?;
        self.cpu_access(texture)?;
        let image = texture.image.ok_or(Error::Invalid(
            "texture buffers are written through their buffer",
        ))?;
        self.backend.copy_to_image(image, region, bytes)
    }

    /// `getBytes:bytesPerRow:bytesPerImage:fromRegion:mipmapLevel:slice:`.
    pub fn get_bytes(
        &mut self,
        id: TextureId,
        region: &BufferImageCopy,
        bytes: &mut [u8],
    ) -> Result<()> {
        let texture = self.resources.textures.get(id.0)?;
        self.cpu_access(texture)?;
        let image = texture.image.ok_or(Error::Invalid(
            "texture buffers are read through their buffer",
        ))?;
        self.backend.copy_from_image(image, region, bytes)
    }

    fn cpu_access(&self, texture: &TextureObject) -> Result<()> {
        ensure(
            texture.descriptor.options.storage_mode != StorageMode::Private,
            "private textures have no CPU access",
        )?;
        match texture.cpu_access {
            CpuAccess::HostImageCopy | CpuAccess::Linear => Ok(()),
            CpuAccess::Staged => Err(Error::Unsupported("CPU access without host image copies")),
            CpuAccess::None => Err(Error::Invalid("the texture has no CPU access")),
        }
    }

    pub fn destroy_texture(&mut self, id: TextureId) -> Result<()> {
        ensure(
            self.resources.textures.get(id.0)?.dependents == 0,
            "views of the texture are still alive",
        )?;
        let texture = self.resources.textures.remove(id.0)?;
        let arrays = if texture.texel_views.is_empty() {
            TEXTURE_ARRAYS
        } else {
            TEXEL_BUFFER_ARRAYS
        };
        self.release_id(texture.id, arrays);
        for view in texture
            .views
            .iter()
            .chain(texture.attachment_views.iter().map(|(_, view)| view))
        {
            self.defer(Object::ImageView(*view));
        }
        for view in texture.texel_views {
            self.defer(Object::BufferView(view));
        }
        match texture.parent {
            Some(parent) => self.resources.textures.get_mut(parent.0)?.dependents -= 1,
            None => {
                if let Some(image) = texture.image {
                    self.defer(Object::Image(image));
                }
                self.release_backing(texture.backing, texture.memory)?;
            }
        }
        Ok(())
    }

    fn release_backing(&mut self, backing: Backing, memory: Option<Memory>) -> Result<()> {
        match (backing, memory) {
            (Backing::Owned(bytes), Some(memory)) => self.release_memory(memory, bytes),
            (Backing::Owned(_), None) => {}
            (
                Backing::Heap {
                    heap,
                    offset,
                    size,
                    aliasable,
                },
                _,
            ) => {
                let heap = self.resources.heaps.get_mut(heap.0)?;
                heap.resources -= 1;
                if let (Some(allocator), false) = (&mut heap.allocator, aliasable) {
                    allocator.free(offset, size)?;
                }
            }
            (Backing::Buffer(buffer), _) => {
                self.resources.buffers.get_mut(buffer.0)?.dependents -= 1
            }
        }
        Ok(())
    }

    /// `newSamplerStateWithDescriptor:`; equal descriptors share one state.
    pub fn new_sampler(&mut self, descriptor: &SamplerDescriptor) -> Result<SamplerId> {
        let existing = self.resources.samplers.entries.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|sampler| sampler.descriptor == *descriptor)
        });
        if let Some(index) = existing {
            self.resources.samplers.get_mut(index as u32)?.references += 1;
            return Ok(SamplerId(index as u32));
        }
        let (id, samplers) = self.create_sampler(descriptor)?;
        let object = SamplerObject {
            descriptor: *descriptor,
            samplers,
            id,
            clamped: Vec::new(),
            references: 1,
        };
        Ok(SamplerId(self.resources.samplers.insert(object)))
    }

    fn create_sampler(
        &mut self,
        descriptor: &SamplerDescriptor,
    ) -> Result<(ResourceId, Vec<Sampler>)> {
        let plan = sampler::sampler(&self.capabilities, descriptor)?;
        let float = self.backend.create_sampler(&plan.float)?;
        let mut samplers = alloc::vec![float];
        let float_index = self.descriptor(Descriptor::Sampler(float))?;
        let integer_index = match plan.integer {
            Some(info) => {
                let integer = self.backend.create_sampler(&info)?;
                samplers.push(integer);
                self.descriptor(Descriptor::Sampler(integer))?
            }
            None => float_index,
        };
        Ok((ResourceId::new(float_index, integer_index), samplers))
    }

    /// `gpuResourceID` of a sampler.
    pub fn sampler_resource_id(&self, id: SamplerId) -> Result<ResourceId> {
        Ok(self.resources.samplers.get(id.0)?.id)
    }

    /// A sampler like the one `id` names with its LOD range clamped.
    pub(super) fn clamped_sampler(
        &mut self,
        id: ResourceId,
        lod_min: f32,
        lod_max: f32,
    ) -> Result<ResourceId> {
        ensure(
            lod_min >= 0.0 && lod_min <= lod_max,
            "LOD clamps are ordered and nonnegative",
        )?;
        let found = self
            .resources
            .samplers
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|sampler| sampler.id == id));
        let index = found.ok_or(Error::Invalid("unknown sampler"))? as u32;
        let sampler = self.resources.samplers.get(index)?;
        if let Some(&(_, _, clamped)) = sampler
            .clamped
            .iter()
            .find(|(min, max, _)| *min == lod_min && *max == lod_max)
        {
            return Ok(clamped);
        }
        let descriptor = SamplerDescriptor {
            lod_min_clamp: sampler.descriptor.lod_min_clamp.max(lod_min),
            lod_max_clamp: sampler.descriptor.lod_max_clamp.min(lod_max),
            ..sampler.descriptor
        };
        let (clamped, samplers) = self.create_sampler(&descriptor)?;
        let sampler = self.resources.samplers.get_mut(index)?;
        sampler.samplers.extend(samplers);
        sampler.clamped.push((lod_min, lod_max, clamped));
        Ok(clamped)
    }

    pub fn destroy_sampler(&mut self, id: SamplerId) -> Result<()> {
        let sampler = self.resources.samplers.get_mut(id.0)?;
        sampler.references -= 1;
        if sampler.references > 0 {
            return Ok(());
        }
        let sampler = self.resources.samplers.remove(id.0)?;
        let ids = core::iter::once(sampler.id).chain(sampler.clamped.iter().map(|&(_, _, id)| id));
        for id in ids.collect::<Vec<_>>() {
            let low = ResourceId::new(id.low(), super::super::binding::NULL_DESCRIPTOR);
            self.release_id(low, [HeapArray::Samplers; 2]);
            if id.high() != id.low() {
                self.release_id(
                    ResourceId::new(id.high(), super::super::binding::NULL_DESCRIPTOR),
                    [HeapArray::Samplers; 2],
                );
            }
        }
        for sampler in sampler.samplers {
            self.defer(Object::Sampler(sampler));
        }
        Ok(())
    }

    /// `newHeapWithDescriptor:`.
    pub fn new_heap(&mut self, descriptor: &HeapDescriptor) -> Result<HeapId> {
        let plan = heap::heap(
            &self.capabilities,
            descriptor,
            crate::gpu::metal::capabilities::ApiFeatures::IMPLEMENTED,
        )?;
        let memory = self
            .backend
            .allocate_memory(plan.size, plan.memory, u32::MAX)?;
        self.allocated += plan.size;
        let allocator =
            (descriptor.heap_type == HeapType::Automatic).then(|| HeapAllocator::new(plan.size));
        Ok(HeapId(self.resources.heaps.insert(HeapObject {
            descriptor: *descriptor,
            memory,
            allocator,
            resources: 0,
        })))
    }

    /// `heapBufferSizeAndAlignWithLength:options:`.
    pub fn heap_buffer_size_and_align(
        &mut self,
        length: u64,
        options: ResourceOptions,
    ) -> Result<SizeAndAlign> {
        let plan = resource::buffer(&self.capabilities, length, options)?;
        let requirements = self.backend.buffer_requirements(&plan.info)?;
        SizeAndAlign::from_requirements(requirements.size, requirements.alignment)
            .ok_or(Error::Invalid("requirements"))
    }

    /// `heapTextureSizeAndAlignWithDescriptor:`.
    pub fn heap_texture_size_and_align(
        &mut self,
        descriptor: &TextureDescriptor,
    ) -> Result<SizeAndAlign> {
        let plan = resource::texture(&self.capabilities, descriptor)?;
        let requirements = self.backend.image_requirements(&plan.image)?;
        SizeAndAlign::from_requirements(requirements.size, requirements.alignment)
            .ok_or(Error::Invalid("requirements"))
    }

    /// Reserves heap memory: first fit in automatic heaps, the given offset
    /// in placement heaps.
    fn place(
        &mut self,
        id: HeapId,
        options: ResourceOptions,
        requirement: SizeAndAlign,
        offset: Option<u64>,
    ) -> Result<(Memory, u64)> {
        let heap = self.resources.heaps.get_mut(id.0)?;
        ensure(
            options.storage_mode == heap.descriptor.options.storage_mode,
            "heap resources share the heap's storage mode",
        )?;
        let offset = match (&mut heap.allocator, offset) {
            (Some(allocator), None) => allocator
                .allocate(requirement.size, requirement.align)
                .ok_or(Error::OutOfMemory)?,
            (None, Some(offset)) => {
                heap::placement(heap.descriptor.size, offset, requirement)?;
                offset
            }
            (Some(_), Some(_)) => return Err(Error::Invalid("automatic heaps choose offsets")),
            (None, None) => return Err(Error::Invalid("placement heaps need an offset")),
        };
        heap.resources += 1;
        Ok((heap.memory, offset))
    }

    /// `newBufferWithLength:options:` (and `…offset:`) on a heap.
    pub fn new_heap_buffer(
        &mut self,
        id: HeapId,
        length: u64,
        options: ResourceOptions,
        offset: Option<u64>,
    ) -> Result<BufferId> {
        let requirement = self.heap_buffer_size_and_align(length, options)?;
        let (memory, offset) = self.place(id, options, requirement, offset)?;
        let plan = resource::buffer(&self.capabilities, length, options)?;
        let (buffer, address) = match self
            .backend
            .create_placed_buffer(&plan.info, memory, offset)
        {
            Ok(created) => created,
            Err(error) => {
                self.release_backing(
                    Backing::Heap {
                        heap: id,
                        offset,
                        size: requirement.size,
                        aliasable: false,
                    },
                    None,
                )?;
                return Err(error);
            }
        };
        Ok(BufferId(self.resources.buffers.insert(BufferObject {
            buffer,
            memory,
            memory_offset: offset,
            address,
            length,
            options,
            backing: Backing::Heap {
                heap: id,
                offset,
                size: requirement.size,
                aliasable: false,
            },
            dependents: 0,
        })))
    }

    /// `newTextureWithDescriptor:` (and `…offset:`) on a heap.
    pub fn new_heap_texture(
        &mut self,
        id: HeapId,
        descriptor: &TextureDescriptor,
        offset: Option<u64>,
    ) -> Result<TextureId> {
        let requirement = self.heap_texture_size_and_align(descriptor)?;
        let (memory, offset) = self.place(id, descriptor.options, requirement, offset)?;
        let backing = Backing::Heap {
            heap: id,
            offset,
            size: requirement.size,
            aliasable: false,
        };
        let plan = resource::texture(&self.capabilities, descriptor)?;
        let image = match self
            .backend
            .create_placed_image(&plan.image, memory, offset)
        {
            Ok(image) => image,
            Err(error) => {
                self.release_backing(backing, None)?;
                return Err(error);
            }
        };
        self.finish_texture(image, descriptor, &plan, backing, None)
    }

    /// `makeAliasable` of a heap buffer: its range returns to the heap now.
    pub fn make_buffer_aliasable(&mut self, id: BufferId) -> Result<()> {
        let buffer = self.resources.buffers.get_mut(id.0)?;
        let backing = make_aliasable(&mut buffer.backing)?;
        self.free_heap_range(backing)
    }

    /// `makeAliasable` of a heap texture.
    pub fn make_texture_aliasable(&mut self, id: TextureId) -> Result<()> {
        let texture = self.resources.textures.get_mut(id.0)?;
        let backing = make_aliasable(&mut texture.backing)?;
        self.free_heap_range(backing)
    }

    fn free_heap_range(&mut self, (heap, offset, size): (HeapId, u64, u64)) -> Result<()> {
        if let Some(allocator) = &mut self.resources.heaps.get_mut(heap.0)?.allocator {
            allocator.free(offset, size)?;
        }
        Ok(())
    }

    /// `usedSize` and `maxAvailableSizeWithAlignment:` of a heap.
    pub fn heap_usage(&self, id: HeapId, alignment: u64) -> Result<(u64, u64)> {
        let heap = self.resources.heaps.get(id.0)?;
        Ok(match &heap.allocator {
            Some(allocator) => (allocator.used(), allocator.max_available(alignment)),
            None => (heap.descriptor.size, heap.descriptor.size),
        })
    }

    pub fn destroy_heap(&mut self, id: HeapId) -> Result<()> {
        ensure(
            self.resources.heaps.get(id.0)?.resources == 0,
            "resources still live in the heap",
        )?;
        let heap = self.resources.heaps.remove(id.0)?;
        self.release_memory(heap.memory, heap.descriptor.size);
        Ok(())
    }
}

fn make_aliasable(backing: &mut Backing) -> Result<(HeapId, u64, u64)> {
    match backing {
        Backing::Heap {
            heap,
            offset,
            size,
            aliasable,
        } => {
            ensure(!*aliasable, "the resource is already aliasable")?;
            *aliasable = true;
            Ok((*heap, *offset, *size))
        }
        _ => Err(Error::Invalid("only heap resources become aliasable")),
    }
}
