//! Buffers, textures, samplers and heaps.
use super::{BufferId, Device, HeapId, SamplerId, Slab, TextureId};
use crate::gpu::metal::{
    abi::{CpuCacheMode, HazardTrackingMode, HeapType, ResourceOptions, StorageMode, TextureType},
    binding::{HeapArray, NULL_DESCRIPTOR, ResourceId},
    command_buffer::{
        BufferRef, MappedRange,
        blit::{BufferLayout, Region},
    },
    error::{Error, Result, ensure, require},
    hazard::FULL,
    heap::{self, HeapAllocator, HeapDescriptor, SizeAndAlign},
    pass::AttachmentView,
    resource::{
        self, CpuAccess, ShaderViews, SubresourceLayout, TextureDescriptor, TexturePlan,
        TextureViewDescriptor,
    },
    sampler::{self, SamplerDescriptor},
    shader::Compiler,
    sparse::{self, MappingRequest, SparseLayout, SparsePages, SparseTexture},
    vulkan::{
        BufferCreate, BufferUsage, ImageAspects, MemoryProperties,
        backend::{Backend, BufferAllocation, Descriptor, Object},
        command::{BufferImageCopy, Command, SparseBind},
        object::{
            Buffer, BufferInfo, BufferView, Image, ImageView, ImageViewInfo, Memory, MemoryRequest,
            Sampler, SubresourceRange,
        },
    },
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;

const TEXTURE_ARRAYS: [HeapArray; 2] = [HeapArray::SampledImages, HeapArray::StorageImages];
const TEXEL_BUFFER_ARRAYS: [HeapArray; 2] = [
    HeapArray::UniformTexelBuffers,
    HeapArray::StorageTexelBuffers,
];

/// `allocatedSize` and `heapOffset` of a buffer or texture: zero for those
/// sharing another resource's memory or mapping sparse pages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Placement {
    pub allocated_size: u64,
    pub heap_offset: u64,
}

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
    /// Maps pages of a sparse heap.
    Sparse(HeapId),
}

impl Backing {
    fn placement(self) -> Placement {
        match self {
            Self::Owned(bytes) => Placement {
                allocated_size: bytes,
                heap_offset: 0,
            },
            Self::Heap { offset, size, .. } => Placement {
                allocated_size: size,
                heap_offset: offset,
            },
            Self::Buffer(_) | Self::Sparse(_) => Placement::default(),
        }
    }
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
    /// A managed texture's CPU copy, when the CPU cannot reach the image.
    cpu_copy: Option<BufferAllocation>,
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
    sparse: Option<SparseHeap>,
    resources: u32,
}

/// A sparse heap's pages and the memory types its textures must accept.
#[derive(Debug)]
struct SparseHeap {
    pages: SparsePages,
    memory_types: u32,
}

#[derive(Debug, Default)]
pub(super) struct Resources {
    buffers: Slab<BufferObject>,
    textures: Slab<TextureObject>,
    samplers: Slab<SamplerObject>,
    heaps: Slab<HeapObject>,
    /// CPU-copy regions of managed textures that the next commit uploads.
    cpu_copy_uploads: Vec<(TextureId, BufferImageCopy)>,
    /// Sparse textures by image, with their heaps.
    sparse: BTreeMap<Image, (HeapId, SparseTexture)>,
    /// The samplers of constexpr sampler states by state. Any pipeline
    /// compiled later may name one, so each lives as long as the device.
    constexpr_samplers: BTreeMap<u64, ResourceId>,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newBufferWithLength:options:`.
    pub fn new_buffer(&mut self, length: u64, options: ResourceOptions) -> Result<BufferId> {
        let plan = resource::buffer(&self.capabilities, length, options)?;
        let allocation = self.backend.create_buffer(&plan.info, plan.memory)?;
        Ok(self.own_buffer(allocation, length, options))
    }

    /// `newBufferWithBytesNoCopy:length:options:deallocator:`: a buffer over
    /// the process's memory at `address`, imported where it is, so its
    /// `contents` is `address`. The frontend runs the deallocator once the
    /// last command buffer that used the buffer completes.
    pub fn new_buffer_with_bytes_no_copy(
        &mut self,
        address: u64,
        length: u64,
        options: ResourceOptions,
    ) -> Result<BufferId> {
        let alignment = self
            .backend
            .physical_device()
            .limits
            .host_pointer_alignment
            .ok_or(Error::Unsupported("newBufferWithBytesNoCopy"))?;
        ensure(
            matches!(
                options.storage_mode,
                StorageMode::Shared | StorageMode::Managed
            ),
            "bytesNoCopy buffers are shared or managed",
        )?;
        ensure(
            address != 0 && address.is_multiple_of(alignment) && length.is_multiple_of(alignment),
            "bytesNoCopy memory starts and ends on a page",
        )?;
        let plan = resource::buffer(&self.capabilities, length, options)?;
        let allocation = self.backend.create_host_buffer(&plan.info, address)?;
        Ok(self.own_buffer(allocation, length, options))
    }

    fn own_buffer(
        &mut self,
        allocation: BufferAllocation,
        length: u64,
        options: ResourceOptions,
    ) -> BufferId {
        self.allocated += allocation.allocated;
        BufferId(self.resources.buffers.insert(BufferObject {
            buffer: allocation.buffer,
            memory: allocation.memory,
            memory_offset: 0,
            address: allocation.address,
            length,
            options,
            backing: Backing::Owned(allocation.allocated),
            dependents: 0,
        }))
    }

    /// A shared buffer of the device's own that holds `bytes`.
    pub(super) fn new_shared_buffer(&mut self, bytes: &[u8]) -> Result<BufferId> {
        let options = ResourceOptions {
            cpu_cache_mode: CpuCacheMode::DefaultCache,
            storage_mode: StorageMode::Shared,
            hazard_tracking_mode: HazardTrackingMode::Default,
        };
        let buffer = self.new_buffer(bytes.len() as u64, options)?;
        let (memory, offset, _) = self.buffer_memory(buffer)?;
        if let Err(error) = self.backend.write_memory(memory, offset, bytes) {
            self.destroy_buffer(buffer)?;
            return Err(error);
        }
        Ok(buffer)
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

    /// `contents`: where the CPU reaches the buffer, or zero for a private
    /// buffer.
    pub fn buffer_contents(&self, id: BufferId) -> Result<u64> {
        let buffer = self.resources.buffers.get(id.0)?;
        if buffer.options.storage_mode == StorageMode::Private {
            return Ok(0);
        }
        Ok(self.backend.mapped_address(buffer.memory)? + buffer.memory_offset)
    }

    pub fn buffer_placement(&self, id: BufferId) -> Result<Placement> {
        Ok(self.resources.buffers.get(id.0)?.backing.placement())
    }

    pub fn texture_placement(&self, id: TextureId) -> Result<Placement> {
        Ok(self.resources.textures.get(id.0)?.backing.placement())
    }

    /// The mapped memory behind a buffer: its memory, offset and length.
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

    /// The mapping `synchronizeResource:` makes current for a managed buffer.
    pub fn managed_range(&self, id: BufferId) -> Result<MappedRange> {
        let buffer = self.resources.buffers.get(id.0)?;
        ensure(
            buffer.options.storage_mode == StorageMode::Managed,
            "synchronizeResource: is for managed resources",
        )?;
        Ok(MappedRange {
            memory: buffer.memory,
            offset: buffer.memory_offset,
            length: buffer.length,
        })
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
        let cpu_copy = match plan.cpu_access {
            CpuAccess::Staged => self.new_cpu_copy(descriptor).map(Some),
            _ => Ok(None),
        };
        let created = cpu_copy.and_then(|cpu_copy| match self.shader_views(image, &plan.views) {
            Ok((id, views)) => Ok((id, views, cpu_copy)),
            Err(error) => {
                if let Some(copy) = cpu_copy {
                    self.destroy_cpu_copy(copy);
                }
                Err(error)
            }
        });
        let (id, views, cpu_copy) = match created {
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
            cpu_copy,
        };
        Ok(TextureId(self.resources.textures.insert(texture)))
    }

    /// The host-visible buffer behind a managed texture's CPU copy.
    fn new_cpu_copy(&mut self, descriptor: &TextureDescriptor) -> Result<BufferAllocation> {
        let info = BufferInfo {
            size: descriptor.cpu_copy_bytes(),
            usage: BufferUsage::TRANSFER_SRC | BufferUsage::TRANSFER_DST,
            flags: BufferCreate::EMPTY,
        };
        let request = MemoryRequest {
            required: MemoryProperties::HOST_VISIBLE | MemoryProperties::HOST_COHERENT,
            preferred: MemoryProperties::HOST_CACHED,
            mapped: true,
        };
        let allocation = self.backend.create_buffer(&info, request)?;
        self.allocated += allocation.allocated;
        Ok(allocation)
    }

    fn destroy_cpu_copy(&mut self, copy: BufferAllocation) {
        self.defer(Object::Buffer(copy.buffer));
        self.release_memory(copy.memory, copy.allocated);
    }

    /// Creates the sampled view, a cube's faces and a storage view of each
    /// level, which a storage image holds one of, with their descriptors.
    /// On failure nothing
    /// it created remains.
    fn shader_views(
        &mut self,
        image: Image,
        views: &ShaderViews,
    ) -> Result<(ResourceId, Vec<ImageView>)> {
        let levels = views.storage.iter().flat_map(|info| {
            (0..info.range.level_count).map(|level| ImageViewInfo {
                range: SubresourceRange {
                    base_mip_level: info.range.base_mip_level + level,
                    level_count: 1,
                    ..info.range
                },
                ..*info
            })
        });
        let infos: Vec<_> = views
            .sampled
            .into_iter()
            .chain(views.faces)
            .chain(levels)
            .collect();
        let mut created = Vec::with_capacity(infos.len());
        let mut descriptors = Ok(ResourceId::NULL);
        for info in &infos {
            match self.backend.create_image_view(image, info) {
                Ok(view) => created.push(view),
                Err(error) => {
                    descriptors = Err(error);
                    break;
                }
            }
        }
        if descriptors.is_ok() {
            let sampled = usize::from(views.sampled.is_some()) + usize::from(views.faces.is_some());
            let (sampled, storage) = created.split_at(sampled);
            descriptors = self.view_descriptors(sampled, storage);
        }
        match descriptors {
            Ok(id) => Ok((id, created)),
            Err(error) => {
                for view in created {
                    self.backend.destroy(Object::ImageView(view));
                }
                Err(error)
            }
        }
    }

    /// Writes the descriptors of consecutive sampled views, a view and a
    /// cube's faces, and of consecutive storage views, one per level.
    fn view_descriptors(
        &mut self,
        sampled_views: &[ImageView],
        storage: &[ImageView],
    ) -> Result<ResourceId> {
        let sampled_run = sampled_views.len() as u32;
        let sampled = match sampled_run {
            0 => NULL_DESCRIPTOR,
            run => self
                .descriptors
                .allocate_run(HeapArray::SampledImages, run)?,
        };
        for (index, view) in (sampled..).zip(sampled_views) {
            self.backend
                .write_descriptor(index, Descriptor::SampledImage(*view));
        }
        if storage.is_empty() {
            return Ok(ResourceId::new(sampled, NULL_DESCRIPTOR));
        }
        let levels = storage.len() as u32;
        let first = match self
            .descriptors
            .allocate_run(HeapArray::StorageImages, levels)
        {
            Ok(first) => first,
            Err(error) => {
                self.release_id(
                    ResourceId::new(sampled, NULL_DESCRIPTOR),
                    TEXTURE_ARRAYS,
                    sampled_run,
                );
                return Err(error);
            }
        };
        for (level, view) in (first..).zip(storage) {
            self.backend
                .write_descriptor(level, Descriptor::StorageImage(*view));
        }
        Ok(ResourceId::texture(sampled, first, levels))
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
            cpu_copy: None,
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
                cpu_copy: None,
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
                cpu_copy: None,
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

    /// `replaceRegion:mipmapLevel:slice:withBytes:bytesPerRow:bytesPerImage:`,
    /// for textures the CPU can write.
    pub fn replace_region(
        &mut self,
        id: TextureId,
        region: &Region,
        bytes: &[u8],
        strides: Strides,
    ) -> Result<()> {
        let (copy, rows) = self.cpu_region(id, region, strides, bytes.len())?;
        let packed: Vec<u8> = rows
            .into_iter()
            .flat_map(|row| &bytes[row])
            .copied()
            .collect();
        self.write_region(id, &copy, &packed)
    }

    /// `getBytes:bytesPerRow:bytesPerImage:fromRegion:mipmapLevel:slice:`.
    pub fn get_bytes(
        &mut self,
        id: TextureId,
        region: &Region,
        bytes: &mut [u8],
        strides: Strides,
    ) -> Result<()> {
        let (copy, rows) = self.cpu_region(id, region, strides, bytes.len())?;
        let mut packed = alloc::vec![0; rows.iter().map(ExactSizeIterator::len).sum()];
        self.read_region(id, &copy, &mut packed)?;
        let mut packed = packed.as_slice();
        for row in rows {
            let (head, rest) = packed.split_at(row.len());
            bytes[row].copy_from_slice(head);
            packed = rest;
        }
        Ok(())
    }

    /// The copy of a color texture's `region` and the ranges of its rows in
    /// `length` bytes laid out by `strides`.
    fn cpu_region(
        &self,
        id: TextureId,
        region: &Region,
        strides: Strides,
        length: usize,
    ) -> Result<(BufferImageCopy, Vec<Range<usize>>)> {
        let descriptor = &self.resources.textures.get(id.0)?.descriptor;
        let description = descriptor.pixel_format.describe();
        ensure(
            description.is_color(),
            "the CPU reaches depth and stencil textures through blits",
        )?;
        let (subresource, offset, extent) = region.resolve(descriptor, ImageAspects::COLOR)?;
        let block = description.block;
        let row_bytes = region.size[0].div_ceil(u64::from(block.width)) * u64::from(block.bytes);
        let rows = region.size[1].div_ceil(u64::from(block.height));
        let images = region.size[2];
        ensure(
            strides.bytes_per_row >= row_bytes,
            "bytesPerRow is smaller than a row",
        )?;
        ensure(
            images <= 1 || strides.bytes_per_image >= strides.bytes_per_row * rows,
            "bytesPerImage is smaller than an image",
        )?;
        let starts = (0..images).flat_map(|image| {
            (0..rows).map(move |row| image * strides.bytes_per_image + row * strides.bytes_per_row)
        });
        let rows = starts
            .map(|start| {
                let end = start + row_bytes;
                ensure(end <= length as u64, "the bytes end before the region")?;
                Ok(start as usize..end as usize)
            })
            .collect::<Result<Vec<_>>>()?;
        let copy = BufferImageCopy {
            buffer_offset: 0,
            buffer_row_length: 0,
            buffer_image_height: 0,
            subresource,
            offset,
            extent,
        };
        Ok((copy, rows))
    }

    /// Writes `region` from tightly packed bytes.
    fn write_region(
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
        let Some(copy) = &texture.cpu_copy else {
            return self.backend.copy_to_image(image, region, bytes);
        };
        let (memory, rows) = (
            copy.memory,
            cpu_copy_rows(&texture.descriptor, region, bytes.len())?,
        );
        for (offset, packed) in rows.clone() {
            self.backend.write_memory(memory, offset, &bytes[packed])?;
        }
        let upload = BufferImageCopy {
            buffer_offset: rows.first,
            ..*region
        };
        let upload = cpu_copy_region(&texture.descriptor, upload);
        self.resources.cpu_copy_uploads.push((id, upload));
        Ok(())
    }

    /// Reads `region` into tightly packed bytes.
    fn read_region(
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
        let Some(copy) = &texture.cpu_copy else {
            return self.backend.copy_from_image(image, region, bytes);
        };
        let (memory, rows) = (
            copy.memory,
            cpu_copy_rows(&texture.descriptor, region, bytes.len())?,
        );
        for (offset, packed) in rows {
            self.backend
                .read_memory(memory, offset, &mut bytes[packed])?;
        }
        Ok(())
    }

    /// The CPU copy of a managed texture's `level` and `slice`, for
    /// `synchronizeTexture`; `None` when the CPU reaches the image directly.
    pub fn texture_cpu_copy(
        &self,
        id: TextureId,
        level: u64,
        slice: u64,
    ) -> Result<Option<BufferLayout>> {
        let texture = self.resources.textures.get(id.0)?;
        let Some(copy) = &texture.cpu_copy else {
            return Ok(None);
        };
        let descriptor = &texture.descriptor;
        ensure(
            level < descriptor.mipmap_level_count && slice < descriptor.slice_count(),
            "subresource outside the texture",
        )?;
        let layout = descriptor.subresource_layout(level, slice);
        Ok(Some(BufferLayout {
            buffer: BufferRef {
                buffer: copy.buffer,
                offset: 0,
                address: copy.address,
                length: descriptor.cpu_copy_bytes(),
            },
            offset: layout.offset,
            bytes_per_row: layout.bytes_per_row,
            bytes_per_image: layout.bytes_per_image,
        }))
    }

    /// Commands that bring images up to date with CPU-copy writes since the
    /// last commit, ending in a barrier; empty when there are none.
    pub(super) fn take_cpu_copy_uploads(&mut self) -> Vec<Command> {
        let uploads = core::mem::take(&mut self.resources.cpu_copy_uploads);
        let textures = &self.resources.textures;
        let mut commands: Vec<Command> = uploads
            .into_iter()
            .filter_map(|(id, region)| {
                // A texture destroyed since its write needs no upload.
                let texture = textures.get(id.0).ok()?;
                Some(Command::CopyBufferToImage {
                    src: texture.cpu_copy.as_ref()?.buffer,
                    dst: texture.image?,
                    regions: alloc::vec![region],
                })
            })
            .collect();
        if !commands.is_empty() {
            commands.push(Command::Barrier(FULL));
        }
        commands
    }

    fn cpu_access(&self, texture: &TextureObject) -> Result<()> {
        ensure(
            texture.descriptor.options.storage_mode != StorageMode::Private,
            "private textures have no CPU access",
        )?;
        match texture.cpu_access {
            CpuAccess::HostImageCopy | CpuAccess::Linear | CpuAccess::Staged => Ok(()),
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
        let low_length =
            resource::sampled_descriptors(resource::view_type(texture.descriptor.texture_type));
        self.release_id(texture.id, arrays, low_length);
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
                    self.release_sparse(image)?;
                    self.defer(Object::Image(image));
                }
                if let Some(copy) = texture.cpu_copy {
                    self.destroy_cpu_copy(copy);
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
            (Backing::Sparse(heap), _) => self.resources.heaps.get_mut(heap.0)?.resources -= 1,
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

    /// The sampler of a constexpr sampler state.
    pub(super) fn constexpr_sampler(&mut self, state: u64) -> Result<ResourceId> {
        if let Some(&id) = self.resources.constexpr_samplers.get(&state) {
            return Ok(id);
        }
        let sampler = self.new_sampler(&SamplerDescriptor::from_constexpr(state)?)?;
        let id = self.sampler_resource_id(sampler)?;
        self.resources.constexpr_samplers.insert(state, id);
        Ok(id)
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
            self.release_id(low, [HeapArray::Samplers; 2], 1);
            if id.high() != id.low() {
                self.release_id(
                    ResourceId::new(id.high(), super::super::binding::NULL_DESCRIPTOR),
                    [HeapArray::Samplers; 2],
                    1,
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
        let sparse = match descriptor.heap_type {
            HeapType::Sparse => {
                let probe = sparse::probe(&self.capabilities, descriptor.options)?;
                let page = self
                    .capabilities
                    .sparse_tile_bytes(descriptor.sparse_page_size)
                    .ok_or(Error::Unsupported("sparse page size"))?;
                Some(SparseHeap {
                    pages: SparsePages::new(plan.size, page),
                    memory_types: self.backend.image_requirements(&probe)?.memory_types,
                })
            }
            HeapType::Automatic | HeapType::Placement => None,
        };
        let memory_types = sparse.as_ref().map_or(u32::MAX, |heap| heap.memory_types);
        let memory = self
            .backend
            .allocate_memory(plan.size, plan.memory, memory_types)?;
        self.allocated += plan.size;
        let allocator =
            (descriptor.heap_type == HeapType::Automatic).then(|| HeapAllocator::new(plan.size));
        Ok(HeapId(self.resources.heaps.insert(HeapObject {
            descriptor: *descriptor,
            memory,
            allocator,
            sparse,
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
        if self.resources.heaps.get(id.0)?.sparse.is_some() {
            ensure(offset.is_none(), "sparse heaps place textures themselves")?;
            return self.new_sparse_texture(id, descriptor);
        }
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

    /// A texture on a sparse heap, with every tile unmapped.
    fn new_sparse_texture(
        &mut self,
        id: HeapId,
        descriptor: &TextureDescriptor,
    ) -> Result<TextureId> {
        let (plan, tile) = sparse::texture(&self.capabilities, descriptor)?;
        let heap = self.resources.heaps.get(id.0)?;
        ensure(
            descriptor.options.storage_mode == heap.descriptor.options.storage_mode,
            "heap resources share the heap's storage mode",
        )?;
        let memory_types = heap.sparse.as_ref().map_or(0, |sparse| sparse.memory_types);
        let page = self
            .capabilities
            .sparse_tile_bytes(heap.descriptor.sparse_page_size)
            .ok_or(Error::Unsupported("sparse page size"))?;
        let (image, requirements) = self.backend.create_sparse_image(&plan.image)?;
        let layout = require(
            requirements.memory_types & memory_types == memory_types,
            "sparse textures in this heap's memory",
        )
        .and_then(|()| SparseLayout::new(descriptor, tile, &requirements, page));
        let layout = match layout {
            Ok(layout) => layout,
            Err(error) => {
                self.backend.destroy(Object::Image(image));
                return Err(error);
            }
        };
        self.resources.heaps.get_mut(id.0)?.resources += 1;
        let texture = self.finish_texture(image, descriptor, &plan, Backing::Sparse(id), None)?;
        self.resources
            .sparse
            .insert(image, (id, SparseTexture::new(image, layout)));
        Ok(texture)
    }

    /// The image a resource state encoder names for a sparse texture.
    pub fn sparse_image(&self, id: TextureId) -> Result<Image> {
        let image = self.resources.textures.get(id.0)?.image;
        image
            .filter(|image| self.resources.sparse.contains_key(image))
            .ok_or(Error::Invalid("the texture is not sparse"))
    }

    /// `firstMipmapInTail` and `tailSizeInBytes`; `None` unless the texture
    /// is sparse (`isSparse`).
    pub fn sparse_tail(&self, id: TextureId) -> Result<Option<(u64, u64)>> {
        let image = self.resources.textures.get(id.0)?.image;
        Ok(image
            .and_then(|image| self.resources.sparse.get(&image))
            .map(|(_, texture)| (texture.layout.first_mip_in_tail, texture.layout.tail_bytes)))
    }

    pub(super) fn sparse_texture(&self, image: Image) -> Result<&(HeapId, SparseTexture)> {
        self.resources
            .sparse
            .get(&image)
            .ok_or(Error::Invalid("the texture is not sparse"))
    }

    /// Fails as [`Self::sparse_binds`] would, without changing anything, so
    /// a commit either applies all its mapping updates or none.
    pub(super) fn check_mapping(&self, request: &MappingRequest) -> Result<()> {
        match request {
            MappingRequest::Update { image, updates, .. } => {
                let (_, texture) = self.sparse_texture(*image)?;
                updates
                    .iter()
                    .try_for_each(|update| texture.check_update(update))
            }
            MappingRequest::Move {
                source,
                destination,
                size,
            } => {
                let (heap, from) = self.sparse_texture(source.image)?;
                let (other, to) = self.sparse_texture(destination.image)?;
                ensure(heap == other, "moved mappings stay in one heap")?;
                ensure(
                    from.check_move(source, *size)? == to.check_move(destination, *size)?,
                    "moves cover the same tiles in both textures",
                )
            }
        }
    }

    /// The sparse binds of a resource state encoder's request, applied to
    /// the device's tile and page state.
    pub(super) fn sparse_binds(&mut self, request: &MappingRequest) -> Result<Vec<SparseBind>> {
        let mut binds = Vec::new();
        let resources = &mut self.resources;
        match request {
            MappingRequest::Update {
                image,
                mode,
                updates,
            } => {
                let (heap, texture) = resources
                    .sparse
                    .get_mut(image)
                    .ok_or(Error::Invalid("the texture is not sparse"))?;
                let heap = resources.heaps.get_mut(heap.0)?;
                let pages = &mut heap.sparse.as_mut().expect("sparse heap").pages;
                for update in updates {
                    texture.update(*mode, update, pages, heap.memory, &mut binds)?;
                }
            }
            MappingRequest::Move {
                source,
                destination,
                size,
            } => {
                let (heap, texture) = resources
                    .sparse
                    .get_mut(&source.image)
                    .ok_or(Error::Invalid("the texture is not sparse"))?;
                let heap = resources.heaps.get_mut(heap.0)?;
                let moved = texture.take_region(source, *size, heap.memory, &mut binds)?;
                let (_, texture) = resources
                    .sparse
                    .get_mut(&destination.image)
                    .ok_or(Error::Invalid("the texture is not sparse"))?;
                let pages = &mut heap.sparse.as_mut().expect("sparse heap").pages;
                texture.place_region(destination, *size, moved, pages, heap.memory, &mut binds)?;
            }
        }
        Ok(binds)
    }

    /// Returns a destroyed sparse texture's pages to its heap.
    fn release_sparse(&mut self, image: Image) -> Result<()> {
        if let Some((heap, mut texture)) = self.resources.sparse.remove(&image) {
            let heap = self.resources.heaps.get_mut(heap.0)?;
            texture.release(&mut heap.sparse.as_mut().expect("sparse heap").pages);
        }
        Ok(())
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
        Ok(match (&heap.allocator, &heap.sparse) {
            (Some(allocator), _) => (allocator.used(), allocator.max_available(alignment)),
            (None, Some(sparse)) => (sparse.pages.used_bytes(), sparse.pages.free_bytes()),
            (None, None) => (heap.descriptor.size, heap.descriptor.size),
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

/// The rows `region` covers in a texture's CPU copy, as (copy offset,
/// range in tightly packed bytes of `length`); `first` is the region's
/// first byte in the copy.
#[derive(Clone, Debug)]
struct CopyRows {
    first: u64,
    bytes_per_row: u64,
    bytes_per_image: u64,
    row_bytes: usize,
    rows: u32,
    images: u32,
    next: u32,
}

impl Iterator for CopyRows {
    type Item = (u64, core::ops::Range<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.rows * self.images {
            return None;
        }
        let (image, row) = (self.next / self.rows, self.next % self.rows);
        let offset = self.first
            + u64::from(image) * self.bytes_per_image
            + u64::from(row) * self.bytes_per_row;
        let start = self.next as usize * self.row_bytes;
        self.next += 1;
        Some((offset, start..start + self.row_bytes))
    }
}

/// Validates a tightly packed region of `length` bytes against the texture
/// and locates its rows in the CPU copy.
fn cpu_copy_rows(
    descriptor: &TextureDescriptor,
    region: &BufferImageCopy,
    length: usize,
) -> Result<CopyRows> {
    let subresource = &region.subresource;
    let (level, slice) = (
        u64::from(subresource.mip_level),
        u64::from(subresource.base_array_layer),
    );
    ensure(
        subresource.layer_count == 1
            && level < descriptor.mipmap_level_count
            && slice < descriptor.slice_count(),
        "one subresource of the texture",
    )?;
    let SubresourceLayout {
        offset,
        bytes_per_row,
        bytes_per_image,
        extent,
    } = descriptor.subresource_layout(level, slice);
    let block = descriptor.pixel_format.describe().block;
    let block_size = [u64::from(block.width), u64::from(block.height), 1];
    let origin = region.offset.map(|offset| offset as u64);
    let size = region.extent.map(u64::from);
    for axis in 0..3 {
        let end = origin[axis] + size[axis];
        ensure(end <= extent[axis], "region outside the texture level")?;
        ensure(
            origin[axis].is_multiple_of(block_size[axis])
                && (size[axis].is_multiple_of(block_size[axis]) || end == extent[axis]),
            "compressed regions cover whole blocks",
        )?;
    }
    let row_bytes = size[0].div_ceil(block_size[0]) * u64::from(block.bytes);
    let rows = size[1].div_ceil(block_size[1]);
    ensure(
        row_bytes * rows * size[2] == length as u64,
        "the bytes are the region, tightly packed",
    )?;
    Ok(CopyRows {
        first: offset
            + origin[2] * bytes_per_image
            + origin[1] / block_size[1] * bytes_per_row
            + origin[0] / block_size[0] * u64::from(block.bytes),
        bytes_per_row,
        bytes_per_image,
        row_bytes: row_bytes as usize,
        rows: rows as u32,
        images: size[2] as u32,
        next: 0,
    })
}

/// The row strides of texels in CPU memory: `bytesPerRow`, and
/// `bytesPerImage`, which only regions deeper than one image read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Strides {
    pub bytes_per_row: u64,
    pub bytes_per_image: u64,
}

/// `region` reading its texels from the CPU copy, whose rows span the whole
/// level.
fn cpu_copy_region(descriptor: &TextureDescriptor, region: BufferImageCopy) -> BufferImageCopy {
    let extent = descriptor.level_extent(region.subresource.mip_level.into());
    let block = descriptor.pixel_format.describe().block;
    BufferImageCopy {
        buffer_row_length: extent[0].next_multiple_of(block.width.into()) as u32,
        buffer_image_height: extent[1].next_multiple_of(block.height.into()) as u32,
        ..region
    }
}
