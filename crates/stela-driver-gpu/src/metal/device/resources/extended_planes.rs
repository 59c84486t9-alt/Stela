//! IOSurface textures of Apple's two-plane extended-range formats
//! (`RGB10A8_2P_XR10` and its sRGB variant).
//!
//! The surface's first plane holds each texel's blue, green and red codes in
//! a 32-bit word and its second plane 8-bit alpha, which WindowServer's
//! framebuffers and Core Animation's surfaces share with the display. The
//! texture is those planes: shaders sample and read them through linear
//! images, an `RGB10A2Unorm` view of the codes and an `R8Unorm` view of
//! alpha, which they decode ([`ResourceId::XR10`]). A pass renders the
//! texture as the half floats its format's other textures hold, in a
//! working image kept with it: the pass's start decodes the planes into it
//! when the attachment loads, and its end encodes it into the planes when it
//! stores ([`ExtendedPlanes`]), as an Apple GPU's tile memory holds the
//! outputs between its loads and stores. Shader writes, views, blits and the
//! CPU's copies of these textures are not implemented and are refused; the
//! CPU reaches the surface's planes itself.
use super::{Backing, Device, TestedCopyObject, TextureId, TextureObject};
use crate::metal::{
    abi::TextureUsage,
    binding::{HeapArray, NULL_DESCRIPTOR, ResourceId},
    capabilities::FormatCapabilities,
    command_buffer::BufferRef,
    error::{Error, Result, ensure},
    pass::{AttachmentView, ExtendedPlanes, TestedCopy},
    pixel_format::{Encoding, PixelFormat, Planes},
    resource::{self, CpuAccess, PlaneLayout, TextureDescriptor},
    shader::Compiler,
    vulkan::{
        ComponentSwizzle, ImageAspects, ImageCreate, ImageTiling, ImageType, ImageUsage,
        ImageViewType, MemoryProperties, SampleCounts,
        backend::{Backend, Descriptor, Object},
        object::{ImageInfo, ImageView, ImageViewInfo, MemoryRequest, SubresourceRange},
    },
};
use alloc::vec::Vec;

/// An IOSurface texture's planes and what its working image holds.
///
/// The working image is what passes render: a pass that loads decodes the
/// planes into it only when it may not hold what they do, and a pass that
/// stores encodes it into them, which the display, the CPU and shaders then
/// read. The planes change under the working image when the CPU writes the
/// surface, which changes its seed (`IOSurfaceGetSeed`, as the guest reports
/// it with each pass, [`AttachmentRequest::surface`]), or when another
/// texture over the same surface encodes into them, which counts in the
/// surface's generation. Without a report the planes are decoded every time.
///
/// [`AttachmentRequest::surface`]: crate::metal::device::queue::AttachmentRequest::surface
#[derive(Clone, Copy, Debug)]
pub(in crate::metal::device) struct PlaneState {
    planes: [PlaneLayout; 2],
    /// The surface's ID and the seed its last pass reported.
    surface: Option<(u32, u32)>,
    /// The surface's generation the working image holds, as the texture's
    /// last stored pass encoded it.
    synced: Option<u64>,
}

/// What a pass does with an extended-range attachment
/// ([`Device::extended_pass_planes`]).
#[derive(Clone, Copy, Debug)]
pub(in crate::metal::device) struct PlaneActions {
    /// It loads the attachment's texels.
    pub loads: bool,
    /// It stores them.
    pub stores: bool,
    /// Its store action was set before it began.
    pub settled: bool,
    /// The attachment's IOSurface ID and seed, as the guest reported them.
    pub surface: Option<(u32, u32)>,
}

/// Whether `format` is a two-plane extended-range format.
fn extended(format: PixelFormat) -> bool {
    matches!(format.describe().encoding(), Encoding::ExtendedRange(codes) if codes.planes)
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newTextureWithDescriptor:iosurface:plane:` of a two-plane
    /// extended-range format on the buffer over the surface: each plane's
    /// linear image, whose sampled descriptors are consecutive, the alpha
    /// plane's following the codes'. Usages beyond reading and rendering
    /// are reported.
    pub fn new_extended_plane_texture(
        &mut self,
        buffer_id: super::super::BufferId,
        descriptor: &TextureDescriptor,
        planes: [PlaneLayout; 2],
    ) -> Result<TextureId> {
        let formats = descriptor
            .pixel_format
            .extended_planes()
            .ok_or(Error::Invalid("the format has no extended-range planes"))?;
        if !descriptor.swizzle.is_identity() {
            return Err(Error::Unsupported(
                "swizzled two-plane extended-range textures",
            ));
        }
        ensure(
            descriptor.texture_type == crate::metal::abi::TextureType::D2
                && descriptor.mipmap_level_count == 1
                && descriptor.sample_count <= 1,
            "an IOSurface texture is one 2D level",
        )?;
        let unsupported = descriptor
            .usage
            .difference(TextureUsage::SHADER_READ | TextureUsage::RENDER_TARGET);
        if !descriptor.usage.is_empty() && !unsupported.is_empty() {
            self.unsupported(
                "two-plane extended-range textures' usages beyond reading and rendering",
            );
        }
        let readable = |format: PixelFormat| {
            self.capabilities
                .format(format)
                .contains(FormatCapabilities::READ | FormatCapabilities::LINEAR)
        };
        if !formats.iter().all(|&format| readable(format)) {
            return Err(Error::Unsupported(
                "two-plane extended-range textures on this device",
            ));
        }
        let buffer = self.resources.buffers.get(buffer_id.0)?;
        let (memory, memory_offset, length) = (buffer.memory, buffer.memory_offset, buffer.length);
        let plane = |pixel_format, layout: PlaneLayout| {
            let plane = TextureDescriptor {
                pixel_format,
                usage: TextureUsage::SHADER_READ,
                ..*descriptor
            };
            resource::linear_texture(
                &self.capabilities,
                &plane,
                length,
                layout.offset,
                layout.bytes_per_row,
            )
        };
        let plans = [plane(formats[0], planes[0])?, plane(formats[1], planes[1])?];
        let (_, linear) = self.capabilities.linear_texture_alignments();
        let mut images = Vec::with_capacity(2);
        let mut views = Vec::with_capacity(2);
        let created = (|| -> Result<ResourceId> {
            for (plan, layout) in plans.iter().zip(planes) {
                let place = memory_offset
                    .checked_add(layout.offset)
                    .filter(|place| place.is_multiple_of(linear))
                    .ok_or(Error::Invalid(
                        "the surface's plane is not aligned for a texture",
                    ))?;
                images.push(
                    self.backend
                        .create_placed_image(&plan.image, memory, place)?,
                );
                let image = images[images.len() - 1];
                let info = plan
                    .views
                    .sampled
                    .ok_or(Error::Invalid("a plane has no sampled view"))?;
                views.push(self.backend.create_image_view(image, &info)?);
            }
            let first = self.descriptors.allocate_run(HeapArray::SampledImages, 2)?;
            for (index, view) in (first..).zip(&views) {
                self.backend
                    .write_descriptor(index, Descriptor::SampledImage(*view));
            }
            let srgb = if descriptor.pixel_format.describe().srgb {
                ResourceId::XR10_SRGB
            } else {
                0
            };
            Ok(ResourceId::new(first, NULL_DESCRIPTOR)
                .with_planes(Planes::Full, ResourceId::XR10 | srgb)
                .with_filter_class(descriptor.pixel_format.filter_class()))
        })();
        let id = match created {
            Ok(id) => id,
            Err(error) => {
                for view in views {
                    self.backend.destroy(Object::ImageView(view));
                }
                for image in images {
                    self.backend.destroy(Object::Image(image));
                }
                return Err(error);
            }
        };
        let texture = TextureObject {
            image: Some(images[0]),
            descriptor: *descriptor,
            id,
            views,
            texel_views: Vec::new(),
            attachment_views: Vec::new(),
            attachment_storage: Vec::new(),
            tested_copies: Vec::new(),
            cpu_access: CpuAccess::Linear,
            backing: Backing::Buffer(buffer_id),
            memory: None,
            parent: None,
            dependents: 0,
            cpu_copy: None,
            second_plane: Some(images[1]),
        };
        self.resources.buffers.get_mut(buffer_id.0)?.dependents += 1;
        let id = TextureId(self.resources.textures.insert(texture));
        self.resources.extended_planes.insert(
            id.0,
            PlaneState {
                planes,
                surface: None,
                synced: None,
            },
        );
        Ok(id)
    }

    /// Forgets an IOSurface texture's planes, and its surface's generation
    /// once no texture lies in the surface.
    pub(super) fn forget_extended_planes(&mut self, id: TextureId) {
        let Some(state) = self.resources.extended_planes.remove(&id.0) else {
            return;
        };
        if let Some((surface, _)) = state.surface
            && !self
                .resources
                .extended_planes
                .values()
                .any(|other| other.surface.is_some_and(|(other, _)| other == surface))
        {
            self.resources.extended_generations.remove(&surface);
        }
    }

    /// Whether `id` is an IOSurface texture of extended-range planes.
    pub(super) fn has_extended_planes(&self, id: TextureId) -> bool {
        self.resources.extended_planes.contains_key(&id.0)
    }

    /// The working image an extended-range IOSurface texture renders in, of
    /// `view`'s level and layers: half floats, created on first use and
    /// kept with the texture, with a raw storage view the texel kernels
    /// and storage attachments access.
    pub(super) fn extended_working(
        &mut self,
        id: TextureId,
        view: AttachmentView<()>,
    ) -> Result<TestedCopy> {
        let texture = self.resources.textures.get(id.0)?;
        if let Some(object) = texture
            .tested_copies
            .iter()
            .find(|object| object.view == view && object.aspect == ImageAspects::COLOR)
        {
            return Ok(object.copy);
        }
        let planes = texture
            .image
            .ok_or(Error::Invalid("texture buffers are not attachments"))?;
        let descriptor = texture.descriptor;
        let format = resource::vulkan_format(descriptor.pixel_format)?;
        let raw = resource::raw_texel_format(descriptor.pixel_format)
            .ok_or(Error::Unsupported("rendering to this pixel format"))?;
        let extent = [descriptor.width as u32, descriptor.height as u32];
        let layers = view.range.layer_count;
        let info = ImageInfo {
            flags: ImageCreate::MUTABLE_FORMAT | ImageCreate::EXTENDED_USAGE,
            image_type: ImageType::D2,
            format,
            extent: [extent[0], extent[1], 1],
            mip_levels: 1,
            array_layers: layers,
            samples: SampleCounts::C1,
            tiling: ImageTiling::Optimal,
            usage: ImageUsage::STORAGE | ImageUsage::COLOR_ATTACHMENT,
            view_formats: alloc::vec![format, raw],
            linear: None,
        };
        let request = MemoryRequest {
            required: MemoryProperties::DEVICE_LOCAL,
            preferred: MemoryProperties::EMPTY,
            mapped: false,
        };
        let (image, memory, bytes) = self.backend.create_image(&info, request)?;
        self.allocated += bytes;
        let view_info = ImageViewInfo {
            view_type: ImageViewType::D2Array,
            format: raw,
            components: [ComponentSwizzle::Identity; 4],
            range: SubresourceRange {
                aspects: ImageAspects::COLOR,
                base_mip_level: 0,
                level_count: 1,
                base_array_layer: 0,
                layer_count: layers,
            },
            usage: ImageUsage::STORAGE,
            min_lod: 0.0,
        };
        let created = match self.backend.create_image_view(image, &view_info) {
            Ok(image_view) => match self.descriptor(Descriptor::StorageImage(image_view)) {
                Ok(descriptor) => Ok((image_view, descriptor)),
                Err(error) => {
                    self.backend.destroy(Object::ImageView(image_view));
                    Err(error)
                }
            },
            Err(error) => Err(error),
        };
        let (image_view, storage) = match created {
            Ok(created) => created,
            Err(error) => {
                self.backend.destroy(Object::Image(image));
                self.release_memory(memory, bytes);
                return Err(error);
            }
        };
        let copy = TestedCopy {
            id: ResourceId::texture(NULL_DESCRIPTOR, storage, 1),
            image,
            attachment: planes,
            aspect: ImageAspects::COLOR,
            level: 0,
            base_layer: view.range.base_array_layer,
            layers,
            extent,
            encoding: 0,
            planes: false,
        };
        self.resources
            .textures
            .get_mut(id.0)?
            .tested_copies
            .push(TestedCopyObject {
                view,
                aspect: ImageAspects::COLOR,
                copy,
                memory,
                bytes,
                image_view,
                descriptor: storage,
            });
        Ok(copy)
    }

    /// The attachment view of an extended-range IOSurface texture: its
    /// working image's, created on first use and kept with the texture.
    pub(super) fn extended_attachment_view(
        &mut self,
        id: TextureId,
        view: AttachmentView<()>,
    ) -> Result<ImageView> {
        let working = self.extended_working(id, view)?;
        let texture = self.resources.textures.get(id.0)?;
        let info = ImageViewInfo {
            view_type: view.view_type,
            format: resource::vulkan_format(texture.descriptor.pixel_format)?,
            components: [ComponentSwizzle::Identity; 4],
            range: SubresourceRange {
                base_mip_level: 0,
                base_array_layer: 0,
                ..view.range
            },
            usage: ImageUsage::COLOR_ATTACHMENT,
            min_lod: 0.0,
        };
        let created = self.backend.create_image_view(working.image, &info)?;
        self.resources
            .textures
            .get_mut(id.0)?
            .attachment_views
            .push((view, created));
        Ok(created)
    }

    /// What a pass converts of its color attachment `id`, attached as
    /// `view` over `extent`, when its format is a two-plane extended-range
    /// one: an IOSurface texture's planes, decoded into its working image
    /// where the pass begins if it `loads` and the image may not hold them
    /// ([`PlaneState`]), from `surface` as the guest reported it, and
    /// encoded where it ends if it `stores` ([`PlaneActions`]); another
    /// texture's half floats,
    /// which its end holds to the values its texels read. `None` for other
    /// formats.
    pub(in crate::metal::device) fn extended_pass_planes(
        &mut self,
        id: TextureId,
        view: AttachmentView<()>,
        extent: [u32; 2],
        actions: PlaneActions,
    ) -> Result<Option<ExtendedPlanes>> {
        let PlaneActions {
            loads,
            stores,
            settled,
            surface,
        } = actions;
        let texture = self.resources.textures.get(id.0)?;
        let format = texture.descriptor.pixel_format;
        if !extended(format) {
            return Ok(None);
        }
        if texture.descriptor.sample_count > 1 {
            return Err(Error::Unsupported(
                "multisampled two-plane extended-range attachments",
            ));
        }
        let encoding = format.describe().encoding().texel_kernel();
        let size = [texture.descriptor.width, texture.descriptor.height].map(|size| size as u32);
        let Some(&state) = self.resources.extended_planes.get(&id.0) else {
            return Ok(Some(ExtendedPlanes {
                storage: self.attachment_storage(id, view)?,
                encoding,
                extent,
                layers: view.range.layer_count,
                stores,
                ..ExtendedPlanes::default()
            }));
        };
        let Backing::Buffer(buffer) = texture.backing else {
            return Err(Error::Invalid("an IOSurface texture lies in its buffer"));
        };
        let BufferRef { address, .. } = self.buffer(buffer)?;
        let narrow = |value: u64| {
            u32::try_from(value).map_err(|_| Error::Invalid("a plane's rows exceed 4 GiB"))
        };
        let working = self.extended_working(id, view)?;
        let planes = state.planes;
        // The working image holds the planes when nothing wrote them since
        // this texture's last stored pass: neither the CPU (the seed is the
        // same) nor another texture (the generation is).
        let generations = &mut self.resources.extended_generations;
        let generation = surface.map(|(surface, _)| *generations.entry(surface).or_default());
        let current = surface.is_some()
            && state.surface == surface
            && state.synced.is_some()
            && state.synced == generation
            && view.range.base_array_layer == 0;
        // A pass that stores writes the planes under every other texture's
        // image: of its surface, or of any surface when the guest did not
        // name it. Its own image then holds what it encodes, all of the
        // planes where it held them before, or decodes or clears them all.
        let synced = match surface {
            Some((surface, _)) if stores => {
                let generation = generations.entry(surface).or_default();
                *generation += 1;
                (settled && (current || extent == size)).then_some(*generation)
            }
            None if stores => {
                for generation in generations.values_mut() {
                    *generation += 1;
                }
                None
            }
            _ => None,
        };
        self.resources.extended_planes.insert(
            id.0,
            PlaneState {
                surface,
                synced,
                ..state
            },
        );
        Ok(Some(ExtendedPlanes {
            storage: working.id,
            encoding,
            extent,
            layers: 1,
            color: address + planes[0].offset,
            color_bytes_per_row: narrow(planes[0].bytes_per_row)?,
            alpha: address + planes[1].offset,
            alpha_bytes_per_row: narrow(planes[1].bytes_per_row)?,
            loads: loads && !current,
            stores,
            // What it does not draw keeps the planes' codes, whether its
            // image held them or it decodes them.
            narrows: loads,
            // A surface followed decodes all of it, after which its image
            // holds the planes.
            decodes_whole: surface.is_some(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::{
        abi::{
            CpuCacheMode, HazardTrackingMode, LoadAction, MultisampleDepthResolveFilter,
            MultisampleStencilResolveFilter, ResourceOptions, StorageMode, StoreAction,
            StoreActionOptions, SwizzleChannels, TextureType, VisibilityResultType,
        },
        device::{
            fixture::device,
            queue::{AttachmentRequest, RenderPassRequest},
        },
        pipeline::MAX_COLOR_ATTACHMENTS,
        vulkan::command::Command,
    };

    /// A 1280 x 800 `&b38` surface's planes as the guest sends them: color
    /// words 5120 bytes a row at 0, alpha bytes 1280 a row at 4,161,536.
    const PLANES: [PlaneLayout; 2] = [
        PlaneLayout {
            offset: 0,
            bytes_per_row: 5120,
        },
        PlaneLayout {
            offset: 4_161_536,
            bytes_per_row: 1280,
        },
    ];

    fn options(storage_mode: StorageMode) -> ResourceOptions {
        ResourceOptions {
            cpu_cache_mode: CpuCacheMode::DefaultCache,
            storage_mode,
            hazard_tracking_mode: HazardTrackingMode::Default,
        }
    }

    fn surface_texture(pixel_format: PixelFormat) -> TextureDescriptor {
        TextureDescriptor {
            texture_type: TextureType::D2,
            pixel_format,
            width: 1280,
            height: 800,
            depth: 1,
            mipmap_level_count: 1,
            sample_count: 1,
            array_length: 1,
            options: options(StorageMode::Shared),
            usage: TextureUsage::SHADER_READ | TextureUsage::RENDER_TARGET,
            swizzle: SwizzleChannels::IDENTITY,
        }
    }

    fn pass(texture: TextureId, load_action: LoadAction) -> RenderPassRequest {
        reported(texture, load_action, None)
    }

    /// A pass on `texture` whose guest reported its `surface` and seed.
    fn reported(
        texture: TextureId,
        load_action: LoadAction,
        surface: Option<(u32, u32)>,
    ) -> RenderPassRequest {
        let mut colors = [None; MAX_COLOR_ATTACHMENTS];
        colors[0] = Some(AttachmentRequest {
            texture,
            level: 0,
            slice: 0,
            depth_plane: 0,
            resolve: None,
            load_action,
            store_action: StoreAction::Store,
            store_action_options: StoreActionOptions::EMPTY,
            clear: [2.0, 0.5, -1.0, 0.25],
            surface,
        });
        RenderPassRequest {
            color_attachments: colors,
            depth_attachment: None,
            depth_resolve_filter: MultisampleDepthResolveFilter::Sample0,
            stencil_attachment: None,
            stencil_resolve_filter: MultisampleStencilResolveFilter::Sample0,
            visibility_result_buffer: None,
            visibility_result_type: VisibilityResultType::Reset,
            render_target_array_length: 0,
            render_target_width: 0,
            render_target_height: 0,
            default_raster_sample_count: 0,
            tile_memory: Default::default(),
            sample_positions: Vec::new(),
            rasterization_rate_map: false,
            counter_samples: Vec::new(),
        }
    }

    /// An IOSurface's extended-range texture samples its two planes, which
    /// a pass that loads decodes into its working image first and a pass
    /// that stores encodes into after; another texture of the format holds
    /// its half floats, which a pass's end holds to the codes'.
    #[test]
    fn surface_textures_render_through_their_planes() {
        let mut device = device();
        let buffer = device
            .new_buffer(5_251_264, options(StorageMode::Shared))
            .unwrap();
        for (format, srgb) in [
            (PixelFormat::Rgb10A8_2pXr10, 0),
            (PixelFormat::Rgb10A8_2pXr10Srgb, ResourceId::XR10_SRGB),
        ] {
            let texture = device
                .new_extended_plane_texture(buffer, &surface_texture(format), PLANES)
                .unwrap();
            let id = device.texture_resource_id(texture).unwrap();
            assert_eq!(
                id.high() >> ResourceId::PLANES_SHIFT & 7,
                Planes::Full as u32
            );
            assert_eq!(
                id.high() & (ResourceId::XR10 | ResourceId::XR10_SRGB),
                ResourceId::XR10 | srgb
            );
            for (load, kernels) in [(LoadAction::Load, 2), (LoadAction::Clear, 1)] {
                let mut commands = device.new_command_buffer();
                device
                    .begin_render(&mut commands, &pass(texture, load))
                    .unwrap();
                commands.end_encoding(&mut device.resolver()).unwrap();
                device.commit(commands).unwrap();
                let segment = &device.backend().submissions.last().unwrap()[0];
                let order: Vec<_> = segment
                    .commands
                    .iter()
                    .filter_map(|command| match command {
                        Command::StoreTexels { count, .. } => Some(("decode", *count)),
                        Command::BeginRendering(_) => Some(("begin", 0)),
                        Command::EndRendering => Some(("end", 0)),
                        Command::LoadTexels { count, .. } => Some(("encode", *count)),
                        _ => None,
                    })
                    .collect();
                let texels = 1280 * 800;
                // A loading pass converts only what it drew: here nothing,
                // so its decode is empty and it encodes nothing.
                let expected: &[_] = if kernels == 2 {
                    &[("decode", 0), ("begin", 0), ("end", 0)]
                } else {
                    &[("begin", 0), ("end", 0), ("encode", texels)]
                };
                assert_eq!(order, expected, "{format:?} {load:?}");
            }
            // Blits, views and the CPU's copies are refused.
            assert!(device.texture_image(texture).is_err());
            device.destroy_texture(texture).unwrap();
        }
        // A texture of its own holds half floats: a pass's end holds them.
        let mut own = surface_texture(PixelFormat::Rgb10A8_2pXr10);
        own.options = options(StorageMode::Private);
        let texture = device.new_texture(&own).unwrap();
        let mut commands = device.new_command_buffer();
        device
            .begin_render(&mut commands, &pass(texture, LoadAction::Load))
            .unwrap();
        commands.end_encoding(&mut device.resolver()).unwrap();
        device.commit(commands).unwrap();
        let segment = &device.backend().submissions.last().unwrap()[0];
        let kernels: Vec<_> = segment
            .commands
            .iter()
            .filter_map(|command| match command {
                Command::StoreTexels { .. } => Some(false),
                Command::LoadTexels { .. } => Some(true),
                _ => None,
            })
            .collect();
        assert_eq!(kernels, [true]);
    }

    /// The conversions an empty pass of `request` runs, in order: a decode
    /// of all the planes, or an encode of all of them.
    fn conversions(
        device: &mut crate::metal::device::fixture::TestDevice,
        request: &RenderPassRequest,
    ) -> Vec<&'static str> {
        let mut commands = device.new_command_buffer();
        device.begin_render(&mut commands, request).unwrap();
        commands.end_encoding(&mut device.resolver()).unwrap();
        device.commit(commands).unwrap();
        let segment = &device.backend().submissions.last().unwrap()[0];
        segment
            .commands
            .iter()
            .filter_map(|command| match command {
                Command::StoreTexels { count, .. } => Some(if *count == 1280 * 800 {
                    "decode"
                } else {
                    "part"
                }),
                Command::LoadTexels { count, .. } => Some(if *count == 1280 * 800 {
                    "encode"
                } else {
                    "part"
                }),
                _ => None,
            })
            .collect()
    }

    /// The working image is what passes render: a pass that loads decodes
    /// the planes only when they changed under it, as the CPU's writes
    /// change the surface's seed and another texture's stored passes its
    /// generation; a pass that stores encodes what it drew. Unreported
    /// surfaces decode every time.
    #[test]
    fn passes_decode_only_planes_that_changed_under_their_image() {
        let mut device = device();
        let buffer = device
            .new_buffer(5_251_264, options(StorageMode::Shared))
            .unwrap();
        let format = PixelFormat::Rgb10A8_2pXr10;
        let first = device
            .new_extended_plane_texture(buffer, &surface_texture(format), PLANES)
            .unwrap();
        let load = |texture, seed| reported(texture, LoadAction::Load, Some((7, seed)));
        // Its first pass decodes all of the planes; the next, which draws
        // nothing, converts nothing.
        assert_eq!(conversions(&mut device, &load(first, 1)), ["decode"]);
        assert!(conversions(&mut device, &load(first, 1)).is_empty());
        // The CPU wrote the surface.
        assert_eq!(conversions(&mut device, &load(first, 2)), ["decode"]);
        assert!(conversions(&mut device, &load(first, 2)).is_empty());
        // A pass that clears all of it encodes all of it, which its image
        // then holds.
        let clear = reported(first, LoadAction::Clear, Some((7, 2)));
        assert_eq!(conversions(&mut device, &clear), ["encode"]);
        assert!(conversions(&mut device, &load(first, 2)).is_empty());
        // Another texture over the surface decodes it, and once it stores,
        // the first texture's image no longer holds the planes.
        let second = device
            .new_extended_plane_texture(buffer, &surface_texture(format), PLANES)
            .unwrap();
        assert_eq!(conversions(&mut device, &load(second, 2)), ["decode"]);
        assert!(conversions(&mut device, &load(second, 2)).is_empty());
        assert_eq!(conversions(&mut device, &load(first, 2)), ["decode"]);
        assert!(conversions(&mut device, &load(first, 2)).is_empty());
        // A pass that does not store leaves its image apart from the planes.
        let mut kept = load(first, 2);
        kept.color_attachments[0].as_mut().unwrap().store_action = StoreAction::DontCare;
        assert!(conversions(&mut device, &kept).is_empty());
        assert_eq!(conversions(&mut device, &load(first, 2)), ["decode"]);
        // Without a report, every loading pass decodes what it drew, and
        // writes the planes under every image.
        assert_eq!(
            conversions(&mut device, &pass(second, LoadAction::Load)),
            ["part"]
        );
        assert_eq!(conversions(&mut device, &load(first, 2)), ["decode"]);
        device.destroy_texture(second).unwrap();
        device.destroy_texture(first).unwrap();
        assert!(device.resources.extended_generations.is_empty());
    }

    #[test]
    fn only_the_two_plane_formats_have_extended_planes() {
        assert!(extended(PixelFormat::Rgb10A8_2pXr10));
        assert!(extended(PixelFormat::Rgb10A8_2pXr10Srgb));
        assert!(!extended(PixelFormat::Bgr10Xr));
        assert!(!extended(PixelFormat::Bgra8Unorm));
        assert_eq!(
            PixelFormat::Rgb10A8_2pXr10.extended_planes(),
            Some([PixelFormat::Rgb10A2Unorm, PixelFormat::R8Unorm])
        );
        assert_eq!(
            resource::vulkan_format(PixelFormat::Rgb10A8_2pXr10).unwrap(),
            crate::metal::vulkan::Format::R16G16B16A16Sfloat
        );
    }
}
