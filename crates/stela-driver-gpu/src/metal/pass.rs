//! `MTLRenderPassDescriptor` lowered to Vulkan dynamic rendering.
//!
//! Each attachment becomes a `VkRenderingAttachmentInfo` over a view of one
//! mip level and the pass's layers (depth planes of a 3D texture are viewed
//! as 2D array layers). Resolves use the attachment's resolve mode instead
//! of separate commands. A store action of `Unknown` stays open until the
//! encoder sets it, which [`RenderPassPlan::set_store_action`] patches before
//! the pass's commands are submitted.
use super::{
    abi::{
        LoadAction, MultisampleDepthResolveFilter, MultisampleStencilResolveFilter, StoreAction,
        StoreActionOptions, TextureType, TextureUsage,
    },
    capabilities::{Capabilities, FormatCapabilities as C},
    error::{Error, Result, ensure, require},
    pipeline::MAX_COLOR_ATTACHMENTS,
    pixel_format::{Kind, Numeric, PixelFormat},
    resource::{TextureDescriptor, vulkan_format},
    vulkan::{
        AttachmentLoadOp, AttachmentStoreOp, ImageAspects, ImageViewType, ResolveModes,
        object::SubresourceRange,
    },
};
use alloc::vec::Vec;

/// A texture as a pass sees it: the device's handle and its descriptor.
#[derive(Clone, Copy, Debug)]
pub struct AttachedTexture<'a, T> {
    pub texture: T,
    pub descriptor: &'a TextureDescriptor,
}

/// Where in a texture an attachment renders or resolves.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a, T> {
    pub texture: AttachedTexture<'a, T>,
    pub level: u64,
    pub slice: u64,
    pub depth_plane: u64,
}

/// `MTLRenderPassAttachmentDescriptor`, with its kind's clear value.
#[derive(Clone, Copy, Debug)]
pub struct AttachmentDescriptor<'a, T, Clear> {
    pub target: Target<'a, T>,
    pub resolve: Option<Target<'a, T>>,
    pub load_action: LoadAction,
    pub store_action: StoreAction,
    pub store_action_options: StoreActionOptions,
    pub clear: Clear,
}

pub type ColorAttachment<'a, T> = AttachmentDescriptor<'a, T, [f64; 4]>;
pub type DepthAttachment<'a, T> = AttachmentDescriptor<'a, T, f64>;
pub type StencilAttachment<'a, T> = AttachmentDescriptor<'a, T, u32>;

/// `MTLRenderPassDescriptor`.
#[derive(Clone, Debug)]
pub struct RenderPassDescriptor<'a, T> {
    pub color_attachments: [Option<ColorAttachment<'a, T>>; MAX_COLOR_ATTACHMENTS],
    pub depth_attachment: Option<DepthAttachment<'a, T>>,
    pub depth_resolve_filter: MultisampleDepthResolveFilter,
    pub stencil_attachment: Option<StencilAttachment<'a, T>>,
    pub stencil_resolve_filter: MultisampleStencilResolveFilter,
    /// The pass writes visibility results into a buffer.
    pub visibility_results: bool,
    pub render_target_array_length: u64,
    pub render_target_width: u64,
    pub render_target_height: u64,
    pub default_raster_sample_count: u64,
    /// Tile memory: imageblock sample length, threadgroup memory length and
    /// tile size. Any nonzero value needs an Apple GPU.
    pub tile_memory: bool,
    /// `samplePositions`, in [0, 1) from the pixel's top left.
    pub sample_positions: Vec<[f32; 2]>,
    pub rasterization_rate_map: bool,
}

/// `VkClearValue`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClearValue {
    Float([f32; 4]),
    Sint([i32; 4]),
    Uint([u32; 4]),
    DepthStencil { depth: f32, stencil: u32 },
}

/// A view of one level and the pass's layers of a texture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentView<T> {
    pub texture: T,
    pub view_type: ImageViewType,
    pub range: SubresourceRange,
}

/// `VkRenderingAttachmentInfo` in the general layout.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RenderingAttachment<T> {
    pub view: AttachmentView<T>,
    pub resolve: Option<(ResolveModes, AttachmentView<T>)>,
    pub load_op: AttachmentLoadOp,
    pub store_op: AttachmentStoreOp,
    pub clear: ClearValue,
    /// Metal's store action, kept to apply a deferred `Unknown` action.
    pub store_action: StoreAction,
}

/// `VkRenderingInfo` and what the encoder checks against it.
#[derive(Clone, Debug, PartialEq)]
pub struct RenderPassPlan<T> {
    pub extent: [u32; 2],
    pub layer_count: u32,
    pub color: Vec<Option<RenderingAttachment<T>>>,
    pub depth: Option<RenderingAttachment<T>>,
    pub stencil: Option<RenderingAttachment<T>>,
    pub sample_count: u32,
    pub color_formats: [Option<PixelFormat>; MAX_COLOR_ATTACHMENTS],
    pub depth_format: Option<PixelFormat>,
    pub stencil_format: Option<PixelFormat>,
    pub visibility_results: bool,
    /// Custom sample positions in Vulkan's [0, 1) pixel space.
    pub sample_locations: Vec<[f32; 2]>,
}

/// An attachment of a pass, named for deferred store actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentSlot {
    Color(usize),
    Depth,
    Stencil,
}

impl<T: Copy> RenderPassPlan<T> {
    fn attachment(&mut self, slot: AttachmentSlot) -> Option<&mut RenderingAttachment<T>> {
        match slot {
            AttachmentSlot::Color(index) => self.color.get_mut(index).and_then(Option::as_mut),
            AttachmentSlot::Depth => self.depth.as_mut(),
            AttachmentSlot::Stencil => self.stencil.as_mut(),
        }
    }

    /// `set{Color,Depth,Stencil}StoreAction:`, valid only for attachments
    /// whose store action was `Unknown`.
    pub fn set_store_action(&mut self, slot: AttachmentSlot, action: StoreAction) -> Result<()> {
        ensure(
            action != StoreAction::Unknown,
            "the deferred store action must be known",
        )?;
        let attachment = self
            .attachment(slot)
            .ok_or(Error::Invalid("no attachment at that slot"))?;
        ensure(
            attachment.store_action == StoreAction::Unknown,
            "only an Unknown store action may be set later",
        )?;
        ensure(
            !action.resolves() || attachment.resolve.is_some(),
            "a resolving store action needs a resolve texture",
        )?;
        attachment.store_action = action;
        attachment.store_op = store_op(action);
        if !action.resolves() {
            attachment.resolve = None;
        }
        Ok(())
    }

    /// `set{Color,Depth,Stencil}StoreActionOptions:`. Vulkan stores the
    /// samples a pass's custom positions produced as it stores any, so the
    /// options only need those positions.
    pub fn set_store_action_options(
        &mut self,
        slot: AttachmentSlot,
        options: StoreActionOptions,
    ) -> Result<()> {
        ensure(
            self.attachment(slot).is_some(),
            "no attachment at that slot",
        )?;
        ensure(
            !options.contains(StoreActionOptions::CUSTOM_SAMPLE_POSITIONS)
                || !self.sample_locations.is_empty(),
            "custom sample position stores need sample positions",
        )
    }

    /// Fails while any store action is still `Unknown`; Metal requires
    /// them set before `endEncoding`.
    pub fn finish(&self) -> Result<()> {
        let attachments = self
            .color
            .iter()
            .flatten()
            .chain(&self.depth)
            .chain(&self.stencil);
        let mut store_actions = attachments.map(|attachment| attachment.store_action);
        ensure(
            store_actions.all(|action| action != StoreAction::Unknown),
            "a store action was never set",
        )
    }
}

pub fn render_pass<T: Copy + Eq>(
    capabilities: &Capabilities,
    descriptor: &RenderPassDescriptor<T>,
) -> Result<RenderPassPlan<T>> {
    require(!descriptor.tile_memory, "tile memory")?;
    require(
        !descriptor.rasterization_rate_map,
        "rasterization rate maps",
    )?;
    let layer_count = descriptor.render_target_array_length.max(1);
    require(
        layer_count <= capabilities.limits.max_texture_array_length,
        "render target array length",
    )?;

    let mut pass = Builder {
        capabilities,
        layer_count,
        extent: None,
        sample_count: None,
    };
    let mut color = Vec::new();
    let mut color_formats = [None; MAX_COLOR_ATTACHMENTS];
    for (index, attachment) in descriptor.color_attachments.iter().enumerate() {
        let Some(attachment) = attachment else {
            color.push(None);
            continue;
        };
        let format = attachment.target.texture.descriptor.pixel_format;
        let Kind::Color(numeric) = format.describe().kind else {
            return Err(Error::Invalid("color attachments need color textures"));
        };
        let mode = if numeric.is_integer() {
            ResolveModes::SAMPLE_ZERO
        } else {
            ResolveModes::AVERAGE
        };
        color_formats[index] = Some(format);
        color.push(Some(pass.attachment(
            attachment,
            ImageAspects::COLOR,
            mode,
            clear_color(numeric, attachment.clear),
        )?));
    }

    let depth_format = descriptor
        .depth_attachment
        .map(|depth| depth.target.texture.descriptor.pixel_format);
    let stencil_format = descriptor
        .stencil_attachment
        .map(|stencil| stencil.target.texture.descriptor.pixel_format);
    let depth_mode = match descriptor.depth_resolve_filter {
        MultisampleDepthResolveFilter::Sample0 => ResolveModes::SAMPLE_ZERO,
        MultisampleDepthResolveFilter::Min => ResolveModes::MIN,
        MultisampleDepthResolveFilter::Max => ResolveModes::MAX,
    };
    let depth = match &descriptor.depth_attachment {
        Some(attachment) => {
            ensure(
                depth_format.is_some_and(|format| format.describe().has_depth()),
                "the depth attachment has no depth",
            )?;
            if attachment.resolve.is_some() {
                require(
                    capabilities.depth_resolve_modes.contains(depth_mode),
                    "depth resolve filter",
                )?;
            }
            let clear = ClearValue::DepthStencil {
                depth: attachment.clear as f32,
                stencil: 0,
            };
            ensure(
                (0.0..=1.0).contains(&attachment.clear),
                "clear depth is within [0, 1]",
            )?;
            Some(pass.attachment(attachment, ImageAspects::DEPTH, depth_mode, clear)?)
        }
        None => None,
    };
    let stencil = match &descriptor.stencil_attachment {
        Some(attachment) => {
            ensure(
                stencil_format.is_some_and(|format| format.describe().has_stencil()),
                "the stencil attachment has no stencil",
            )?;
            let mode = match descriptor.stencil_resolve_filter {
                MultisampleStencilResolveFilter::Sample0 => ResolveModes::SAMPLE_ZERO,
                // Following depth is sample 0 only when depth resolves sample 0.
                MultisampleStencilResolveFilter::DepthResolvedSample
                    if depth_mode == ResolveModes::SAMPLE_ZERO =>
                {
                    ResolveModes::SAMPLE_ZERO
                }
                MultisampleStencilResolveFilter::DepthResolvedSample => {
                    return Err(Error::Unsupported(
                        "stencil resolve following a min or max depth resolve",
                    ));
                }
            };
            let clear = ClearValue::DepthStencil {
                depth: 0.0,
                stencil: attachment.clear,
            };
            Some(pass.attachment(attachment, ImageAspects::STENCIL, mode, clear)?)
        }
        None => None,
    };
    if let (Some(depth), Some(stencil)) =
        (&descriptor.depth_attachment, &descriptor.stencil_attachment)
    {
        let same = depth.target.texture.texture == stencil.target.texture.texture;
        let combined = |format: Option<PixelFormat>| {
            format.is_some_and(|format| format.describe().kind == Kind::DepthStencil)
        };
        ensure(
            same || !(combined(depth_format) || combined(stencil_format)),
            "depth and stencil attachments of combined formats are one texture",
        )?;
        ensure(
            !same
                || (depth.target.level == stencil.target.level
                    && depth.target.slice == stencil.target.slice),
            "depth and stencil of one texture attach the same level and slice",
        )?;
    }

    let (extent, sample_count) = match (pass.extent, pass.sample_count) {
        (Some(extent), Some(samples)) => (extent, samples),
        _ => {
            ensure(
                descriptor.render_target_width > 0 && descriptor.render_target_height > 0,
                "passes without attachments set renderTargetWidth and renderTargetHeight",
            )?;
            let samples = descriptor.default_raster_sample_count.max(1);
            require(
                capabilities.supports_texture_sample_count(samples),
                "default raster sample count",
            )?;
            let maximum = capabilities.limits.max_texture_dimension_2d;
            require(
                descriptor.render_target_width <= maximum
                    && descriptor.render_target_height <= maximum,
                "render target size",
            )?;
            (
                [
                    descriptor.render_target_width as u32,
                    descriptor.render_target_height as u32,
                ],
                samples as u32,
            )
        }
    };

    let sample_locations =
        sample_locations(capabilities, &descriptor.sample_positions, sample_count)?;
    let custom_stores = descriptor
        .color_attachments
        .iter()
        .flatten()
        .map(|attachment| attachment.store_action_options)
        .chain(
            descriptor
                .depth_attachment
                .map(|depth| depth.store_action_options),
        )
        .chain(
            descriptor
                .stencil_attachment
                .map(|stencil| stencil.store_action_options),
        )
        .any(|options| options.contains(StoreActionOptions::CUSTOM_SAMPLE_POSITIONS));
    ensure(
        !custom_stores || !sample_locations.is_empty(),
        "custom sample position stores need sample positions",
    )?;

    Ok(RenderPassPlan {
        extent,
        layer_count: layer_count as u32,
        color,
        depth,
        stencil,
        sample_count,
        color_formats,
        depth_format,
        stencil_format,
        visibility_results: descriptor.visibility_results,
        sample_locations,
    })
}

struct Builder<'a> {
    capabilities: &'a Capabilities,
    layer_count: u64,
    extent: Option<[u32; 2]>,
    sample_count: Option<u32>,
}

impl Builder<'_> {
    fn attachment<T: Copy, Clear>(
        &mut self,
        attachment: &AttachmentDescriptor<T, Clear>,
        aspect: ImageAspects,
        mode: ResolveModes,
        clear: ClearValue,
    ) -> Result<RenderingAttachment<T>> {
        let (view, extent) = self.view(&attachment.target, aspect)?;
        let source = attachment.target.texture.descriptor;
        let samples = source.sample_count as u32;
        let format = self.capabilities.format(source.pixel_format);
        require(
            format.intersects(C::COLOR | C::DEPTH_STENCIL),
            "rendering to this pixel format",
        )?;
        if samples > 1 {
            require(
                format.contains(C::MSAA),
                "multisampled attachment pixel format",
            )?;
        }
        ensure(
            self.sample_count.is_none_or(|count| count == samples),
            "attachments share one sample count",
        )?;
        self.sample_count = Some(samples);
        // Vulkan's render area must lie within every attachment.
        self.extent = Some(match self.extent {
            Some([width, height]) => [width.min(extent[0]), height.min(extent[1])],
            None => extent,
        });

        let resolve = match (attachment.store_action.resolves(), &attachment.resolve) {
            (true, None) => {
                return Err(Error::Invalid(
                    "a resolving store action needs a resolve texture",
                ));
            }
            (_, Some(target)) => {
                ensure(samples > 1, "only multisampled attachments resolve")?;
                if aspect == ImageAspects::COLOR {
                    require(format.contains(C::RESOLVE), "resolving this pixel format")?;
                }
                let resolved = target.texture.descriptor;
                ensure(
                    resolved.sample_count == 1,
                    "resolve textures have one sample",
                )?;
                ensure(
                    resolved.pixel_format == source.pixel_format,
                    "resolve textures match the attachment format",
                )?;
                let (view, resolve_extent) = self.view(target, aspect)?;
                ensure(
                    resolve_extent == extent,
                    "resolve textures match the attachment size",
                )?;
                // An Unknown store action may still become a resolve.
                let keep = attachment.store_action.resolves()
                    || attachment.store_action == StoreAction::Unknown;
                keep.then_some((mode, view))
            }
            (false, None) => None,
        };
        Ok(RenderingAttachment {
            view,
            resolve,
            load_op: match attachment.load_action {
                LoadAction::DontCare => AttachmentLoadOp::DontCare,
                LoadAction::Load => AttachmentLoadOp::Load,
                LoadAction::Clear => AttachmentLoadOp::Clear,
            },
            store_op: store_op(attachment.store_action),
            clear,
            store_action: attachment.store_action,
        })
    }

    fn view<T: Copy>(
        &self,
        target: &Target<T>,
        aspect: ImageAspects,
    ) -> Result<(AttachmentView<T>, [u32; 2])> {
        let texture = target.texture.descriptor;
        ensure(
            texture.usage.is_empty() || texture.usage.contains(TextureUsage::RENDER_TARGET),
            "the texture is not a render target",
        )?;
        ensure(
            target.level < texture.mipmap_level_count,
            "attachment level beyond the texture's mipmaps",
        )?;
        vulkan_format(texture.pixel_format)?;
        let at_level = |size: u64| (size >> target.level).max(1);
        let layers = self.layer_count;
        let (base_layer, available) = match texture.texture_type {
            TextureType::D2 | TextureType::D2Multisample => (target.slice, 1),
            TextureType::D2Array | TextureType::D2MultisampleArray => {
                (target.slice, texture.array_length)
            }
            TextureType::Cube => (target.slice, 6),
            TextureType::CubeArray => (target.slice, texture.array_length * 6),
            TextureType::D3 => (target.depth_plane, at_level(texture.depth)),
            TextureType::D1 | TextureType::D1Array | TextureType::TextureBuffer => {
                return Err(Error::Invalid(
                    "1D textures and texture buffers are not attachments",
                ));
            }
        };
        ensure(
            texture.texture_type == TextureType::D3 || target.depth_plane == 0,
            "only 3D textures have depth planes",
        )?;
        ensure(
            texture.texture_type != TextureType::D3 || target.slice == 0,
            "3D textures have one slice",
        )?;
        ensure(
            base_layer
                .checked_add(layers)
                .is_some_and(|end| end <= available),
            "attachment layers exceed the texture",
        )?;
        let view = AttachmentView {
            texture: target.texture.texture,
            view_type: if layers > 1 {
                ImageViewType::D2Array
            } else {
                ImageViewType::D2
            },
            range: SubresourceRange {
                aspects: aspect,
                base_mip_level: target.level as u32,
                level_count: 1,
                base_array_layer: base_layer as u32,
                layer_count: layers as u32,
            },
        };
        let height = if matches!(
            texture.texture_type,
            TextureType::Cube | TextureType::CubeArray
        ) {
            texture.width
        } else {
            texture.height
        };
        Ok((
            view,
            [at_level(texture.width) as u32, at_level(height) as u32],
        ))
    }
}

pub const fn store_op(action: StoreAction) -> AttachmentStoreOp {
    if action.stores() || matches!(action, StoreAction::Unknown) {
        AttachmentStoreOp::Store
    } else {
        AttachmentStoreOp::DontCare
    }
}

/// Metal's double clear color in the attachment's numeric class.
fn clear_color(numeric: Numeric, clear: [f64; 4]) -> ClearValue {
    match numeric {
        Numeric::Uint => ClearValue::Uint(clear.map(|channel| channel as u32)),
        Numeric::Sint => ClearValue::Sint(clear.map(|channel| channel as i32)),
        Numeric::Unorm | Numeric::Snorm | Numeric::Float => {
            ClearValue::Float(clear.map(|channel| channel as f32))
        }
    }
}

/// Metal positions are in [0, 1) from the pixel's top left, as Vulkan's.
/// Sample locations need the programmable sample positions path and one
/// position per sample.
fn sample_locations(
    capabilities: &Capabilities,
    positions: &[[f32; 2]],
    samples: u32,
) -> Result<Vec<[f32; 2]>> {
    if positions.is_empty() {
        return Ok(Vec::new());
    }
    require(
        capabilities.programmable_sample_positions,
        "programmable sample positions",
    )?;
    ensure(
        positions.len() == samples as usize,
        "one sample position per sample",
    )?;
    ensure(
        positions
            .iter()
            .flatten()
            .all(|&coordinate| (0.0..1.0).contains(&coordinate)),
        "sample positions lie in [0, 1)",
    )?;
    // Vulkan snaps to the device's sub-pixel grid, which is Metal's 1/16.
    Ok(positions
        .iter()
        .map(|position| position.map(|coordinate| (coordinate * 16.0) as u32 as f32 / 16.0))
        .collect())
}

#[cfg(test)]
mod tests;
