//! Buffers, textures and texture views: Metal descriptors validated against
//! Metal's rules and the device, then lowered to Vulkan objects.
//!
//! Every texture uses one image layout for its whole life
//! (`VK_KHR_unified_image_layouts`), so lowering never schedules layout
//! transitions. Storage modes map to memory as a discrete Mac GPU realizes
//! them: shared and managed resources live in host-visible memory, private
//! resources in device-local memory, and memoryless storage is refused.
use super::{
    abi::{
        CpuCacheMode, ResourceOptions, StorageMode, SwizzleChannels, TextureSwizzle, TextureType,
        TextureUsage,
    },
    capabilities::{Capabilities, FormatCapabilities as C},
    error::{Result, ensure, require},
    pixel_format::{Description, Kind, PixelFormat, Realization},
    vulkan::{
        BufferCreate, BufferUsage, ComponentSwizzle, Format, ImageAspects, ImageCreate,
        ImageTiling, ImageType, ImageUsage, ImageViewType, MemoryProperties as M, SampleCounts,
        object::{
            BufferInfo, BufferViewInfo, ImageInfo, ImageViewInfo, LinearLayout, MemoryRequest,
            SubresourceRange,
        },
    },
};
use alloc::{vec, vec::Vec};
use core::ops::Range;

/// Buffers serve every Metal use: shaders address them through device
/// addresses, and vertex, index, indirect, texel and blit commands read them.
const BUFFER_USAGE: BufferUsage = BufferUsage::TRANSFER_SRC
    .union(BufferUsage::TRANSFER_DST)
    .union(BufferUsage::UNIFORM_TEXEL_BUFFER)
    .union(BufferUsage::STORAGE_TEXEL_BUFFER)
    .union(BufferUsage::STORAGE_BUFFER)
    .union(BufferUsage::INDEX_BUFFER)
    .union(BufferUsage::VERTEX_BUFFER)
    .union(BufferUsage::INDIRECT_BUFFER)
    .union(BufferUsage::SHADER_DEVICE_ADDRESS);

/// The memory realizing a storage mode and CPU cache mode.
///
/// Shared memory is host-coherent. Managed memory may be non-coherent: the
/// device flushes ranges on `didModifyRange:` and invalidates after
/// `synchronizeResource:` completes. Write-combined CPU access prefers
/// device-local memory behind the BAR, since the CPU only writes it.
pub fn memory(options: ResourceOptions) -> Result<MemoryRequest> {
    let preferred = match options.cpu_cache_mode {
        CpuCacheMode::DefaultCache => M::HOST_CACHED,
        CpuCacheMode::WriteCombined => M::DEVICE_LOCAL,
    };
    match options.storage_mode {
        StorageMode::Shared => Ok(MemoryRequest {
            required: M::HOST_VISIBLE | M::HOST_COHERENT,
            preferred,
            mapped: true,
        }),
        StorageMode::Managed => Ok(MemoryRequest {
            required: M::HOST_VISIBLE,
            preferred,
            mapped: true,
        }),
        StorageMode::Private => Ok(MemoryRequest {
            required: M::DEVICE_LOCAL,
            preferred: M::EMPTY,
            mapped: false,
        }),
        // Lazily allocated attachments are the only Vulkan equivalent, and
        // Mac GPUs outside the Apple families have none.
        StorageMode::Memoryless => Err(super::error::Error::Unsupported("memoryless storage")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferPlan {
    pub info: BufferInfo,
    pub memory: MemoryRequest,
}

pub fn buffer(
    capabilities: &Capabilities,
    length: u64,
    options: ResourceOptions,
) -> Result<BufferPlan> {
    ensure(length > 0, "buffer length must be nonzero")?;
    require(
        length <= capabilities.limits.max_buffer_length,
        "buffer length",
    )?;
    Ok(BufferPlan {
        info: BufferInfo {
            size: length,
            usage: BUFFER_USAGE,
            flags: BufferCreate::EMPTY,
        },
        memory: memory(options)?,
    })
}

/// `MTLTextureDescriptor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextureDescriptor {
    pub texture_type: TextureType,
    pub pixel_format: PixelFormat,
    pub width: u64,
    pub height: u64,
    pub depth: u64,
    pub mipmap_level_count: u64,
    pub sample_count: u64,
    pub array_length: u64,
    pub options: ResourceOptions,
    pub usage: TextureUsage,
    pub swizzle: SwizzleChannels,
}

/// Where one level and slice of a managed texture lives in its CPU copy.
/// Levels are packed in order, each level's slices in order, and rows hold
/// whole blocks without padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubresourceLayout {
    pub offset: u64,
    pub bytes_per_row: u64,
    pub bytes_per_image: u64,
    /// The level's extent in texels.
    pub extent: [u64; 3],
}

impl TextureDescriptor {
    /// Slices: array elements, with six faces per cube.
    pub fn slice_count(&self) -> u64 {
        match self.texture_type {
            TextureType::Cube | TextureType::CubeArray => self.array_length * 6,
            TextureType::D3 => 1,
            _ => self.array_length,
        }
    }

    /// Texels of `level` along each axis.
    pub fn level_extent(&self, level: u64) -> [u64; 3] {
        let height = match self.texture_type {
            TextureType::D1 | TextureType::D1Array | TextureType::TextureBuffer => 1,
            TextureType::Cube | TextureType::CubeArray => self.width,
            _ => self.height,
        };
        let depth = if self.texture_type == TextureType::D3 {
            self.depth
        } else {
            1
        };
        [self.width, height, depth].map(|size| (size >> level).max(1))
    }

    /// The CPU copy's layout of `level` and `slice`.
    pub fn subresource_layout(&self, level: u64, slice: u64) -> SubresourceLayout {
        let block = self.pixel_format.describe().block;
        let packed = |level| {
            let extent = self.level_extent(level);
            let bytes_per_row = extent[0].div_ceil(block.width.into()) * u64::from(block.bytes);
            let bytes_per_image = bytes_per_row * extent[1].div_ceil(block.height.into());
            (extent, bytes_per_row, bytes_per_image)
        };
        let earlier: u64 = (0..level)
            .map(|level| {
                let (extent, _, bytes_per_image) = packed(level);
                bytes_per_image * extent[2] * self.slice_count()
            })
            .sum();
        let (extent, bytes_per_row, bytes_per_image) = packed(level);
        SubresourceLayout {
            offset: earlier + slice * bytes_per_image * extent[2],
            bytes_per_row,
            bytes_per_image,
            extent,
        }
    }

    /// Bytes of the CPU copy of every level and slice.
    pub fn cpu_copy_bytes(&self) -> u64 {
        self.subresource_layout(self.mipmap_level_count, 0).offset
    }
}

/// How the CPU reaches a texture's contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuAccess {
    None,
    /// `vkCopyMemoryToImage` and `vkCopyImageToMemory`.
    HostImageCopy,
    /// Metal's CPU copy of a managed texture, in a host-visible buffer:
    /// CPU writes reach the image at the next commit, and
    /// `synchronizeTexture` copies the image back.
    Staged,
    /// The texture aliases a buffer's mapped rows.
    Linear,
}

/// The views shaders use. Vulkan storage views need identity swizzles, so a
/// swizzled texture that shaders also write has two.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShaderViews {
    pub sampled: Option<ImageViewInfo>,
    /// A sampled cube's faces as a 2D array, through which shaders read its
    /// texels: texel fetches take no cube.
    pub faces: Option<ImageViewInfo>,
    pub storage: Option<ImageViewInfo>,
}

/// The sampled descriptors of a view of `view_type`, consecutive in the
/// heap: a cube's is followed by its faces'.
pub const fn sampled_descriptors(view_type: ImageViewType) -> u32 {
    match view_type {
        ImageViewType::Cube | ImageViewType::CubeArray => 2,
        _ => 1,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TexturePlan {
    pub image: ImageInfo,
    pub memory: MemoryRequest,
    pub views: ShaderViews,
    pub cpu_access: CpuAccess,
}

pub fn texture(capabilities: &Capabilities, descriptor: &TextureDescriptor) -> Result<TexturePlan> {
    let description = descriptor.pixel_format.describe();
    ensure(
        !description.view_only,
        "stencil view formats only describe texture views",
    )?;
    ensure(
        descriptor.texture_type != TextureType::TextureBuffer,
        "texture buffers are created from buffers",
    )?;
    let realization = realization(description)?;
    check_shape(capabilities, descriptor, description)?;
    let usage = effective_usage(capabilities, descriptor)?;

    if descriptor.options.storage_mode == StorageMode::Managed {
        ensure(
            description.is_color() && descriptor.sample_count == 1,
            "depth, stencil and multisample textures use private storage",
        )?;
    }
    let cpu_access = match descriptor.options.storage_mode {
        StorageMode::Private => CpuAccess::None,
        StorageMode::Managed
            if capabilities
                .format(descriptor.pixel_format)
                .contains(C::HOST_TRANSFER) =>
        {
            CpuAccess::HostImageCopy
        }
        StorageMode::Managed => CpuAccess::Staged,
        StorageMode::Shared => {
            return Err(super::error::Error::Invalid(
                "shared textures need unified memory; use managed or private storage",
            ));
        }
        StorageMode::Memoryless => {
            return Err(super::error::Error::Unsupported("memoryless storage"));
        }
    };

    let mut image = image_info(descriptor, description, realization, usage);
    if cpu_access == CpuAccess::HostImageCopy {
        image.usage |= ImageUsage::HOST_TRANSFER;
    }
    // Passes with custom sample positions draw only to depth and stencil
    // attachments made for them.
    if capabilities.programmable_sample_positions
        && !description.is_color()
        && descriptor.sample_count > 1
        && usage.contains(TextureUsage::RENDER_TARGET)
    {
        image.flags |= ImageCreate::SAMPLE_LOCATIONS_COMPATIBLE_DEPTH;
    }
    let range = full_range(descriptor, description);
    let views = shader_views(
        view_type(descriptor.texture_type),
        realization,
        descriptor.swizzle,
        range,
        image.usage,
    );
    Ok(TexturePlan {
        image,
        memory: MemoryRequest {
            required: M::DEVICE_LOCAL,
            preferred: M::EMPTY,
            mapped: false,
        },
        views,
        cpu_access,
    })
}

fn realization(description: &Description) -> Result<Realization> {
    description
        .realization
        .map_err(|_| super::error::Error::Unsupported("pixel format"))
}

fn check_shape(
    capabilities: &Capabilities,
    descriptor: &TextureDescriptor,
    description: &Description,
) -> Result<()> {
    let limits = &capabilities.limits;
    let TextureDescriptor {
        texture_type,
        width,
        height,
        depth,
        array_length,
        sample_count,
        ..
    } = *descriptor;
    ensure(
        width >= 1 && height >= 1 && depth >= 1,
        "texture dimensions must be nonzero",
    )?;
    ensure(array_length >= 1, "array length must be nonzero")?;
    ensure(
        descriptor.mipmap_level_count >= 1,
        "mipmap level count must be nonzero",
    )?;
    let max_levels = 64 - width.max(height).max(depth).leading_zeros() as u64;
    ensure(
        descriptor.mipmap_level_count <= max_levels,
        "too many mipmap levels",
    )?;
    ensure(
        texture_type.is_array() || array_length == 1,
        "only array textures have slices",
    )?;
    ensure(
        array_length <= limits.max_texture_array_length,
        "array length exceeds the device limit",
    )?;

    let (max_width, max_height, max_depth) = match texture_type {
        TextureType::D1 | TextureType::D1Array => {
            ensure(
                height == 1 && depth == 1,
                "1D textures have unit height and depth",
            )?;
            (limits.max_texture_dimension_1d, 1, 1)
        }
        TextureType::D2
        | TextureType::D2Array
        | TextureType::D2Multisample
        | TextureType::D2MultisampleArray => {
            ensure(depth == 1, "2D textures have unit depth")?;
            let max = limits.max_texture_dimension_2d;
            (max, max, 1)
        }
        TextureType::Cube | TextureType::CubeArray => {
            ensure(
                width == height && depth == 1,
                "cube faces are square with unit depth",
            )?;
            let max = limits.max_texture_dimension_cube;
            ensure(
                array_length * 6 <= limits.max_texture_array_length,
                "cube array exceeds the layer limit",
            )?;
            (max, max, 1)
        }
        TextureType::D3 => {
            let max = limits.max_texture_dimension_3d;
            (max, max, max)
        }
        TextureType::TextureBuffer => unreachable!("refused before shape checks"),
    };
    require(
        width <= max_width && height <= max_height && depth <= max_depth,
        "texture dimensions",
    )?;

    if texture_type.is_multisample() {
        ensure(
            descriptor.mipmap_level_count == 1,
            "multisample textures have one level",
        )?;
        ensure(
            sample_count > 1,
            "multisample textures have more than one sample",
        )?;
        require(
            capabilities.supports_texture_sample_count(sample_count),
            "texture sample count",
        )?;
        require(
            capabilities
                .format(descriptor.pixel_format)
                .contains(C::MSAA),
            "multisampling for this pixel format",
        )?;
    } else {
        ensure(
            sample_count == 1,
            "only multisample textures have more than one sample",
        )?;
    }

    if !description.is_color() {
        ensure(
            !matches!(
                texture_type,
                TextureType::D1 | TextureType::D1Array | TextureType::D3
            ),
            "depth and stencil textures are 2D or cube",
        )?;
    }
    if description.is_compressed() {
        ensure(
            !texture_type.is_multisample()
                && !matches!(texture_type, TextureType::D1 | TextureType::D1Array),
            "compressed textures are 2D, cube or 3D",
        )?;
    }
    Ok(())
}

/// The usage a texture is created with. `Unknown` usage admits every use
/// the format supports.
fn effective_usage(
    capabilities: &Capabilities,
    descriptor: &TextureDescriptor,
) -> Result<TextureUsage> {
    let format = capabilities.format(descriptor.pixel_format);
    let render = C::COLOR | C::DEPTH_STENCIL;
    if descriptor.usage.is_empty() {
        let usage = TextureUsage::PIXEL_FORMAT_VIEW
            .with(TextureUsage::SHADER_READ, format.contains(C::READ))
            .with(TextureUsage::SHADER_WRITE, format.contains(C::WRITE))
            .with(TextureUsage::RENDER_TARGET, format.intersects(render))
            .with(TextureUsage::SHADER_ATOMIC, format.contains(C::ATOMIC));
        require(
            usage != TextureUsage::PIXEL_FORMAT_VIEW || format.contains(C::BLIT),
            "pixel format",
        )?;
        return Ok(usage);
    }
    let usage = descriptor.usage;
    if usage.contains(TextureUsage::SHADER_READ) {
        require(
            format.contains(C::READ),
            "shader reads of this pixel format",
        )?;
    }
    if usage.contains(TextureUsage::SHADER_WRITE) {
        require(
            format.contains(C::WRITE),
            "shader writes to this pixel format",
        )?;
    }
    if usage.contains(TextureUsage::RENDER_TARGET) {
        require(format.intersects(render), "rendering to this pixel format")?;
    }
    if usage.contains(TextureUsage::SHADER_ATOMIC) {
        require(
            format.contains(C::ATOMIC),
            "texture atomics on this pixel format",
        )?;
    }
    Ok(usage)
}

fn image_info(
    descriptor: &TextureDescriptor,
    description: &Description,
    realization: Realization,
    usage: TextureUsage,
) -> ImageInfo {
    let width = descriptor.width as u32;
    let height = descriptor.height as u32;
    let layers = descriptor.array_length as u32;
    let (image_type, extent, array_layers) = match descriptor.texture_type {
        TextureType::D1 | TextureType::D1Array => (ImageType::D1, [width, 1, 1], layers),
        TextureType::Cube | TextureType::CubeArray => {
            (ImageType::D2, [width, width, 1], layers * 6)
        }
        TextureType::D3 => (ImageType::D3, [width, height, descriptor.depth as u32], 1),
        _ => (ImageType::D2, [width, height, 1], layers),
    };

    let mut flags = ImageCreate::EMPTY;
    // Metal views 2D arrays of six or more square slices as cubes.
    if image_type == ImageType::D2
        && extent[0] == extent[1]
        && array_layers >= 6
        && !descriptor.texture_type.is_multisample()
    {
        flags |= ImageCreate::CUBE_COMPATIBLE;
    }
    // Render passes attach depth planes of 3D textures as 2D array layers.
    if image_type == ImageType::D3 && usage.contains(TextureUsage::RENDER_TARGET) {
        flags |= ImageCreate::ARRAY_2D_COMPATIBLE;
    }
    let view_formats = if usage.contains(TextureUsage::PIXEL_FORMAT_VIEW) {
        flags |= ImageCreate::MUTABLE_FORMAT | ImageCreate::EXTENDED_USAGE;
        Vec::new()
    } else if let Some(pair) = descriptor.pixel_format.srgb_pair()
        && let Ok(paired) = pair.describe().realization
    {
        flags |= ImageCreate::MUTABLE_FORMAT | ImageCreate::EXTENDED_USAGE;
        vec![realization.format, paired.format]
    } else {
        Vec::new()
    };

    let attachment = if description.is_color() {
        ImageUsage::COLOR_ATTACHMENT
    } else {
        ImageUsage::DEPTH_STENCIL_ATTACHMENT
    };
    let image_usage = (ImageUsage::TRANSFER_SRC | ImageUsage::TRANSFER_DST)
        .with(
            ImageUsage::SAMPLED,
            usage.contains(TextureUsage::SHADER_READ),
        )
        .with(
            ImageUsage::STORAGE,
            usage.intersects(TextureUsage::SHADER_WRITE | TextureUsage::SHADER_ATOMIC),
        )
        .with(attachment, usage.contains(TextureUsage::RENDER_TARGET));

    ImageInfo {
        flags,
        image_type,
        format: realization.format,
        extent,
        mip_levels: descriptor.mipmap_level_count as u32,
        array_layers,
        samples: SampleCounts::single(descriptor.sample_count as u32).unwrap_or(SampleCounts::C1),
        tiling: ImageTiling::Optimal,
        usage: image_usage,
        view_formats,
        linear: None,
    }
}

fn full_range(descriptor: &TextureDescriptor, description: &Description) -> SubresourceRange {
    let layers = descriptor.slice_count();
    SubresourceRange {
        aspects: shader_aspects(description),
        base_mip_level: 0,
        level_count: descriptor.mipmap_level_count as u32,
        base_array_layer: 0,
        layer_count: layers as u32,
    }
}

/// Shaders read depth from a depth-stencil texture and stencil from its
/// stencil views.
fn shader_aspects(description: &Description) -> ImageAspects {
    match description.kind {
        Kind::Color(_) => ImageAspects::COLOR,
        Kind::Depth | Kind::DepthStencil => ImageAspects::DEPTH,
        Kind::Stencil => ImageAspects::STENCIL,
    }
}

pub const fn view_type(texture_type: TextureType) -> ImageViewType {
    match texture_type {
        TextureType::D1 => ImageViewType::D1,
        TextureType::D1Array => ImageViewType::D1Array,
        TextureType::D2 | TextureType::D2Multisample | TextureType::TextureBuffer => {
            ImageViewType::D2
        }
        TextureType::D2Array | TextureType::D2MultisampleArray => ImageViewType::D2Array,
        TextureType::Cube => ImageViewType::Cube,
        TextureType::CubeArray => ImageViewType::CubeArray,
        TextureType::D3 => ImageViewType::D3,
    }
}

/// Composes Metal's channel swizzle over the format's realization swizzle:
/// each Metal channel names a component of the Metal format, which the
/// realization maps to a Vulkan source.
pub fn compose_swizzle(
    realization: [ComponentSwizzle; 4],
    swizzle: SwizzleChannels,
) -> [ComponentSwizzle; 4] {
    const SOURCES: [ComponentSwizzle; 4] = [
        ComponentSwizzle::R,
        ComponentSwizzle::G,
        ComponentSwizzle::B,
        ComponentSwizzle::A,
    ];
    let component = |index: usize| match realization[index] {
        ComponentSwizzle::Identity => SOURCES[index],
        source => source,
    };
    let composed = swizzle.0.map(|channel| match channel {
        TextureSwizzle::Zero => ComponentSwizzle::Zero,
        TextureSwizzle::One => ComponentSwizzle::One,
        TextureSwizzle::Red => component(0),
        TextureSwizzle::Green => component(1),
        TextureSwizzle::Blue => component(2),
        TextureSwizzle::Alpha => component(3),
    });
    let mut normalized = composed;
    for (index, value) in normalized.iter_mut().enumerate() {
        if *value == SOURCES[index] {
            *value = ComponentSwizzle::Identity;
        }
    }
    normalized
}

const IDENTITY: [ComponentSwizzle; 4] = [ComponentSwizzle::Identity; 4];

fn shader_views(
    view_type: ImageViewType,
    realization: Realization,
    swizzle: SwizzleChannels,
    range: SubresourceRange,
    image_usage: ImageUsage,
) -> ShaderViews {
    let components = compose_swizzle(realization.swizzle, swizzle);
    let view = |usage, components| ImageViewInfo {
        view_type,
        format: realization.format,
        components,
        range,
        usage,
    };
    let sampled = image_usage.contains(ImageUsage::SAMPLED);
    let storage = image_usage.contains(ImageUsage::STORAGE);
    let (sampled, storage) = if components == IDENTITY {
        let usage = image_usage & (ImageUsage::SAMPLED | ImageUsage::STORAGE);
        let shared = (!usage.is_empty()).then(|| view(usage, IDENTITY));
        (shared.filter(|_| sampled), shared.filter(|_| storage))
    } else {
        (
            sampled.then(|| view(ImageUsage::SAMPLED, components)),
            storage.then(|| view(ImageUsage::STORAGE, IDENTITY)),
        )
    };
    let faces = sampled
        .filter(|_| sampled_descriptors(view_type) == 2)
        .map(|_| ImageViewInfo {
            view_type: ImageViewType::D2Array,
            ..view(ImageUsage::SAMPLED, components)
        });
    ShaderViews {
        sampled,
        faces,
        storage,
    }
}

/// `newTextureViewWithPixelFormat:textureType:levels:slices:swizzle:`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextureViewDescriptor {
    pub pixel_format: PixelFormat,
    pub texture_type: TextureType,
    pub levels: Range<u64>,
    pub slices: Range<u64>,
    pub swizzle: SwizzleChannels,
}

pub fn texture_view(
    capabilities: &Capabilities,
    parent: &TextureDescriptor,
    view: &TextureViewDescriptor,
) -> Result<ShaderViews> {
    let parent_description = parent.pixel_format.describe();
    let description = view.pixel_format.describe();
    let realization = realization(description)?;
    ensure(
        view_format_compatible(parent, view.pixel_format),
        "view format is not compatible with the texture",
    )?;
    ensure(
        view_type_compatible(parent.texture_type, view.texture_type),
        "view type is not compatible with the texture",
    )?;

    let parent_layers = parent.slice_count();
    ensure(
        !view.levels.is_empty() && view.levels.end <= parent.mipmap_level_count,
        "view levels outside the texture",
    )?;
    ensure(
        !view.slices.is_empty() && view.slices.end <= parent_layers,
        "view slices outside the texture",
    )?;
    let slices = view.slices.end - view.slices.start;
    match view.texture_type {
        TextureType::Cube => ensure(slices == 6, "cube views have six slices")?,
        TextureType::CubeArray => ensure(
            slices.is_multiple_of(6),
            "cube array views have whole cubes",
        )?,
        TextureType::D1 | TextureType::D2 | TextureType::D2Multisample | TextureType::D3 => {
            ensure(slices == 1, "non-array views have one slice")?
        }
        _ => {}
    }
    if parent_description.is_color() {
        ensure(description.is_color(), "color textures have color views")?;
    }

    let mut usage = ImageUsage::EMPTY;
    let parent_format = capabilities.format(parent.pixel_format);
    let view_format = capabilities.format(view.pixel_format);
    if parent.usage.is_empty() || parent.usage.contains(TextureUsage::SHADER_READ) {
        usage = usage.with(
            ImageUsage::SAMPLED,
            view_format.contains(C::READ) && parent_format.contains(C::READ),
        );
    }
    if parent.usage.is_empty() || parent.usage.contains(TextureUsage::SHADER_WRITE) {
        usage = usage.with(
            ImageUsage::STORAGE,
            view_format.contains(C::WRITE) && parent_format.contains(C::WRITE),
        );
    }
    let range = SubresourceRange {
        aspects: shader_aspects(description),
        base_mip_level: view.levels.start as u32,
        level_count: slices_u32(view.levels.end - view.levels.start),
        base_array_layer: view.slices.start as u32,
        layer_count: slices_u32(slices),
    };
    Ok(shader_views(
        view_type(view.texture_type),
        realization,
        view.swizzle,
        range,
        usage,
    ))
}

fn slices_u32(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Metal views a texture with its own format, its sRGB pair, a stencil view
/// of its depth-stencil format, or with `PixelFormatView` usage any color
/// format of the same block size and footprint.
fn view_format_compatible(parent: &TextureDescriptor, format: PixelFormat) -> bool {
    use PixelFormat as P;
    if format == parent.pixel_format || parent.pixel_format.srgb_pair() == Some(format) {
        return true;
    }
    if matches!(
        (parent.pixel_format, format),
        (P::Depth32FloatStencil8, P::X32Stencil8) | (P::Depth24UnormStencil8, P::X24Stencil8)
    ) {
        return true;
    }
    let (a, b) = (parent.pixel_format.describe(), format.describe());
    parent.usage.contains(TextureUsage::PIXEL_FORMAT_VIEW)
        && a.is_color()
        && b.is_color()
        && a.block == b.block
        && a.is_compressed() == b.is_compressed()
}

fn view_type_compatible(parent: TextureType, view: TextureType) -> bool {
    use TextureType as T;
    match parent {
        T::D1 | T::D1Array => matches!(view, T::D1 | T::D1Array),
        T::D2 => matches!(view, T::D2 | T::D2Array),
        T::D2Array | T::Cube | T::CubeArray => {
            matches!(view, T::D2 | T::D2Array | T::Cube | T::CubeArray)
        }
        T::D2Multisample | T::D2MultisampleArray => {
            matches!(view, T::D2Multisample | T::D2MultisampleArray)
        }
        T::D3 => view == T::D3,
        T::TextureBuffer => view == T::TextureBuffer,
    }
}

/// `newTextureWithDescriptor:offset:bytesPerRow:` on a buffer: a 2D linear
/// texture over the buffer's memory, bound at `offset`.
pub fn linear_texture(
    capabilities: &Capabilities,
    descriptor: &TextureDescriptor,
    buffer_length: u64,
    offset: u64,
    bytes_per_row: u64,
) -> Result<TexturePlan> {
    let description = descriptor.pixel_format.describe();
    let realization = realization(description)?;
    if descriptor.texture_type == TextureType::D1 {
        // NVK stores linear images only as single-level 2D images, and a 2D
        // image has no 1D view.
        return Err(super::error::Error::Unsupported(
            "1D textures inside buffers",
        ));
    }
    ensure(
        descriptor.texture_type == TextureType::D2,
        "linear textures are 2D",
    )?;
    ensure(
        descriptor.mipmap_level_count == 1
            && descriptor.sample_count == 1
            && descriptor.array_length == 1,
        "linear textures have one level, sample and slice",
    )?;
    ensure(
        descriptor.depth == 1 && descriptor.width >= 1 && descriptor.height >= 1,
        "invalid linear extent",
    )?;
    require(
        capabilities
            .format(descriptor.pixel_format)
            .contains(C::LINEAR),
        "linear textures of this pixel format",
    )?;
    require(
        descriptor.width.max(descriptor.height) <= capabilities.limits.max_texture_dimension_2d,
        "texture dimensions",
    )?;
    let (row_alignment, offset_alignment) = capabilities.linear_texture_alignments();
    ensure(
        bytes_per_row.is_multiple_of(row_alignment),
        "bytesPerRow is not aligned",
    )?;
    ensure(
        offset.is_multiple_of(offset_alignment),
        "offset is not aligned",
    )?;
    ensure(
        bytes_per_row >= description.row_bytes(descriptor.width),
        "bytesPerRow is smaller than a row",
    )?;
    let rows = description.block.rows(descriptor.height);
    let end = (rows - 1)
        .checked_mul(bytes_per_row)
        .and_then(|bytes| bytes.checked_add(description.row_bytes(descriptor.width)))
        .and_then(|bytes| bytes.checked_add(offset));
    ensure(
        end.is_some_and(|end| end <= buffer_length),
        "texture extends past the buffer",
    )?;
    ensure(
        u32::try_from(bytes_per_row).is_ok(),
        "bytesPerRow exceeds the row pitch range",
    )?;

    let usage = effective_usage(capabilities, descriptor)?;
    let mut image = image_info(descriptor, description, realization, usage);
    image.tiling = ImageTiling::DrmFormatModifier;
    image.linear = Some(LinearLayout {
        row_pitch: bytes_per_row,
    });
    image.flags = image.flags.difference(ImageCreate::CUBE_COMPATIBLE);
    let range = full_range(descriptor, description);
    let views = shader_views(
        ImageViewType::D2,
        realization,
        descriptor.swizzle,
        range,
        image.usage,
    );
    Ok(TexturePlan {
        image,
        memory: memory(descriptor.options)?,
        views,
        cpu_access: if descriptor.options.storage_mode == StorageMode::Private {
            CpuAccess::None
        } else {
            CpuAccess::Linear
        },
    })
}

/// A texture buffer: a texel buffer view of `width` texels at `offset`.
pub fn texture_buffer(
    capabilities: &Capabilities,
    pixel_format: PixelFormat,
    width: u64,
    usage: TextureUsage,
    buffer_length: u64,
    offset: u64,
) -> Result<BufferViewInfo> {
    let description = pixel_format.describe();
    let realization = realization(description)?;
    let format = capabilities.format(pixel_format);
    let alignment = capabilities.minimum_texture_buffer_alignment(pixel_format);
    require(alignment != 0, "texture buffers of this pixel format")?;
    ensure(width >= 1, "texture buffer width must be nonzero")?;
    require(
        width <= capabilities.limits.max_texture_buffer_width,
        "texture buffer width",
    )?;
    ensure(
        offset.is_multiple_of(alignment),
        "texture buffer offset is not aligned",
    )?;
    let reads = usage.contains(TextureUsage::SHADER_READ);
    let writes = usage.contains(TextureUsage::SHADER_WRITE);
    require(
        !reads || format.contains(C::TEXTURE_BUFFER_READ),
        "texture buffer reads",
    )?;
    require(
        !writes || format.contains(C::TEXTURE_BUFFER_WRITE),
        "texture buffer writes",
    )?;
    require(
        !(reads && writes) || format.contains(C::TEXTURE_BUFFER_READ_WRITE),
        "read-write texture buffers",
    )?;
    let range = width * u64::from(description.block.bytes);
    ensure(
        offset
            .checked_add(range)
            .is_some_and(|end| end <= buffer_length),
        "texture buffer extends past the buffer",
    )?;
    Ok(BufferViewInfo {
        format: realization.format,
        offset,
        range,
    })
}

/// The Vulkan format a render or blit operation uses for `format`.
pub fn vulkan_format(format: PixelFormat) -> Result<Format> {
    realization(format.describe()).map(|realization| realization.format)
}

#[cfg(test)]
mod tests;
