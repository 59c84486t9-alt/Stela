//! The capability block: [`Capabilities`] as one fixed-width record that the
//! guest frontend reads once per device and answers every `MTLDevice` query
//! from, without crossing the boundary again.
//!
//! The record is `#[repr(C)]` with naturally aligned fields and no implicit
//! padding, little-endian on both sides of the boundary; [`Block::BYTES`]
//! fixes its size and [`VERSION`] its layout. Raw values are Metal's and
//! Vulkan's own: pixel and vertex formats, GPU families, device locations,
//! tiers, sample counts and resolve modes. Lists hold their count and leave
//! the rest of their array zero; strings are UTF-8 with their length.
//! Decoding accepts only a block the encoder writes, which it checks by
//! encoding the result again.
use super::{
    Capabilities, Cause, FormatCapabilities, Gap, IndexedPixelFormats, Limits, PixelFormats, Size,
    TexelBufferAlignment,
};
use crate::metal::{
    abi::{
        ArgumentBuffersTier, CounterSamplingPoint, DeviceLocation, GpuFamily, ReadWriteTextureTier,
    },
    error::{Error, Result, ensure},
    pixel_format::PixelFormat,
    vertex::VertexFormat,
    vulkan::{ResolveModes, SampleCounts},
};
use alloc::{boxed::Box, string::String, vec::Vec};

/// "STCB": a Stela capability block.
pub const MAGIC: [u8; 4] = *b"STCB";
pub const VERSION: u32 = 1;
pub const NAME_BYTES: usize = 256;
pub const ARCHITECTURE_BYTES: usize = 64;
pub const FAMILIES: usize = 32;
pub const FORMATS: usize = 256;
pub const GAPS: usize = 128;
pub const GAP_TEXT_BYTES: usize = 4096;

option_set! {
    /// The yes-or-no capabilities, each one of [`Capabilities`]' fields.
    pub struct Flags: u64 {
        const HEADLESS = 1 << 0;
        const LOW_POWER = 1 << 1;
        const REMOVABLE = 1 << 2;
        const UNIFIED_MEMORY = 1 << 3;
        const FLOAT32_FILTERING = 1 << 4;
        const FLOAT32_MSAA = 1 << 5;
        const BC_TEXTURE_COMPRESSION = 1 << 6;
        const DEPTH24_STENCIL8 = 1 << 7;
        const QUERY_TEXTURE_LOD = 1 << 8;
        const PULL_MODEL_INTERPOLATION = 1 << 9;
        const SHADER_BARYCENTRIC_COORDINATES = 1 << 10;
        const PROGRAMMABLE_SAMPLE_POSITIONS = 1 << 11;
        const RASTER_ORDER_GROUPS = 1 << 12;
        const RAYTRACING = 1 << 13;
        const RAYTRACING_FROM_RENDER = 1 << 14;
        const PRIMITIVE_MOTION_BLUR = 1 << 15;
        const FUNCTION_POINTERS = 1 << 16;
        const FUNCTION_POINTERS_FROM_RENDER = 1 << 17;
        const DYNAMIC_LIBRARIES = 1 << 18;
        const RENDER_DYNAMIC_LIBRARIES = 1 << 19;
        const PLACEMENT_SPARSE = 1 << 20;
        const MESH_SHADERS = 1 << 21;
        const TESSELLATION = 1 << 22;
        const SAMPLER_MIRROR_CLAMP_TO_EDGE = 1 << 23;
        const SAMPLER_REDUCTION_MODES = 1 << 24;
        const DUAL_SOURCE_BLENDING = 1 << 25;
        const ALPHA_TO_ONE = 1 << 26;
        const DEPTH_CLAMP = 1 << 27;
        const WIREFRAME = 1 << 28;
        const STATISTIC_COUNTERS = 1 << 29;
        const CONSTANT_VERTEX_STEP = 1 << 30;
        /// Sparse 3D textures.
        const SPARSE_VOLUMES = 1 << 31;
        /// Texel buffers of power-of-two texels align to one texel when that
        /// is less than their alignment.
        const SINGLE_TEXEL_ALIGNMENT = 1 << 32;
    }
}

/// [`Limits`], each a `u64` but the point size.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockLimits {
    pub max_threads_per_threadgroup: [u64; 3],
    pub max_total_threads_per_threadgroup: u64,
    pub thread_execution_width: u64,
    pub max_threadgroup_memory_length: u64,
    pub max_buffer_length: u64,
    pub max_texture_dimension_1d: u64,
    pub max_texture_dimension_2d: u64,
    pub max_texture_dimension_3d: u64,
    pub max_texture_dimension_cube: u64,
    pub max_texture_array_length: u64,
    pub max_texture_buffer_width: u64,
    pub max_color_attachments: u64,
    pub max_viewports: u64,
    pub max_vertex_amplification_count: u64,
    pub max_argument_buffer_sampler_count: u64,
    pub max_argument_buffer_resources: u64,
    pub max_vertex_buffer_stride: u64,
    pub max_vertex_attribute_offset: u64,
    pub max_vertex_step_rate: u64,
    pub max_tessellation_factor: u64,
    pub max_mesh_threads_per_threadgroup: u64,
    pub max_object_payload_length: u64,
    pub buffer_alignment_for_uniforms: u64,
    pub sparse_tile_bytes: u64,
    pub max_point_size: f32,
    pub reserved: u32,
}

/// A pixel format's raw `MTLPixelFormat` and its value: its
/// [`FormatCapabilities`] or its sparse textures' `VkSampleCountFlags`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FormatEntry {
    pub format: u32,
    pub value: u32,
}

/// A gap: its [`Cause`] and its capability's name, `bytes` long at `offset`
/// in the gap text.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GapEntry {
    pub cause: u32,
    pub offset: u32,
    pub bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Block {
    pub magic: [u8; 4],
    pub version: u32,
    /// [`Block::BYTES`].
    pub bytes: u32,
    pub name_bytes: u32,
    pub architecture_bytes: u32,
    pub family_count: u32,
    pub format_count: u32,
    pub sparse_format_count: u32,
    pub gap_count: u32,
    pub texture_sample_counts: u32,
    pub depth_resolve_modes: u32,
    pub stencil_resolve_modes: u32,
    /// Bit `n` is `MTLCounterSamplingPoint` `n`.
    pub counter_sampling: u32,
    pub max_sampler_anisotropy: f32,
    pub flags: u64,
    pub location: u64,
    pub location_number: u64,
    pub max_transfer_rate: u64,
    pub recommended_max_working_set_size: u64,
    pub argument_buffers_tier: u64,
    pub read_write_texture_tier: u64,
    pub timestamp_frequency: u64,
    /// Bit `n` is `MTLVertexFormat` `n`.
    pub vertex_formats: u64,
    pub linear_row_alignment: u64,
    pub linear_offset_alignment: u64,
    pub texel_buffer_alignment: u64,
    pub limits: BlockLimits,
    /// Raw `MTLGPUFamily` values.
    pub families: [u64; FAMILIES],
    pub formats: [FormatEntry; FORMATS],
    /// The sample counts of each format's sparse 2D textures.
    pub sparse_formats: [FormatEntry; FORMATS],
    pub gaps: [GapEntry; GAPS],
    pub name: [u8; NAME_BYTES],
    pub architecture: [u8; ARCHITECTURE_BYTES],
    pub gap_text: [u8; GAP_TEXT_BYTES],
}

const _: () = assert!(core::mem::size_of::<Block>() == Block::BYTES);

impl Block {
    pub const BYTES: usize = 10672;

    const EMPTY: Self = Self {
        magic: MAGIC,
        version: VERSION,
        bytes: Self::BYTES as u32,
        name_bytes: 0,
        architecture_bytes: 0,
        family_count: 0,
        format_count: 0,
        sparse_format_count: 0,
        gap_count: 0,
        texture_sample_counts: 0,
        depth_resolve_modes: 0,
        stencil_resolve_modes: 0,
        counter_sampling: 0,
        max_sampler_anisotropy: 0.0,
        flags: 0,
        location: 0,
        location_number: 0,
        max_transfer_rate: 0,
        recommended_max_working_set_size: 0,
        argument_buffers_tier: 0,
        read_write_texture_tier: 0,
        timestamp_frequency: 0,
        vertex_formats: 0,
        linear_row_alignment: 0,
        linear_offset_alignment: 0,
        texel_buffer_alignment: 0,
        limits: BlockLimits {
            max_threads_per_threadgroup: [0; 3],
            max_total_threads_per_threadgroup: 0,
            thread_execution_width: 0,
            max_threadgroup_memory_length: 0,
            max_buffer_length: 0,
            max_texture_dimension_1d: 0,
            max_texture_dimension_2d: 0,
            max_texture_dimension_3d: 0,
            max_texture_dimension_cube: 0,
            max_texture_array_length: 0,
            max_texture_buffer_width: 0,
            max_color_attachments: 0,
            max_viewports: 0,
            max_vertex_amplification_count: 0,
            max_argument_buffer_sampler_count: 0,
            max_argument_buffer_resources: 0,
            max_vertex_buffer_stride: 0,
            max_vertex_attribute_offset: 0,
            max_vertex_step_rate: 0,
            max_tessellation_factor: 0,
            max_mesh_threads_per_threadgroup: 0,
            max_object_payload_length: 0,
            buffer_alignment_for_uniforms: 0,
            sparse_tile_bytes: 0,
            max_point_size: 0.0,
            reserved: 0,
        },
        families: [0; FAMILIES],
        formats: [FormatEntry {
            format: 0,
            value: 0,
        }; FORMATS],
        sparse_formats: [FormatEntry {
            format: 0,
            value: 0,
        }; FORMATS],
        gaps: [GapEntry {
            cause: 0,
            offset: 0,
            bytes: 0,
        }; GAPS],
        name: [0; NAME_BYTES],
        architecture: [0; ARCHITECTURE_BYTES],
        gap_text: [0; GAP_TEXT_BYTES],
    };

    /// The capabilities the block carries; refuses a block the encoder
    /// would not write.
    pub fn capabilities(&self) -> Result<Capabilities> {
        ensure(
            self.magic == MAGIC && self.version == VERSION && self.bytes as usize == Self::BYTES,
            "capability block header",
        )?;
        let flags = Flags::from_bits(self.flags).ok_or(MALFORMED)?;
        let has = |flag| flags.contains(flag);
        let limits = &self.limits;
        let mut counter_sampling = [false; 5];
        for point in CounterSamplingPoint::ALL {
            counter_sampling[point.raw() as usize] = self.counter_sampling & 1 << point.raw() != 0;
        }
        let gaps = listed(&self.gaps, self.gap_count)?
            .iter()
            .map(|gap| {
                Ok(Gap {
                    capability: text(&self.gap_text, gap.offset, gap.bytes)?,
                    cause: Cause::from_raw(gap.cause).ok_or(MALFORMED)?,
                })
            })
            .collect::<Result<_>>()?;
        let capabilities = Capabilities {
            name: text(&self.name, 0, self.name_bytes)?,
            architecture: text(&self.architecture, 0, self.architecture_bytes)?,
            location: DeviceLocation::from_raw(self.location).ok_or(MALFORMED)?,
            location_number: self.location_number,
            max_transfer_rate: self.max_transfer_rate,
            headless: has(Flags::HEADLESS),
            low_power: has(Flags::LOW_POWER),
            removable: has(Flags::REMOVABLE),
            has_unified_memory: has(Flags::UNIFIED_MEMORY),
            recommended_max_working_set_size: self.recommended_max_working_set_size,
            limits: Limits {
                max_threads_per_threadgroup: Size {
                    width: limits.max_threads_per_threadgroup[0],
                    height: limits.max_threads_per_threadgroup[1],
                    depth: limits.max_threads_per_threadgroup[2],
                },
                max_total_threads_per_threadgroup: limits.max_total_threads_per_threadgroup,
                thread_execution_width: limits.thread_execution_width,
                max_threadgroup_memory_length: limits.max_threadgroup_memory_length,
                max_buffer_length: limits.max_buffer_length,
                max_texture_dimension_1d: limits.max_texture_dimension_1d,
                max_texture_dimension_2d: limits.max_texture_dimension_2d,
                max_texture_dimension_3d: limits.max_texture_dimension_3d,
                max_texture_dimension_cube: limits.max_texture_dimension_cube,
                max_texture_array_length: limits.max_texture_array_length,
                max_texture_buffer_width: limits.max_texture_buffer_width,
                max_color_attachments: limits.max_color_attachments,
                max_viewports: limits.max_viewports,
                max_vertex_amplification_count: limits.max_vertex_amplification_count,
                max_argument_buffer_sampler_count: limits.max_argument_buffer_sampler_count,
                max_argument_buffer_resources: limits.max_argument_buffer_resources,
                max_point_size: limits.max_point_size,
                max_vertex_buffer_stride: limits.max_vertex_buffer_stride,
                max_vertex_attribute_offset: limits.max_vertex_attribute_offset,
                max_vertex_step_rate: limits.max_vertex_step_rate,
                max_tessellation_factor: limits.max_tessellation_factor,
                max_mesh_threads_per_threadgroup: limits.max_mesh_threads_per_threadgroup,
                max_object_payload_length: limits.max_object_payload_length,
                buffer_alignment_for_uniforms: limits.buffer_alignment_for_uniforms,
                sparse_tile_bytes: limits.sparse_tile_bytes,
            },
            argument_buffers_tier: ArgumentBuffersTier::from_raw(self.argument_buffers_tier)
                .ok_or(MALFORMED)?,
            read_write_texture_tier: ReadWriteTextureTier::from_raw(self.read_write_texture_tier)
                .ok_or(MALFORMED)?,
            supports_32bit_float_filtering: has(Flags::FLOAT32_FILTERING),
            supports_32bit_msaa: has(Flags::FLOAT32_MSAA),
            supports_bc_texture_compression: has(Flags::BC_TEXTURE_COMPRESSION),
            depth24_stencil8_supported: has(Flags::DEPTH24_STENCIL8),
            supports_query_texture_lod: has(Flags::QUERY_TEXTURE_LOD),
            supports_pull_model_interpolation: has(Flags::PULL_MODEL_INTERPOLATION),
            supports_shader_barycentric_coordinates: has(Flags::SHADER_BARYCENTRIC_COORDINATES),
            programmable_sample_positions: has(Flags::PROGRAMMABLE_SAMPLE_POSITIONS),
            raster_order_groups: has(Flags::RASTER_ORDER_GROUPS),
            supports_raytracing: has(Flags::RAYTRACING),
            supports_raytracing_from_render: has(Flags::RAYTRACING_FROM_RENDER),
            supports_primitive_motion_blur: has(Flags::PRIMITIVE_MOTION_BLUR),
            supports_function_pointers: has(Flags::FUNCTION_POINTERS),
            supports_function_pointers_from_render: has(Flags::FUNCTION_POINTERS_FROM_RENDER),
            supports_dynamic_libraries: has(Flags::DYNAMIC_LIBRARIES),
            supports_render_dynamic_libraries: has(Flags::RENDER_DYNAMIC_LIBRARIES),
            supports_placement_sparse: has(Flags::PLACEMENT_SPARSE),
            supports_mesh_shaders: has(Flags::MESH_SHADERS),
            supports_tessellation: has(Flags::TESSELLATION),
            depth_resolve_modes: ResolveModes::from_bits(self.depth_resolve_modes)
                .ok_or(MALFORMED)?,
            stencil_resolve_modes: ResolveModes::from_bits(self.stencil_resolve_modes)
                .ok_or(MALFORMED)?,
            texture_sample_counts: SampleCounts::from_bits(self.texture_sample_counts)
                .ok_or(MALFORMED)?,
            max_sampler_anisotropy: self.max_sampler_anisotropy,
            sampler_mirror_clamp_to_edge: has(Flags::SAMPLER_MIRROR_CLAMP_TO_EDGE),
            sampler_reduction_modes: has(Flags::SAMPLER_REDUCTION_MODES),
            dual_source_blending: has(Flags::DUAL_SOURCE_BLENDING),
            alpha_to_one: has(Flags::ALPHA_TO_ONE),
            depth_clamp: has(Flags::DEPTH_CLAMP),
            wireframe: has(Flags::WIREFRAME),
            timestamp_frequency: self.timestamp_frequency,
            statistic_counters: has(Flags::STATISTIC_COUNTERS),
            constant_vertex_step: has(Flags::CONSTANT_VERTEX_STEP),
            counter_sampling,
            sparse_volumes: has(Flags::SPARSE_VOLUMES),
            sparse_samples: formats(
                listed(&self.sparse_formats, self.sparse_format_count)?,
                SampleCounts::from_bits,
            )?,
            vertex_formats: VertexFormat::ALL
                .iter()
                .copied()
                .filter(|format| self.vertex_formats & 1 << format.raw() != 0)
                .collect(),
            families: listed(&self.families, self.family_count)?
                .iter()
                .map(|&raw| GpuFamily::from_raw(raw).ok_or(MALFORMED))
                .collect::<Result<_>>()?,
            formats: pixel_formats(listed(&self.formats, self.format_count)?)?,
            gaps,
            linear_row_alignment: self.linear_row_alignment,
            linear_offset_alignment: self.linear_offset_alignment,
            texel_buffer_alignment: TexelBufferAlignment {
                bytes: self.texel_buffer_alignment,
                single_texel: has(Flags::SINGLE_TEXEL_ALIGNMENT),
            },
        };
        ensure(
            *capabilities.block()? == *self,
            "capability block is not canonical",
        )?;
        Ok(capabilities)
    }
}

/// A value the encoder never writes.
const MALFORMED: Error = Error::Invalid("capability block value");

/// The first `count` entries of a list.
fn listed<T>(entries: &[T], count: u32) -> Result<&[T]> {
    entries.get(..count as usize).ok_or(MALFORMED)
}

/// `bytes` of UTF-8 text at `offset`.
fn text(field: &[u8], offset: u32, bytes: u32) -> Result<String> {
    let start = offset as usize;
    let text = field
        .get(start..start.checked_add(bytes as usize).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    Ok(String::from(
        core::str::from_utf8(text).map_err(|_| MALFORMED)?,
    ))
}

/// Format entries in wire order, each value decoded.
fn formats<T>(
    entries: &[FormatEntry],
    decode: impl Fn(u32) -> Option<T>,
) -> Result<Vec<(PixelFormat, T)>> {
    entries
        .iter()
        .map(|entry| {
            Ok((
                PixelFormat::from_raw(u64::from(entry.format)).ok_or(MALFORMED)?,
                decode(entry.value).ok_or(MALFORMED)?,
            ))
        })
        .collect()
}

fn pixel_formats(entries: &[FormatEntry]) -> Result<PixelFormats> {
    if entries.len() == PixelFormat::ALL.len()
        && entries
            .iter()
            .zip(PixelFormat::ALL)
            .all(|(entry, format)| u64::from(entry.format) == format.raw())
    {
        let mut formats: Box<IndexedPixelFormats> =
            Box::new([FormatCapabilities::EMPTY; PixelFormat::ALL.len()]);
        for (capabilities, entry) in formats.iter_mut().zip(entries) {
            *capabilities = FormatCapabilities::from_bits(entry.value).ok_or(MALFORMED)?;
        }
        return Ok(PixelFormats::Indexed(formats));
    }
    let formats = formats(entries, FormatCapabilities::from_bits)?;
    Ok(PixelFormats::Listed(formats.into_boxed_slice()))
}

/// Copies `text` into the start of `field`, returning its length.
fn put_text(field: &mut [u8], text: &str, what: &'static str) -> Result<u32> {
    let bytes = text.as_bytes();
    field
        .get_mut(..bytes.len())
        .ok_or(Error::Invalid(what))?
        .copy_from_slice(bytes);
    Ok(bytes.len() as u32)
}

/// Fills the start of `field` with `items`, returning their count.
fn put_list<T, U>(
    field: &mut [U],
    items: impl ExactSizeIterator<Item = T>,
    what: &'static str,
    encode: impl Fn(T) -> Result<U>,
) -> Result<u32> {
    let count = items.len();
    let slots = field.get_mut(..count).ok_or(Error::Invalid(what))?;
    for (slot, item) in slots.iter_mut().zip(items) {
        *slot = encode(item)?;
    }
    Ok(count as u32)
}

/// A format entry of `format` and `value`.
fn format_entry(format: PixelFormat, value: u32) -> Result<FormatEntry> {
    Ok(FormatEntry {
        format: u32::try_from(format.raw()).map_err(|_| MALFORMED)?,
        value,
    })
}

fn put_pixel_formats(field: &mut [FormatEntry], formats: &PixelFormats) -> Result<u32> {
    let what = "pixel format count";
    let encode = |(format, capabilities): (PixelFormat, FormatCapabilities)| {
        format_entry(format, capabilities.bits())
    };
    match formats {
        PixelFormats::Indexed(formats) => put_list(
            field,
            PixelFormat::ALL
                .iter()
                .copied()
                .zip(formats.iter().copied()),
            what,
            encode,
        ),
        PixelFormats::Listed(formats) => put_list(field, formats.iter().copied(), what, encode),
    }
}

impl Capabilities {
    /// The block that carries these capabilities across the boundary.
    pub fn block(&self) -> Result<Box<Block>> {
        let mut block = Box::new(Block::EMPTY);
        let limits = &self.limits;
        block.name_bytes = put_text(&mut block.name, &self.name, "device name length")?;
        block.architecture_bytes = put_text(
            &mut block.architecture,
            &self.architecture,
            "architecture name length",
        )?;
        block.family_count = put_list(
            &mut block.families,
            self.families.iter(),
            "GPU family count",
            |family| Ok(family.raw()),
        )?;
        block.format_count = put_pixel_formats(&mut block.formats, &self.formats)?;
        block.sparse_format_count = put_list(
            &mut block.sparse_formats,
            self.sparse_samples.iter(),
            "sparse pixel format count",
            |&(format, counts)| format_entry(format, counts.bits()),
        )?;
        ensure(self.gaps.len() <= GAPS, "capability gap count")?;
        let Block { gaps, gap_text, .. } = &mut *block;
        let mut used = 0;
        for (slot, gap) in gaps.iter_mut().zip(&self.gaps) {
            let bytes = put_text(
                &mut gap_text[used..],
                &gap.capability,
                "capability gap text length",
            )?;
            *slot = GapEntry {
                cause: gap.cause.raw(),
                offset: used as u32,
                bytes,
            };
            used += bytes as usize;
        }
        block.gap_count = self.gaps.len() as u32;
        block.texture_sample_counts = self.texture_sample_counts.bits();
        block.depth_resolve_modes = self.depth_resolve_modes.bits();
        block.stencil_resolve_modes = self.stencil_resolve_modes.bits();
        block.counter_sampling = CounterSamplingPoint::ALL
            .iter()
            .filter(|point| self.counter_sampling[point.raw() as usize])
            .fold(0, |mask, point| mask | 1 << point.raw());
        block.max_sampler_anisotropy = self.max_sampler_anisotropy;
        block.flags = Flags::EMPTY
            .with(Flags::HEADLESS, self.headless)
            .with(Flags::LOW_POWER, self.low_power)
            .with(Flags::REMOVABLE, self.removable)
            .with(Flags::UNIFIED_MEMORY, self.has_unified_memory)
            .with(
                Flags::FLOAT32_FILTERING,
                self.supports_32bit_float_filtering,
            )
            .with(Flags::FLOAT32_MSAA, self.supports_32bit_msaa)
            .with(
                Flags::BC_TEXTURE_COMPRESSION,
                self.supports_bc_texture_compression,
            )
            .with(Flags::DEPTH24_STENCIL8, self.depth24_stencil8_supported)
            .with(Flags::QUERY_TEXTURE_LOD, self.supports_query_texture_lod)
            .with(
                Flags::PULL_MODEL_INTERPOLATION,
                self.supports_pull_model_interpolation,
            )
            .with(
                Flags::SHADER_BARYCENTRIC_COORDINATES,
                self.supports_shader_barycentric_coordinates,
            )
            .with(
                Flags::PROGRAMMABLE_SAMPLE_POSITIONS,
                self.programmable_sample_positions,
            )
            .with(Flags::RASTER_ORDER_GROUPS, self.raster_order_groups)
            .with(Flags::RAYTRACING, self.supports_raytracing)
            .with(
                Flags::RAYTRACING_FROM_RENDER,
                self.supports_raytracing_from_render,
            )
            .with(
                Flags::PRIMITIVE_MOTION_BLUR,
                self.supports_primitive_motion_blur,
            )
            .with(Flags::FUNCTION_POINTERS, self.supports_function_pointers)
            .with(
                Flags::FUNCTION_POINTERS_FROM_RENDER,
                self.supports_function_pointers_from_render,
            )
            .with(Flags::DYNAMIC_LIBRARIES, self.supports_dynamic_libraries)
            .with(
                Flags::RENDER_DYNAMIC_LIBRARIES,
                self.supports_render_dynamic_libraries,
            )
            .with(Flags::PLACEMENT_SPARSE, self.supports_placement_sparse)
            .with(Flags::MESH_SHADERS, self.supports_mesh_shaders)
            .with(Flags::TESSELLATION, self.supports_tessellation)
            .with(
                Flags::SAMPLER_MIRROR_CLAMP_TO_EDGE,
                self.sampler_mirror_clamp_to_edge,
            )
            .with(Flags::SAMPLER_REDUCTION_MODES, self.sampler_reduction_modes)
            .with(Flags::DUAL_SOURCE_BLENDING, self.dual_source_blending)
            .with(Flags::ALPHA_TO_ONE, self.alpha_to_one)
            .with(Flags::DEPTH_CLAMP, self.depth_clamp)
            .with(Flags::WIREFRAME, self.wireframe)
            .with(Flags::STATISTIC_COUNTERS, self.statistic_counters)
            .with(Flags::CONSTANT_VERTEX_STEP, self.constant_vertex_step)
            .with(Flags::SPARSE_VOLUMES, self.sparse_volumes)
            .with(
                Flags::SINGLE_TEXEL_ALIGNMENT,
                self.texel_buffer_alignment.single_texel,
            )
            .bits();
        block.location = self.location.raw();
        block.location_number = self.location_number;
        block.max_transfer_rate = self.max_transfer_rate;
        block.recommended_max_working_set_size = self.recommended_max_working_set_size;
        block.argument_buffers_tier = self.argument_buffers_tier.raw();
        block.read_write_texture_tier = self.read_write_texture_tier.raw();
        block.timestamp_frequency = self.timestamp_frequency;
        block.vertex_formats = self
            .vertex_formats
            .iter()
            .fold(0, |mask, format| mask | 1 << format.raw());
        block.linear_row_alignment = self.linear_row_alignment;
        block.linear_offset_alignment = self.linear_offset_alignment;
        block.texel_buffer_alignment = self.texel_buffer_alignment.bytes;
        let size = limits.max_threads_per_threadgroup;
        block.limits = BlockLimits {
            max_threads_per_threadgroup: [size.width, size.height, size.depth],
            max_total_threads_per_threadgroup: limits.max_total_threads_per_threadgroup,
            thread_execution_width: limits.thread_execution_width,
            max_threadgroup_memory_length: limits.max_threadgroup_memory_length,
            max_buffer_length: limits.max_buffer_length,
            max_texture_dimension_1d: limits.max_texture_dimension_1d,
            max_texture_dimension_2d: limits.max_texture_dimension_2d,
            max_texture_dimension_3d: limits.max_texture_dimension_3d,
            max_texture_dimension_cube: limits.max_texture_dimension_cube,
            max_texture_array_length: limits.max_texture_array_length,
            max_texture_buffer_width: limits.max_texture_buffer_width,
            max_color_attachments: limits.max_color_attachments,
            max_viewports: limits.max_viewports,
            max_vertex_amplification_count: limits.max_vertex_amplification_count,
            max_argument_buffer_sampler_count: limits.max_argument_buffer_sampler_count,
            max_argument_buffer_resources: limits.max_argument_buffer_resources,
            max_vertex_buffer_stride: limits.max_vertex_buffer_stride,
            max_vertex_attribute_offset: limits.max_vertex_attribute_offset,
            max_vertex_step_rate: limits.max_vertex_step_rate,
            max_tessellation_factor: limits.max_tessellation_factor,
            max_mesh_threads_per_threadgroup: limits.max_mesh_threads_per_threadgroup,
            max_object_payload_length: limits.max_object_payload_length,
            buffer_alignment_for_uniforms: limits.buffer_alignment_for_uniforms,
            sparse_tile_bytes: limits.sparse_tile_bytes,
            max_point_size: limits.max_point_size,
            reserved: 0,
        };
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::nvidia::fixture;

    #[test]
    fn blocks_decode_to_the_capabilities_they_carry() {
        let capabilities = fixture::capabilities();
        let block = capabilities.block().unwrap();
        assert_eq!(block.capabilities().unwrap(), capabilities);
        assert!(block.family_count > 0 && block.format_count > 0 && block.gap_count > 0);
        for (format, entry) in PixelFormat::ALL.iter().zip(&block.formats) {
            assert_eq!(format.raw(), u64::from(entry.format));
            assert_eq!(capabilities.format(*format).bits(), entry.value);
        }
    }

    #[test]
    fn nonstandard_pixel_format_lists_keep_wire_order_and_first_match() {
        let capabilities = fixture::capabilities();
        let mut block = capabilities.block().unwrap();
        let bgra = PixelFormat::Bgra8Unorm;
        let rgba = PixelFormat::Rgba8Unorm;
        let entry = |format: PixelFormat, value: FormatCapabilities| FormatEntry {
            format: format.raw() as u32,
            value: value.bits(),
        };
        block.formats.fill(FormatEntry::default());
        block.formats[..3].copy_from_slice(&[
            entry(bgra, FormatCapabilities::EMPTY),
            entry(rgba, FormatCapabilities::READ),
            entry(bgra, FormatCapabilities::WRITE),
        ]);
        block.format_count = 3;
        let decoded = block.capabilities().unwrap();
        assert_eq!(decoded.format(bgra), FormatCapabilities::EMPTY);
        assert_eq!(decoded.format(rgba), FormatCapabilities::READ);
        assert_eq!(
            decoded.format(PixelFormat::Depth32Float),
            FormatCapabilities::EMPTY
        );
        assert_eq!(decoded.block().unwrap(), block);

        block.formats[3..].fill(entry(rgba, FormatCapabilities::EMPTY));
        block.format_count = FORMATS as u32;
        assert_eq!(block.capabilities().unwrap().block().unwrap(), block);

        block.formats[1].format = u32::MAX;
        assert_eq!(block.capabilities(), Err(MALFORMED));
    }

    #[test]
    fn every_flag_carries_its_own_capability() {
        let block = fixture::capabilities().block().unwrap();
        for bit in 0..u64::BITS {
            let mut flipped = block.clone();
            flipped.flags ^= 1 << bit;
            let known = Flags::KNOWN.bits() & 1 << bit != 0;
            assert_eq!(flipped.capabilities().is_ok(), known, "flag bit {bit}");
        }
    }

    #[test]
    fn blocks_the_encoder_would_not_write_are_refused() {
        let block = fixture::capabilities().block().unwrap();
        let refused = |edit: fn(&mut Block)| {
            let mut edited = block.clone();
            edit(&mut edited);
            edited.capabilities().is_err()
        };
        assert!(refused(|b| b.version += 1));
        assert!(refused(|b| b.magic[0] = 0));
        assert!(refused(|b| b.family_count = FAMILIES as u32 + 1));
        assert!(refused(|b| b.families[0] = 7));
        assert!(refused(|b| b.formats[0].value = u32::MAX));
        assert!(refused(|b| b.name_bytes = NAME_BYTES as u32 + 1));
        assert!(refused(|b| b.name[0] = 0xff));
        // Bytes past a list or a string, and reserved fields, stay zero.
        assert!(refused(|b| b.families[FAMILIES - 1] = GpuFamily::Mac2.raw()));
        assert!(refused(|b| b.gap_text[GAP_TEXT_BYTES - 1] = b'x'));
        assert!(refused(|b| b.limits.reserved = 1));
        assert!(refused(|b| b.gaps[0].cause = 9));
    }

    #[test]
    fn capabilities_beyond_the_block_are_refused() {
        let mut capabilities = fixture::capabilities();
        capabilities.name = "n".repeat(NAME_BYTES + 1);
        assert_eq!(
            capabilities.block().err(),
            Some(Error::Invalid("device name length"))
        );
    }
}
