//! The binding ABI shared by command encoding and compiled shaders.
//!
//! Every pipeline uses one Vulkan pipeline layout:
//!
//! - **Set 0** is the device's bindless descriptor heap: one
//!   update-after-bind, partially bound array per [`HeapArray`]. Index 0 of
//!   each array is a null descriptor, so an unbound slot reads zero.
//! - **Push constants** are [`PushConstants`]: the GPU address of each
//!   stage's argument table, of the latest draw's or dispatch's own
//!   arguments and of the log buffer, and the dispatch's grid size. Every
//!   stage may read them.
//!
//! An [`ArgumentTable`] mirrors Metal's per-stage binding slots. Buffers are
//! device addresses with their bound lengths; textures and samplers are
//! [`ResourceId`]s, the same 64-bit values `gpuResourceID` reports and
//! argument buffers store. A texture's ID names its read descriptor (sampled
//! image, or uniform texel buffer for texture buffers) in the low half and
//! its write descriptors (storage images or a storage texel buffer) in the
//! high half; the compiler selects the array from the texture's declared type
//! and access. A storage image holds one level, so a texture has one per
//! level, consecutive from the high half's index, which carries their count
//! (see [`ResourceId::texture`]). A sampler's ID names its float-border
//! descriptor in the low half and its integer-border twin in the high half.
//! A texture view pool's entry has an ID of its own, flagged with
//! [`ResourceId::POOL_VIEW`], which names the word in the pool's buffer that
//! holds its view's ID; shaders load that ID for an argument buffer's
//! flagged one.
//!
//! Encoders write a table to the command buffer's upload ring whenever its
//! slots change and push its address before the next draw or dispatch.
//!
//! The compiler's side of this ABI is `compiler/metal_abi.h`, which the tests
//! check against these layouts.
use super::{
    capabilities::{MAX_BUFFER_BINDINGS, MAX_SAMPLER_BINDINGS, MAX_TEXTURE_BINDINGS},
    error::{Error, Result},
    pipeline::MAX_COLOR_ATTACHMENTS,
    pixel_format::{FilterClass, Planes},
    vulkan::physical::Limits,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

raw_enum! {
    /// The bindless arrays of descriptor set 0, by binding number.
    pub enum HeapArray: u32 {
        SampledImages = 0,
        StorageImages = 1,
        Samplers = 2,
        UniformTexelBuffers = 3,
        StorageTexelBuffers = 4,
    }
}

/// The heap's descriptor set index.
pub const HEAP_SET: u32 = 0;
/// The null descriptor every array reserves.
pub const NULL_DESCRIPTOR: u32 = 0;

/// Two descriptor indices packed as Metal's `MTLResourceID`. A cube
/// texture's sampled image is followed by its faces' 2D array, which texel
/// reads fetch from.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ResourceId(pub u64);

impl ResourceId {
    pub const NULL: Self = Self(0);
    /// The high half's bits from which it counts its descriptors, less one;
    /// the index is below them.
    pub const LEVEL_SHIFT: u32 = 27;
    /// Descriptors one high half names: levels of a texture, at most 16 in
    /// Metal, which leave [`Self::POOL_VIEW`] clear.
    pub const MAX_LEVELS: u32 = 1 << (31 - Self::LEVEL_SHIFT);
    /// The high-half bit of a texture view pool entry's ID. Below it is
    /// the address over 8 of the word in the pool's buffer that holds the
    /// entry's view's ID, which shaders load in its place.
    pub const POOL_VIEW: u32 = 1 << 31;
    /// The high-half bit of a texture whose storage views hold an sRGB
    /// format's texels through its linear twin: shaders encode what they
    /// write and decode what they read, as Apple GPUs write sRGB textures.
    /// Storage indices lie below it.
    pub const SRGB_STORAGE: u32 = 1 << (Self::LEVEL_SHIFT - 1);
    /// The high-half bits from which a texture holds its
    /// [`FilterClass`], how shaders filter its texels bicubically. Storage
    /// indices lie below them.
    pub const FILTER_CLASS_SHIFT: u32 = Self::LEVEL_SHIFT - 3;
    /// The high-half bits from which a two-plane texture holds its
    /// [`Planes`], zero for one plane, and above them [`Self::YCBCR`]: its
    /// sampled descriptor is its first plane's, followed by its second's,
    /// which shaders combine. Storage indices lie below them.
    pub const PLANES_SHIFT: u32 = Self::FILTER_CLASS_SHIFT - 3;
    /// The high-half bit of a two-plane texture whose planes hold luma and
    /// chroma, which shaders convert to RGB.
    pub const YCBCR: u32 = 4 << Self::PLANES_SHIFT;
    /// The high-half bit of a two-plane texture whose components are the
    /// high 10 bits of 16-bit words, rather than bytes. It and
    /// [`Self::VIDEO_RANGE`] take the top storage index bits, which a
    /// two-plane texture, with no storage views, leaves free.
    pub const TEN_BIT: u32 = 1 << (Self::PLANES_SHIFT - 1);
    /// The high-half bit of a two-plane YCbCr texture whose surface's pixel
    /// format is video range, rather than full range.
    pub const VIDEO_RANGE: u32 = 1 << (Self::PLANES_SHIFT - 2);
    /// The bit of [`Self::VIDEO_RANGE`] on a two-plane RGB texture: its
    /// planes hold `RGB10A8_2P_XR10`'s extended-range codes and 8-bit alpha,
    /// with [`Self::XR10_SRGB`] through the sRGB curve.
    pub const XR10: u32 = Self::VIDEO_RANGE;
    /// The bit of [`Self::TEN_BIT`] on an [`Self::XR10`] texture: its codes
    /// read through the sRGB curve.
    pub const XR10_SRGB: u32 = Self::TEN_BIT;
    /// The bit of [`Self::YCBCR`] on a texture of one plane: its storage
    /// views hold a two-plane extended-range format's half floats, which
    /// shaders hold to the format's codes and 8-bit alpha as they write,
    /// through the sRGB curve with [`Self::SRGB_STORAGE`] (which then does
    /// not encode), as Apple GPUs write `RGB10A8_2P_XR10` textures.
    pub const EXTENDED_STORAGE: u32 = Self::YCBCR;
    /// The storage indices a texture's high half holds.
    pub const MAX_STORAGE: u32 = 1 << Self::PLANES_SHIFT;

    pub const fn new(low: u32, high: u32) -> Self {
        Self(low as u64 | (high as u64) << 32)
    }

    /// The high-half bit of a sampler that compares with Never, through
    /// which a comparison is zero: its Vulkan samplers do not compare.
    pub const SAMPLER_NEVER: u32 = 1 << 31;
    /// The high-half bit of a sampler with Metal's bicubic filter, which
    /// shaders apply to 2D textures: Vulkan's samplers have none.
    pub const SAMPLER_CUBIC: u32 = 1 << 30;
    /// With [`Self::SAMPLER_CUBIC`], the bit of a sampler that selects mip
    /// levels.
    pub const SAMPLER_MIPPED: u32 = 1 << 29;
    /// The bit of a sampler that takes pixel coordinates, which shaders
    /// divide by the base level's size: its Vulkan samplers are normalized.
    /// The integer-border index lies below it.
    pub const SAMPLER_PIXELS: u32 = 1 << 28;
    /// The bits of a sampler that shaders apply themselves, whose samples
    /// read the sampler's flags.
    pub const SAMPLER_SHADED: u32 = Self::SAMPLER_CUBIC | Self::SAMPLER_PIXELS;

    /// A sampler's ID: its float-border descriptor, its integer-border twin,
    /// and its `SAMPLER_*` flags.
    pub const fn sampler(float: u32, integer: u32, flags: u32) -> Self {
        debug_assert!(integer & !(Self::SAMPLER_PIXELS - 1) == 0);
        debug_assert!(flags & (Self::SAMPLER_PIXELS - 1) == 0);
        Self::new(float, integer | flags)
    }

    /// A sampler ID's integer-border descriptor.
    pub const fn sampler_integer(self) -> u32 {
        self.high() & (Self::SAMPLER_PIXELS - 1)
    }

    /// A texture's ID: its read descriptor, and its `levels` write
    /// descriptors from `storage`.
    pub const fn texture(sampled: u32, storage: u32, levels: u32) -> Self {
        debug_assert!(storage < Self::MAX_STORAGE);
        debug_assert!(levels >= 1 && levels <= Self::MAX_LEVELS);
        Self::new(sampled, storage | (levels - 1) << Self::LEVEL_SHIFT)
    }

    /// This texture ID with [`Self::SRGB_STORAGE`] set when `srgb`.
    pub const fn with_srgb_storage(self, srgb: bool) -> Self {
        if srgb {
            Self(self.0 | (Self::SRGB_STORAGE as u64) << 32)
        } else {
            self
        }
    }

    /// This texture ID with [`Self::EXTENDED_STORAGE`], and
    /// [`Self::SRGB_STORAGE`] for the sRGB curve, when `extended` is some.
    pub const fn with_extended_storage(self, extended: Option<bool>) -> Self {
        match extended {
            Some(srgb) => {
                Self(self.0 | (Self::EXTENDED_STORAGE as u64) << 32).with_srgb_storage(srgb)
            }
            None => self,
        }
    }

    /// This texture ID holding `class`.
    pub const fn with_filter_class(self, class: FilterClass) -> Self {
        let high = (self.high() & !(3 << Self::FILTER_CLASS_SHIFT))
            | (class as u32) << Self::FILTER_CLASS_SHIFT;
        Self::new(self.low(), high)
    }

    /// This texture ID of a two-plane texture whose second plane is
    /// `planes`, with `flags` of [`Self::YCBCR`], [`Self::TEN_BIT`] and
    /// [`Self::VIDEO_RANGE`].
    pub const fn with_planes(self, planes: Planes, flags: u32) -> Self {
        debug_assert!(flags & !(Self::YCBCR | Self::TEN_BIT | Self::VIDEO_RANGE) == 0);
        debug_assert!(self.high_index() == 0);
        let high = (self.high() & !(7 << Self::PLANES_SHIFT))
            | (planes as u32) << Self::PLANES_SHIFT
            | flags;
        Self::new(self.low(), high)
    }

    /// The first descriptor the high half names.
    pub const fn high_index(self) -> u32 {
        self.high() & (Self::MAX_STORAGE - 1)
    }

    /// The descriptors the high half names.
    pub const fn high_count(self) -> u32 {
        (self.high() >> Self::LEVEL_SHIFT) + 1
    }

    pub const fn low(self) -> u32 {
        self.0 as u32
    }

    pub const fn high(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

raw_enum! {
    /// Which push-constant table address a Metal stage reads.
    pub enum TableSlot: u32 {
        /// Vertex, kernel and object functions.
        Primary = 0,
        Fragment = 1,
        Mesh = 2,
    }
}

/// The push-constant block shared by every pipeline layout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PushConstants {
    pub tables: [u64; 3],
    /// The latest patch draw's [`TessellationArguments`], or a stage-in
    /// dispatch's region (`MTLStageInRegionIndirectArguments`: `uint`
    /// origin and size). Only stages synthesized for those read it.
    pub arguments: u64,
    /// The command buffer's log state's buffer, which `os_log` appends to;
    /// zero for none.
    pub log: u64,
    /// Threads in the grid (`dispatchThreads`), for the compiler's bounds
    /// check of non-uniform threadgroups; zero for uniform dispatches.
    pub grid: [u32; 3],
    /// The view an amplified draw renders (`[[amplification_id]]`). Each
    /// view is its own draw, so Metal's view mappings need no multiview.
    pub amplification_id: u32,
    /// That view's `MTLVertexAmplificationViewMapping`: the viewport offset
    /// in the low half, the render target array offset in the high half.
    pub view_mapping: u32,
    /// The views of the draw (`[[amplification_count]]`), at least one.
    pub amplification_count: u32,
}

// Vulkan guarantees 128 bytes of push constants.
const _: () = assert!(PushConstants::BYTES <= 128);

impl PushConstants {
    pub const BYTES: u32 = 64;
    pub const TABLES_OFFSET: u32 = 0;
    pub const ARGUMENTS_OFFSET: u32 = 24;
    pub const LOG_OFFSET: u32 = 32;
    pub const GRID_OFFSET: u32 = 40;
    pub const AMPLIFICATION_OFFSET: u32 = 52;
    pub const VIEW_MAPPING_OFFSET: u32 = 56;
    pub const AMPLIFICATIONS_OFFSET: u32 = 60;

    pub fn encode(&self) -> [u8; Self::BYTES as usize] {
        let mut bytes = [0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        self.tables.iter().for_each(|table| writer.u64(*table));
        writer.u64(self.arguments);
        writer.u64(self.log);
        self.grid.iter().for_each(|size| writer.u32(*size));
        writer.u32(self.amplification_id);
        writer.u32(self.view_mapping);
        writer.u32(self.amplification_count);
        bytes
    }
}

/// A bound buffer: its device address and the bytes from there to the end
/// of the binding, which the compiler uses for bounds-checked access.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BufferBinding {
    pub address: u64,
    pub length: u64,
}

/// One stage's binding slots, as the GPU reads them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentTable {
    pub buffers: [BufferBinding; MAX_BUFFER_BINDINGS as usize],
    pub textures: [ResourceId; MAX_TEXTURE_BINDINGS as usize],
    pub samplers: [ResourceId; MAX_SAMPLER_BINDINGS as usize],
    /// The pass's color attachments, which `[[color(n)]]` inputs read.
    pub attachments: [ResourceId; MAX_COLOR_ATTACHMENTS],
    /// The pass's samples, which `get_num_samples` and
    /// `get_sample_position` read.
    pub samples: PassSamples,
    /// The render encoder's blend color, as each float's bits, which
    /// functions blending the attachments they access as storage read.
    pub blend_color: [u32; 4],
    /// The pass's imageblock data, which fragment and tile functions
    /// access.
    pub imageblock: PassImageblock,
    /// What a fragment function that runs the fragment tests itself reads.
    pub fragment_tests: FragmentTests,
}

/// The fragment tests a fragment function runs itself
/// ([`Capabilities::fragment_tests`]): the state words of
/// `STELA_AIR_DEPTH_STENCIL` (`air_to_nir.h`), the encoder's stencil
/// reference values, the front face's in bits 0 to 7 and the back face's
/// in bits 8 to 15, the viewport's depth range, and the storage views of
/// the pass's depth and stencil copies.
///
/// [`Capabilities::fragment_tests`]: super::capabilities::Capabilities::fragment_tests
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentTests {
    pub state: [u32; 3],
    pub references: u32,
    /// The near and far depths' bits.
    pub range: [u32; 2],
    pub depth: ResourceId,
    pub stencil: ResourceId,
}

impl FragmentTests {
    /// The depth word's depth writes, encoding shift, stencil attachment
    /// and clamping bits.
    pub const DEPTH_WRITE: u32 = 1 << 3;
    pub const DEPTH_FORMAT_SHIFT: u32 = 4;
    pub const STENCIL_ATTACHED: u32 = 1 << 6;
    pub const DEPTH_CLAMP: u32 = 1 << 7;
}

/// A render pass's imageblock data: `stride` bytes for each sample, each
/// pixel's samples in turn, `pitch` pixels to a row, at `address`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PassImageblock {
    pub stride: u32,
    pub pitch: u32,
    pub address: u64,
}

impl Default for ArgumentTable {
    fn default() -> Self {
        Self {
            buffers: [BufferBinding::default(); MAX_BUFFER_BINDINGS as usize],
            textures: [ResourceId::NULL; MAX_TEXTURE_BINDINGS as usize],
            samplers: [ResourceId::NULL; MAX_SAMPLER_BINDINGS as usize],
            attachments: [ResourceId::NULL; MAX_COLOR_ATTACHMENTS],
            samples: PassSamples::default(),
            blend_color: [0; 4],
            imageblock: PassImageblock::default(),
            fragment_tests: FragmentTests::default(),
        }
    }
}

/// A render pass's samples per pixel and their positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassSamples {
    /// A byte per sample, the first lowest: x in 1/16 pixel in the low
    /// nibble, y in the high.
    pub positions: u128,
    pub count: u32,
}

impl Default for PassSamples {
    /// One sample at the pixel's centre.
    fn default() -> Self {
        Self {
            positions: 0x88,
            count: 1,
        }
    }
}

impl PassSamples {
    /// The most samples the table holds.
    pub const MAX: usize = 16;

    /// Samples at `positions` in [0, 1) from the pixel's top left, on the
    /// 1/16 pixel grid.
    pub fn new(positions: &[[f32; 2]]) -> Self {
        debug_assert!(!positions.is_empty() && positions.len() <= Self::MAX);
        let sixteenths = |coordinate: f32| (coordinate * 16.0) as u128 & 0xf;
        Self {
            positions: positions
                .iter()
                .enumerate()
                .fold(0, |packed, (sample, &[x, y])| {
                    packed | (sixteenths(x) | sixteenths(y) << 4) << (8 * sample)
                }),
            count: positions.len() as u32,
        }
    }
}

impl ArgumentTable {
    pub const BUFFER_ADDRESSES_OFFSET: u32 = 0;
    pub const BUFFER_LENGTHS_OFFSET: u32 = MAX_BUFFER_BINDINGS * 8;
    pub const TEXTURES_OFFSET: u32 = Self::BUFFER_LENGTHS_OFFSET + MAX_BUFFER_BINDINGS * 8;
    pub const SAMPLERS_OFFSET: u32 = Self::TEXTURES_OFFSET + MAX_TEXTURE_BINDINGS * 8;
    pub const ATTACHMENTS_OFFSET: u32 = Self::SAMPLERS_OFFSET + MAX_SAMPLER_BINDINGS * 8;
    pub const SAMPLE_POSITIONS_OFFSET: u32 =
        Self::ATTACHMENTS_OFFSET + MAX_COLOR_ATTACHMENTS as u32 * 8;
    pub const SAMPLE_COUNT_OFFSET: u32 = Self::SAMPLE_POSITIONS_OFFSET + 16;
    pub const BLEND_COLOR_OFFSET: u32 = Self::SAMPLE_COUNT_OFFSET + 16;
    pub const IMAGEBLOCK_OFFSET: u32 = Self::BLEND_COLOR_OFFSET + 16;
    pub const DEPTH_STENCIL_OFFSET: u32 = Self::IMAGEBLOCK_OFFSET + 16;
    pub const DEPTH_RANGE_OFFSET: u32 = Self::DEPTH_STENCIL_OFFSET + 16;
    pub const DEPTH_COPIES_OFFSET: u32 = Self::DEPTH_RANGE_OFFSET + 16;
    pub const BYTES: u32 = Self::DEPTH_COPIES_OFFSET + 16;
    /// Tables are placed at this alignment in the upload ring.
    pub const ALIGNMENT: u64 = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::BYTES as usize];
        self.encode_into(&mut bytes);
        bytes
    }

    pub(super) fn encode_into(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), Self::BYTES as usize);
        let mut writer = Writer { bytes, offset: 0 };
        self.buffers
            .iter()
            .for_each(|buffer| writer.u64(buffer.address));
        self.buffers
            .iter()
            .for_each(|buffer| writer.u64(buffer.length));
        self.textures
            .iter()
            .chain(&self.samplers)
            .chain(&self.attachments)
            .for_each(|id| writer.u64(id.0));
        writer.u64(self.samples.positions as u64);
        writer.u64((self.samples.positions >> 64) as u64);
        [self.samples.count, 0, 0, 0]
            .into_iter()
            .for_each(|word| writer.u32(word));
        self.blend_color
            .into_iter()
            .for_each(|channel| writer.u32(channel));
        writer.u32(self.imageblock.stride);
        writer.u32(self.imageblock.pitch);
        writer.u64(self.imageblock.address);
        let tests = &self.fragment_tests;
        tests.state.into_iter().for_each(|word| writer.u32(word));
        writer.u32(tests.references);
        [tests.range[0], tests.range[1], 0, 0]
            .into_iter()
            .for_each(|word| writer.u32(word));
        writer.u64(tests.depth.0);
        writer.u64(tests.stencil.0);
    }
}

/// What a patch draw's synthesized tessellation stages read, uploaded per
/// draw (see [`Tessellation`](super::shader::Tessellation)).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TessellationArguments {
    /// The factor buffer from `setTessellationFactorBuffer:offset:`.
    pub factors: BufferBinding,
    /// `uint` patch numbers; zero when the draw has no patch index buffer.
    pub patch_indices: BufferBinding,
    /// Control point indices of the pipeline's index type; zero for
    /// non-indexed patch draws.
    pub control_point_indices: BufferBinding,
    /// Bytes between instances' factors (`instanceStride`).
    pub instance_stride: u32,
    /// `setTessellationFactorScale:`; the pipeline decides whether it
    /// applies.
    pub factor_scale: f32,
    /// `numberOfPatchControlPoints`.
    pub control_points: u32,
    /// The stride `setVertexBuffer:offset:attributeStride:` bound with each
    /// vertex buffer the evaluation stage fetches through a layout of
    /// dynamic stride; zero for the others.
    pub strides: [u32; MAX_BUFFER_BINDINGS as usize],
}

impl TessellationArguments {
    pub const FACTORS_OFFSET: u32 = 0;
    pub const PATCH_INDICES_OFFSET: u32 = 16;
    pub const CONTROL_POINT_INDICES_OFFSET: u32 = 32;
    pub const INSTANCE_STRIDE_OFFSET: u32 = 48;
    pub const FACTOR_SCALE_OFFSET: u32 = 52;
    pub const CONTROL_POINTS_OFFSET: u32 = 56;
    pub const STRIDES_OFFSET: u32 = 60;
    pub const BYTES: u32 = 60 + 4 * MAX_BUFFER_BINDINGS;
    pub const ALIGNMENT: u64 = 16;

    pub fn encode(&self) -> [u8; Self::BYTES as usize] {
        let mut bytes = [0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        for binding in [self.factors, self.patch_indices, self.control_point_indices] {
            writer.u64(binding.address);
            writer.u64(binding.length);
        }
        writer.u32(self.instance_stride);
        writer.u32(self.factor_scale.to_bits());
        writer.u32(self.control_points);
        self.strides.iter().for_each(|stride| writer.u32(*stride));
        bytes
    }
}

/// What the backend's internal accumulate kernel reads at the push
/// constants' `arguments`: runs of 64-bit query results, each summed into
/// its own destination. Thread `n` sums run `n`: the `count` results at
/// `results[first + j * stride]`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccumulateArguments {
    /// Address of the first result.
    pub results: u64,
    /// Results between consecutive elements of a run.
    pub stride: u32,
    /// (first result, result count, destination address).
    pub runs: Vec<(u32, u32, u64)>,
}

impl AccumulateArguments {
    pub const RESULTS_OFFSET: u32 = 0;
    pub const COUNT_OFFSET: u32 = 8;
    pub const STRIDE_OFFSET: u32 = 12;
    pub const RUNS_OFFSET: u32 = 16;
    pub const RUN_BYTES: u32 = 16;
    pub const ALIGNMENT: u64 = 16;
    /// Threads per workgroup of the kernel.
    pub const WORKGROUP_SIZE: u32 = 64;

    pub fn encode(&self) -> Vec<u8> {
        let length = Self::RUNS_OFFSET + Self::RUN_BYTES * self.runs.len() as u32;
        let mut bytes = alloc::vec![0; length as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        writer.u64(self.results);
        writer.u32(self.runs.len() as u32);
        writer.u32(self.stride);
        for &(first, count, destination) in &self.runs {
            writer.u32(first);
            writer.u32(count);
            writer.u64(destination);
        }
        bytes
    }
}

/// What the backend's texel kernels read at the push constants'
/// `arguments`: a buffer copy of a region of one level between Metal's
/// bytes in the buffer and a texture's stored texels, which a raw storage
/// view of the level's layers holds. Thread `n` converts texel `n`, counted
/// along rows, then rows, then images; `origin` is the region's x, y and
/// first layer in the view.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TexelArguments {
    pub buffer: u64,
    pub count: u32,
    /// `enum stela_metal_texel_encoding`.
    pub encoding: u32,
    /// The raw storage view's `gpuResourceID`-shaped identifier.
    pub image: u64,
    pub width: u32,
    pub height: u32,
    pub bytes_per_row: u32,
    pub bytes_per_image: u32,
    pub origin: [u32; 3],
    /// For the two-plane extended-range encodings, the address of the
    /// alpha plane's byte of the region's first texel, or zero for none,
    /// and that plane's bytes per row.
    pub alpha: u64,
    pub alpha_bytes_per_row: u32,
}

impl TexelArguments {
    pub const BUFFER_OFFSET: u32 = 0;
    pub const COUNT_OFFSET: u32 = 8;
    pub const ENCODING_OFFSET: u32 = 12;
    pub const IMAGE_OFFSET: u32 = 16;
    pub const WIDTH_OFFSET: u32 = 24;
    pub const HEIGHT_OFFSET: u32 = 28;
    pub const ROW_OFFSET: u32 = 32;
    pub const IMAGE_BYTES_OFFSET: u32 = 36;
    pub const ORIGIN_OFFSET: u32 = 40;
    pub const ALPHA_OFFSET: u32 = 56;
    pub const ALPHA_ROW_OFFSET: u32 = 64;
    pub const BYTES: u32 = 72;
    pub const ALIGNMENT: u64 = 16;
    /// Threads per workgroup of the kernels.
    pub const WORKGROUP_SIZE: u32 = 64;

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        writer.u64(self.buffer);
        writer.u32(self.count);
        writer.u32(self.encoding);
        writer.u64(self.image);
        writer.u32(self.width);
        writer.u32(self.height);
        writer.u32(self.bytes_per_row);
        writer.u32(self.bytes_per_image);
        for coordinate in self.origin {
            writer.u32(coordinate);
        }
        writer.u32(0);
        writer.u64(self.alpha);
        writer.u32(self.alpha_bytes_per_row);
        bytes
    }
}

/// What the backend's average samples kernel reads at the push constants'
/// `arguments`: thread `n` below `count` resolves texel `n` of a
/// multisampled attachment, counted along rows, then rows, then layers,
/// from the raw storage view `source` into the raw storage view
/// `destination` of its resolve texture, decoding and encoding its samples
/// by `format` (`enum stela_metal_average_format`). With
/// [`FOLLOW_DEPTH`](Self::FOLLOW_DEPTH), it resolves a stencil following a
/// min or max depth resolve instead, from storage copies of the stencil and
/// `depth` samples into a copy of the resolve texture's stencil.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AverageArguments {
    pub source: u64,
    pub destination: u64,
    pub count: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
    pub samples: u32,
    pub depth: u64,
}

impl AverageArguments {
    pub const SOURCE_OFFSET: u32 = 0;
    pub const DESTINATION_OFFSET: u32 = 8;
    pub const COUNT_OFFSET: u32 = 16;
    pub const FORMAT_OFFSET: u32 = 20;
    pub const WIDTH_OFFSET: u32 = 24;
    pub const HEIGHT_OFFSET: u32 = 28;
    pub const SAMPLES_OFFSET: u32 = 32;
    pub const DEPTH_OFFSET: u32 = 40;
    pub const BYTES: u32 = 48;
    pub const ALIGNMENT: u64 = 16;
    /// A format of a stencil resolve following the depth resolve, whose
    /// low bits are the depth copy's `enum stela_air_depth_format`
    /// ([`TestedCopy::encoding`](crate::metal::pass::TestedCopy::encoding)).
    pub const FOLLOW_DEPTH: u32 = 0x10;
    /// With [`FOLLOW_DEPTH`](Self::FOLLOW_DEPTH), follows the greatest
    /// depth rather than the least.
    pub const FOLLOW_MAX: u32 = 0x20;
    /// Threads per workgroup of the kernel.
    pub const WORKGROUP_SIZE: u32 = 64;

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        writer.u64(self.source);
        writer.u64(self.destination);
        writer.u32(self.count);
        writer.u32(self.format);
        writer.u32(self.width);
        writer.u32(self.height);
        writer.u32(self.samples);
        writer.u32(0);
        writer.u64(self.depth);
        bytes
    }
}

/// What the backend's reorder blocks kernel reads at the push constants'
/// `arguments`: thread `n` below `count` copies block `n` of a region,
/// counted along its rows of `width` blocks, between `rows`, a buffer's
/// rows `row_bytes` apart from the region's first block, and `level`, a
/// PVRTC level of `columns` by `level_rows` blocks in their Morton order,
/// into the buffer when `to_rows`. `origin` is the region's first column
/// and row of blocks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReorderArguments {
    pub rows: u64,
    pub level: u64,
    pub count: u32,
    pub to_rows: bool,
    pub columns: u32,
    pub level_rows: u32,
    pub origin: [u32; 2],
    pub width: u32,
    pub row_bytes: u32,
}

impl ReorderArguments {
    pub const ROWS_OFFSET: u32 = 0;
    pub const LEVEL_OFFSET: u32 = 8;
    pub const COUNT_OFFSET: u32 = 16;
    pub const TO_ROWS_OFFSET: u32 = 20;
    pub const COLUMNS_OFFSET: u32 = 24;
    pub const LEVEL_ROWS_OFFSET: u32 = 28;
    pub const ORIGIN_OFFSET: u32 = 32;
    pub const WIDTH_OFFSET: u32 = 40;
    pub const ROW_BYTES_OFFSET: u32 = 44;
    pub const BYTES: u32 = 48;
    pub const ALIGNMENT: u64 = 16;
    /// Threads per workgroup of the kernel.
    pub const WORKGROUP_SIZE: u32 = 64;

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        writer.u64(self.rows);
        writer.u64(self.level);
        writer.u32(self.count);
        writer.u32(u32::from(self.to_rows));
        writer.u32(self.columns);
        writer.u32(self.level_rows);
        writer.u32(self.origin[0]);
        writer.u32(self.origin[1]);
        writer.u32(self.width);
        writer.u32(self.row_bytes);
        bytes
    }
}

/// What the backend's internal select kernel reads at the push constants'
/// `arguments`. Thread `n` below `count` writes the 32-bit flag
/// `flags[n]`: 1 when the `MTLIndirectCommandBufferExecutionRange` at
/// `range` (`uint` location and length) holds command `n`, else 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SelectArguments {
    pub range: u64,
    pub flags: u64,
    pub count: u32,
}

impl SelectArguments {
    pub const RANGE_OFFSET: u32 = 0;
    pub const FLAGS_OFFSET: u32 = 8;
    pub const COUNT_OFFSET: u32 = 16;
    pub const BYTES: u32 = 24;
    pub const ALIGNMENT: u64 = 16;
    /// Threads per workgroup of the kernel.
    pub const WORKGROUP_SIZE: u32 = 64;

    pub fn encode(&self) -> [u8; Self::BYTES as usize] {
        let mut bytes = [0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        writer.u64(self.range);
        writer.u64(self.flags);
        writer.u32(self.count);
        bytes
    }
}

/// What the backend's internal resolve kernels read at the push constants'
/// `arguments`: `stela_metal_resolve_draws_kernel` turns each command of a
/// GPU-resident render indirect command buffer into a [`GeneratedSequence`]
/// and its counts per [`ResolveSlot`], and
/// `stela_metal_resolve_dispatches_kernel` each command of a compute one
/// into a [`GeneratedSequence`], reading neither counts, strides, classes,
/// vertex buffers nor slots.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolveArguments {
    /// The buffer's header (its `gpuResourceID`).
    pub header: u64,
    /// The execution range: `uint` location and length.
    pub range: u64,
    /// Where thread `n` writes its sequence, at `n * GeneratedSequence::BYTES`.
    pub sequences: u64,
    /// Where thread `n` writes its `u32` count of each slot.
    pub counts: u64,
    /// Where thread `n` writes its vertex and fragment, or kernel, argument
    /// tables, at `2n` and `2n + 1`, unless the buffer inherits buffers.
    pub tables: u64,
    /// The pipeline classes' static vertex strides: `u32` per class and
    /// buffer index, zero for none.
    pub strides: u64,
    pub count: u32,
    /// The command of thread 0.
    pub first: u32,
    pub inherit_pipeline: bool,
    pub inherit_buffers: bool,
    pub class_count: u32,
    /// The factor scale of patch draws the CPU encoded: the encoder's when
    /// its pipeline enables scaling, else one.
    pub factor_scale: f32,
    /// Whether the encoder's pipeline scales factors, so that the scale a
    /// shader encoded with a patch draw applies.
    pub scales: bool,
    /// The encoder's push constants, whose tables the commands' tables
    /// copy.
    pub constants: PushConstants,
    /// The encoder's vertex buffers by index, for buffers that inherit them.
    pub vertex_buffers: [SequenceVertexBuffer; MAX_BUFFER_BINDINGS as usize],
    pub slots: Vec<ResolveSlot>,
}

/// A vertex buffer as a [`GeneratedSequence`] binds it
/// (`VkBindVertexBufferIndirectCommandEXT`); a zero stride is the
/// pipeline's.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SequenceVertexBuffer {
    pub address: u64,
    pub size: u32,
    pub stride: u32,
}

/// One execution of a resolved command: its pipeline class (zero when the
/// buffer inherits pipeline state), its action and its `MTLPrimitiveType`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolveSlot {
    pub class: u32,
    pub action: u32,
    pub primitive: u32,
}

impl ResolveArguments {
    pub const HEADER_OFFSET: u32 = 0;
    pub const RANGE_OFFSET: u32 = 8;
    pub const SEQUENCES_OFFSET: u32 = 16;
    pub const COUNTS_OFFSET: u32 = 24;
    pub const TABLES_OFFSET: u32 = 32;
    pub const STRIDES_OFFSET: u32 = 40;
    pub const COUNT_OFFSET: u32 = 48;
    pub const FIRST_OFFSET: u32 = 52;
    pub const SLOT_COUNT_OFFSET: u32 = 56;
    pub const FLAGS_OFFSET: u32 = 60;
    pub const CLASS_COUNT_OFFSET: u32 = 64;
    pub const FACTOR_SCALE_OFFSET: u32 = 68;
    pub const PUSH_OFFSET: u32 = 72;
    /// The kernel loads each 16-byte vertex buffer and slot as one vector,
    /// so both arrays start on 16-byte boundaries.
    pub const VERTEX_BUFFERS_OFFSET: u32 = 144;
    pub const SLOTS_OFFSET: u32 = 640;
    pub const SLOT_BYTES: u32 = 16;
    pub const INHERIT_PIPELINE: u32 = 1;
    pub const INHERIT_BUFFERS: u32 = 2;
    pub const SCALES: u32 = 4;
    pub const ALIGNMENT: u64 = 16;
    /// Threads per workgroup of the kernel.
    pub const WORKGROUP_SIZE: u32 = 64;

    pub fn encode(&self) -> Vec<u8> {
        let length = Self::SLOTS_OFFSET + Self::SLOT_BYTES * self.slots.len() as u32;
        let mut bytes = alloc::vec![0; length as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        for address in [
            self.header,
            self.range,
            self.sequences,
            self.counts,
            self.tables,
            self.strides,
        ] {
            writer.u64(address);
        }
        let flag = |set: bool, flag: u32| if set { flag } else { 0 };
        let flags = flag(self.inherit_pipeline, Self::INHERIT_PIPELINE)
            | flag(self.inherit_buffers, Self::INHERIT_BUFFERS)
            | flag(self.scales, Self::SCALES);
        for word in [
            self.count,
            self.first,
            self.slots.len() as u32,
            flags,
            self.class_count,
            self.factor_scale.to_bits(),
        ] {
            writer.u32(word);
        }
        writer.offset = Self::PUSH_OFFSET as usize;
        writer.bytes[writer.offset..writer.offset + PushConstants::BYTES as usize]
            .copy_from_slice(&self.constants.encode());
        writer.offset = Self::VERTEX_BUFFERS_OFFSET as usize;
        for buffer in &self.vertex_buffers {
            writer.u64(buffer.address);
            writer.u32(buffer.size);
            writer.u32(buffer.stride);
        }
        for slot in &self.slots {
            writer.u32(slot.class);
            writer.u32(slot.action);
            writer.u32(slot.primitive);
            writer.u32(0);
        }
        bytes
    }
}

const _: () = assert!(
    ResolveArguments::PUSH_OFFSET + PushConstants::BYTES <= ResolveArguments::VERTEX_BUFFERS_OFFSET
        && ResolveArguments::VERTEX_BUFFERS_OFFSET
            + GeneratedSequence::VERTEX_BUFFER_BYTES * MAX_BUFFER_BINDINGS
            == ResolveArguments::SLOTS_OFFSET
        && (ResolveArguments::VERTEX_BUFFERS_OFFSET as u64)
            .is_multiple_of(ResolveArguments::ALIGNMENT)
        && (ResolveArguments::SLOTS_OFFSET as u64).is_multiple_of(ResolveArguments::ALIGNMENT)
        && GeneratedSequence::VERTEX_BUFFER_BYTES as u64 == ResolveArguments::ALIGNMENT
        && ResolveArguments::SLOT_BYTES as u64 == ResolveArguments::ALIGNMENT
);

/// The offsets of what a dynamic kernel's dispatch reads at the push
/// constants' `arguments`: the stage-in region's origin and size, where a
/// stage-in kernel's arguments hold them, then the `u32` threadgroup shape
/// and each threadgroup buffer's `u32` offset in threadgroup memory, by
/// Metal index ([`Specialization::dynamic_threadgroups`]).
///
/// [`Specialization::dynamic_threadgroups`]: super::shader::Specialization::dynamic_threadgroups
pub struct DispatchArguments;

impl DispatchArguments {
    pub const REGION_OFFSET: u32 = 0;
    pub const SHAPE_OFFSET: u32 = 24;
    pub const OFFSETS_OFFSET: u32 = 36;
    /// Each buffer's attribute stride, by Metal index, which stage-in
    /// layouts of a dynamic stride read.
    pub const STRIDES_OFFSET: u32 = Self::OFFSETS_OFFSET + 4 * MAX_BUFFER_BINDINGS;
    /// A tile dispatch's tile: its width in the low half of a `u32` and its
    /// height in the high half, the `u32` bytes of each tile's threadgroup
    /// memory that persist across the pass's dispatches, and the `u64`
    /// address of the memory that holds them, tile after tile in rows.
    pub const TILE_OFFSET: u32 =
        (Self::STRIDES_OFFSET + 4 * MAX_BUFFER_BINDINGS).next_multiple_of(16);
    pub const BYTES: u32 = Self::TILE_OFFSET + 16;
    pub const ALIGNMENT: u64 = 16;
}

/// The offsets of a command's device-generated sequence, which the resolve
/// kernels write and each indirect commands layout reads at its own token
/// offsets: the execution set index and push constants, then a render
/// command's index buffer, vertex buffers and draws, and a patch draw's
/// [`TessellationArguments`] its push constants' `arguments` address, or a
/// compute command's dispatch and the [`DispatchArguments`] its push
/// constants' `arguments` address.
pub struct GeneratedSequence;

impl GeneratedSequence {
    /// The `u32` execution set index.
    pub const PIPELINE_OFFSET: u32 = 0;
    pub const PUSH_OFFSET: u32 = 8;
    /// `VkBindIndexBufferIndirectCommandEXT`.
    pub const INDEX_BUFFER_OFFSET: u32 = 72;
    /// A [`SequenceVertexBuffer`] per vertex buffer index.
    pub const VERTEX_BUFFERS_OFFSET: u32 = 88;
    pub const VERTEX_BUFFER_BYTES: u32 = 16;
    /// `VkDrawIndirectCommand`.
    pub const DRAW_OFFSET: u32 = 584;
    /// `VkDrawIndexedIndirectCommand`.
    pub const DRAW_INDEXED_OFFSET: u32 = 600;
    /// `VkDispatchIndirectCommand`.
    pub const DISPATCH_OFFSET: u32 = 72;
    pub const DISPATCH_ARGUMENTS_OFFSET: u32 = 96;
    /// [`TessellationArguments`].
    pub const TESSELLATION_OFFSET: u32 = 624;
    pub const BYTES: u32 = 816;
    pub const ALIGNMENT: u64 = 16;
}

const _: () = assert!(
    GeneratedSequence::PUSH_OFFSET + PushConstants::BYTES <= GeneratedSequence::INDEX_BUFFER_OFFSET
        && GeneratedSequence::VERTEX_BUFFERS_OFFSET
            + GeneratedSequence::VERTEX_BUFFER_BYTES * MAX_BUFFER_BINDINGS
            == GeneratedSequence::DRAW_OFFSET
        && GeneratedSequence::DRAW_OFFSET + 16 == GeneratedSequence::DRAW_INDEXED_OFFSET
        && GeneratedSequence::DRAW_INDEXED_OFFSET + 20 <= GeneratedSequence::BYTES
        && GeneratedSequence::PUSH_OFFSET + PushConstants::BYTES
            <= GeneratedSequence::DISPATCH_OFFSET
        && GeneratedSequence::DISPATCH_OFFSET + 12 <= GeneratedSequence::DISPATCH_ARGUMENTS_OFFSET
        && (GeneratedSequence::DISPATCH_ARGUMENTS_OFFSET as u64)
            .is_multiple_of(DispatchArguments::ALIGNMENT)
        && GeneratedSequence::DISPATCH_ARGUMENTS_OFFSET + DispatchArguments::BYTES
            <= GeneratedSequence::BYTES
        && GeneratedSequence::DRAW_INDEXED_OFFSET + 20 <= GeneratedSequence::TESSELLATION_OFFSET
        && (GeneratedSequence::TESSELLATION_OFFSET as u64)
            .is_multiple_of(TessellationArguments::ALIGNMENT)
        && GeneratedSequence::TESSELLATION_OFFSET + TessellationArguments::BYTES
            <= GeneratedSequence::BYTES
        && (GeneratedSequence::BYTES as u64).is_multiple_of(GeneratedSequence::ALIGNMENT)
);

struct Writer<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl Writer<'_> {
    fn u32(&mut self, value: u32) {
        self.bytes[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());
        self.offset += 4;
    }

    fn u64(&mut self, value: u64) {
        self.bytes[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());
        self.offset += 8;
    }
}

/// Descriptor counts of each heap array, within the device's
/// update-after-bind limits. Texel buffers count against the image limits,
/// so they take a quarter of each.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapLayout {
    pub counts: [u32; 5],
}

impl HeapLayout {
    pub fn new(limits: &Limits) -> Self {
        let sampled = limits
            .max_descriptor_set_update_after_bind_sampled_images
            .min(limits.max_per_stage_update_after_bind_sampled_images);
        let storage = limits
            .max_descriptor_set_update_after_bind_storage_images
            .min(limits.max_per_stage_update_after_bind_storage_images);
        let samplers = limits
            .max_descriptor_set_update_after_bind_samplers
            .min(limits.max_per_stage_update_after_bind_samplers)
            .min(limits.max_sampler_allocation_count);
        // Storage indices leave the high half's flag and level count bits free.
        let storage = storage.min(ResourceId::MAX_STORAGE);
        Self {
            counts: [
                sampled - sampled / 4,
                storage - storage / 4,
                samplers,
                sampled / 4,
                storage / 4,
            ],
        }
    }

    pub fn count(&self, array: HeapArray) -> u32 {
        self.counts[array.raw() as usize]
    }
}

/// Allocates runs of consecutive indices in one heap array, first fit.
/// Released runs are reused only after the GPU completes the submission that
/// last could read them, and adjacent free runs merge.
#[derive(Clone, Debug)]
pub struct DescriptorIndices {
    /// Free runs as first index to length; no two are adjacent.
    free: BTreeMap<u32, u32>,
    /// (serial, first index, length) in release order; serials never
    /// decrease.
    retiring: VecDeque<(u64, u32, u32)>,
    in_use: u32,
}

impl DescriptorIndices {
    pub fn new(count: u32) -> Self {
        let first = NULL_DESCRIPTOR + 1;
        Self {
            free: (count > first)
                .then_some((first, count - first))
                .into_iter()
                .collect(),
            retiring: VecDeque::new(),
            in_use: 0,
        }
    }

    pub fn allocate(&mut self) -> Result<u32> {
        self.allocate_run(1)
    }

    /// The first of `length` consecutive indices.
    pub fn allocate_run(&mut self, length: u32) -> Result<u32> {
        debug_assert!(length > 0);
        let (&first, &free) = self
            .free
            .iter()
            .find(|&(_, &free)| free >= length)
            .ok_or(Error::OutOfMemory)?;
        self.free.remove(&first);
        if free > length {
            self.free.insert(first + length, free - length);
        }
        self.in_use += length;
        Ok(first)
    }

    pub fn release(&mut self, index: u32, serial: u64) {
        self.release_run(index, 1, serial);
    }

    /// Releases a run once submission `serial` completes. Callers pass the
    /// last submitted serial, which never decreases.
    pub fn release_run(&mut self, first: u32, length: u32, serial: u64) {
        debug_assert!(first != NULL_DESCRIPTOR && length > 0);
        debug_assert!(
            self.retiring
                .back()
                .is_none_or(|&(last, ..)| last <= serial)
        );
        self.retiring.push_back((serial, first, length));
    }

    /// Returns runs whose submissions have completed to the free runs.
    pub fn retire(&mut self, completed: u64) {
        while let Some(&(serial, mut first, mut length)) = self.retiring.front() {
            if serial > completed {
                break;
            }
            self.retiring.pop_front();
            self.in_use -= length;
            if let Some((&before, &free)) = self.free.range(..first).next_back()
                && before + free == first
            {
                self.free.remove(&before);
                (first, length) = (before, free + length);
            }
            if let Some(after) = self.free.remove(&(first + length)) {
                length += after;
            }
            self.free.insert(first, length);
        }
    }

    pub fn in_use(&self) -> u32 {
        self.in_use
    }

    /// Indices released but not yet past the GPU.
    pub fn retiring(&self) -> u32 {
        self.retiring.iter().map(|&(_, _, length)| length).sum()
    }
}

/// The device's descriptor heap allocator.
#[derive(Clone, Debug)]
pub struct DescriptorHeap {
    layout: HeapLayout,
    arrays: [DescriptorIndices; 5],
}

impl DescriptorHeap {
    pub fn new(layout: HeapLayout) -> Self {
        Self {
            layout,
            arrays: layout.counts.map(DescriptorIndices::new),
        }
    }

    pub fn layout(&self) -> HeapLayout {
        self.layout
    }

    pub fn allocate(&mut self, array: HeapArray) -> Result<u32> {
        self.arrays[array.raw() as usize].allocate()
    }

    pub fn allocate_run(&mut self, array: HeapArray, length: u32) -> Result<u32> {
        self.arrays[array.raw() as usize].allocate_run(length)
    }

    pub fn release_run(&mut self, array: HeapArray, first: u32, length: u32, serial: u64) {
        self.arrays[array.raw() as usize].release_run(first, length, serial);
    }

    pub fn retire(&mut self, completed: u64) {
        self.arrays
            .iter_mut()
            .for_each(|array| array.retire(completed));
    }

    pub fn in_use(&self, array: HeapArray) -> u32 {
        self.arrays[array.raw() as usize].in_use()
    }

    pub fn retiring(&self, array: HeapArray) -> u32 {
        self.arrays[array.raw() as usize].retiring()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::{
        abi::{TessellationFactorStepFunction, TessellationPartitionMode, Winding},
        indirect::{IndirectPipeline, RecordLayout},
        nvidia::{CHIPS, fixture::nvk},
        vertex::{StageInStep, StepFunction},
    };

    #[test]
    fn plane_flags_match_the_compiler() {
        // metal_abi.c's texture_planes gathers them into these values.
        let header = include_str!("../compiler/air_to_nir.h");
        for (name, value) in [
            ("STELA_AIR_PLANES_YCBCR = ", 4),
            ("STELA_AIR_PLANES_TEN_BIT = ", 8),
            ("STELA_AIR_PLANES_VIDEO = ", 16),
        ] {
            let declared = header
                .split(name)
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap();
            assert_eq!(declared.parse::<u32>().unwrap(), value);
        }
        assert_eq!(ResourceId::YCBCR, 4 << ResourceId::PLANES_SHIFT);
        assert_eq!(ResourceId::TEN_BIT, 1 << (ResourceId::PLANES_SHIFT - 1));
        assert_eq!(ResourceId::VIDEO_RANGE, 1 << (ResourceId::PLANES_SHIFT - 2));
    }

    #[test]
    fn texture_ids_carry_their_planes_beside_the_filter_class() {
        use crate::metal::pixel_format::{FilterClass, Planes};
        let id = ResourceId::new(7, 0).with_filter_class(FilterClass::Unorm);
        for planes in [Planes::Full, Planes::Horizontal, Planes::Both] {
            for flags in [
                0,
                ResourceId::YCBCR,
                ResourceId::TEN_BIT,
                ResourceId::YCBCR | ResourceId::TEN_BIT | ResourceId::VIDEO_RANGE,
            ] {
                let planar = id.with_planes(planes, flags);
                assert_eq!(planar.low(), 7);
                assert_eq!(planar.high() >> ResourceId::PLANES_SHIFT & 3, planes as u32);
                let mask = ResourceId::YCBCR | ResourceId::TEN_BIT | ResourceId::VIDEO_RANGE;
                assert_eq!(planar.high() & mask, flags);
                assert_eq!(planar.with_filter_class(FilterClass::Unorm), planar);
                assert_eq!(
                    planar.high() & (ResourceId::MAX_STORAGE - 1),
                    flags & (ResourceId::TEN_BIT | ResourceId::VIDEO_RANGE)
                );
            }
        }
    }

    #[test]
    fn fragment_test_words_match_the_compiler() {
        let header = include_str!("../compiler/air_to_nir.h");
        let define = |name: &str| -> u32 {
            header
                .lines()
                .find_map(|line| {
                    let value = line.strip_prefix("#define ")?.strip_prefix(name)?;
                    value.strip_prefix(' ')?.strip_suffix('u')?.parse().ok()
                })
                .unwrap_or_else(|| panic!("air_to_nir.h does not define {name}"))
        };
        assert_eq!(define("STELA_AIR_DEPTH_WRITE"), FragmentTests::DEPTH_WRITE);
        assert_eq!(
            define("STELA_AIR_DEPTH_FORMAT_SHIFT"),
            FragmentTests::DEPTH_FORMAT_SHIFT
        );
        assert_eq!(
            define("STELA_AIR_DEPTH_STENCIL_ATTACHED"),
            FragmentTests::STENCIL_ATTACHED
        );
        assert_eq!(define("STELA_AIR_DEPTH_CLAMP"), FragmentTests::DEPTH_CLAMP);
    }

    #[test]
    fn compiler_header_matches_the_layouts() {
        let header = include_str!("../compiler/metal_abi.h");
        let define = |name: &str| -> u32 {
            header
                .lines()
                .find_map(|line| {
                    let value = line.strip_prefix("#define ")?.strip_prefix(name)?;
                    let value = value.strip_prefix(' ')?.strip_suffix('u')?;
                    match value.strip_prefix("0x") {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => value.parse().ok(),
                    }
                })
                .unwrap_or_else(|| panic!("metal_abi.h does not define {name}"))
        };
        let expected = [
            ("STELA_METAL_PUSH_BYTES", PushConstants::BYTES),
            ("STELA_METAL_PUSH_TABLES", PushConstants::TABLES_OFFSET),
            (
                "STELA_METAL_PUSH_ARGUMENTS",
                PushConstants::ARGUMENTS_OFFSET,
            ),
            ("STELA_METAL_PUSH_LOG", PushConstants::LOG_OFFSET),
            ("STELA_METAL_PUSH_GRID", PushConstants::GRID_OFFSET),
            (
                "STELA_METAL_PUSH_AMPLIFICATION",
                PushConstants::AMPLIFICATION_OFFSET,
            ),
            (
                "STELA_METAL_PUSH_VIEW_MAPPING",
                PushConstants::VIEW_MAPPING_OFFSET,
            ),
            (
                "STELA_METAL_PUSH_AMPLIFICATIONS",
                PushConstants::AMPLIFICATIONS_OFFSET,
            ),
            ("STELA_METAL_BUFFERS", MAX_BUFFER_BINDINGS),
            ("STELA_METAL_TEXTURES", MAX_TEXTURE_BINDINGS),
            ("STELA_METAL_SAMPLERS", MAX_SAMPLER_BINDINGS),
            ("STELA_METAL_HEAP_SET", HEAP_SET),
            ("STELA_METAL_LEVEL_SHIFT", ResourceId::LEVEL_SHIFT),
            ("STELA_METAL_SAMPLER_NEVER", ResourceId::SAMPLER_NEVER),
            ("STELA_METAL_POOL_VIEW", ResourceId::POOL_VIEW),
            ("STELA_METAL_SRGB_STORAGE", ResourceId::SRGB_STORAGE),
            (
                "STELA_METAL_FILTER_CLASS_SHIFT",
                ResourceId::FILTER_CLASS_SHIFT,
            ),
            ("STELA_METAL_PLANES_SHIFT", ResourceId::PLANES_SHIFT),
            ("STELA_METAL_EXTENDED_STORAGE", ResourceId::EXTENDED_STORAGE),
            ("STELA_METAL_SAMPLER_CUBIC", ResourceId::SAMPLER_CUBIC),
            ("STELA_METAL_SAMPLER_MIPPED", ResourceId::SAMPLER_MIPPED),
            ("STELA_METAL_SAMPLER_PIXELS", ResourceId::SAMPLER_PIXELS),
            (
                "STELA_METAL_TABLE_BUFFER_ADDRESSES",
                ArgumentTable::BUFFER_ADDRESSES_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_BUFFER_LENGTHS",
                ArgumentTable::BUFFER_LENGTHS_OFFSET,
            ),
            ("STELA_METAL_TABLE_TEXTURES", ArgumentTable::TEXTURES_OFFSET),
            ("STELA_METAL_TABLE_SAMPLERS", ArgumentTable::SAMPLERS_OFFSET),
            (
                "STELA_METAL_TABLE_ATTACHMENTS",
                ArgumentTable::ATTACHMENTS_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_SAMPLE_POSITIONS",
                ArgumentTable::SAMPLE_POSITIONS_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_SAMPLE_COUNT",
                ArgumentTable::SAMPLE_COUNT_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_BLEND_COLOR",
                ArgumentTable::BLEND_COLOR_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_IMAGEBLOCK",
                ArgumentTable::IMAGEBLOCK_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_DEPTH_STENCIL",
                ArgumentTable::DEPTH_STENCIL_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_DEPTH_RANGE",
                ArgumentTable::DEPTH_RANGE_OFFSET,
            ),
            (
                "STELA_METAL_TABLE_DEPTH_COPIES",
                ArgumentTable::DEPTH_COPIES_OFFSET,
            ),
            ("STELA_METAL_TABLE_BYTES", ArgumentTable::BYTES),
            (
                "STELA_METAL_ACCUMULATE_RESULTS",
                AccumulateArguments::RESULTS_OFFSET,
            ),
            (
                "STELA_METAL_ACCUMULATE_COUNT",
                AccumulateArguments::COUNT_OFFSET,
            ),
            (
                "STELA_METAL_ACCUMULATE_STRIDE",
                AccumulateArguments::STRIDE_OFFSET,
            ),
            (
                "STELA_METAL_ACCUMULATE_RUNS",
                AccumulateArguments::RUNS_OFFSET,
            ),
            (
                "STELA_METAL_ACCUMULATE_RUN_BYTES",
                AccumulateArguments::RUN_BYTES,
            ),
            ("STELA_METAL_TEXELS_BUFFER", TexelArguments::BUFFER_OFFSET),
            ("STELA_METAL_TEXELS_COUNT", TexelArguments::COUNT_OFFSET),
            (
                "STELA_METAL_TEXELS_ENCODING",
                TexelArguments::ENCODING_OFFSET,
            ),
            ("STELA_METAL_TEXELS_IMAGE", TexelArguments::IMAGE_OFFSET),
            ("STELA_METAL_TEXELS_WIDTH", TexelArguments::WIDTH_OFFSET),
            ("STELA_METAL_TEXELS_HEIGHT", TexelArguments::HEIGHT_OFFSET),
            ("STELA_METAL_TEXELS_ROW", TexelArguments::ROW_OFFSET),
            (
                "STELA_METAL_TEXELS_IMAGE_BYTES",
                TexelArguments::IMAGE_BYTES_OFFSET,
            ),
            ("STELA_METAL_TEXELS_ORIGIN", TexelArguments::ORIGIN_OFFSET),
            ("STELA_METAL_TEXELS_ALPHA", TexelArguments::ALPHA_OFFSET),
            (
                "STELA_METAL_TEXELS_ALPHA_ROW",
                TexelArguments::ALPHA_ROW_OFFSET,
            ),
            ("STELA_METAL_TEXELS_BYTES", TexelArguments::BYTES),
            (
                "STELA_METAL_AVERAGE_SOURCE",
                AverageArguments::SOURCE_OFFSET,
            ),
            (
                "STELA_METAL_AVERAGE_DESTINATION",
                AverageArguments::DESTINATION_OFFSET,
            ),
            ("STELA_METAL_AVERAGE_COUNT", AverageArguments::COUNT_OFFSET),
            (
                "STELA_METAL_AVERAGE_FORMAT",
                AverageArguments::FORMAT_OFFSET,
            ),
            ("STELA_METAL_AVERAGE_WIDTH", AverageArguments::WIDTH_OFFSET),
            (
                "STELA_METAL_AVERAGE_HEIGHT",
                AverageArguments::HEIGHT_OFFSET,
            ),
            (
                "STELA_METAL_AVERAGE_SAMPLES",
                AverageArguments::SAMPLES_OFFSET,
            ),
            ("STELA_METAL_AVERAGE_DEPTH", AverageArguments::DEPTH_OFFSET),
            ("STELA_METAL_AVERAGE_BYTES", AverageArguments::BYTES),
            (
                "STELA_METAL_AVERAGE_FOLLOW_DEPTH",
                AverageArguments::FOLLOW_DEPTH,
            ),
            (
                "STELA_METAL_AVERAGE_FOLLOW_MAX",
                AverageArguments::FOLLOW_MAX,
            ),
            ("STELA_METAL_REORDER_ROWS", ReorderArguments::ROWS_OFFSET),
            ("STELA_METAL_REORDER_LEVEL", ReorderArguments::LEVEL_OFFSET),
            ("STELA_METAL_REORDER_COUNT", ReorderArguments::COUNT_OFFSET),
            (
                "STELA_METAL_REORDER_TO_ROWS",
                ReorderArguments::TO_ROWS_OFFSET,
            ),
            (
                "STELA_METAL_REORDER_COLUMNS",
                ReorderArguments::COLUMNS_OFFSET,
            ),
            (
                "STELA_METAL_REORDER_LEVEL_ROWS",
                ReorderArguments::LEVEL_ROWS_OFFSET,
            ),
            (
                "STELA_METAL_REORDER_ORIGIN",
                ReorderArguments::ORIGIN_OFFSET,
            ),
            ("STELA_METAL_REORDER_WIDTH", ReorderArguments::WIDTH_OFFSET),
            (
                "STELA_METAL_REORDER_ROW_BYTES",
                ReorderArguments::ROW_BYTES_OFFSET,
            ),
            ("STELA_METAL_REORDER_BYTES", ReorderArguments::BYTES),
            (
                "STELA_METAL_INDIRECT_HEADER_BYTES",
                RecordLayout::HEADER_BYTES,
            ),
            ("STELA_METAL_INDIRECT_STRIDE", RecordLayout::HEADER_STRIDE),
            ("STELA_METAL_INDIRECT_COUNT", RecordLayout::HEADER_COUNT),
            ("STELA_METAL_INDIRECT_TABLES", RecordLayout::HEADER_TABLES),
            (
                "STELA_METAL_INDIRECT_TABLE_SLOTS",
                RecordLayout::HEADER_TABLE_SLOTS,
            ),
            ("STELA_METAL_INDIRECT_WORDS", RecordLayout::HEADER_WORDS),
            (
                "STELA_METAL_INDIRECT_WORD_COUNT",
                RecordLayout::HEADER_WORD_COUNT,
            ),
            ("STELA_METAL_INDIRECT_STRIDES", RecordLayout::HEADER_STRIDES),
            (
                "STELA_METAL_INDIRECT_STRIDE_COUNT",
                RecordLayout::HEADER_STRIDE_COUNT,
            ),
            ("STELA_METAL_RECORD_ACTION", RecordLayout::ACTION),
            ("STELA_METAL_RECORD_BARRIER", RecordLayout::BARRIER),
            ("STELA_METAL_RECORD_PIPELINE", RecordLayout::PIPELINE),
            ("STELA_METAL_RECORD_VERTICES", RecordLayout::VERTICES),
            ("STELA_METAL_RECORD_INSTANCES", RecordLayout::INSTANCES),
            (
                "STELA_METAL_RECORD_FIRST_VERTEX",
                RecordLayout::FIRST_VERTEX,
            ),
            ("STELA_METAL_RECORD_BASE_VERTEX", RecordLayout::BASE_VERTEX),
            (
                "STELA_METAL_RECORD_BASE_INSTANCE",
                RecordLayout::BASE_INSTANCE,
            ),
            ("STELA_METAL_RECORD_PRIMITIVE", RecordLayout::PRIMITIVE),
            (
                "STELA_METAL_RECORD_INDEX_ADDRESS",
                RecordLayout::INDEX_ADDRESS,
            ),
            (
                "STELA_METAL_RECORD_INDEX_LENGTH",
                RecordLayout::INDEX_LENGTH,
            ),
            ("STELA_METAL_RECORD_INDEX_TYPE", RecordLayout::INDEX_TYPE),
            ("STELA_METAL_RECORD_GRID", RecordLayout::GRID),
            ("STELA_METAL_RECORD_THREADS", RecordLayout::THREADS),
            (
                "STELA_METAL_RECORD_STAGE_IN_ORIGIN",
                RecordLayout::STAGE_IN_ORIGIN,
            ),
            (
                "STELA_METAL_RECORD_STAGE_IN_SIZE",
                RecordLayout::STAGE_IN_SIZE,
            ),
            ("STELA_METAL_RECORD_STAGE_IN", RecordLayout::STAGE_IN),
            ("STELA_METAL_RECORD_DRAW", RecordLayout::DRAW),
            (
                "STELA_METAL_RECORD_DRAW_INDEXED",
                RecordLayout::DRAW_INDEXED,
            ),
            (
                "STELA_METAL_RECORD_DRAW_PATCHES",
                RecordLayout::DRAW_PATCHES,
            ),
            (
                "STELA_METAL_RECORD_DRAW_INDEXED_PATCHES",
                RecordLayout::DRAW_INDEXED_PATCHES,
            ),
            (
                "STELA_METAL_RECORD_CONTROL_POINTS",
                RecordLayout::CONTROL_POINTS,
            ),
            (
                "STELA_METAL_RECORD_CONTROL_POINT_INDICES",
                RecordLayout::CONTROL_POINT_INDICES,
            ),
            (
                "STELA_METAL_RECORD_CONTROL_POINT_INDEX_LENGTH",
                RecordLayout::CONTROL_POINT_INDEX_LENGTH,
            ),
            (
                "STELA_METAL_RECORD_INSTANCE_STRIDE",
                RecordLayout::INSTANCE_STRIDE,
            ),
            (
                "STELA_METAL_RECORD_PATCH_INDICES",
                RecordLayout::PATCH_INDICES,
            ),
            ("STELA_METAL_RECORD_FACTORS", RecordLayout::FACTORS),
            (
                "STELA_METAL_RECORD_PATCH_INDEX_LENGTH",
                RecordLayout::PATCH_INDEX_LENGTH,
            ),
            (
                "STELA_METAL_RECORD_FACTOR_LENGTH",
                RecordLayout::FACTOR_LENGTH,
            ),
            (
                "STELA_METAL_RECORD_FACTOR_SCALE",
                RecordLayout::FACTOR_SCALE,
            ),
            ("STELA_METAL_RECORD_SCALED", RecordLayout::SCALED),
            ("STELA_METAL_RECORD_DISPATCH", RecordLayout::DISPATCH),
            (
                "STELA_METAL_RECORD_DISPATCH_THREADS",
                RecordLayout::DISPATCH_THREADS,
            ),
            (
                "STELA_METAL_RECORD_COMPUTE_PIPELINES",
                IndirectPipeline::COMPUTE_CLASS + 1,
            ),
            (
                "STELA_METAL_RESOLVE_HEADER",
                ResolveArguments::HEADER_OFFSET,
            ),
            ("STELA_METAL_RESOLVE_RANGE", ResolveArguments::RANGE_OFFSET),
            (
                "STELA_METAL_RESOLVE_SEQUENCES",
                ResolveArguments::SEQUENCES_OFFSET,
            ),
            (
                "STELA_METAL_RESOLVE_COUNTS",
                ResolveArguments::COUNTS_OFFSET,
            ),
            (
                "STELA_METAL_RESOLVE_TABLES",
                ResolveArguments::TABLES_OFFSET,
            ),
            (
                "STELA_METAL_RESOLVE_STRIDES",
                ResolveArguments::STRIDES_OFFSET,
            ),
            ("STELA_METAL_RESOLVE_COUNT", ResolveArguments::COUNT_OFFSET),
            ("STELA_METAL_RESOLVE_FIRST", ResolveArguments::FIRST_OFFSET),
            (
                "STELA_METAL_RESOLVE_SLOT_COUNT",
                ResolveArguments::SLOT_COUNT_OFFSET,
            ),
            ("STELA_METAL_RESOLVE_FLAGS", ResolveArguments::FLAGS_OFFSET),
            (
                "STELA_METAL_RESOLVE_CLASS_COUNT",
                ResolveArguments::CLASS_COUNT_OFFSET,
            ),
            (
                "STELA_METAL_RESOLVE_FACTOR_SCALE",
                ResolveArguments::FACTOR_SCALE_OFFSET,
            ),
            ("STELA_METAL_RESOLVE_SCALES", ResolveArguments::SCALES),
            ("STELA_METAL_RESOLVE_PUSH", ResolveArguments::PUSH_OFFSET),
            (
                "STELA_METAL_RESOLVE_VERTEX_BUFFERS",
                ResolveArguments::VERTEX_BUFFERS_OFFSET,
            ),
            ("STELA_METAL_RESOLVE_SLOTS", ResolveArguments::SLOTS_OFFSET),
            (
                "STELA_METAL_RESOLVE_SLOT_BYTES",
                ResolveArguments::SLOT_BYTES,
            ),
            (
                "STELA_METAL_RESOLVE_INHERIT_PIPELINE",
                ResolveArguments::INHERIT_PIPELINE,
            ),
            (
                "STELA_METAL_RESOLVE_INHERIT_BUFFERS",
                ResolveArguments::INHERIT_BUFFERS,
            ),
            (
                "STELA_METAL_DISPATCH_REGION",
                DispatchArguments::REGION_OFFSET,
            ),
            (
                "STELA_METAL_DISPATCH_SHAPE",
                DispatchArguments::SHAPE_OFFSET,
            ),
            (
                "STELA_METAL_DISPATCH_OFFSETS",
                DispatchArguments::OFFSETS_OFFSET,
            ),
            (
                "STELA_METAL_DISPATCH_STRIDES",
                DispatchArguments::STRIDES_OFFSET,
            ),
            ("STELA_METAL_DISPATCH_TILE", DispatchArguments::TILE_OFFSET),
            ("STELA_METAL_DISPATCH_BYTES", DispatchArguments::BYTES),
            (
                "STELA_METAL_SEQUENCE_PIPELINE",
                GeneratedSequence::PIPELINE_OFFSET,
            ),
            ("STELA_METAL_SEQUENCE_PUSH", GeneratedSequence::PUSH_OFFSET),
            (
                "STELA_METAL_SEQUENCE_DISPATCH",
                GeneratedSequence::DISPATCH_OFFSET,
            ),
            (
                "STELA_METAL_SEQUENCE_DISPATCH_ARGUMENTS",
                GeneratedSequence::DISPATCH_ARGUMENTS_OFFSET,
            ),
            (
                "STELA_METAL_SEQUENCE_TESSELLATION",
                GeneratedSequence::TESSELLATION_OFFSET,
            ),
            (
                "STELA_METAL_SEQUENCE_INDEX_BUFFER",
                GeneratedSequence::INDEX_BUFFER_OFFSET,
            ),
            (
                "STELA_METAL_SEQUENCE_VERTEX_BUFFERS",
                GeneratedSequence::VERTEX_BUFFERS_OFFSET,
            ),
            (
                "STELA_METAL_SEQUENCE_VERTEX_BUFFER_BYTES",
                GeneratedSequence::VERTEX_BUFFER_BYTES,
            ),
            ("STELA_METAL_SEQUENCE_DRAW", GeneratedSequence::DRAW_OFFSET),
            (
                "STELA_METAL_SEQUENCE_DRAW_INDEXED",
                GeneratedSequence::DRAW_INDEXED_OFFSET,
            ),
            ("STELA_METAL_SEQUENCE_BYTES", GeneratedSequence::BYTES),
            ("STELA_METAL_SELECT_RANGE", SelectArguments::RANGE_OFFSET),
            ("STELA_METAL_SELECT_FLAGS", SelectArguments::FLAGS_OFFSET),
            ("STELA_METAL_SELECT_COUNT", SelectArguments::COUNT_OFFSET),
            (
                "STELA_METAL_KERNEL_WORKGROUP",
                AccumulateArguments::WORKGROUP_SIZE,
            ),
            (
                "STELA_METAL_TESSELLATION_FACTORS",
                TessellationArguments::FACTORS_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_PATCH_INDICES",
                TessellationArguments::PATCH_INDICES_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_CONTROL_POINT_INDICES",
                TessellationArguments::CONTROL_POINT_INDICES_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_INSTANCE_STRIDE",
                TessellationArguments::INSTANCE_STRIDE_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_FACTOR_SCALE",
                TessellationArguments::FACTOR_SCALE_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_CONTROL_POINTS",
                TessellationArguments::CONTROL_POINTS_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_STRIDES",
                TessellationArguments::STRIDES_OFFSET,
            ),
            (
                "STELA_METAL_TESSELLATION_BYTES",
                TessellationArguments::BYTES,
            ),
        ];
        for (name, value) in expected {
            assert_eq!(define(name), value, "{name}");
        }
        // C enums count from zero in declaration order.
        let enumerators = |name: &str| -> Vec<&str> {
            let body = header
                .split(&alloc::format!("enum {name} {{"))
                .nth(1)
                .and_then(|rest| rest.split('}').next())
                .unwrap_or_else(|| panic!("metal_abi.h does not declare {name}"));
            body.lines()
                .filter_map(|line| line.trim().split(',').next())
                .filter(|enumerator| enumerator.starts_with("STELA_"))
                .collect()
        };
        let check_enum = |name: &str, values: &[(&str, u64)]| {
            let declared = enumerators(name);
            assert_eq!(declared.len(), values.len(), "{name}");
            for &(enumerator, raw) in values {
                assert_eq!(
                    declared.iter().position(|&declared| declared == enumerator),
                    Some(raw as usize),
                    "{enumerator}"
                );
            }
        };
        // The block codecs count from one, as their encodings.
        let codecs: Vec<&str> = enumerators("stela_metal_block_codec")
            .into_iter()
            .map(|enumerator| enumerator.trim_end_matches(" = 1"))
            .collect();
        use crate::metal::pixel_format::Codec;
        let expected = [
            ("STELA_METAL_BLOCKS_ETC2_RGB8", Codec::Etc2Rgb8),
            ("STELA_METAL_BLOCKS_ETC2_RGB8A1", Codec::Etc2Rgb8A1),
            ("STELA_METAL_BLOCKS_EAC_RGBA8", Codec::EacRgba8),
            ("STELA_METAL_BLOCKS_EAC_R11", Codec::EacR11),
            ("STELA_METAL_BLOCKS_EAC_R11_SNORM", Codec::EacR11Snorm),
            ("STELA_METAL_BLOCKS_EAC_RG11", Codec::EacRg11),
            ("STELA_METAL_BLOCKS_EAC_RG11_SNORM", Codec::EacRg11Snorm),
            ("STELA_METAL_BLOCKS_PVRTC_4BPP", Codec::Pvrtc4),
            ("STELA_METAL_BLOCKS_PVRTC_2BPP", Codec::Pvrtc2),
            ("STELA_METAL_BLOCKS_ASTC", Codec::Astc),
            ("STELA_METAL_BLOCKS_ASTC_SRGB", Codec::AstcSrgb),
            ("STELA_METAL_BLOCKS_ASTC_HDR", Codec::AstcHdr),
        ];
        assert_eq!(codecs.len(), expected.len());
        for (enumerator, codec) in expected {
            assert_eq!(
                codecs.iter().position(|&declared| declared == enumerator),
                Some(codec as usize - 1),
                "{enumerator}"
            );
        }
        check_enum(
            "stela_metal_heap_array",
            &[
                (
                    "STELA_METAL_HEAP_SAMPLED_IMAGES",
                    HeapArray::SampledImages.raw().into(),
                ),
                (
                    "STELA_METAL_HEAP_STORAGE_IMAGES",
                    HeapArray::StorageImages.raw().into(),
                ),
                (
                    "STELA_METAL_HEAP_SAMPLERS",
                    HeapArray::Samplers.raw().into(),
                ),
                (
                    "STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS",
                    HeapArray::UniformTexelBuffers.raw().into(),
                ),
                (
                    "STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS",
                    HeapArray::StorageTexelBuffers.raw().into(),
                ),
            ],
        );
        check_enum(
            "stela_metal_table",
            &[
                ("STELA_METAL_TABLE_PRIMARY", TableSlot::Primary.raw().into()),
                (
                    "STELA_METAL_TABLE_FRAGMENT",
                    TableSlot::Fragment.raw().into(),
                ),
                ("STELA_METAL_TABLE_MESH", TableSlot::Mesh.raw().into()),
            ],
        );
        check_enum(
            "stela_metal_partition",
            &[
                (
                    "STELA_METAL_PARTITION_POW2",
                    TessellationPartitionMode::Pow2.raw(),
                ),
                (
                    "STELA_METAL_PARTITION_INTEGER",
                    TessellationPartitionMode::Integer.raw(),
                ),
                (
                    "STELA_METAL_PARTITION_FRACTIONAL_ODD",
                    TessellationPartitionMode::FractionalOdd.raw(),
                ),
                (
                    "STELA_METAL_PARTITION_FRACTIONAL_EVEN",
                    TessellationPartitionMode::FractionalEven.raw(),
                ),
            ],
        );
        check_enum(
            "stela_metal_factor_step",
            &[
                (
                    "STELA_METAL_FACTOR_STEP_CONSTANT",
                    TessellationFactorStepFunction::Constant.raw(),
                ),
                (
                    "STELA_METAL_FACTOR_STEP_PER_PATCH",
                    TessellationFactorStepFunction::PerPatch.raw(),
                ),
                (
                    "STELA_METAL_FACTOR_STEP_PER_INSTANCE",
                    TessellationFactorStepFunction::PerInstance.raw(),
                ),
                (
                    "STELA_METAL_FACTOR_STEP_PER_PATCH_AND_PER_INSTANCE",
                    TessellationFactorStepFunction::PerPatchAndPerInstance.raw(),
                ),
            ],
        );
        let steps = [
            StepFunction::Constant.raw(),
            StepFunction::PerVertex.raw(),
            StepFunction::PerInstance.raw(),
            StepFunction::PerPatch.raw(),
            StepFunction::PerPatchControlPoint.raw(),
            StageInStep::ThreadPositionInGridX.raw(),
            StageInStep::ThreadPositionInGridY.raw(),
            StageInStep::ThreadPositionInGridXIndexed.raw(),
            StageInStep::ThreadPositionInGridYIndexed.raw(),
        ];
        let names = [
            "CONSTANT",
            "PER_VERTEX",
            "PER_INSTANCE",
            "PER_PATCH",
            "PER_PATCH_CONTROL_POINT",
            "THREAD_POSITION_IN_GRID_X",
            "THREAD_POSITION_IN_GRID_Y",
            "THREAD_POSITION_IN_GRID_X_INDEXED",
            "THREAD_POSITION_IN_GRID_Y_INDEXED",
        ]
        .map(|name| alloc::format!("STELA_METAL_STEP_{name}"));
        let values: Vec<_> = names
            .iter()
            .zip(steps)
            .map(|(name, raw)| (name.as_str(), raw))
            .collect();
        check_enum("stela_metal_step", &values);
        check_enum(
            "stela_metal_winding",
            &[
                ("STELA_METAL_WINDING_CLOCKWISE", Winding::Clockwise.raw()),
                (
                    "STELA_METAL_WINDING_COUNTER_CLOCKWISE",
                    Winding::CounterClockwise.raw(),
                ),
            ],
        );
        assert_eq!(
            AccumulateArguments::WORKGROUP_SIZE,
            SelectArguments::WORKGROUP_SIZE
        );
    }

    #[test]
    fn table_layout_is_packed_and_aligned() {
        assert_eq!(ArgumentTable::BUFFER_LENGTHS_OFFSET, 248);
        assert_eq!(ArgumentTable::TEXTURES_OFFSET, 496);
        assert_eq!(ArgumentTable::SAMPLERS_OFFSET, 1520);
        assert_eq!(ArgumentTable::ATTACHMENTS_OFFSET, 1648);
        assert_eq!(ArgumentTable::SAMPLE_POSITIONS_OFFSET, 1712);
        assert_eq!(ArgumentTable::BLEND_COLOR_OFFSET, 1744);
        assert_eq!(ArgumentTable::IMAGEBLOCK_OFFSET, 1760);
        assert_eq!(ArgumentTable::DEPTH_STENCIL_OFFSET, 1776);
        assert_eq!(ArgumentTable::DEPTH_COPIES_OFFSET, 1808);
        assert_eq!(ArgumentTable::BYTES, 1824);
        assert_eq!(
            u64::from(ArgumentTable::BYTES) % ArgumentTable::ALIGNMENT,
            0
        );

        let mut table = ArgumentTable::default();
        table.buffers[30] = BufferBinding {
            address: 0x1234_5678_9abc,
            length: 64,
        };
        table.textures[1] = ResourceId::new(7, 9);
        table.samplers[15] = ResourceId::new(3, 4);
        // Sixteen samples, the last at (1/16, 0).
        table.samples = PassSamples::new(
            &[[0.5, 0.5]; 15]
                .into_iter()
                .chain([[0.0625, 0.0]])
                .collect::<Vec<_>>(),
        );
        let bytes = table.encode();
        let u64_at =
            |offset: u32| u64::from_le_bytes(bytes[offset as usize..][..8].try_into().unwrap());
        assert_eq!(u64_at(30 * 8), 0x1234_5678_9abc);
        assert_eq!(u64_at(ArgumentTable::BUFFER_LENGTHS_OFFSET + 30 * 8), 64);
        assert_eq!(u64_at(ArgumentTable::TEXTURES_OFFSET + 8), 9 << 32 | 7);
        assert_eq!(u64_at(ArgumentTable::SAMPLERS_OFFSET + 15 * 8), 4 << 32 | 3);
        assert_eq!(
            u64_at(ArgumentTable::SAMPLE_POSITIONS_OFFSET),
            0x8888_8888_8888_8888
        );
        assert_eq!(
            u64_at(ArgumentTable::SAMPLE_POSITIONS_OFFSET + 8),
            0x0188_8888_8888_8888
        );
        assert_eq!(bytes[ArgumentTable::SAMPLE_COUNT_OFFSET as usize], 16);
        table.imageblock = PassImageblock {
            stride: 48,
            pitch: 64,
            address: 0x10_0000_0040,
        };
        let bytes = table.encode();
        let at = ArgumentTable::IMAGEBLOCK_OFFSET as usize;
        assert_eq!(bytes[at..at + 8], [48, 0, 0, 0, 64, 0, 0, 0]);
        assert_eq!(
            u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap()),
            0x10_0000_0040
        );
        table.fragment_tests = FragmentTests {
            state: [0x17, 0x2, 0x3],
            references: 0x0201,
            range: [0.25f32.to_bits(), 1.0f32.to_bits()],
            depth: ResourceId::new(0, 5),
            stencil: ResourceId::new(0, 6),
        };
        let bytes = table.encode();
        let u32_at =
            |offset: u32| u32::from_le_bytes(bytes[offset as usize..][..4].try_into().unwrap());
        assert_eq!(u32_at(ArgumentTable::DEPTH_STENCIL_OFFSET), 0x17);
        assert_eq!(u32_at(ArgumentTable::DEPTH_STENCIL_OFFSET + 8), 0x3);
        assert_eq!(u32_at(ArgumentTable::DEPTH_STENCIL_OFFSET + 12), 0x0201);
        assert_eq!(u32_at(ArgumentTable::DEPTH_RANGE_OFFSET), 0.25f32.to_bits());
        assert_eq!(u32_at(ArgumentTable::DEPTH_COPIES_OFFSET + 12), 6);
    }

    #[test]
    fn push_constants_encode_in_layout_order() {
        let constants = PushConstants {
            tables: [1, 2, 3],
            arguments: 7,
            log: 8,
            grid: [4, 5, 6],
            amplification_id: 1,
            amplification_count: 2,
            view_mapping: 2 << 16 | 1,
        };
        let bytes = constants.encode();
        assert_eq!(bytes[PushConstants::TABLES_OFFSET as usize + 16], 3);
        assert_eq!(bytes[PushConstants::ARGUMENTS_OFFSET as usize], 7);
        assert_eq!(bytes[PushConstants::LOG_OFFSET as usize], 8);
        assert_eq!(bytes[PushConstants::GRID_OFFSET as usize + 8], 6);
        assert_eq!(bytes[PushConstants::AMPLIFICATION_OFFSET as usize], 1);
        assert_eq!(bytes[PushConstants::VIEW_MAPPING_OFFSET as usize + 2], 2);
        assert_eq!(bytes[PushConstants::AMPLIFICATIONS_OFFSET as usize], 2);
    }

    #[test]
    fn tessellation_arguments_encode_in_layout_order() {
        let arguments = TessellationArguments {
            factors: BufferBinding {
                address: 0x1000,
                length: 24,
            },
            patch_indices: BufferBinding::default(),
            control_point_indices: BufferBinding {
                address: 0x2000,
                length: 64,
            },
            instance_stride: 96,
            factor_scale: 2.0,
            control_points: 16,
            strides: core::array::from_fn(|index| 4 * index as u32),
        };
        let bytes = arguments.encode();
        let u64_at =
            |offset: u32| u64::from_le_bytes(bytes[offset as usize..][..8].try_into().unwrap());
        assert_eq!(u64_at(TessellationArguments::FACTORS_OFFSET + 8), 24);
        assert_eq!(u64_at(TessellationArguments::PATCH_INDICES_OFFSET), 0);
        assert_eq!(
            u64_at(TessellationArguments::CONTROL_POINT_INDICES_OFFSET),
            0x2000
        );
        assert_eq!(
            bytes[TessellationArguments::INSTANCE_STRIDE_OFFSET as usize],
            96
        );
        assert_eq!(
            bytes[TessellationArguments::FACTOR_SCALE_OFFSET as usize..][..4],
            2.0f32.to_le_bytes()
        );
        assert_eq!(
            bytes[TessellationArguments::CONTROL_POINTS_OFFSET as usize],
            16
        );
        assert_eq!(bytes[TessellationArguments::BYTES as usize - 4], 120);
    }

    #[test]
    fn select_arguments_encode_in_layout_order() {
        let bytes = SelectArguments {
            range: 0x1000,
            flags: 0x2000,
            count: 7,
        }
        .encode();
        let u64_at =
            |offset: u32| u64::from_le_bytes(bytes[offset as usize..][..8].try_into().unwrap());
        assert_eq!(u64_at(SelectArguments::RANGE_OFFSET), 0x1000);
        assert_eq!(u64_at(SelectArguments::FLAGS_OFFSET), 0x2000);
        assert_eq!(bytes[SelectArguments::COUNT_OFFSET as usize], 7);
    }

    #[test]
    fn resolve_arguments_encode_in_layout_order() {
        let mut vertex_buffers = [SequenceVertexBuffer::default(); MAX_BUFFER_BINDINGS as usize];
        vertex_buffers[30] = SequenceVertexBuffer {
            address: 0x5000,
            size: 64,
            stride: 12,
        };
        let bytes = ResolveArguments {
            header: 0x1000,
            strides: 0x4000,
            count: 9,
            inherit_buffers: true,
            class_count: 3,
            constants: PushConstants {
                tables: [0x6000, 0, 0],
                ..PushConstants::default()
            },
            vertex_buffers,
            slots: alloc::vec![ResolveSlot {
                class: 2,
                action: 1,
                primitive: 4,
            }],
            ..ResolveArguments::default()
        }
        .encode();
        let u32_at =
            |offset: u32| u32::from_le_bytes(bytes[offset as usize..][..4].try_into().unwrap());
        let u64_at =
            |offset: u32| u64::from_le_bytes(bytes[offset as usize..][..8].try_into().unwrap());
        assert_eq!(bytes.len(), 656);
        assert_eq!(u64_at(ResolveArguments::HEADER_OFFSET), 0x1000);
        assert_eq!(u64_at(ResolveArguments::STRIDES_OFFSET), 0x4000);
        assert_eq!(u32_at(ResolveArguments::COUNT_OFFSET), 9);
        assert_eq!(u32_at(ResolveArguments::SLOT_COUNT_OFFSET), 1);
        assert_eq!(
            u32_at(ResolveArguments::FLAGS_OFFSET),
            ResolveArguments::INHERIT_BUFFERS
        );
        assert_eq!(u32_at(ResolveArguments::CLASS_COUNT_OFFSET), 3);
        assert_eq!(u64_at(ResolveArguments::PUSH_OFFSET), 0x6000);
        let last = ResolveArguments::SLOTS_OFFSET - GeneratedSequence::VERTEX_BUFFER_BYTES;
        assert_eq!(
            (u64_at(last), u32_at(last + 8), u32_at(last + 12)),
            (0x5000, 64, 12)
        );
        let slot = ResolveArguments::SLOTS_OFFSET;
        assert_eq!(
            (u32_at(slot), u32_at(slot + 4), u32_at(slot + 8)),
            (2, 1, 4)
        );
    }

    #[test]
    fn resource_ids_pack_two_indices() {
        let id = ResourceId::new(u32::MAX, 1);
        assert_eq!((id.low(), id.high()), (u32::MAX, 1));
        assert_eq!(
            ResourceId::NULL,
            ResourceId::new(NULL_DESCRIPTOR, NULL_DESCRIPTOR)
        );
    }

    #[test]
    fn released_indices_wait_for_their_submission() {
        let mut indices = DescriptorIndices::new(4);
        assert_eq!(indices.allocate(), Ok(1));
        assert_eq!(indices.allocate(), Ok(2));
        assert_eq!(indices.allocate(), Ok(3));
        assert_eq!(indices.allocate(), Err(Error::OutOfMemory));
        indices.release(2, 10);
        indices.release(1, 11);
        indices.retire(9);
        assert_eq!(
            indices.allocate(),
            Err(Error::OutOfMemory),
            "serial 10 is still pending"
        );
        indices.retire(10);
        assert_eq!(indices.allocate(), Ok(2));
        assert_eq!(indices.in_use(), 3, "index 1 is released but still pending");
        indices.retire(11);
        assert_eq!(indices.in_use(), 2);
    }

    #[test]
    fn runs_are_consecutive_and_merge_when_retired() {
        let mut indices = DescriptorIndices::new(12);
        assert_eq!(indices.allocate_run(4), Ok(1));
        assert_eq!(indices.allocate_run(3), Ok(5));
        assert_eq!(indices.allocate_run(3), Ok(8));
        assert_eq!(indices.allocate_run(2), Err(Error::OutOfMemory));
        assert_eq!(indices.allocate(), Ok(11));
        indices.release_run(1, 4, 1);
        indices.release_run(5, 3, 1);
        indices.retire(1);
        assert_eq!(indices.in_use(), 4);
        assert_eq!(indices.allocate_run(7), Ok(1), "the two runs merged");
        indices.release_run(8, 3, 2);
        indices.release(11, 2);
        indices.retire(2);
        assert_eq!(indices.allocate_run(4), Ok(8));
        assert_eq!(indices.in_use(), 11);
    }

    #[test]
    fn extended_storage_is_a_chroma_flag_without_planes() {
        let id = ResourceId::texture(5, ResourceId::MAX_STORAGE - 1, 1);
        assert_eq!(id.with_extended_storage(None), id);
        let codes = id.with_extended_storage(Some(false));
        assert_eq!(codes.high() >> ResourceId::PLANES_SHIFT & 7, 4);
        assert_eq!(codes.high_index(), ResourceId::MAX_STORAGE - 1);
        assert_eq!(codes.high() & ResourceId::SRGB_STORAGE, 0);
        let srgb = id.with_extended_storage(Some(true));
        assert_ne!(srgb.high() & ResourceId::SRGB_STORAGE, 0);
        assert_eq!(srgb.high_index(), ResourceId::MAX_STORAGE - 1);
    }

    #[test]
    fn texture_ids_count_their_storage_levels() {
        let id = ResourceId::texture(7, 9, 15);
        assert_eq!((id.low(), id.high_index(), id.high_count()), (7, 9, 15));
        let sampler = ResourceId::new(3, 4);
        assert_eq!((sampler.high_index(), sampler.high_count()), (4, 1));
        let flags = ResourceId::SAMPLER_NEVER
            | ResourceId::SAMPLER_CUBIC
            | ResourceId::SAMPLER_MIPPED
            | ResourceId::SAMPLER_PIXELS;
        let flagged = ResourceId::sampler(3, 4, flags);
        assert_eq!((flagged.low(), flagged.sampler_integer()), (3, 4));
        assert_eq!(ResourceId::sampler(3, 4, 0), sampler);
        assert_eq!(ResourceId::MAX_LEVELS, 16);
        let deepest = ResourceId::texture(7, 9, ResourceId::MAX_LEVELS);
        assert_eq!(deepest.high() & ResourceId::POOL_VIEW, 0);
        // The sRGB storage flag leaves the index and count.
        let srgb = id.with_srgb_storage(true);
        assert_eq!(
            (srgb.low(), srgb.high_index(), srgb.high_count()),
            (7, 9, 15)
        );
        assert_ne!(srgb.high() & ResourceId::SRGB_STORAGE, 0);
        assert_eq!(id.with_srgb_storage(false), id);
        // So does the filter class, which a later class replaces.
        let nearest = srgb.with_filter_class(FilterClass::Nearest);
        assert_eq!(
            (nearest.low(), nearest.high_index(), nearest.high_count()),
            (7, 9, 15)
        );
        assert_eq!(nearest.high() >> ResourceId::FILTER_CLASS_SHIFT & 3, 3);
        assert_ne!(nearest.high() & ResourceId::SRGB_STORAGE, 0);
        assert_eq!(nearest.with_filter_class(FilterClass::Float), srgb);
    }

    #[test]
    fn nvk_heap_holds_tier_two_argument_buffers() {
        let layout = HeapLayout::new(&nvk(&CHIPS[0], 8 << 30).limits);
        assert!(layout.count(HeapArray::SampledImages) >= 500_000);
        assert!(layout.count(HeapArray::StorageImages) >= 500_000);
        assert_eq!(layout.count(HeapArray::Samplers), 4000);
        let mut heap = DescriptorHeap::new(layout);
        assert_eq!(heap.allocate(HeapArray::Samplers), Ok(1));
        assert_eq!(heap.in_use(HeapArray::Samplers), 1);
        assert_eq!(heap.in_use(HeapArray::SampledImages), 0);
    }
}
