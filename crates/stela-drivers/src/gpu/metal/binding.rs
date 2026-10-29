//! The binding ABI shared by command encoding and compiled shaders.
//!
//! Every pipeline uses one Vulkan pipeline layout:
//!
//! - **Set 0** is the device's bindless descriptor heap: one
//!   update-after-bind, partially bound array per [`HeapArray`]. Index 0 of
//!   each array is a null descriptor, so an unbound slot reads zero.
//! - **Push constants** are [`PushConstants`]: the GPU address of each
//!   stage's argument table, of the latest draw's or dispatch's own
//!   arguments, and the dispatch's grid size. Every stage may read them.
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
//!
//! Encoders write a table to the command buffer's upload ring whenever its
//! slots change and push its address before the next draw or dispatch.
//!
//! The compiler's side of this ABI is `compiler/metal_abi.h`, which the tests
//! check against these layouts.
use super::{
    capabilities::{MAX_BUFFER_BINDINGS, MAX_SAMPLER_BINDINGS, MAX_TEXTURE_BINDINGS},
    error::{Error, Result},
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

/// Two descriptor indices packed as Metal's `MTLResourceID`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ResourceId(pub u64);

impl ResourceId {
    pub const NULL: Self = Self(0);
    /// The high half's bits from which it counts its descriptors, less one;
    /// the index is below them.
    pub const LEVEL_SHIFT: u32 = 27;
    /// Descriptors one high half names: levels of a texture.
    pub const MAX_LEVELS: u32 = 1 << (32 - Self::LEVEL_SHIFT);

    pub const fn new(low: u32, high: u32) -> Self {
        Self(low as u64 | (high as u64) << 32)
    }

    /// A texture's ID: its read descriptor, and its `levels` write
    /// descriptors from `storage`.
    pub const fn texture(sampled: u32, storage: u32, levels: u32) -> Self {
        debug_assert!(storage >> Self::LEVEL_SHIFT == 0);
        debug_assert!(levels >= 1 && levels <= Self::MAX_LEVELS);
        Self::new(sampled, storage | (levels - 1) << Self::LEVEL_SHIFT)
    }

    /// The first descriptor the high half names.
    pub const fn high_index(self) -> u32 {
        self.high() & ((1 << Self::LEVEL_SHIFT) - 1)
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
    /// Threads in the grid (`dispatchThreads`), for the compiler's bounds
    /// check of non-uniform threadgroups; zero for uniform dispatches.
    pub grid: [u32; 3],
    /// The view an amplified draw renders (`[[amplification_id]]`). Each
    /// view is its own draw, so Metal's view mappings need no multiview.
    pub amplification_id: u32,
    /// That view's `MTLVertexAmplificationViewMapping`: the viewport offset
    /// in the low half, the render target array offset in the high half.
    pub view_mapping: u32,
}

// Vulkan guarantees 128 bytes of push constants.
const _: () = assert!(PushConstants::BYTES <= 128);

impl PushConstants {
    pub const BYTES: u32 = 52;
    pub const TABLES_OFFSET: u32 = 0;
    pub const ARGUMENTS_OFFSET: u32 = 24;
    pub const GRID_OFFSET: u32 = 32;
    pub const AMPLIFICATION_OFFSET: u32 = 44;
    pub const VIEW_MAPPING_OFFSET: u32 = 48;

    pub fn encode(&self) -> [u8; Self::BYTES as usize] {
        let mut bytes = [0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        self.tables.iter().for_each(|table| writer.u64(*table));
        writer.u64(self.arguments);
        self.grid.iter().for_each(|size| writer.u32(*size));
        writer.u32(self.amplification_id);
        writer.u32(self.view_mapping);
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
}

impl Default for ArgumentTable {
    fn default() -> Self {
        Self {
            buffers: [BufferBinding::default(); MAX_BUFFER_BINDINGS as usize],
            textures: [ResourceId::NULL; MAX_TEXTURE_BINDINGS as usize],
            samplers: [ResourceId::NULL; MAX_SAMPLER_BINDINGS as usize],
        }
    }
}

impl ArgumentTable {
    pub const BUFFER_ADDRESSES_OFFSET: u32 = 0;
    pub const BUFFER_LENGTHS_OFFSET: u32 = MAX_BUFFER_BINDINGS * 8;
    pub const TEXTURES_OFFSET: u32 = Self::BUFFER_LENGTHS_OFFSET + MAX_BUFFER_BINDINGS * 8;
    pub const SAMPLERS_OFFSET: u32 = Self::TEXTURES_OFFSET + MAX_TEXTURE_BINDINGS * 8;
    pub const BYTES: u32 = Self::SAMPLERS_OFFSET + MAX_SAMPLER_BINDINGS * 8;
    /// Tables are placed at this alignment in the upload ring.
    pub const ALIGNMENT: u64 = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::BYTES as usize];
        let mut writer = Writer {
            bytes: &mut bytes,
            offset: 0,
        };
        self.buffers
            .iter()
            .for_each(|buffer| writer.u64(buffer.address));
        self.buffers
            .iter()
            .for_each(|buffer| writer.u64(buffer.length));
        self.textures
            .iter()
            .chain(&self.samplers)
            .for_each(|id| writer.u64(id.0));
        bytes
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

/// What the backend's internal resolve kernel reads at the push constants'
/// `arguments` (`stela_metal_resolve_kernel`): it turns each command of a
/// GPU-resident render indirect command buffer into a [`GeneratedSequence`]
/// and its counts per [`ResolveSlot`].
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
    /// Where thread `n` writes its vertex and fragment argument tables,
    /// unless the buffer inherits buffers.
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
    pub const PUSH_OFFSET: u32 = 72;
    pub const VERTEX_BUFFERS_OFFSET: u32 = 128;
    pub const SLOTS_OFFSET: u32 = 624;
    pub const SLOT_BYTES: u32 = 16;
    pub const INHERIT_PIPELINE: u32 = 1;
    pub const INHERIT_BUFFERS: u32 = 2;
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
            | flag(self.inherit_buffers, Self::INHERIT_BUFFERS);
        for word in [
            self.count,
            self.first,
            self.slots.len() as u32,
            flags,
            self.class_count,
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
);

/// The offsets of a command's device-generated sequence, which the resolve
/// kernel writes and each indirect commands layout reads at its own token
/// offsets.
pub struct GeneratedSequence;

impl GeneratedSequence {
    /// The `u32` execution set index.
    pub const PIPELINE_OFFSET: u32 = 0;
    pub const PUSH_OFFSET: u32 = 8;
    /// `VkBindIndexBufferIndirectCommandEXT`.
    pub const INDEX_BUFFER_OFFSET: u32 = 64;
    /// A [`SequenceVertexBuffer`] per vertex buffer index.
    pub const VERTEX_BUFFERS_OFFSET: u32 = 80;
    pub const VERTEX_BUFFER_BYTES: u32 = 16;
    /// `VkDrawIndirectCommand`.
    pub const DRAW_OFFSET: u32 = 576;
    /// `VkDrawIndexedIndirectCommand`.
    pub const DRAW_INDEXED_OFFSET: u32 = 592;
    pub const BYTES: u32 = 624;
    pub const ALIGNMENT: u64 = 16;
}

const _: () = assert!(
    GeneratedSequence::PUSH_OFFSET + PushConstants::BYTES <= GeneratedSequence::INDEX_BUFFER_OFFSET
        && GeneratedSequence::VERTEX_BUFFERS_OFFSET
            + GeneratedSequence::VERTEX_BUFFER_BYTES * MAX_BUFFER_BINDINGS
            == GeneratedSequence::DRAW_OFFSET
        && GeneratedSequence::DRAW_OFFSET + 16 == GeneratedSequence::DRAW_INDEXED_OFFSET
        && GeneratedSequence::DRAW_INDEXED_OFFSET + 20 <= GeneratedSequence::BYTES
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
        // Storage indices leave the high half's level count bits free.
        let storage = storage.min(1 << ResourceId::LEVEL_SHIFT);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::metal::{
        abi::{TessellationFactorStepFunction, TessellationPartitionMode, Winding},
        indirect::RecordLayout,
        nvidia::{CHIPS, fixture::nvk},
        vertex::{StageInStep, StepFunction},
    };

    #[test]
    fn compiler_header_matches_the_layouts() {
        let header = include_str!("../compiler/metal_abi.h");
        let define = |name: &str| -> u32 {
            header
                .lines()
                .find_map(|line| {
                    let value = line.strip_prefix("#define ")?.strip_prefix(name)?;
                    value.strip_prefix(' ')?.strip_suffix('u')?.parse().ok()
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
            ("STELA_METAL_PUSH_GRID", PushConstants::GRID_OFFSET),
            (
                "STELA_METAL_PUSH_AMPLIFICATION",
                PushConstants::AMPLIFICATION_OFFSET,
            ),
            (
                "STELA_METAL_PUSH_VIEW_MAPPING",
                PushConstants::VIEW_MAPPING_OFFSET,
            ),
            ("STELA_METAL_BUFFERS", MAX_BUFFER_BINDINGS),
            ("STELA_METAL_TEXTURES", MAX_TEXTURE_BINDINGS),
            ("STELA_METAL_SAMPLERS", MAX_SAMPLER_BINDINGS),
            ("STELA_METAL_HEAP_SET", HEAP_SET),
            ("STELA_METAL_LEVEL_SHIFT", ResourceId::LEVEL_SHIFT),
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
            ("STELA_METAL_RECORD_DISPATCH", RecordLayout::DISPATCH),
            (
                "STELA_METAL_RECORD_DISPATCH_THREADS",
                RecordLayout::DISPATCH_THREADS,
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
                "STELA_METAL_SEQUENCE_PIPELINE",
                GeneratedSequence::PIPELINE_OFFSET,
            ),
            ("STELA_METAL_SEQUENCE_PUSH", GeneratedSequence::PUSH_OFFSET),
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
        assert_eq!(ArgumentTable::BYTES, 1648);
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
        let bytes = table.encode();
        let u64_at =
            |offset: u32| u64::from_le_bytes(bytes[offset as usize..][..8].try_into().unwrap());
        assert_eq!(u64_at(30 * 8), 0x1234_5678_9abc);
        assert_eq!(u64_at(ArgumentTable::BUFFER_LENGTHS_OFFSET + 30 * 8), 64);
        assert_eq!(u64_at(ArgumentTable::TEXTURES_OFFSET + 8), 9 << 32 | 7);
        assert_eq!(u64_at(ArgumentTable::SAMPLERS_OFFSET + 15 * 8), 4 << 32 | 3);
    }

    #[test]
    fn push_constants_encode_in_layout_order() {
        let constants = PushConstants {
            tables: [1, 2, 3],
            arguments: 7,
            grid: [4, 5, 6],
            amplification_id: 1,
            view_mapping: 2 << 16 | 1,
        };
        let bytes = constants.encode();
        assert_eq!(bytes[PushConstants::TABLES_OFFSET as usize + 16], 3);
        assert_eq!(bytes[PushConstants::ARGUMENTS_OFFSET as usize], 7);
        assert_eq!(bytes[PushConstants::GRID_OFFSET as usize + 8], 6);
        assert_eq!(bytes[PushConstants::AMPLIFICATION_OFFSET as usize], 1);
        assert_eq!(bytes[PushConstants::VIEW_MAPPING_OFFSET as usize + 2], 2);
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
        assert_eq!(bytes.len(), 640);
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
    fn texture_ids_count_their_storage_levels() {
        let id = ResourceId::texture(7, 9, 15);
        assert_eq!((id.low(), id.high_index(), id.high_count()), (7, 9, 15));
        let sampler = ResourceId::new(3, 4);
        assert_eq!((sampler.high_index(), sampler.high_count()), (4, 1));
        assert_eq!(ResourceId::MAX_LEVELS, 32);
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
