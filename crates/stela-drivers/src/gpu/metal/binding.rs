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
//! its write descriptor (storage image or storage texel buffer) in the high
//! half; the compiler selects the array from the texture's declared type and
//! access. A sampler's ID names its float-border descriptor in the low half
//! and its integer-border twin in the high half.
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
use alloc::{collections::VecDeque, vec::Vec};

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

    pub const fn new(low: u32, high: u32) -> Self {
        Self(low as u64 | (high as u64) << 32)
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
}

impl TessellationArguments {
    pub const FACTORS_OFFSET: u32 = 0;
    pub const PATCH_INDICES_OFFSET: u32 = 16;
    pub const CONTROL_POINT_INDICES_OFFSET: u32 = 32;
    pub const INSTANCE_STRIDE_OFFSET: u32 = 48;
    pub const FACTOR_SCALE_OFFSET: u32 = 52;
    pub const BYTES: u32 = 56;
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

/// Allocates indices in one heap array. Released indices are reused only
/// after the GPU completes the submission that last could read them.
#[derive(Clone, Debug)]
pub struct DescriptorIndices {
    count: u32,
    next: u32,
    free: Vec<u32>,
    /// (serial, index) in release order; serials never decrease.
    retiring: VecDeque<(u64, u32)>,
}

impl DescriptorIndices {
    pub fn new(count: u32) -> Self {
        Self {
            count,
            next: NULL_DESCRIPTOR + 1,
            free: Vec::new(),
            retiring: VecDeque::new(),
        }
    }

    pub fn allocate(&mut self) -> Result<u32> {
        if let Some(index) = self.free.pop() {
            return Ok(index);
        }
        if self.next >= self.count {
            return Err(Error::OutOfMemory);
        }
        self.next += 1;
        Ok(self.next - 1)
    }

    /// Releases `index` once submission `serial` completes. Callers pass the
    /// last submitted serial, which never decreases.
    pub fn release(&mut self, index: u32, serial: u64) {
        debug_assert!(index != NULL_DESCRIPTOR && index < self.next);
        debug_assert!(self.retiring.back().is_none_or(|&(last, _)| last <= serial));
        self.retiring.push_back((serial, index));
    }

    /// Returns indices whose submissions have completed to the free list.
    pub fn retire(&mut self, completed: u64) {
        while let Some(&(serial, index)) = self.retiring.front() {
            if serial > completed {
                break;
            }
            self.retiring.pop_front();
            self.free.push(index);
        }
    }

    pub fn in_use(&self) -> u32 {
        self.next - 1 - self.free.len() as u32
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

    pub fn release(&mut self, array: HeapArray, index: u32, serial: u64) {
        self.arrays[array.raw() as usize].release(index, serial);
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
        nvidia::{CHIPS, fixture::nvk},
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
