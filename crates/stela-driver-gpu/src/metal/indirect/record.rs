//! The device-memory form of a GPU-resident indirect command buffer, which
//! CPU encoding, blit encoders and shaders write and the backend's resolve
//! kernel reads; `compiler/metal_abi.h` mirrors it.
//!
//! A header of [`RecordLayout::HEADER_BYTES`] leads, and the records
//! follow it, [`RecordLayout::stride`] bytes apart. Every record opens with
//! the same prefix: its action, its barrier flag and its pipeline handle,
//! then the action's arguments. Its buffer tables follow, each the
//! addresses and then the lengths of one stage's buffer slots, as an
//! [`ArgumentTable`](crate::metal::binding::ArgumentTable) holds them,
//! and then a run of words: render records' vertex strides, zero for the
//! pipeline's, or compute records' threadgroup memory lengths. A zeroed
//! record is a reset command.
use super::{IndirectAction, IndirectCommand, IndirectCommandBufferDescriptor};
use crate::metal::{
    abi::{IndirectCommandType, PrimitiveType},
    capabilities::Size,
    error::{Error, Result, ensure},
    shader::Stage,
};
use alloc::vec::Vec;

/// What a CPU encoding call changed, which it writes to a resident record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Field {
    Pipeline,
    Barrier,
    Action,
    StageIn,
    /// A buffer slot of a stage, with its vertex stride.
    Buffer(Stage, u32),
    ThreadgroupLength(u32),
    /// The whole record, as a reset leaves it.
    Record,
}

/// Where a record's encoded bytes go.
pub(super) trait Sink {
    /// Writes `bytes` at `offset` within the record.
    fn put(&mut self, offset: u32, bytes: &[u8]);
}

/// The record image, whose fields land in place.
impl Sink for [u8] {
    fn put(&mut self, offset: u32, bytes: &[u8]) {
        let offset = offset as usize;
        self[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}

/// Writes in device memory at a record's offset in the buffer.
pub(super) struct Writes<'a> {
    pub record: u64,
    pub writes: &'a mut Vec<(u64, Vec<u8>)>,
}

impl Sink for Writes<'_> {
    fn put(&mut self, offset: u32, bytes: &[u8]) {
        self.writes
            .push((self.record + u64::from(offset), bytes.to_vec()));
    }
}

/// Where a buffer's records keep their parts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLayout {
    pub renders: bool,
    pub stride: u32,
    pub count: u32,
    /// Record offsets of the stages' buffer tables: vertex and fragment, or
    /// kernel and none.
    pub tables: [u32; 2],
    /// Buffer slots of each table.
    pub table_slots: [u32; 2],
    /// Record offset of the words.
    pub words: u32,
    pub word_count: u32,
}

impl RecordLayout {
    pub const HEADER_BYTES: u32 = 64;
    pub const HEADER_STRIDE: u32 = 0;
    pub const HEADER_COUNT: u32 = 4;
    pub const HEADER_TABLES: u32 = 8;
    pub const HEADER_TABLE_SLOTS: u32 = 16;
    pub const HEADER_WORDS: u32 = 24;
    pub const HEADER_WORD_COUNT: u32 = 28;
    pub const RECORD_ALIGNMENT: u32 = 16;

    /// The prefix every record shares.
    pub const ACTION: u32 = 0;
    pub const BARRIER: u32 = 4;
    pub const PIPELINE: u32 = 8;
    /// Render arguments: vertex or index count, instance count, first
    /// vertex, base vertex, base instance and `MTLPrimitiveType`, then the
    /// index buffer's address, its byte length and its `MTLIndexType`.
    pub const VERTICES: u32 = 16;
    pub const INSTANCES: u32 = 20;
    pub const FIRST_VERTEX: u32 = 24;
    pub const BASE_VERTEX: u32 = 28;
    pub const BASE_INSTANCE: u32 = 32;
    pub const PRIMITIVE: u32 = 36;
    pub const INDEX_ADDRESS: u32 = 40;
    pub const INDEX_LENGTH: u32 = 48;
    pub const INDEX_TYPE: u32 = 52;
    /// Compute arguments: the threadgroup or thread grid, the threads per
    /// threadgroup, and the stage-in region's origin and size with a flag
    /// that it is set.
    pub const GRID: u32 = 16;
    pub const THREADS: u32 = 28;
    pub const STAGE_IN_ORIGIN: u32 = 40;
    pub const STAGE_IN_SIZE: u32 = 52;
    pub const STAGE_IN: u32 = 64;
    pub const PREFIX_BYTES: u32 = 80;

    /// Actions: render records draw or draw indexed, compute records
    /// dispatch threadgroups or threads; zero does nothing.
    pub const DRAW: u32 = 1;
    pub const DRAW_INDEXED: u32 = 2;
    pub const DISPATCH: u32 = 1;
    pub const DISPATCH_THREADS: u32 = 2;

    /// The layout of a buffer of `count` commands, refusing commands
    /// records cannot hold: patch and mesh draws, which need the CPU's
    /// per-draw arguments and pipeline variants, and rasterizer state the
    /// encoder does not provide.
    pub fn new(descriptor: &IndirectCommandBufferDescriptor, count: usize) -> Result<Self> {
        let recordable = IndirectCommandType::DRAW
            | IndirectCommandType::DRAW_INDEXED
            | IndirectCommandType::CONCURRENT_DISPATCH
            | IndirectCommandType::CONCURRENT_DISPATCH_THREADS;
        if !recordable.contains(descriptor.command_types) {
            return Err(Error::Unsupported(
                "patch and mesh draws in GPU-resident indirect command buffers",
            ));
        }
        let renders = descriptor.renders();
        let inherits_raster = descriptor.inherit_cull_mode
            && descriptor.inherit_depth_stencil_state
            && descriptor.inherit_depth_bias
            && descriptor.inherit_depth_clip_mode
            && descriptor.inherit_front_facing_winding
            && descriptor.inherit_triangle_fill_mode;
        if renders && !inherits_raster {
            return Err(Error::Unsupported(
                "per-command rasterizer state in GPU-resident indirect command buffers",
            ));
        }
        let renders = descriptor.renders();
        // Validated against the argument table's slots.
        let slots = |count: u64| count as u32;
        let table_slots = match (descriptor.inherit_buffers, renders) {
            (true, _) => [0, 0],
            (false, true) => [
                slots(descriptor.max_vertex_buffer_bind_count),
                slots(descriptor.max_fragment_buffer_bind_count),
            ],
            (false, false) => [slots(descriptor.max_kernel_buffer_bind_count), 0],
        };
        let word_count = match renders {
            true if descriptor.support_dynamic_attribute_stride => table_slots[0],
            true => 0,
            false => slots(descriptor.max_kernel_threadgroup_memory_bind_count),
        };
        let second = Self::PREFIX_BYTES + 16 * table_slots[0];
        let words = second + 16 * table_slots[1];
        let stride = (words + 4 * word_count).next_multiple_of(Self::RECORD_ALIGNMENT);
        let layout = Self {
            renders,
            stride,
            count: u32::try_from(count).map_err(|_| Error::Invalid("indirect command count"))?,
            tables: [Self::PREFIX_BYTES, second],
            table_slots,
            words,
            word_count,
        };
        ensure(
            layout.bytes() <= u64::from(u32::MAX),
            "GPU-resident indirect command buffers within 4 GiB",
        )?;
        Ok(layout)
    }

    /// The bytes of the header and every record.
    pub fn bytes(&self) -> u64 {
        u64::from(Self::HEADER_BYTES) + u64::from(self.stride) * u64::from(self.count)
    }

    /// The buffer offset of record `index`.
    pub fn record(&self, index: usize) -> u64 {
        u64::from(Self::HEADER_BYTES) + u64::from(self.stride) * index as u64
    }

    pub fn header(&self) -> [u8; Self::HEADER_BYTES as usize] {
        let mut header = [0; Self::HEADER_BYTES as usize];
        let words = [
            self.stride,
            self.count,
            self.tables[0],
            self.tables[1],
            self.table_slots[0],
            self.table_slots[1],
            self.words,
            self.word_count,
        ];
        for (index, word) in words.iter().enumerate() {
            header[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        header
    }

    /// The header and every command's record.
    pub(super) fn image(&self, commands: &[IndirectCommand]) -> Result<Vec<u8>> {
        let mut image = self.header().to_vec();
        image.append(&mut self.records(commands)?);
        Ok(image)
    }

    /// The consecutive records of `commands`.
    pub(super) fn records(&self, commands: &[IndirectCommand]) -> Result<Vec<u8>> {
        let mut records = alloc::vec![0; self.stride as usize * commands.len()];
        for (record, command) in records.chunks_exact_mut(self.stride as usize).zip(commands) {
            self.write(record, command, Field::Record)?;
        }
        Ok(records)
    }

    /// Encodes `field` of `command` into its record.
    pub(super) fn write(
        &self,
        record: &mut (impl Sink + ?Sized),
        command: &IndirectCommand,
        field: Field,
    ) -> Result<()> {
        match field {
            Field::Pipeline => {
                let handle = match command.pipeline {
                    None => 0,
                    Some(pipeline) if pipeline.handle != 0 => pipeline.handle,
                    Some(_) => {
                        return Err(Error::Invalid(
                            "the pipeline state does not support indirect command buffers",
                        ));
                    }
                };
                record.put(Self::PIPELINE, &handle.to_le_bytes());
            }
            Field::Barrier => record.put(Self::BARRIER, &u32::from(command.barrier).to_le_bytes()),
            Field::Action => self.write_action(record, command.action.as_ref())?,
            Field::StageIn => {
                let mut words = [0; 7];
                if let Some((origin, size)) = command.stage_in {
                    for (word, value) in words.iter_mut().zip(origin.iter().chain(&size)) {
                        *word = u32::try_from(*value)
                            .map_err(|_| Error::Invalid("stage-in regions within 32 bits"))?;
                    }
                    words[6] = 1;
                }
                record.put(Self::STAGE_IN_ORIGIN, &le_words(&words));
            }
            Field::Buffer(stage, slot) => self.write_buffer(record, command, stage, slot)?,
            Field::ThreadgroupLength(slot) => {
                let length = command
                    .threadgroup_lengths
                    .iter()
                    .find(|&&(index, _)| index == slot)
                    .map_or(0, |&(_, length)| length);
                let length = u32::try_from(length)
                    .map_err(|_| Error::Invalid("threadgroup memory length"))?;
                record.put(self.words + 4 * slot, &length.to_le_bytes());
            }
            Field::Record => {
                record.put(0, &alloc::vec![0; self.stride as usize]);
                if command.pipeline.is_some() {
                    self.write(record, command, Field::Pipeline)?;
                }
                if command.barrier {
                    self.write(record, command, Field::Barrier)?;
                }
                if command.action.is_some() {
                    self.write(record, command, Field::Action)?;
                }
                if command.stage_in.is_some() {
                    self.write(record, command, Field::StageIn)?;
                }
                for buffer in &command.buffers {
                    self.write(record, command, Field::Buffer(buffer.stage, buffer.index))?;
                }
                for &(slot, _) in &command.threadgroup_lengths {
                    self.write(record, command, Field::ThreadgroupLength(slot))?;
                }
            }
        }
        Ok(())
    }

    fn write_action(
        &self,
        record: &mut (impl Sink + ?Sized),
        action: Option<&IndirectAction>,
    ) -> Result<()> {
        let words = |values: &[u32]| le_words(values);
        match action {
            None => record.put(Self::ACTION, &0u32.to_le_bytes()),
            Some(&IndirectAction::Draw {
                primitive,
                vertex_start,
                vertex_count,
                instance_count,
                base_instance,
            }) => {
                record.put(Self::ACTION, &Self::DRAW.to_le_bytes());
                record.put(
                    Self::VERTICES,
                    &words(&[
                        vertex_count,
                        instance_count,
                        vertex_start,
                        0,
                        base_instance,
                        primitive_raw(primitive),
                    ]),
                );
            }
            Some(&IndirectAction::DrawIndexed {
                primitive,
                index_count,
                index_type,
                index_buffer,
                index_buffer_offset,
                instance_count,
                base_vertex,
                base_instance,
            }) => {
                ensure(
                    index_buffer_offset.is_multiple_of(index_type.bytes()),
                    "index buffer offsets are aligned to the index size",
                )?;
                index_buffer.at(index_buffer_offset, 0)?;
                let length = (index_buffer.length - index_buffer_offset).min(u32::MAX.into());
                record.put(Self::ACTION, &Self::DRAW_INDEXED.to_le_bytes());
                record.put(
                    Self::VERTICES,
                    &words(&[
                        index_count,
                        instance_count,
                        0,
                        base_vertex as u32,
                        base_instance,
                        primitive_raw(primitive),
                    ]),
                );
                record.put(
                    Self::INDEX_ADDRESS,
                    &(index_buffer.address + index_buffer_offset).to_le_bytes(),
                );
                record.put(
                    Self::INDEX_LENGTH,
                    &words(&[length as u32, index_type.raw() as u32]),
                );
            }
            Some(IndirectAction::Dispatch {
                threadgroups,
                threads,
            }) => {
                record.put(Self::ACTION, &Self::DISPATCH.to_le_bytes());
                record.put(Self::GRID, &words(threadgroups));
                record.put(Self::THREADS, &words(&size_words(threads)?));
            }
            Some(IndirectAction::DispatchThreads { grid, threads }) => {
                record.put(Self::ACTION, &Self::DISPATCH_THREADS.to_le_bytes());
                record.put(Self::GRID, &words(grid));
                record.put(Self::THREADS, &words(&size_words(threads)?));
            }
            Some(_) => {
                return Err(Error::Unsupported(
                    "patch and mesh draws in GPU-resident indirect command buffers",
                ));
            }
        }
        Ok(())
    }

    fn write_buffer(
        &self,
        record: &mut (impl Sink + ?Sized),
        command: &IndirectCommand,
        stage: Stage,
        slot: u32,
    ) -> Result<()> {
        let table = match (self.renders, stage) {
            (true, Stage::Vertex) | (false, Stage::Kernel) => 0,
            (true, Stage::Fragment) => 1,
            _ => {
                return Err(Error::Unsupported(
                    "object and mesh buffers in GPU-resident indirect command buffers",
                ));
            }
        };
        let binding = command
            .buffers
            .iter()
            .find(|binding| (binding.stage, binding.index) == (stage, slot));
        let (address, length) = binding.map_or((0, 0), |binding| {
            (
                binding.buffer.address + binding.offset,
                binding.buffer.length - binding.offset,
            )
        });
        let start = self.tables[table];
        let slots = self.table_slots[table];
        record.put(start + 8 * slot, &address.to_le_bytes());
        record.put(start + 8 * (slots + slot), &length.to_le_bytes());
        if self.renders && table == 0 && slot < self.word_count {
            let stride = binding.and_then(|binding| binding.stride).unwrap_or(0);
            let stride =
                u32::try_from(stride).map_err(|_| Error::Invalid("vertex attribute stride"))?;
            record.put(self.words + 4 * slot, &stride.to_le_bytes());
        }
        Ok(())
    }
}

fn primitive_raw(primitive: PrimitiveType) -> u32 {
    primitive.raw() as u32
}

fn size_words(size: &Size) -> Result<[u32; 3]> {
    let word =
        |value: u64| u32::try_from(value).map_err(|_| Error::Invalid("threads per threadgroup"));
    Ok([word(size.width)?, word(size.height)?, word(size.depth)?])
}

fn le_words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}
