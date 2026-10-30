//! Commands of `MTLResourceStateCommandEncoder`.
use super::Payload;
use crate::gpu::metal::{
    abi::SparseTextureMappingMode,
    command_buffer::CommandBuffer,
    device::TextureId,
    service::{
        Service, known,
        wire::{
            Empty, Fault,
            commands::{
                MappingRecord, MoveEndRecord, MoveMappings, ResourceStateCode,
                UpdateMappingIndirect, UpdateMappings,
            },
        },
    },
    shader::Compiler,
    sparse::{MappingUpdate, MoveEnd, SparseRegion},
    vulkan::{backend::Backend, object::Image},
};
use core::num::NonZeroU64;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn resource_state(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: ResourceStateCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            ResourceStateCode::Begin => {
                payload.record::<Empty>()?;
                commands.begin_resource_state(&mut self.device.resolver())?;
            }
            ResourceStateCode::UpdateMappings => {
                let (UpdateMappings { texture, mode }, data) = payload.split()?;
                let image = self.sparse_image(connection, texture)?;
                let updates = data
                    .list::<MappingRecord>()?
                    .into_iter()
                    .map(|record| MappingUpdate {
                        level: record.level,
                        slice: record.slice,
                        region: SparseRegion {
                            origin: record.origin,
                            size: record.size,
                        },
                    })
                    .collect();
                commands.update_texture_mappings(image, mapping_mode(mode)?, updates)?;
            }
            ResourceStateCode::UpdateMappingIndirect => {
                let request: UpdateMappingIndirect = payload.record()?;
                let image = self.sparse_image(connection, request.texture)?;
                let buffer = self.buffer_ref(connection, request.buffer)?;
                commands.update_texture_mapping_indirect(
                    &mut self.device.resolver(),
                    image,
                    mapping_mode(request.mode)?,
                    buffer,
                    request.offset,
                )?;
            }
            ResourceStateCode::MoveMappings => {
                let MoveMappings {
                    source,
                    destination,
                    size,
                } = payload.record()?;
                let source = self.move_end(connection, &source)?;
                let destination = self.move_end(connection, &destination)?;
                commands.move_texture_mappings(source, destination, size)?;
            }
        }
        Ok(())
    }

    fn sparse_image(&self, connection: NonZeroU64, handle: u64) -> Result<Image, Fault> {
        let texture = self.object::<TextureId>(connection, handle)?;
        Ok(self.device.sparse_image(texture)?)
    }

    fn move_end(&self, connection: NonZeroU64, record: &MoveEndRecord) -> Result<MoveEnd, Fault> {
        Ok(MoveEnd {
            image: self.sparse_image(connection, record.texture)?,
            level: record.level,
            slice: record.slice,
            origin: record.origin,
        })
    }
}

fn mapping_mode(raw: u64) -> Result<SparseTextureMappingMode, Fault> {
    known(SparseTextureMappingMode::from_raw(raw), "mapping mode")
}
