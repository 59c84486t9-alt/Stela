//! Commands on indirect command buffers: executions in render and compute
//! encoders, and the blit encoder's resets, copies and optimizations.
use super::Payload;
use crate::metal::{
    command_buffer::{CommandBuffer, indirect::ExecutionRange},
    indirect::IndirectCommandBufferId,
    service::{
        Service, command_range,
        wire::{
            Fault,
            commands::{CopyCommands, ExecuteIndirect, IndirectCode, IndirectRange},
        },
    },
    shader::Compiler,
    vulkan::backend::Backend,
};
use core::num::NonZeroU64;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn indirect(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: IndirectCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            IndirectCode::ExecuteIndirect => {
                let ExecuteIndirect {
                    buffer,
                    range_buffer,
                    offset,
                } = payload.record()?;
                let id = self.object::<IndirectCommandBufferId>(connection, buffer)?;
                let range = ExecutionRange::Indirect {
                    buffer: self.buffer_ref(connection, range_buffer)?,
                    offset,
                };
                commands.execute_commands(&mut self.device.resolver(), id, range)?;
            }
            IndirectCode::Copy => {
                let request: CopyCommands = payload.record()?;
                let source = self.object(connection, request.source)?;
                let destination = self.object(connection, request.destination)?;
                let range = command_range(request.first, request.count)?;
                let index = usize::try_from(request.index)
                    .map_err(|_| Fault::malformed("command index"))?;
                commands.copy_indirect_commands(
                    &mut self.device.resolver(),
                    source,
                    range,
                    destination,
                    index,
                )?;
            }
            IndirectCode::Execute | IndirectCode::Reset | IndirectCode::Optimize => {
                let IndirectRange {
                    buffer,
                    first,
                    count,
                } = payload.record()?;
                let id = self.object::<IndirectCommandBufferId>(connection, buffer)?;
                let range = command_range(first, count)?;
                let resolver = &mut self.device.resolver();
                match code {
                    IndirectCode::Execute => {
                        commands.execute_commands(resolver, id, ExecutionRange::Direct(range))
                    }
                    IndirectCode::Reset => commands.reset_commands(resolver, id, range),
                    _ => commands.optimize_indirect_commands(resolver, id, range),
                }?;
            }
        }
        Ok(())
    }
}
