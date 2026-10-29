//! Records a [`Segment`]'s commands into a primary command buffer.
use super::{
    NativeBackend, failure, handle,
    objects::{self, extent, offset, stages, subresource},
};
use crate::gpu::metal::{
    binding::{AccumulateArguments, PushConstants, ResolveArguments, SelectArguments},
    command_buffer::Segment,
    error::{Error, Result},
    pass::ClearValue,
    vulkan::{
        Access, StencilOp,
        command::{Attachment, Barrier, Command, DepthStencil, Rendering, VertexBuffer},
    },
};
use alloc::vec::Vec;
use ash::vk;

/// Records `segment` into `buffer`, first moving `adopt` (new images) from
/// `UNDEFINED` to `GENERAL`.
pub(super) fn segment(
    backend: &NativeBackend,
    buffer: vk::CommandBuffer,
    adopt: &[(vk::Image, vk::ImageAspectFlags)],
    segment: &Segment,
) -> Result<()> {
    let recorder = Recorder { backend, buffer };
    let device = &backend.device;
    let begin =
        vk::CommandBufferBeginInfo::default().flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
    // SAFETY: the buffer was just allocated from the backend's pool.
    unsafe { device.begin_command_buffer(buffer, &begin) }.map_err(failure)?;
    recorder.adopt(adopt);
    recorder.bind_heap();
    segment
        .commands
        .iter()
        .try_for_each(|command| recorder.command(command))?;
    // SAFETY: the buffer is in the recording state.
    unsafe { device.end_command_buffer(buffer) }.map_err(failure)
}

struct Recorder<'a> {
    backend: &'a NativeBackend,
    buffer: vk::CommandBuffer,
}

fn clear(value: ClearValue) -> vk::ClearValue {
    match value {
        ClearValue::Float(float32) => vk::ClearValue {
            color: vk::ClearColorValue { float32 },
        },
        ClearValue::Sint(int32) => vk::ClearValue {
            color: vk::ClearColorValue { int32 },
        },
        ClearValue::Uint(uint32) => vk::ClearValue {
            color: vk::ClearColorValue { uint32 },
        },
        ClearValue::DepthStencil { depth, stencil } => vk::ClearValue {
            depth_stencil: vk::ClearDepthStencilValue { depth, stencil },
        },
    }
}

fn attachment(attachment: &Attachment) -> vk::RenderingAttachmentInfo<'static> {
    let info = vk::RenderingAttachmentInfo::default()
        .image_view(handle(attachment.view.0))
        .image_layout(vk::ImageLayout::GENERAL)
        .load_op(vk::AttachmentLoadOp::from_raw(
            attachment.load_op.raw() as i32
        ))
        .store_op(vk::AttachmentStoreOp::from_raw(
            attachment.store_op.raw() as i32
        ))
        .clear_value(clear(attachment.clear));
    match attachment.resolve {
        None => info,
        Some((mode, view)) => info
            .resolve_mode(vk::ResolveModeFlags::from_raw(mode.bits()))
            .resolve_image_view(handle(view.0))
            .resolve_image_layout(vk::ImageLayout::GENERAL),
    }
}

fn access(access: Access) -> vk::AccessFlags2 {
    vk::AccessFlags2::from_raw(access.bits())
}

fn stencil_op(op: StencilOp) -> vk::StencilOp {
    vk::StencilOp::from_raw(op.raw() as i32)
}

fn compare_op(op: crate::gpu::metal::vulkan::CompareOp) -> vk::CompareOp {
    vk::CompareOp::from_raw(op.raw() as i32)
}

fn unsupported<'a, T>(fns: Option<&'a T>, name: &'static str) -> Result<&'a T> {
    fns.ok_or(Error::Unsupported(name))
}

impl Recorder<'_> {
    fn device(&self) -> &ash::Device {
        &self.backend.device
    }

    fn adopt(&self, images: &[(vk::Image, vk::ImageAspectFlags)]) {
        if images.is_empty() {
            return;
        }
        let barriers: Vec<_> = images
            .iter()
            .map(|&(image, aspects)| {
                vk::ImageMemoryBarrier2::default()
                    .dst_stage_mask(vk::PipelineStageFlags2::ALL_COMMANDS)
                    .dst_access_mask(vk::AccessFlags2::MEMORY_READ | vk::AccessFlags2::MEMORY_WRITE)
                    .old_layout(vk::ImageLayout::UNDEFINED)
                    .new_layout(vk::ImageLayout::GENERAL)
                    .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                    .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                    .image(image)
                    .subresource_range(objects::whole(aspects))
            })
            .collect();
        let dependency = vk::DependencyInfo::default().image_memory_barriers(&barriers);
        // SAFETY: the images are alive and no earlier command used them.
        unsafe {
            self.device()
                .cmd_pipeline_barrier2(self.buffer, &dependency)
        };
    }

    fn bind_heap(&self) {
        let sets = [self.backend.heap.set];
        for point in [
            vk::PipelineBindPoint::GRAPHICS,
            vk::PipelineBindPoint::COMPUTE,
        ] {
            // SAFETY: the heap set matches set 0 of the pipeline layout.
            unsafe {
                self.device().cmd_bind_descriptor_sets(
                    self.buffer,
                    point,
                    self.backend.layout,
                    0,
                    &sets,
                    &[],
                );
            }
        }
    }

    fn push_constants(&self, constants: &PushConstants) {
        // SAFETY: the range is the layout's single push-constant range.
        unsafe {
            self.device().cmd_push_constants(
                self.buffer,
                self.backend.layout,
                vk::ShaderStageFlags::ALL,
                0,
                &constants.encode(),
            );
        }
    }

    fn barrier(&self, barrier: &Barrier) {
        let barriers = [vk::MemoryBarrier2::default()
            .src_stage_mask(stages(barrier.src_stages))
            .src_access_mask(access(barrier.src_access))
            .dst_stage_mask(stages(barrier.dst_stages))
            .dst_access_mask(access(barrier.dst_access))];
        let dependency = vk::DependencyInfo::default().memory_barriers(&barriers);
        // SAFETY: a global memory barrier outside or inside a render pass
        // the Metal layer split for it.
        unsafe {
            self.device()
                .cmd_pipeline_barrier2(self.buffer, &dependency)
        };
    }

    fn begin_rendering(&self, rendering: &Rendering) {
        let colors: Vec<_> = rendering
            .color
            .iter()
            .map(|slot| slot.as_ref().map_or_else(Default::default, attachment))
            .collect();
        let depth = rendering.depth.as_ref().map(attachment);
        let stencil = rendering.stencil.as_ref().map(attachment);
        let [width, height] = rendering.extent;
        let mut info = vk::RenderingInfo::default()
            .render_area(vk::Rect2D {
                offset: vk::Offset2D::default(),
                extent: vk::Extent2D { width, height },
            })
            .layer_count(rendering.layer_count)
            .color_attachments(&colors);
        if let Some(depth) = depth.as_ref() {
            info = info.depth_attachment(depth);
        }
        if let Some(stencil) = stencil.as_ref() {
            info = info.stencil_attachment(stencil);
        }
        // SAFETY: every view is alive and in `GENERAL`.
        unsafe { self.device().cmd_begin_rendering(self.buffer, &info) };
    }

    fn depth_stencil(&self, state: &DepthStencil) {
        let device = self.device();
        let buffer = self.buffer;
        let faces = [vk::StencilFaceFlags::FRONT, vk::StencilFaceFlags::BACK];
        // SAFETY: each state is dynamic in every graphics pipeline.
        unsafe {
            device.cmd_set_depth_test_enable(buffer, state.depth_test);
            device.cmd_set_depth_write_enable(buffer, state.depth_write);
            device.cmd_set_depth_compare_op(buffer, compare_op(state.depth_compare));
            device.cmd_set_stencil_test_enable(buffer, state.stencil_test);
            for (face, (fail, pass, depth_fail, compare, compare_mask, write_mask)) in
                faces.into_iter().zip(state.faces)
            {
                device.cmd_set_stencil_op(
                    buffer,
                    face,
                    stencil_op(fail),
                    stencil_op(pass),
                    stencil_op(depth_fail),
                    compare_op(compare),
                );
                device.cmd_set_stencil_compare_mask(buffer, face, compare_mask);
                device.cmd_set_stencil_write_mask(buffer, face, write_mask);
            }
        }
    }

    /// Binds runs of buffers that all set, or all keep, their strides:
    /// `pStrides` covers every buffer of a call or none.
    fn bind_vertex_buffers(&self, first: u32, buffers: &[VertexBuffer]) {
        let mut binding = first;
        for run in buffers.chunk_by(|a, b| a.stride.is_some() == b.stride.is_some()) {
            let handles: Vec<vk::Buffer> =
                run.iter().map(|vertex| handle(vertex.buffer.0)).collect();
            let offsets: Vec<u64> = run.iter().map(|vertex| vertex.offset).collect();
            let sizes: Vec<u64> = run.iter().map(|vertex| vertex.size).collect();
            let strides: Option<Vec<u64>> = run.iter().map(|vertex| vertex.stride).collect();
            // SAFETY: the buffers are alive with vertex-buffer usage.
            unsafe {
                self.device().cmd_bind_vertex_buffers2(
                    self.buffer,
                    binding,
                    &handles,
                    &offsets,
                    Some(&sizes),
                    strides.as_deref(),
                );
            }
            binding += run.len() as u32;
        }
    }

    /// Dispatches an internal kernel over `threads` with `arguments` in the
    /// push constants.
    fn internal(&self, pipeline: vk::Pipeline, arguments: u64, threads: u32, workgroup: u32) {
        // SAFETY: the internal pipeline uses the device's pipeline layout.
        unsafe {
            self.device()
                .cmd_bind_pipeline(self.buffer, vk::PipelineBindPoint::COMPUTE, pipeline);
        }
        self.push_constants(&PushConstants {
            arguments,
            ..PushConstants::default()
        });
        let groups = threads.div_ceil(workgroup);
        // SAFETY: the kernel reads only `arguments` and the addresses in it.
        unsafe { self.device().cmd_dispatch(self.buffer, groups, 1, 1) };
    }

    fn command(&self, command: &Command) -> Result<()> {
        let device = self.device();
        let buffer = self.buffer;
        let fns = &self.backend.fns;
        // SAFETY: for every call below, the Metal layer records commands valid
        // for the device's features over live objects, and each dynamic
        // state it sets is dynamic in the bound pipeline.
        unsafe {
            match command {
                Command::Barrier(barrier) => self.barrier(barrier),
                Command::BeginRendering(rendering) => self.begin_rendering(rendering),
                Command::EndRendering => device.cmd_end_rendering(buffer),
                &Command::BindPipeline {
                    bind_point,
                    pipeline,
                } => device.cmd_bind_pipeline(
                    buffer,
                    vk::PipelineBindPoint::from_raw(bind_point.raw() as i32),
                    handle(pipeline.0),
                ),
                Command::PushConstants(constants) => self.push_constants(constants),
                Command::SetViewports(viewports) => {
                    let viewports: Vec<_> = viewports
                        .iter()
                        .map(|viewport| vk::Viewport {
                            x: viewport.x,
                            y: viewport.y,
                            width: viewport.width,
                            height: viewport.height,
                            min_depth: viewport.min_depth,
                            max_depth: viewport.max_depth,
                        })
                        .collect();
                    device.cmd_set_viewport_with_count(buffer, &viewports);
                }
                Command::SetScissors(rects) => {
                    let rects: Vec<_> = rects
                        .iter()
                        .map(|rect| vk::Rect2D {
                            offset: vk::Offset2D {
                                x: rect.offset[0],
                                y: rect.offset[1],
                            },
                            extent: vk::Extent2D {
                                width: rect.extent[0],
                                height: rect.extent[1],
                            },
                        })
                        .collect();
                    device.cmd_set_scissor_with_count(buffer, &rects);
                }
                &Command::SetDepthBias {
                    enable,
                    constant,
                    clamp,
                    slope,
                } => {
                    device.cmd_set_depth_bias_enable(buffer, enable);
                    device.cmd_set_depth_bias(buffer, constant, clamp, slope);
                }
                Command::SetBlendConstants(constants) => {
                    device.cmd_set_blend_constants(buffer, constants);
                }
                &Command::SetStencilReference { front, back } => {
                    device.cmd_set_stencil_reference(buffer, vk::StencilFaceFlags::FRONT, front);
                    device.cmd_set_stencil_reference(buffer, vk::StencilFaceFlags::BACK, back);
                }
                Command::SetDepthStencil(state) => self.depth_stencil(state),
                Command::SetCullMode(mode) => {
                    device.cmd_set_cull_mode(buffer, vk::CullModeFlags::from_raw(mode.bits()));
                }
                Command::SetFrontFace(face) => {
                    device.cmd_set_front_face(buffer, vk::FrontFace::from_raw(face.raw() as i32));
                }
                Command::SetPrimitiveTopology(topology) => device.cmd_set_primitive_topology(
                    buffer,
                    vk::PrimitiveTopology::from_raw(topology.raw() as i32),
                ),
                &Command::SetPrimitiveRestart(enable) => {
                    device.cmd_set_primitive_restart_enable(buffer, enable);
                }
                &Command::SetRasterizerDiscard(enable) => {
                    device.cmd_set_rasterizer_discard_enable(buffer, enable);
                }
                Command::SetPolygonMode(mode) => {
                    unsupported(fns.dynamic_state3.as_ref(), "dynamic polygon mode")?
                        .cmd_set_polygon_mode(buffer, vk::PolygonMode::from_raw(mode.raw() as i32));
                }
                &Command::SetDepthClamp(clamp) => {
                    let state3 = unsupported(fns.dynamic_state3.as_ref(), "dynamic depth clamp")?;
                    state3.cmd_set_depth_clamp_enable(buffer, clamp);
                    state3.cmd_set_depth_clip_enable(buffer, !clamp);
                }
                Command::SetSampleLocations { samples, locations } => {
                    let state3 =
                        unsupported(fns.dynamic_state3.as_ref(), "dynamic sample locations")?;
                    state3.cmd_set_sample_locations_enable(buffer, !locations.is_empty());
                    if !locations.is_empty() {
                        let locations: Vec<_> = locations
                            .iter()
                            .map(|&[x, y]| vk::SampleLocationEXT { x, y })
                            .collect();
                        let info = vk::SampleLocationsInfoEXT::default()
                            .sample_locations_per_pixel(vk::SampleCountFlags::from_raw(
                                samples.bits(),
                            ))
                            .sample_location_grid_size(vk::Extent2D {
                                width: 1,
                                height: 1,
                            })
                            .sample_locations(&locations);
                        unsupported(fns.sample_locations.as_ref(), "sample locations")?
                            .cmd_set_sample_locations(buffer, &info);
                    }
                }
                Command::BindVertexBuffers { first, buffers } => {
                    self.bind_vertex_buffers(*first, buffers);
                }
                &Command::BindIndexBuffer {
                    buffer: index,
                    offset,
                    index_type,
                } => device.cmd_bind_index_buffer(
                    buffer,
                    handle(index.0),
                    offset,
                    vk::IndexType::from_raw(index_type.raw() as i32),
                ),
                &Command::Draw {
                    vertex_count,
                    instance_count,
                    first_vertex,
                    first_instance,
                } => device.cmd_draw(
                    buffer,
                    vertex_count,
                    instance_count,
                    first_vertex,
                    first_instance,
                ),
                &Command::DrawIndexed {
                    index_count,
                    instance_count,
                    first_index,
                    vertex_offset,
                    first_instance,
                } => device.cmd_draw_indexed(
                    buffer,
                    index_count,
                    instance_count,
                    first_index,
                    vertex_offset,
                    first_instance,
                ),
                &Command::DrawIndirect {
                    buffer: arguments,
                    offset,
                } => device.cmd_draw_indirect(
                    buffer,
                    handle(arguments.0),
                    offset,
                    1,
                    size_of::<vk::DrawIndirectCommand>() as u32,
                ),
                &Command::DrawIndexedIndirect {
                    buffer: arguments,
                    offset,
                } => device.cmd_draw_indexed_indirect(
                    buffer,
                    handle(arguments.0),
                    offset,
                    1,
                    size_of::<vk::DrawIndexedIndirectCommand>() as u32,
                ),
                &Command::DrawMeshTasks([x, y, z]) => {
                    unsupported(fns.mesh.as_ref(), "mesh shaders")?
                        .cmd_draw_mesh_tasks(buffer, x, y, z);
                }
                &Command::DrawMeshTasksIndirect {
                    buffer: arguments,
                    offset,
                } => unsupported(fns.mesh.as_ref(), "mesh shaders")?.cmd_draw_mesh_tasks_indirect(
                    buffer,
                    handle(arguments.0),
                    offset,
                    1,
                    size_of::<vk::DrawMeshTasksIndirectCommandEXT>() as u32,
                ),
                &Command::Dispatch([x, y, z]) => device.cmd_dispatch(buffer, x, y, z),
                &Command::DispatchIndirect {
                    buffer: arguments,
                    offset,
                } => device.cmd_dispatch_indirect(buffer, handle(arguments.0), offset),
                Command::CopyBuffer { src, dst, regions } => {
                    let regions: Vec<_> = regions
                        .iter()
                        .map(|region| {
                            vk::BufferCopy2::default()
                                .src_offset(region.src_offset)
                                .dst_offset(region.dst_offset)
                                .size(region.size)
                        })
                        .collect();
                    let info = vk::CopyBufferInfo2::default()
                        .src_buffer(handle(src.0))
                        .dst_buffer(handle(dst.0))
                        .regions(&regions);
                    device.cmd_copy_buffer2(buffer, &info);
                }
                Command::CopyBufferToImage { src, dst, regions } => {
                    let regions: Vec<_> = regions.iter().map(buffer_image).collect();
                    let info = vk::CopyBufferToImageInfo2::default()
                        .src_buffer(handle(src.0))
                        .dst_image(handle(dst.0))
                        .dst_image_layout(vk::ImageLayout::GENERAL)
                        .regions(&regions);
                    device.cmd_copy_buffer_to_image2(buffer, &info);
                }
                Command::CopyImageToBuffer { src, dst, regions } => {
                    let regions: Vec<_> = regions.iter().map(buffer_image).collect();
                    let info = vk::CopyImageToBufferInfo2::default()
                        .src_image(handle(src.0))
                        .src_image_layout(vk::ImageLayout::GENERAL)
                        .dst_buffer(handle(dst.0))
                        .regions(&regions);
                    device.cmd_copy_image_to_buffer2(buffer, &info);
                }
                Command::CopyImage { src, dst, regions } => {
                    let regions: Vec<_> = regions
                        .iter()
                        .map(|region| {
                            vk::ImageCopy2::default()
                                .src_subresource(subresource(region.src))
                                .src_offset(offset(region.src_offset))
                                .dst_subresource(subresource(region.dst))
                                .dst_offset(offset(region.dst_offset))
                                .extent(extent(region.extent))
                        })
                        .collect();
                    let info = vk::CopyImageInfo2::default()
                        .src_image(handle(src.0))
                        .src_image_layout(vk::ImageLayout::GENERAL)
                        .dst_image(handle(dst.0))
                        .dst_image_layout(vk::ImageLayout::GENERAL)
                        .regions(&regions);
                    device.cmd_copy_image2(buffer, &info);
                }
                Command::BlitImage {
                    src,
                    dst,
                    regions,
                    filter,
                } => {
                    let regions: Vec<_> = regions
                        .iter()
                        .map(|region| {
                            vk::ImageBlit2::default()
                                .src_subresource(subresource(region.src))
                                .src_offsets(region.src_bounds.map(offset))
                                .dst_subresource(subresource(region.dst))
                                .dst_offsets(region.dst_bounds.map(offset))
                        })
                        .collect();
                    let info = vk::BlitImageInfo2::default()
                        .src_image(handle(src.0))
                        .src_image_layout(vk::ImageLayout::GENERAL)
                        .dst_image(handle(dst.0))
                        .dst_image_layout(vk::ImageLayout::GENERAL)
                        .regions(&regions)
                        .filter(vk::Filter::from_raw(filter.raw() as i32));
                    device.cmd_blit_image2(buffer, &info);
                }
                &Command::FillBuffer {
                    buffer: target,
                    offset,
                    size,
                    data,
                } => device.cmd_fill_buffer(buffer, handle(target.0), offset, size, data),
                &Command::ResetQueryPool { pool, first, count } => {
                    device.cmd_reset_query_pool(buffer, handle(pool.0), first, count);
                }
                &Command::BeginQuery {
                    pool,
                    query,
                    precise,
                } => {
                    let flags = if precise {
                        vk::QueryControlFlags::PRECISE
                    } else {
                        vk::QueryControlFlags::empty()
                    };
                    device.cmd_begin_query(buffer, handle(pool.0), query, flags);
                }
                &Command::EndQuery { pool, query } => {
                    device.cmd_end_query(buffer, handle(pool.0), query);
                }
                &Command::WriteTimestamp { pool, query, stage } => {
                    device.cmd_write_timestamp2(buffer, stages(stage), handle(pool.0), query);
                }
                &Command::CopyQueryResults {
                    pool,
                    first,
                    count,
                    dst,
                    offset,
                    stride,
                    wait,
                } => {
                    let mut flags = vk::QueryResultFlags::TYPE_64;
                    if wait {
                        flags |= vk::QueryResultFlags::WAIT;
                    }
                    device.cmd_copy_query_pool_results(
                        buffer,
                        handle(pool.0),
                        first,
                        count,
                        handle(dst.0),
                        offset,
                        stride,
                        flags,
                    );
                }
                &Command::AccumulateResults { arguments, runs } => self.internal(
                    self.backend.accumulate,
                    arguments,
                    runs,
                    AccumulateArguments::WORKGROUP_SIZE,
                ),
                &Command::SelectCommands { arguments, count } => self.internal(
                    self.backend.select,
                    arguments,
                    count,
                    SelectArguments::WORKGROUP_SIZE,
                ),
                &Command::ResolveCommands { arguments, count } => self.internal(
                    self.backend.resolve,
                    arguments,
                    count,
                    ResolveArguments::WORKGROUP_SIZE,
                ),
                &Command::BeginConditionalRendering {
                    buffer: flags,
                    offset,
                } => {
                    let info = vk::ConditionalRenderingBeginInfoEXT::default()
                        .buffer(handle(flags.0))
                        .offset(offset);
                    (fns.conditional.fp().cmd_begin_conditional_rendering_ext)(buffer, &info);
                }
                Command::EndConditionalRendering => {
                    (fns.conditional.fp().cmd_end_conditional_rendering_ext)(buffer);
                }
                Command::ExecuteGeneratedCommands(commands) => {
                    self.backend.generated().execute(buffer, commands);
                }
            }
        }
        Ok(())
    }
}

fn buffer_image(
    region: &crate::gpu::metal::vulkan::command::BufferImageCopy,
) -> vk::BufferImageCopy2<'static> {
    vk::BufferImageCopy2::default()
        .buffer_offset(region.buffer_offset)
        .buffer_row_length(region.buffer_row_length)
        .buffer_image_height(region.buffer_image_height)
        .image_subresource(subresource(region.subresource))
        .image_offset(offset(region.offset))
        .image_extent(extent(region.extent))
}
