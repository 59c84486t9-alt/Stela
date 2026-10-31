/*
 * Indirect command buffers. CPU encoding collects in a stream of `EncodeIndirect`
 * entries, each naming its command, which the service takes at the next commit
 * or reset: a loop of setters then crosses the gate once.
 */
#include "Bundle.h"

@interface StelaGPUIndirectCommandBuffer ()
- (void)encode:(uint64_t)command code:(uint32_t)code record:(const void *)record bytes:(size_t)bytes;
@end

#define ENCODE(entry, value) [_buffer encode:_index code:entry record:&(value) bytes:sizeof(value)]
#define SIGNAL(entry) [_buffer encode:_index code:entry record:NULL bytes:0]

@implementation StelaGPUIndirectRenderCommand

- (void)setRenderPipelineState:(StelaGPURenderPipeline *)pipeline
{
	StelaSetPipeline record = {.pipeline = pipeline->_handle};
	ENCODE(StelaIndirectRenderCodeSetPipeline, record);
}

- (void)setBuffer:(StelaGPUBuffer *)buffer stage:(uint64_t)stage offset:(NSUInteger)offset index:(NSUInteger)index
{
	StelaStageBuffer record = {.stage = stage, .buffer = buffer->_handle, .offset = offset, .index = index};
	ENCODE(StelaIndirectRenderCodeSetBuffer, record);
}

- (void)setVertexBuffer:(id)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	[self setBuffer:buffer stage:MTLRenderStageVertex offset:offset index:index];
}

- (void)setFragmentBuffer:(id)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	[self setBuffer:buffer stage:MTLRenderStageFragment offset:offset index:index];
}

- (void)setObjectBuffer:(id)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	[self setBuffer:buffer stage:MTLRenderStageObject offset:offset index:index];
}

- (void)setMeshBuffer:(id)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	[self setBuffer:buffer stage:MTLRenderStageMesh offset:offset index:index];
}

- (void)setVertexBuffer:(StelaGPUBuffer *)buffer
		 offset:(NSUInteger)offset
	attributeStride:(NSUInteger)stride
		atIndex:(NSUInteger)index
{
	StelaVertexBufferStride record = {
		.buffer = buffer->_handle,
		.offset = offset,
		.stride = stride,
		.index = index,
	};
	ENCODE(StelaIndirectRenderCodeSetVertexBufferStride, record);
}

- (void)setCullMode:(NSUInteger)mode
{
	StelaMode record = {.mode = mode};
	ENCODE(StelaIndirectRenderCodeSetCullMode, record);
}

- (void)setFrontFacingWinding:(NSUInteger)winding
{
	StelaMode record = {.mode = winding};
	ENCODE(StelaIndirectRenderCodeSetFrontFacingWinding, record);
}

- (void)setTriangleFillMode:(NSUInteger)mode
{
	StelaMode record = {.mode = mode};
	ENCODE(StelaIndirectRenderCodeSetTriangleFillMode, record);
}

- (void)setDepthClipMode:(NSUInteger)mode
{
	StelaMode record = {.mode = mode};
	ENCODE(StelaIndirectRenderCodeSetDepthClipMode, record);
}

- (void)setDepthBias:(float)bias slopeScale:(float)scale clamp:(float)clamp
{
	StelaDepthBias record = {.constant = bias, .slope = scale, .clamp = clamp};
	ENCODE(StelaIndirectRenderCodeSetDepthBias, record);
}

- (void)setDepthStencilState:(StelaGPUDepthStencil *)state
{
	StelaDepthStencilRecord record;
	if (state) {
		record = state->_record;
	} else {
		stela_depth_stencil_record(nil, &record);
	}
	ENCODE(StelaIndirectRenderCodeSetDepthStencilState, record);
}

- (void)setBarrier
{
	SIGNAL(StelaIndirectRenderCodeSetBarrier);
}

- (void)clearBarrier
{
	SIGNAL(StelaIndirectRenderCodeClearBarrier);
}

- (void)reset
{
	SIGNAL(StelaIndirectRenderCodeReset);
}

- (void)drawPrimitives:(NSUInteger)primitive
	   vertexStart:(NSUInteger)start
	   vertexCount:(NSUInteger)count
	 instanceCount:(NSUInteger)instances
	  baseInstance:(NSUInteger)base
{
	StelaDrawPrimitives record = {
		.primitive = primitive,
		.vertex_start = start,
		.vertex_count = count,
		.instance_count = instances,
		.base_instance = base,
	};
	ENCODE(StelaIndirectRenderCodeDrawPrimitives, record);
}

- (void)drawIndexedPrimitives:(NSUInteger)primitive
		   indexCount:(NSUInteger)count
		    indexType:(NSUInteger)type
		  indexBuffer:(StelaGPUBuffer *)indices
	    indexBufferOffset:(NSUInteger)offset
		instanceCount:(NSUInteger)instances
		   baseVertex:(NSInteger)vertex
		 baseInstance:(NSUInteger)base
{
	StelaDrawIndexed record = {
		.primitive = primitive,
		.index_count = count,
		.index_type = type,
		.index_buffer = indices->_handle,
		.index_buffer_offset = offset,
		.instance_count = instances,
		.base_vertex = vertex,
		.base_instance = base,
	};
	ENCODE(StelaIndirectRenderCodeDrawIndexed, record);
}

- (void)patches:(StelaPatchSourceRecord)source
	      start:(NSUInteger)start
	      count:(NSUInteger)count
	  instances:(NSUInteger)instances
	       base:(NSUInteger)base
	    factors:(StelaGPUBuffer *)factors
       factorOffset:(NSUInteger)offset
       factorStride:(NSUInteger)stride
{
	StelaIndirectPatches record = {
		.draw = {
			.source = source,
			.patch_start = start,
			.patch_count = count,
			.instance_count = instances,
			.base_instance = base,
		},
		.factors = {.buffer = factors->_handle, .offset = offset, .instance_stride = stride},
	};
	ENCODE(StelaIndirectRenderCodeDrawPatches, record);
}

- (void)drawPatches:(NSUInteger)points
				  patchStart:(NSUInteger)start
				  patchCount:(NSUInteger)count
			    patchIndexBuffer:(StelaGPUBuffer *)patches
		      patchIndexBufferOffset:(NSUInteger)patchOffset
			       instanceCount:(NSUInteger)instances
				baseInstance:(NSUInteger)base
		    tessellationFactorBuffer:(id)factors
	      tessellationFactorBufferOffset:(NSUInteger)factorOffset
	tessellationFactorBufferInstanceStride:(NSUInteger)stride
{
	StelaPatchSourceRecord source = {
		.control_points = points,
		.patch_index_buffer = patches ? patches->_handle : 0,
		.patch_index_offset = patchOffset,
	};
	[self patches:source
		       start:start
		       count:count
		   instances:instances
			base:base
		     factors:factors
		factorOffset:factorOffset
		factorStride:stride];
}

- (void)drawIndexedPatches:(NSUInteger)points
				  patchStart:(NSUInteger)start
				  patchCount:(NSUInteger)count
			    patchIndexBuffer:(StelaGPUBuffer *)patches
		      patchIndexBufferOffset:(NSUInteger)patchOffset
		     controlPointIndexBuffer:(StelaGPUBuffer *)controls
	       controlPointIndexBufferOffset:(NSUInteger)controlOffset
			       instanceCount:(NSUInteger)instances
				baseInstance:(NSUInteger)base
		    tessellationFactorBuffer:(id)factors
	      tessellationFactorBufferOffset:(NSUInteger)factorOffset
	tessellationFactorBufferInstanceStride:(NSUInteger)stride
{
	StelaPatchSourceRecord source = {
		.control_points = points,
		.patch_index_buffer = patches ? patches->_handle : 0,
		.patch_index_offset = patchOffset,
		.control_point_index_buffer = controls->_handle,
		.control_point_index_offset = controlOffset,
	};
	[self patches:source
		       start:start
		       count:count
		   instances:instances
			base:base
		     factors:factors
		factorOffset:factorOffset
		factorStride:stride];
}

- (void)setObjectThreadgroupMemoryLength:(NSUInteger)length atIndex:(NSUInteger)index
{
	StelaSetThreadgroupMemory record = {.length = length, .index = index};
	ENCODE(StelaIndirectRenderCodeSetObjectThreadgroupMemory, record);
}

- (void)drawMeshThreadgroups:(MTLSize)groups
    threadsPerObjectThreadgroup:(MTLSize)object
      threadsPerMeshThreadgroup:(MTLSize)mesh
{
	StelaDrawMesh record = {
		.size = {groups.width, groups.height, groups.depth},
		.object_threads = {object.width, object.height, object.depth},
		.mesh_threads = {mesh.width, mesh.height, mesh.depth},
	};
	ENCODE(StelaIndirectRenderCodeDrawMeshThreadgroups, record);
}

- (void)drawMeshThreads:(MTLSize)threads
    threadsPerObjectThreadgroup:(MTLSize)object
      threadsPerMeshThreadgroup:(MTLSize)mesh
{
	StelaDrawMesh record = {
		.size = {threads.width, threads.height, threads.depth},
		.object_threads = {object.width, object.height, object.depth},
		.mesh_threads = {mesh.width, mesh.height, mesh.depth},
	};
	ENCODE(StelaIndirectRenderCodeDrawMeshThreads, record);
}

@end

@implementation StelaGPUIndirectComputeCommand

- (void)setComputePipelineState:(StelaGPUComputePipeline *)pipeline
{
	StelaSetPipeline record = {.pipeline = pipeline->_handle};
	ENCODE(StelaIndirectComputeCodeSetPipeline, record);
}

- (void)setKernelBuffer:(StelaGPUBuffer *)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	StelaSetBuffer record = {.buffer = buffer->_handle, .offset = offset, .index = index};
	ENCODE(StelaIndirectComputeCodeSetBuffer, record);
}

- (void)setThreadgroupMemoryLength:(NSUInteger)length atIndex:(NSUInteger)index
{
	StelaSetThreadgroupMemory record = {.length = length, .index = index};
	ENCODE(StelaIndirectComputeCodeSetThreadgroupMemory, record);
}

- (void)setStageInRegion:(MTLRegion)region
{
	StelaStageInRegion record = {
		.origin = {region.origin.x, region.origin.y, region.origin.z},
		.size = {region.size.width, region.size.height, region.size.depth},
	};
	ENCODE(StelaIndirectComputeCodeSetStageInRegion, record);
}

- (void)setBarrier
{
	SIGNAL(StelaIndirectComputeCodeSetBarrier);
}

- (void)clearBarrier
{
	SIGNAL(StelaIndirectComputeCodeClearBarrier);
}

- (void)reset
{
	SIGNAL(StelaIndirectComputeCodeReset);
}

- (void)concurrentDispatchThreadgroups:(MTLSize)groups threadsPerThreadgroup:(MTLSize)threads
{
	StelaDispatch record = {
		.size = {groups.width, groups.height, groups.depth},
		.threads = {threads.width, threads.height, threads.depth},
	};
	ENCODE(StelaIndirectComputeCodeDispatchThreadgroups, record);
}

- (void)concurrentDispatchThreads:(MTLSize)size threadsPerThreadgroup:(MTLSize)threads
{
	StelaDispatch record = {
		.size = {size.width, size.height, size.depth},
		.threads = {threads.width, threads.height, threads.depth},
	};
	ENCODE(StelaIndirectComputeCodeDispatchThreads, record);
}

@end

@implementation StelaGPUIndirectCommandBuffer {
	StelaStream _encoding;
	os_unfair_lock _lock;
}

- (void)dealloc
{
	[_device forgetIndirect:self];
	stela_stream_free(&_encoding);
}

- (NSUInteger)size
{
	return _size;
}

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_resourceID};
}

- (id)indirectRenderCommandAtIndex:(NSUInteger)index
{
	StelaGPUIndirectRenderCommand *command = [StelaGPUIndirectRenderCommand new];
	command->_buffer = self;
	command->_index = index;
	return command;
}

- (id)indirectComputeCommandAtIndex:(NSUInteger)index
{
	StelaGPUIndirectComputeCommand *command = [StelaGPUIndirectComputeCommand new];
	command->_buffer = self;
	command->_index = index;
	return command;
}

- (void)encode:(uint64_t)command code:(uint32_t)code record:(const void *)record bytes:(size_t)bytes
{
	StelaIndirectTarget target = {.command = command};
	os_unfair_lock_lock(&_lock);
	bool first = _encoding.length == 0;
	stela_stream_entry(&_encoding, code, &target, sizeof(target), record, bytes);
	os_unfair_lock_unlock(&_lock);
	if (first) {
		[_device noteIndirect:self];
	}
}

- (void)flush
{
	os_unfair_lock_lock(&_lock);
	if (_encoding.length) {
		StelaEncodeIndirectRequest request = {
			.buffer = _handle,
			.commands = stela_span(_encoding.bytes, _encoding.length),
		};
		StelaEmpty nothing;
		StelaFailure failure;
		StelaSpans spans = {.reads = &request.commands, .read_count = 1};
		if (STELA_CALL_SPANS(&_device->_gate, EncodeIndirect, &request, &nothing, spans, &failure)
		    != StelaStatusOk) {
			stela_report("encoding an indirect command", &failure);
		}
		_encoding.length = 0;
	}
	os_unfair_lock_unlock(&_lock);
}

- (void)resetWithRange:(NSRange)range
{
	[self flush];
	StelaIndirectRange request = {.buffer = _handle, .first = range.location, .count = range.length};
	StelaEmpty nothing;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, ResetIndirect, &request, &nothing, &failure) != StelaStatusOk) {
		stela_report("resetWithRange:", &failure);
	}
}

@end

@implementation StelaGPUDevice (Indirect)

- (id)newIndirectCommandBufferWithDescriptor:(id)descriptor
			     maxCommandCount:(NSUInteger)count
				     options:(NSUInteger)options
{
	uint64_t inherits = ([descriptor inheritPipelineState] ? StelaIndirectInherits_PIPELINE_STATE : 0)
			    | ([descriptor inheritBuffers] ? StelaIndirectInherits_BUFFERS : 0)
			    | ([descriptor inheritCullMode] ? StelaIndirectInherits_CULL_MODE : 0)
			    | ([descriptor inheritDepthStencilState] ? StelaIndirectInherits_DEPTH_STENCIL_STATE : 0)
			    | ([descriptor inheritDepthBias] ? StelaIndirectInherits_DEPTH_BIAS : 0)
			    | ([descriptor inheritDepthClipMode] ? StelaIndirectInherits_DEPTH_CLIP_MODE : 0)
			    | ([descriptor inheritFrontFacingWinding] ? StelaIndirectInherits_FRONT_FACING_WINDING : 0)
			    | ([descriptor inheritTriangleFillMode] ? StelaIndirectInherits_TRIANGLE_FILL_MODE : 0);
	StelaNewIndirectRequest request = {
		.command_types = [descriptor commandTypes],
		.inherits = inherits,
		.max_command_count = count,
		.max_vertex_buffer_bind_count = [descriptor maxVertexBufferBindCount],
		.max_fragment_buffer_bind_count = [descriptor maxFragmentBufferBindCount],
		.max_kernel_buffer_bind_count = [descriptor maxKernelBufferBindCount],
		.max_kernel_threadgroup_memory_bind_count = [descriptor maxKernelThreadgroupMemoryBindCount],
		.max_object_buffer_bind_count = [descriptor maxObjectBufferBindCount],
		.max_mesh_buffer_bind_count = [descriptor maxMeshBufferBindCount],
		.support_ray_tracing = [descriptor supportRayTracing],
		.support_dynamic_attribute_stride = [descriptor supportDynamicAttributeStride],
	};
	StelaHandle response;
	StelaFailure failure;
	if (STELA_CALL(&_gate, NewIndirectCommandBuffer, &request, &response, &failure) != StelaStatusOk) {
		stela_report("an indirect command buffer", &failure);
		return nil;
	}
	StelaHandle identified = {.handle = response.handle};
	StelaValue resource = {};
	if (STELA_CALL(&_gate, IndirectResourceId, &identified, &resource, &failure) != StelaStatusOk) {
		stela_report("an indirect command buffer's resource ID", &failure);
		[self releaseHandle:response.handle];
		return nil;
	}
	StelaGPUIndirectCommandBuffer *buffer = [[StelaGPUIndirectCommandBuffer alloc] initWithDevice:self
											       handle:response.handle];
	buffer->_options = options;
	buffer->_size = count;
	buffer->_resourceID = resource.value;
	return buffer;
}

@end
