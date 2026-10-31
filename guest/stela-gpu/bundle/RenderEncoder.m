/* The render encoder and the parallel encoder that hands out its children. */
#include "Bundle.h"

#define ENTRY(code, record) stela_stream_entry(_stream, code, &(record), sizeof(record), NULL, 0)

/* Every stage's bindings, by `MTLRenderStages` bit. */
#define STAGE_BINDINGS(Stage, bit)                                                                 \
	-(void)set##Stage##Buffer : (id)buffer offset : (NSUInteger)offset atIndex                 \
		: (NSUInteger)index                                                                \
	{                                                                                          \
		[self bindBuffer:buffer stage:bit offset:offset index:index];                      \
	}                                                                                          \
	-(void)set##Stage##Buffers : (const id __unsafe_unretained[])buffers offsets               \
		: (const NSUInteger[])offsets withRange : (NSRange)range                           \
	{                                                                                          \
		for (NSUInteger i = 0; i < range.length; i++) {                                    \
			[self bindBuffer:buffers[i]                                                \
				   stage:bit                                                       \
				  offset:offsets[i]                                                \
				   index:range.location + i];                                      \
		}                                                                                  \
	}                                                                                          \
	-(void)set##Stage##BufferOffset : (NSUInteger)offset atIndex : (NSUInteger)index           \
	{                                                                                          \
		StelaStageBufferOffset command = {.stage = bit, .offset = offset, .index = index}; \
		ENTRY(StelaRenderCodeSetBufferOffset, command);                                    \
	}                                                                                          \
	-(void)set##Stage##Bytes : (const void *)bytes length : (NSUInteger)length atIndex         \
		: (NSUInteger)index                                                                \
	{                                                                                          \
		StelaStageBytes command = {.stage = bit, .index = index};                          \
		stela_stream_entry(_stream, StelaRenderCodeSetBytes, &command, sizeof(command),    \
				   bytes, length);                                                 \
	}                                                                                          \
	-(void)set##Stage##Texture : (id)texture atIndex : (NSUInteger)index                       \
	{                                                                                          \
		[self bindTexture:texture stage:bit index:index];                                  \
	}                                                                                          \
	-(void)set##Stage##Textures : (const id __unsafe_unretained[])textures withRange           \
		: (NSRange)range                                                                   \
	{                                                                                          \
		for (NSUInteger i = 0; i < range.length; i++) {                                    \
			[self bindTexture:textures[i] stage:bit index:range.location + i];         \
		}                                                                                  \
	}                                                                                          \
	-(void)set##Stage##SamplerState : (id)sampler atIndex : (NSUInteger)index                  \
	{                                                                                          \
		[self bindSampler:sampler stage:bit clamped:NO min:0 max:0 index:index];           \
	}                                                                                          \
	-(void)set##Stage##SamplerStates : (const id __unsafe_unretained[])samplers withRange      \
		: (NSRange)range                                                                   \
	{                                                                                          \
		for (NSUInteger i = 0; i < range.length; i++) {                                    \
			[self bindSampler:samplers[i]                                              \
				    stage:bit                                                      \
				  clamped:NO                                                       \
				      min:0                                                        \
				      max:0                                                        \
				    index:range.location + i];                                     \
		}                                                                                  \
	}                                                                                          \
	-(void)set##Stage##SamplerState : (id)sampler lodMinClamp : (float)minimum lodMaxClamp     \
		: (float)maximum atIndex : (NSUInteger)index                                       \
	{                                                                                          \
		[self bindSampler:sampler stage:bit clamped:YES min:minimum max:maximum index:index]; \
	}                                                                                          \
	-(void)set##Stage##SamplerStates : (const id __unsafe_unretained[])samplers lodMinClamps   \
		: (const float[])minimums lodMaxClamps : (const float[])maximums withRange         \
		: (NSRange)range                                                                   \
	{                                                                                          \
		for (NSUInteger i = 0; i < range.length; i++) {                                    \
			[self bindSampler:samplers[i]                                              \
				    stage:bit                                                      \
				  clamped:YES                                                      \
				      min:minimums[i]                                              \
				      max:maximums[i]                                              \
				    index:range.location + i];                                     \
		}                                                                                  \
	}                                                                                          \
	-(void)set##Stage##VisibleFunctionTable : (id)table atBufferIndex : (NSUInteger)index      \
	{                                                                                          \
		[self bindBuffer:table stage:bit offset:0 index:index];                            \
	}                                                                                          \
	-(void)set##Stage##VisibleFunctionTables : (const id __unsafe_unretained[])tables          \
		withBufferRange : (NSRange)range                                                   \
	{                                                                                          \
		for (NSUInteger i = 0; i < range.length; i++) {                                    \
			[self bindBuffer:tables[i] stage:bit offset:0 index:range.location + i];   \
		}                                                                                  \
	}

static StelaViewportRecord viewport_record(MTLViewport viewport)
{
	return (StelaViewportRecord){
		.origin_x = viewport.originX,
		.origin_y = viewport.originY,
		.width = viewport.width,
		.height = viewport.height,
		.znear = viewport.znear,
		.zfar = viewport.zfar,
	};
}

@implementation StelaGPURenderEncoder

- (void)bindBuffer:(StelaGPUBuffer *)buffer
	     stage:(uint64_t)stage
	    offset:(NSUInteger)offset
	     index:(NSUInteger)index
{
	[_commands use:buffer];
	StelaStageBuffer command = {
		.stage = stage,
		.buffer = buffer ? buffer->_handle : 0,
		.offset = offset,
		.index = index,
	};
	ENTRY(StelaRenderCodeSetBuffer, command);
}

- (void)bindTexture:(StelaGPUTexture *)texture stage:(uint64_t)stage index:(NSUInteger)index
{
	[_commands use:texture];
	StelaStageTexture command = {.stage = stage, .texture = texture ? texture->_handle : 0, .index = index};
	ENTRY(StelaRenderCodeSetTexture, command);
}

- (void)bindSampler:(StelaGPUSampler *)sampler
	      stage:(uint64_t)stage
	    clamped:(BOOL)clamped
		min:(float)minimum
		max:(float)maximum
	      index:(NSUInteger)index
{
	[_commands use:sampler];
	StelaStageSampler command = {
		.stage = stage,
		.sampler = sampler ? sampler->_handle : 0,
		.index = index,
		.clamped = clamped,
		.lod_min = minimum,
		.lod_max = maximum,
	};
	ENTRY(StelaRenderCodeSetSampler, command);
}

STAGE_BINDINGS(Vertex, MTLRenderStageVertex)
STAGE_BINDINGS(Fragment, MTLRenderStageFragment)
STAGE_BINDINGS(Object, MTLRenderStageObject)
STAGE_BINDINGS(Mesh, MTLRenderStageMesh)

- (void)setVertexBuffer:(StelaGPUBuffer *)buffer
		 offset:(NSUInteger)offset
	attributeStride:(NSUInteger)stride
		atIndex:(NSUInteger)index
{
	[_commands use:buffer];
	StelaVertexBufferStride command = {
		.buffer = buffer ? buffer->_handle : 0,
		.offset = offset,
		.stride = stride,
		.index = index,
	};
	ENTRY(StelaRenderCodeSetVertexBufferStride, command);
}

- (void)setRenderPipelineState:(StelaGPURenderPipeline *)pipeline
{
	[_commands use:pipeline];
	StelaSetPipeline command = {.pipeline = pipeline->_handle};
	ENTRY(StelaRenderCodeSetPipeline, command);
}

- (void)setViewport:(MTLViewport)viewport
{
	StelaViewportRecord record = viewport_record(viewport);
	stela_stream_entry(_stream, StelaRenderCodeSetViewports, NULL, 0, &record, sizeof(record));
}

- (void)setViewports:(const MTLViewport[])viewports count:(NSUInteger)count
{
	StelaViewportRecord *records = calloc(count, sizeof(*records));
	for (NSUInteger i = 0; i < count; i++) {
		records[i] = viewport_record(viewports[i]);
	}
	stela_stream_entry(_stream, StelaRenderCodeSetViewports, NULL, 0, records, count * sizeof(*records));
	free(records);
}

/* `MTLScissorRect` and the record share their layout. */
- (void)setScissorRect:(MTLScissorRect)rectangle
{
	stela_stream_entry(_stream, StelaRenderCodeSetScissorRects, NULL, 0, &rectangle, sizeof(rectangle));
}

- (void)setScissorRects:(const MTLScissorRect[])rectangles count:(NSUInteger)count
{
	stela_stream_entry(_stream, StelaRenderCodeSetScissorRects, NULL, 0, rectangles, count * sizeof(*rectangles));
}

- (void)setCullMode:(NSUInteger)mode
{
	StelaMode command = {.mode = mode};
	ENTRY(StelaRenderCodeSetCullMode, command);
}

- (void)setFrontFacingWinding:(NSUInteger)winding
{
	StelaMode command = {.mode = winding};
	ENTRY(StelaRenderCodeSetFrontFacingWinding, command);
}

- (void)setDepthBias:(float)bias slopeScale:(float)scale clamp:(float)clamp
{
	StelaDepthBias command = {.constant = bias, .slope = scale, .clamp = clamp};
	ENTRY(StelaRenderCodeSetDepthBias, command);
}

- (void)setDepthStencilState:(StelaGPUDepthStencil *)state
{
	StelaDepthStencilRecord record;
	if (state) {
		record = state->_record;
	} else {
		stela_depth_stencil_record(nil, &record);
	}
	ENTRY(StelaRenderCodeSetDepthStencilState, record);
}

- (void)setStencilFrontReferenceValue:(uint32_t)front backReferenceValue:(uint32_t)back
{
	StelaStencilReference command = {.front = front, .back = back};
	ENTRY(StelaRenderCodeSetStencilReference, command);
}

- (void)setStencilReferenceValue:(uint32_t)value
{
	[self setStencilFrontReferenceValue:value backReferenceValue:value];
}

- (void)setBlendColorRed:(float)red green:(float)green blue:(float)blue alpha:(float)alpha
{
	StelaBlendColor command = {.color = {red, green, blue, alpha}};
	ENTRY(StelaRenderCodeSetBlendColor, command);
}

- (void)setTriangleFillMode:(NSUInteger)mode
{
	StelaMode command = {.mode = mode};
	ENTRY(StelaRenderCodeSetTriangleFillMode, command);
}

- (void)setDepthClipMode:(NSUInteger)mode
{
	StelaMode command = {.mode = mode};
	ENTRY(StelaRenderCodeSetDepthClipMode, command);
}

/* `MTLVertexAmplificationViewMapping` and the record share their layout. */
- (void)setVertexAmplificationCount:(NSUInteger)count viewMappings:(const MTLVertexAmplificationViewMapping *)mappings
{
	stela_stream_entry(_stream, StelaRenderCodeSetVertexAmplification, NULL, 0, mappings,
			   mappings ? count * sizeof(*mappings) : 0);
}

- (void)setVisibilityResultMode:(NSUInteger)mode offset:(NSUInteger)offset
{
	StelaVisibilityMode command = {.mode = mode, .offset = offset};
	ENTRY(StelaRenderCodeSetVisibilityResultMode, command);
}

- (void)setColorStoreAction:(NSUInteger)action atIndex:(NSUInteger)index
{
	StelaColorStoreAction command = {.action = action, .index = index};
	ENTRY(StelaRenderCodeSetColorStoreAction, command);
}

- (void)setDepthStoreAction:(NSUInteger)action
{
	StelaMode command = {.mode = action};
	ENTRY(StelaRenderCodeSetDepthStoreAction, command);
}

- (void)setStencilStoreAction:(NSUInteger)action
{
	StelaMode command = {.mode = action};
	ENTRY(StelaRenderCodeSetStencilStoreAction, command);
}

- (void)setColorStoreActionOptions:(NSUInteger)options atIndex:(NSUInteger)index
{
	StelaColorStoreActionOptions command = {.options = options, .index = index};
	ENTRY(StelaRenderCodeSetColorStoreActionOptions, command);
}

- (void)setDepthStoreActionOptions:(NSUInteger)options
{
	StelaMode command = {.mode = options};
	ENTRY(StelaRenderCodeSetDepthStoreActionOptions, command);
}

- (void)setStencilStoreActionOptions:(NSUInteger)options
{
	StelaMode command = {.mode = options};
	ENTRY(StelaRenderCodeSetStencilStoreActionOptions, command);
}

- (void)memoryBarrierWithScope:(NSUInteger)scope
		   afterStages:(NSUInteger)after
		  beforeStages:(NSUInteger)before
{
	StelaRenderBarrier command = {.scope = scope, .after = after, .before = before};
	ENTRY(StelaRenderCodeMemoryBarrier, command);
}

/* A barrier on all the kinds of resources is the wider one the hardware has. */
- (void)memoryBarrierWithResources:(const id __unsafe_unretained[])resources
			     count:(NSUInteger)count
		       afterStages:(NSUInteger)after
		      beforeStages:(NSUInteger)before
{
	(void)resources;
	(void)count;
	[self memoryBarrierWithScope:MTLBarrierScopeBuffers | MTLBarrierScopeTextures | MTLBarrierScopeRenderTargets
			 afterStages:after
			beforeStages:before];
}

- (void)textureBarrier
{
	[self memoryBarrierWithScope:MTLBarrierScopeTextures
			 afterStages:MTLRenderStageFragment
			beforeStages:MTLRenderStageFragment];
}

- (void)drawPrimitives:(NSUInteger)primitive
	   vertexStart:(NSUInteger)start
	   vertexCount:(NSUInteger)count
	 instanceCount:(NSUInteger)instances
	  baseInstance:(NSUInteger)base
{
	StelaDrawPrimitives command = {
		.primitive = primitive,
		.vertex_start = start,
		.vertex_count = count,
		.instance_count = instances,
		.base_instance = base,
	};
	ENTRY(StelaRenderCodeDrawPrimitives, command);
}

- (void)drawPrimitives:(NSUInteger)primitive
	   vertexStart:(NSUInteger)start
	   vertexCount:(NSUInteger)count
	 instanceCount:(NSUInteger)instances
{
	[self drawPrimitives:primitive vertexStart:start vertexCount:count instanceCount:instances baseInstance:0];
}

- (void)drawPrimitives:(NSUInteger)primitive vertexStart:(NSUInteger)start vertexCount:(NSUInteger)count
{
	[self drawPrimitives:primitive vertexStart:start vertexCount:count instanceCount:1 baseInstance:0];
}

- (void)drawPrimitives:(NSUInteger)primitive
	    indirectBuffer:(StelaGPUBuffer *)buffer
      indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:buffer];
	StelaDrawIndirect command = {.primitive = primitive, .buffer = buffer->_handle, .offset = offset};
	ENTRY(StelaRenderCodeDrawIndirect, command);
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
	[_commands use:indices];
	StelaDrawIndexed command = {
		.primitive = primitive,
		.index_count = count,
		.index_type = type,
		.index_buffer = indices->_handle,
		.index_buffer_offset = offset,
		.instance_count = instances,
		.base_vertex = vertex,
		.base_instance = base,
	};
	ENTRY(StelaRenderCodeDrawIndexed, command);
}

- (void)drawIndexedPrimitives:(NSUInteger)primitive
		   indexCount:(NSUInteger)count
		    indexType:(NSUInteger)type
		  indexBuffer:(id)indices
	    indexBufferOffset:(NSUInteger)offset
		instanceCount:(NSUInteger)instances
{
	[self drawIndexedPrimitives:primitive
			 indexCount:count
			  indexType:type
			indexBuffer:indices
		  indexBufferOffset:offset
		      instanceCount:instances
			 baseVertex:0
		       baseInstance:0];
}

- (void)drawIndexedPrimitives:(NSUInteger)primitive
		   indexCount:(NSUInteger)count
		    indexType:(NSUInteger)type
		  indexBuffer:(id)indices
	    indexBufferOffset:(NSUInteger)offset
{
	[self drawIndexedPrimitives:primitive
			 indexCount:count
			  indexType:type
			indexBuffer:indices
		  indexBufferOffset:offset
		      instanceCount:1
			 baseVertex:0
		       baseInstance:0];
}

- (void)drawIndexedPrimitives:(NSUInteger)primitive
		    indexType:(NSUInteger)type
		  indexBuffer:(StelaGPUBuffer *)indices
	    indexBufferOffset:(NSUInteger)indexOffset
	       indirectBuffer:(StelaGPUBuffer *)buffer
	 indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:indices];
	[_commands use:buffer];
	StelaDrawIndexedIndirect command = {
		.primitive = primitive,
		.index_type = type,
		.index_buffer = indices->_handle,
		.index_buffer_offset = indexOffset,
		.buffer = buffer->_handle,
		.offset = offset,
	};
	ENTRY(StelaRenderCodeDrawIndexedIndirect, command);
}

- (void)setTessellationFactorBuffer:(StelaGPUBuffer *)buffer
			     offset:(NSUInteger)offset
		     instanceStride:(NSUInteger)stride
{
	[_commands use:buffer];
	StelaFactorBuffer command = {
		.buffer = buffer ? buffer->_handle : 0,
		.offset = offset,
		.instance_stride = stride,
	};
	ENTRY(StelaRenderCodeSetTessellationFactorBuffer, command);
}

- (void)setTessellationFactorScale:(float)scale
{
	StelaFactorScale command = {.scale = scale};
	ENTRY(StelaRenderCodeSetTessellationFactorScale, command);
}

- (StelaPatchSourceRecord)patchSource:(NSUInteger)points
			 patchIndices:(StelaGPUBuffer *)patches
			  patchOffset:(NSUInteger)patchOffset
			 pointIndices:(StelaGPUBuffer *)controls
			  pointOffset:(NSUInteger)controlOffset
{
	[_commands use:patches];
	[_commands use:controls];
	return (StelaPatchSourceRecord){
		.control_points = points,
		.patch_index_buffer = patches ? patches->_handle : 0,
		.patch_index_offset = patchOffset,
		.control_point_index_buffer = controls ? controls->_handle : 0,
		.control_point_index_offset = controlOffset,
	};
}

- (void)drawPatches:(NSUInteger)points
	    patchStart:(NSUInteger)start
	    patchCount:(NSUInteger)count
      patchIndexBuffer:(id)patches
patchIndexBufferOffset:(NSUInteger)offset
	 instanceCount:(NSUInteger)instances
	  baseInstance:(NSUInteger)base
{
	StelaDrawPatches command = {
		.source = [self patchSource:points patchIndices:patches patchOffset:offset pointIndices:nil pointOffset:0],
		.patch_start = start,
		.patch_count = count,
		.instance_count = instances,
		.base_instance = base,
	};
	ENTRY(StelaRenderCodeDrawPatches, command);
}

- (void)drawPatches:(NSUInteger)points
      patchIndexBuffer:(id)patches
patchIndexBufferOffset:(NSUInteger)patchOffset
	indirectBuffer:(StelaGPUBuffer *)buffer
  indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:buffer];
	StelaDrawPatchesIndirect command = {
		.source = [self patchSource:points patchIndices:patches patchOffset:patchOffset pointIndices:nil pointOffset:0],
		.buffer = buffer->_handle,
		.offset = offset,
	};
	ENTRY(StelaRenderCodeDrawPatchesIndirect, command);
}

- (void)drawIndexedPatches:(NSUInteger)points
			patchStart:(NSUInteger)start
			patchCount:(NSUInteger)count
		  patchIndexBuffer:(id)patches
	    patchIndexBufferOffset:(NSUInteger)patchOffset
	   controlPointIndexBuffer:(id)controls
     controlPointIndexBufferOffset:(NSUInteger)controlOffset
		     instanceCount:(NSUInteger)instances
		      baseInstance:(NSUInteger)base
{
	StelaDrawPatches command = {
		.source = [self patchSource:points
			       patchIndices:patches
				patchOffset:patchOffset
			       pointIndices:controls
				pointOffset:controlOffset],
		.patch_start = start,
		.patch_count = count,
		.instance_count = instances,
		.base_instance = base,
	};
	ENTRY(StelaRenderCodeDrawPatches, command);
}

- (void)drawIndexedPatches:(NSUInteger)points
		  patchIndexBuffer:(id)patches
	    patchIndexBufferOffset:(NSUInteger)patchOffset
	   controlPointIndexBuffer:(id)controls
     controlPointIndexBufferOffset:(NSUInteger)controlOffset
		    indirectBuffer:(StelaGPUBuffer *)buffer
	      indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:buffer];
	StelaDrawPatchesIndirect command = {
		.source = [self patchSource:points
			       patchIndices:patches
				patchOffset:patchOffset
			       pointIndices:controls
				pointOffset:controlOffset],
		.buffer = buffer->_handle,
		.offset = offset,
	};
	ENTRY(StelaRenderCodeDrawPatchesIndirect, command);
}

- (void)setObjectThreadgroupMemoryLength:(NSUInteger)length atIndex:(NSUInteger)index
{
	StelaSetThreadgroupMemory command = {.length = length, .index = index};
	ENTRY(StelaRenderCodeSetObjectThreadgroupMemory, command);
}

- (void)drawMeshThreadgroups:(MTLSize)groups
    threadsPerObjectThreadgroup:(MTLSize)object
      threadsPerMeshThreadgroup:(MTLSize)mesh
{
	StelaDrawMesh command = {
		.size = {groups.width, groups.height, groups.depth},
		.object_threads = {object.width, object.height, object.depth},
		.mesh_threads = {mesh.width, mesh.height, mesh.depth},
	};
	ENTRY(StelaRenderCodeDrawMeshThreadgroups, command);
}

- (void)drawMeshThreads:(MTLSize)threads
    threadsPerObjectThreadgroup:(MTLSize)object
      threadsPerMeshThreadgroup:(MTLSize)mesh
{
	StelaDrawMesh command = {
		.size = {threads.width, threads.height, threads.depth},
		.object_threads = {object.width, object.height, object.depth},
		.mesh_threads = {mesh.width, mesh.height, mesh.depth},
	};
	ENTRY(StelaRenderCodeDrawMeshThreads, command);
}

- (void)drawMeshThreadgroupsWithIndirectBuffer:(StelaGPUBuffer *)buffer
			  indirectBufferOffset:(NSUInteger)offset
		   threadsPerObjectThreadgroup:(MTLSize)object
		     threadsPerMeshThreadgroup:(MTLSize)mesh
{
	[_commands use:buffer];
	StelaDrawMeshIndirect command = {
		.buffer = buffer->_handle,
		.offset = offset,
		.object_threads = {object.width, object.height, object.depth},
		.mesh_threads = {mesh.width, mesh.height, mesh.depth},
	};
	ENTRY(StelaRenderCodeDrawMeshIndirect, command);
}

- (void)executeCommandsInBuffer:(StelaGPUIndirectCommandBuffer *)buffer withRange:(NSRange)range
{
	[_commands use:buffer];
	StelaIndirectRange command = {.buffer = buffer->_handle, .first = range.location, .count = range.length};
	ENTRY(StelaIndirectCodeExecute, command);
}

- (void)executeCommandsInBuffer:(StelaGPUIndirectCommandBuffer *)buffer
		 indirectBuffer:(StelaGPUBuffer *)ranges
	   indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:buffer];
	[_commands use:ranges];
	StelaExecuteIndirect command = {.buffer = buffer->_handle, .range_buffer = ranges->_handle, .offset = offset};
	ENTRY(StelaIndirectCodeExecuteIndirect, command);
}

@end

/*
 * A child encoder writes a stream of its own, which `endEncoding` of the
 * parallel encoder joins in the order they were made, starting each from
 * Metal's default state as a pass does.
 */
@interface StelaGPUChildEncoder : StelaGPURenderEncoder
@end

@implementation StelaGPUChildEncoder

- (void)endEncoding
{
}

@end

@implementation StelaGPUParallelEncoder {
	NSMutableArray *_children;
	os_unfair_lock _lock;
}

- (instancetype)initWithCommandBuffer:(StelaGPUCommandBuffer *)commands stream:(StelaStream *)stream
{
	self = [super initWithCommandBuffer:commands stream:stream];
	if (self) {
		_children = [NSMutableArray arrayWithCapacity:8];
		_lock = OS_UNFAIR_LOCK_INIT;
	}
	return self;
}

- (id)renderCommandEncoder
{
	StelaStream *stream = calloc(1, sizeof(*stream));
	StelaGPUChildEncoder *child = [[StelaGPUChildEncoder alloc] initWithCommandBuffer:_commands stream:stream];
	[child setCullMode:MTLCullModeNone];
	[child setFrontFacingWinding:MTLWindingClockwise];
	[child setTriangleFillMode:MTLTriangleFillModeFill];
	[child setDepthClipMode:MTLDepthClipModeClip];
	[child setDepthBias:0 slopeScale:0 clamp:0];
	[child setDepthStencilState:nil];
	[child setStencilReferenceValue:0];
	[child setBlendColorRed:0 green:0 blue:0 alpha:0];
	[child setVisibilityResultMode:MTLVisibilityResultModeDisabled offset:0];
	os_unfair_lock_lock(&_lock);
	[_children addObject:child];
	os_unfair_lock_unlock(&_lock);
	return child;
}

- (void)endEncoding
{
	for (NSUInteger i = 0; i < _children.count; i++) {
		StelaGPUChildEncoder *child = [_children objectAtIndex:i];
		stela_stream_append(_stream, child->_stream);
		stela_stream_free(child->_stream);
		free(child->_stream);
		child->_stream = NULL;
	}
	[super endEncoding];
}

- (void)setColorStoreAction:(NSUInteger)action atIndex:(NSUInteger)index
{
	StelaColorStoreAction command = {.action = action, .index = index};
	ENTRY(StelaRenderCodeSetColorStoreAction, command);
}

- (void)setDepthStoreAction:(NSUInteger)action
{
	StelaMode command = {.mode = action};
	ENTRY(StelaRenderCodeSetDepthStoreAction, command);
}

- (void)setStencilStoreAction:(NSUInteger)action
{
	StelaMode command = {.mode = action};
	ENTRY(StelaRenderCodeSetStencilStoreAction, command);
}

- (void)setColorStoreActionOptions:(NSUInteger)options atIndex:(NSUInteger)index
{
	StelaColorStoreActionOptions command = {.options = options, .index = index};
	ENTRY(StelaRenderCodeSetColorStoreActionOptions, command);
}

- (void)setDepthStoreActionOptions:(NSUInteger)options
{
	StelaMode command = {.mode = options};
	ENTRY(StelaRenderCodeSetDepthStoreActionOptions, command);
}

- (void)setStencilStoreActionOptions:(NSUInteger)options
{
	StelaMode command = {.mode = options};
	ENTRY(StelaRenderCodeSetStencilStoreActionOptions, command);
}

@end
