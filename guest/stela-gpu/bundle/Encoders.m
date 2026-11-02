/*
 * The blit, compute and resource state encoders, and what every encoder shares.
 * An encoder writes one entry per call. `useResource:`, `useHeap:` and fences
 * write none: every resource is resident and the hazard tracker orders the
 * queue. Residency declarations still keep the declared objects alive on
 * command buffers with retained references. See docs/design/metal-device.md.
 */
#include "Bundle.h"

#define ENTRY(code, record) stela_stream_entry(_stream, code, &(record), sizeof(record), NULL, 0)

static StelaRegionRecord region_record(NSUInteger slice, NSUInteger level, MTLOrigin origin, MTLSize size)
{
	return (StelaRegionRecord){
		.slice = slice,
		.level = level,
		.origin = {origin.x, origin.y, origin.z},
		.size = {size.width, size.height, size.depth},
	};
}

@implementation StelaGPUEncoder {
	NSString *_label;
	StelaGPUEncoderInfo *_errorInfo;
	/* What `endEncoding` samples. */
	struct {
		__unsafe_unretained StelaGPUCounterSampleBuffer *buffer;
		NSUInteger index;
	} _endSamples[4];
	NSUInteger _endSampleCount;
}

- (instancetype)initWithCommandBuffer:(StelaGPUCommandBuffer *)commands stream:(StelaStream *)stream
{
	self = [super init];
	if (self) {
		_commands = commands;
		_stream = stream;
		_errorInfo = [commands recordEncoder];
	}
	return self;
}

- (id)device
{
	return _commands->_device;
}

- (NSString *)label
{
	return _label;
}

- (void)setLabel:(NSString *)label
{
	_label = [label copy];
	_errorInfo.label = label ?: @"";
}

- (void)endEncoding
{
	for (NSUInteger i = 0; i < _endSampleCount; i++) {
		[self sampleCountersInBuffer:_endSamples[i].buffer atSampleIndex:_endSamples[i].index withBarrier:YES];
	}
	stela_stream_entry(_stream, StelaCommandBufferCodeEndEncoding, NULL, 0, NULL, 0);
}

- (void)insertDebugSignpost:(NSString *)name
{
	(void)name;
}

- (void)pushDebugGroup:(NSString *)name
{
	(void)name;
}

- (void)popDebugGroup
{
}

- (void)updateFence:(id)fence
{
	(void)fence;
}

- (void)waitForFence:(id)fence
{
	(void)fence;
}

- (void)useResource:(id)resource usage:(NSUInteger)usage
{
	(void)usage;
	[_commands use:resource];
}

- (void)useResources:(const id __unsafe_unretained[])resources count:(NSUInteger)count usage:(NSUInteger)usage
{
	for (NSUInteger i = 0; i < count; i++) {
		[self useResource:resources[i] usage:usage];
	}
}

- (void)useHeap:(id)heap
{
	[_commands use:heap];
}

- (void)useHeaps:(const id __unsafe_unretained[])heaps count:(NSUInteger)count
{
	for (NSUInteger i = 0; i < count; i++) {
		[self useHeap:heaps[i]];
	}
}

- (void)useResource:(id)resource usage:(NSUInteger)usage stages:(NSUInteger)stages
{
	(void)stages;
	[self useResource:resource usage:usage];
}

- (void)useResources:(const id __unsafe_unretained[])resources
	       count:(NSUInteger)count
	       usage:(NSUInteger)usage
	      stages:(NSUInteger)stages
{
	(void)stages;
	[self useResources:resources count:count usage:usage];
}

- (void)useHeap:(id)heap stages:(NSUInteger)stages
{
	(void)stages;
	[self useHeap:heap];
}

- (void)useHeaps:(const id __unsafe_unretained[])heaps count:(NSUInteger)count stages:(NSUInteger)stages
{
	(void)stages;
	[self useHeaps:heaps count:count];
}

/* The queue's hazard barriers cover every graphics stage between encoders. */
- (void)updateFence:(id)fence afterStages:(NSUInteger)stages
{
	(void)stages;
	[self updateFence:fence];
}

- (void)waitForFence:(id)fence beforeStages:(NSUInteger)stages
{
	(void)stages;
	[self waitForFence:fence];
}

- (void)sampleCountersInBuffer:(StelaGPUCounterSampleBuffer *)buffer
		 atSampleIndex:(NSUInteger)index
		   withBarrier:(BOOL)barrier
{
	[_commands use:buffer];
	StelaSampleCounters command = {.buffer = buffer->_handle, .index = index, .barrier = barrier};
	ENTRY(StelaCommandBufferCodeSampleCounters, command);
}

/* What a descriptor's `sampleBufferAttachments` ask: the encoder's first and last samples. */
- (void)sampleAttachments:(id)attachments
{
	for (NSUInteger i = 0; i < 4; i++) {
		id attachment = [attachments objectAtIndexedSubscript:i];
		StelaGPUCounterSampleBuffer *buffer = [attachment sampleBuffer];
		if (!buffer) {
			continue;
		}
		NSUInteger start = [attachment startOfEncoderSampleIndex];
		if (start != MTLCounterDontSample) {
			[self sampleCountersInBuffer:buffer atSampleIndex:start withBarrier:NO];
		}
		NSUInteger end = [attachment endOfEncoderSampleIndex];
		if (end != MTLCounterDontSample) {
			/* The descriptor keeps the buffer until the pass ends. */
			[_commands use:buffer];
			_endSamples[_endSampleCount].buffer = buffer;
			_endSamples[_endSampleCount++].index = end;
		}
	}
}

@end

@implementation StelaGPUBlitEncoder

- (void)copyFromBuffer:(StelaGPUBuffer *)source
	  sourceOffset:(NSUInteger)sourceOffset
	      toBuffer:(StelaGPUBuffer *)destination
     destinationOffset:(NSUInteger)destinationOffset
		  size:(NSUInteger)size
{
	[_commands use:source];
	[_commands use:destination];
	StelaCopyBuffer command = {
		.source = source->_handle,
		.source_offset = sourceOffset,
		.destination = destination->_handle,
		.destination_offset = destinationOffset,
		.size = size,
	};
	ENTRY(StelaBlitCodeCopyBuffer, command);
}

- (void)copyFromBuffer:(StelaGPUBuffer *)source
	       sourceOffset:(NSUInteger)offset
	  sourceBytesPerRow:(NSUInteger)bytesPerRow
	sourceBytesPerImage:(NSUInteger)bytesPerImage
		 sourceSize:(MTLSize)size
		  toTexture:(StelaGPUTexture *)texture
	   destinationSlice:(NSUInteger)slice
	   destinationLevel:(NSUInteger)level
	  destinationOrigin:(MTLOrigin)origin
		    options:(NSUInteger)options
{
	[_commands use:source];
	[_commands use:texture];
	StelaCopyBufferToTexture command = {
		.source = {source->_handle, offset, bytesPerRow, bytesPerImage},
		.texture = texture->_handle,
		.region = region_record(slice, level, origin, size),
		.options = options,
	};
	ENTRY(StelaBlitCodeCopyBufferToTexture, command);
}

- (void)copyFromBuffer:(id)source
	       sourceOffset:(NSUInteger)offset
	  sourceBytesPerRow:(NSUInteger)bytesPerRow
	sourceBytesPerImage:(NSUInteger)bytesPerImage
		 sourceSize:(MTLSize)size
		  toTexture:(id)texture
	   destinationSlice:(NSUInteger)slice
	   destinationLevel:(NSUInteger)level
	  destinationOrigin:(MTLOrigin)origin
{
	[self copyFromBuffer:source
		 sourceOffset:offset
	    sourceBytesPerRow:bytesPerRow
	  sourceBytesPerImage:bytesPerImage
		   sourceSize:size
		    toTexture:texture
	     destinationSlice:slice
	     destinationLevel:level
	    destinationOrigin:origin
		      options:0];
}

- (void)copyFromTexture:(StelaGPUTexture *)texture
		sourceSlice:(NSUInteger)slice
		sourceLevel:(NSUInteger)level
	       sourceOrigin:(MTLOrigin)origin
		 sourceSize:(MTLSize)size
		   toBuffer:(StelaGPUBuffer *)destination
	  destinationOffset:(NSUInteger)offset
     destinationBytesPerRow:(NSUInteger)bytesPerRow
   destinationBytesPerImage:(NSUInteger)bytesPerImage
		    options:(NSUInteger)options
{
	[_commands use:texture];
	[_commands use:destination];
	StelaCopyTextureToBuffer command = {
		.texture = texture->_handle,
		.region = region_record(slice, level, origin, size),
		.destination = {destination->_handle, offset, bytesPerRow, bytesPerImage},
		.options = options,
	};
	ENTRY(StelaBlitCodeCopyTextureToBuffer, command);
}

- (void)copyFromTexture:(id)texture
		sourceSlice:(NSUInteger)slice
		sourceLevel:(NSUInteger)level
	       sourceOrigin:(MTLOrigin)origin
		 sourceSize:(MTLSize)size
		   toBuffer:(id)destination
	  destinationOffset:(NSUInteger)offset
     destinationBytesPerRow:(NSUInteger)bytesPerRow
   destinationBytesPerImage:(NSUInteger)bytesPerImage
{
	[self copyFromTexture:texture
			 sourceSlice:slice
			 sourceLevel:level
			sourceOrigin:origin
			  sourceSize:size
			    toBuffer:destination
		   destinationOffset:offset
	      destinationBytesPerRow:bytesPerRow
	    destinationBytesPerImage:bytesPerImage
			     options:0];
}

- (void)copyFromTexture:(StelaGPUTexture *)source
	      sourceSlice:(NSUInteger)sourceSlice
	      sourceLevel:(NSUInteger)sourceLevel
	     sourceOrigin:(MTLOrigin)sourceOrigin
	       sourceSize:(MTLSize)size
		toTexture:(StelaGPUTexture *)destination
	 destinationSlice:(NSUInteger)slice
	 destinationLevel:(NSUInteger)level
	destinationOrigin:(MTLOrigin)origin
{
	[_commands use:source];
	[_commands use:destination];
	StelaCopyTexture command = {
		.source = source->_handle,
		.region = region_record(sourceSlice, sourceLevel, sourceOrigin, size),
		.destination = destination->_handle,
		.destination_slice = slice,
		.destination_level = level,
		.destination_origin = {origin.x, origin.y, origin.z},
	};
	ENTRY(StelaBlitCodeCopyTexture, command);
}

- (void)copyFromTexture:(StelaGPUTexture *)source
	     sourceSlice:(NSUInteger)sourceSlice
	     sourceLevel:(NSUInteger)sourceLevel
	       toTexture:(StelaGPUTexture *)destination
	destinationSlice:(NSUInteger)slice
	destinationLevel:(NSUInteger)level
	      sliceCount:(NSUInteger)sliceCount
	      levelCount:(NSUInteger)levelCount
{
	[_commands use:source];
	[_commands use:destination];
	StelaCopyTextureSlices command = {
		.source = source->_handle,
		.source_slice = sourceSlice,
		.source_level = sourceLevel,
		.destination = destination->_handle,
		.destination_slice = slice,
		.destination_level = level,
		.slice_count = sliceCount,
		.level_count = levelCount,
	};
	ENTRY(StelaBlitCodeCopyTextureSlices, command);
}

- (void)copyFromTexture:(StelaGPUTexture *)source toTexture:(StelaGPUTexture *)destination
{
	NSUInteger faces = source->_textureType == MTLTextureTypeCube || source->_textureType == MTLTextureTypeCubeArray ? 6 : 1;
	NSUInteger levels = source->_mipmapLevelCount < destination->_mipmapLevelCount ? source->_mipmapLevelCount
										       : destination->_mipmapLevelCount;
	[self copyFromTexture:source
		   sourceSlice:0
		   sourceLevel:0
		     toTexture:destination
	      destinationSlice:0
	      destinationLevel:0
		    sliceCount:source->_arrayLength * faces
		    levelCount:levels];
}

- (void)fillBuffer:(StelaGPUBuffer *)buffer range:(NSRange)range value:(uint8_t)value
{
	[_commands use:buffer];
	StelaFillBuffer command = {
		.buffer = buffer->_handle,
		.start = range.location,
		.length = range.length,
		.value = value,
	};
	ENTRY(StelaBlitCodeFillBuffer, command);
}

- (void)generateMipmapsForTexture:(StelaGPUTexture *)texture
{
	[_commands use:texture];
	StelaResource command = {.resource = texture->_handle};
	ENTRY(StelaBlitCodeGenerateMipmaps, command);
}

- (void)synchronizeResource:(StelaGPUObject *)resource
{
	[_commands use:resource];
	StelaResource command = {.resource = resource->_handle};
	ENTRY(StelaBlitCodeSynchronize, command);
}

- (void)synchronizeTexture:(StelaGPUTexture *)texture slice:(NSUInteger)slice level:(NSUInteger)level
{
	[_commands use:texture];
	StelaSynchronizeTexture command = {.texture = texture->_handle, .slice = slice, .level = level};
	ENTRY(StelaBlitCodeSynchronizeTexture, command);
}

/* A hint with no effect: contents keep one layout for CPU and GPU. */
- (void)optimizeContentsForGPUAccess:(id)texture
{
	(void)texture;
}

- (void)optimizeContentsForGPUAccess:(id)texture slice:(NSUInteger)slice level:(NSUInteger)level
{
	(void)texture;
	(void)slice;
	(void)level;
}

- (void)optimizeContentsForCPUAccess:(id)texture
{
	(void)texture;
}

- (void)optimizeContentsForCPUAccess:(id)texture slice:(NSUInteger)slice level:(NSUInteger)level
{
	(void)texture;
	(void)slice;
	(void)level;
}

- (void)resolveCounters:(StelaGPUCounterSampleBuffer *)buffer
	      inRange:(NSRange)range
    destinationBuffer:(StelaGPUBuffer *)destination
    destinationOffset:(NSUInteger)offset
{
	[_commands use:buffer];
	[_commands use:destination];
	StelaResolveCounters command = {
		.buffer = buffer->_handle,
		.first = range.location,
		.count = range.length,
		.destination = destination->_handle,
		.offset = offset,
	};
	ENTRY(StelaBlitCodeResolveCounters, command);
}

- (void)resetCommandsInBuffer:(StelaGPUIndirectCommandBuffer *)buffer withRange:(NSRange)range
{
	[_commands use:buffer];
	StelaIndirectRange command = {.buffer = buffer->_handle, .first = range.location, .count = range.length};
	ENTRY(StelaIndirectCodeReset, command);
}

- (void)copyIndirectCommandBuffer:(StelaGPUIndirectCommandBuffer *)source
		      sourceRange:(NSRange)range
		      destination:(StelaGPUIndirectCommandBuffer *)destination
		 destinationIndex:(NSUInteger)index
{
	[_commands use:source];
	[_commands use:destination];
	StelaCopyCommands command = {
		.source = source->_handle,
		.first = range.location,
		.count = range.length,
		.destination = destination->_handle,
		.index = index,
	};
	ENTRY(StelaIndirectCodeCopy, command);
}

- (void)optimizeIndirectCommandBuffer:(StelaGPUIndirectCommandBuffer *)buffer withRange:(NSRange)range
{
	[_commands use:buffer];
	StelaIndirectRange command = {.buffer = buffer->_handle, .first = range.location, .count = range.length};
	ENTRY(StelaIndirectCodeOptimize, command);
}

@end

@implementation StelaGPUComputeEncoder

- (NSUInteger)dispatchType
{
	return _dispatchType;
}

- (void)setComputePipelineState:(StelaGPUComputePipeline *)pipeline
{
	[_commands use:pipeline];
	StelaSetPipeline command = {.pipeline = pipeline->_handle};
	ENTRY(StelaComputeCodeSetPipeline, command);
}

- (void)setBuffer:(StelaGPUBuffer *)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	[_commands use:buffer];
	StelaSetBuffer command = {.buffer = buffer ? buffer->_handle : 0, .offset = offset, .index = index};
	ENTRY(StelaComputeCodeSetBuffer, command);
}

- (void)setBuffers:(const id __unsafe_unretained[])buffers
	   offsets:(const NSUInteger[])offsets
	 withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setBuffer:buffers[i] offset:offsets[i] atIndex:range.location + i];
	}
}

- (void)setBufferOffset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	StelaSetBufferOffset command = {.offset = offset, .index = index};
	ENTRY(StelaComputeCodeSetBufferOffset, command);
}

- (void)setBytes:(const void *)bytes length:(NSUInteger)length atIndex:(NSUInteger)index
{
	StelaSetBytes command = {.index = index};
	stela_stream_entry(_stream, StelaComputeCodeSetBytes, &command, sizeof(command), bytes, length);
}

- (void)setTexture:(StelaGPUTexture *)texture atIndex:(NSUInteger)index
{
	[_commands use:texture];
	StelaSetTexture command = {.texture = texture ? texture->_handle : 0, .index = index};
	ENTRY(StelaComputeCodeSetTexture, command);
}

- (void)setTextures:(const id __unsafe_unretained[])textures withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setTexture:textures[i] atIndex:range.location + i];
	}
}

- (void)setSampler:(StelaGPUSampler *)sampler
	   clamped:(BOOL)clamped
	       min:(float)minimum
	       max:(float)maximum
	   atIndex:(NSUInteger)index
{
	[_commands use:sampler];
	StelaSetSampler command = {
		.sampler = sampler ? sampler->_handle : 0,
		.index = index,
		.clamped = clamped,
		.lod_min = minimum,
		.lod_max = maximum,
	};
	ENTRY(StelaComputeCodeSetSampler, command);
}

- (void)setSamplerState:(id)sampler atIndex:(NSUInteger)index
{
	[self setSampler:sampler clamped:NO min:0 max:0 atIndex:index];
}

- (void)setSamplerStates:(const id __unsafe_unretained[])samplers withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setSampler:samplers[i] clamped:NO min:0 max:0 atIndex:range.location + i];
	}
}

- (void)setSamplerState:(id)sampler
	    lodMinClamp:(float)minimum
	    lodMaxClamp:(float)maximum
		atIndex:(NSUInteger)index
{
	[self setSampler:sampler clamped:YES min:minimum max:maximum atIndex:index];
}

- (void)setSamplerStates:(const id __unsafe_unretained[])samplers
	    lodMinClamps:(const float[])minimums
	    lodMaxClamps:(const float[])maximums
	       withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setSampler:samplers[i] clamped:YES min:minimums[i] max:maximums[i] atIndex:range.location + i];
	}
}

- (void)setThreadgroupMemoryLength:(NSUInteger)length atIndex:(NSUInteger)index
{
	StelaSetThreadgroupMemory command = {.length = length, .index = index};
	ENTRY(StelaComputeCodeSetThreadgroupMemory, command);
}

- (void)setVisibleFunctionTable:(id)table atBufferIndex:(NSUInteger)index
{
	[self setBuffer:table offset:0 atIndex:index];
}

- (void)setVisibleFunctionTables:(const id __unsafe_unretained[])tables withBufferRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setBuffer:tables[i] offset:0 atIndex:range.location + i];
	}
}

- (void)setStageInRegion:(MTLRegion)region
{
	StelaStageInRegion command = {
		.origin = {region.origin.x, region.origin.y, region.origin.z},
		.size = {region.size.width, region.size.height, region.size.depth},
	};
	ENTRY(StelaComputeCodeSetStageInRegion, command);
}

- (void)setStageInRegionWithIndirectBuffer:(StelaGPUBuffer *)buffer indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:buffer];
	StelaBufferOffset command = {.buffer = buffer->_handle, .offset = offset};
	ENTRY(StelaComputeCodeSetStageInRegionIndirect, command);
}

- (void)dispatchThreadgroups:(MTLSize)groups threadsPerThreadgroup:(MTLSize)threads
{
	StelaDispatch command = {
		.size = {groups.width, groups.height, groups.depth},
		.threads = {threads.width, threads.height, threads.depth},
	};
	ENTRY(StelaComputeCodeDispatchThreadgroups, command);
}

- (void)dispatchThreads:(MTLSize)size threadsPerThreadgroup:(MTLSize)threads
{
	StelaDispatch command = {
		.size = {size.width, size.height, size.depth},
		.threads = {threads.width, threads.height, threads.depth},
	};
	ENTRY(StelaComputeCodeDispatchThreads, command);
}

- (void)dispatchThreadgroupsWithIndirectBuffer:(StelaGPUBuffer *)buffer
			  indirectBufferOffset:(NSUInteger)offset
			 threadsPerThreadgroup:(MTLSize)threads
{
	[_commands use:buffer];
	StelaDispatchIndirect command = {
		.buffer = buffer->_handle,
		.offset = offset,
		.threads = {threads.width, threads.height, threads.depth},
	};
	ENTRY(StelaComputeCodeDispatchIndirect, command);
}

- (void)memoryBarrierWithScope:(NSUInteger)scope
{
	StelaMemoryBarrier command = {.scope = scope};
	ENTRY(StelaComputeCodeMemoryBarrier, command);
}

- (void)barrierAfterQueueStages:(NSUInteger)after beforeStages:(NSUInteger)before
{
	(void)after;
	(void)before;
	[self memoryBarrierWithScope:MTLBarrierScopeBuffers | MTLBarrierScopeTextures];
}

/* A barrier on all the kinds of resources is the wider one the hardware has. */
- (void)memoryBarrierWithResources:(const id __unsafe_unretained[])resources count:(NSUInteger)count
{
	(void)resources;
	(void)count;
	[self memoryBarrierWithScope:MTLBarrierScopeBuffers | MTLBarrierScopeTextures];
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

@implementation StelaGPUResourceStateEncoder

- (void)updateTextureMappings:(StelaGPUTexture *)texture
			 mode:(NSUInteger)mode
		      regions:(const MTLRegion[])regions
		    mipLevels:(const NSUInteger[])levels
		       slices:(const NSUInteger[])slices
		   numRegions:(NSUInteger)count
{
	[_commands use:texture];
	StelaUpdateMappings command = {.texture = texture->_handle, .mode = mode};
	StelaMappingRecord *records = calloc(count, sizeof(*records));
	for (NSUInteger i = 0; i < count; i++) {
		const MTLRegion *region = &regions[i];
		records[i] = (StelaMappingRecord){
			.level = levels[i],
			.slice = slices[i],
			.origin = {region->origin.x, region->origin.y, region->origin.z},
			.size = {region->size.width, region->size.height, region->size.depth},
		};
	}
	stela_stream_entry(_stream, StelaResourceStateCodeUpdateMappings, &command, sizeof(command), records,
			   count * sizeof(*records));
	free(records);
}

- (void)updateTextureMapping:(id)texture
			mode:(NSUInteger)mode
		      region:(MTLRegion)region
		    mipLevel:(NSUInteger)level
		       slice:(NSUInteger)slice
{
	[self updateTextureMappings:texture mode:mode regions:&region mipLevels:&level slices:&slice numRegions:1];
}

- (void)updateTextureMapping:(StelaGPUTexture *)texture
			mode:(NSUInteger)mode
	      indirectBuffer:(StelaGPUBuffer *)buffer
	indirectBufferOffset:(NSUInteger)offset
{
	[_commands use:texture];
	[_commands use:buffer];
	StelaUpdateMappingIndirect command = {
		.texture = texture->_handle,
		.mode = mode,
		.buffer = buffer->_handle,
		.offset = offset,
	};
	ENTRY(StelaResourceStateCodeUpdateMappingIndirect, command);
}

- (void)moveTextureMappingsFromTexture:(StelaGPUTexture *)source
			   sourceSlice:(NSUInteger)sourceSlice
			   sourceLevel:(NSUInteger)sourceLevel
			  sourceOrigin:(MTLOrigin)sourceOrigin
			    sourceSize:(MTLSize)size
			     toTexture:(StelaGPUTexture *)destination
		      destinationSlice:(NSUInteger)slice
		      destinationLevel:(NSUInteger)level
		     destinationOrigin:(MTLOrigin)origin
{
	[_commands use:source];
	[_commands use:destination];
	StelaMoveMappings command = {
		.source = {source->_handle, sourceSlice, sourceLevel, {sourceOrigin.x, sourceOrigin.y, sourceOrigin.z}},
		.destination = {destination->_handle, slice, level, {origin.x, origin.y, origin.z}},
		.size = {size.width, size.height, size.depth},
	};
	ENTRY(StelaResourceStateCodeMoveMappings, command);
}

@end
