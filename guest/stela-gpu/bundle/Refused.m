/*
 * What this device does not offer. Each entry answers as Metal does for a
 * missing feature and reports once; `metal/README.md` says why each is absent.
 */
#include "Bundle.h"

#define REFUSE(what, why)                                                                          \
	do {                                                                                       \
		static bool reported;                                                              \
		if (!__atomic_exchange_n(&reported, true, __ATOMIC_RELAXED)) {                     \
			StelaFailure failure = {.reason = why};                                    \
			stela_report(what, &failure);                                              \
		}                                                                                  \
	} while (0)

#define ABSENT(signature, why, answer)                                                             \
	-signature                                                                                 \
	{                                                                                          \
		REFUSE(#signature, why);                                                           \
		return answer;                                                                     \
	}

#define RAY_TRACING "this device has no acceleration structures"
#define INTERSECTION "this device has no intersection functions"
#define TILE "this device has no tile shaders"
#define TENSORS "this device has no tensors"
#define IMAGEBLOCKS "this device has no imageblocks"
#define BINARY_LINKING "this device links no binary functions into a pipeline"
#define SPECIALIZATION "this device cannot look functions up by name in a pipeline"
#define STAGE_IN_STRIDE "this device takes no attribute stride for this binding"
#define ARGUMENT_OBJECT "this device encodes no such object in an argument buffer"
#define NO_TILED_TEXTURE "this device has no tiled textures over caller memory"
#define INDIRECT_ARGUMENT_LAYOUT "this device has no indirect argument layouts"

@implementation StelaGPUDevice (Refused)

ABSENT((id)newRasterizationRateMapWithDescriptor:(id)descriptor, "this device has no rasterization rate maps", nil)
ABSENT((MTLAccelerationStructureSizes)accelerationStructureSizesWithDescriptor:(id)descriptor, RAY_TRACING,
       (MTLAccelerationStructureSizes){0})
ABSENT((MTLSizeAndAlign)heapAccelerationStructureSizeAndAlignWithSize:(NSUInteger)size, RAY_TRACING,
       (MTLSizeAndAlign){0})
ABSENT((MTLSizeAndAlign)heapAccelerationStructureSizeAndAlignWithDescriptor:(id)descriptor, RAY_TRACING,
       (MTLSizeAndAlign){0})
ABSENT((id)newAccelerationStructureWithSize:(NSUInteger)size, RAY_TRACING, nil)
ABSENT((id)newAccelerationStructureWithDescriptor:(id)descriptor, RAY_TRACING, nil)
ABSENT((id)newIntersectionFunctionTableWithDescriptor:(id)descriptor, INTERSECTION, nil)
ABSENT((id)newIndirectArgumentBufferLayoutWithStructType:(id)type, INDIRECT_ARGUMENT_LAYOUT, nil)
ABSENT((id)newIndirectComputeCommandEncoderWithBuffer:(id)buffer, INDIRECT_ARGUMENT_LAYOUT, nil)
ABSENT((id)newIndirectRenderCommandEncoderWithBuffer:(id)buffer, INDIRECT_ARGUMENT_LAYOUT, nil)
ABSENT((uint64_t)singleFPConfig, "this device states no OpenCL floating point configuration", 0)
ABSENT((uint64_t)doubleFPConfig, "this device states no OpenCL floating point configuration", 0)
ABSENT((uint64_t)halfFPConfig, "this device states no OpenCL floating point configuration", 0)

- (id)newTiledTextureWithBytesNoCopy:(void *)bytes
			      length:(NSUInteger)length
			 deallocator:(void (^)(void *, NSUInteger))deallocator
			  descriptor:(id)descriptor
			      offset:(NSUInteger)offset
			 bytesPerRow:(NSUInteger)bytesPerRow
{
	REFUSE("newTiledTextureWithBytesNoCopy:length:deallocator:descriptor:offset:bytesPerRow:", NO_TILED_TEXTURE);
	return nil;
}

- (id)newTiledTextureWithBytesNoCopy:(void *)bytes
			      length:(NSUInteger)length
			  descriptor:(id)descriptor
			      offset:(NSUInteger)offset
			 bytesPerRow:(NSUInteger)bytesPerRow
{
	REFUSE("newTiledTextureWithBytesNoCopy:length:descriptor:offset:bytesPerRow:", NO_TILED_TEXTURE);
	return nil;
}

@end

@implementation StelaGPUCommandBuffer (Refused)

ABSENT((id)accelerationStructureCommandEncoder, RAY_TRACING, nil)
ABSENT((id)accelerationStructureCommandEncoderWithDescriptor:(id)descriptor, RAY_TRACING, nil)

@end

@implementation StelaGPUHeap (Refused)

ABSENT((id)newAccelerationStructureWithSize:(NSUInteger)size, RAY_TRACING, nil)
ABSENT((id)newAccelerationStructureWithDescriptor:(id)descriptor, RAY_TRACING, nil)

- (id)newAccelerationStructureWithSize:(NSUInteger)size offset:(NSUInteger)offset
{
	REFUSE("newAccelerationStructureWithSize:offset:", RAY_TRACING);
	return nil;
}

- (id)newAccelerationStructureWithDescriptor:(id)descriptor offset:(NSUInteger)offset
{
	REFUSE("newAccelerationStructureWithDescriptor:offset:", RAY_TRACING);
	return nil;
}

@end

@implementation StelaGPUBuffer (Refused)

- (id)newTensorWithDescriptor:(id)descriptor offset:(NSUInteger)offset error:(NSError **)error
{
	REFUSE("newTensorWithDescriptor:offset:error:", TENSORS);
	return nil;
}

@end

@implementation StelaGPUTexture (Refused)

ABSENT((id)newRemoteTextureViewForDevice:(id)device, "this device shares no textures with another device", nil)

@end

@implementation StelaGPUDepthStencil (Refused)

ABSENT((MTLResourceID)gpuResourceID, "this device has no depth stencil states in argument buffers",
       (MTLResourceID){0})

@end

@implementation StelaGPULibrary (Refused)

ABSENT((id)reflectionForFunctionWithName:(NSString *)name, "this device reflects functions through their pipelines",
       nil)

- (void)newIntersectionFunctionWithDescriptor:(id)descriptor completionHandler:(void (^)(id, NSError *))handler
{
	REFUSE("newIntersectionFunctionWithDescriptor:completionHandler:", INTERSECTION);
	StelaFailure failure = {.reason = INTERSECTION};
	handler(nil, stela_error(@"MTLLibraryErrorDomain", 1, &failure));
}

@end

@implementation StelaGPUBinaryArchive (Refused)

- (BOOL)addLibraryWithDescriptor:(id)descriptor error:(NSError **)error
{
	REFUSE("addLibraryWithDescriptor:error:", "this device archives pipelines, not libraries");
	return NO;
}

@end

@implementation StelaGPURenderPipeline (Refused)

ABSENT((id)reflection, "this device hands reflection out when a pipeline is made", nil)

- (id)functionHandleWithName:(NSString *)name stage:(NSUInteger)stage
{
	REFUSE("functionHandleWithName:stage:", SPECIALIZATION);
	return nil;
}

- (id)functionHandleWithBinaryFunction:(id)function stage:(NSUInteger)stage
{
	REFUSE("functionHandleWithBinaryFunction:stage:", BINARY_LINKING);
	return nil;
}

- (id)newRenderPipelineStateWithBinaryFunctions:(id)functions error:(NSError **)error
{
	REFUSE("newRenderPipelineStateWithBinaryFunctions:error:", BINARY_LINKING);
	return nil;
}

@end

@implementation StelaGPUComputePipeline (Refused)

ABSENT((id)reflection, "this device hands reflection out when a pipeline is made", nil)
ABSENT((id)functionHandleWithName:(NSString *)name, SPECIALIZATION, nil)
ABSENT((id)functionHandleWithBinaryFunction:(id)function, BINARY_LINKING, nil)

- (id)newComputePipelineStateWithBinaryFunctions:(id)functions error:(NSError **)error
{
	REFUSE("newComputePipelineStateWithBinaryFunctions:error:", BINARY_LINKING);
	return nil;
}

@end

@implementation StelaGPUArgumentEncoder (Refused)

ABSENT((id)newArgumentEncoderForBufferAtIndex:(NSUInteger)index, ARGUMENT_OBJECT, nil)

- (void)setAccelerationStructure:(id)structure atIndex:(NSUInteger)index
{
	REFUSE("setAccelerationStructure:atIndex:", RAY_TRACING);
}

- (void)setDepthStencilState:(id)state atIndex:(NSUInteger)index
{
	REFUSE("setDepthStencilState:atIndex:", ARGUMENT_OBJECT);
}

- (void)setDepthStencilStates:(const id __unsafe_unretained[])states withRange:(NSRange)range
{
	REFUSE("setDepthStencilStates:withRange:", ARGUMENT_OBJECT);
}

- (void)setIntersectionFunctionTable:(id)table atIndex:(NSUInteger)index
{
	REFUSE("setIntersectionFunctionTable:atIndex:", INTERSECTION);
}

- (void)setIntersectionFunctionTables:(const id __unsafe_unretained[])tables withRange:(NSRange)range
{
	REFUSE("setIntersectionFunctionTables:withRange:", INTERSECTION);
}

- (void)setVisibleFunctionTable:(id)table atIndex:(NSUInteger)index
{
	REFUSE("setVisibleFunctionTable:atIndex:", ARGUMENT_OBJECT);
}

- (void)setVisibleFunctionTables:(const id __unsafe_unretained[])tables withRange:(NSRange)range
{
	REFUSE("setVisibleFunctionTables:withRange:", ARGUMENT_OBJECT);
}

@end

@implementation StelaGPUEncoder (Refused)

/* Render and compute encoders override this with their barriers. */
- (void)barrierAfterQueueStages:(NSUInteger)after beforeStages:(NSUInteger)before
{
	REFUSE("barrierAfterQueueStages:beforeStages:", "this encoder has no queue barrier");
}

@end

@implementation StelaGPUBlitEncoder (Refused)

- (void)copyFromTensor:(id)source
	  sourceOrigin:(id)origin
      sourceDimensions:(id)dimensions
	      toTensor:(id)destination
     destinationOrigin:(id)destinationOrigin
 destinationDimensions:(id)destinationDimensions
{
	REFUSE("copyFromTensor:sourceOrigin:sourceDimensions:toTensor:destinationOrigin:destinationDimensions:", TENSORS);
}

- (void)copyFromTensor:(id)source
	  sourceOrigin:(id)origin
      sourceDimensions:(id)dimensions
	   sourcePlane:(NSInteger)plane
	      toTensor:(id)destination
     destinationOrigin:(id)destinationOrigin
 destinationDimensions:(id)destinationDimensions
      destinationPlane:(NSInteger)destinationPlane
{
	REFUSE("copyFromTensor:sourceOrigin:sourceDimensions:sourcePlane:toTensor:...", TENSORS);
}

@end

@implementation StelaGPUComputeEncoder (Refused)

- (void)setAccelerationStructure:(id)structure atBufferIndex:(NSUInteger)index
{
	REFUSE("setAccelerationStructure:atBufferIndex:", RAY_TRACING);
}

- (void)setIntersectionFunctionTable:(id)table atBufferIndex:(NSUInteger)index
{
	REFUSE("setIntersectionFunctionTable:atBufferIndex:", INTERSECTION);
}

- (void)setIntersectionFunctionTables:(const id __unsafe_unretained[])tables withBufferRange:(NSRange)range
{
	REFUSE("setIntersectionFunctionTables:withBufferRange:", INTERSECTION);
}

- (void)setBuffer:(id)buffer
	     offset:(NSUInteger)offset
    attributeStride:(NSUInteger)stride
	    atIndex:(NSUInteger)index
{
	REFUSE("setBuffer:offset:attributeStride:atIndex:", STAGE_IN_STRIDE);
}

- (void)setBufferOffset:(NSUInteger)offset attributeStride:(NSUInteger)stride atIndex:(NSUInteger)index
{
	REFUSE("setBufferOffset:attributeStride:atIndex:", STAGE_IN_STRIDE);
}

- (void)setBuffers:(const id __unsafe_unretained[])buffers
	      offsets:(const NSUInteger[])offsets
     attributeStrides:(const NSUInteger[])strides
	    withRange:(NSRange)range
{
	REFUSE("setBuffers:offsets:attributeStrides:withRange:", STAGE_IN_STRIDE);
}

- (void)setBytes:(const void *)bytes
	     length:(NSUInteger)length
    attributeStride:(NSUInteger)stride
	    atIndex:(NSUInteger)index
{
	REFUSE("setBytes:length:attributeStride:atIndex:", STAGE_IN_STRIDE);
}

- (void)setImageblockWidth:(NSUInteger)width height:(NSUInteger)height
{
	REFUSE("setImageblockWidth:height:", IMAGEBLOCKS);
}

@end

@implementation StelaGPUIndirectComputeCommand (Refused)

- (void)setImageblockWidth:(NSUInteger)width height:(NSUInteger)height
{
	REFUSE("setImageblockWidth:height:", IMAGEBLOCKS);
}

- (void)setKernelBuffer:(id)buffer
		 offset:(NSUInteger)offset
	attributeStride:(NSUInteger)stride
		atIndex:(NSUInteger)index
{
	REFUSE("setKernelBuffer:offset:attributeStride:atIndex:", STAGE_IN_STRIDE);
}

@end

/* One render stage's bindings of a kind this device has no shader to read. */
#define ABSENT_TABLES(stage)                                                                       \
	-(void)set##stage##IntersectionFunctionTable : (id)table atBufferIndex : (NSUInteger)index \
	{                                                                                          \
		REFUSE("set" #stage "IntersectionFunctionTable:atBufferIndex:", INTERSECTION);     \
	}                                                                                          \
	-(void)set##stage##IntersectionFunctionTables                                              \
	    : (const id __unsafe_unretained[])tables withBufferRange : (NSRange)range              \
	{                                                                                          \
		REFUSE("set" #stage "IntersectionFunctionTables:withBufferRange:", INTERSECTION);  \
	}                                                                                          \
	-(void)set##stage##AccelerationStructure : (id)structure atBufferIndex : (NSUInteger)index \
	{                                                                                          \
		REFUSE("set" #stage "AccelerationStructure:atBufferIndex:", RAY_TRACING);          \
	}

@implementation StelaGPURenderEncoder (Refused)

ABSENT_TABLES(Vertex)
ABSENT_TABLES(Fragment)
ABSENT_TABLES(Tile)

ABSENT((NSUInteger)tileWidth, TILE, 0)
ABSENT((NSUInteger)tileHeight, TILE, 0)
ABSENT((void)setColorAttachmentMap:(id)map, "this device has no color attachment maps", )

- (void)setDepthTestMinBound:(float)minimum maxBound:(float)maximum
{
	REFUSE("setDepthTestMinBound:maxBound:", "this device has no depth bounds test");
}

- (void)setThreadgroupMemoryLength:(NSUInteger)length offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	REFUSE("setThreadgroupMemoryLength:offset:atIndex:", TILE);
}

- (void)dispatchThreadsPerTile:(MTLSize)threads
{
	REFUSE("dispatchThreadsPerTile:", TILE);
}

- (void)setTileBuffer:(id)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	REFUSE("setTileBuffer:offset:atIndex:", TILE);
}

- (void)setTileBufferOffset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	REFUSE("setTileBufferOffset:atIndex:", TILE);
}

- (void)setTileBuffers:(const id __unsafe_unretained[])buffers
	       offsets:(const NSUInteger[])offsets
	     withRange:(NSRange)range
{
	REFUSE("setTileBuffers:offsets:withRange:", TILE);
}

- (void)setTileBytes:(const void *)bytes length:(NSUInteger)length atIndex:(NSUInteger)index
{
	REFUSE("setTileBytes:length:atIndex:", TILE);
}

- (void)setTileSamplerState:(id)sampler atIndex:(NSUInteger)index
{
	REFUSE("setTileSamplerState:atIndex:", TILE);
}

- (void)setTileSamplerState:(id)sampler
		lodMinClamp:(float)minimum
		lodMaxClamp:(float)maximum
		    atIndex:(NSUInteger)index
{
	REFUSE("setTileSamplerState:lodMinClamp:lodMaxClamp:atIndex:", TILE);
}

- (void)setTileSamplerStates:(const id __unsafe_unretained[])samplers withRange:(NSRange)range
{
	REFUSE("setTileSamplerStates:withRange:", TILE);
}

- (void)setTileSamplerStates:(const id __unsafe_unretained[])samplers
		lodMinClamps:(const float[])minimums
		lodMaxClamps:(const float[])maximums
		   withRange:(NSRange)range
{
	REFUSE("setTileSamplerStates:lodMinClamps:lodMaxClamps:withRange:", TILE);
}

- (void)setTileTexture:(id)texture atIndex:(NSUInteger)index
{
	REFUSE("setTileTexture:atIndex:", TILE);
}

- (void)setTileTextures:(const id __unsafe_unretained[])textures withRange:(NSRange)range
{
	REFUSE("setTileTextures:withRange:", TILE);
}

- (void)setTileVisibleFunctionTable:(id)table atBufferIndex:(NSUInteger)index
{
	REFUSE("setTileVisibleFunctionTable:atBufferIndex:", TILE);
}

- (void)setTileVisibleFunctionTables:(const id __unsafe_unretained[])tables withBufferRange:(NSRange)range
{
	REFUSE("setTileVisibleFunctionTables:withBufferRange:", TILE);
}

- (void)setVertexBufferOffset:(NSUInteger)offset attributeStride:(NSUInteger)stride atIndex:(NSUInteger)index
{
	REFUSE("setVertexBufferOffset:attributeStride:atIndex:", STAGE_IN_STRIDE);
}

- (void)setVertexBytes:(const void *)bytes
		 length:(NSUInteger)length
	attributeStride:(NSUInteger)stride
		atIndex:(NSUInteger)index
{
	REFUSE("setVertexBytes:length:attributeStride:atIndex:", STAGE_IN_STRIDE);
}

@end
