/*
 * The Metal plugin: Metal's objects over the native service, through the gate
 * page the kext maps into the task. See docs/design/metal-device.md.
 *
 * Objects hold the service's handles; encoders write the command stream a
 * commit replays, and nothing else crosses. What a CPU reaches is the task's
 * own memory, which the kext wires and the GPU imports.
 */
#pragma once

#include "Metal.h"
#include <StelaGPU/Interface.h>
#include <StelaGPU/Wire.h>
#include <stela/gate.h>

/* The gate page of one device in this task. */
typedef struct {
	io_connect_t connect;
	volatile uint64_t *page;
} StelaGate;

/* Why a call failed: its status and the service's reason. */
typedef struct {
	uint32_t status;
	char reason[160];
} StelaFailure;

/* The memory a call's records name, which the call maps before it runs. */
typedef struct {
	const StelaSpan *reads, *writes;
	size_t read_count, write_count;
} StelaSpans;

/*
 * Runs one operation and answers its status. A span's page may be away when the
 * service copies it, so the call touches `spans`, and touches them again if the
 * service found one gone. `failure` may be NULL.
 */
uint32_t stela_gate_call(StelaGate *gate, uint32_t operation, const void *request, size_t request_bytes,
			 void *response, size_t response_bytes, StelaSpans spans, StelaFailure *failure);

/* A call of operation `name`, whose records' types the compiler checks. */
#define STELA_CALL_SPANS(gate, name, request, response, spans, failure)                            \
	({                                                                                         \
		const Stela##name##Call *call_request = (request);                                 \
		Stela##name##Reply *call_response = (response);                                    \
		stela_gate_call((gate), StelaOperation##name, call_request, sizeof(*call_request), \
				call_response, sizeof(*call_response), (spans), (failure));        \
	})
#define STELA_CALL(gate, name, request, response, failure)                                         \
	STELA_CALL_SPANS(gate, name, request, response, (StelaSpans){0}, failure)

static inline StelaSpan stela_span(const void *address, size_t length)
{
	return (StelaSpan){.address = (uint64_t)address, .length = length};
}

/* An NSError of `domain` from a failed call. */
NSError *stela_error(NSString *domain, NSInteger code, const StelaFailure *failure);
/* Says in the system log, once for each, that `what` could not be done. */
void stela_report(const char *what, const StelaFailure *failure);

/* A growing command stream. */
typedef struct {
	uint8_t *bytes;
	size_t length, capacity;
} StelaStream;

void stela_stream_entry(StelaStream *stream, uint32_t code, const void *record, size_t record_bytes,
			const void *data, size_t data_bytes);
void stela_stream_append(StelaStream *stream, const StelaStream *other);
void stela_stream_free(StelaStream *stream);

/* The descriptors' records; a nil descriptor is the default one. */
void stela_texture_record(id descriptor, StelaTextureDescriptorRecord *record);
void stela_depth_stencil_record(id descriptor, StelaDepthStencilRecord *record);

@class StelaGPUCommandBuffer, StelaGPUFunction, StelaGPUIndirectCommandBuffer;

@interface StelaGPUDevice : _MTLDevice {
@public
	StelaGate _gate;
	StelaBlock *_capabilities;
}
- (instancetype)initWithAcceleratorPort:(io_service_t)port;
/* `length` bytes of new memory at *contents wired for the GPU; 0 on failure. */
- (uint64_t)importLength:(uint64_t)length contents:(void **)contents failure:(StelaFailure *)failure;
/* Wires the task's memory at `address`; 0 on failure. */
- (uint64_t)importAddress:(void *)address length:(uint64_t)length failure:(StelaFailure *)failure;
/* Completes `buffer` once the service reaches its serial. */
- (void)track:(StelaGPUCommandBuffer *)buffer;
/* Completes `buffer`, whose commit `failure` refused. */
- (void)failed:(StelaGPUCommandBuffer *)buffer with:(StelaFailure)failure;
- (void)releaseHandle:(uint64_t)handle;
/* The host seconds of a GPU timestamp, as `GPUStartTime` counts them. */
- (CFTimeInterval)secondsOfTick:(uint64_t)tick;
/* Indirect command buffers with encoding the next commit takes. */
- (void)noteIndirect:(StelaGPUIndirectCommandBuffer *)buffer;
- (void)forgetIndirect:(StelaGPUIndirectCommandBuffer *)buffer;
- (void)flushIndirect;
@end

/* What holds a service handle. */
@interface StelaGPUObject : NSObject {
@public
	StelaGPUDevice *_device;
	uint64_t _handle;
}
@property(copy) NSString *label;
- (instancetype)initWithDevice:(StelaGPUDevice *)device handle:(uint64_t)handle;
- (StelaGPUDevice *)device;
@end

@interface StelaGPUResource : StelaGPUObject <MTLResource, MTLAllocation> {
@public
	NSUInteger _options;
	NSUInteger _allocatedSize, _heapOffset;
	id _heap;
	BOOL _aliasable;
}
@end

@interface StelaGPUBuffer : StelaGPUResource <MTLBuffer> {
@public
	void *_contents;
	NSUInteger _length;
	uint64_t _gpuAddress;
	/* Memory of the bundle's own, unmapped with the buffer. */
	uint64_t _mappedBytes;
	void (^_deallocator)(void *, NSUInteger);
}
- (instancetype)initWithDevice:(StelaGPUDevice *)device
		      response:(const StelaBufferResponse *)response
		       options:(NSUInteger)options
			length:(NSUInteger)length;
@end

@interface StelaGPUTexture : StelaGPUResource <MTLTexture> {
@public
	uint64_t _resourceID;
	NSUInteger _textureType, _pixelFormat, _width, _height, _depth;
	NSUInteger _mipmapLevelCount, _sampleCount, _arrayLength, _usage;
	NSUInteger _bufferOffset, _bufferBytesPerRow, _firstMipmapInTail, _tailSizeInBytes;
	NSUInteger _parentLevel, _parentSlice;
	MTLTextureSwizzleChannels _swizzle;
	BOOL _sparse;
	id _buffer, _parent;
	IOSurfaceRef _surface;
	NSUInteger _surfacePlane;
}
- (instancetype)initWithDevice:(StelaGPUDevice *)device
		      response:(const StelaTextureResponse *)response
		    descriptor:(id)descriptor;
@end

@interface StelaGPUSampler : StelaGPUObject <MTLSamplerState> {
@public
	uint64_t _resourceID;
}
@end

/* Encoded by value at each use: the service keeps no depth-stencil objects. */
@interface StelaGPUDepthStencil : NSObject <MTLDepthStencilState> {
@public
	StelaDepthStencilRecord _record;
	StelaGPUDevice *_device;
}
@property(copy) NSString *label;
@end

@interface StelaGPUHeap : StelaGPUObject <MTLHeap> {
@public
	void *_contents;
	NSUInteger _size, _options, _type;
	uint64_t _mappedBytes;
}
@end

@interface StelaGPUFence : NSObject <MTLFence> {
@public
	StelaGPUDevice *_device;
}
@property(copy) NSString *label;
@end

@interface StelaGPUEvent : StelaGPUObject <MTLSharedEvent>
@end

@interface StelaGPULibrary : StelaGPUObject <MTLLibrary, MTLDynamicLibrary> {
@public
	BOOL _identified;
	NSUInteger _type;
	NSString *_installName;
}
- (NSUInteger)type;
@end

/* `MTLVertexAttribute` and `MTLAttribute`. */
@interface StelaGPUAttribute : NSObject
@property(copy) NSString *name;
@property NSUInteger attributeIndex, attributeType;
@property(getter=isActive) BOOL active;
@property(getter=isPatchData) BOOL patchData;
@property(getter=isPatchControlPointData) BOOL patchControlPointData;
@end

/* `MTLFunctionConstant`. */
@interface StelaGPUFunctionConstant : NSObject
@property(copy) NSString *name;
@property NSUInteger type, index;
@property BOOL required;
@end

/* Every `MTLType`: which selectors mean something follows from `dataType`. */
@interface StelaGPUType : NSObject {
@public
	NSUInteger _dataType;
	StelaGPUType *_element;
	NSArray *_members;
}
@property NSUInteger elementType, arrayLength, stride, argumentIndexStride;
@property NSUInteger access, alignment, dataSize, textureType, textureDataType;
@property BOOL elementIsArgumentBuffer, isDepthTexture;
- (NSUInteger)dataType;
@end

/* `MTLStructMember`. */
@interface StelaGPUMember : NSObject {
@public
	StelaGPUType *_type;
}
@property(copy) NSString *name;
@property NSUInteger dataType, offset, argumentIndex;
@end

/* Every `MTLBinding`: buffers', textures', threadgroup memory's and payloads'. */
@interface StelaGPUBinding : NSObject <MTLBufferBinding, MTLTextureBinding, MTLThreadgroupBinding, MTLObjectPayloadBinding> {
@public
	BOOL _used;
	StelaGPUType *_typeInfo;
}
@property(copy) NSString *name;
@property NSUInteger type, access, index, arrayLength;
@property NSUInteger bufferAlignment, bufferDataSize, bufferDataType;
@property NSUInteger threadgroupMemoryAlignment, threadgroupMemoryDataSize;
@property NSUInteger objectPayloadAlignment, objectPayloadDataSize;
@property NSUInteger textureType, textureDataType;
@property BOOL isDepthTexture;
@end

@interface StelaGPUReflection : NSObject
+ (NSArray *)bindingsOfFunction:(StelaGPUFunction *)function;
@end

/* `MTLRenderPipelineReflection`. */
@interface StelaGPURenderReflection : NSObject
@property(copy) NSArray *vertexBindings, *fragmentBindings, *objectBindings, *meshBindings;
@end

/* `MTLComputePipelineReflection`. */
@interface StelaGPUComputeReflection : NSObject
@property(copy) NSArray *bindings;
@end

@interface StelaGPUArgumentEncoder : NSObject <MTLArgumentEncoder> {
@public
	NSUInteger _encodedLength, _alignment;
}
@property(copy) NSString *label;
- (instancetype)initWithDevice:(StelaGPUDevice *)device
		 encodedLength:(NSUInteger)length
		     alignment:(NSUInteger)alignment;
- (void)addSlotAt:(NSUInteger)index offset:(NSUInteger)offset;
- (void)addType:(StelaGPUType *)type offset:(NSUInteger)offset index:(NSUInteger)index;
@end

@interface StelaGPUFunction : StelaGPUObject <MTLFunction> {
@public
	StelaGPULibrary *_library;
	NSString *_name;
	NSUInteger _functionType, _patchType;
	NSInteger _patchControlPointCount;
	NSArray *_attributes;
	NSDictionary *_constants;
}
- (instancetype)initWithLibrary:(StelaGPULibrary *)library handle:(uint64_t)handle name:(NSString *)name;
@end

@interface StelaGPURenderPipeline : StelaGPUObject <MTLRenderPipelineState> {
@public
	uint64_t _resourceID;
	NSUInteger _maxTotalThreadsPerObjectThreadgroup, _maxTotalThreadsPerMeshThreadgroup;
	NSUInteger _objectThreadExecutionWidth, _meshThreadExecutionWidth;
	BOOL _supportIndirectCommandBuffers;
}
@end

@interface StelaGPUComputePipeline : StelaGPUObject <MTLComputePipelineState> {
@public
	uint64_t _resourceID;
	NSUInteger _maxTotalThreadsPerThreadgroup, _threadExecutionWidth;
	NSUInteger _staticThreadgroupMemoryLength;
	BOOL _supportIndirectCommandBuffers;
}
@end

@interface StelaGPUFunctionHandle : NSObject <MTLFunctionHandle> {
@public
	uint64_t _value;
	StelaGPUFunction *_function;
}
@end

@interface StelaGPUFunctionTable : StelaGPUBuffer <MTLVisibleFunctionTable> {
@public
	NSUInteger _functionCount;
}
@end

@interface StelaGPUIndirectCommandBuffer : StelaGPUResource <MTLIndirectCommandBuffer> {
@public
	NSUInteger _size;
	uint64_t _resourceID;
}
- (void)flush;
@end

/* A command of an indirect command buffer, which encoding addresses. */
@interface StelaGPUIndirectRenderCommand : NSObject <MTLIndirectRenderCommand> {
@public
	StelaGPUIndirectCommandBuffer *_buffer;
	NSUInteger _index;
}
@end

@interface StelaGPUIndirectComputeCommand : NSObject <MTLIndirectComputeCommand> {
@public
	StelaGPUIndirectCommandBuffer *_buffer;
	NSUInteger _index;
}
@end

@interface StelaGPUCounter : NSObject <MTLCounter>
@property(copy) NSString *name;
@end

@interface StelaGPUCounterSet : NSObject <MTLCounterSet> {
@public
	uint64_t _code;
}
@property(copy) NSString *name;
@property(copy) NSArray *counters;
+ (instancetype)setWithCode:(uint64_t)code;
@end

@interface StelaGPUCounterSampleBuffer : StelaGPUObject <MTLCounterSampleBuffer> {
@public
	NSUInteger _sampleCount, _valuesPerSample;
}
@end

@interface StelaGPUQueue : NSObject <MTLCommandQueue> {
@public
	StelaGPUDevice *_device;
}
@property(copy) NSString *label;
- (instancetype)initWithDevice:(StelaGPUDevice *)device;
- (void)enqueue:(StelaGPUCommandBuffer *)buffer;
- (void)flush;
@end

@interface StelaGPUCommandBuffer : NSObject <MTLCommandBuffer> {
@public
	StelaGPUDevice *_device;
	StelaGPUQueue *_queue;
	StelaStream _stream;
	NSMutableArray *_retained;
	uint64_t _serial;
	bool _committed;
}
@property(copy) NSString *label;
- (instancetype)initWithQueue:(StelaGPUQueue *)queue retainsReferences:(BOOL)retains;
/* Keeps `object` until the command buffer completes, unless it retains none. */
- (void)use:(id)object;
- (void)submit;
/* On the device's queue, ahead of completion. */
- (void)didSchedule;
- (void)beginRender:(id)descriptor;
/* The service finished the command buffer, or `failure` ended it. */
- (void)didCompleteWith:(const StelaFailure *)failure;
@end

/* The commands an encoder writes, into its command buffer's stream or its own. */
@interface StelaGPUEncoder : NSObject <MTLCommandEncoder> {
@public
	StelaGPUCommandBuffer *_commands;
	StelaStream *_stream;
}
@property(copy) NSString *label;
- (instancetype)initWithCommandBuffer:(StelaGPUCommandBuffer *)commands stream:(StelaStream *)stream;
/* Samples a descriptor's `sampleBufferAttachments` ask at the encoder's two ends. */
- (void)sampleAttachments:(id)attachments;
- (void)endEncoding;
- (void)sampleCountersInBuffer:(StelaGPUCounterSampleBuffer *)buffer
		 atSampleIndex:(NSUInteger)index
		   withBarrier:(BOOL)barrier;
@end

@interface StelaGPUBlitEncoder : StelaGPUEncoder <MTLBlitCommandEncoder>
@end

@interface StelaGPUComputeEncoder : StelaGPUEncoder <MTLComputeCommandEncoder> {
@public
	NSUInteger _dispatchType;
}
@end

@interface StelaGPURenderEncoder : StelaGPUEncoder <MTLRenderCommandEncoder>
- (void)setCullMode:(NSUInteger)mode;
- (void)setFrontFacingWinding:(NSUInteger)winding;
- (void)setTriangleFillMode:(NSUInteger)mode;
- (void)setDepthClipMode:(NSUInteger)mode;
- (void)setDepthBias:(float)bias slopeScale:(float)scale clamp:(float)clamp;
- (void)setDepthStencilState:(StelaGPUDepthStencil *)state;
- (void)setStencilReferenceValue:(uint32_t)value;
- (void)setBlendColorRed:(float)red green:(float)green blue:(float)blue alpha:(float)alpha;
- (void)setVisibilityResultMode:(NSUInteger)mode offset:(NSUInteger)offset;
@end

@interface StelaGPUResourceStateEncoder : StelaGPUEncoder <MTLResourceStateCommandEncoder>
@end

@interface StelaGPUParallelEncoder : StelaGPUEncoder <MTLParallelRenderCommandEncoder>
@end
