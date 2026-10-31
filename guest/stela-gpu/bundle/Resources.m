/* Buffers, textures, samplers, heaps, events and counters. */
#include "Bundle.h"

#define PAGE 0x4000ull

static uint64_t page_aligned(uint64_t length)
{
	return (length + PAGE - 1) & ~(PAGE - 1);
}

static NSUInteger storage_mode(NSUInteger options)
{
	return (options & MTLResourceStorageModeMask) >> MTLResourceStorageModeShift;
}

static bool cpu_visible(NSUInteger options)
{
	NSUInteger mode = storage_mode(options);
	return mode == MTLStorageModeShared || mode == MTLStorageModeManaged;
}

void stela_texture_record(id descriptor, StelaTextureDescriptorRecord *record)
{
	MTLTextureSwizzleChannels swizzle = [descriptor swizzle];
	*record = (StelaTextureDescriptorRecord){
		.texture_type = [descriptor textureType],
		.pixel_format = [descriptor pixelFormat],
		.width = [descriptor width],
		.height = [descriptor height],
		.depth = [descriptor depth],
		.mipmap_level_count = [descriptor mipmapLevelCount],
		.sample_count = [descriptor sampleCount],
		.array_length = [descriptor arrayLength],
		.options = [descriptor resourceOptions],
		.usage = [descriptor usage],
		.swizzle = {swizzle.red, swizzle.green, swizzle.blue, swizzle.alpha},
	};
}

static void stencil_record(id stencil, StelaStencilRecord *record)
{
	*record = (StelaStencilRecord){
		.compare_function = stencil ? [stencil stencilCompareFunction] : MTLCompareFunctionAlways,
		.stencil_failure_operation = stencil ? [stencil stencilFailureOperation] : MTLStencilOperationKeep,
		.depth_failure_operation = stencil ? [stencil depthFailureOperation] : MTLStencilOperationKeep,
		.depth_stencil_pass_operation = stencil ? [stencil depthStencilPassOperation] : MTLStencilOperationKeep,
		.read_mask = stencil ? [stencil readMask] : UINT32_MAX,
		.write_mask = stencil ? (uint32_t)[stencil writeMask] : UINT32_MAX,
	};
}

void stela_depth_stencil_record(id descriptor, StelaDepthStencilRecord *record)
{
	*record = (StelaDepthStencilRecord){
		.depth_compare_function = descriptor ? [descriptor depthCompareFunction] : MTLCompareFunctionAlways,
		.depth_write_enabled = descriptor ? [descriptor isDepthWriteEnabled] : NO,
	};
	stencil_record(descriptor ? [descriptor frontFaceStencil] : nil, &record->front_face_stencil);
	stencil_record(descriptor ? [descriptor backFaceStencil] : nil, &record->back_face_stencil);
}

@implementation StelaGPUObject

- (instancetype)initWithDevice:(StelaGPUDevice *)device handle:(uint64_t)handle
{
	self = [super init];
	if (self) {
		_device = device;
		_handle = handle;
	}
	return self;
}

- (StelaGPUDevice *)device
{
	return _device;
}

- (void)dealloc
{
	if (_handle) {
		[_device releaseHandle:_handle];
	}
}

@end

@implementation StelaGPUResource

- (NSUInteger)resourceOptions
{
	return _options;
}

- (NSUInteger)cpuCacheMode
{
	return (_options & MTLResourceCPUCacheModeMask) >> MTLResourceCPUCacheModeShift;
}

- (NSUInteger)storageMode
{
	return storage_mode(_options);
}

- (NSUInteger)hazardTrackingMode
{
	return (_options & MTLResourceHazardTrackingModeMask) >> MTLResourceHazardTrackingModeShift;
}

/* Memory stays resident: everything is nonvolatile, as a query or a request. */
- (NSUInteger)setPurgeableState:(NSUInteger)state
{
	(void)state;
	return MTLPurgeableStateNonVolatile;
}

- (NSUInteger)allocatedSize
{
	return _allocatedSize;
}

- (NSUInteger)heapOffset
{
	return _heapOffset;
}

- (id)heap
{
	return _heap;
}

- (void)makeAliasable
{
	StelaHandle request = {.handle = _handle};
	StelaEmpty nothing;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, MakeAliasable, &request, &nothing, &failure) != StelaStatusOk) {
		stela_report("makeAliasable", &failure);
	} else {
		_aliasable = YES;
	}
}

- (BOOL)isAliasable
{
	return _aliasable;
}

@end

@implementation StelaGPUBuffer

- (instancetype)initWithDevice:(StelaGPUDevice *)device
		      response:(const StelaBufferResponse *)response
		       options:(NSUInteger)options
			length:(NSUInteger)length
{
	self = [super initWithDevice:device handle:response->handle];
	if (self) {
		_options = options;
		_length = length;
		_gpuAddress = response->gpu_address;
		_allocatedSize = response->allocated_size;
		_heapOffset = response->heap_offset;
	}
	return self;
}

- (void)dealloc
{
	if (_deallocator) {
		_deallocator(_contents, _length);
	} else if (_mappedBytes) {
		mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)_contents, _mappedBytes);
	}
}

- (NSUInteger)length
{
	return _length;
}

- (void *)contents
{
	return _contents;
}

- (uint64_t)gpuAddress
{
	return _gpuAddress;
}

- (void)didModifyRange:(NSRange)range
{
	StelaBufferRangeRequest request = {.buffer = _handle, .offset = range.location, .length = range.length};
	StelaEmpty nothing;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, BufferDidModifyRange, &request, &nothing, &failure) != StelaStatusOk) {
		stela_report("didModifyRange:", &failure);
	}
}

- (id)newTextureWithDescriptor:(id)descriptor offset:(NSUInteger)offset bytesPerRow:(NSUInteger)bytesPerRow
{
	StelaNewBufferTextureRequest request = {.buffer = _handle, .offset = offset, .bytes_per_row = bytesPerRow};
	stela_texture_record(descriptor, &request.descriptor);
	StelaTextureResponse response;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, NewBufferTexture, &request, &response, &failure) != StelaStatusOk) {
		stela_report("a texture of a buffer", &failure);
		return nil;
	}
	StelaGPUTexture *texture = [[StelaGPUTexture alloc] initWithDevice:_device
								  response:&response
								descriptor:descriptor];
	texture->_buffer = self;
	texture->_bufferOffset = offset;
	texture->_bufferBytesPerRow = bytesPerRow;
	return texture;
}

- (void)addDebugMarker:(NSString *)marker range:(NSRange)range
{
	(void)marker;
	(void)range;
}

- (void)removeAllDebugMarkers
{
}

- (id)remoteStorageBuffer
{
	return nil;
}

- (id)newRemoteBufferViewForDevice:(id)device
{
	(void)device;
	return nil;
}

@end

@implementation StelaGPUTexture

- (instancetype)initWithDevice:(StelaGPUDevice *)device
		      response:(const StelaTextureResponse *)response
		    descriptor:(id)descriptor
{
	self = [super initWithDevice:device handle:response->handle];
	if (self) {
		_options = [descriptor resourceOptions];
		_allocatedSize = response->allocated_size;
		_heapOffset = response->heap_offset;
		_resourceID = response->resource_id;
		_sparse = response->sparse != 0;
		_firstMipmapInTail = response->first_mipmap_in_tail;
		_tailSizeInBytes = response->tail_size;
		_textureType = [descriptor textureType];
		_pixelFormat = [descriptor pixelFormat];
		_width = [descriptor width];
		_height = [descriptor height];
		_depth = [descriptor depth];
		_mipmapLevelCount = [descriptor mipmapLevelCount];
		_sampleCount = [descriptor sampleCount];
		_arrayLength = [descriptor arrayLength];
		_usage = [descriptor usage];
		_swizzle = [descriptor swizzle];
	}
	return self;
}

- (NSUInteger)textureType
{
	return _textureType;
}

- (NSUInteger)pixelFormat
{
	return _pixelFormat;
}

- (NSUInteger)width
{
	return _width;
}

- (NSUInteger)height
{
	return _height;
}

- (NSUInteger)depth
{
	return _depth;
}

- (NSUInteger)mipmapLevelCount
{
	return _mipmapLevelCount;
}

- (NSUInteger)sampleCount
{
	return _sampleCount;
}

- (NSUInteger)arrayLength
{
	return _arrayLength;
}

- (NSUInteger)usage
{
	return _usage;
}

- (BOOL)isShareable
{
	return NO;
}

- (BOOL)isFramebufferOnly
{
	return NO;
}

- (BOOL)allowGPUOptimizedContents
{
	return YES;
}

- (NSUInteger)compressionType
{
	return 0;
}

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_resourceID};
}

- (MTLTextureSwizzleChannels)swizzle
{
	return _swizzle;
}

- (id)parentTexture
{
	return _parent;
}

- (NSUInteger)parentRelativeLevel
{
	return _parentLevel;
}

- (NSUInteger)parentRelativeSlice
{
	return _parentSlice;
}

- (id)buffer
{
	return _buffer;
}

- (NSUInteger)bufferOffset
{
	return _bufferOffset;
}

- (NSUInteger)bufferBytesPerRow
{
	return _bufferBytesPerRow;
}

- (NSUInteger)firstMipmapInTail
{
	return _firstMipmapInTail;
}

- (NSUInteger)tailSizeInBytes
{
	return _tailSizeInBytes;
}

- (BOOL)isSparse
{
	return _sparse;
}

- (IOSurfaceRef)iosurface
{
	return _surface;
}

- (NSUInteger)iosurfacePlane
{
	return _surfacePlane;
}

- (StelaTextureBytesRequest)bytesRequest:(const void *)bytes
			     bytesPerRow:(NSUInteger)bytesPerRow
			   bytesPerImage:(NSUInteger)bytesPerImage
				  region:(MTLRegion)region
				   level:(NSUInteger)level
				   slice:(NSUInteger)slice
{
	NSUInteger images = region.size.depth ? region.size.depth : 1;
	NSUInteger image = bytesPerImage ? bytesPerImage : bytesPerRow * region.size.height;
	return (StelaTextureBytesRequest){
		.texture = _handle,
		.region = {.slice = slice,
			   .level = level,
			   .origin = {region.origin.x, region.origin.y, region.origin.z},
			   .size = {region.size.width, region.size.height, region.size.depth}},
		.bytes = stela_span(bytes, image * images),
		.bytes_per_row = bytesPerRow,
		.bytes_per_image = bytesPerImage,
	};
}

- (void)getBytes:(void *)bytes
      bytesPerRow:(NSUInteger)bytesPerRow
    bytesPerImage:(NSUInteger)bytesPerImage
       fromRegion:(MTLRegion)region
      mipmapLevel:(NSUInteger)level
	    slice:(NSUInteger)slice
{
	StelaTextureBytesRequest request = [self bytesRequest:bytes
						  bytesPerRow:bytesPerRow
						bytesPerImage:bytesPerImage
						       region:region
							level:level
							slice:slice];
	StelaEmpty nothing;
	StelaFailure failure;
	StelaSpans spans = {.writes = &request.bytes, .write_count = 1};
	if (STELA_CALL_SPANS(&_device->_gate, GetBytes, &request, &nothing, spans, &failure) != StelaStatusOk) {
		stela_report("getBytes:", &failure);
	}
}

- (void)getBytes:(void *)bytes
    bytesPerRow:(NSUInteger)bytesPerRow
     fromRegion:(MTLRegion)region
    mipmapLevel:(NSUInteger)level
{
	[self getBytes:bytes bytesPerRow:bytesPerRow bytesPerImage:0 fromRegion:region mipmapLevel:level slice:0];
}

- (void)replaceRegion:(MTLRegion)region
	  mipmapLevel:(NSUInteger)level
		slice:(NSUInteger)slice
	    withBytes:(const void *)bytes
	  bytesPerRow:(NSUInteger)bytesPerRow
	bytesPerImage:(NSUInteger)bytesPerImage
{
	StelaTextureBytesRequest request = [self bytesRequest:bytes
						  bytesPerRow:bytesPerRow
						bytesPerImage:bytesPerImage
						       region:region
							level:level
							slice:slice];
	StelaEmpty nothing;
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.bytes, .read_count = 1};
	if (STELA_CALL_SPANS(&_device->_gate, ReplaceRegion, &request, &nothing, spans, &failure) != StelaStatusOk) {
		stela_report("replaceRegion:", &failure);
	}
}

- (void)replaceRegion:(MTLRegion)region
	  mipmapLevel:(NSUInteger)level
	    withBytes:(const void *)bytes
	  bytesPerRow:(NSUInteger)bytesPerRow
{
	[self replaceRegion:region mipmapLevel:level slice:0 withBytes:bytes bytesPerRow:bytesPerRow bytesPerImage:0];
}

- (id)newTextureViewWithPixelFormat:(NSUInteger)format
			textureType:(NSUInteger)type
			     levels:(NSRange)levels
			     slices:(NSRange)slices
			    swizzle:(MTLTextureSwizzleChannels)swizzle
{
	StelaNewTextureViewRequest request = {
		.texture = _handle,
		.pixel_format = format,
		.texture_type = type,
		.levels = {levels.location, levels.length},
		.slices = {slices.location, slices.length},
		.swizzle = {swizzle.red, swizzle.green, swizzle.blue, swizzle.alpha},
	};
	StelaTextureResponse response;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, NewTextureView, &request, &response, &failure) != StelaStatusOk) {
		stela_report("a texture view", &failure);
		return nil;
	}
	StelaGPUTexture *view = [StelaGPUTexture alloc];
	view = [view initWithDevice:_device handle:response.handle];
	view->_options = _options;
	view->_allocatedSize = response.allocated_size;
	view->_resourceID = response.resource_id;
	view->_textureType = type;
	view->_pixelFormat = format;
	view->_width = _width >> levels.location ?: 1;
	view->_height = _height >> levels.location ?: 1;
	view->_depth = _depth >> levels.location ?: 1;
	view->_mipmapLevelCount = levels.length;
	view->_sampleCount = _sampleCount;
	view->_arrayLength = slices.length;
	view->_usage = _usage;
	view->_swizzle = swizzle;
	view->_parent = self;
	view->_parentLevel = levels.location;
	view->_parentSlice = slices.location;
	return view;
}

- (id)newTextureViewWithPixelFormat:(NSUInteger)format
			textureType:(NSUInteger)type
			     levels:(NSRange)levels
			     slices:(NSRange)slices
{
	return [self newTextureViewWithPixelFormat:format
				       textureType:type
					    levels:levels
					    slices:slices
					   swizzle:_swizzle];
}

- (id)newTextureViewWithPixelFormat:(NSUInteger)format
{
	return [self newTextureViewWithPixelFormat:format
				       textureType:_textureType
					    levels:(NSRange){0, _mipmapLevelCount}
					    slices:(NSRange){0, _arrayLength}
					   swizzle:_swizzle];
}

@end

@implementation StelaGPUSampler

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_resourceID};
}

@end

@implementation StelaGPUDepthStencil
- (id)device
{
	return _device;
}
@end

@implementation StelaGPUFence
- (id)device
{
	return _device;
}
@end

@implementation StelaGPUHeap

- (void)dealloc
{
	if (_mappedBytes) {
		mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)_contents, _mappedBytes);
	}
}

- (NSUInteger)size
{
	return _size;
}

- (NSUInteger)resourceOptions
{
	return _options;
}

- (NSUInteger)cpuCacheMode
{
	return (_options & MTLResourceCPUCacheModeMask) >> MTLResourceCPUCacheModeShift;
}

- (NSUInteger)storageMode
{
	return storage_mode(_options);
}

- (NSUInteger)hazardTrackingMode
{
	return (_options & MTLResourceHazardTrackingModeMask) >> MTLResourceHazardTrackingModeShift;
}

- (NSUInteger)type
{
	return _type;
}

- (NSUInteger)allocatedSize
{
	return _size;
}

- (NSUInteger)setPurgeableState:(NSUInteger)state
{
	(void)state;
	return MTLPurgeableStateNonVolatile;
}

- (StelaHeapUsageResponse)usageForAlignment:(NSUInteger)alignment
{
	StelaHeapUsageRequest request = {.heap = _handle, .alignment = alignment};
	StelaHeapUsageResponse usage = {};
	STELA_CALL(&_device->_gate, HeapUsage, &request, &usage, NULL);
	return usage;
}

- (NSUInteger)usedSize
{
	return [self usageForAlignment:1].used_size;
}

- (NSUInteger)currentAllocatedSize
{
	return _size;
}

- (NSUInteger)maxAvailableSizeWithAlignment:(NSUInteger)alignment
{
	return [self usageForAlignment:alignment].max_available_size;
}

- (id)newBufferWithLength:(NSUInteger)length options:(NSUInteger)options offset:(uint64_t)offset
{
	StelaNewHeapBufferRequest request = {
		.heap = _handle, .length = length, .options = options, .offset = offset};
	StelaBufferResponse response;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, NewHeapBuffer, &request, &response, &failure) != StelaStatusOk) {
		return nil;
	}
	StelaGPUBuffer *buffer = [[StelaGPUBuffer alloc] initWithDevice:_device
							       response:&response
								options:options
								 length:length];
	buffer->_heap = self;
	buffer->_contents = _contents ? (uint8_t *)_contents + response.heap_offset : NULL;
	return buffer;
}

- (id)newBufferWithLength:(NSUInteger)length options:(NSUInteger)options
{
	return [self newBufferWithLength:length options:options offset:STELA_AUTOMATIC];
}

- (id)newTextureWithDescriptor:(id)descriptor offset:(uint64_t)offset
{
	StelaNewHeapTextureRequest request = {.heap = _handle, .offset = offset};
	stela_texture_record(descriptor, &request.descriptor);
	StelaTextureResponse response;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, NewHeapTexture, &request, &response, &failure) != StelaStatusOk) {
		return nil;
	}
	StelaGPUTexture *texture = [[StelaGPUTexture alloc] initWithDevice:_device
								  response:&response
								descriptor:descriptor];
	texture->_heap = self;
	return texture;
}

- (id)newTextureWithDescriptor:(id)descriptor
{
	return [self newTextureWithDescriptor:descriptor offset:STELA_AUTOMATIC];
}

- (id)newBufferWithLength:(NSUInteger)length options:(NSUInteger)options placementOffset:(NSUInteger)offset
{
	return [self newBufferWithLength:length options:options offset:offset];
}

- (id)newTextureWithDescriptor:(id)descriptor placementOffset:(NSUInteger)offset
{
	return [self newTextureWithDescriptor:descriptor offset:offset];
}

@end

@implementation StelaGPUEvent

- (uint64_t)signaledValue
{
	StelaHandle request = {.handle = _handle};
	StelaValue value = {};
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, EventSignaledValue, &request, &value, &failure) != StelaStatusOk) {
		stela_report("signaledValue", &failure);
	}
	return value.value;
}

- (void)setSignaledValue:(uint64_t)value
{
	StelaEventValueRequest request = {.event = _handle, .value = value};
	StelaEmpty nothing;
	StelaFailure failure;
	if (STELA_CALL(&_device->_gate, SetEventSignaledValue, &request, &nothing, &failure) != StelaStatusOk) {
		stela_report("setSignaledValue:", &failure);
	}
}

/*
 * A CPU waiter may be what the GPU waits for in the same command buffer as the
 * signal, so no completion need ever arrive: the event is read every
 * millisecond, each read also submitting what the signal released.
 */
- (BOOL)waitUntilSignaledValue:(uint64_t)value timeoutMS:(uint64_t)milliseconds
{
	for (uint64_t waited = 0;; waited++) {
		StelaWaitEventRequest request = {.event = _handle, .value = value};
		StelaWaitResponse response = {};
		StelaFailure failure;
		if (STELA_CALL(&_device->_gate, WaitEvent, &request, &response, &failure) != StelaStatusOk) {
			stela_report("waitUntilSignaledValue:", &failure);
			return NO;
		}
		if (response.reached) {
			return YES;
		}
		if (waited >= milliseconds) {
			return NO;
		}
		usleep(1000);
	}
}

- (void)notifyListener:(id)listener atValue:(uint64_t)value block:(void (^)(id, uint64_t))block
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		[self waitUntilSignaledValue:value timeoutMS:UINT64_MAX];
		dispatch_async([listener dispatchQueue], ^{
			block(self, [self signaledValue]);
		});
	});
}

- (id)newSharedEventHandle
{
	return nil;
}

@end

@implementation StelaGPUCounter
@end

@implementation StelaGPUCounterSet

+ (instancetype)setWithCode:(uint64_t)code
{
	StelaGPUCounterSet *set = [StelaGPUCounterSet new];
	set->_code = code;
	set.name = code == StelaCounterSetCodeTimestamp ? MTLCommonCounterSetTimestamp : MTLCommonCounterSetStatistic;
	StelaGPUCounter *counter = [StelaGPUCounter new];
	counter.name = code == StelaCounterSetCodeTimestamp ? MTLCommonCounterTimestamp : set.name;
	set.counters = [NSArray arrayWithObjects:&counter count:1];
	return set;
}

@end

@implementation StelaGPUCounterSampleBuffer

- (NSUInteger)sampleCount
{
	return _sampleCount;
}

- (NSData *)resolveCounterRange:(NSRange)range
{
	NSUInteger length = range.length * sizeof(uint64_t) * _valuesPerSample;
	NSMutableData *data = [NSMutableData dataWithLength:length];
	StelaResolveCountersRequest request = {
		.buffer = _handle,
		.first = range.location,
		.count = range.length,
		.out = stela_span(data.mutableBytes, length),
	};
	StelaResolveCountersResponse response = {};
	StelaFailure failure;
	StelaSpans spans = {.writes = &request.out, .write_count = 1};
	uint32_t status = STELA_CALL_SPANS(&_device->_gate, ResolveCounters, &request, &response, spans, &failure);
	if (status != StelaStatusOk) {
		stela_report("resolveCounterRange:", &failure);
		return nil;
	}
	return response.resolved ? data : nil;
}

@end

/* The device's resource factories. */

@implementation StelaGPUDevice (Resources)

- (id)newBufferWithLength:(NSUInteger)length options:(NSUInteger)options
{
	StelaBufferResponse response;
	StelaFailure failure;
	if (!cpu_visible(options)) {
		StelaNewBufferRequest request = {.length = length, .options = options};
		if (STELA_CALL(&_gate, NewBuffer, &request, &response, &failure) != StelaStatusOk) {
			return nil;
		}
		return [[StelaGPUBuffer alloc] initWithDevice:self response:&response options:options length:length];
	}
	uint64_t mapped = page_aligned(length);
	void *contents = NULL;
	uint64_t memory = [self importLength:mapped contents:&contents failure:&failure];
	if (memory == 0) {
		return nil;
	}
	StelaNewImportedBufferRequest request = {.memory = memory, .length = length, .options = options};
	if (STELA_CALL(&_gate, NewImportedBuffer, &request, &response, &failure) != StelaStatusOk) {
		[self releaseHandle:memory];
		mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)contents, mapped);
		return nil;
	}
	StelaGPUBuffer *buffer = [[StelaGPUBuffer alloc] initWithDevice:self
							       response:&response
								options:options
								 length:length];
	buffer->_contents = contents;
	buffer->_mappedBytes = mapped;
	return buffer;
}

- (id)newBufferWithBytes:(const void *)bytes length:(NSUInteger)length options:(NSUInteger)options
{
	StelaGPUBuffer *buffer = [self newBufferWithLength:length options:options];
	if (buffer && !buffer->_contents) {
		StelaFailure failure = {.reason = "private memory is out of the CPU's reach"};
		stela_report("newBufferWithBytes:", &failure);
		return nil;
	}
	if (buffer) {
		memcpy(buffer->_contents, bytes, length);
	}
	return buffer;
}

- (id)newBufferWithBytesNoCopy:(void *)bytes
			length:(NSUInteger)length
		       options:(NSUInteger)options
		   deallocator:(void (^)(void *, NSUInteger))deallocator
{
	StelaFailure failure;
	uint64_t memory = [self importAddress:bytes length:page_aligned(length) failure:&failure];
	if (memory == 0) {
		stela_report("newBufferWithBytesNoCopy:", &failure);
		return nil;
	}
	StelaNewImportedBufferRequest request = {.memory = memory, .length = length, .options = options};
	StelaBufferResponse response;
	if (STELA_CALL(&_gate, NewImportedBuffer, &request, &response, &failure) != StelaStatusOk) {
		stela_report("newBufferWithBytesNoCopy:", &failure);
		[self releaseHandle:memory];
		return nil;
	}
	StelaGPUBuffer *buffer = [[StelaGPUBuffer alloc] initWithDevice:self
							       response:&response
								options:options
								 length:length];
	buffer->_contents = bytes;
	buffer->_deallocator = deallocator;
	return buffer;
}

/* The texture reads the surface's own pages, through a buffer over them that
 * keeps the surface. Wiring them outlasts the lock that maps them. */
- (id)newTextureWithDescriptor:(id)descriptor iosurface:(IOSurfaceRef)surface plane:(NSUInteger)plane
{
	if (IOSurfaceLock(surface, 0, NULL) != 0) {
		StelaFailure failure = {.reason = "the surface does not lock"};
		stela_report("newTextureWithDescriptor:iosurface:plane:", &failure);
		return nil;
	}
	uint8_t *base = IOSurfaceGetBaseAddress(surface);
	NSUInteger offset = (uint8_t *)IOSurfaceGetBaseAddressOfPlane(surface, plane) - base;
	NSUInteger bytesPerRow = IOSurfaceGetBytesPerRowOfPlane(surface, plane);
	CFRetain(surface);
	StelaGPUBuffer *buffer = [self newBufferWithBytesNoCopy:base
							 length:IOSurfaceGetAllocSize(surface)
							options:MTLStorageModeShared << 4
						    deallocator:^(void *contents, NSUInteger length) {
							    CFRelease(surface);
						    }];
	IOSurfaceUnlock(surface, 0, NULL);
	if (!buffer) {
		CFRelease(surface);
		return nil;
	}
	StelaGPUTexture *texture = [buffer newTextureWithDescriptor:descriptor offset:offset bytesPerRow:bytesPerRow];
	if (texture) {
		texture->_surface = surface;
		texture->_surfacePlane = plane;
	}
	return texture;
}

- (id)newTextureWithDescriptor:(id)descriptor
{
	StelaTextureDescriptorRecord request;
	stela_texture_record(descriptor, &request);
	StelaTextureResponse response;
	StelaFailure failure;
	if (STELA_CALL(&_gate, NewTexture, &request, &response, &failure) != StelaStatusOk) {
		stela_report("a texture", &failure);
		return nil;
	}
	return [[StelaGPUTexture alloc] initWithDevice:self response:&response descriptor:descriptor];
}

- (id)newSamplerStateWithDescriptor:(id)descriptor
{
	StelaSamplerDescriptorRecord request = {
		.min_filter = [descriptor minFilter],
		.mag_filter = [descriptor magFilter],
		.mip_filter = [descriptor mipFilter],
		.max_anisotropy = [descriptor maxAnisotropy],
		.address_modes = {[descriptor sAddressMode], [descriptor tAddressMode], [descriptor rAddressMode]},
		.border_color = [descriptor borderColor],
		.reduction_mode = [descriptor reductionMode],
		.compare_function = [descriptor compareFunction],
		.lod_min_clamp = [descriptor lodMinClamp],
		.lod_max_clamp = [descriptor lodMaxClamp],
		.normalized_coordinates = [descriptor normalizedCoordinates],
	};
	StelaSamplerResponse response;
	StelaFailure failure;
	if (STELA_CALL(&_gate, NewSampler, &request, &response, &failure) != StelaStatusOk) {
		stela_report("a sampler", &failure);
		return nil;
	}
	StelaGPUSampler *sampler = [[StelaGPUSampler alloc] initWithDevice:self handle:response.handle];
	sampler->_resourceID = response.resource_id;
	sampler.label = [descriptor label];
	return sampler;
}

- (id)newHeapWithDescriptor:(id)descriptor
{
	NSUInteger options = [descriptor resourceOptions];
	StelaHeapDescriptorRecord request = {
		.size = [descriptor size],
		.options = options,
		.heap_type = [descriptor type],
		.sparse_page_size = [descriptor sparsePageSize],
	};
	void *contents = NULL;
	uint64_t mapped = 0;
	StelaFailure failure;
	if (cpu_visible(options)) {
		mapped = page_aligned(request.size);
		request.memory = [self importLength:mapped contents:&contents failure:&failure];
		if (request.memory == 0) {
			return nil;
		}
	}
	StelaHandle response;
	if (STELA_CALL(&_gate, NewHeap, &request, &response, &failure) != StelaStatusOk) {
		if (mapped) {
			[self releaseHandle:request.memory];
			mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)contents, mapped);
		}
		return nil;
	}
	StelaGPUHeap *heap = [[StelaGPUHeap alloc] initWithDevice:self handle:response.handle];
	heap->_contents = contents;
	heap->_mappedBytes = mapped;
	heap->_size = request.size;
	heap->_options = options;
	heap->_type = request.heap_type;
	heap.label = [descriptor label];
	return heap;
}

- (MTLSizeAndAlign)heapBufferSizeAndAlignWithLength:(NSUInteger)length options:(NSUInteger)options
{
	StelaHeapBufferSizeRequest request = {.length = length, .options = options};
	StelaSizeAndAlignRecord size = {};
	STELA_CALL(&_gate, HeapBufferSizeAndAlign, &request, &size, NULL);
	return (MTLSizeAndAlign){size.size, size.align};
}

- (MTLSizeAndAlign)heapTextureSizeAndAlignWithDescriptor:(id)descriptor
{
	StelaTextureDescriptorRecord request;
	stela_texture_record(descriptor, &request);
	StelaSizeAndAlignRecord size = {};
	STELA_CALL(&_gate, HeapTextureSizeAndAlign, &request, &size, NULL);
	return (MTLSizeAndAlign){size.size, size.align};
}

- (id)newEvent
{
	return [self newSharedEvent];
}

- (id)newSharedEvent
{
	StelaEmpty nothing = {};
	StelaHandle response;
	StelaFailure failure;
	if (STELA_CALL(&_gate, NewEvent, &nothing, &response, &failure) != StelaStatusOk) {
		stela_report("an event", &failure);
		return nil;
	}
	return [[StelaGPUEvent alloc] initWithDevice:self handle:response.handle];
}

- (id)newCounterSampleBufferWithDescriptor:(id)descriptor error:(NSError **)error
{
	StelaGPUCounterSet *set = [descriptor counterSet];
	StelaNewCounterBufferRequest request = {.counter_set = set->_code, .sample_count = [descriptor sampleCount]};
	StelaHandle response;
	StelaFailure failure;
	if (STELA_CALL(&_gate, NewCounterBuffer, &request, &response, &failure) != StelaStatusOk) {
		if (error) {
			*error = stela_error(MTLCounterErrorDomain, MTLCounterSampleBufferErrorInternal, &failure);
		}
		return nil;
	}
	StelaGPUCounterSampleBuffer *buffer = [[StelaGPUCounterSampleBuffer alloc] initWithDevice:self
											   handle:response.handle];
	buffer->_sampleCount = request.sample_count;
	/* A statistic sample is one value per statistic; a timestamp is one. */
	buffer->_valuesPerSample = 1;
	buffer.label = [descriptor label];
	return buffer;
}

@end
