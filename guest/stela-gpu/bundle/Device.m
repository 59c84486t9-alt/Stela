/*
 * The device: what the capability block answers, the objects that need nothing
 * of their own, and completion delivery. Metal's own _MTLDevice keeps the
 * registration bookkeeping; every query it would answer from a hardware hook
 * is answered here.
 */
#include "Bundle.h"

#define FLAG(selector, flag)                                                                       \
	-(BOOL)selector                                                                            \
	{                                                                                          \
		return (_capabilities->flags & StelaFlags_##flag) != 0;                            \
	}
#define LIMIT(selector, field)                                                                     \
	-(NSUInteger)selector                                                                      \
	{                                                                                          \
		return _capabilities->limits.field;                                                \
	}
#define FIELD(selector, field)                                                                     \
	-(NSUInteger)selector                                                                      \
	{                                                                                          \
		return _capabilities->field;                                                       \
	}

/* Vulkan's standard sample locations, the GPU's own, in 1/16ths of a pixel. */
static const uint8_t PATTERN_2[][2] = {{12, 12}, {4, 4}};
static const uint8_t PATTERN_4[][2] = {{6, 2}, {14, 6}, {2, 10}, {10, 14}};
static const uint8_t PATTERN_8[][2] = {{9, 5},	{7, 11}, {13, 9}, {5, 3},
				       {3, 13}, {1, 7},	 {11, 15}, {15, 1}};
static const uint8_t PATTERN_16[][2] = {{9, 9},	 {7, 5},  {5, 10}, {12, 7}, {3, 6},  {10, 13},
					{13, 11}, {11, 3}, {6, 14}, {8, 1},  {4, 2},  {2, 12},
					{0, 8},	 {15, 4}, {14, 15}, {1, 0}};

@interface StelaGPUArchitecture : NSObject
@property(copy) NSString *name;
@end

@implementation StelaGPUArchitecture
@end

static void completed(void *reference, int result, void *count);

/* The tiles a pixel span covers, or lies across whole for an inward mode. */
static void tile_span(NSUInteger start, NSUInteger length, NSUInteger tile, NSUInteger mode, NSUInteger *first,
		      NSUInteger *count)
{
	NSUInteger end = start + length;
	BOOL inward = mode == MTLSparseTextureRegionAlignmentModeInward;
	NSUInteger low = (inward ? start + tile - 1 : start) / tile;
	NSUInteger high = (inward ? end : end + tile - 1) / tile;
	*first = low;
	*count = high > low ? high - low : 0;
}

@implementation StelaGPUDevice {
	io_service_t _port;
	id _acceleratorService;
	dispatch_queue_t _completions;
	IONotificationPortRef _notifications;
	os_unfair_lock _lock;
	/* Committed command buffers, by serial. */
	NSMutableArray *_inFlight;
	NSMutableArray *_indirect;
	uint64_t _seen;
	bool _lost;
	/* A moment both clocks read: the GPU's in ticks, the CPU's in seconds. */
	uint64_t _anchorTick;
	double _anchorSeconds;
	BOOL _shouldMaximizeConcurrentCompilation;
}

- (instancetype)initWithAcceleratorPort:(io_service_t)port
{
	self = [super init];
	if (!self) {
		return nil;
	}
	_port = port;
	IOObjectRetain(port);
	_lock = OS_UNFAIR_LOCK_INIT;
	_inFlight = [NSMutableArray arrayWithCapacity:64];
	_indirect = [NSMutableArray arrayWithCapacity:4];
	mach_vm_address_t page = 0;
	mach_vm_size_t bytes = 0;
	if (IOServiceOpen(port, mach_task_self(), kStelaGPUUserClientType, &_gate.connect) != KERN_SUCCESS) {
		return nil;
	}
	if (IOConnectMapMemory64(_gate.connect, kStelaGPUGateMemory, mach_task_self(), &page, &bytes,
				 kIOMapAnywhere | kIOMapDefaultCache)
	    != KERN_SUCCESS) {
		IOServiceClose(_gate.connect);
		return nil;
	}
	_gate.page = (volatile uint64_t *)page;

	StelaNegotiateRequest versions = {.major = STELA_MAJOR, .minor = STELA_MINOR};
	StelaNegotiateResponse agreed;
	StelaFailure failure;
	if (STELA_CALL(&_gate, Negotiate, &versions, &agreed, &failure) != StelaStatusOk) {
		stela_report("the service's protocol", &failure);
		return nil;
	}
	StelaEmpty nothing = {};
	_capabilities = malloc(sizeof(*_capabilities));
	if (!_capabilities || agreed.capability_bytes != sizeof(*_capabilities)
	    || STELA_CALL(&_gate, Capabilities, &nothing, _capabilities, &failure) != StelaStatusOk) {
		stela_report("the capability block", &failure);
		return nil;
	}

	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	uint64_t now;
	[self sampleTimestamps:&now gpuTimestamp:&_anchorTick];
	_anchorSeconds = (double)now * timebase.numer / timebase.denom / 1e9;

	_completions = dispatch_queue_create("com.stela.StelaGPU.completions", NULL);
	_notifications = IONotificationPortCreate(kIOMainPortDefault);
	IONotificationPortSetDispatchQueue(_notifications, _completions);
	[self arm];
	return self;
}

- (uint32_t)acceleratorPort
{
	return _port;
}

- (void)_setAcceleratorService:(id)service
{
	_acceleratorService = service;
}

- (id)acceleratorService
{
	return _acceleratorService;
}

/* The block answers these; there is nothing to gather. */
- (void)initLimits
{
}

- (void)initFeatureQueries
{
}

- (void)initGPUFamilySupport
{
}

/* An unknown profile: no code path of Metal's may take this for an AGX GPU. */
- (uint32_t)featureProfile
{
	return 'STLA';
}

/* Waking on completions. */

- (void)arm
{
	uint64_t reference[kIOAsyncCalloutCount] = {(uint64_t)completed, (uint64_t)(__bridge void *)self};
	mach_port_t port = IONotificationPortGetMachPort(_notifications);
	IOConnectCallAsyncScalarMethod(_gate.connect, kStelaGPUNotifyCompletion, port, reference,
				       kIOAsyncCalloutCount, &_seen, 1, NULL, NULL);
}

- (void)completionsReached:(uint64_t)count
{
	_seen = count;
	StelaEmpty nothing = {};
	StelaValue reached = {};
	StelaFailure failure;
	bool lost = STELA_CALL(&_gate, Poll, &nothing, &reached, &failure) != StelaStatusOk;
	NSMutableArray *done = [NSMutableArray arrayWithCapacity:8];
	os_unfair_lock_lock(&_lock);
	_lost = _lost || lost;
	while (_inFlight.count) {
		StelaGPUCommandBuffer *buffer = [_inFlight objectAtIndex:0];
		if (!lost && buffer->_serial > reached.value) {
			break;
		}
		[done addObject:buffer];
		[_inFlight removeObjectAtIndex:0];
	}
	os_unfair_lock_unlock(&_lock);
	for (NSUInteger i = 0; i < done.count; i++) {
		[[done objectAtIndex:i] didCompleteWith:lost ? &failure : NULL];
	}
	[self arm];
}

static void completed(void *reference, int result, void *count)
{
	(void)result;
	[(__bridge StelaGPUDevice *)reference completionsReached:(uint64_t)count];
}

/* A completion can precede this, so the queue looks again once it is noted. */
- (void)track:(StelaGPUCommandBuffer *)buffer
{
	os_unfair_lock_lock(&_lock);
	[_inFlight addObject:buffer];
	os_unfair_lock_unlock(&_lock);
	dispatch_async(_completions, ^{
		[buffer didSchedule];
		[self completionsReached:self->_seen];
	});
}

- (void)failed:(StelaGPUCommandBuffer *)buffer with:(StelaFailure)failure
{
	dispatch_async(_completions, ^{
		[buffer didCompleteWith:&failure];
	});
}

- (CFTimeInterval)secondsOfTick:(uint64_t)tick
{
	if (tick == 0) {
		return 0;
	}
	return _anchorSeconds + (double)(int64_t)(tick - _anchorTick) / (double)_capabilities->timestamp_frequency;
}

- (void)noteIndirect:(StelaGPUIndirectCommandBuffer *)buffer
{
	os_unfair_lock_lock(&_lock);
	[_indirect addObject:[NSValue valueWithNonretainedObject:buffer]];
	os_unfair_lock_unlock(&_lock);
}

- (void)forgetIndirect:(StelaGPUIndirectCommandBuffer *)buffer
{
	os_unfair_lock_lock(&_lock);
	for (NSUInteger i = _indirect.count; i > 0; i--) {
		if ([[_indirect objectAtIndex:i - 1] nonretainedObjectValue] == buffer) {
			[_indirect removeObjectAtIndex:i - 1];
		}
	}
	os_unfair_lock_unlock(&_lock);
}

- (void)flushIndirect
{
	os_unfair_lock_lock(&_lock);
	NSArray *noted = _indirect;
	_indirect = [NSMutableArray arrayWithCapacity:4];
	for (NSUInteger i = 0; i < noted.count; i++) {
		[(StelaGPUIndirectCommandBuffer *)[[noted objectAtIndex:i] nonretainedObjectValue] flush];
	}
	os_unfair_lock_unlock(&_lock);
}

- (void)releaseHandle:(uint64_t)handle
{
	StelaHandle request = {.handle = handle};
	StelaEmpty nothing;
	STELA_CALL(&_gate, Release, &request, &nothing, NULL);
}

/* What a CPU reaches is the task's own memory, wired for the GPU. */

- (uint64_t)importAddress:(void *)address length:(uint64_t)length failure:(StelaFailure *)failure
{
	uint64_t input[2] = {(uint64_t)address, length};
	uint64_t handle = 0;
	uint32_t outputs = 1;
	kern_return_t result =
	    IOConnectCallScalarMethod(_gate.connect, kStelaGPUImportMemory, input, 2, &handle, &outputs);
	if (result != KERN_SUCCESS) {
		*failure = (StelaFailure){.status = StelaStatusOutOfMemory, .reason = "out of wired memory"};
		return 0;
	}
	return handle;
}

- (uint64_t)importLength:(uint64_t)length contents:(void **)contents failure:(StelaFailure *)failure
{
	mach_vm_address_t address = 0;
	if (mach_vm_allocate(mach_task_self(), &address, length, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
		*failure = (StelaFailure){.status = StelaStatusOutOfMemory, .reason = "out of memory"};
		return 0;
	}
	uint64_t memory = [self importAddress:(void *)address length:length failure:failure];
	if (memory == 0) {
		mach_vm_deallocate(mach_task_self(), address, length);
		return 0;
	}
	*contents = (void *)address;
	return memory;
}

/* Identity. */

- (NSString *)name
{
	return [[NSString alloc] initWithBytes:_capabilities->name
					length:_capabilities->name_bytes
				      encoding:NSUTF8StringEncoding];
}

- (id)architecture
{
	StelaGPUArchitecture *architecture = [StelaGPUArchitecture new];
	architecture.name = [[NSString alloc] initWithBytes:_capabilities->architecture
						     length:_capabilities->architecture_bytes
						   encoding:NSUTF8StringEncoding];
	return architecture;
}

- (uint64_t)registryID
{
	uint64_t identifier = 0;
	IORegistryEntryGetRegistryEntryID(_port, &identifier);
	return identifier;
}

- (uint64_t)peerGroupID
{
	return 0;
}

- (uint32_t)peerIndex
{
	return 0;
}

- (uint32_t)peerCount
{
	return 0;
}

FIELD(location, location)
FIELD(locationNumber, location_number)
FIELD(argumentBuffersSupport, argument_buffers_tier)
FIELD(readWriteTextureSupport, read_write_texture_tier)

- (uint64_t)maxTransferRate
{
	return _capabilities->max_transfer_rate;
}

- (uint64_t)recommendedMaxWorkingSetSize
{
	return _capabilities->recommended_max_working_set_size;
}

- (NSUInteger)currentAllocatedSize
{
	StelaEmpty nothing = {};
	StelaValue size = {};
	STELA_CALL(&_gate, AllocatedSize, &nothing, &size, NULL);
	return size.value;
}

FLAG(isHeadless, HEADLESS)
FLAG(isLowPower, LOW_POWER)
FLAG(isRemovable, REMOVABLE)
FLAG(hasUnifiedMemory, UNIFIED_MEMORY)
FLAG(supports32BitFloatFiltering, FLOAT32_FILTERING)
FLAG(supports32BitMSAA, FLOAT32_MSAA)
FLAG(supportsBCTextureCompression, BC_TEXTURE_COMPRESSION)
FLAG(isDepth24Stencil8PixelFormatSupported, DEPTH24_STENCIL8)
FLAG(supportsQueryTextureLOD, QUERY_TEXTURE_LOD)
FLAG(supportsPullModelInterpolation, PULL_MODEL_INTERPOLATION)
FLAG(supportsShaderBarycentricCoordinates, SHADER_BARYCENTRIC_COORDINATES)
FLAG(areBarycentricCoordsSupported, SHADER_BARYCENTRIC_COORDINATES)
FLAG(areProgrammableSamplePositionsSupported, PROGRAMMABLE_SAMPLE_POSITIONS)
FLAG(areRasterOrderGroupsSupported, RASTER_ORDER_GROUPS)
FLAG(supportsRaytracing, RAYTRACING)
FLAG(supportsRaytracingFromRender, RAYTRACING_FROM_RENDER)
FLAG(supportsPrimitiveMotionBlur, PRIMITIVE_MOTION_BLUR)
FLAG(supportsFunctionPointers, FUNCTION_POINTERS)
FLAG(supportsFunctionPointersFromRender, FUNCTION_POINTERS_FROM_RENDER)
FLAG(supportsDynamicLibraries, DYNAMIC_LIBRARIES)
FLAG(supportsRenderDynamicLibraries, RENDER_DYNAMIC_LIBRARIES)
FLAG(supportsPlacementSparse, PLACEMENT_SPARSE)

LIMIT(maxThreadgroupMemoryLength, max_threadgroup_memory_length)
LIMIT(maxBufferLength, max_buffer_length)
LIMIT(maxArgumentBufferSamplerCount, max_argument_buffer_sampler_count)
LIMIT(sparseTileSizeInBytes, sparse_tile_bytes)

- (MTLSize)maxThreadsPerThreadgroup
{
	const uint64_t *size = _capabilities->limits.max_threads_per_threadgroup;
	return (MTLSize){size[0], size[1], size[2]};
}

- (NSUInteger)sparseTileSizeInBytesForSparsePageSize:(NSInteger)page
{
	NSUInteger bytes = _capabilities->limits.sparse_tile_bytes;
	/* MTLSparsePageSize's raw values are the size in KiB. */
	return (NSUInteger)page * 1024 == bytes ? bytes : 0;
}

- (MTLSize)sparseTileSizeWithTextureType:(NSUInteger)type
			     pixelFormat:(NSUInteger)format
			     sampleCount:(NSUInteger)count
{
	StelaSparseTileRequest request = {.texture_type = type, .pixel_format = format, .sample_count = count};
	StelaSparseTileResponse tile = {};
	STELA_CALL(&_gate, SparseTileSize, &request, &tile, NULL);
	return (MTLSize){tile.size[0], tile.size[1], tile.size[2]};
}

- (MTLSize)sparseTileSizeWithTextureType:(NSUInteger)type
			     pixelFormat:(NSUInteger)format
			     sampleCount:(NSUInteger)count
			  sparsePageSize:(NSInteger)page
{
	if (![self sparseTileSizeInBytesForSparsePageSize:page]) {
		return (MTLSize){0, 0, 0};
	}
	return [self sparseTileSizeWithTextureType:type pixelFormat:format sampleCount:count];
}

- (void)convertSparsePixelRegions:(const MTLRegion[])pixels
		    toTileRegions:(MTLRegion[])tiles
		     withTileSize:(MTLSize)tile
		    alignmentMode:(NSUInteger)mode
		       numRegions:(NSUInteger)count
{
	for (NSUInteger i = 0; i < count; i++) {
		MTLOrigin origin = pixels[i].origin;
		MTLSize size = pixels[i].size;
		tile_span(origin.x, size.width, tile.width, mode, &tiles[i].origin.x, &tiles[i].size.width);
		tile_span(origin.y, size.height, tile.height, mode, &tiles[i].origin.y, &tiles[i].size.height);
		tile_span(origin.z, size.depth, tile.depth, mode, &tiles[i].origin.z, &tiles[i].size.depth);
	}
}

- (void)convertSparseTileRegions:(const MTLRegion[])tiles
		   toPixelRegions:(MTLRegion[])pixels
		     withTileSize:(MTLSize)tile
		       numRegions:(NSUInteger)count
{
	for (NSUInteger i = 0; i < count; i++) {
		MTLOrigin origin = tiles[i].origin;
		MTLSize size = tiles[i].size;
		pixels[i].origin = (MTLOrigin){origin.x * tile.width, origin.y * tile.height, origin.z * tile.depth};
		pixels[i].size = (MTLSize){size.width * tile.width, size.height * tile.height, size.depth * tile.depth};
	}
}

- (BOOL)shouldMaximizeConcurrentCompilation
{
	return _shouldMaximizeConcurrentCompilation;
}

- (void)setShouldMaximizeConcurrentCompilation:(BOOL)maximize
{
	_shouldMaximizeConcurrentCompilation = maximize;
}

/* The service takes one call at a time. */
- (NSUInteger)maximumConcurrentCompilationTaskCount
{
	return 1;
}

- (StelaFormatAlignmentsResponse)alignmentsOfFormat:(NSUInteger)format
{
	StelaPixelFormatRequest request = {.pixel_format = format};
	StelaFormatAlignmentsResponse alignments = {};
	StelaFailure failure;
	if (STELA_CALL(&_gate, FormatAlignments, &request, &alignments, &failure) != StelaStatusOk) {
		stela_report("a pixel format's alignment", &failure);
	}
	return alignments;
}

- (NSUInteger)minimumLinearTextureAlignmentForPixelFormat:(NSUInteger)format
{
	return [self alignmentsOfFormat:format].linear_texture;
}

- (NSUInteger)minimumTextureBufferAlignmentForPixelFormat:(NSUInteger)format
{
	return [self alignmentsOfFormat:format].texture_buffer;
}

- (BOOL)supportsFamily:(NSInteger)family
{
	for (uint32_t i = 0; i < _capabilities->family_count; i++) {
		if (_capabilities->families[i] == (uint64_t)family) {
			return YES;
		}
	}
	return NO;
}

/* The deprecated macOS sets; iOS and tvOS sets are unknown here. */
- (BOOL)supportsFeatureSet:(NSUInteger)set
{
	if (set == MTLFeatureSet_macOS_ReadWriteTextureTier2) {
		return _capabilities->read_write_texture_tier >= 2;
	}
	if (set >= MTLFeatureSet_macOS_GPUFamily1_v1 && set <= MTLFeatureSet_macOS_GPUFamily1_v4) {
		return [self supportsFamily:MTLGPUFamilyMac1];
	}
	return set == MTLFeatureSet_macOS_GPUFamily2_v1 && [self supportsFamily:MTLGPUFamilyMac2];
}

- (BOOL)supportsTextureSampleCount:(NSUInteger)count
{
	/* VkSampleCountFlags: each bit is its count. */
	return count != 0 && (count & (count - 1)) == 0 && (_capabilities->texture_sample_counts & count) != 0;
}

- (BOOL)supportsVertexAmplificationCount:(NSUInteger)count
{
	return count != 0 && count <= _capabilities->limits.max_vertex_amplification_count;
}

- (BOOL)supportsRasterizationRateMapWithLayerCount:(NSUInteger)count
{
	(void)count;
	return NO;
}

- (BOOL)supportsCounterSampling:(NSUInteger)point
{
	return point < 32 && (_capabilities->counter_sampling >> point & 1) != 0;
}

- (void)getDefaultSamplePositions:(MTLSamplePosition *)positions count:(NSUInteger)count
{
	const uint8_t(*pattern)[2];
	switch (count) {
	case 1:
		positions[0] = (MTLSamplePosition){0.5f, 0.5f};
		return;
	case 2:
		pattern = PATTERN_2;
		break;
	case 4:
		pattern = PATTERN_4;
		break;
	case 8:
		pattern = PATTERN_8;
		break;
	case 16:
		pattern = PATTERN_16;
		break;
	default:
		return;
	}
	for (NSUInteger i = 0; i < count; i++) {
		positions[i] = (MTLSamplePosition){pattern[i][0] / 16.0f, pattern[i][1] / 16.0f};
	}
}

- (void)sampleTimestamps:(MTLTimestamp *)cpu gpuTimestamp:(MTLTimestamp *)gpu
{
	StelaEmpty nothing = {};
	StelaTimestampsResponse times = {};
	StelaFailure failure;
	/* The guest's clock, not the Vulkan host's, is the CPU's. */
	*cpu = mach_absolute_time();
	if (STELA_CALL(&_gate, SampleTimestamps, &nothing, &times, &failure) != StelaStatusOk) {
		stela_report("a timestamp", &failure);
	}
	*gpu = times.gpu;
}

- (NSArray *)counterSets
{
	StelaGPUCounterSet *sets[2];
	NSUInteger count = 0;
	sets[count++] = [StelaGPUCounterSet setWithCode:StelaCounterSetCodeTimestamp];
	if (_capabilities->flags & StelaFlags_STATISTIC_COUNTERS) {
		sets[count++] = [StelaGPUCounterSet setWithCode:StelaCounterSetCodeStatistic];
	}
	return [NSArray arrayWithObjects:sets count:count];
}

/* Queues. */

- (id)newCommandQueue
{
	return [[StelaGPUQueue alloc] initWithDevice:self];
}

- (id)newCommandQueueWithMaxCommandBufferCount:(NSUInteger)count
{
	(void)count;
	return [self newCommandQueue];
}

- (id)newCommandQueueWithDescriptor:(id)descriptor
{
	(void)descriptor;
	return [self newCommandQueue];
}

/* What has no service object. */

- (id)newFence
{
	StelaGPUFence *fence = [StelaGPUFence new];
	fence->_device = self;
	return fence;
}

- (id)newDepthStencilStateWithDescriptor:(id)descriptor
{
	StelaGPUDepthStencil *state = [StelaGPUDepthStencil new];
	state->_device = self;
	state.label = [descriptor label];
	stela_depth_stencil_record(descriptor, &state->_record);
	return state;
}

@end
