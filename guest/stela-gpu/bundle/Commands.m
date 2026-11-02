/*
 * Queues and command buffers. A command buffer's stream stays here until
 * commit, when the service replays it; completions arrive in serial order on
 * the device's queue. What the stream names stays retained until then.
 */
#include "Bundle.h"

static CFTimeInterval host_time(void)
{
	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	return (double)mach_absolute_time() * timebase.numer / timebase.denom / 1e9;
}

@implementation StelaGPUQueue {
	os_unfair_lock _lock;
	/* Enqueued command buffers, which commit in this order. */
	NSMutableArray *_enqueued;
}

- (instancetype)initWithDevice:(StelaGPUDevice *)device
{
	self = [super init];
	if (self) {
		_device = device;
		_lock = OS_UNFAIR_LOCK_INIT;
		_enqueued = [NSMutableArray arrayWithCapacity:16];
	}
	return self;
}

- (id)device
{
	return _device;
}

/* Everything a task holds is resident: `Residency.m`. */
- (void)addResidencySet:(id)set
{
}

- (void)addResidencySets:(const id __unsafe_unretained[])sets count:(NSUInteger)count
{
}

- (void)removeResidencySet:(id)set
{
}

- (void)removeResidencySets:(const id __unsafe_unretained[])sets count:(NSUInteger)count
{
}

- (id)commandBuffer
{
	return [[StelaGPUCommandBuffer alloc] initWithQueue:self retainsReferences:YES logState:_logState];
}

- (id)commandBufferWithUnretainedReferences
{
	return [[StelaGPUCommandBuffer alloc] initWithQueue:self retainsReferences:NO logState:_logState];
}

- (id)commandBufferWithDescriptor:(id)descriptor
{
	StelaGPUCommandBuffer *buffer = [[StelaGPUCommandBuffer alloc] initWithQueue:self
					  retainsReferences:[descriptor retainedReferences]
						   logState:[descriptor logState] ?: _logState];
	buffer.errorOptions = [descriptor errorOptions];
	return buffer;
}

- (void)insertDebugCaptureBoundary
{
}

- (void)enqueue:(StelaGPUCommandBuffer *)buffer
{
	os_unfair_lock_lock(&_lock);
	[_enqueued addObject:buffer];
	os_unfair_lock_unlock(&_lock);
}

/* Commits the enqueued command buffers that are ready, from the first. */
- (void)flush
{
	os_unfair_lock_lock(&_lock);
	while (_enqueued.count) {
		StelaGPUCommandBuffer *buffer = [_enqueued objectAtIndex:0];
		if (!buffer->_committed) {
			break;
		}
		[_enqueued removeObjectAtIndex:0];
		[buffer submit];
	}
	os_unfair_lock_unlock(&_lock);
}

@end

@implementation StelaGPUCommandBuffer {
	dispatch_group_t _scheduling;
	dispatch_group_t _completion;
	NSMutableArray *_scheduledHandlers, *_completedHandlers;
	NSError *_error;
	_Atomic(NSUInteger) _status;
	NSUInteger _errorOptions;
	NSMutableArray *_encoderInfos;
	os_unfair_lock _referencesLock;
	CFTimeInterval _kernelStart, _kernelEnd;
	bool _enqueued;
	bool _retains;
}

- (instancetype)initWithQueue:(StelaGPUQueue *)queue
	    retainsReferences:(BOOL)retains
		     logState:(StelaGPULogState *)logState
{
	self = [super init];
	if (self) {
		_queue = queue;
		_device = queue->_device;
		_retains = retains;
		_referencesLock = OS_UNFAIR_LOCK_INIT;
		_retained = retains ? [NSMutableArray arrayWithCapacity:64] : nil;
		_scheduling = dispatch_group_create();
		_completion = dispatch_group_create();
		_scheduledHandlers = [NSMutableArray arrayWithCapacity:2];
		_completedHandlers = [NSMutableArray arrayWithCapacity:2];
		_status = MTLCommandBufferStatusNotEnqueued;
		_logState = logState;
		if (logState) {
			StelaHandle buffer = {.handle = [logState bufferHandle]};
			stela_stream_entry(&_stream, StelaCommandBufferCodeLogBuffer, &buffer, sizeof(buffer), NULL, 0);
		}
		dispatch_group_enter(_scheduling);
		dispatch_group_enter(_completion);
	}
	return self;
}

- (void)dealloc
{
	stela_stream_free(&_stream);
	dispatch_release(_scheduling);
	dispatch_release(_completion);
}

- (id)device
{
	return _device;
}

- (id)commandQueue
{
	return _queue;
}

- (BOOL)retainedReferences
{
	return _retains;
}

- (NSUInteger)errorOptions
{
	return _errorOptions;
}

- (void)setErrorOptions:(NSUInteger)options
{
	_errorOptions = options;
	_encoderInfos = options & MTLCommandBufferErrorOptionEncoderExecutionStatus
			? [NSMutableArray arrayWithCapacity:4]
			: nil;
}

- (StelaGPUEncoderInfo *)recordEncoder
{
	if (!_encoderInfos) {
		return nil;
	}
	StelaGPUEncoderInfo *info = [StelaGPUEncoderInfo new];
	info.label = @"";
	info.debugSignposts = [NSArray array];
	os_unfair_lock_lock(&_referencesLock);
	[_encoderInfos addObject:info];
	os_unfair_lock_unlock(&_referencesLock);
	return info;
}

- (id)logs
{
	return stela_empty_logs();
}

- (NSUInteger)status
{
	return _status;
}

- (NSError *)error
{
	return _error;
}

- (void)use:(id)object
{
	if (object) {
		/* Parallel render encoders share this command buffer's references. */
		os_unfair_lock_lock(&_referencesLock);
		[_retained addObject:object];
		os_unfair_lock_unlock(&_referencesLock);
	}
}

- (void)enqueue
{
	if (!_enqueued) {
		_enqueued = true;
		_status = MTLCommandBufferStatusEnqueued;
		[_queue enqueue:self];
	}
}

- (void)commit
{
	[self enqueue];
	_status = MTLCommandBufferStatusCommitted;
	_committed = true;
	[_queue flush];
}

/* Under the queue's lock, so serials follow the order of enqueue. */
- (void)submit
{
	_kernelStart = host_time();
	[_logState commandBufferStarted];
	[_device flushIndirect];
	StelaCommitRequest request = {.commands = stela_span(_stream.bytes, _stream.length)};
	StelaValue serial = {};
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.commands, .read_count = 1};
	if (STELA_CALL_SPANS(&_device->_gate, Commit, &request, &serial, spans, &failure) != StelaStatusOk) {
		_kernelEnd = host_time();
		[_device failed:self with:failure];
		return;
	}
	stela_stream_free(&_stream);
	_serial = serial.value;
	_kernelEnd = host_time();
	[_device track:self];
}

/* On the device's queue, ahead of completion. */
- (void)didSchedule
{
	/* A completion notification can beat the device's queued scheduling callback. */
	if (_status >= MTLCommandBufferStatusScheduled) {
		return;
	}
	_status = MTLCommandBufferStatusScheduled;
	for (NSUInteger i = 0; i < _scheduledHandlers.count; i++) {
		((void (^)(id))[_scheduledHandlers objectAtIndex:i])(self);
	}
	[_scheduledHandlers removeAllObjects];
	dispatch_group_leave(_scheduling);
}

- (void)didCompleteWith:(const StelaFailure *)failure
{
	[self didSchedule];
	if (failure) {
		_error = stela_command_error(failure, _encoderInfos, _serial != 0);
	}
	_status = failure ? MTLCommandBufferStatusError : MTLCommandBufferStatusCompleted;
	[_logState commandBufferEnded];
	dispatch_queue_t queue = (__bridge dispatch_queue_t)_queue.completionQueue;
	if (queue) {
		dispatch_async(queue, ^{
			[self finishCompletion];
		});
	} else {
		[self finishCompletion];
	}
}

- (void)finishCompletion
{
	for (NSUInteger i = 0; i < _completedHandlers.count; i++) {
		((void (^)(id))[_completedHandlers objectAtIndex:i])(self);
	}
	[_completedHandlers removeAllObjects];
	os_unfair_lock_lock(&_referencesLock);
	[_retained removeAllObjects];
	os_unfair_lock_unlock(&_referencesLock);
	dispatch_group_leave(_completion);
}

- (void)addScheduledHandler:(void (^)(id))handler
{
	[_scheduledHandlers addObject:[handler copy]];
}

/* Everything a task holds is resident: `Residency.m`. */
- (void)useResidencySet:(id)set
{
}

- (void)useResidencySets:(const id __unsafe_unretained[])sets count:(NSUInteger)count
{
}

- (void)addCompletedHandler:(void (^)(id))handler
{
	[_completedHandlers addObject:[handler copy]];
}

- (void)waitUntilScheduled
{
	dispatch_group_wait(_scheduling, DISPATCH_TIME_FOREVER);
}

- (void)waitUntilCompleted
{
	dispatch_group_wait(_completion, DISPATCH_TIME_FOREVER);
}

- (CFTimeInterval)kernelStartTime
{
	return _status >= MTLCommandBufferStatusScheduled ? _kernelStart : 0;
}

- (CFTimeInterval)kernelEndTime
{
	return _status >= MTLCommandBufferStatusScheduled ? _kernelEnd : 0;
}

- (StelaCommandBufferTimesResponse)times
{
	StelaValue request = {.value = _serial};
	StelaCommandBufferTimesResponse times = {};
	STELA_CALL(&_device->_gate, CommandBufferTimes, &request, &times, NULL);
	return times;
}

- (CFTimeInterval)GPUStartTime
{
	return [_device secondsOfTick:[self times].start];
}

- (CFTimeInterval)GPUEndTime
{
	return [_device secondsOfTick:[self times].end];
}

- (void)pushDebugGroup:(NSString *)name
{
	(void)name;
}

- (void)popDebugGroup
{
}

/* No fence reaches the window server, so a frame presents once the GPU finished it. */
- (void)presentDrawable:(id)drawable
{
	[self addCompletedHandler:^(id buffer) {
		(void)buffer;
		[drawable present];
	}];
}

- (void)presentDrawable:(id)drawable atTime:(CFTimeInterval)time
{
	[self addCompletedHandler:^(id buffer) {
		(void)buffer;
		[drawable presentAtTime:time];
	}];
}

- (void)presentDrawable:(id)drawable afterMinimumDuration:(CFTimeInterval)duration
{
	[self addCompletedHandler:^(id buffer) {
		(void)buffer;
		[drawable presentAfterMinimumDuration:duration];
	}];
}

- (void)encodeSignalEvent:(StelaGPUEvent *)event value:(uint64_t)value
{
	[self use:event];
	StelaEventCommand command = {.event = event->_handle, .value = value};
	stela_stream_entry(&_stream, StelaCommandBufferCodeSignalEvent, &command, sizeof(command), NULL, 0);
}

- (void)encodeWaitForEvent:(StelaGPUEvent *)event value:(uint64_t)value
{
	[self use:event];
	StelaEventCommand command = {.event = event->_handle, .value = value};
	stela_stream_entry(&_stream, StelaCommandBufferCodeWaitForEvent, &command, sizeof(command), NULL, 0);
}

- (id)blitCommandEncoder
{
	StelaGPUBlitEncoder *encoder = [[StelaGPUBlitEncoder alloc] initWithCommandBuffer:self stream:&_stream];
	stela_stream_entry(&_stream, StelaBlitCodeBegin, NULL, 0, NULL, 0);
	return encoder;
}

- (id)blitCommandEncoderWithDescriptor:(id)descriptor
{
	StelaGPUBlitEncoder *encoder = [self blitCommandEncoder];
	[encoder sampleAttachments:[descriptor sampleBufferAttachments]];
	return encoder;
}

- (id)computeCommandEncoderWithDispatchType:(NSUInteger)type
{
	StelaGPUComputeEncoder *encoder = [[StelaGPUComputeEncoder alloc] initWithCommandBuffer:self stream:&_stream];
	encoder->_dispatchType = type;
	StelaBeginCompute begin = {.dispatch_type = type};
	stela_stream_entry(&_stream, StelaComputeCodeBegin, &begin, sizeof(begin), NULL, 0);
	return encoder;
}

- (id)computeCommandEncoder
{
	return [self computeCommandEncoderWithDispatchType:MTLDispatchTypeSerial];
}

- (id)computeCommandEncoderWithDescriptor:(id)descriptor
{
	StelaGPUComputeEncoder *encoder = [self computeCommandEncoderWithDispatchType:[descriptor dispatchType]];
	[encoder sampleAttachments:[descriptor sampleBufferAttachments]];
	return encoder;
}

- (id)resourceStateCommandEncoder
{
	StelaGPUResourceStateEncoder *encoder = [[StelaGPUResourceStateEncoder alloc] initWithCommandBuffer:self
												     stream:&_stream];
	stela_stream_entry(&_stream, StelaResourceStateCodeBegin, NULL, 0, NULL, 0);
	return encoder;
}

- (id)resourceStateCommandEncoderWithDescriptor:(id)descriptor
{
	StelaGPUResourceStateEncoder *encoder = [self resourceStateCommandEncoder];
	[encoder sampleAttachments:[descriptor sampleBufferAttachments]];
	return encoder;
}

- (id)renderCommandEncoderWithDescriptor:(id)descriptor
{
	[self beginRender:descriptor];
	return [[StelaGPURenderEncoder alloc] initWithCommandBuffer:self stream:&_stream];
}

- (id)parallelRenderCommandEncoderWithDescriptor:(id)descriptor
{
	[self beginRender:descriptor];
	return [[StelaGPUParallelEncoder alloc] initWithCommandBuffer:self stream:&_stream];
}

static void pass_attachment(id attachment, StelaPassAttachmentRecord *record)
{
	StelaGPUTexture *texture = [attachment texture];
	StelaGPUTexture *resolve = [attachment resolveTexture];
	*record = (StelaPassAttachmentRecord){
		.texture = texture ? texture->_handle : 0,
		.level = [attachment level],
		.slice = [attachment slice],
		.depth_plane = [attachment depthPlane],
		.resolve_texture = resolve ? resolve->_handle : 0,
		.resolve_level = [attachment resolveLevel],
		.resolve_slice = [attachment resolveSlice],
		.resolve_depth_plane = [attachment resolveDepthPlane],
		.load_action = [attachment loadAction],
		.store_action = [attachment storeAction],
		.store_action_options = [attachment storeActionOptions],
	};
}

- (void)beginRender:(id)descriptor
{
	StelaBeginRender begin = {};
	id colors = [descriptor colorAttachments];
	for (NSUInteger i = 0; i < 8; i++) {
		id color = [colors objectAtIndexedSubscript:i];
		pass_attachment(color, &begin.color_attachments[i].attachment);
		[self use:[color texture]];
		[self use:[color resolveTexture]];
		MTLClearColor clear = [color clearColor];
		memcpy(begin.color_attachments[i].clear_color, &clear, sizeof(clear));
	}
	id depth = [descriptor depthAttachment];
	id stencil = [descriptor stencilAttachment];
	pass_attachment(depth, &begin.depth_attachment.attachment);
	pass_attachment(stencil, &begin.stencil_attachment.attachment);
	[self use:[depth texture]];
	[self use:[depth resolveTexture]];
	[self use:[stencil texture]];
	[self use:[stencil resolveTexture]];
	begin.depth_attachment.clear_depth = [depth clearDepth];
	begin.depth_attachment.resolve_filter = [depth depthResolveFilter];
	begin.stencil_attachment.clear_stencil = [stencil clearStencil];
	begin.stencil_attachment.resolve_filter = [stencil stencilResolveFilter];
	StelaGPUBuffer *visibility = [descriptor visibilityResultBuffer];
	[self use:visibility];
	begin.visibility_result_buffer = visibility ? visibility->_handle : 0;
	begin.render_target_array_length = [descriptor renderTargetArrayLength];
	begin.render_target_width = [descriptor renderTargetWidth];
	begin.render_target_height = [descriptor renderTargetHeight];
	begin.default_raster_sample_count = [descriptor defaultRasterSampleCount];
	begin.tile_memory = [descriptor imageblockSampleLength] != 0 || [descriptor threadgroupMemoryLength] != 0
			    || [descriptor tileWidth] != 0 || [descriptor tileHeight] != 0;
	begin.rasterization_rate_map = [descriptor rasterizationRateMap] != nil;

	MTLSamplePosition positions[16];
	/* Metal validates a count it is given, so it answers how many first. */
	begin.sample_position_count = (uint32_t)[descriptor getSamplePositions:NULL count:0];
	if (begin.sample_position_count) {
		[descriptor getSamplePositions:positions count:begin.sample_position_count];
	}
	StelaCounterSampleRecord samples[4 * 4];
	NSUInteger sample_count = 0;
	id attachments = [descriptor sampleBufferAttachments];
	for (NSUInteger i = 0; i < 4; i++) {
		id attachment = [attachments objectAtIndexedSubscript:i];
		StelaGPUCounterSampleBuffer *buffer = [attachment sampleBuffer];
		if (!buffer) {
			continue;
		}
		[self use:buffer];
		const NSUInteger indices[4] = {
			[attachment startOfVertexSampleIndex],
			[attachment endOfVertexSampleIndex],
			[attachment startOfFragmentSampleIndex],
			[attachment endOfFragmentSampleIndex],
		};
		for (NSUInteger boundary = 0; boundary < 4; boundary++) {
			if (indices[boundary] != MTLCounterDontSample) {
				samples[sample_count++] = (StelaCounterSampleRecord){
					.buffer = buffer->_handle,
					.index = indices[boundary],
					.boundary = boundary,
				};
			}
		}
	}
	begin.counter_sample_count = (uint32_t)sample_count;
	size_t positions_bytes = begin.sample_position_count * sizeof(positions[0]);
	uint8_t data[sizeof(positions) + sizeof(samples)];
	memcpy(data, positions, positions_bytes);
	memcpy(data + positions_bytes, samples, sample_count * sizeof(samples[0]));
	stela_stream_entry(&_stream, StelaRenderCodeBegin, &begin, sizeof(begin), data,
			   positions_bytes + sample_count * sizeof(samples[0]));
}

@end
