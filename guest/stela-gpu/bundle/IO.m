/*
 * Metal I/O. A command buffer runs its commands in order on a dispatch queue of
 * its command queue's: a load reads its file into memory the CPU reaches and
 * blits from there to what the CPU does not. A concurrent command queue overlaps
 * command buffers, its barriers are dispatch barriers, and a command buffer's
 * own barriers hold by its order. After a failed or cancelled load the other
 * loads are skipped; status copies and events still run, as work on the GPU may
 * wait for them. Metal's container of compressed files is undocumented, so
 * compressed handles are refused.
 */
#include "Bundle.h"

/* The most of a private buffer that one blit carries. */
#define STAGING_BYTES (16u << 20)
#define STAGING_OPTIONS (MTLStorageModeShared << 4)

/* What loads use of Metal's objects. */
@interface NSObject (StelaIO)
- (id)newCommandQueue;
- (id)newBufferWithLength:(NSUInteger)length options:(NSUInteger)options;
- (id)commandBuffer;
- (id)blitCommandEncoder;
- (void)commit;
- (void)waitUntilCompleted;
- (NSUInteger)status;
- (void *)contents;
- (void)didModifyRange:(NSRange)range;
- (void)copyFromBuffer:(id)source
	   sourceOffset:(NSUInteger)sourceOffset
	       toBuffer:(id)destination
      destinationOffset:(NSUInteger)destinationOffset
		   size:(NSUInteger)size;
- (void)copyFromBuffer:(id)source
	     sourceOffset:(NSUInteger)sourceOffset
	sourceBytesPerRow:(NSUInteger)bytesPerRow
      sourceBytesPerImage:(NSUInteger)bytesPerImage
	       sourceSize:(MTLSize)size
		toTexture:(id)destination
	 destinationSlice:(NSUInteger)slice
	 destinationLevel:(NSUInteger)level
	destinationOrigin:(MTLOrigin)origin;
- (BOOL)waitUntilSignaledValue:(uint64_t)value timeoutMS:(uint64_t)milliseconds;
- (void)setSignaledValue:(uint64_t)value;
@end

@class StelaGPUIOCommandBuffer;

typedef void (^StelaIOCommand)(StelaGPUIOCommandBuffer *buffer);

@interface StelaGPUIOFileHandle : NSObject <MTLIOFileHandle> {
@public
	int _file;
}
@property(copy) NSString *label;
@end

@interface StelaGPUIOCommandQueue : NSObject <MTLIOCommandQueue> {
@public
	StelaGPUDevice *_device;
	/* What blits run on. */
	id _copies;
	dispatch_queue_t _queue;
	/* The command buffers still to be created. */
	dispatch_semaphore_t _slots;
}
@property(copy) NSString *label;
- (void)enqueue:(StelaGPUIOCommandBuffer *)buffer;
- (void)flush;
@end

@interface StelaGPUIOCommandBuffer : NSObject <MTLIOCommandBuffer> {
@public
	bool _committed;
}
@property(copy) NSString *label;
- (instancetype)initWithQueue:(StelaGPUIOCommandQueue *)queue;
- (void)run;
@end

static BOOL read_file(StelaGPUIOFileHandle *handle, void *bytes, NSUInteger length, NSUInteger offset)
{
	uint8_t *to = bytes;
	while (length) {
		long count = pread(handle->_file, to, length, offset);
		if (count < 0 && *__error() == EINTR) {
			continue;
		}
		if (count <= 0) {
			return NO;
		}
		to += count;
		offset += count;
		length -= count;
	}
	return YES;
}

/* Commits the blit `encode` encodes and waits for it. */
static BOOL blit(StelaGPUIOCommandQueue *queue, void (^encode)(id encoder))
{
	id commands = [queue->_copies commandBuffer];
	id encoder = [commands blitCommandEncoder];
	encode(encoder);
	[encoder endEncoding];
	[commands commit];
	[commands waitUntilCompleted];
	return [commands status] == MTLCommandBufferStatusCompleted;
}

static BOOL load_private_buffer(StelaGPUIOCommandQueue *queue, id buffer, NSUInteger offset, NSUInteger size,
				StelaGPUIOFileHandle *handle, NSUInteger from)
{
	NSUInteger bytes = size < STAGING_BYTES ? size : STAGING_BYTES;
	id staging = [queue->_device newBufferWithLength:bytes options:STAGING_OPTIONS];
	if (!staging) {
		return NO;
	}
	for (NSUInteger done = 0; done < size; done += bytes) {
		bytes = size - done < STAGING_BYTES ? size - done : STAGING_BYTES;
		if (!read_file(handle, [staging contents], bytes, from + done)
		    || !blit(queue, ^(id encoder) {
			       [encoder copyFromBuffer:staging
					  sourceOffset:0
					      toBuffer:buffer
				     destinationOffset:offset + done
						  size:bytes];
		       })) {
			return NO;
		}
	}
	return YES;
}

@implementation StelaGPUIOFileHandle

- (void)dealloc
{
	close(_file);
}

@end

@implementation StelaGPUIOCommandQueue {
	os_unfair_lock _lock;
	/* Enqueued command buffers, which run in this order, and barriers as the queue itself. */
	NSMutableArray *_enqueued;
}

- (instancetype)initWithDevice:(StelaGPUDevice *)device descriptor:(id)descriptor
{
	self = [super init];
	if (self) {
		_device = device;
		_copies = [device newCommandQueue];
		_lock = OS_UNFAIR_LOCK_INIT;
		_enqueued = [NSMutableArray arrayWithCapacity:16];
		_slots = dispatch_semaphore_create([descriptor maxCommandBufferCount]);
		static const unsigned classes[] = {[MTLIOPriorityHigh] = QOS_CLASS_USER_INITIATED,
						   [MTLIOPriorityNormal] = QOS_CLASS_DEFAULT,
						   [MTLIOPriorityLow] = QOS_CLASS_UTILITY};
		dispatch_queue_attr_t order
		    = [descriptor type] == MTLIOCommandQueueTypeSerial ? NULL : DISPATCH_QUEUE_CONCURRENT;
		_queue = dispatch_queue_create(
		    "StelaGPU.io", dispatch_queue_attr_make_with_qos_class(order, classes[[descriptor priority]], 0));
	}
	return self;
}

- (void)dealloc
{
	dispatch_release(_slots);
	dispatch_release(_queue);
}

- (id)commandBuffer
{
	dispatch_semaphore_wait(_slots, DISPATCH_TIME_FOREVER);
	return [[StelaGPUIOCommandBuffer alloc] initWithQueue:self];
}

- (id)commandBufferWithUnretainedReferences
{
	return [self commandBuffer];
}

- (void)enqueueBarrier
{
	os_unfair_lock_lock(&_lock);
	[_enqueued addObject:self];
	os_unfair_lock_unlock(&_lock);
	[self flush];
}

- (void)enqueue:(StelaGPUIOCommandBuffer *)buffer
{
	os_unfair_lock_lock(&_lock);
	[_enqueued addObject:buffer];
	os_unfair_lock_unlock(&_lock);
}

/* Starts what is enqueued and ready, from the first. */
- (void)flush
{
	os_unfair_lock_lock(&_lock);
	while (_enqueued.count) {
		id first = [_enqueued objectAtIndex:0];
		if (first == self) {
			dispatch_barrier_async(_queue, ^{
			});
		} else {
			StelaGPUIOCommandBuffer *buffer = first;
			if (!buffer->_committed) {
				break;
			}
			dispatch_async(_queue, ^{
				[buffer run];
			});
		}
		[_enqueued removeObjectAtIndex:0];
	}
	os_unfair_lock_unlock(&_lock);
}

@end

@implementation StelaGPUIOCommandBuffer {
	StelaGPUIOCommandQueue *_queue;
	NSMutableArray *_commands, *_completedHandlers;
	dispatch_group_t _completion;
	NSError *_error;
	/* How the loads so far went, while nothing has failed `MTLIOStatusPending`. */
	NSInteger _outcome;
	_Atomic(NSInteger) _status;
	_Atomic(bool) _cancelled, _slotFree;
	bool _enqueued;
}

- (instancetype)initWithQueue:(StelaGPUIOCommandQueue *)queue
{
	self = [super init];
	if (self) {
		_queue = queue;
		_commands = [NSMutableArray arrayWithCapacity:16];
		_completedHandlers = [NSMutableArray arrayWithCapacity:2];
		_completion = dispatch_group_create();
		_outcome = MTLIOStatusPending;
		_status = MTLIOStatusPending;
		dispatch_group_enter(_completion);
	}
	return self;
}

- (void)dealloc
{
	[self freeSlot];
	dispatch_release(_completion);
}

- (void)freeSlot
{
	if (!__c11_atomic_exchange(&_slotFree, true, __ATOMIC_SEQ_CST)) {
		dispatch_semaphore_signal(_queue->_slots);
	}
}

- (NSUInteger)status
{
	return _status;
}

- (NSError *)error
{
	return _error;
}

- (void)addCompletedHandler:(void (^)(id))handler
{
	[_completedHandlers addObject:[handler copy]];
}

- (void)addCommand:(StelaIOCommand)command
{
	[_commands addObject:[command copy]];
}

/* The command of `load`, which answers whether it worked. */
- (void)addLoad:(BOOL (^)(void))load
{
	[self addCommand:^(StelaGPUIOCommandBuffer *buffer) {
		if (buffer->_cancelled && buffer->_outcome == MTLIOStatusPending) {
			buffer->_outcome = MTLIOStatusCancelled;
		}
		if (buffer->_outcome == MTLIOStatusPending && !load()) {
			StelaFailure failure = {.reason = "a load could not read its file or fill its resource"};
			buffer->_outcome = MTLIOStatusError;
			buffer->_error = stela_error(MTLIOErrorDomain, MTLIOErrorInternal, &failure);
		}
	}];
}

- (void)loadBytes:(void *)bytes
	      size:(NSUInteger)size
      sourceHandle:(StelaGPUIOFileHandle *)handle
sourceHandleOffset:(NSUInteger)from
{
	[self addLoad:^BOOL {
		return read_file(handle, bytes, size, from);
	}];
}

- (void)loadBuffer:(id)buffer
	    offset:(NSUInteger)offset
	      size:(NSUInteger)size
      sourceHandle:(StelaGPUIOFileHandle *)handle
sourceHandleOffset:(NSUInteger)from
{
	StelaGPUIOCommandQueue *queue = _queue;
	[self addLoad:^BOOL {
		NSUInteger storage = [buffer storageMode];
		if (storage == MTLStorageModePrivate) {
			return load_private_buffer(queue, buffer, offset, size, handle, from);
		}
		if (!read_file(handle, (uint8_t *)[buffer contents] + offset, size, from)) {
			return NO;
		}
		if (storage == MTLStorageModeManaged) {
			[buffer didModifyRange:(NSRange){offset, size}];
		}
		return YES;
	}];
}

/* The service keeps every texture where only a copy reaches it. */
- (void)loadTexture:(id)texture
		  slice:(NSUInteger)slice
		  level:(NSUInteger)level
		   size:(MTLSize)size
      sourceBytesPerRow:(NSUInteger)bytesPerRow
    sourceBytesPerImage:(NSUInteger)bytesPerImage
      destinationOrigin:(MTLOrigin)origin
	   sourceHandle:(StelaGPUIOFileHandle *)handle
     sourceHandleOffset:(NSUInteger)from
{
	StelaGPUIOCommandQueue *queue = _queue;
	[self addLoad:^BOOL {
		NSUInteger length = bytesPerImage * size.depth;
		id staging = [queue->_device newBufferWithLength:length options:STAGING_OPTIONS];
		if (!staging || !read_file(handle, [staging contents], length, from)) {
			return NO;
		}
		return blit(queue, ^(id encoder) {
			[encoder copyFromBuffer:staging
				   sourceOffset:0
			      sourceBytesPerRow:bytesPerRow
			    sourceBytesPerImage:bytesPerImage
				     sourceSize:size
				      toTexture:texture
			       destinationSlice:slice
			       destinationLevel:level
			      destinationOrigin:origin];
		});
	}];
}

/* What a command before this one left, as `status` would answer once done. */
- (void)copyStatusToBuffer:(id)target offset:(NSUInteger)offset
{
	[self addCommand:^(StelaGPUIOCommandBuffer *buffer) {
		NSInteger status = buffer->_outcome == MTLIOStatusPending ? MTLIOStatusComplete : buffer->_outcome;
		memcpy((uint8_t *)[target contents] + offset, &status, sizeof(status));
	}];
}

- (void)waitForEvent:(id)event value:(uint64_t)value
{
	[self addCommand:^(StelaGPUIOCommandBuffer *buffer) {
		[event waitUntilSignaledValue:value timeoutMS:UINT64_MAX];
	}];
}

- (void)signalEvent:(id)event value:(uint64_t)value
{
	[self addCommand:^(StelaGPUIOCommandBuffer *buffer) {
		[event setSignaledValue:value];
	}];
}

/* Commands already run in order. */
- (void)addBarrier
{
}

- (void)pushDebugGroup:(NSString *)name
{
}

- (void)popDebugGroup
{
}

- (void)enqueue
{
	if (!_enqueued) {
		_enqueued = true;
		[_queue enqueue:self];
	}
}

- (void)commit
{
	[self enqueue];
	_committed = true;
	[_queue flush];
}

- (void)tryCancel
{
	_cancelled = true;
}

- (void)waitUntilCompleted
{
	dispatch_group_wait(_completion, DISPATCH_TIME_FOREVER);
}

- (void)run
{
	for (NSUInteger index = 0; index < _commands.count; index++) {
		StelaIOCommand command = [_commands objectAtIndex:index];
		command(self);
	}
	_commands = nil;
	_status = _outcome == MTLIOStatusPending ? MTLIOStatusComplete : _outcome;
	for (NSUInteger index = 0; index < _completedHandlers.count; index++) {
		void (^handler)(id) = [_completedHandlers objectAtIndex:index];
		handler(self);
	}
	_completedHandlers = nil;
	dispatch_group_leave(_completion);
	[self freeSlot];
}

@end

@implementation StelaGPUDevice (IO)

- (id)newIOFileHandleWithURL:(NSURL *)url error:(NSError **)error
{
	int file = open(url.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
	if (file < 0) {
		if (error) {
			StelaFailure failure = {.reason = "that file cannot be opened"};
			*error = stela_error(MTLIOErrorDomain, MTLIOErrorURLInvalid, &failure);
		}
		return nil;
	}
	StelaGPUIOFileHandle *handle = [StelaGPUIOFileHandle new];
	handle->_file = file;
	return handle;
}

- (id)newIOFileHandleWithURL:(NSURL *)url compressionMethod:(NSInteger)method error:(NSError **)error
{
	if (error) {
		StelaFailure failure = {.reason = "this device reads no compressed Metal I/O files"};
		*error = stela_error(MTLIOErrorDomain, MTLIOErrorInternal, &failure);
	}
	return nil;
}

- (id)newIOHandleWithURL:(NSURL *)url error:(NSError **)error
{
	return [self newIOFileHandleWithURL:url error:error];
}

- (id)newIOHandleWithURL:(NSURL *)url compressionMethod:(NSInteger)method error:(NSError **)error
{
	return [self newIOFileHandleWithURL:url compressionMethod:method error:error];
}

- (id)newIOCommandQueueWithDescriptor:(id)descriptor error:(NSError **)error
{
	if ([descriptor maxCommandBufferCount] == 0 || (NSUInteger)[descriptor priority] > MTLIOPriorityLow) {
		if (error) {
			StelaFailure failure = {.reason = "a queue needs command buffers and a priority of Metal's"};
			*error = stela_error(MTLIOErrorDomain, MTLIOErrorInternal, &failure);
		}
		return nil;
	}
	return [[StelaGPUIOCommandQueue alloc] initWithDevice:self descriptor:descriptor];
}

@end
