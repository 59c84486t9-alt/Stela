/*
 * Texture view pools. A pool is a shared buffer of one 8-byte word per entry,
 * which holds the resource ID of the entry's view, or zero. An entry's own ID
 * is STELA_POOL_VIEW over its word's address in 8-byte units: the pool's IDs
 * follow baseResourceID one by one and keep naming their entries as views
 * change, as Apple's do. A shader resolves an argument buffer's pool ID to
 * the view's ID by loading the word (`metal_abi.h`).
 */
#include "Bundle.h"

/* Apple7's most entries a pool holds. */
#define VIEW_POOL_MAX_ENTRIES (128ull << 20)
/* metal_abi.h STELA_METAL_POOL_VIEW, in the 64-bit ID. */
#define STELA_POOL_VIEW (1ull << 63)

@implementation StelaGPUTextureViewPool

- (id)device
{
	return _device;
}

- (NSUInteger)resourceViewCount
{
	return _count;
}

- (MTLResourceID)baseResourceID
{
	return (MTLResourceID){STELA_POOL_VIEW | _table->_gpuAddress >> 3};
}

- (MTLResourceID)idAt:(NSUInteger)index
{
	return (MTLResourceID){[self baseResourceID]._impl + index};
}

/* Sets entry `index` to `view`, or empties it for nil, and returns its ID. */
- (MTLResourceID)set:(id)view atIndex:(NSUInteger)index selector:(const char *)selector
{
	if (index >= _count) {
		StelaFailure failure = {.reason = "an index past the pool's views"};
		stela_report(selector, &failure);
		return (MTLResourceID){0};
	}
	os_unfair_lock_lock(&_lock);
	_views[index] = view;
	((uint64_t *)_table->_contents)[index] = view ? [view gpuResourceID]._impl : 0;
	os_unfair_lock_unlock(&_lock);
	return [self idAt:index];
}

- (MTLResourceID)setTextureView:(id)texture atIndex:(NSUInteger)index
{
	return [self set:texture atIndex:index selector:"setTextureView:atIndex:"];
}

- (MTLResourceID)setTextureView:(id)texture descriptor:(id)descriptor atIndex:(NSUInteger)index
{
	id view = texture ? [texture newTextureViewWithDescriptor:descriptor] : nil;
	if (texture && !view)
		return (MTLResourceID){0};
	return [self set:view atIndex:index selector:"setTextureView:descriptor:atIndex:"];
}

- (MTLResourceID)setTextureViewFromBuffer:(id)buffer
			       descriptor:(id)descriptor
				   offset:(NSUInteger)offset
			      bytesPerRow:(NSUInteger)bytesPerRow
				  atIndex:(NSUInteger)index
{
	id view = buffer ? [buffer newTextureWithDescriptor:descriptor offset:offset bytesPerRow:bytesPerRow] : nil;
	if (buffer && !view)
		return (MTLResourceID){0};
	return [self set:view
		   atIndex:index
		  selector:"setTextureViewFromBuffer:descriptor:offset:bytesPerRow:atIndex:"];
}

- (MTLResourceID)copyResourceViewsFromPool:(id)sourcePool
			       sourceRange:(NSRange)sourceRange
			  destinationIndex:(NSUInteger)destinationIndex
{
	StelaGPUTextureViewPool *source = sourcePool;
	if (![source isKindOfClass:[StelaGPUTextureViewPool class]] || sourceRange.location > source->_count ||
	    source->_count - sourceRange.location < sourceRange.length || destinationIndex > _count ||
	    _count - destinationIndex < sourceRange.length) {
		StelaFailure failure = {.reason = "a range past either pool's views"};
		stela_report("copyResourceViewsFromPool:sourceRange:destinationIndex:", &failure);
		return (MTLResourceID){0};
	}
	/* Gather the source's views first: the pools may be one, and their
	 * ranges may overlap. */
	NSUInteger length = sourceRange.length;
	__strong id *views = (__strong id *)calloc(length ?: 1, sizeof(id));
	if (!views)
		return (MTLResourceID){0};
	os_unfair_lock_lock(&source->_lock);
	for (NSUInteger i = 0; i < length; i++)
		views[i] = source->_views[sourceRange.location + i];
	os_unfair_lock_unlock(&source->_lock);
	for (NSUInteger i = 0; i < length; i++)
		[self set:views[i] atIndex:destinationIndex + i selector:"copyResourceViewsFromPool:sourceRange:destinationIndex:"];
	for (NSUInteger i = 0; i < length; i++)
		views[i] = nil;
	free(views);
	return [self idAt:destinationIndex];
}

- (void)dealloc
{
	for (NSUInteger i = 0; i < _count; i++)
		_views[i] = nil;
	free(_views);
}

@end

@implementation StelaGPUDevice (ViewPools)

- (id)newTextureViewPoolWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSUInteger count = [descriptor resourceViewCount];
	const char *reason = "a texture view pool of no views, or more than 128 million";
	StelaGPUBuffer *table = nil;
	__strong id *views = NULL;
	if (count && count <= VIEW_POOL_MAX_ENTRIES) {
		table = [self newBufferWithLength:count * 8 options:MTLStorageModeShared << 4];
		views = (__strong id *)calloc(count, sizeof(id));
		if (!table || !views)
			reason = "no memory for the pool's entries";
	}
	if (!table || !views) {
		free(views);
		StelaFailure failure = {0};
		snprintf(failure.reason, sizeof failure.reason, "%s", reason);
		if (error)
			*error = stela_error(@"MTLResourceViewPoolErrorDomain", 1, &failure);
		return nil;
	}
	memset(table->_contents, 0, count * 8);
	StelaGPUTextureViewPool *pool = [StelaGPUTextureViewPool new];
	pool->_device = self;
	pool->_count = count;
	pool->_table = table;
	pool->_views = views;
	pool->_lock = OS_UNFAIR_LOCK_INIT;
	pool.label = [descriptor label];
	return pool;
}

@end
