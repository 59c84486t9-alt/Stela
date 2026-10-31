/*
 * `MTLResidencySet`. Whatever a task holds stays resident for as long as it
 * exists, so a set keeps only what its accessors answer.
 */
#include "Bundle.h"

@interface StelaGPUResidencySet : NSObject <MTLResidencySet>
@property(copy) NSString *label;
@end

@implementation StelaGPUResidencySet {
	StelaGPUDevice *_device;
	NSMutableSet *_allocations;
}

- (instancetype)initWithDevice:(StelaGPUDevice *)device capacity:(NSUInteger)capacity
{
	self = [super init];
	if (self) {
		_device = device;
		_allocations = [NSMutableSet setWithCapacity:capacity];
	}
	return self;
}

- (id)device
{
	return _device;
}

- (NSUInteger)allocatedSize
{
	NSArray *allocations = _allocations.allObjects;
	NSUInteger size = 0;
	for (NSUInteger i = 0; i < allocations.count; i++) {
		size += [allocations[i] allocatedSize];
	}
	return size;
}

- (void)requestResidency
{
}

- (void)endResidency
{
}

- (void)commit
{
}

- (void)addAllocation:(id)allocation
{
	[_allocations addObject:allocation];
}

- (void)addAllocations:(const id __unsafe_unretained[])allocations count:(NSUInteger)count
{
	for (NSUInteger i = 0; i < count; i++) {
		[_allocations addObject:allocations[i]];
	}
}

- (void)removeAllocation:(id)allocation
{
	[_allocations removeObject:allocation];
}

- (void)removeAllocations:(const id __unsafe_unretained[])allocations count:(NSUInteger)count
{
	for (NSUInteger i = 0; i < count; i++) {
		[_allocations removeObject:allocations[i]];
	}
}

- (void)removeAllAllocations
{
	[_allocations removeAllObjects];
}

- (BOOL)containsAllocation:(id)allocation
{
	return [_allocations containsObject:allocation];
}

- (NSArray *)allAllocations
{
	return _allocations.allObjects;
}

- (NSUInteger)allocationCount
{
	return _allocations.count;
}

@end

@implementation StelaGPUDevice (Residency)

- (id)newResidencySetWithDescriptor:(id)descriptor error:(NSError **)error
{
	(void)error;
	StelaGPUResidencySet *set = [[StelaGPUResidencySet alloc] initWithDevice:self
								       capacity:[descriptor initialCapacity]];
	set.label = [descriptor label];
	return set;
}

@end
