/* What Metal's private SPI asks of a driver that has a real answer here. */
#include "Bundle.h"

@interface NSObject (StelaSPI)
- (void)commit;
- (void)waitUntilScheduled;
- (void)encodeSignalEvent:(id)event value:(uint64_t)value;
- (void)setFragmentTexture:(id)texture atIndex:(NSUInteger)index;
- (void)setFragmentSamplerState:(id)sampler atIndex:(NSUInteger)index;
- (void)setDepthClipMode:(NSUInteger)mode;
- (NSUInteger)resourceOptions;
@end

@implementation StelaGPUQueue (SPI)

/* Every queue here executes what it is given. */
- (BOOL)executionEnabled
{
	return YES;
}

/* A commit runs on its caller, with no queue of its own to replace. */
- (void)setSubmissionQueue:(id)queue
{
}

/* Every queue here runs at the device's one priority. */
- (BOOL)setGPUPriority:(NSUInteger)priority
{
	return YES;
}

@end

@implementation StelaGPUCommandBuffer (SPI)

/* The device has no deadlines: work runs as it arrives. */
- (void)commitWithDeadline:(uint64_t)deadline
{
	[(id)self commit];
}

- (BOOL)commitAndWaitUntilSubmitted
{
	[(id)self commit];
	[(id)self waitUntilScheduled];
	return YES;
}

- (BOOL)commitAndWaitUntilSubmittedWithDeadline:(uint64_t)deadline
{
	return [self commitAndWaitUntilSubmitted];
}

/* Every agent sees a signal the device makes. */
- (void)encodeSignalEvent:(id)event value:(uint64_t)value agentMask:(uint64_t)mask
{
	[(id)self encodeSignalEvent:event value:value];
}

@end

@implementation StelaGPUResource (SPI)

/* Work on a resource finishes with its command buffer, which callers wait on. */
- (BOOL)isComplete
{
	return YES;
}

- (BOOL)isWriteComplete
{
	return YES;
}

- (NSUInteger)unfilteredResourceOptions
{
	return [(id)self resourceOptions];
}

/* No memory here is protected. */
- (NSUInteger)protectionOptions
{
	return 0;
}

@end

@implementation StelaGPURenderEncoder (SPI)

- (void)setDepthClipModeSPI:(NSUInteger)mode
{
	[(id)self setDepthClipMode:mode];
}

- (void)setFragmentTexture:(id)texture
	    atTextureIndex:(NSUInteger)textureIndex
	      samplerState:(id)sampler
	    atSamplerIndex:(NSUInteger)samplerIndex
{
	[(id)self setFragmentTexture:texture atIndex:textureIndex];
	[(id)self setFragmentSamplerState:sampler atIndex:samplerIndex];
}

@end
