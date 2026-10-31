/*
 * What this device does not offer. Each entry answers as Metal does for a
 * missing feature and reports once; `metal/README.md` says why each is absent.
 */
#include "Bundle.h"

#define REFUSE(what, why)                                                                          \
	do {                                                                                       \
		StelaFailure failure = {.reason = why};                                            \
		stela_report(what, &failure);                                                      \
	} while (0)

#define REFUSE_ERROR(domain, code, why)                                                            \
	do {                                                                                       \
		if (error) {                                                                       \
			StelaFailure failure = {.reason = why};                                    \
			*error = stela_error(domain, code, &failure);                              \
		}                                                                                  \
	} while (0)

#define STITCHING "this device links no stitched function graphs"
#define IO "this device has no Metal I/O queues"
#define RAY_TRACING "this device has no acceleration structures"

@implementation StelaGPUDevice (Refused)

- (id)newRasterizationRateMapWithDescriptor:(id)descriptor
{
	REFUSE("newRasterizationRateMapWithDescriptor:", "this device has no rasterization rate maps");
	return nil;
}

- (MTLAccelerationStructureSizes)accelerationStructureSizesWithDescriptor:(id)descriptor
{
	REFUSE("accelerationStructureSizesWithDescriptor:", RAY_TRACING);
	return (MTLAccelerationStructureSizes){0};
}

- (MTLSizeAndAlign)heapAccelerationStructureSizeAndAlignWithSize:(NSUInteger)size
{
	REFUSE("heapAccelerationStructureSizeAndAlignWithSize:", RAY_TRACING);
	return (MTLSizeAndAlign){0};
}

- (MTLSizeAndAlign)heapAccelerationStructureSizeAndAlignWithDescriptor:(id)descriptor
{
	REFUSE("heapAccelerationStructureSizeAndAlignWithDescriptor:", RAY_TRACING);
	return (MTLSizeAndAlign){0};
}

- (id)newAccelerationStructureWithSize:(NSUInteger)size
{
	REFUSE("newAccelerationStructureWithSize:", RAY_TRACING);
	return nil;
}

- (id)newAccelerationStructureWithDescriptor:(id)descriptor
{
	REFUSE("newAccelerationStructureWithDescriptor:", RAY_TRACING);
	return nil;
}

- (id)newLogStateWithDescriptor:(id)descriptor error:(NSError **)error
{
	REFUSE_ERROR(MTLLogStateErrorDomain, MTLLogStateErrorInvalid, "this device has no shader logging");
	return nil;
}

- (id)newLibraryWithStitchedDescriptor:(id)descriptor error:(NSError **)error
{
	REFUSE_ERROR(MTLLibraryErrorDomain, MTLLibraryErrorUnsupported, STITCHING);
	return nil;
}

- (void)newLibraryWithStitchedDescriptor:(id)descriptor completionHandler:(void (^)(id, NSError *))handler
{
	NSError *error = nil;
	id library = [self newLibraryWithStitchedDescriptor:descriptor error:&error];
	handler(library, error);
}

- (id)newIOHandleWithURL:(NSURL *)url error:(NSError **)error
{
	REFUSE_ERROR(MTLIOErrorDomain, MTLIOErrorInternal, IO);
	return nil;
}

- (id)newIOHandleWithURL:(NSURL *)url compressionMethod:(NSInteger)method error:(NSError **)error
{
	REFUSE_ERROR(MTLIOErrorDomain, MTLIOErrorInternal, IO);
	return nil;
}

- (id)newIOFileHandleWithURL:(NSURL *)url error:(NSError **)error
{
	REFUSE_ERROR(MTLIOErrorDomain, MTLIOErrorInternal, IO);
	return nil;
}

- (id)newIOFileHandleWithURL:(NSURL *)url compressionMethod:(NSInteger)method error:(NSError **)error
{
	REFUSE_ERROR(MTLIOErrorDomain, MTLIOErrorInternal, IO);
	return nil;
}

- (id)newIOCommandQueueWithDescriptor:(id)descriptor error:(NSError **)error
{
	REFUSE_ERROR(MTLIOErrorDomain, MTLIOErrorInternal, IO);
	return nil;
}

@end
