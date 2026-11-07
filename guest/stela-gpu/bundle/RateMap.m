/*
 * Rasterization rate maps. A map's layers ask for at least the quality their
 * samples give, which Metal may round up; this device renders every region
 * at full quality, so a map's physical size is its screen size and its
 * mappings are the identity. Its parameter data, which shaders' decoders
 * read, holds each layer's mapping as a scale and offset per axis.
 */
#include "Bundle.h"

/* Apple's sizes, which applications allocate and align parameter buffers by,
 * and the granularity its maps change at. */
#define RATE_MAP_PARAMETER_BYTES 24624u
#define RATE_MAP_PARAMETER_ALIGNMENT 4u
#define RATE_MAP_GRANULARITY 32u
/* The layers a map holds, as Apple's do. */
#define RATE_MAP_LAYERS 2u

@implementation StelaGPURateMap

- (id)device
{
	return _device;
}

- (MTLSize)screenSize
{
	return _screenSize;
}

- (MTLSize)physicalGranularity
{
	return (MTLSize){RATE_MAP_GRANULARITY, RATE_MAP_GRANULARITY, 1};
}

- (NSUInteger)layerCount
{
	return _layerCount;
}

- (MTLSizeAndAlign)parameterBufferSizeAndAlign
{
	return (MTLSizeAndAlign){RATE_MAP_PARAMETER_BYTES, RATE_MAP_PARAMETER_ALIGNMENT};
}

- (MTLSizeAndAlign)parameterDataSizeAndAlign
{
	return [self parameterBufferSizeAndAlign];
}

/* Per layer: the horizontal scale and offset, then the vertical, from screen
 * to physical coordinates. The decoders' lowering reads this layout. */
- (void)copyParameterDataToBuffer:(id)buffer offset:(NSUInteger)offset
{
	StelaGPUBuffer *target = buffer;
	if (![target isKindOfClass:[StelaGPUBuffer class]] || !target->_contents ||
	    offset > target->_length || target->_length - offset < RATE_MAP_PARAMETER_BYTES) {
		StelaFailure failure = {.reason = "a parameter buffer the CPU cannot write, or too small"};
		stela_report("copyParameterDataToBuffer:offset:", &failure);
		return;
	}
	float *data = (float *)((uint8_t *)target->_contents + offset);
	memset(data, 0, RATE_MAP_PARAMETER_BYTES);
	for (NSUInteger layer = 0; layer < RATE_MAP_LAYERS; layer++) {
		data[layer * 4 + 0] = 1.0f;
		data[layer * 4 + 2] = 1.0f;
	}
}

- (MTLSize)physicalSizeForLayer:(NSUInteger)layerIndex
{
	if (layerIndex >= _layerCount)
		return (MTLSize){0, 0, 0};
	return (MTLSize){_screenSize.width, _screenSize.height, 1};
}

- (MTLCoordinate2D)mapScreenToPhysicalCoordinates:(MTLCoordinate2D)screenCoordinates forLayer:(NSUInteger)layerIndex
{
	(void)layerIndex;
	return screenCoordinates;
}

- (MTLCoordinate2D)mapPhysicalToScreenCoordinates:(MTLCoordinate2D)physicalCoordinates forLayer:(NSUInteger)layerIndex
{
	(void)layerIndex;
	return physicalCoordinates;
}

@end

@implementation StelaGPUDevice (RateMaps)

- (BOOL)supportsRasterizationRateMapWithLayerCount:(NSUInteger)count
{
	return count != 0 && count <= RATE_MAP_LAYERS;
}

- (id)newRasterizationRateMapWithDescriptor:(id)descriptor
{
	if (!descriptor)
		return nil;
	MTLSize screen = [descriptor screenSize];
	NSUInteger layers = [descriptor layerCount];
	if (layers > RATE_MAP_LAYERS) {
		StelaFailure failure = {.reason = "a rate map holds at most two layers"};
		stela_report("newRasterizationRateMapWithDescriptor:", &failure);
		return nil;
	}
	StelaGPURateMap *map = [StelaGPURateMap new];
	map->_device = self;
	map->_screenSize = (MTLSize){screen.width, screen.height, 1};
	map->_layerCount = layers;
	map.label = [descriptor label];
	return map;
}

@end
