/*
 * Events and textures other processes open. A handle is Metal's own class, as
 * Apple's drivers' handles are, so a process decodes one before it loads any
 * driver: a texture's wraps an IOSurface, and an event's the port of its
 * kernel IOSurface event, which a process opening it shares through a twin.
 * A texture's surface carries, in its creation properties, the token the
 * service knows the texture by, beside the registry ID and texture properties
 * Metal's handle and Apple's drivers record there. A handle keeps its object
 * alive in the task that made it; a token alone holds nothing.
 */
#include "Bundle.h"

typedef struct {
	uint64_t token[2];
	uint64_t registry;
} StelaShare;

/* What Metal's handles hold that this device reads back. */
@interface MTLSharedTextureHandle (Stela)
- (instancetype)initWithIOSurface:(IOSurfaceRef)surface label:(NSString *)label;
- (IOSurfaceRef)ioSurface;
- (NSString *)label;
@end

@interface MTLSharedEventHandle (Stela)
- (instancetype)initWithSharedEvent:(id)event;
- (mach_port_t)eventPort;
- (NSString *)label;
@end

/* The creation property holding a share, and a texture's descriptor. */
#define SHARE_KEY @"StelaGPUShare"
#define RECORD_KEY @"StelaGPUTextureRecord"

/* The object a handle keeps alive, by association. */
static char shared_object;

static BOOL share_object(StelaGPUObject *object, StelaShare *share, const char *what)
{
	StelaShareObjectRequest request = {.handle = object->_handle};
	arc4random_buf(request.token, sizeof(request.token));
	StelaShareToken response;
	StelaFailure failure;
	if (STELA_CALL(&object->_device->_gate, ShareObject, &request, &response, &failure) != StelaStatusOk) {
		stela_report(what, &failure);
		return NO;
	}
	*share = (StelaShare){
		.token = {response.token[0], response.token[1]},
		.registry = [object->_device registryID],
	};
	return YES;
}

static NSNumber *number(uint64_t value)
{
	return [NSNumber numberWithUnsignedLongLong:value];
}

/* A surface of no texels carrying a share, and a texture's descriptor as
 * Apple's drivers record a shared texture's. */
static IOSurfaceRef carrier(const StelaShare *share, const StelaTextureDescriptorRecord *record, const char *what)
{
	NSMutableDictionary *properties = [NSMutableDictionary dictionary];
	[properties setObject:number(1) forKey:@"IOSurfaceAllocSize"];
	[properties setObject:@"Metal" forKey:@"IOSurfaceName"];
	[properties setObject:number(share->registry) forKey:@"kMetalRegistryID"];
	[properties setObject:[NSData dataWithBytes:share length:sizeof(*share)] forKey:SHARE_KEY];
	if (record) {
		[properties setObject:[NSData dataWithBytes:record length:sizeof(*record)] forKey:RECORD_KEY];
		[properties setObject:number(record->texture_type) forKey:@"kMetalTextureType"];
		[properties setObject:number(record->pixel_format) forKey:@"kMetalTexturePixelFormat"];
		[properties setObject:number(record->width) forKey:@"kMetalTextureWidth"];
		[properties setObject:number(record->height) forKey:@"kMetalTextureHeight"];
		[properties setObject:number(record->depth) forKey:@"kMetalTextureDepth"];
		[properties setObject:number(record->mipmap_level_count) forKey:@"kMetalTextureMipmapLevelCount"];
		[properties setObject:number(record->array_length) forKey:@"kMetalTextureArrayLength"];
		[properties setObject:number(record->sample_count) forKey:@"kMetalTextureSampleCount"];
		[properties setObject:number(record->usage) forKey:@"kMetalTextureUsage"];
		[properties setObject:number(record->options) forKey:@"kMetalTextureResourceOptions"];
	}
	IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)properties);
	if (!surface) {
		StelaFailure failure = {.reason = "IOSurface refused the surface carrying the share"};
		stela_report(what, &failure);
	}
	return surface;
}

/* The bytes of key a carrier surface was created with, exactly length of
 * them. */
static BOOL carried(IOSurfaceRef surface, NSString *key, void *bytes, NSUInteger length)
{
	if (!surface) {
		return NO;
	}
	NSDictionary *creation =
		(__bridge_transfer NSDictionary *)IOSurfaceCopyValue(surface, (__bridge CFStringRef)@"CreationProperties");
	id value = [creation objectForKey:key];
	if (![value isKindOfClass:[NSData class]] || [value length] != length) {
		return NO;
	}
	memcpy(bytes, [value bytes], length);
	return YES;
}

@implementation StelaGPUEvent (Shared)

/* Metal's handle holds the kernel event's port, as Apple's does. */
- (id)newSharedEventHandle
{
	MTLSharedEventHandle *handle = [[MTLSharedEventHandle alloc] initWithSharedEvent:self];
	if (handle) {
		objc_setAssociatedObject(handle, &shared_object, self, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
	}
	return handle;
}

@end

@implementation StelaGPUTexture (Shared)

- (id)newSharedTextureHandle
{
	if (!_shareable) {
		StelaFailure failure = {.reason = "this texture is not shareable"};
		stela_report("newSharedTextureHandle", &failure);
		return nil;
	}
	StelaShare share;
	if (!share_object(self, &share, "newSharedTextureHandle")) {
		return nil;
	}
	IOSurfaceRef surface = carrier(&share, &_record, "newSharedTextureHandle");
	if (!surface) {
		return nil;
	}
	MTLSharedTextureHandle *handle = [[MTLSharedTextureHandle alloc] initWithIOSurface:surface label:self.label];
	CFRelease(surface);
	if (handle) {
		objc_setAssociatedObject(handle, &shared_object, self, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
	}
	return handle;
}

@end

@implementation StelaGPUDevice (Shared)

/* Any process's event handle: a twin on the kernel event its port names. */
- (id)newSharedEventWithHandle:(id)handle
{
	if (![handle isKindOfClass:[MTLSharedEventHandle class]]) {
		StelaFailure failure = {.reason = "not an event handle"};
		stela_report("newSharedEventWithHandle:", &failure);
		return nil;
	}
	StelaGPUEvent *event = [self newSharedEventWithMachPort:[handle eventPort]];
	event.label = [handle label];
	return event;
}

- (id)newSharedTextureWithDescriptor:(id)descriptor
{
	if ([descriptor storageMode] != MTLStorageModePrivate) {
		StelaFailure failure = {.reason = "a shareable texture has private storage"};
		stela_report("newSharedTextureWithDescriptor:", &failure);
		return nil;
	}
	StelaGPUTexture *texture = [self newTextureWithDescriptor:descriptor];
	if (texture) {
		texture->_shareable = YES;
	}
	return texture;
}

- (id)newSharedTextureWithHandle:(id)handle
{
	StelaFailure failure = {.reason = "that handle is not this device's"};
	StelaShare share;
	StelaTextureDescriptorRecord record;
	IOSurfaceRef surface = [handle isKindOfClass:[MTLSharedTextureHandle class]] ? [handle ioSurface] : NULL;
	if (!carried(surface, SHARE_KEY, &share, sizeof(share)) || !carried(surface, RECORD_KEY, &record, sizeof(record))
	    || share.registry != [self registryID]) {
		stela_report("newSharedTextureWithHandle:", &failure);
		return nil;
	}
	StelaShareToken request = {.token = {share.token[0], share.token[1]}};
	StelaTextureResponse response;
	if (STELA_CALL(&_gate, OpenSharedTexture, &request, &response, &failure) != StelaStatusOk) {
		stela_report("newSharedTextureWithHandle:", &failure);
		return nil;
	}
	StelaGPUTexture *texture = [[StelaGPUTexture alloc] initWithDevice:self
								  response:&response
								    record:&record];
	texture->_shareable = YES;
	texture.label = [handle label];
	return texture;
}

@end
