/*
 * Events and textures other processes open. A handle crosses as the token the
 * service knows its object by, which any coder carries. A handle keeps its
 * object alive in the task that made it; a token alone holds nothing.
 */
#include "Bundle.h"

typedef struct {
	uint64_t token[2];
	uint64_t registry;
} StelaShare;

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

static BOOL decode_bytes(NSCoder *coder, NSString *key, void *bytes, NSUInteger length)
{
	NSUInteger decoded = 0;
	const uint8_t *from = [coder decodeBytesForKey:key returnedLength:&decoded];
	if (decoded != length) {
		return NO;
	}
	memcpy(bytes, from, length);
	return YES;
}

@interface StelaGPUSharedEventHandle : MTLSharedEventHandle {
@public
	StelaShare _share;
	/* In the task that shared it, the event. */
	id _event;
}
@property(copy) NSString *label;
@end

@implementation StelaGPUSharedEventHandle

+ (BOOL)supportsSecureCoding
{
	return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeBytes:(const uint8_t *)&_share length:sizeof(_share) forKey:@"share"];
	[coder encodeObject:self.label forKey:@"label"];
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
	self = [super init];
	if (self) {
		if (!decode_bytes(coder, @"share", &_share, sizeof(_share))) {
			return nil;
		}
		self.label = [coder decodeObjectOfClass:[NSString class] forKey:@"label"];
	}
	return self;
}

@end

@interface StelaGPUSharedTextureHandle : MTLSharedTextureHandle {
@public
	StelaShare _share;
	StelaTextureDescriptorRecord _record;
	/* In the task that shared it, the texture. */
	id _texture;
}
@property(copy) NSString *label;
@end

@implementation StelaGPUSharedTextureHandle

+ (BOOL)supportsSecureCoding
{
	return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeBytes:(const uint8_t *)&_share length:sizeof(_share) forKey:@"share"];
	[coder encodeBytes:(const uint8_t *)&_record length:sizeof(_record) forKey:@"record"];
	[coder encodeObject:self.label forKey:@"label"];
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
	self = [super init];
	if (self) {
		if (!decode_bytes(coder, @"share", &_share, sizeof(_share))
		    || !decode_bytes(coder, @"record", &_record, sizeof(_record))) {
			return nil;
		}
		self.label = [coder decodeObjectOfClass:[NSString class] forKey:@"label"];
	}
	return self;
}

- (id)device
{
	NSArray *devices = MTLCopyAllDevices();
	for (NSUInteger index = 0; index < devices.count; index++) {
		id device = devices[index];
		if ([device registryID] == _share.registry) {
			return device;
		}
	}
	return nil;
}

@end

@implementation StelaGPUEvent (Shared)

- (id)newSharedEventHandle
{
	StelaGPUSharedEventHandle *handle = [StelaGPUSharedEventHandle new];
	if (!share_object(self, &handle->_share, "newSharedEventHandle")) {
		return nil;
	}
	handle->_event = self;
	handle.label = self.label;
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
	StelaGPUSharedTextureHandle *handle = [StelaGPUSharedTextureHandle new];
	if (!share_object(self, &handle->_share, "newSharedTextureHandle")) {
		return nil;
	}
	handle->_record = _record;
	handle->_texture = self;
	handle.label = self.label;
	return handle;
}

@end

@implementation StelaGPUDevice (Shared)

- (id)newSharedEventWithHandle:(id)handle
{
	StelaFailure failure = {.reason = "that handle is not this device's"};
	if (![handle isKindOfClass:[StelaGPUSharedEventHandle class]]) {
		stela_report("newSharedEventWithHandle:", &failure);
		return nil;
	}
	StelaGPUSharedEventHandle *shared = handle;
	StelaShareToken request = {.token = {shared->_share.token[0], shared->_share.token[1]}};
	StelaHandle response;
	if (STELA_CALL(&_gate, OpenSharedEvent, &request, &response, &failure) != StelaStatusOk) {
		stela_report("newSharedEventWithHandle:", &failure);
		return nil;
	}
	StelaGPUEvent *event = [[StelaGPUEvent alloc] initWithDevice:self handle:response.handle];
	event.label = shared.label;
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
	if (![handle isKindOfClass:[StelaGPUSharedTextureHandle class]]) {
		stela_report("newSharedTextureWithHandle:", &failure);
		return nil;
	}
	StelaGPUSharedTextureHandle *shared = handle;
	StelaShareToken request = {.token = {shared->_share.token[0], shared->_share.token[1]}};
	StelaTextureResponse response;
	if (STELA_CALL(&_gate, OpenSharedTexture, &request, &response, &failure) != StelaStatusOk) {
		stela_report("newSharedTextureWithHandle:", &failure);
		return nil;
	}
	StelaGPUTexture *texture = [[StelaGPUTexture alloc] initWithDevice:self
								  response:&response
								    record:&shared->_record];
	texture->_shareable = YES;
	texture.label = shared.label;
	return texture;
}

@end
