/*
 * What the bundle uses of macOS, declared here since no SDK takes part in the
 * build. Values are the public headers'; classes and selectors exist in the
 * running system, which the Objective-C runtime resolves by name.
 */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef bool BOOL;
#define YES true
#define NO false
#define nil ((id)0)

typedef unsigned long NSUInteger;
typedef long NSInteger;
typedef double CFTimeInterval;
typedef unsigned int mach_port_t;
typedef unsigned int io_object_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_service_t;
typedef int kern_return_t;
typedef mach_port_t task_t;
typedef unsigned long long mach_vm_address_t;
typedef unsigned long long mach_vm_size_t;
typedef struct IONotificationPort *IONotificationPortRef;
typedef struct dispatch_queue_s *dispatch_queue_t;
typedef struct dispatch_data_s *dispatch_data_t;
typedef struct dispatch_group_s *dispatch_group_t;
typedef const void *CFTypeRef;
typedef struct __IOSurface *IOSurfaceRef;
typedef const struct __CFString *CFStringRef;
typedef const struct objc_method *Method;
typedef void (*IMP)(void);

struct NSRange {
	NSUInteger location, length;
};
typedef struct NSRange NSRange;

/* Foundation. */
@class NSError, NSURL;

__attribute__((objc_root_class)) @interface NSObject
+ (instancetype)alloc;
- (instancetype)init;
+ (instancetype)new;
- (void)dealloc;
- (BOOL)conformsToProtocol:(id)protocol;
- (Class)class;
- (id)copy;
@end

@interface NSString : NSObject
+ (instancetype)stringWithUTF8String:(const char *)text;
+ (instancetype)stringWithFormat:(NSString *)format, ...;
- (BOOL)isEqualToString:(NSString *)other;
- (instancetype)initWithBytes:(const void *)bytes length:(NSUInteger)length encoding:(NSUInteger)encoding;
@property(readonly) const char *UTF8String;
@property(readonly) NSUInteger length;
@end

#define NSUTF8StringEncoding 4

@interface NSArray : NSObject
+ (instancetype)array;
+ (instancetype)arrayWithObjects:(const id __unsafe_unretained[])objects count:(NSUInteger)count;
- (id)objectAtIndexedSubscript:(NSUInteger)index;
- (id)objectAtIndex:(NSUInteger)index;
@property(readonly) NSUInteger count;
@end

@interface NSMutableArray : NSArray
+ (instancetype)arrayWithCapacity:(NSUInteger)capacity;
- (void)addObject:(id)object;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)removeAllObjects;
@end

@interface NSDictionary : NSObject
+ (instancetype)dictionaryWithObjects:(const id __unsafe_unretained[])objects
			      forKeys:(const id __unsafe_unretained[])keys
				count:(NSUInteger)count;
- (id)objectForKey:(id)key;
- (id)objectForKeyedSubscript:(id)key;
@property(readonly) NSUInteger count;
@end

@interface NSMutableDictionary : NSDictionary
+ (instancetype)dictionary;
- (void)setObject:(id)object forKey:(id)key;
@end

@interface NSValue : NSObject
+ (instancetype)valueWithNonretainedObject:(id)object;
@property(readonly) id nonretainedObjectValue;
@end

@interface NSError : NSObject
+ (instancetype)errorWithDomain:(NSString *)domain code:(NSInteger)code userInfo:(NSDictionary *)information;
@property(readonly) NSDictionary *userInfo;
@end

enum {
	NSDataWritingAtomic = 1,
};

@interface NSData : NSObject
+ (instancetype)dataWithBytes:(const void *)bytes length:(NSUInteger)length;
+ (instancetype)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length freeWhenDone:(BOOL)free;
+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSUInteger)options error:(NSError **)error;
+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSUInteger)options error:(NSError **)error;
- (BOOL)writeToURL:(NSURL *)url options:(NSUInteger)options error:(NSError **)error;
@property(readonly) const void *bytes;
@property(readonly) NSUInteger length;
@end

@interface NSMutableData : NSData
+ (instancetype)dataWithLength:(NSUInteger)length;
- (void)appendBytes:(const void *)bytes length:(NSUInteger)length;
@property(readonly) void *mutableBytes;
@end

@interface NSBundle : NSObject
+ (instancetype)mainBundle;
@end

@interface NSURL : NSObject
@property(readonly) const char *fileSystemRepresentation;
@end

extern NSString *const NSLocalizedDescriptionKey;
void NSLog(NSString *format, ...);
Class NSClassFromString(NSString *name);

/* The Objective-C runtime. */
#define OBJC_ASSOCIATION_RETAIN 01401
Method class_getInstanceMethod(Class class, SEL selector);
IMP method_getImplementation(Method method);
IMP method_setImplementation(Method method, IMP implementation);
IMP imp_implementationWithBlock(id block);
id objc_getAssociatedObject(id object, const void *key);
void objc_setAssociatedObject(id object, const void *key, id value, uintptr_t policy);

/* libsystem, IOKit and libdispatch. */
extern mach_port_t mach_task_self_;
#define mach_task_self() mach_task_self_
#define KERN_SUCCESS 0
#define VM_FLAGS_ANYWHERE 1
#define kIOReturnSuccess 0
#define kIOMapAnywhere 1u
#define kIOMapDefaultCache 0u
#define kIOAsyncCalloutCount 8

typedef void (*IOAsyncCallback1)(void *reference, int result, void *argument);
typedef void (*IOAsyncCallback)(void *reference, int result, void **arguments, uint32_t count);

kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t IOServiceOpen(io_service_t service, task_t owner, uint32_t type, io_connect_t *connect);
kern_return_t IOServiceClose(io_connect_t connect);
kern_return_t IOConnectMapMemory64(io_connect_t connect, uint32_t type, task_t task,
				   mach_vm_address_t *address, mach_vm_size_t *size, uint32_t options);
kern_return_t IOConnectUnmapMemory64(io_connect_t connect, uint32_t type, task_t task, mach_vm_address_t address);
kern_return_t IOConnectCallScalarMethod(io_connect_t connect, uint32_t selector, const uint64_t *input,
					uint32_t inputs, uint64_t *output, uint32_t *outputs);
kern_return_t IOConnectCallAsyncScalarMethod(io_connect_t connect, uint32_t selector, mach_port_t port,
					     uint64_t *reference, uint32_t references,
					     const uint64_t *input, uint32_t inputs, uint64_t *output,
					     uint32_t *outputs);
kern_return_t IOObjectRetain(io_object_t object);
kern_return_t IOObjectRelease(io_object_t object);
CFTypeRef IORegistryEntryCreateCFProperty(io_service_t entry, CFStringRef key, const void *allocator, uint32_t options);
kern_return_t IORegistryEntryGetRegistryEntryID(io_service_t entry, uint64_t *identifier);
IONotificationPortRef IONotificationPortCreate(mach_port_t main);
mach_port_t IONotificationPortGetMachPort(IONotificationPortRef port);
void IONotificationPortSetDispatchQueue(IONotificationPortRef port, dispatch_queue_t queue);
void IONotificationPortDestroy(IONotificationPortRef port);
extern const mach_port_t kIOMainPortDefault;

CFTypeRef CFRetain(CFTypeRef object);
void CFRelease(CFTypeRef object);
kern_return_t IOSurfaceLock(IOSurfaceRef surface, uint32_t options, uint32_t *seed);
kern_return_t IOSurfaceUnlock(IOSurfaceRef surface, uint32_t options, uint32_t *seed);
void *IOSurfaceGetBaseAddress(IOSurfaceRef surface);
void *IOSurfaceGetBaseAddressOfPlane(IOSurfaceRef surface, size_t plane);
size_t IOSurfaceGetBytesPerRowOfPlane(IOSurfaceRef surface, size_t plane);
size_t IOSurfaceGetAllocSize(IOSurfaceRef surface);

#define DISPATCH_TIME_FOREVER (~0ull)
dispatch_queue_t dispatch_queue_create(const char *label, const void *attributes);
dispatch_queue_t dispatch_get_global_queue(long priority, unsigned long flags);
dispatch_group_t dispatch_group_create(void);
void dispatch_group_enter(dispatch_group_t group);
void dispatch_group_leave(dispatch_group_t group);
long dispatch_group_wait(dispatch_group_t group, uint64_t timeout);
void dispatch_release(void *object);
void dispatch_async(dispatch_queue_t queue, void (^block)(void));
dispatch_data_t dispatch_data_create_map(dispatch_data_t data, const void **buffer, size_t *size);

uint64_t mach_absolute_time(void);
typedef struct {
	uint32_t numer, denom;
} mach_timebase_info_data_t;
kern_return_t mach_timebase_info(mach_timebase_info_data_t *information);

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *pointer, size_t size);
void free(void *pointer);
void *memcpy(void *to, const void *from, size_t size);
void *memset(void *to, int value, size_t size);
int memcmp(const void *a, const void *b, size_t size);
size_t strlen(const char *text);
int usleep(unsigned int microseconds);
void abort(void) __attribute__((noreturn));

typedef struct {
	uint32_t opaque;
} os_unfair_lock;
#define OS_UNFAIR_LOCK_INIT ((os_unfair_lock){0})
void os_unfair_lock_lock(os_unfair_lock *lock);
void os_unfair_lock_unlock(os_unfair_lock *lock);
