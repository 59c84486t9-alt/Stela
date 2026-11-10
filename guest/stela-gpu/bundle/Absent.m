/*
 * Metal's private SPI protocols require far more of a driver than any caller
 * of this device reaches: emulation state, telemetry, tool hooks. Their
 * declarations are only in the running Metal, so at load each class takes the
 * SPI of every protocol it adopts, and what it lacks answers zero and reports
 * once by name. A selector no protocol requires stays unanswered to
 * `respondsToSelector:`, and forwarding gives it the same zero and report.
 * `SPI.m` holds what has a real answer.
 */
#include "Bundle.h"

void *objc_getProtocol(const char *name);
const char *protocol_getName(void *protocol);
void **protocol_copyProtocolList(void *protocol, unsigned *count);
void **class_copyProtocolList(Class class, unsigned *count);
const char *sel_getName(SEL selector);
BOOL class_addMethod(Class class, SEL selector, IMP implementation, const char *types);
BOOL class_respondsToSelector(Class class, SEL selector);
Class object_getClass(id object);
const char *method_getTypeEncoding(Method method);
Class objc_getClass(const char *name);
const char *class_getName(Class class);

@interface NSObject (StelaForwarding)
+ (id)signatureWithObjCTypes:(const char *)types;
- (SEL)selector;
@end

struct objc_method_description {
	SEL name;
	char *types;
};
struct objc_method_description *protocol_copyMethodDescriptionList(void *protocol, BOOL required, BOOL instance,
								   unsigned *count);

/* Class and selector pairs reported so far, by a key of both, open
 * addressed. Past the table's size a pair is not remembered: the first one
 * says so, and later ones are not reported. */
#define REPORTED 4096
static uint64_t reported[REPORTED];
static bool overflowed;

/* Reports `selector` sent to an object of `class` once, with the image and
 * offset of the code that sent it when `caller` is known. */
static void report(Class class, SEL selector, const void *caller)
{
	const char *name = sel_getName(selector);
	const char *receiver = class ? class_getName(class) : "nil";
	/* Zero marks a free slot. */
	uint64_t key = ((uint64_t)(uintptr_t)name * 0x9e3779b97f4a7c15ull) ^ (uint64_t)(uintptr_t)class;
	key = key ? key : 1;
	size_t at = (size_t)(key >> 7);
	for (size_t probe = 0; probe < REPORTED; probe++, at++) {
		uint64_t expected = 0;
		if (__atomic_compare_exchange_n(&reported[at % REPORTED], &expected, key, false, __ATOMIC_RELAXED,
						__ATOMIC_RELAXED)) {
			StelaFailure failure = {.reason = "Metal's SPI asked for what this device has no answer to"};
			char what[384];
			Dl_info image = {};
			if (!caller || !dladdr(caller, &image) || !image.dli_fname) {
				snprintf(what, sizeof(what), "-[%s %s]", receiver, name);
			} else {
				snprintf(what, sizeof(what), "-[%s %s], asked by %s+0x%lx", receiver, name,
					 image.dli_fname, (unsigned long)((uintptr_t)caller - (uintptr_t)image.dli_fbase));
			}
			stela_report(what, &failure);
			return;
		}
		if (expected == key) {
			return;
		}
	}
	if (!__atomic_exchange_n(&overflowed, true, __ATOMIC_RELAXED)) {
		StelaFailure failure = {.reason = "more absent selectors than the report table holds; later ones are "
						  "not reported"};
		char what[320];
		snprintf(what, sizeof(what), "-[%s %s]", receiver, name);
		stela_report(what, &failure);
	}
}

/* Pointers, integers and structs of two words come back in x0 and x1. */
static unsigned __int128 absent(id self, SEL selector)
{
	report(object_getClass(self), selector, __builtin_return_address(0));
	return 0;
}

static double absent_float(id self, SEL selector)
{
	report(object_getClass(self), selector, __builtin_return_address(0));
	return 0;
}

static MTLSize absent_size(id self, SEL selector)
{
	report(object_getClass(self), selector, __builtin_return_address(0));
	return (MTLSize){0};
}

/* The answer for a method of `types`; NULL for a struct this cannot zero. */
static IMP answer(const char *types)
{
	if (types[0] == 'f' || types[0] == 'd') {
		return (IMP)(void *)absent_float;
	}
	if (types[0] != '{') {
		return (IMP)(void *)absent;
	}
	const char *body = strchr(types, '=');
	if (body && !strncmp(body, "=QQQ}", 5)) {
		return (IMP)(void *)absent_size;
	}
	return body && (!strncmp(body, "=QQ}", 4) || !strncmp(body, "=Q}", 3)) ? (IMP)(void *)absent : NULL;
}

static void take_on(Class class, void *protocol)
{
	unsigned count = 0;
	struct objc_method_description *methods = protocol_copyMethodDescriptionList(protocol, YES, YES, &count);
	for (unsigned i = 0; i < count; i++) {
		IMP implementation = answer(methods[i].types);
		if (implementation && !class_respondsToSelector(class, methods[i].name)) {
			class_addMethod(class, methods[i].name, implementation, methods[i].types);
		}
	}
	free(methods);
	void **adopted = protocol_copyProtocolList(protocol, &count);
	for (unsigned i = 0; i < count; i++) {
		take_on(class, adopted[i]);
	}
	free(adopted);
}

/* Integer arguments in the selector's number, for a method nothing declares. */
static id forwarding_signature(id self, SEL selector, SEL wanted)
{
	Method method = class_getInstanceMethod(object_getClass(self), wanted);
	if (method) {
		return [(id)objc_getClass("NSMethodSignature") signatureWithObjCTypes:method_getTypeEncoding(method)];
	}
	char types[32] = "Q@:";
	size_t length = strlen(types);
	for (const char *name = sel_getName(wanted); *name && length + 1 < sizeof(types); name++) {
		if (*name == ':') {
			types[length++] = 'Q';
		}
	}
	types[length] = 0;
	return [(id)objc_getClass("NSMethodSignature") signatureWithObjCTypes:types];
}

/* The return address of the code that sent a forwarded message: the first
 * frame outside this bundle, the Objective-C runtime and CoreFoundation's
 * forwarding. */
static const void *forwarded_sender(void)
{
	void *frames[12];
	int count = backtrace(frames, 12);
	Dl_info own = {};
	dladdr((const void *)forwarded_sender, &own);
	for (int i = 1; i < count; i++) {
		Dl_info image = {};
		if (!dladdr(frames[i], &image) || !image.dli_fname) {
			continue;
		}
		if (image.dli_fbase == own.dli_fbase || strstr(image.dli_fname, "CoreFoundation") ||
		    strstr(image.dli_fname, "libobjc")) {
			continue;
		}
		return frames[i];
	}
	return NULL;
}

/* An invocation's return value starts zeroed. */
static void forward(id self, SEL selector, id invocation)
{
	report(object_getClass(self), [invocation selector], forwarded_sender());
}

@interface StelaGPUAbsent : NSObject
@end

@implementation StelaGPUAbsent

+ (void)load
{
	Class classes[] = {
		[StelaGPUDevice class],	       [StelaGPUResource class],      [StelaGPUBuffer class],
		[StelaGPUTexture class],       [StelaGPUSampler class],	      [StelaGPUDepthStencil class],
		[StelaGPUHeap class],	       [StelaGPUFence class],	      [StelaGPURateMap class],	      [StelaGPUEvent class],
		[StelaGPUTextureViewPool class],
		[StelaGPULibrary class],       [StelaGPUBinaryArchive class], [StelaGPUArgumentEncoder class],
		[StelaGPUFunction class],      [StelaGPURenderPipeline class], [StelaGPUComputePipeline class],
		[StelaGPUFunctionHandle class], [StelaGPUFunctionTable class], [StelaGPUIndirectCommandBuffer class],
		[StelaGPUQueue class],	       [StelaGPUCommandBuffer class], [StelaGPUEncoder class],
		[StelaGPUBlitEncoder class],   [StelaGPUComputeEncoder class], [StelaGPURenderEncoder class],
		[StelaGPUResourceStateEncoder class], [StelaGPUParallelEncoder class],
	};
	for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
		class_addMethod(classes[i], @selector(methodSignatureForSelector:), (IMP)(void *)forwarding_signature, "@@::");
		class_addMethod(classes[i], @selector(forwardInvocation:), (IMP)(void *)forward, "v@:@");
		unsigned count = 0;
		void **protocols = class_copyProtocolList(classes[i], &count);
		for (unsigned j = 0; j < count; j++) {
			char name[128];
			snprintf(name, sizeof(name), "%sSPI", protocol_getName(protocols[j]));
			void *protocol = objc_getProtocol(name);
			if (protocol) {
				take_on(classes[i], protocol);
			}
		}
		free(protocols);
	}
}

@end
