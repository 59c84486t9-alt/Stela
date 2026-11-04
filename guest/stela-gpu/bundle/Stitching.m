/*
 * MTLFunctionStitchingGraph as the stream `metal/stitching.rs` reads: the nodes
 * a graph reaches, each after what it uses, whether as an argument or as a
 * control dependency. Metal's attributes need nothing, since every call inlines,
 * and a builtin node reads the builtin of the kernel the call inlines into.
 */
#include "Bundle.h"

/* Metal's graphs and nodes. */
@interface NSObject (StelaStitching)
- (NSArray *)functionGraphs;
- (NSArray *)functions;
- (NSArray *)nodes;
- (id)outputNode;
- (NSString *)functionName;
- (NSString *)name;
- (NSArray *)arguments;
- (NSArray *)controlDependencies;
- (NSUInteger)argumentIndex;
- (NSUInteger)bindIndex;
- (NSUInteger)byteOffset;
- (BOOL)dereference;
- (id)condition;
- (NSUInteger)options;
/* Foundation's, which names an unknown node. */
- (NSString *)className;
- (id)methodSignatureForSelector:(SEL)selector;
- (id)forwardingTargetForSelector:(SEL)selector;
@end

@interface StelaGPUStitcher : NSObject
- (instancetype)initWithFunctions:(NSArray *)functions;
/* False after setting `failure`. */
- (BOOL)addGraph:(id)graph failure:(StelaFailure *)failure;
@property(readonly) NSMutableData *stream;
@end

@implementation StelaGPUStitcher {
	NSArray *_functions;
	/* The graph's nodes in the stream's order, and those still being added. */
	NSMutableArray *_nodes, *_open;
	NSMutableData *_body;
	/* The graph's output node, or nil. */
	id _output;
}

- (instancetype)initWithFunctions:(NSArray *)functions
{
	self = [super init];
	if (self) {
		_functions = functions;
		_stream = [NSMutableData dataWithLength:0];
	}
	return self;
}

- (void)word:(uint32_t)word
{
	[_body appendBytes:&word length:sizeof(word)];
}

/* Whether `object` takes `selector`, itself or by forwarding it. */
static BOOL answers(id object, SEL selector)
{
	return [object respondsToSelector:selector] || [object methodSignatureForSelector:selector]
	       || [object forwardingTargetForSelector:selector];
}

static BOOL refuse(StelaFailure *failure, const char *reason)
{
	strlcpy(failure->reason, reason, sizeof(failure->reason));
	return NO;
}

- (NSUInteger)indexOfFunctionNamed:(NSString *)name
{
	for (NSUInteger index = 0; index < _functions.count; index++) {
		if ([[_functions[index] name] isEqualToString:name]) {
			return index;
		}
	}
	return NSNotFound;
}

/* Adds what `node` needs and then `node`, unless the stream has it already. */
- (BOOL)addNode:(id)node failure:(StelaFailure *)failure
{
	if ([_nodes indexOfObjectIdenticalTo:node] != NSNotFound) {
		return YES;
	}
	if ([_open indexOfObjectIdenticalTo:node] != NSNotFound) {
		return refuse(failure, "a stitched function graph has a cycle");
	}
	/* `MTLFunctionStitchingNode` declares nothing. Metal's own input nodes are
	 * one class, each kind of binding, early returns and each builtin
	 * another; any other node is a call unless it has no name to answer and
	 * an argument index instead. */
	/* Builtins, by the stream's numbers. */
	static NSString *const builtins[] = {
		@"MTLFunctionStitchingBuiltinThreadPositionInGrid",
		@"MTLFunctionStitchingBuiltinThreadPositionInThreadgroup",
	};
	for (uint32_t index = 0; index < sizeof(builtins) / sizeof(*builtins); index++) {
		if ([node isKindOfClass:NSClassFromString(builtins[index])]) {
			[self word:UINT32_MAX];
			[self word:index + 1];
			[_nodes addObject:node];
			return YES;
		}
	}
	/* The texture, sampler and threadgroup memory bound at an index, and a
	 * buffer, which is its address with no offset. */
	BOOL texture = [node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputTexture")];
	BOOL sampler = [node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputSampler")];
	BOOL threadgroup = [node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputThreadgroup")];
	BOOL buffer = [node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputBuffer")];
	if (texture || sampler || threadgroup || buffer) {
		if ([node bindIndex] > UINT32_MAX) {
			return refuse(failure, "a stitched input past every binding index");
		}
		[self word:texture ? UINT32_MAX - 3 : sampler ? UINT32_MAX - 4 : threadgroup ? UINT32_MAX - 5 : UINT32_MAX - 1];
		[self word:(uint32_t)[node bindIndex]];
		if (buffer) {
			[self word:0];
			[self word:0];
			[self word:0];
		}
		[_nodes addObject:node];
		return YES;
	}
	if ([node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputBufferAddress")]) {
		uint64_t offset = [node byteOffset];
		if ([node bindIndex] > UINT32_MAX) {
			return refuse(failure, "a stitched buffer address past every buffer index");
		}
		[self word:UINT32_MAX - 1];
		[self word:(uint32_t)[node bindIndex]];
		[self word:(uint32_t)offset];
		[self word:(uint32_t)(offset >> 32)];
		[self word:[node dereference] ? 1 : 0];
		[_nodes addObject:node];
		return YES;
	}
	if ([node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingEarlyReturnNode")]) {
		/* It returns its one argument, if any, when its condition is true;
		 * an argument that is its condition is only what it depends on. */
		id condition = [node condition];
		NSArray *values = [node arguments];
		if (values.count > 1 || !condition) {
			return refuse(failure, "a stitched early return of several values or on no condition");
		}
		if (values.count && values[0] == condition) {
			values = @[];
		}
		if (values.count && !_output) {
			snprintf(failure->reason, sizeof(failure->reason),
				 "a stitched early return of %s from a function with no output",
				 [[values[0] name] UTF8String] ?: [values[0] className].UTF8String);
			return NO;
		}
		[_open addObject:node];
		NSArray *dependencies = [node controlDependencies];
		for (NSUInteger index = 0; index < dependencies.count; index++) {
			if (![self addNode:dependencies[index] failure:failure]) {
				return NO;
			}
		}
		if (![self addNode:condition failure:failure] || (values.count && ![self addNode:values[0] failure:failure])) {
			return NO;
		}
		[_open removeLastObject];
		[self word:UINT32_MAX - 2];
		[self word:(uint32_t)[_nodes indexOfObjectIdenticalTo:condition]];
		[self word:values.count ? (uint32_t)[_nodes indexOfObjectIdenticalTo:values[0]] + 1 : 0];
		[_nodes addObject:node];
		return YES;
	}
	BOOL named = answers(node, @selector(name));
	if ([node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputNode")]
	    || (!named && answers(node, @selector(argumentIndex)))) {
		[self word:0];
		[self word:(uint32_t)[node argumentIndex]];
		[_nodes addObject:node];
		return YES;
	}
	if (!named) {
		snprintf(failure->reason, sizeof(failure->reason), "a stitched function graph has a %s node",
			 [node className].UTF8String);
		return NO;
	}
	NSUInteger function = [self indexOfFunctionNamed:[node name]];
	if (function == NSNotFound) {
		char listed[96] = "";
		size_t used = 0;
		for (NSUInteger index = 0; index < _functions.count && used < sizeof(listed); index++) {
			int length = snprintf(listed + used, sizeof(listed) - used, "%s%s", index ? " " : "",
					      [[_functions[index] name] UTF8String] ?: "?");
			used += length > 0 ? (size_t)length : 0;
		}
		snprintf(failure->reason, sizeof(failure->reason),
			 "a stitched %s names %s, which the descriptor's functions (%s) do not",
			 [node className].UTF8String, [[node name] UTF8String] ?: "?", listed);
		return NO;
	}
	[_open addObject:node];
	NSArray *arguments = [node arguments], *dependencies = [node controlDependencies];
	for (NSUInteger index = 0; index < dependencies.count; index++) {
		if (![self addNode:dependencies[index] failure:failure]) {
			return NO;
		}
	}
	for (NSUInteger index = 0; index < arguments.count; index++) {
		if (![self addNode:arguments[index] failure:failure]) {
			return NO;
		}
	}
	[_open removeLastObject];
	[self word:(uint32_t)function + 1];
	[self word:(uint32_t)arguments.count];
	for (NSUInteger index = 0; index < arguments.count; index++) {
		[self word:(uint32_t)[_nodes indexOfObjectIdenticalTo:arguments[index]]];
	}
	[_nodes addObject:node];
	return YES;
}

- (BOOL)addGraph:(id)graph failure:(StelaFailure *)failure
{
	_nodes = [NSMutableArray arrayWithCapacity:16];
	_open = [NSMutableArray arrayWithCapacity:16];
	_body = [NSMutableData dataWithLength:0];
	NSArray *nodes = [graph nodes];
	id output = [graph outputNode];
	_output = output;
	for (NSUInteger index = 0; index < nodes.count; index++) {
		if (![self addNode:nodes[index] failure:failure]) {
			return NO;
		}
	}
	if (output && ![self addNode:output failure:failure]) {
		return NO;
	}
	const char *name = [graph functionName].UTF8String;
	uint32_t header[] = {
		(uint32_t)strlen(name),
		(uint32_t)_nodes.count,
		output ? (uint32_t)[_nodes indexOfObjectIdenticalTo:output] + 1 : 0,
	};
	static const uint8_t padding[4];
	[_stream appendBytes:header length:sizeof(header)];
	[_stream appendBytes:name length:header[0]];
	[_stream appendBytes:padding length:-header[0] & 3];
	[_stream appendBytes:_body.bytes length:_body.length];
	return YES;
}

@end

@implementation StelaGPUDevice (Stitching)

- (id)newLibraryWithStitchedDescriptor:(id)descriptor error:(NSError **)error
{
	StelaFailure failure = {};
	NSArray *graphs = [descriptor functionGraphs], *functions = [descriptor functions];
	StelaGPUStitcher *stitcher = [[StelaGPUStitcher alloc] initWithFunctions:functions];
	BOOL encoded = YES;
	for (NSUInteger index = 0; encoded && index < graphs.count; index++) {
		encoded = [stitcher addGraph:graphs[index] failure:&failure];
	}
	/* No stitched function comes from an archive here, so all would miss. */
	if (encoded && ([descriptor options] & MTLStitchedLibraryOptionFailOnBinaryArchiveMiss)) {
		encoded = NO;
		strlcpy(failure.reason, "a stitched library that must come from an archive", sizeof(failure.reason));
	}
	uint64_t handles[functions.count + 1];
	for (NSUInteger index = 0; index < functions.count; index++) {
		handles[index] = ((StelaGPUObject *)functions[index])->_handle;
	}
	StelaNewStitchedLibraryRequest request = {
		.functions = stela_span(handles, functions.count * sizeof(*handles)),
		.graphs = stela_span(stitcher.stream.bytes, stitcher.stream.length),
	};
	StelaHandle response = {};
	StelaSpans spans = {.reads = &request.functions, .read_count = 2};
	if (!encoded) {
		stela_report("a stitched library", &failure);
	}
	if (!encoded
	    || STELA_CALL_SPANS(&_gate, NewStitchedLibrary, &request, &response, spans, &failure) != StelaStatusOk) {
		if (error) {
			*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorInternal, &failure);
		}
		return nil;
	}
	return [[StelaGPULibrary alloc] initWithDevice:self handle:response.handle];
}

- (void)newLibraryWithStitchedDescriptor:(id)descriptor completionHandler:(void (^)(id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		NSError *error = nil;
		id library = [self newLibraryWithStitchedDescriptor:descriptor error:&error];
		handler(library, error);
	});
}

@end
