/*
 * MTLFunctionStitchingGraph as the stream `metal/stitching.rs` reads: the nodes
 * a graph reaches, each after what it uses, whether as an argument or as a
 * control dependency. Metal's attributes need nothing, since every call inlines.
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
- (NSUInteger)options;
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
	if ([node isKindOfClass:NSClassFromString(@"MTLFunctionStitchingInputNode")]) {
		[self word:0];
		[self word:(uint32_t)[node argumentIndex]];
		[_nodes addObject:node];
		return YES;
	}
	NSUInteger function = [self indexOfFunctionNamed:[node name]];
	if (function == NSNotFound) {
		return refuse(failure, "a stitched node names a function the descriptor does not list");
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
