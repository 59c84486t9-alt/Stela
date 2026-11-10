/*
 * Metal's text form of stitched function graphs, which MPS and Core ML pass to
 * -newLibraryWithDAG:functions:error: and Metal's -newDagStringWithGraphs:
 * writes. Each graph becomes Metal's own graph objects again, and the library
 * compiles as -newLibraryWithStitchedDescriptor:error: compiles one. Metal's
 * base form sends the text to its compiler service with each function's AIR,
 * which it reads from Metal's private library data; this device's functions
 * have none.
 *
 *   DAGS { NAME { ATTRIBUTE; ... STATEMENT; ... } ... }
 *   ATTRIBUTE   ALWAYS_INLINE or KERNEL
 *   STATEMENT   NODE(LABEL) or OUTPUT(LABEL), then " : ", then FUNCTION(NAME)
 *               or EARLY_RETURN, then ", ARGUMENT" for each argument
 *   ARGUMENT    INPUT(n), NODE(LABEL), *NODE(LABEL) for a control dependency,
 *               BUFFER(CONSTANT, n), BUFFER_ADDR(BUFFER(CONSTANT, n), offset)
 *               with a * to dereference it, TEXTURE(n), SAMPLER(n),
 *               THREADGROUP(n), IMAGEBLOCK, or BUILTIN(THREAD_POSITION_IN_GRID)
 *               and BUILTIN(THREAD_POSITION_IN_THREADGROUP)
 *
 * An early return's one node is its condition, as -newDagStringWithGraphs:
 * writes a return of no value.
 */
#include "Bundle.h"

/* Metal's initializers of its graph classes. */
@interface NSObject (StelaStitchedDAG)
- (id)initWithArgumentIndex:(NSUInteger)index;
- (id)initWithBindIndex:(NSUInteger)index;
- (id)initWithBindIndex:(NSUInteger)index byteOffset:(NSUInteger)offset dereference:(BOOL)dereference;
- (id)initWithCondition:(id)condition controlDependencies:(NSArray *)dependencies;
- (id)initWithName:(NSString *)name arguments:(NSArray *)arguments controlDependencies:(NSArray *)dependencies;
- (id)initWithFunctionName:(NSString *)name nodes:(NSArray *)nodes outputNode:(id)output attributes:(NSArray *)attributes;
- (void)setFunctionGraphs:(NSArray *)graphs;
- (void)setFunctions:(NSArray *)functions;
@end

/* A statement of a graph: a function call or an early return, whose
 * arguments are Metal's input and binding nodes or the labels of the
 * statements they use. */
@interface StelaDAGStatement : NSObject {
@public
	NSString *_label;
	/* Nil for an early return. */
	NSString *_function;
	BOOL _output;
	NSMutableArray *_arguments;
	NSMutableArray *_dependencies;
	/* The node once built, and whether its arguments are being built. */
	id _node;
	BOOL _building;
}
@end

@implementation StelaDAGStatement
@end

typedef struct {
	const char *at, *end;
	StelaFailure *failure;
} StelaDAGText;

static BOOL fail(StelaDAGText *text, const char *expected)
{
	size_t left = (size_t)(text->end - text->at);
	snprintf(text->failure->reason, sizeof(text->failure->reason), "a stitching DAG where %s was expected: \"%.*s\"",
		 expected, (int)(left < 48 ? left : 48), text->at);
	return NO;
}

static BOOL space(char character)
{
	return character == ' ' || character == '\n' || character == '\t' || character == '\r';
}

static void skip(StelaDAGText *text)
{
	while (text->at < text->end && space(*text->at)) {
		text->at++;
	}
}

/* Takes `word` when the text continues with it, after any space. */
static BOOL take(StelaDAGText *text, const char *word)
{
	skip(text);
	size_t length = strlen(word);
	if ((size_t)(text->end - text->at) < length || memcmp(text->at, word, length)) {
		return NO;
	}
	text->at += length;
	return YES;
}

/* The text up to the first of `stops` or space, which is not empty. */
static NSString *name(StelaDAGText *text, const char *stops)
{
	skip(text);
	const char *start = text->at;
	while (text->at < text->end && !space(*text->at) && !strchr(stops, *text->at)) {
		text->at++;
	}
	if (text->at == start) {
		return nil;
	}
	return [[NSString alloc] initWithBytes:start length:(NSUInteger)(text->at - start) encoding:NSUTF8StringEncoding];
}

static BOOL number(StelaDAGText *text, NSUInteger *value)
{
	skip(text);
	const char *start = text->at;
	*value = 0;
	while (text->at < text->end && *text->at >= '0' && *text->at <= '9' && *value <= UINT32_MAX) {
		*value = *value * 10 + (NSUInteger)(*text->at++ - '0');
	}
	return text->at != start && *value <= UINT32_MAX;
}

/* "n)" after an opening parenthesis. */
static BOOL index_argument(StelaDAGText *text, NSUInteger *value)
{
	return number(text, value) && take(text, ")");
}

static id bound(NSString *class, NSUInteger index)
{
	return [[NSClassFromString(class) alloc] initWithBindIndex:index];
}

/* One argument of `statement`. */
static BOOL argument(StelaDAGText *text, StelaDAGStatement *statement)
{
	BOOL star = take(text, "*");
	NSUInteger index = 0, offset = 0;
	if (take(text, "NODE(")) {
		NSString *label = name(text, ")");
		if (!label || !take(text, ")")) {
			return fail(text, "a node's label");
		}
		[star ? statement->_dependencies : statement->_arguments addObject:label];
		return YES;
	}
	if (take(text, "BUFFER_ADDR(")) {
		if (!take(text, "BUFFER(") || !take(text, "CONSTANT") || !take(text, ",") || !index_argument(text, &index)
		    || !take(text, ",") || !index_argument(text, &offset)) {
			return fail(text, "BUFFER_ADDR(BUFFER(CONSTANT, index), offset)");
		}
		[statement->_arguments addObject:[[NSClassFromString(@"MTLFunctionStitchingInputBufferAddress") alloc]
						     initWithBindIndex:index
							    byteOffset:offset
							   dereference:star]];
		return YES;
	}
	if (star) {
		return fail(text, "a node or buffer address after *");
	}
	id node = nil;
	if (take(text, "INPUT(")) {
		node = index_argument(text, &index)
			       ? [[NSClassFromString(@"MTLFunctionStitchingInputNode") alloc] initWithArgumentIndex:index]
			       : nil;
	} else if (take(text, "BUFFER(")) {
		node = take(text, "CONSTANT") && take(text, ",") && index_argument(text, &index)
			       ? bound(@"MTLFunctionStitchingInputBuffer", index)
			       : nil;
	} else if (take(text, "TEXTURE(")) {
		node = index_argument(text, &index) ? bound(@"MTLFunctionStitchingInputTexture", index) : nil;
	} else if (take(text, "SAMPLER(")) {
		node = index_argument(text, &index) ? bound(@"MTLFunctionStitchingInputSampler", index) : nil;
	} else if (take(text, "THREADGROUP(")) {
		node = index_argument(text, &index) ? bound(@"MTLFunctionStitchingInputThreadgroup", index) : nil;
	} else if (take(text, "IMAGEBLOCK")) {
		node = bound(@"MTLFunctionStitchingInputImageblock", 0);
	} else if (take(text, "BUILTIN(THREAD_POSITION_IN_GRID)")) {
		node = [NSClassFromString(@"MTLFunctionStitchingBuiltinThreadPositionInGrid") new];
	} else if (take(text, "BUILTIN(THREAD_POSITION_IN_THREADGROUP)")) {
		node = [NSClassFromString(@"MTLFunctionStitchingBuiltinThreadPositionInThreadgroup") new];
	}
	if (!node) {
		return fail(text, "an argument");
	}
	[statement->_arguments addObject:node];
	return YES;
}

/* The statement after its NODE( or OUTPUT(. */
static StelaDAGStatement *statement(StelaDAGText *text, BOOL output)
{
	StelaDAGStatement *statement = [StelaDAGStatement new];
	statement->_output = output;
	statement->_arguments = [NSMutableArray array];
	statement->_dependencies = [NSMutableArray array];
	statement->_label = name(text, ")");
	if (!statement->_label || !take(text, ")") || !take(text, ":")) {
		fail(text, "a statement's label and \":\"");
		return nil;
	}
	if (take(text, "FUNCTION(")) {
		statement->_function = name(text, ")");
		if (!statement->_function || !take(text, ")")) {
			fail(text, "a function's name");
			return nil;
		}
	} else if (!take(text, "EARLY_RETURN")) {
		fail(text, "FUNCTION or EARLY_RETURN");
		return nil;
	}
	while (take(text, ",")) {
		if (!argument(text, statement)) {
			return nil;
		}
	}
	if (!take(text, ";")) {
		fail(text, "\";\"");
		return nil;
	}
	return statement;
}

/* The node of `statement`, after those it uses. */
static id build(NSDictionary *labels, StelaDAGStatement *statement,
		StelaFailure *failure)
{
	if (statement->_node) {
		return statement->_node;
	}
	if (statement->_building) {
		snprintf(failure->reason, sizeof(failure->reason), "a stitching DAG whose node %s uses itself",
			 statement->_label.UTF8String);
		return nil;
	}
	statement->_building = YES;
	NSMutableArray *arguments = [NSMutableArray arrayWithCapacity:statement->_arguments.count];
	NSMutableArray *dependencies = [NSMutableArray arrayWithCapacity:statement->_dependencies.count];
	for (int list = 0; list < 2; list++) {
		NSArray *from = list ? statement->_dependencies : statement->_arguments;
		NSMutableArray *to = list ? dependencies : arguments;
		for (NSUInteger index = 0; index < from.count; index++) {
			id entry = from[index];
			if (![entry isKindOfClass:[NSString class]]) {
				[to addObject:entry];
				continue;
			}
			StelaDAGStatement *used = labels[entry];
			if (!used) {
				snprintf(failure->reason, sizeof(failure->reason),
					 "a stitching DAG whose node %s uses %s, which no statement labels",
					 statement->_label.UTF8String, [entry UTF8String]);
				return nil;
			}
			id node = build(labels, used, failure);
			if (!node) {
				return nil;
			}
			[to addObject:node];
		}
	}
	if (statement->_function) {
		statement->_node = [[NSClassFromString(@"MTLFunctionStitchingFunctionNode") alloc]
			initWithName:statement->_function
			   arguments:arguments
		 controlDependencies:dependencies];
	} else if (arguments.count == 1) {
		statement->_node = [[NSClassFromString(@"MTLFunctionStitchingEarlyReturnNode") alloc]
			   initWithCondition:arguments[0]
			 controlDependencies:dependencies];
	} else {
		snprintf(failure->reason, sizeof(failure->reason),
			 "a stitching DAG whose early return %s has %lu nodes, not its one condition",
			 statement->_label.UTF8String, (unsigned long)arguments.count);
		return nil;
	}
	statement->_building = NO;
	return statement->_node;
}

/* A graph after its name. */
static id graph(StelaDAGText *text, NSString *function)
{
	NSMutableArray *attributes = [NSMutableArray array], *statements = [NSMutableArray array];
	NSMutableDictionary *labels = [NSMutableDictionary dictionary];
	StelaDAGStatement *output = nil;
	if (!take(text, "{")) {
		fail(text, "\"{\" after a graph's name");
		return nil;
	}
	while (!take(text, "}")) {
		BOOL is_output = NO;
		if (take(text, "ALWAYS_INLINE;")) {
			[attributes addObject:[NSClassFromString(@"MTLFunctionStitchingAttributeAlwaysInline") new]];
			continue;
		}
		if (take(text, "KERNEL;")) {
			[attributes addObject:[NSClassFromString(@"MTLFunctionStitchingAttributeKernel") new]];
			continue;
		}
		if (!take(text, "NODE(") && !(is_output = take(text, "OUTPUT("))) {
			fail(text, "an attribute or a statement");
			return nil;
		}
		StelaDAGStatement *parsed = statement(text, is_output);
		if (!parsed) {
			return nil;
		}
		if (labels[parsed->_label] || (is_output && output)) {
			snprintf(text->failure->reason, sizeof(text->failure->reason),
				 "a stitching DAG whose graph %s has two statements labelled %s or two outputs",
				 function.UTF8String, parsed->_label.UTF8String);
			return nil;
		}
		[labels setObject:parsed forKey:parsed->_label];
		/* The output is one of the graph's nodes too, in its place, as
		 * Metal writes a graph whose nodes include its output. */
		output = is_output ? parsed : output;
		[statements addObject:parsed];
	}
	NSMutableArray *nodes = [NSMutableArray arrayWithCapacity:statements.count];
	for (NSUInteger index = 0; index < statements.count; index++) {
		id node = build(labels, statements[index], text->failure);
		if (!node) {
			return nil;
		}
		[nodes addObject:node];
	}
	id outputNode = output ? build(labels, output, text->failure) : nil;
	if (output && !outputNode) {
		return nil;
	}
	return [[NSClassFromString(@"MTLFunctionStitchingGraph") alloc] initWithFunctionName:function
										       nodes:nodes
										  outputNode:outputNode
										  attributes:attributes];
}

/* The graphs of `dag`, or nil after setting `failure`. */
static NSArray *graphs(NSString *dag, StelaFailure *failure)
{
	const char *bytes = dag.UTF8String ?: "";
	StelaDAGText text = {.at = bytes, .end = bytes + strlen(bytes), .failure = failure};
	if (!take(&text, "DAGS") || !take(&text, "{")) {
		fail(&text, "\"DAGS {\"");
		return nil;
	}
	NSMutableArray *graphs = [NSMutableArray array];
	while (!take(&text, "}")) {
		NSString *function = name(&text, "{}");
		id parsed = function ? graph(&text, function) : nil;
		if (!function) {
			fail(&text, "a graph's name");
		}
		if (!parsed) {
			return nil;
		}
		[graphs addObject:parsed];
	}
	skip(&text);
	if (text.at != text.end) {
		fail(&text, "the end");
		return nil;
	}
	return graphs;
}

@implementation StelaGPUDevice (StitchedDAG)

- (id)newLibraryWithDAG:(NSString *)dag functions:(NSArray *)functions error:(NSError **)error
{
	StelaFailure failure = {};
	NSArray *parsed = graphs(dag, &failure);
	if (!parsed) {
		stela_report("newLibraryWithDAG:functions:error:", &failure);
		if (error) {
			*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorCompileFailure, &failure);
		}
		return nil;
	}
	id descriptor = [NSClassFromString(@"MTLStitchedLibraryDescriptor") new];
	[descriptor setFunctionGraphs:parsed];
	[descriptor setFunctions:functions];
	return [self newLibraryWithStitchedDescriptor:descriptor error:error];
}

@end
