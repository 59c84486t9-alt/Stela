/*
 * Metal source compiles in the process that asks for it, through the compiler
 * macOS ships. Its C entry points (`docs/research/metal-compiler.md`) make AIR
 * with no GPU's back end, and the service makes that a library. A build's
 * directory names its version, so nothing here follows one build.
 */
#include "Bundle.h"

#define COMPILER_VERSIONS @"/System/Library/PrivateFrameworks/GPUCompiler.framework/Versions"

static struct {
	void *(*context_create)(void);
	void (*context_dispose)(void *context);
	const void *(*buffer_start)(void *buffer);
	size_t (*buffer_size)(void *buffer);
	void (*buffer_dispose)(void *buffer);
	void *(*compiler_create)(int debug);
	void (*compiler_destroy)(void *compiler);
	int (*set_target)(void *compiler, const char *triple);
	int (*compile)(void *compiler, void *context, const char *source, const char *const *headers,
		       const char *const *header_names, size_t header_count, const char *options,
		       char **log, void **buffer);
} apple;

/* The standard headers of the compiler in `apple`. */
static NSString *include_directory;

/* The name in `directory` of the highest number. */
static NSString *newest_version(NSString *directory)
{
	NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:NULL];
	NSString *newest = nil;
	for (NSUInteger i = 0; i < names.count; i++) {
		NSString *name = names[i];
		if (name.integerValue > newest.integerValue) {
			newest = name;
		}
	}
	return newest;
}

#define LOAD(field, library, name) (apple.field = (__typeof__(apple.field))dlsym(library, name))

static BOOL load_compiler(void)
{
	NSString *version = newest_version(COMPILER_VERSIONS);
	NSString *root = [NSString stringWithFormat:@"%@/%@/Libraries", COMPILER_VERSIONS, version];
	NSString *clang = [NSString stringWithFormat:@"%@/lib/clang", root];
	NSString *headers = newest_version(clang);
	if (!version || !headers) {
		return NO;
	}
	include_directory = [NSString stringWithFormat:@"%@/%@/include/metal", clang, headers];
	const char *gpu_path = [NSString stringWithFormat:@"%@/libGPUCompiler.dylib", root].UTF8String;
	const char *llvm_path = [NSString stringWithFormat:@"%@/libLLVM.dylib", root].UTF8String;
	void *gpu = dlopen(gpu_path, RTLD_NOW | RTLD_LOCAL);
	void *llvm = dlopen(llvm_path, RTLD_NOW | RTLD_LOCAL);
	return gpu && llvm && LOAD(context_create, llvm, "LLVMContextCreate") &&
	       LOAD(context_dispose, llvm, "LLVMContextDispose") &&
	       LOAD(buffer_start, llvm, "LLVMGetBufferStart") &&
	       LOAD(buffer_size, llvm, "LLVMGetBufferSize") &&
	       LOAD(buffer_dispose, llvm, "LLVMDisposeMemoryBuffer") &&
	       LOAD(compiler_create, gpu, "MTLGPUCompilerCreate") &&
	       LOAD(compiler_destroy, gpu, "MTLGPUCompilerDestroy") &&
	       LOAD(set_target, gpu, "MTLGPUCompilerSetTargetTriple") &&
	       LOAD(compile, gpu, "MTLGPUCompilerCompileFromSourceToBuffer");
}

/* `text` as one argument of an options line. */
static NSString *argument(NSString *text)
{
	id special = [NSCharacterSet characterSetWithCharactersInString:@" \t\n\"'\\"];
	if ([text rangeOfCharacterFromSet:special].location == NSNotFound) {
		return text;
	}
	NSString *escaped = [text stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
	escaped = [escaped stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
	return [NSString stringWithFormat:@"\"%@\"", escaped];
}

/* The compiler's options for `MTLCompileOptions`. */
static NSString *options_line(id options)
{
	static const char *const math_modes[] = {"safe", "relaxed", "fast"};
	static const char *const math_functions[] = {"fast", "precise"};
	NSUInteger language = [options languageVersion];
	NSUInteger major = language >> 16, minor = language & 0xffff;
	NSMutableString *line = [NSMutableString
		stringWithFormat:@"-x metal -std=%smetal%lu.%lu -fmetal-math-mode=%s -fmetal-math-fp32-functions=%s "
				 @"-I%@ -finclude-default-header",
				 major < 3 ? "macos-" : "", major, minor, math_modes[[options mathMode]],
				 math_functions[[options mathFloatingPointFunctions]], include_directory];
	if ([options optimizationLevel] == MTLLibraryOptimizationLevelSize) {
		[line appendFormat:@" -Os"];
	}
	if ([options compileSymbolVisibility] == MTLCompileSymbolVisibilityHidden) {
		[line appendFormat:@" -fvisibility=hidden"];
	}
	if ([options preserveInvariance]) {
		[line appendFormat:@" -fpreserve-invariance"];
	}
	if ([options enableLogging]) {
		[line appendFormat:@" -fmetal-enable-logging"];
	}
	NSDictionary *macros = [options preprocessorMacros];
	NSArray *names = macros.allKeys;
	for (NSUInteger i = 0; i < names.count; i++) {
		NSString *definition = [NSString stringWithFormat:@"%@=%@", names[i], macros[names[i]]];
		[line appendFormat:@" -D %@", argument(definition)];
	}
	return line;
}

/* The compiler's target: AIR's version follows the language, and macOS's this system. */
static NSString *target_triple(NSUInteger language)
{
	NSUInteger major = language >> 16, minor = language & 0xffff;
	NSUInteger air_major = major < 3 ? major : 2;
	NSUInteger air_minor = major < 3 ? minor : 5 + 3 * (major - 3) + minor;
	char version[32] = {0};
	size_t size = sizeof(version) - 1;
	int system_major = 0, system_minor = 0;
	sysctlbyname("kern.osproductversion", version, &size, NULL, 0);
	sscanf(version, "%d.%d", &system_major, &system_minor);
	return [NSString stringWithFormat:@"air64_v%lu%lu-apple-macosx%d.%d.0", air_major, air_minor,
					  system_major, system_minor];
}

/* One compile in its own context, whose AIR, on success, leaves in `air`. */
static BOOL compile_once(const char *source, const char *options, const char *triple, char **log, NSData **air)
{
	void *context = apple.context_create();
	void *compiler = context ? apple.compiler_create(0) : NULL;
	void *buffer = NULL;
	BOOL compiled = compiler && apple.set_target(compiler, triple) &&
			apple.compile(compiler, context, source, NULL, NULL, 0, options, log, &buffer);
	if (compiled) {
		*air = [NSData dataWithBytes:apple.buffer_start(buffer) length:apple.buffer_size(buffer)];
		apple.buffer_dispose(buffer);
	}
	if (compiler) {
		apple.compiler_destroy(compiler);
	}
	if (context) {
		apple.context_dispose(context);
	}
	return compiled;
}

static NSError *source_error(NSInteger code, NSString *reason)
{
	NSString *key = NSLocalizedDescriptionKey;
	NSDictionary *information = [NSDictionary dictionaryWithObjects:&reason forKeys:&key count:1];
	return [NSError errorWithDomain:MTLLibraryErrorDomain code:code userInfo:information];
}

NSData *stela_compile_source(NSString *source, id options, NSError **error)
{
	static long once;
	static BOOL loaded;
	/* Requests run one at a time: nothing shows the compiler takes more. */
	static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
	dispatch_once(&once, ^{
		loaded = load_compiler();
	});
	if (!loaded) {
		if (error) {
			*error = source_error(MTLLibraryErrorUnsupported, @"this system has no Metal compiler");
		}
		return nil;
	}
	const char *line = options_line(options).UTF8String;
	const char *triple = target_triple([options languageVersion]).UTF8String;
	NSData *air = nil;
	char *log = NULL;
	os_unfair_lock_lock(&lock);
	BOOL compiled = compile_once(source.UTF8String, line, triple, NULL, &air);
	/*
	 * The log's allocation has no public disposer, so only a refused source
	 * asks for one, and keeps it.
	 */
	if (!compiled) {
		compile_once(source.UTF8String, line, triple, &log, &air);
	}
	os_unfair_lock_unlock(&lock);
	if (!compiled && error) {
		NSString *reason = log ? [NSString stringWithUTF8String:log] : nil;
		*error = source_error(MTLLibraryErrorCompileFailure, reason ?: @"the Metal compiler refused the source");
	}
	return compiled ? air : nil;
}
