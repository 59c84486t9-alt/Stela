/* SPDX-License-Identifier: MIT */
/*
 * The Metal suite's runner: executes every case of a plan that
 * `cargo xtask gpu metal-suite plan` wrote and stores each output's bytes. The same
 * arm64 binary runs on a Mac, giving the reference, and in a macOS guest on
 * Stela, so both read the same libraries and inputs.
 *
 *   runner PLAN_DIR RESULTS_DIR [--only SUBSTRING]... [--skip-done]
 *
 * Each case writes RESULTS_DIR/<case>/status.json before it runs ("running")
 * and after ("ok", "error" or "timeout", with the GPU time its work took as
 * gpu_ms), and one <output>.bin per output. A
 * case that does not complete within its timeout stops the runner with exit
 * status 2, since the device may not recover; --skip-done resumes after it.
 * Nothing here interprets results: the plan says what to bind and dispatch.
 *
 * The binary runs from Runner.app, whose Share.xpc service is the same
 * binary: launched by launchd for `host` cases that share a texture and an
 * event with another process.
 */
#import <Foundation/Foundation.h>
#import <CoreImage/CoreImage.h>
#import <IOSurface/IOSurface.h>
#import <Metal/Metal.h>
#import <MetalPerformanceShaders/MetalPerformanceShaders.h>
#import <QuartzCore/CAMetalLayer.h>
#include <stdio.h>

static NSString *plan_dir;
/* GPU time of the case's own command buffers, not its output readback. */
static double gpu_seconds;
static BOOL timing;

@interface Case : NSObject
@property(retain) NSDictionary *spec;
@property(retain) NSString *name;
@property(retain) NSString *dir;
@property(retain) id<MTLDevice> device;
@property(retain) NSMutableDictionary<NSString *, id<MTLBuffer>> *buffers;
@property(retain) NSMutableDictionary<NSString *, id<MTLTexture>> *textures;
@property(retain) NSMutableDictionary<NSString *, id<MTLSamplerState>> *samplers;
@property(retain) NSMutableArray *resident;
@property(retain) NSMutableDictionary<NSString *, id<MTLFence>> *fences;
@property(retain) NSMutableDictionary<NSString *, id<MTLEvent>> *events;
@property(retain) NSMutableDictionary<NSString *, id<MTLIndirectCommandBuffer>> *icbs;
@property(retain) NSMutableDictionary<NSString *, id<MTLHeap>> *heaps;
@property(retain) NSMutableDictionary *libraries;
@property(retain) NSDictionary *plan;
@property(retain) id<MTLCommandQueue> queue;
@end
@implementation Case
@end

static NSException *failure(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static NSException *failure(NSString *format, ...)
{
	va_list args;
	va_start(args, format);
	NSString *reason = [[NSString alloc] initWithFormat:format arguments:args];
	va_end(args);
	return [NSException exceptionWithName:@"CaseFailure" reason:reason userInfo:nil];
}

static NSUInteger number(NSDictionary *d, NSString *key, NSUInteger fallback)
{
	id v = d[key];
	return v ? [v unsignedIntegerValue] : fallback;
}

static NSUInteger lookup(NSDictionary<NSString *, NSNumber *> *table, NSString *kind, id name)
{
	if ([name isKindOfClass:[NSNumber class]])
		return [name unsignedIntegerValue];
	NSNumber *v = table[name];
	if (!v)
		@throw failure(@"unknown %@ '%@'", kind, name);
	return v.unsignedIntegerValue;
}

static NSDictionary<NSString *, NSNumber *> *pixel_formats(void)
{
	static NSDictionary *t;
	if (!t)
		t = @{
			@"a8unorm" : @(MTLPixelFormatA8Unorm), @"r8unorm" : @(MTLPixelFormatR8Unorm),
			@"r8unorm_srgb" : @(MTLPixelFormatR8Unorm_sRGB), @"r8snorm" : @(MTLPixelFormatR8Snorm),
			@"r8uint" : @(MTLPixelFormatR8Uint), @"r8sint" : @(MTLPixelFormatR8Sint),
			@"r16unorm" : @(MTLPixelFormatR16Unorm), @"r16snorm" : @(MTLPixelFormatR16Snorm),
			@"r16uint" : @(MTLPixelFormatR16Uint), @"r16sint" : @(MTLPixelFormatR16Sint),
			@"r16float" : @(MTLPixelFormatR16Float), @"rg8unorm" : @(MTLPixelFormatRG8Unorm),
			@"rg8snorm" : @(MTLPixelFormatRG8Snorm), @"rg8uint" : @(MTLPixelFormatRG8Uint),
			@"rg8sint" : @(MTLPixelFormatRG8Sint), @"rg8unorm_srgb" : @(MTLPixelFormatRG8Unorm_sRGB),
			@"b5g6r5unorm" : @(MTLPixelFormatB5G6R5Unorm), @"a1bgr5unorm" : @(MTLPixelFormatA1BGR5Unorm),
			@"abgr4unorm" : @(MTLPixelFormatABGR4Unorm), @"bgr5a1unorm" : @(MTLPixelFormatBGR5A1Unorm),
			@"r32uint" : @(MTLPixelFormatR32Uint), @"r32sint" : @(MTLPixelFormatR32Sint),
			@"r32float" : @(MTLPixelFormatR32Float), @"rg16unorm" : @(MTLPixelFormatRG16Unorm),
			@"rg16snorm" : @(MTLPixelFormatRG16Snorm), @"rg16uint" : @(MTLPixelFormatRG16Uint),
			@"rg16sint" : @(MTLPixelFormatRG16Sint), @"rg16float" : @(MTLPixelFormatRG16Float),
			@"rgba8unorm" : @(MTLPixelFormatRGBA8Unorm), @"rgba8unorm_srgb" : @(MTLPixelFormatRGBA8Unorm_sRGB),
			@"rgba8snorm" : @(MTLPixelFormatRGBA8Snorm), @"rgba8uint" : @(MTLPixelFormatRGBA8Uint),
			@"rgba8sint" : @(MTLPixelFormatRGBA8Sint), @"bgra8unorm" : @(MTLPixelFormatBGRA8Unorm),
			@"bgra8unorm_srgb" : @(MTLPixelFormatBGRA8Unorm_sRGB),
			@"rgb10a2unorm" : @(MTLPixelFormatRGB10A2Unorm), @"rgb10a2uint" : @(MTLPixelFormatRGB10A2Uint),
			@"bgr10a2unorm" : @(MTLPixelFormatBGR10A2Unorm), @"rg11b10float" : @(MTLPixelFormatRG11B10Float),
			@"rgb9e5float" : @(MTLPixelFormatRGB9E5Float), @"rg32uint" : @(MTLPixelFormatRG32Uint),
			@"rg32sint" : @(MTLPixelFormatRG32Sint), @"rg32float" : @(MTLPixelFormatRG32Float),
			@"rgba16unorm" : @(MTLPixelFormatRGBA16Unorm), @"rgba16snorm" : @(MTLPixelFormatRGBA16Snorm),
			@"rgba16uint" : @(MTLPixelFormatRGBA16Uint), @"rgba16sint" : @(MTLPixelFormatRGBA16Sint),
			@"rgba16float" : @(MTLPixelFormatRGBA16Float), @"rgba32uint" : @(MTLPixelFormatRGBA32Uint),
			@"rgba32sint" : @(MTLPixelFormatRGBA32Sint), @"rgba32float" : @(MTLPixelFormatRGBA32Float),
			@"bc1_rgba" : @(MTLPixelFormatBC1_RGBA), @"bc3_rgba" : @(MTLPixelFormatBC3_RGBA),
			@"bc4_runorm" : @(MTLPixelFormatBC4_RUnorm), @"bc5_rgunorm" : @(MTLPixelFormatBC5_RGUnorm),
			@"bc7_rgbaunorm" : @(MTLPixelFormatBC7_RGBAUnorm), @"bc7_rgbaunorm_srgb" : @(MTLPixelFormatBC7_RGBAUnorm_sRGB),
			@"bc1_rgba_srgb" : @(MTLPixelFormatBC1_RGBA_sRGB), @"bc2_rgba" : @(MTLPixelFormatBC2_RGBA),
			@"bc2_rgba_srgb" : @(MTLPixelFormatBC2_RGBA_sRGB), @"bc3_rgba_srgb" : @(MTLPixelFormatBC3_RGBA_sRGB),
			@"bc4_rsnorm" : @(MTLPixelFormatBC4_RSnorm), @"bc5_rgsnorm" : @(MTLPixelFormatBC5_RGSnorm),
			@"bc6h_rgbfloat" : @(MTLPixelFormatBC6H_RGBFloat), @"bc6h_rgbufloat" : @(MTLPixelFormatBC6H_RGBUfloat),
			@"depth24unorm_stencil8" : @(MTLPixelFormatDepth24Unorm_Stencil8),
			@"x32_stencil8" : @(MTLPixelFormatX32_Stencil8), @"x24_stencil8" : @(MTLPixelFormatX24_Stencil8),
			@"depth16unorm" : @(MTLPixelFormatDepth16Unorm), @"depth32float" : @(MTLPixelFormatDepth32Float),
			@"stencil8" : @(MTLPixelFormatStencil8),
			@"depth32float_stencil8" : @(MTLPixelFormatDepth32Float_Stencil8),
		};
	return t;
}

static NSDictionary<NSString *, NSNumber *> *vertex_formats(void)
{
	static NSDictionary *t;
	if (!t)
		t = @{
			@"uchar2" : @(MTLVertexFormatUChar2), @"uchar3" : @(MTLVertexFormatUChar3),
			@"uchar4" : @(MTLVertexFormatUChar4), @"char2" : @(MTLVertexFormatChar2),
			@"char3" : @(MTLVertexFormatChar3), @"char4" : @(MTLVertexFormatChar4),
			@"uchar2normalized" : @(MTLVertexFormatUChar2Normalized),
			@"uchar3normalized" : @(MTLVertexFormatUChar3Normalized),
			@"uchar4normalized" : @(MTLVertexFormatUChar4Normalized),
			@"char2normalized" : @(MTLVertexFormatChar2Normalized),
			@"char3normalized" : @(MTLVertexFormatChar3Normalized),
			@"char4normalized" : @(MTLVertexFormatChar4Normalized),
			@"ushort2" : @(MTLVertexFormatUShort2), @"ushort3" : @(MTLVertexFormatUShort3),
			@"ushort4" : @(MTLVertexFormatUShort4), @"short2" : @(MTLVertexFormatShort2),
			@"short3" : @(MTLVertexFormatShort3), @"short4" : @(MTLVertexFormatShort4),
			@"ushort2normalized" : @(MTLVertexFormatUShort2Normalized),
			@"ushort3normalized" : @(MTLVertexFormatUShort3Normalized),
			@"ushort4normalized" : @(MTLVertexFormatUShort4Normalized),
			@"short2normalized" : @(MTLVertexFormatShort2Normalized),
			@"short3normalized" : @(MTLVertexFormatShort3Normalized),
			@"short4normalized" : @(MTLVertexFormatShort4Normalized),
			@"half2" : @(MTLVertexFormatHalf2), @"half3" : @(MTLVertexFormatHalf3),
			@"half4" : @(MTLVertexFormatHalf4), @"float" : @(MTLVertexFormatFloat),
			@"float2" : @(MTLVertexFormatFloat2), @"float3" : @(MTLVertexFormatFloat3),
			@"float4" : @(MTLVertexFormatFloat4), @"int" : @(MTLVertexFormatInt),
			@"int2" : @(MTLVertexFormatInt2), @"int3" : @(MTLVertexFormatInt3),
			@"int4" : @(MTLVertexFormatInt4), @"uint" : @(MTLVertexFormatUInt),
			@"uint2" : @(MTLVertexFormatUInt2), @"uint3" : @(MTLVertexFormatUInt3),
			@"uint4" : @(MTLVertexFormatUInt4),
			@"int1010102normalized" : @(MTLVertexFormatInt1010102Normalized),
			@"uint1010102normalized" : @(MTLVertexFormatUInt1010102Normalized),
			@"uchar4normalized_bgra" : @(MTLVertexFormatUChar4Normalized_BGRA),
			@"uchar" : @(MTLVertexFormatUChar), @"char" : @(MTLVertexFormatChar),
			@"ucharnormalized" : @(MTLVertexFormatUCharNormalized),
			@"charnormalized" : @(MTLVertexFormatCharNormalized), @"ushort" : @(MTLVertexFormatUShort),
			@"short" : @(MTLVertexFormatShort), @"ushortnormalized" : @(MTLVertexFormatUShortNormalized),
			@"shortnormalized" : @(MTLVertexFormatShortNormalized), @"half" : @(MTLVertexFormatHalf),
			@"floatrg11b10" : @(MTLVertexFormatFloatRG11B10), @"floatrgb9e5" : @(MTLVertexFormatFloatRGB9E5),
		};
	return t;
}

static NSDictionary<NSString *, NSNumber *> *blend_factors(void)
{
	static NSDictionary *t;
	if (!t)
		t = @{
			@"zero" : @(MTLBlendFactorZero), @"one" : @(MTLBlendFactorOne),
			@"source_color" : @(MTLBlendFactorSourceColor),
			@"one_minus_source_color" : @(MTLBlendFactorOneMinusSourceColor),
			@"source_alpha" : @(MTLBlendFactorSourceAlpha),
			@"one_minus_source_alpha" : @(MTLBlendFactorOneMinusSourceAlpha),
			@"destination_color" : @(MTLBlendFactorDestinationColor),
			@"one_minus_destination_color" : @(MTLBlendFactorOneMinusDestinationColor),
			@"destination_alpha" : @(MTLBlendFactorDestinationAlpha),
			@"one_minus_destination_alpha" : @(MTLBlendFactorOneMinusDestinationAlpha),
			@"source_alpha_saturated" : @(MTLBlendFactorSourceAlphaSaturated),
			@"blend_color" : @(MTLBlendFactorBlendColor),
			@"one_minus_blend_color" : @(MTLBlendFactorOneMinusBlendColor),
			@"blend_alpha" : @(MTLBlendFactorBlendAlpha),
			@"one_minus_blend_alpha" : @(MTLBlendFactorOneMinusBlendAlpha),
			@"source1_color" : @(MTLBlendFactorSource1Color),
			@"one_minus_source1_color" : @(MTLBlendFactorOneMinusSource1Color),
			@"source1_alpha" : @(MTLBlendFactorSource1Alpha),
			@"one_minus_source1_alpha" : @(MTLBlendFactorOneMinusSource1Alpha),
		};
	return t;
}

static NSDictionary<NSString *, NSNumber *> *blend_operations(void)
{
	return @{
		@"add" : @(MTLBlendOperationAdd), @"subtract" : @(MTLBlendOperationSubtract),
		@"reverse_subtract" : @(MTLBlendOperationReverseSubtract), @"min" : @(MTLBlendOperationMin),
		@"max" : @(MTLBlendOperationMax),
	};
}

static NSDictionary<NSString *, NSNumber *> *compare_functions(void)
{
	return @{
		@"never" : @(MTLCompareFunctionNever), @"less" : @(MTLCompareFunctionLess),
		@"equal" : @(MTLCompareFunctionEqual), @"less_equal" : @(MTLCompareFunctionLessEqual),
		@"greater" : @(MTLCompareFunctionGreater), @"not_equal" : @(MTLCompareFunctionNotEqual),
		@"greater_equal" : @(MTLCompareFunctionGreaterEqual), @"always" : @(MTLCompareFunctionAlways),
	};
}

static NSDictionary<NSString *, NSNumber *> *stencil_operations(void)
{
	return @{
		@"keep" : @(MTLStencilOperationKeep), @"zero" : @(MTLStencilOperationZero),
		@"replace" : @(MTLStencilOperationReplace),
		@"increment_clamp" : @(MTLStencilOperationIncrementClamp),
		@"decrement_clamp" : @(MTLStencilOperationDecrementClamp), @"invert" : @(MTLStencilOperationInvert),
		@"increment_wrap" : @(MTLStencilOperationIncrementWrap),
		@"decrement_wrap" : @(MTLStencilOperationDecrementWrap),
	};
}

static NSDictionary<NSString *, NSNumber *> *texture_types(void)
{
	return @{
		@"1d" : @(MTLTextureType1D), @"1d_array" : @(MTLTextureType1DArray), @"2d" : @(MTLTextureType2D),
		@"2d_array" : @(MTLTextureType2DArray), @"2d_ms" : @(MTLTextureType2DMultisample),
		@"2d_ms_array" : @(MTLTextureType2DMultisampleArray), @"cube" : @(MTLTextureTypeCube),
		@"cube_array" : @(MTLTextureTypeCubeArray), @"3d" : @(MTLTextureType3D),
	};
}

static NSDictionary<NSString *, NSNumber *> *data_types(void)
{
	return @{
		@"bool" : @(MTLDataTypeBool), @"char" : @(MTLDataTypeChar), @"uchar" : @(MTLDataTypeUChar),
		@"short" : @(MTLDataTypeShort), @"ushort" : @(MTLDataTypeUShort), @"int" : @(MTLDataTypeInt),
		@"uint" : @(MTLDataTypeUInt), @"long" : @(MTLDataTypeLong), @"ulong" : @(MTLDataTypeULong),
		@"half" : @(MTLDataTypeHalf), @"float" : @(MTLDataTypeFloat), @"float2" : @(MTLDataTypeFloat2),
		@"float4" : @(MTLDataTypeFloat4), @"int2" : @(MTLDataTypeInt2), @"int4" : @(MTLDataTypeInt4),
		@"uint4" : @(MTLDataTypeUInt4), @"half4" : @(MTLDataTypeHalf4),
	};
}

static NSData *read_file(NSString *relative)
{
	NSString *path = [plan_dir stringByAppendingPathComponent:relative];
	NSData *data = [NSData dataWithContentsOfFile:path];
	if (!data)
		@throw failure(@"cannot read %@", path);
	return data;
}

static void write_json(NSString *path, NSDictionary *value)
{
	NSData *data = [NSJSONSerialization dataWithJSONObject:value
						       options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
							 error:nil];
	[data writeToFile:path atomically:YES];
}

/* The plan's library: a corpus metallib beside the plan, or the first of a
 * list of system paths that exists. */
static id<MTLLibrary> library_named(id<MTLDevice> device, NSDictionary *plan, NSString *name, NSMutableDictionary *cache)
{
	if (cache[name])
		return cache[name];
	id where = plan[@"libraries"][name];
	if (!where)
		@throw failure(@"plan has no library %@", name);
	if ([where isKindOfClass:[NSDictionary class]]) {
		/* Compiled from source by the device at run time, with the
		 * options an application passes. */
		NSDictionary *w = where;
		NSString *source = [[NSString alloc] initWithData:read_file(w[@"source"]) encoding:NSUTF8StringEncoding];
		MTLCompileOptions *o = [MTLCompileOptions new];
		NSDictionary *versions = @{@"2.0" : @(MTLLanguageVersion2_0), @"2.1" : @(MTLLanguageVersion2_1), @"2.2" : @(MTLLanguageVersion2_2),
					   @"2.3" : @(MTLLanguageVersion2_3), @"2.4" : @(MTLLanguageVersion2_4), @"3.0" : @(MTLLanguageVersion3_0),
					   @"3.1" : @(MTLLanguageVersion3_1)};
		if (w[@"language"])
			o.languageVersion = lookup(versions, @"language version", w[@"language"]);
		if (w[@"fast_math"])
			o.fastMathEnabled = [w[@"fast_math"] boolValue];
		if (w[@"macros"])
			o.preprocessorMacros = w[@"macros"];
		o.preserveInvariance = [w[@"preserve_invariance"] boolValue];
		if ([w[@"optimization"] isEqualToString:@"size"])
			o.optimizationLevel = MTLLibraryOptimizationLevelSize;
		NSError *error = nil;
		id<MTLLibrary> library = [device newLibraryWithSource:source options:o error:&error];
		if (!library)
			@throw failure(@"library %@ from source: %@", name, error.localizedDescription);
		cache[name] = library;
		return library;
	}
	NSArray *candidates = [where isKindOfClass:[NSArray class]] ? where : @[ [plan_dir stringByAppendingPathComponent:where] ];
	for (NSString *path in candidates) {
		if (![[NSFileManager defaultManager] fileExistsAtPath:path])
			continue;
		NSError *error = nil;
		id<MTLLibrary> library = [device newLibraryWithURL:[NSURL fileURLWithPath:path] error:&error];
		if (!library)
			@throw failure(@"library %@: %@", path, error.localizedDescription);
		cache[name] = library;
		return library;
	}
	@throw failure(@"library %@ is not present", name);
}

/* The dynamic libraries a pipeline preloads, by plan library name. */
static NSArray<id<MTLDynamicLibrary>> *preloaded(Case *c, NSArray *names)
{
	NSMutableArray *out = [NSMutableArray new];
	for (NSString *name in names) {
		NSError *error = nil;
		id<MTLDynamicLibrary> dylib = [c.device newDynamicLibrary:library_named(c.device, c.plan, name, c.libraries) error:&error];
		if (!dylib)
			@throw failure(@"dynamic library %@: %@", name, error.localizedDescription);
		[out addObject:dylib];
	}
	return out;
}

static MTLFunctionConstantValues *constants_of(NSArray *constants)
{
	MTLFunctionConstantValues *values = [MTLFunctionConstantValues new];
	for (NSDictionary *c in constants) {
		NSUInteger type = lookup(data_types(), @"data type", c[@"type"]);
		NSData *bytes;
		if (c[@"bytes"]) {
			bytes = [[NSData alloc] initWithBase64EncodedString:c[@"bytes"] options:0];
		} else {
			union {
				uint8_t u8;
				uint16_t u16;
				uint32_t u32;
				uint64_t u64;
				float f;
				__fp16 h;
			} v = {0};
			size_t size = 4;
			double value = [c[@"value"] doubleValue];
			switch (type) {
			case MTLDataTypeBool: case MTLDataTypeChar: case MTLDataTypeUChar:
				v.u8 = (uint8_t)(int64_t)value; size = 1; break;
			case MTLDataTypeShort: case MTLDataTypeUShort:
				v.u16 = (uint16_t)(int64_t)value; size = 2; break;
			case MTLDataTypeHalf: v.h = (__fp16)value; size = 2; break;
			case MTLDataTypeFloat: v.f = (float)value; break;
			case MTLDataTypeLong: case MTLDataTypeULong:
				v.u64 = (uint64_t)[c[@"value"] longLongValue]; size = 8; break;
			default: v.u32 = (uint32_t)[c[@"value"] longLongValue]; break;
			}
			bytes = [NSData dataWithBytes:&v length:size];
		}
		if (c[@"name"])
			[values setConstantValue:bytes.bytes type:type withName:c[@"name"]];
		else
			[values setConstantValue:bytes.bytes type:type atIndex:number(c, @"index", 0)];
	}
	return values;
}

static id<MTLFunction> function_named(id<MTLLibrary> library, NSString *name, NSArray *constants)
{
	NSError *error = nil;
	id<MTLFunction> function;
	if (constants.count)
		function = [library newFunctionWithName:name constantValues:constants_of(constants) error:&error];
	else
		function = [library newFunctionWithName:name];
	if (!function)
		@throw failure(@"function %@: %@", name, error ? error.localizedDescription : @"not in library");
	return function;
}

/* Shared storage, without hazard tracking when the case orders its uses
 * itself with fences or events. */
/* A heap: automatic (the heap places resources) or placement (each names
 * its offset), shared or private, tracked or untracked. */
static id<MTLHeap> make_heap(Case *c, NSDictionary *h)
{
	MTLHeapDescriptor *d = [MTLHeapDescriptor new];
	d.size = number(h, @"size", 65536);
	d.type = [h[@"type"] isEqualToString:@"placement"] ? MTLHeapTypePlacement : MTLHeapTypeAutomatic;
	d.storageMode = [h[@"storage"] isEqualToString:@"private"] ? MTLStorageModePrivate : MTLStorageModeShared;
	d.hazardTrackingMode = [h[@"untracked"] boolValue] ? MTLHazardTrackingModeUntracked : MTLHazardTrackingModeTracked;
	id<MTLHeap> heap = [c.device newHeapWithDescriptor:d];
	if (!heap)
		@throw failure(@"heap %@ creation failed", h[@"name"]);
	heap.label = h[@"name"];
	return heap;
}

static MTLResourceOptions storage_option(NSString *storage)
{
	if ([storage isEqualToString:@"private"])
		return MTLResourceStorageModePrivate;
	if ([storage isEqualToString:@"managed"])
		return MTLResourceStorageModeManaged;
	if (storage && ![storage isEqualToString:@"shared"])
		@throw failure(@"unknown storage mode %@", storage);
	return MTLResourceStorageModeShared;
}

static MTLResourceOptions buffer_options(NSDictionary *b)
{
	MTLResourceOptions options = storage_option(b[@"storage"]);
	if ([b[@"untracked"] boolValue])
		options |= MTLResourceHazardTrackingModeUntracked;
	return options;
}

/* A buffer of `length` bytes: from the device, or from the named heap at
 * an offset when that heap places its resources. */
static id<MTLBuffer> allocate_buffer(Case *c, NSDictionary *b, NSUInteger length)
{
	if ([b[@"no_copy"] boolValue]) {
		/* Memory the application owns, wrapped without a copy. */
		NSUInteger page = (NSUInteger)getpagesize(), bytes = (length + page - 1) / page * page;
		void *memory = NULL;
		if (posix_memalign(&memory, page, bytes))
			return nil;
		return [c.device newBufferWithBytesNoCopy:memory length:bytes options:buffer_options(b)
					      deallocator:^(void *pointer, NSUInteger _) { free(pointer); }];
	}
	if (!b[@"heap"])
		return [c.device newBufferWithLength:length options:buffer_options(b)];
	id<MTLHeap> heap = c.heaps[b[@"heap"]];
	if (!heap)
		@throw failure(@"buffer %@ names no heap", b[@"name"]);
	MTLResourceOptions options = buffer_options(b) & ~MTLResourceHazardTrackingModeMask;
	options |= heap.resourceOptions & MTLResourceHazardTrackingModeMask;
	if (heap.type == MTLHeapTypePlacement)
		return [heap newBufferWithLength:length options:options offset:number(b, @"heap_offset", 0)];
	return [heap newBufferWithLength:length options:options];
}

/* Runs one blit on the case's queue and waits for it. */
static void blit_now(Case *c, void (^encode)(id<MTLBlitCommandEncoder>))
{
	id<MTLCommandBuffer> cb = [c.queue commandBuffer];
	id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
	encode(e);
	[e endEncoding];
	[cb commit];
	[cb waitUntilCompleted];
	if (cb.error)
		@throw failure(@"blit: %@", cb.error.localizedDescription);
}

static id<MTLBuffer> make_buffer(Case *c, NSDictionary *b)
{
	NSData *data = b[@"file"] ? read_file(b[@"file"]) : nil;
	NSUInteger length = MAX(MAX(number(b, @"length", data ? data.length : 16), data.length), (NSUInteger)16);
	id<MTLBuffer> buffer = allocate_buffer(c, b, length);
	if (!buffer)
		@throw failure(@"buffer %@ allocation failed", b[@"name"]);
	buffer.label = b[@"name"];
	/* An alias keeps the bytes of the resource it overlaps. */
	if (b[@"alias_of"])
		return buffer;
	/* The initial bytes go in through the CPU, or through a staging
	 * buffer and a blit when the CPU cannot reach the storage. */
	id<MTLBuffer> target = buffer;
	if (buffer.storageMode == MTLStorageModePrivate)
		target = [c.device newBufferWithLength:buffer.length options:MTLResourceStorageModeShared];
	memset(target.contents, (int)number(b, @"fill", 0), target.length);
	if (data)
		memcpy(target.contents, data.bytes, data.length);
	if (buffer.storageMode == MTLStorageModeManaged)
		[buffer didModifyRange:NSMakeRange(0, buffer.length)];
	if (target != buffer)
		blit_now(c, ^(id<MTLBlitCommandEncoder> e) {
			[e copyFromBuffer:target sourceOffset:0 toBuffer:buffer destinationOffset:0 size:buffer.length];
		});
	return buffer;
}

/* Bytes of one block of a format the runner uploads or reads back; blocks
 * are 1x1 except for the compressed formats. */
static NSUInteger pixel_bytes(MTLPixelFormat f, NSUInteger *block)
{
	*block = 1;
	switch (f) {
	case MTLPixelFormatA8Unorm: case MTLPixelFormatR8Unorm: case MTLPixelFormatR8Unorm_sRGB:
	case MTLPixelFormatR8Snorm: case MTLPixelFormatR8Uint: case MTLPixelFormatR8Sint:
	case MTLPixelFormatStencil8:
		return 1;
	case MTLPixelFormatR16Unorm: case MTLPixelFormatR16Snorm: case MTLPixelFormatR16Uint:
	case MTLPixelFormatR16Sint: case MTLPixelFormatR16Float: case MTLPixelFormatRG8Unorm:
	case MTLPixelFormatRG8Snorm: case MTLPixelFormatRG8Uint: case MTLPixelFormatB5G6R5Unorm:
	case MTLPixelFormatRG8Sint: case MTLPixelFormatRG8Unorm_sRGB:
	case MTLPixelFormatA1BGR5Unorm: case MTLPixelFormatABGR4Unorm: case MTLPixelFormatBGR5A1Unorm:
	case MTLPixelFormatDepth16Unorm:
		return 2;
	case MTLPixelFormatRG32Uint: case MTLPixelFormatRG32Sint: case MTLPixelFormatRG32Float:
	case MTLPixelFormatRGBA16Unorm: case MTLPixelFormatRGBA16Snorm: case MTLPixelFormatRGBA16Uint:
	case MTLPixelFormatRGBA16Sint: case MTLPixelFormatRGBA16Float:
		return 8;
	case MTLPixelFormatRGBA32Uint: case MTLPixelFormatRGBA32Sint: case MTLPixelFormatRGBA32Float:
		return 16;
	case MTLPixelFormatBC1_RGBA: case MTLPixelFormatBC1_RGBA_sRGB: case MTLPixelFormatBC4_RUnorm: case MTLPixelFormatBC4_RSnorm:
		*block = 4;
		return 8;
	case MTLPixelFormatBC2_RGBA: case MTLPixelFormatBC2_RGBA_sRGB: case MTLPixelFormatBC3_RGBA: case MTLPixelFormatBC3_RGBA_sRGB:
	case MTLPixelFormatBC5_RGUnorm: case MTLPixelFormatBC5_RGSnorm: case MTLPixelFormatBC6H_RGBFloat:
	case MTLPixelFormatBC6H_RGBUfloat: case MTLPixelFormatBC7_RGBAUnorm: case MTLPixelFormatBC7_RGBAUnorm_sRGB:
		*block = 4;
		return 16;
	default:
		return 4;
	}
}

static NSUInteger level_extent(NSUInteger size, NSUInteger level)
{
	return MAX((NSUInteger)1, size >> level);
}

/* The bytes of each (slice, level) of a texture, tightly packed, slices
 * outermost and levels inner: how inputs are uploaded and outputs read. */
struct region {
	NSUInteger slice, level, offset, bytes_per_row, bytes_per_image;
	MTLSize size;
};

static NSArray<NSValue *> *regions_of(id<MTLTexture> t, NSString *aspect, NSUInteger *total)
{
	NSMutableArray *out = [NSMutableArray new];
	NSUInteger block, bytes = pixel_bytes(t.pixelFormat, &block), offset = 0;
	if (t.pixelFormat == MTLPixelFormatDepth32Float_Stencil8 || t.pixelFormat == MTLPixelFormatDepth24Unorm_Stencil8)
		bytes = [aspect isEqualToString:@"stencil"] ? 1 : 4;
	NSUInteger slices = t.arrayLength * (t.textureType == MTLTextureTypeCube || t.textureType == MTLTextureTypeCubeArray ? 6 : 1);
	for (NSUInteger slice = 0; slice < slices; slice++) {
		for (NSUInteger level = 0; level < t.mipmapLevelCount; level++) {
			struct region r = {slice, level, offset, 0, 0, MTLSizeMake(0, 0, 0)};
			r.size = MTLSizeMake(level_extent(t.width, level), level_extent(t.height, level), level_extent(t.depth, level));
			r.bytes_per_row = (r.size.width + block - 1) / block * bytes;
			r.bytes_per_image = r.bytes_per_row * ((r.size.height + block - 1) / block);
			offset += r.bytes_per_image * r.size.depth;
			[out addObject:[NSValue value:&r withObjCType:@encode(struct region)]];
		}
	}
	*total = offset;
	return out;
}

static MTLBlitOption blit_option(MTLPixelFormat f, NSString *aspect)
{
	if (f == MTLPixelFormatDepth32Float_Stencil8 || f == MTLPixelFormatDepth24Unorm_Stencil8)
		return [aspect isEqualToString:@"stencil"] ? MTLBlitOptionStencilFromDepthStencil : MTLBlitOptionDepthFromDepthStencil;
	return MTLBlitOptionNone;
}

static MTLTextureUsage texture_usage(NSDictionary *t)
{
	MTLTextureUsage usage = 0;
	for (NSString *u in t[@"usage"] ?: @[ @"read" ]) {
		if ([u isEqualToString:@"read"]) usage |= MTLTextureUsageShaderRead;
		else if ([u isEqualToString:@"write"]) usage |= MTLTextureUsageShaderWrite;
		else if ([u isEqualToString:@"render"]) usage |= MTLTextureUsageRenderTarget;
		else if ([u isEqualToString:@"atomic"]) usage |= MTLTextureUsageShaderAtomic;
		else if ([u isEqualToString:@"view"]) usage |= MTLTextureUsagePixelFormatView;
		else @throw failure(@"unknown texture usage %@", u);
	}
	return usage;
}

/* A texture buffer: a linear view of one of the case's buffers. */
static id<MTLTexture> make_texture_buffer(Case *c, NSDictionary *t)
{
	id<MTLBuffer> storage = c.buffers[t[@"buffer"]];
	if (!storage)
		@throw failure(@"texture buffer %@ names no buffer", t[@"name"]);
	MTLPixelFormat format = lookup(pixel_formats(), @"pixel format", t[@"format"]);
	NSUInteger block, width = number(t, @"width", 1);
	NSUInteger row = width * pixel_bytes(format, &block);
	NSUInteger align = [c.device minimumTextureBufferAlignmentForPixelFormat:format];
	MTLTextureDescriptor *d = [MTLTextureDescriptor textureBufferDescriptorWithPixelFormat:format width:width
									    resourceOptions:storage.resourceOptions
										      usage:texture_usage(t)];
	id<MTLTexture> texture = [storage newTextureWithDescriptor:d offset:number(t, @"offset", 0)
						      bytesPerRow:(row + align - 1) / align * align];
	if (!texture)
		@throw failure(@"texture buffer %@ creation failed", t[@"name"]);
	texture.label = t[@"name"];
	return texture;
}

static id<MTLTexture> make_texture(Case *c, NSDictionary *t, id<MTLCommandQueue> queue)
{
	if ([t[@"type"] isEqual:@"buffer"])
		return make_texture_buffer(c, t);
	if (t[@"view_of"]) {
		/* A view of an earlier texture: another format, type, mipmap and
		 * slice range or component swizzle over the same memory. */
		id<MTLTexture> source = c.textures[t[@"view_of"]];
		if (!source)
			@throw failure(@"view %@ names no texture", t[@"name"]);
		NSArray *levels = t[@"levels"] ?: @[ @0, @(source.mipmapLevelCount) ];
		NSArray *slices = t[@"slices"] ?: @[ @0, @(source.textureType == MTLTextureTypeCube ? 6 : source.arrayLength) ];
		NSDictionary *components = @{@"r" : @(MTLTextureSwizzleRed), @"g" : @(MTLTextureSwizzleGreen), @"b" : @(MTLTextureSwizzleBlue),
					     @"a" : @(MTLTextureSwizzleAlpha), @"0" : @(MTLTextureSwizzleZero), @"1" : @(MTLTextureSwizzleOne)};
		NSString *sw = t[@"swizzle"] ?: @"rgba";
		MTLTextureSwizzle channel[4];
		for (NSUInteger k = 0; k < 4; k++)
			channel[k] = lookup(components, @"swizzle", [sw substringWithRange:NSMakeRange(k, 1)]);
		id<MTLTexture> view = [source newTextureViewWithPixelFormat:t[@"format"] ? lookup(pixel_formats(), @"pixel format", t[@"format"]) : source.pixelFormat
								 textureType:t[@"type"] ? lookup(texture_types(), @"texture type", t[@"type"]) : source.textureType
								      levels:NSMakeRange([levels[0] unsignedIntegerValue], [levels[1] unsignedIntegerValue])
								      slices:NSMakeRange([slices[0] unsignedIntegerValue], [slices[1] unsignedIntegerValue])
								     swizzle:MTLTextureSwizzleChannelsMake(channel[0], channel[1], channel[2], channel[3])];
		if (!view)
			@throw failure(@"view %@ creation failed", t[@"name"]);
		view.label = t[@"name"];
		return view;
	}
	MTLTextureDescriptor *d = [MTLTextureDescriptor new];
	d.textureType = lookup(texture_types(), @"texture type", t[@"type"] ?: @"2d");
	d.pixelFormat = lookup(pixel_formats(), @"pixel format", t[@"format"]);
	d.width = number(t, @"width", 1);
	d.height = number(t, @"height", 1);
	d.depth = number(t, @"depth", 1);
	d.arrayLength = number(t, @"array", 1);
	d.mipmapLevelCount = number(t, @"mipmaps", 1);
	d.sampleCount = number(t, @"samples", 1);
	d.storageMode = t[@"storage"] ? (MTLStorageMode)(storage_option(t[@"storage"]) >> MTLResourceStorageModeShift)
				      : MTLStorageModePrivate;
	d.usage = texture_usage(t);
	id<MTLTexture> texture;
	if (t[@"over_buffer"]) {
		/* A linear 2D texture over a buffer's bytes, rows `bytes_per_row`
		 * apart, the buffer's contents its texels. */
		id<MTLBuffer> storage = c.buffers[t[@"over_buffer"]];
		if (!storage)
			@throw failure(@"texture %@ names no buffer", t[@"name"]);
		d.storageMode = storage.storageMode;
		d.resourceOptions = storage.resourceOptions;
		texture = [storage newTextureWithDescriptor:d offset:number(t, @"offset", 0) bytesPerRow:number(t, @"bytes_per_row", 256)];
	} else if (t[@"heap"]) {
		id<MTLHeap> heap = c.heaps[t[@"heap"]];
		if (!heap)
			@throw failure(@"texture %@ names no heap", t[@"name"]);
		d.storageMode = heap.storageMode;
		d.hazardTrackingMode = heap.hazardTrackingMode;
		texture = heap.type == MTLHeapTypePlacement ? [heap newTextureWithDescriptor:d offset:number(t, @"heap_offset", 0)]
							    : [heap newTextureWithDescriptor:d];
	} else {
		texture = [c.device newTextureWithDescriptor:d];
	}
	if (!texture)
		@throw failure(@"texture %@ allocation failed", t[@"name"]);
	texture.label = t[@"name"];
	for (NSString *key in @[ @"file", @"stencil_file" ]) {
		if (!t[key])
			continue;
		NSData *data = read_file(t[key]);
		NSString *aspect = [key isEqualToString:@"stencil_file"] ? @"stencil" : t[@"aspect"];
		NSUInteger total;
		NSArray *regions = regions_of(texture, aspect, &total);
		if (data.length < total)
			@throw failure(@"texture %@ input has %lu bytes, needs %lu", t[@"name"], (unsigned long)data.length, (unsigned long)total);
		if (texture.storageMode != MTLStorageModePrivate) {
			/* A texture the CPU reaches takes its texels from the CPU,
			 * rows and images `row_padding` bytes apart beyond their
			 * texels. */
			NSUInteger pad = number(t, @"row_padding", 0);
			for (NSValue *v in regions) {
				struct region r;
				[v getValue:&r];
				NSUInteger rows = r.bytes_per_image / r.bytes_per_row, row = r.bytes_per_row + pad;
				NSMutableData *padded = [NSMutableData dataWithLength:row * rows * r.size.depth];
				for (NSUInteger k = 0; k < rows * r.size.depth; k++)
					memcpy((uint8_t *)padded.mutableBytes + k * row, (const uint8_t *)data.bytes + r.offset + k * r.bytes_per_row,
					       r.bytes_per_row);
				[texture replaceRegion:MTLRegionMake3D(0, 0, 0, r.size.width, r.size.height, r.size.depth)
					   mipmapLevel:r.level slice:r.slice withBytes:padded.bytes bytesPerRow:row bytesPerImage:row * rows];
			}
			continue;
		}
		id<MTLBuffer> staging = [c.device newBufferWithBytes:data.bytes length:total options:MTLResourceStorageModeShared];
		id<MTLCommandBuffer> cb = [queue commandBuffer];
		id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
		for (NSValue *v in regions) {
			struct region r;
			[v getValue:&r];
			[blit copyFromBuffer:staging sourceOffset:r.offset sourceBytesPerRow:r.bytes_per_row
			     sourceBytesPerImage:r.bytes_per_image sourceSize:r.size toTexture:texture
				destinationSlice:r.slice destinationLevel:r.level destinationOrigin:MTLOriginMake(0, 0, 0)
					 options:blit_option(texture.pixelFormat, aspect)];
		}
		[blit endEncoding];
		[cb commit];
		[cb waitUntilCompleted];
		if (cb.error)
			@throw failure(@"texture %@ upload: %@", t[@"name"], cb.error.localizedDescription);
	}
	return texture;
}

static NSDictionary<NSString *, NSNumber *> *address_modes(void)
{
	return @{
		@"clamp_to_edge" : @(MTLSamplerAddressModeClampToEdge),
		@"mirror_clamp_to_edge" : @(MTLSamplerAddressModeMirrorClampToEdge),
		@"repeat" : @(MTLSamplerAddressModeRepeat), @"mirror_repeat" : @(MTLSamplerAddressModeMirrorRepeat),
		@"clamp_to_zero" : @(MTLSamplerAddressModeClampToZero),
		@"clamp_to_border" : @(MTLSamplerAddressModeClampToBorderColor),
	};
}

static id<MTLSamplerState> make_sampler(Case *c, NSDictionary *s)
{
	MTLSamplerDescriptor *d = [MTLSamplerDescriptor new];
	NSDictionary *filters = @{@"nearest" : @(MTLSamplerMinMagFilterNearest), @"linear" : @(MTLSamplerMinMagFilterLinear)};
	NSDictionary *mips = @{@"none" : @(MTLSamplerMipFilterNotMipmapped), @"nearest" : @(MTLSamplerMipFilterNearest),
			       @"linear" : @(MTLSamplerMipFilterLinear)};
	d.minFilter = lookup(filters, @"filter", s[@"min"] ?: @"nearest");
	d.magFilter = lookup(filters, @"filter", s[@"mag"] ?: @"nearest");
	d.mipFilter = lookup(mips, @"mip filter", s[@"mip"] ?: @"none");
	NSArray *address = s[@"address"] ?: @[ @"clamp_to_edge" ];
	d.sAddressMode = lookup(address_modes(), @"address mode", address[0]);
	d.tAddressMode = lookup(address_modes(), @"address mode", address[MIN(1u, address.count - 1)]);
	d.rAddressMode = lookup(address_modes(), @"address mode", address[MIN(2u, address.count - 1)]);
	NSDictionary *borders = @{@"transparent_black" : @(MTLSamplerBorderColorTransparentBlack),
				  @"opaque_black" : @(MTLSamplerBorderColorOpaqueBlack),
				  @"opaque_white" : @(MTLSamplerBorderColorOpaqueWhite)};
	d.borderColor = lookup(borders, @"border color", s[@"border"] ?: @"transparent_black");
	d.normalizedCoordinates = s[@"normalized"] ? [s[@"normalized"] boolValue] : YES;
	d.lodMinClamp = s[@"lod_min"] ? [s[@"lod_min"] floatValue] : 0.0f;
	d.lodMaxClamp = s[@"lod_max"] ? [s[@"lod_max"] floatValue] : FLT_MAX;
	d.maxAnisotropy = number(s, @"anisotropy", 1);
	if (s[@"compare"])
		d.compareFunction = lookup(compare_functions(), @"compare function", s[@"compare"]);
	d.supportArgumentBuffers = [s[@"argument_buffers"] boolValue];
	if (s[@"reduction"] || s[@"lod_bias"]) {
		if (@available(macOS 26.0, *)) {
			NSDictionary *reductions = @{@"weighted_average" : @(MTLSamplerReductionModeWeightedAverage),
						     @"minimum" : @(MTLSamplerReductionModeMinimum),
						     @"maximum" : @(MTLSamplerReductionModeMaximum)};
			d.reductionMode = lookup(reductions, @"reduction mode", s[@"reduction"] ?: @"weighted_average");
			d.lodBias = [s[@"lod_bias"] floatValue];
		} else {
			@throw [NSException exceptionWithName:@"CaseUnsupported" reason:@"sampler reduction and bias need macOS 26" userInfo:nil];
		}
	}
	id<MTLSamplerState> sampler = [c.device newSamplerStateWithDescriptor:d];
	if (!sampler)
		@throw failure(@"sampler %@ creation failed", s[@"name"]);
	return sampler;
}

/* Fills an argument buffer's entries with GPU addresses and resource IDs,
 * the Tier 2 layout of a struct of pointers, textures and samplers. */
static void encode_arguments(Case *c, NSDictionary *a)
{
	id<MTLBuffer> buffer = c.buffers[a[@"buffer"]];
	if (!buffer)
		@throw failure(@"argument buffer %@ is not a buffer", a[@"buffer"]);
	uint8_t *bytes = buffer.contents;
	/* The case's library, loaded only by entries that name functions. */
	id<MTLLibrary> (^library)(void) = ^{
		return library_named(c.device, c.plan, c.spec[@"library"], c.libraries);
	};
	if (a[@"encoder"]) {
		/* The argument encoder a function's buffer argument describes,
		 * each entry at its [[id]]: the path before Tier 2 layouts. */
		id<MTLFunction> f = function_named(library(), a[@"encoder"][@"function"], nil);
		id<MTLArgumentEncoder> ae = [f newArgumentEncoderWithBufferIndex:number(a[@"encoder"], @"index", 0)];
		[ae setArgumentBuffer:buffer offset:number(a, @"offset", 0)];
		for (NSDictionary *e in a[@"entries"]) {
			NSString *kind = e[@"kind"], *name = e[@"resource"];
			NSUInteger index = number(e, @"id", 0);
			if ([kind isEqualToString:@"buffer"]) {
				[ae setBuffer:c.buffers[name] offset:number(e, @"resource_offset", 0) atIndex:index];
				[c.resident addObject:c.buffers[name]];
			} else if ([kind isEqualToString:@"texture"]) {
				[ae setTexture:c.textures[name] atIndex:index];
				[c.resident addObject:c.textures[name]];
			} else if ([kind isEqualToString:@"sampler"]) {
				[ae setSamplerState:c.samplers[name] atIndex:index];
			} else if ([kind isEqualToString:@"constant"]) {
				uint32_t value = (uint32_t)number(e, @"value", 0);
				memcpy([ae constantDataAtIndex:index], &value, 4);
			} else {
				@throw failure(@"unknown encoded argument kind %@", kind);
			}
		}
		return;
	}
	for (NSDictionary *e in a[@"entries"]) {
		NSUInteger offset = number(e, @"offset", 0);
		NSString *kind = e[@"kind"], *name = e[@"resource"];
		if ([kind isEqualToString:@"buffer"]) {
			id<MTLBuffer> target = c.buffers[name];
			if (!target) @throw failure(@"argument %@ names no buffer", name);
			uint64_t address = target.gpuAddress + number(e, @"resource_offset", 0);
			memcpy(bytes + offset, &address, 8);
			/* A heap's resources are made resident by useHeap, and a
			 * residency set's by the set. */
			if (!target.heap && ![e[@"residency_set"] boolValue])
				[c.resident addObject:target];
		} else if ([kind isEqualToString:@"texture"]) {
			id<MTLTexture> target = c.textures[name];
			if (!target) @throw failure(@"argument %@ names no texture", name);
			MTLResourceID id_ = target.gpuResourceID;
			memcpy(bytes + offset, &id_, 8);
			if (!target.heap)
				[c.resident addObject:target];
		} else if ([kind isEqualToString:@"icb"]) {
			id<MTLIndirectCommandBuffer> target = c.icbs[name];
			if (!target) @throw failure(@"argument %@ names no indirect command buffer", name);
			MTLResourceID id_ = target.gpuResourceID;
			memcpy(bytes + offset, &id_, 8);
			[c.resident addObject:target];
		} else if ([kind isEqualToString:@"sampler"]) {
			id<MTLSamplerState> target = c.samplers[name];
			if (!target) @throw failure(@"argument %@ names no sampler", name);
			MTLResourceID id_ = target.gpuResourceID;
			memcpy(bytes + offset, &id_, 8);
		} else if ([kind isEqualToString:@"compute_pipeline"]) {
			/* A pipeline an indirect command sets, by its resource ID. */
			MTLComputePipelineDescriptor *pd = [MTLComputePipelineDescriptor new];
			pd.computeFunction = function_named(library(), e[@"function"], nil);
			pd.supportIndirectCommandBuffers = YES;
			NSError *error = nil;
			id<MTLComputePipelineState> pipeline = [c.device newComputePipelineStateWithDescriptor:pd options:MTLPipelineOptionNone
												   reflection:nil error:&error];
			if (!pipeline)
				@throw failure(@"argument compute pipeline: %@", error.localizedDescription);
			MTLResourceID id_ = pipeline.gpuResourceID;
			memcpy(bytes + offset, &id_, 8);
			[c.resident addObject:pipeline];
		} else if ([kind isEqualToString:@"render_pipeline"]) {
			MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
			pd.vertexFunction = function_named(library(), e[@"vertex"], nil);
			pd.fragmentFunction = function_named(library(), e[@"fragment"], nil);
			pd.colorAttachments[0].pixelFormat = lookup(pixel_formats(), @"pixel format", e[@"format"]);
			pd.supportIndirectCommandBuffers = YES;
			NSError *error = nil;
			id<MTLRenderPipelineState> pipeline = [c.device newRenderPipelineStateWithDescriptor:pd error:&error];
			if (!pipeline)
				@throw failure(@"argument render pipeline: %@", error.localizedDescription);
			MTLResourceID id_ = pipeline.gpuResourceID;
			memcpy(bytes + offset, &id_, 8);
			[c.resident addObject:pipeline];
		} else {
			@throw failure(@"unknown argument kind %@", kind);
		}
	}
}

/* The bytes an inline buffer records: its declared length, or all of it. */
static NSUInteger inline_length(NSDictionary *b, id<MTLBuffer> buffer)
{
	NSUInteger length = number(b, @"length", 0);
	return length ? MIN(length, buffer.length) : buffer.length;
}

static void bind_compute(Case *c, id<MTLComputeCommandEncoder> e, NSDictionary *spec)
{
	for (NSDictionary *b in spec[@"buffers"]) {
		if (!b[@"index"])
			continue;
		id<MTLBuffer> buffer = c.buffers[b[@"name"]];
		/* An inline buffer's bytes are recorded into the command. */
		if ([b[@"inline"] boolValue])
			[e setBytes:buffer.contents length:inline_length(b, buffer) atIndex:number(b, @"index", 0)];
		else
			[e setBuffer:buffer offset:number(b, @"offset", 0) atIndex:number(b, @"index", 0)];
	}
	for (NSDictionary *t in spec[@"textures"])
		if (t[@"index"])
			[e setTexture:c.textures[t[@"name"]] atIndex:number(t, @"index", 0)];
	for (NSDictionary *s in spec[@"samplers"])
		if (s[@"index"])
			[e setSamplerState:c.samplers[s[@"name"]] atIndex:number(s, @"index", 0)];
	for (NSDictionary *m in spec[@"threadgroup_memory"])
		[e setThreadgroupMemoryLength:number(m, @"length", 16) atIndex:number(m, @"index", 0)];
	for (id r in c.resident) {
		if ([r conformsToProtocol:@protocol(MTLResource)])
			[e useResource:r usage:MTLResourceUsageRead | MTLResourceUsageWrite];
	}
	for (NSString *name in spec[@"use_heaps"])
		[e useHeap:c.heaps[name]];
}

static void bind_render(Case *c, id<MTLRenderCommandEncoder> e, NSDictionary *spec)
{
	for (NSDictionary *b in spec[@"buffers"]) {
		if (!b[@"index"])
			continue;
		NSString *stage = b[@"stage"] ?: @"fragment";
		id<MTLBuffer> buffer = c.buffers[b[@"name"]];
		NSUInteger offset = number(b, @"offset", 0), index = number(b, @"index", 0);
		BOOL vertex = [stage isEqualToString:@"vertex"] || [stage isEqualToString:@"both"];
		BOOL fragment = [stage isEqualToString:@"fragment"] || [stage isEqualToString:@"both"];
		if ([b[@"inline"] boolValue]) {
			NSUInteger length = inline_length(b, buffer);
			if (vertex)
				[e setVertexBytes:buffer.contents length:length atIndex:index];
			if (fragment)
				[e setFragmentBytes:buffer.contents length:length atIndex:index];
			continue;
		}
		if (vertex)
			[e setVertexBuffer:buffer offset:offset atIndex:index];
		if (fragment)
			[e setFragmentBuffer:buffer offset:offset atIndex:index];
		if ([stage isEqualToString:@"object"])
			[e setObjectBuffer:buffer offset:offset atIndex:index];
		if ([stage isEqualToString:@"mesh"])
			[e setMeshBuffer:buffer offset:offset atIndex:index];
	}
	for (NSDictionary *t in spec[@"textures"]) {
		if (!t[@"index"])
			continue;
		NSString *stage = t[@"stage"] ?: @"fragment";
		id<MTLTexture> texture = c.textures[t[@"name"]];
		if ([stage isEqualToString:@"vertex"] || [stage isEqualToString:@"both"])
			[e setVertexTexture:texture atIndex:number(t, @"index", 0)];
		if ([stage isEqualToString:@"fragment"] || [stage isEqualToString:@"both"])
			[e setFragmentTexture:texture atIndex:number(t, @"index", 0)];
	}
	for (NSDictionary *s in spec[@"samplers"]) {
		if (!s[@"index"])
			continue;
		NSString *stage = s[@"stage"] ?: @"fragment";
		id<MTLSamplerState> sampler = c.samplers[s[@"name"]];
		if ([stage isEqualToString:@"vertex"] || [stage isEqualToString:@"both"])
			[e setVertexSamplerState:sampler atIndex:number(s, @"index", 0)];
		if ([stage isEqualToString:@"fragment"] || [stage isEqualToString:@"both"])
			[e setFragmentSamplerState:sampler atIndex:number(s, @"index", 0)];
	}
	for (id r in c.resident) {
		if ([r conformsToProtocol:@protocol(MTLResource)])
			[e useResource:r usage:MTLResourceUsageRead | MTLResourceUsageWrite
				stages:MTLRenderStageVertex | MTLRenderStageFragment];
	}
}

/* A stitched function from the plan's graph: each node calls a stitchable
 * library function on the graph's inputs or earlier nodes. */
static id<MTLFunction> stitched_function(Case *c, id<MTLLibrary> library, NSDictionary *g)
{
	NSMutableArray *functions = [NSMutableArray new], *nodes = [NSMutableArray new];
	NSMutableDictionary *named = [NSMutableDictionary new];
	for (NSUInteger i = 0; i < number(g, @"inputs", 0); i++)
		named[[NSString stringWithFormat:@"in%lu", (unsigned long)i]] = [[MTLFunctionStitchingInputNode alloc] initWithArgumentIndex:i];
	for (NSDictionary *n in g[@"nodes"]) {
		id<MTLFunction> f = function_named(library, n[@"function"], nil);
		if (![functions containsObject:f])
			[functions addObject:f];
		NSMutableArray *arguments = [NSMutableArray new];
		for (NSString *a in n[@"args"]) {
			if (!named[a]) @throw failure(@"stitching argument %@ is undefined", a);
			[arguments addObject:named[a]];
		}
		MTLFunctionStitchingFunctionNode *node =
			[[MTLFunctionStitchingFunctionNode alloc] initWithName:n[@"function"] arguments:arguments controlDependencies:@[]];
		named[n[@"id"]] = node;
		[nodes addObject:node];
	}
	MTLFunctionStitchingGraph *graph = [[MTLFunctionStitchingGraph alloc] initWithFunctionName:g[@"name"]
										    nodes:[nodes subarrayWithRange:NSMakeRange(0, nodes.count - 1)]
									       outputNode:nodes.lastObject
									       attributes:@[]];
	MTLStitchedLibraryDescriptor *d = [MTLStitchedLibraryDescriptor new];
	d.functions = functions;
	d.functionGraphs = @[ graph ];
	NSError *error = nil;
	id<MTLLibrary> stitched = [c.device newLibraryWithStitchedDescriptor:d error:&error];
	if (!stitched)
		@throw failure(@"stitched library: %@", error.localizedDescription);
	return function_named(stitched, g[@"name"], nil);
}

/* The device's counter set of a common name: timestamp or statistic. */
static id<MTLCounterSet> counter_set(id<MTLDevice> d, NSString *name)
{
	NSString *common = [name isEqualToString:@"statistic"] ? MTLCommonCounterSetStatistic : MTLCommonCounterSetTimestamp;
	for (id<MTLCounterSet> set in d.counterSets)
		if ([set.name isEqualToString:common])
			return set;
	@throw [NSException exceptionWithName:@"CaseUnsupported" reason:[NSString stringWithFormat:@"no %@ counter set", name] userInfo:nil];
}

/* Once the command buffer completes, the samples resolved into the named
 * buffer: timestamps as sampled, statistics as the counts between each
 * pair of samples. */
static void resolve_counters_after(Case *c, id<MTLCommandBuffer> cb, id<MTLCounterSampleBuffer> samples, NSUInteger count,
				   NSDictionary *spec)
{
	id<MTLBuffer> out = c.buffers[spec[@"buffer"]];
	if (!out)
		@throw failure(@"counters name no buffer %@", spec[@"buffer"]);
	BOOL statistic = [spec[@"counters"] isEqualToString:@"statistic"];
	[cb addCompletedHandler:^(id<MTLCommandBuffer> _) {
		NSData *data = [samples resolveCounterRange:NSMakeRange(0, count)];
		memset(out.contents, 0, out.length);
		if (!statistic) {
			memcpy(out.contents, data.bytes, MIN(data.length, out.length));
			return;
		}
		const MTLCounterResultStatistic *s = data.bytes;
		uint64_t *o = out.contents;
		const NSUInteger fields = sizeof(MTLCounterResultStatistic) / sizeof(uint64_t);
		for (NSUInteger pair = 0; pair + 1 < count && (pair / 2 + 1) * fields * 8 <= out.length; pair += 2) {
			const uint64_t *from = (const uint64_t *)&s[pair], *to = (const uint64_t *)&s[pair + 1];
			for (NSUInteger f = 0; f < fields; f++)
				o[pair / 2 * fields + f] = to[f] - from[f];
		}
	}];
}

/* The named buffer's bytes replaced by a text and zeros after it. */
static void write_text(Case *c, NSString *name, NSString *text)
{
	id<MTLBuffer> out = c.buffers[name];
	if (!out)
		@throw failure(@"text output names no buffer %@", name);
	NSData *bytes = [text dataUsingEncoding:NSUTF8StringEncoding];
	memset(out.contents, 0, out.length);
	memcpy(out.contents, bytes.bytes, MIN(bytes.length, out.length));
}

/* A command buffer, with a log state that collects what its shaders log
 * when the case asks for `log`. */
static id<MTLCommandBuffer> command_buffer(Case *c, id<MTLCommandQueue> queue, NSDictionary *spec, NSMutableArray *lines)
{
	if (!spec[@"log"])
		return [queue commandBuffer];
	if (@available(macOS 15.0, *)) {
		MTLLogStateDescriptor *ld = [MTLLogStateDescriptor new];
		ld.level = MTLLogLevelDebug;
		ld.bufferSize = 65536;
		NSError *error = nil;
		id<MTLLogState> state = [c.device newLogStateWithDescriptor:ld error:&error];
		if (!state)
			@throw failure(@"log state: %@", error.localizedDescription);
		[state addLogHandler:^(NSString *subsystem, NSString *category, MTLLogLevel level, NSString *message) {
			@synchronized(lines) {
				[lines addObject:[NSString stringWithFormat:@"%@ %@ %ld %@", subsystem ?: @"-", category ?: @"-", (long)level, message]];
			}
		}];
		MTLCommandBufferDescriptor *cd = [MTLCommandBufferDescriptor new];
		cd.logState = state;
		return [queue commandBufferWithDescriptor:cd];
	}
	@throw [NSException exceptionWithName:@"CaseUnsupported" reason:@"shader logging needs macOS 15" userInfo:nil];
}

/* The logged lines, once `count` have arrived or two seconds passed, in
 * the order the log handler received them. */
static void store_log(Case *c, NSDictionary *spec, NSMutableArray *lines)
{
	NSUInteger want = number(spec[@"log"], @"lines", 1);
	for (int k = 0; k < 200; k++) {
		@synchronized(lines) {
			if (lines.count >= want)
				break;
		}
		usleep(10000);
	}
	@synchronized(lines) {
		write_text(c, spec[@"log"][@"buffer"], [[lines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"]);
	}
}

/* A pipeline's bindings, one line each in index order within each kind:
 * what an application learns from reflection. */
static NSString *bindings_text(NSArray<id<MTLBinding>> *bindings)
{
	NSMutableArray *lines = [NSMutableArray new];
	NSArray *sorted = [bindings sortedArrayUsingComparator:^NSComparisonResult(id<MTLBinding> a, id<MTLBinding> b) {
		if (a.type != b.type)
			return a.type < b.type ? NSOrderedAscending : NSOrderedDescending;
		return a.index < b.index ? NSOrderedAscending : a.index > b.index ? NSOrderedDescending : NSOrderedSame;
	}];
	for (id<MTLBinding> b in sorted) {
		NSMutableString *line = [NSMutableString stringWithFormat:@"%@ type=%ld index=%lu access=%ld used=%d argument=%d", b.name,
						(long)b.type, (unsigned long)b.index, (long)b.access, b.used, b.argument];
		if ([b conformsToProtocol:@protocol(MTLBufferBinding)]) {
			id<MTLBufferBinding> bb = (id<MTLBufferBinding>)b;
			[line appendFormat:@" size=%lu align=%lu data=%ld", (unsigned long)bb.bufferDataSize, (unsigned long)bb.bufferAlignment,
					   (long)bb.bufferDataType];
			if (bb.bufferStructType)
				for (MTLStructMember *m in bb.bufferStructType.members)
					[line appendFormat:@" %@@%lu:%ld", m.name, (unsigned long)m.offset, (long)m.dataType];
		} else if ([b conformsToProtocol:@protocol(MTLTextureBinding)]) {
			id<MTLTextureBinding> tb = (id<MTLTextureBinding>)b;
			[line appendFormat:@" texture=%ld data=%ld depth=%d array=%lu", (long)tb.textureType, (long)tb.textureDataType,
					   tb.depthTexture, (unsigned long)tb.arrayLength];
		} else if ([b conformsToProtocol:@protocol(MTLThreadgroupBinding)]) {
			id<MTLThreadgroupBinding> gb = (id<MTLThreadgroupBinding>)b;
			[line appendFormat:@" size=%lu align=%lu", (unsigned long)gb.threadgroupMemoryDataSize,
					   (unsigned long)gb.threadgroupMemoryAlignment];
		}
		[lines addObject:line];
	}
	return [lines componentsJoinedByString:@"\n"];
}

static void wait_for(id<MTLCommandBuffer> cb, NSDictionary *spec)
{
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	[cb addCompletedHandler:^(id<MTLCommandBuffer> _) {
		dispatch_semaphore_signal(done);
	}];
	[cb commit];
	double seconds = spec[@"timeout"] ? [spec[@"timeout"] doubleValue] : 20.0;
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC))))
		@throw [NSException exceptionWithName:@"CaseTimeout" reason:@"command buffer did not complete" userInfo:nil];
	if (cb.error)
		@throw failure(@"command buffer: %@", cb.error.localizedDescription);
	if (timing && cb.GPUEndTime > cb.GPUStartTime)
		gpu_seconds += cb.GPUEndTime - cb.GPUStartTime;
}

static id<MTLFence> fence_named(Case *c, NSString *name)
{
	if (!c.fences[name])
		c.fences[name] = [c.device newFence];
	return c.fences[name];
}

/* Waits for a step's fences before its work and updates its fences after. */
static void wait_fences(Case *c, id<MTLCommandEncoder> e, NSDictionary *spec)
{
	for (NSString *name in spec[@"wait_fences"]) {
		if ([e conformsToProtocol:@protocol(MTLComputeCommandEncoder)])
			[(id<MTLComputeCommandEncoder>)e waitForFence:fence_named(c, name)];
		else if ([e conformsToProtocol:@protocol(MTLBlitCommandEncoder)])
			[(id<MTLBlitCommandEncoder>)e waitForFence:fence_named(c, name)];
		else
			[(id<MTLRenderCommandEncoder>)e waitForFence:fence_named(c, name) beforeStages:MTLRenderStageVertex];
	}
}

static void update_fences(Case *c, id<MTLCommandEncoder> e, NSDictionary *spec)
{
	for (NSString *name in spec[@"update_fences"]) {
		if ([e conformsToProtocol:@protocol(MTLComputeCommandEncoder)])
			[(id<MTLComputeCommandEncoder>)e updateFence:fence_named(c, name)];
		else if ([e conformsToProtocol:@protocol(MTLBlitCommandEncoder)])
			[(id<MTLBlitCommandEncoder>)e updateFence:fence_named(c, name)];
		else
			[(id<MTLRenderCommandEncoder>)e updateFence:fence_named(c, name) afterStages:MTLRenderStageFragment];
	}
}

/* Encodes a compute step into cb, or into `open` when the step continues
 * the previous compute encoder; returns the encoder, still open. */
static id<MTLComputeCommandEncoder> encode_compute(Case *c, id<MTLCommandBuffer> cb, id<MTLComputeCommandEncoder> open,
						    id<MTLLibrary> library, NSDictionary *spec)
{
	id<MTLFunction> function = function_named(library, spec[@"function"], spec[@"constants"]);
	MTLComputePipelineDescriptor *d = [MTLComputePipelineDescriptor new];
	d.computeFunction = function;
	d.supportIndirectCommandBuffers = [spec[@"supports_icb"] boolValue];
	if (spec[@"preload"])
		d.preloadedLibraries = preloaded(c, spec[@"preload"]);
	if (spec[@"stage_input"]) {
		/* Compute stage-in: attributes fetched by grid position. */
		MTLStageInputOutputDescriptor *si = [MTLStageInputOutputDescriptor stageInputOutputDescriptor];
		for (NSDictionary *a in spec[@"stage_input"][@"attributes"]) {
			MTLAttributeDescriptor *ad = si.attributes[number(a, @"index", 0)];
			ad.format = (MTLAttributeFormat)lookup(vertex_formats(), @"attribute format", a[@"format"]);
			ad.offset = number(a, @"offset", 0);
			ad.bufferIndex = number(a, @"buffer", 0);
		}
		NSDictionary *steps = @{@"grid_x" : @(MTLStepFunctionThreadPositionInGridX), @"grid_y" : @(MTLStepFunctionThreadPositionInGridY),
					@"constant" : @(MTLStepFunctionConstant)};
		for (NSDictionary *l in spec[@"stage_input"][@"layouts"]) {
			MTLBufferLayoutDescriptor *ld = si.layouts[number(l, @"buffer", 0)];
			ld.stride = number(l, @"stride", 16);
			ld.stepFunction = lookup(steps, @"step function", l[@"step"] ?: @"grid_x");
			ld.stepRate = number(l, @"rate", 1);
		}
		d.stageInputDescriptor = si;
	}
	NSMutableArray *linked = [NSMutableArray new];
	for (NSString *name in spec[@"visible_functions"])
		[linked addObject:function_named(library, name, nil)];
	/* Visible functions compiled to binaries on their own, then linked. */
	NSMutableArray *binaries = [NSMutableArray new];
	for (NSString *name in spec[@"binary_functions"]) {
		MTLFunctionDescriptor *fd = [MTLFunctionDescriptor functionDescriptor];
		fd.name = name;
		fd.options = MTLFunctionOptionCompileToBinary;
		NSError *error = nil;
		id<MTLFunction> f = [library newFunctionWithDescriptor:fd error:&error];
		if (!f)
			@throw failure(@"binary function %@: %@", name, error.localizedDescription);
		[binaries addObject:f];
		[linked addObject:f];
	}
	NSMutableDictionary *stitched = [NSMutableDictionary new];
	for (NSDictionary *g in spec[@"stitched"]) {
		id<MTLFunction> f = stitched_function(c, library, g);
		stitched[g[@"name"]] = f;
		[linked addObject:f];
	}
	if (linked.count) {
		MTLLinkedFunctions *l = [MTLLinkedFunctions new];
		NSMutableArray *source = [linked mutableCopy];
		[source removeObjectsInArray:binaries];
		l.functions = source;
		l.binaryFunctions = binaries;
		d.linkedFunctions = l;
	}
	NSError *error = nil;
	MTLComputePipelineReflection *reflection = nil;
	id<MTLComputePipelineState> pipeline = [c.device newComputePipelineStateWithDescriptor:d
										       options:spec[@"reflection"] ? MTLPipelineOptionBindingInfo | MTLPipelineOptionBufferTypeInfo : MTLPipelineOptionNone
										    reflection:spec[@"reflection"] ? &reflection : nil
											 error:&error];
	if (!pipeline)
		@throw failure(@"compute pipeline: %@", error.localizedDescription);
	if (spec[@"reflection"])
		write_text(c, spec[@"reflection"], [NSString stringWithFormat:@"%@\nstatic_threadgroup_memory=%lu\n",
								    bindings_text(reflection.bindings),
								    (unsigned long)pipeline.staticThreadgroupMemoryLength]);
	id<MTLComputeCommandEncoder> e = open;
	/* A barrier between dispatches of one encoder, scoped as named. */
	if (e && spec[@"barrier"]) {
		NSString *b = spec[@"barrier"];
		MTLBarrierScope scope = ([b containsString:@"buffers"] ? MTLBarrierScopeBuffers : 0) |
					([b containsString:@"textures"] ? MTLBarrierScopeTextures : 0);
		[e memoryBarrierWithScope:scope];
	}
	if (!e && [spec[@"concurrent"] boolValue])
		e = [cb computeCommandEncoderWithDispatchType:MTLDispatchTypeConcurrent];
	if (!e && spec[@"timestamps"]) {
		/* Samples at the start and end of the encoder's work. */
		MTLCounterSampleBufferDescriptor *sd = [MTLCounterSampleBufferDescriptor new];
		sd.counterSet = counter_set(c.device, spec[@"timestamps"][@"counters"] ?: @"timestamp");
		sd.sampleCount = 2;
		sd.storageMode = MTLStorageModeShared;
		id<MTLCounterSampleBuffer> samples = [c.device newCounterSampleBufferWithDescriptor:sd error:&error];
		if (!samples)
			@throw failure(@"counter sample buffer: %@", error.localizedDescription);
		MTLComputePassDescriptor *cp = [MTLComputePassDescriptor computePassDescriptor];
		cp.sampleBufferAttachments[0].sampleBuffer = samples;
		cp.sampleBufferAttachments[0].startOfEncoderSampleIndex = 0;
		cp.sampleBufferAttachments[0].endOfEncoderSampleIndex = 1;
		resolve_counters_after(c, cb, samples, 2, spec[@"timestamps"]);
		e = [cb computeCommandEncoderWithDescriptor:cp];
	}
	e = e ?: [cb computeCommandEncoder];
	if (!open)
		wait_fences(c, e, spec);
	[e setComputePipelineState:pipeline];
	bind_compute(c, e, spec);
	for (NSDictionary *table in spec[@"function_tables"]) {
		MTLVisibleFunctionTableDescriptor *td = [MTLVisibleFunctionTableDescriptor new];
		NSArray *names = table[@"functions"];
		td.functionCount = names.count;
		id<MTLVisibleFunctionTable> vft = [pipeline newVisibleFunctionTableWithDescriptor:td];
		if (!vft)
			@throw failure(@"visible function table creation failed");
		for (NSUInteger i = 0; i < names.count; i++) {
			id<MTLFunction> f = stitched[names[i]] ?: nil;
			if (!f) {
				for (id<MTLFunction> l in linked)
					if ([l.name isEqualToString:names[i]]) f = l;
			}
			id<MTLFunctionHandle> handle = [pipeline functionHandleWithFunction:f];
			if (!handle)
				@throw failure(@"no function handle for %@", names[i]);
			[vft setFunction:handle atIndex:i];
		}
		[e setVisibleFunctionTable:vft atBufferIndex:number(table, @"index", 0)];
	}
	NSArray *grid = spec[@"grid"] ?: @[ @1, @1, @1 ], *group = spec[@"threadgroup"] ?: @[ @64, @1, @1 ];
	MTLSize g = MTLSizeMake([grid[0] unsignedIntegerValue], [grid[1] unsignedIntegerValue], [grid[2] unsignedIntegerValue]);
	MTLSize t = MTLSizeMake([group[0] unsignedIntegerValue], [group[1] unsignedIntegerValue], [group[2] unsignedIntegerValue]);
	if (spec[@"execute_icb"]) {
		NSDictionary *x = spec[@"execute_icb"];
		for (id r in c.resident)
			if ([r conformsToProtocol:@protocol(MTLResource)])
				[e useResource:r usage:MTLResourceUsageRead | MTLResourceUsageWrite];
		for (NSString *name in spec[@"use"])
			[e useResource:c.buffers[name] usage:MTLResourceUsageRead | MTLResourceUsageWrite];
		[e executeCommandsInBuffer:c.icbs[x[@"icb"]] withRange:NSMakeRange(number(x, @"start", 0), number(x, @"count", 1))];
	} else if (spec[@"indirect"]) {
		NSDictionary *i = spec[@"indirect"];
		if (spec[@"stage_input"])
			[e setStageInRegion:MTLRegionMake3D(0, 0, 0, g.width, g.height, g.depth)];
		[e dispatchThreadgroupsWithIndirectBuffer:c.buffers[i[@"buffer"]] indirectBufferOffset:number(i, @"offset", 0)
				    threadsPerThreadgroup:t];
	} else if ([spec[@"dispatch"] isEqualToString:@"threads"]) {
		if (spec[@"stage_input"])
			[e setStageInRegion:MTLRegionMake3D(0, 0, 0, g.width, g.height, g.depth)];
		[e dispatchThreads:g threadsPerThreadgroup:t];
	} else {
		[e dispatchThreadgroups:MTLSizeMake((g.width + t.width - 1) / t.width, (g.height + t.height - 1) / t.height,
						    (g.depth + t.depth - 1) / t.depth)
		  threadsPerThreadgroup:t];
	}
	return e;
}

static void run_compute(Case *c, id<MTLCommandQueue> queue, id<MTLLibrary> library, NSDictionary *spec)
{
	NSMutableArray *lines = [NSMutableArray new];
	id<MTLCommandBuffer> cb = command_buffer(c, queue, spec, lines);
	if (spec[@"residency_set"]) {
		/* The named buffers resident through a residency set alone. */
		if (@available(macOS 15.0, *)) {
			NSError *error = nil;
			id<MTLResidencySet> set = [c.device newResidencySetWithDescriptor:[MTLResidencySetDescriptor new] error:&error];
			if (!set)
				@throw failure(@"residency set: %@", error.localizedDescription);
			for (NSString *name in spec[@"residency_set"])
				[set addAllocation:c.buffers[name]];
			[set commit];
			[set requestResidency];
			[cb useResidencySet:set];
		} else {
			@throw [NSException exceptionWithName:@"CaseUnsupported" reason:@"residency sets need macOS 15" userInfo:nil];
		}
	}
	id<MTLComputeCommandEncoder> e = encode_compute(c, cb, nil, library, spec);
	update_fences(c, e, spec);
	[e endEncoding];
	wait_for(cb, spec);
	if (spec[@"log"])
		store_log(c, spec, lines);
}

static void encode_render(Case *c, id<MTLCommandBuffer> cb, id<MTLLibrary> library, NSDictionary *spec)
{
	NSDictionary *r = spec[@"render"];
	MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
	NSDictionary *mesh = r[@"mesh"];
	if (!mesh)
		d.vertexFunction = function_named(library, spec[@"vertex"], spec[@"constants"]);
	d.maxVertexAmplificationCount = number(r[@"amplification"], @"count", 1);
	if (r[@"preload"]) {
		d.vertexPreloadedLibraries = preloaded(c, r[@"preload"]);
		d.fragmentPreloadedLibraries = d.vertexPreloadedLibraries;
	}
	NSMutableArray *fragment_linked = [NSMutableArray new];
	for (NSString *name in r[@"fragment_visible_functions"])
		[fragment_linked addObject:function_named(library, name, nil)];
	if (fragment_linked.count) {
		MTLLinkedFunctions *l = [MTLLinkedFunctions new];
		l.functions = fragment_linked;
		d.fragmentLinkedFunctions = l;
	}
	if (spec[@"fragment"])
		d.fragmentFunction = function_named(library, spec[@"fragment"], spec[@"constants"]);
	d.rasterSampleCount = number(r, @"samples", 1);
	d.alphaToCoverageEnabled = [r[@"alpha_to_coverage"] boolValue];
	d.alphaToOneEnabled = [r[@"alpha_to_one"] boolValue];
	d.supportIndirectCommandBuffers = [r[@"supports_icb"] boolValue];
	NSDictionary *tess = r[@"tessellation"];
	if (tess) {
		NSDictionary *modes = @{@"pow2" : @(MTLTessellationPartitionModePow2), @"integer" : @(MTLTessellationPartitionModeInteger),
					@"fractional_odd" : @(MTLTessellationPartitionModeFractionalOdd),
					@"fractional_even" : @(MTLTessellationPartitionModeFractionalEven)};
		d.tessellationPartitionMode = lookup(modes, @"partition mode", tess[@"partition"] ?: @"integer");
		d.maxTessellationFactor = number(tess, @"max_factor", 16);
		/* Instances read their own factors only when the draw gives them a
		 * stride. */
		d.tessellationFactorStepFunction = tess[@"instance_stride"] ? MTLTessellationFactorStepFunctionPerPatchAndPerInstance
									    : MTLTessellationFactorStepFunctionPerPatch;
		d.tessellationOutputWindingOrder = [tess[@"winding"] isEqualToString:@"cw"] ? MTLWindingClockwise : MTLWindingCounterClockwise;
		d.tessellationFactorFormat = MTLTessellationFactorFormatHalf;
	}
	if (r[@"rasterize"] && ![r[@"rasterize"] boolValue])
		d.rasterizationEnabled = NO;
	if (r[@"input_primitive"]) {
		NSDictionary *topologies = @{@"point" : @(MTLPrimitiveTopologyClassPoint), @"line" : @(MTLPrimitiveTopologyClassLine),
					     @"triangle" : @(MTLPrimitiveTopologyClassTriangle)};
		d.inputPrimitiveTopology = lookup(topologies, @"primitive class", r[@"input_primitive"]);
	}
	if (r[@"vertex_descriptor"]) {
		MTLVertexDescriptor *v = [MTLVertexDescriptor vertexDescriptor];
		for (NSDictionary *a in r[@"vertex_descriptor"][@"attributes"]) {
			MTLVertexAttributeDescriptor *ad = v.attributes[number(a, @"index", 0)];
			ad.format = lookup(vertex_formats(), @"vertex format", a[@"format"]);
			ad.offset = number(a, @"offset", 0);
			ad.bufferIndex = number(a, @"buffer", 0);
		}
		for (NSDictionary *l in r[@"vertex_descriptor"][@"layouts"]) {
			MTLVertexBufferLayoutDescriptor *ld = v.layouts[number(l, @"buffer", 0)];
			ld.stride = number(l, @"stride", 16);
			NSString *step = l[@"step"] ?: @"vertex";
			ld.stepFunction = [step isEqualToString:@"instance"] ? MTLVertexStepFunctionPerInstance :
					  [step isEqualToString:@"constant"] ? MTLVertexStepFunctionConstant :
					  [step isEqualToString:@"patch"] ? MTLVertexStepFunctionPerPatch :
					  [step isEqualToString:@"patch_control_point"] ? MTLVertexStepFunctionPerPatchControlPoint :
									       MTLVertexStepFunctionPerVertex;
			ld.stepRate = [step isEqualToString:@"constant"] ? 0 : number(l, @"rate", 1);
		}
		d.vertexDescriptor = v;
	}
	MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
	if (r[@"sample_positions"]) {
		NSArray *list = r[@"sample_positions"];
		MTLSamplePosition positions[16];
		NSUInteger count = MIN(list.count, (NSUInteger)16);
		for (NSUInteger k = 0; k < count; k++)
			positions[k] = MTLSamplePositionMake([list[k][0] floatValue], [list[k][1] floatValue]);
		[pass setSamplePositions:positions count:count];
	}
	NSArray *colors = r[@"colors"] ?: @[];
	if (r[@"visibility"])
		pass.visibilityResultBuffer = c.buffers[r[@"visibility"][@"buffer"]];
	if (r[@"timestamps"]) {
		/* Timestamps at the start and end of the vertex and fragment
		 * stages, resolved after the pass into the named buffer. */
		MTLCounterSampleBufferDescriptor *sd = [MTLCounterSampleBufferDescriptor new];
		sd.counterSet = counter_set(c.device, r[@"timestamps"][@"counters"] ?: @"timestamp");
		sd.sampleCount = 4;
		sd.storageMode = MTLStorageModeShared;
		NSError *error = nil;
		id<MTLCounterSampleBuffer> samples = [c.device newCounterSampleBufferWithDescriptor:sd error:&error];
		if (!samples)
			@throw failure(@"counter sample buffer: %@", error.localizedDescription);
		MTLRenderPassSampleBufferAttachmentDescriptor *sa = pass.sampleBufferAttachments[0];
		sa.sampleBuffer = samples;
		sa.startOfVertexSampleIndex = 0;
		sa.endOfVertexSampleIndex = 1;
		sa.startOfFragmentSampleIndex = 2;
		sa.endOfFragmentSampleIndex = 3;
		resolve_counters_after(c, cb, samples, 4, r[@"timestamps"]);
	}
	if (r[@"target_size"]) {
		pass.renderTargetWidth = [r[@"target_size"][0] unsignedIntegerValue];
		pass.renderTargetHeight = [r[@"target_size"][1] unsignedIntegerValue];
		pass.defaultRasterSampleCount = number(r, @"samples", 1);
	}
	for (NSUInteger i = 0; i < colors.count; i++) {
		NSDictionary *a = colors[i];
		id<MTLTexture> t = c.textures[a[@"texture"]];
		if (!t) @throw failure(@"color attachment %lu names no texture", (unsigned long)i);
		MTLRenderPipelineColorAttachmentDescriptor *pa = d.colorAttachments[i];
		pa.pixelFormat = t.pixelFormat;
		NSDictionary *blend = a[@"blend"];
		if (blend) {
			pa.blendingEnabled = YES;
			pa.rgbBlendOperation = lookup(blend_operations(), @"blend operation", blend[@"rgb"] ?: @"add");
			pa.alphaBlendOperation = lookup(blend_operations(), @"blend operation", blend[@"alpha"] ?: @"add");
			pa.sourceRGBBlendFactor = lookup(blend_factors(), @"blend factor", blend[@"src_rgb"] ?: @"one");
			pa.destinationRGBBlendFactor = lookup(blend_factors(), @"blend factor", blend[@"dst_rgb"] ?: @"zero");
			pa.sourceAlphaBlendFactor = lookup(blend_factors(), @"blend factor", blend[@"src_alpha"] ?: @"one");
			pa.destinationAlphaBlendFactor = lookup(blend_factors(), @"blend factor", blend[@"dst_alpha"] ?: @"zero");
		}
		if (a[@"write_mask"]) {
			MTLColorWriteMask mask = 0;
			NSString *m = a[@"write_mask"];
			if ([m containsString:@"r"]) mask |= MTLColorWriteMaskRed;
			if ([m containsString:@"g"]) mask |= MTLColorWriteMaskGreen;
			if ([m containsString:@"b"]) mask |= MTLColorWriteMaskBlue;
			if ([m containsString:@"a"]) mask |= MTLColorWriteMaskAlpha;
			pa.writeMask = mask;
		}
		MTLRenderPassColorAttachmentDescriptor *ca = pass.colorAttachments[i];
		ca.texture = t;
		/* One level, slice or 3D plane of the texture. */
		ca.level = number(a, @"level", 0);
		ca.slice = number(a, @"slice", 0);
		ca.depthPlane = number(a, @"depth_plane", 0);
		ca.resolveLevel = number(a, @"resolve_level", 0);
		ca.resolveSlice = number(a, @"resolve_slice", 0);
		/* An array target is layered, the vertex function picking the
		 * slice, unless the attachment names one. */
		if ((t.textureType == MTLTextureType2DArray || t.textureType == MTLTextureType2DMultisampleArray) && !a[@"slice"])
			pass.renderTargetArrayLength = t.arrayLength;
		NSArray *clear = a[@"clear"];
		ca.loadAction = clear ? MTLLoadActionClear : MTLLoadActionLoad;
		if (clear)
			ca.clearColor = MTLClearColorMake([clear[0] doubleValue], [clear[1] doubleValue], [clear[2] doubleValue], [clear[3] doubleValue]);
		ca.storeAction = MTLStoreActionStore;
		if (a[@"resolve"]) {
			ca.resolveTexture = c.textures[a[@"resolve"]];
			ca.storeAction = [a[@"store"] isEqualToString:@"resolve"] ? MTLStoreActionMultisampleResolve
										   : MTLStoreActionStoreAndMultisampleResolve;
		}
	}
	MTLDepthStencilDescriptor *ds = [MTLDepthStencilDescriptor new];
	if (r[@"depth"]) {
		NSDictionary *a = r[@"depth"];
		id<MTLTexture> t = c.textures[a[@"texture"]];
		d.depthAttachmentPixelFormat = t.pixelFormat;
		pass.depthAttachment.texture = t;
		pass.depthAttachment.loadAction = a[@"clear"] ? MTLLoadActionClear : MTLLoadActionLoad;
		pass.depthAttachment.clearDepth = [a[@"clear"] doubleValue];
		pass.depthAttachment.storeAction = MTLStoreActionStore;
		if (a[@"resolve"]) {
			NSDictionary *filters = @{@"sample0" : @(MTLMultisampleDepthResolveFilterSample0),
						  @"min" : @(MTLMultisampleDepthResolveFilterMin), @"max" : @(MTLMultisampleDepthResolveFilterMax)};
			pass.depthAttachment.resolveTexture = c.textures[a[@"resolve"]];
			pass.depthAttachment.depthResolveFilter = lookup(filters, @"depth resolve filter", a[@"resolve_filter"] ?: @"sample0");
			pass.depthAttachment.storeAction = MTLStoreActionStoreAndMultisampleResolve;
		}
		ds.depthCompareFunction = lookup(compare_functions(), @"compare function", a[@"compare"] ?: @"always");
		ds.depthWriteEnabled = a[@"write"] ? [a[@"write"] boolValue] : YES;
	}
	if (r[@"stencil"]) {
		NSDictionary *a = r[@"stencil"];
		id<MTLTexture> t = c.textures[a[@"texture"]];
		d.stencilAttachmentPixelFormat = t.pixelFormat;
		pass.stencilAttachment.texture = t;
		pass.stencilAttachment.loadAction = a[@"clear"] ? MTLLoadActionClear : MTLLoadActionLoad;
		pass.stencilAttachment.clearStencil = (uint32_t)number(a, @"clear", 0);
		pass.stencilAttachment.storeAction = MTLStoreActionStore;
		if (a[@"resolve"]) {
			NSDictionary *filters = @{@"sample0" : @(MTLMultisampleStencilResolveFilterSample0),
						  @"depth_resolved" : @(MTLMultisampleStencilResolveFilterDepthResolvedSample)};
			pass.stencilAttachment.resolveTexture = c.textures[a[@"resolve"]];
			pass.stencilAttachment.stencilResolveFilter = lookup(filters, @"stencil resolve filter", a[@"resolve_filter"] ?: @"sample0");
			pass.stencilAttachment.storeAction = MTLStoreActionStoreAndMultisampleResolve;
		}
		for (NSString *face in @[ @"front", @"back" ]) {
			MTLStencilDescriptor *s = [MTLStencilDescriptor new];
			NSDictionary *f = a[face] ?: a;
			s.stencilCompareFunction = lookup(compare_functions(), @"compare function", f[@"compare"] ?: @"always");
			s.stencilFailureOperation = lookup(stencil_operations(), @"stencil operation", f[@"fail"] ?: @"keep");
			s.depthFailureOperation = lookup(stencil_operations(), @"stencil operation", f[@"depth_fail"] ?: @"keep");
			s.depthStencilPassOperation = lookup(stencil_operations(), @"stencil operation", f[@"pass"] ?: @"keep");
			s.readMask = (uint32_t)number(f, @"read_mask", 0xff);
			s.writeMask = (uint32_t)number(f, @"write_mask", 0xff);
			if ([face isEqualToString:@"front"]) ds.frontFaceStencil = s;
			else ds.backFaceStencil = s;
		}
	}
	NSError *error = nil;
	id<MTLRenderPipelineState> pipeline;
	if (mesh) {
		/* Object (optional) and mesh functions in place of a vertex
		 * function, with the same attachments and fragment function. */
		MTLMeshRenderPipelineDescriptor *m = [MTLMeshRenderPipelineDescriptor new];
		if (mesh[@"object"])
			m.objectFunction = function_named(library, mesh[@"object"], spec[@"constants"]);
		m.meshFunction = function_named(library, mesh[@"mesh"], spec[@"constants"]);
		m.fragmentFunction = d.fragmentFunction;
		m.rasterSampleCount = d.rasterSampleCount;
		m.alphaToCoverageEnabled = d.alphaToCoverageEnabled;
		for (NSUInteger i = 0; i < colors.count; i++)
			m.colorAttachments[i] = d.colorAttachments[i];
		m.depthAttachmentPixelFormat = d.depthAttachmentPixelFormat;
		m.stencilAttachmentPixelFormat = d.stencilAttachmentPixelFormat;
		m.maxTotalThreadsPerObjectThreadgroup = number(mesh, @"max_object_threads", 0);
		m.maxTotalThreadsPerMeshThreadgroup = number(mesh, @"max_mesh_threads", 0);
		pipeline = [c.device newRenderPipelineStateWithMeshDescriptor:m options:MTLPipelineOptionNone reflection:nil error:&error];
	} else if (spec[@"reflection"]) {
		MTLRenderPipelineReflection *reflection = nil;
		pipeline = [c.device newRenderPipelineStateWithDescriptor:d options:MTLPipelineOptionBindingInfo | MTLPipelineOptionBufferTypeInfo
							       reflection:&reflection error:&error];
		if (pipeline)
			write_text(c, spec[@"reflection"], [NSString stringWithFormat:@"vertex\n%@\nfragment\n%@\n",
									    bindings_text(reflection.vertexBindings),
									    bindings_text(reflection.fragmentBindings)]);
	} else {
		pipeline = [c.device newRenderPipelineStateWithDescriptor:d error:&error];
	}
	if (!pipeline)
		@throw failure(@"render pipeline: %@", error.localizedDescription);
	id<MTLDepthStencilState> depth_stencil = [c.device newDepthStencilStateWithDescriptor:ds];
	/* Everything an encoder of this pass records, from `spec` and its
	 * bindings: once, or once per sub-encoder of a parallel encoder. */
	void (^encode)(id<MTLRenderCommandEncoder>, NSDictionary *) = ^(id<MTLRenderCommandEncoder> e, NSDictionary *spec) {
	wait_fences(c, e, spec);
	[e setRenderPipelineState:pipeline];
	[e setDepthStencilState:depth_stencil];
	if (r[@"stencil"]) {
		uint32_t front = (uint32_t)number(r[@"stencil"], @"reference", 0);
		[e setStencilFrontReferenceValue:front backReferenceValue:(uint32_t)number(r[@"stencil"], @"reference_back", front)];
	}
	if (r[@"depth_bias"]) {
		NSArray *b = r[@"depth_bias"];
		[e setDepthBias:[b[0] floatValue] slopeScale:[b[1] floatValue] clamp:[b[2] floatValue]];
	}
	if ([r[@"depth_clip"] isEqualToString:@"clamp"])
		[e setDepthClipMode:MTLDepthClipModeClamp];
	if ([r[@"fill"] isEqualToString:@"lines"])
		[e setTriangleFillMode:MTLTriangleFillModeLines];
	if (r[@"blend_color"]) {
		NSArray *b = r[@"blend_color"];
		[e setBlendColorRed:[b[0] floatValue] green:[b[1] floatValue] blue:[b[2] floatValue] alpha:[b[3] floatValue]];
	}
	NSString *cull = r[@"cull"] ?: @"none";
	[e setCullMode:[cull isEqualToString:@"front"] ? MTLCullModeFront : [cull isEqualToString:@"back"] ? MTLCullModeBack : MTLCullModeNone];
	[e setFrontFacingWinding:[r[@"winding"] isEqualToString:@"cw"] ? MTLWindingClockwise : MTLWindingCounterClockwise];
	if (r[@"viewport"]) {
		NSArray *v = r[@"viewport"];
		[e setViewport:(MTLViewport){[v[0] doubleValue], [v[1] doubleValue], [v[2] doubleValue], [v[3] doubleValue], 0.0, 1.0}];
	}
	if (r[@"viewports"]) {
		NSArray *list = r[@"viewports"];
		MTLViewport viewports[16];
		NSUInteger count = MIN(list.count, (NSUInteger)16);
		for (NSUInteger k = 0; k < count; k++) {
			NSArray *v = list[k];
			viewports[k] = (MTLViewport){[v[0] doubleValue], [v[1] doubleValue], [v[2] doubleValue], [v[3] doubleValue], 0.0, 1.0};
		}
		[e setViewports:viewports count:count];
	}
	if (r[@"scissor"]) {
		NSArray *s = r[@"scissor"];
		[e setScissorRect:(MTLScissorRect){[s[0] unsignedIntegerValue], [s[1] unsignedIntegerValue], [s[2] unsignedIntegerValue], [s[3] unsignedIntegerValue]}];
	}
	bind_render(c, e, spec);
	for (NSDictionary *table in r[@"fragment_tables"]) {
		MTLVisibleFunctionTableDescriptor *td = [MTLVisibleFunctionTableDescriptor new];
		NSArray *names = table[@"functions"];
		td.functionCount = names.count;
		id<MTLVisibleFunctionTable> vft = [pipeline newVisibleFunctionTableWithDescriptor:td stage:MTLRenderStageFragment];
		if (!vft)
			@throw failure(@"fragment visible function table creation failed");
		for (NSUInteger i = 0; i < names.count; i++) {
			id<MTLFunction> f = nil;
			for (id<MTLFunction> l in fragment_linked)
				if ([l.name isEqualToString:names[i]]) f = l;
			id<MTLFunctionHandle> handle = [pipeline functionHandleWithFunction:f stage:MTLRenderStageFragment];
			if (!handle)
				@throw failure(@"no fragment function handle for %@", names[i]);
			[vft setFunction:handle atIndex:i];
		}
		[e setFragmentVisibleFunctionTable:vft atBufferIndex:number(table, @"index", 0)];
	}
	for (NSString *name in spec[@"use_heaps"])
		[e useHeap:c.heaps[name] stages:MTLRenderStageVertex | MTLRenderStageFragment];
	NSDictionary *primitives = @{@"point" : @(MTLPrimitiveTypePoint), @"line" : @(MTLPrimitiveTypeLine),
				     @"line_strip" : @(MTLPrimitiveTypeLineStrip), @"triangle" : @(MTLPrimitiveTypeTriangle),
				     @"triangle_strip" : @(MTLPrimitiveTypeTriangleStrip)};
	MTLPrimitiveType primitive = lookup(primitives, @"primitive", r[@"primitive"] ?: @"triangle");
	NSUInteger base_instance = number(r, @"base_instance", 0);
	if (r[@"amplification"]) {
		/* Each view's offsets into the viewports and target layers. */
		NSArray *list = r[@"amplification"][@"mappings"] ?: @[];
		MTLVertexAmplificationViewMapping mappings[8];
		NSUInteger count = MIN(list.count, (NSUInteger)8);
		for (NSUInteger k = 0; k < count; k++)
			mappings[k] = (MTLVertexAmplificationViewMapping){[list[k][0] unsignedIntValue], [list[k][1] unsignedIntValue]};
		[e setVertexAmplificationCount:number(r[@"amplification"], @"count", 1) viewMappings:count ? mappings : NULL];
	}
	if (mesh) {
		NSArray *g = mesh[@"threadgroups"] ?: @[ @1 ], *o = mesh[@"object_threads"] ?: @[ @1 ], *t = mesh[@"mesh_threads"] ?: @[ @1 ];
		MTLSize (^size)(NSArray *) = ^(NSArray *a) {
			return MTLSizeMake([a[0] unsignedIntegerValue], a.count > 1 ? [a[1] unsignedIntegerValue] : 1,
					   a.count > 2 ? [a[2] unsignedIntegerValue] : 1);
		};
		[e drawMeshThreadgroups:size(g) threadsPerObjectThreadgroup:size(o) threadsPerMeshThreadgroup:size(t)];
	} else if (tess) {
		/* Factors per patch, and per instance at a stride; patches by
		 * index buffer and draws from an indirect buffer when named. */
		[e setTessellationFactorBuffer:c.buffers[tess[@"factors"]] offset:0
				instanceStride:number(tess, @"instance_stride", 0)];
		id<MTLBuffer> index = tess[@"patch_index"] ? c.buffers[tess[@"patch_index"]] : nil;
		NSUInteger points = number(tess, @"control_points", 4);
		if (tess[@"indirect"])
			[e drawPatches:points patchIndexBuffer:index patchIndexBufferOffset:0
				indirectBuffer:c.buffers[tess[@"indirect"]] indirectBufferOffset:0];
		else
			[e drawPatches:points patchStart:number(tess, @"patch_start", 0)
				patchCount:number(tess, @"patch_count", 1) patchIndexBuffer:index patchIndexBufferOffset:0
			     instanceCount:number(tess, @"instance_count", 1) baseInstance:0];
	} else if (r[@"execute_icb"]) {
		NSDictionary *x = r[@"execute_icb"];
		for (id res in c.resident)
			if ([res conformsToProtocol:@protocol(MTLResource)])
				[e useResource:res usage:MTLResourceUsageRead stages:MTLRenderStageVertex | MTLRenderStageFragment];
		for (NSString *name in spec[@"use"])
			[e useResource:c.buffers[name] usage:MTLResourceUsageRead stages:MTLRenderStageVertex | MTLRenderStageFragment];
		[e executeCommandsInBuffer:c.icbs[x[@"icb"]] withRange:NSMakeRange(number(x, @"start", 0), number(x, @"count", 1))];
	} else if (r[@"indirect"]) {
		NSDictionary *i = r[@"indirect"];
		if (r[@"index_buffer"])
			[e drawIndexedPrimitives:primitive indexType:[r[@"index_type"] isEqualToString:@"uint32"] ? MTLIndexTypeUInt32 : MTLIndexTypeUInt16
				     indexBuffer:c.buffers[r[@"index_buffer"]] indexBufferOffset:number(r, @"index_offset", 0)
				  indirectBuffer:c.buffers[i[@"buffer"]] indirectBufferOffset:number(i, @"offset", 0)];
		else
			[e drawPrimitives:primitive indirectBuffer:c.buffers[i[@"buffer"]] indirectBufferOffset:number(i, @"offset", 0)];
	} else if (r[@"draws"]) {
		/* Several draws, each counted into its own visibility result. */
		NSDictionary *modes = @{@"boolean" : @(MTLVisibilityResultModeBoolean), @"counting" : @(MTLVisibilityResultModeCounting),
					@"disabled" : @(MTLVisibilityResultModeDisabled)};
		for (NSDictionary *draw in r[@"draws"]) {
			if (r[@"visibility"])
				[e setVisibilityResultMode:lookup(modes, @"visibility mode", r[@"visibility"][@"mode"] ?: @"counting")
						    offset:number(draw, @"visibility_offset", 0)];
			[e drawPrimitives:primitive vertexStart:number(draw, @"vertex_start", 0) vertexCount:number(draw, @"vertex_count", 3)
			    instanceCount:number(draw, @"instance_count", 1) baseInstance:base_instance];
		}
	} else if (r[@"index_buffer"]) {
		id<MTLBuffer> indices = c.buffers[r[@"index_buffer"]];
		BOOL wide = [r[@"index_type"] isEqualToString:@"uint32"];
		[e drawIndexedPrimitives:primitive indexCount:number(r, @"vertex_count", 3)
			       indexType:wide ? MTLIndexTypeUInt32 : MTLIndexTypeUInt16 indexBuffer:indices
			 indexBufferOffset:number(r, @"index_offset", 0) instanceCount:number(r, @"instance_count", 1)
			      baseVertex:[r[@"base_vertex"] integerValue] baseInstance:base_instance];
	} else {
		[e drawPrimitives:primitive vertexStart:number(r, @"vertex_start", 0) vertexCount:number(r, @"vertex_count", 3)
		    instanceCount:number(r, @"instance_count", 1) baseInstance:base_instance];
	}
	update_fences(c, e, spec);
	[e endEncoding];
	};
	NSArray *parts = r[@"parallel"];
	if (parts) {
		/* Each part's bindings replace the step's; the parts' encoders
		 * execute in the order they were created. */
		id<MTLParallelRenderCommandEncoder> pe = [cb parallelRenderCommandEncoderWithDescriptor:pass];
		NSMutableArray *encoders = [NSMutableArray new];
		for (NSUInteger k = 0; k < parts.count; k++)
			[encoders addObject:[pe renderCommandEncoder]];
		/* Recorded last part first: order comes from creation alone. */
		for (NSUInteger k = parts.count; k-- > 0;) {
			NSMutableDictionary *part = [spec mutableCopy];
			[part addEntriesFromDictionary:parts[k]];
			encode(encoders[k], part);
		}
		[pe endEncoding];
	} else {
		encode([cb renderCommandEncoderWithDescriptor:pass], spec);
	}
}

static void run_render(Case *c, id<MTLCommandQueue> queue, id<MTLLibrary> library, NSDictionary *spec)
{
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	encode_render(c, cb, library, spec);
	wait_for(cb, spec);
}

static MTLSize size_of(NSArray *a)
{
	return MTLSizeMake([a[0] unsignedIntegerValue], a.count > 1 ? [a[1] unsignedIntegerValue] : 1,
			   a.count > 2 ? [a[2] unsignedIntegerValue] : 1);
}

static MTLOrigin origin_of(NSArray *a)
{
	if (!a) return MTLOriginMake(0, 0, 0);
	return MTLOriginMake([a[0] unsignedIntegerValue], a.count > 1 ? [a[1] unsignedIntegerValue] : 0,
			     a.count > 2 ? [a[2] unsignedIntegerValue] : 0);
}

static void encode_blits(Case *c, id<MTLCommandBuffer> cb, NSDictionary *spec)
{
	id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
	wait_fences(c, e, spec);
	for (NSDictionary *op in spec[@"blits"]) {
		NSString *kind = op[@"op"];
		if ([kind isEqualToString:@"copy_buffer"]) {
			[e copyFromBuffer:c.buffers[op[@"src"]] sourceOffset:number(op, @"src_offset", 0)
				 toBuffer:c.buffers[op[@"dst"]] destinationOffset:number(op, @"dst_offset", 0)
				     size:number(op, @"size", 0)];
		} else if ([kind isEqualToString:@"fill_buffer"]) {
			[e fillBuffer:c.buffers[op[@"dst"]] range:NSMakeRange(number(op, @"offset", 0), number(op, @"size", 0))
				value:(uint8_t)number(op, @"value", 0)];
		} else if ([kind isEqualToString:@"buffer_to_texture"]) {
			[e copyFromBuffer:c.buffers[op[@"src"]] sourceOffset:number(op, @"src_offset", 0)
			     sourceBytesPerRow:number(op, @"bytes_per_row", 0) sourceBytesPerImage:number(op, @"bytes_per_image", 0)
				    sourceSize:size_of(op[@"size"]) toTexture:c.textures[op[@"dst"]]
			      destinationSlice:number(op, @"slice", 0) destinationLevel:number(op, @"level", 0)
			     destinationOrigin:origin_of(op[@"origin"])];
		} else if ([kind isEqualToString:@"texture_to_buffer"]) {
			[e copyFromTexture:c.textures[op[@"src"]] sourceSlice:number(op, @"slice", 0) sourceLevel:number(op, @"level", 0)
				 sourceOrigin:origin_of(op[@"origin"]) sourceSize:size_of(op[@"size"])
				     toBuffer:c.buffers[op[@"dst"]] destinationOffset:number(op, @"dst_offset", 0)
			    destinationBytesPerRow:number(op, @"bytes_per_row", 0)
			  destinationBytesPerImage:number(op, @"bytes_per_image", 0)];
		} else if ([kind isEqualToString:@"copy_texture"]) {
			[e copyFromTexture:c.textures[op[@"src"]] sourceSlice:number(op, @"src_slice", 0)
				   sourceLevel:number(op, @"src_level", 0) sourceOrigin:origin_of(op[@"src_origin"])
				    sourceSize:size_of(op[@"size"]) toTexture:c.textures[op[@"dst"]]
			      destinationSlice:number(op, @"dst_slice", 0) destinationLevel:number(op, @"dst_level", 0)
			     destinationOrigin:origin_of(op[@"dst_origin"])];
		} else if ([kind isEqualToString:@"buffer_to_texture_plane"]) {
			/* One plane of a depth-stencil texture, chosen by aspect. */
			id<MTLTexture> t = c.textures[op[@"dst"]];
			[e copyFromBuffer:c.buffers[op[@"src"]] sourceOffset:number(op, @"src_offset", 0)
			     sourceBytesPerRow:number(op, @"bytes_per_row", 0) sourceBytesPerImage:number(op, @"bytes_per_image", 0)
				    sourceSize:size_of(op[@"size"]) toTexture:t destinationSlice:number(op, @"slice", 0)
			      destinationLevel:number(op, @"level", 0) destinationOrigin:origin_of(op[@"origin"])
				       options:blit_option(t.pixelFormat, op[@"aspect"])];
		} else if ([kind isEqualToString:@"texture_to_buffer_plane"]) {
			id<MTLTexture> t = c.textures[op[@"src"]];
			[e copyFromTexture:t sourceSlice:number(op, @"slice", 0) sourceLevel:number(op, @"level", 0)
				 sourceOrigin:origin_of(op[@"origin"]) sourceSize:size_of(op[@"size"])
				     toBuffer:c.buffers[op[@"dst"]] destinationOffset:number(op, @"dst_offset", 0)
			    destinationBytesPerRow:number(op, @"bytes_per_row", 0)
			  destinationBytesPerImage:number(op, @"bytes_per_image", 0)
					   options:blit_option(t.pixelFormat, op[@"aspect"])];
		} else if ([kind isEqualToString:@"copy_whole_texture"]) {
			[e copyFromTexture:c.textures[op[@"src"]] toTexture:c.textures[op[@"dst"]]];
		} else if ([kind isEqualToString:@"copy_slices"]) {
			[e copyFromTexture:c.textures[op[@"src"]] sourceSlice:number(op, @"src_slice", 0)
				   sourceLevel:number(op, @"src_level", 0) toTexture:c.textures[op[@"dst"]]
			      destinationSlice:number(op, @"dst_slice", 0) destinationLevel:number(op, @"dst_level", 0)
				    sliceCount:number(op, @"slices", 1) levelCount:number(op, @"levels", 1)];
		} else if ([kind isEqualToString:@"optimize_gpu_access"]) {
			[e optimizeContentsForGPUAccess:c.textures[op[@"texture"]]];
		} else if ([kind isEqualToString:@"optimize_cpu_access"]) {
			[e optimizeContentsForCPUAccess:c.textures[op[@"texture"]]];
		} else if ([kind isEqualToString:@"generate_mipmaps"]) {
			[e generateMipmapsForTexture:c.textures[op[@"texture"]]];
		} else if ([kind isEqualToString:@"reset_icb"]) {
			[e resetCommandsInBuffer:c.icbs[op[@"icb"]] withRange:NSMakeRange(number(op, @"start", 0), number(op, @"count", 1))];
		} else if ([kind isEqualToString:@"optimize_icb"]) {
			[e optimizeIndirectCommandBuffer:c.icbs[op[@"icb"]] withRange:NSMakeRange(number(op, @"start", 0), number(op, @"count", 1))];
		} else if ([kind isEqualToString:@"copy_icb"]) {
			[e copyIndirectCommandBuffer:c.icbs[op[@"src"]] sourceRange:NSMakeRange(number(op, @"start", 0), number(op, @"count", 1))
					 destination:c.icbs[op[@"dst"]] destinationIndex:number(op, @"dst_start", 0)];
		} else {
			@throw failure(@"unknown blit %@", kind);
		}
	}
	update_fences(c, e, spec);
	[e endEncoding];
}

static void run_blits(Case *c, id<MTLCommandQueue> queue, NSDictionary *spec)
{
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	encode_blits(c, cb, spec);
	wait_for(cb, spec);
}

static id<MTLEvent> event_named(Case *c, NSString *name)
{
	if (!c.events[name])
		c.events[name] = [c.device newSharedEvent];
	return c.events[name];
}

/* Records, per command buffer in commit order, when it was scheduled and
 * completed, for checking the order a queue keeps. */
@interface Handlers : NSObject
@property(retain) NSMutableArray<NSNumber *> *completed;
@property NSUInteger scheduled;
@property BOOL scheduled_first;
@end
@implementation Handlers
@end

/* Steps of compute, render and blit work over the case's resources, in one
 * command buffer unless a step starts a new one. A compute step may
 * continue the previous compute encoder; a step may wait for and update
 * fences, and wait for or signal an event's value between encoders. Every
 * command buffer is committed in order and the last one waited for. */
static void run_sequence(Case *c, id<MTLCommandQueue> queue, NSDictionary *plan, NSDictionary *spec,
			 NSMutableDictionary *libraries)
{
	/* Steps run on the case's queue or on others it creates by index;
	 * command buffers retain their resources unless `unretained`. */
	NSMutableDictionary<NSNumber *, id<MTLCommandQueue>> *queues = [NSMutableDictionary dictionaryWithObject:queue forKey:@0];
	BOOL unretained = [spec[@"unretained"] boolValue];
	Handlers *handlers = [Handlers new];
	handlers.completed = [NSMutableArray new];
	handlers.scheduled_first = YES;
	__block NSUInteger committed = 0;
	id<MTLCommandBuffer> (^make)(id<MTLCommandQueue>) = ^(id<MTLCommandQueue> q) {
		id<MTLCommandBuffer> b = unretained ? [q commandBufferWithUnretainedReferences] : [q commandBuffer];
		NSUInteger k = committed++;
		if (spec[@"handlers"]) {
			[b addScheduledHandler:^(id<MTLCommandBuffer> _) {
				@synchronized(handlers) {
					handlers.scheduled++;
				}
			}];
			[b addCompletedHandler:^(id<MTLCommandBuffer> _) {
				@synchronized(handlers) {
					if (handlers.scheduled < handlers.completed.count + 1)
						handlers.scheduled_first = NO;
					[handlers.completed addObject:@(k)];
				}
			}];
		}
		return b;
	};
	NSNumber *on = @0;
	id<MTLCommandBuffer> cb = make(queue);
	id<MTLComputeCommandEncoder> open = nil;
	NSDictionary *open_step = nil;
	for (NSDictionary *step in spec[@"steps"]) {
		NSString *kind = step[@"kind"];
		BOOL continues = [kind isEqualToString:@"compute"] && [step[@"continue"] boolValue] && open;
		if (open && !continues) {
			update_fences(c, open, open_step);
			[open endEncoding];
			open = nil;
		}
		NSNumber *wanted = step[@"queue"] ?: @0;
		if (!queues[wanted])
			queues[wanted] = [c.device newCommandQueue];
		if ([step[@"new_command_buffer"] boolValue] || ![wanted isEqual:on]) {
			[cb commit];
			on = wanted;
			cb = make(queues[on]);
		}
		for (NSArray *w in step[@"wait_events"])
			[cb encodeWaitForEvent:event_named(c, w[0]) value:[w[1] unsignedLongLongValue]];
		id<MTLLibrary> library = nil;
		if (![kind isEqualToString:@"blit"])
			library = library_named(c.device, plan, step[@"library"] ?: spec[@"library"], libraries);
		if ([kind isEqualToString:@"compute"]) {
			open = encode_compute(c, cb, continues ? open : nil, library, step);
			open_step = step;
		} else if ([kind isEqualToString:@"render"]) {
			encode_render(c, cb, library, step);
		} else if ([kind isEqualToString:@"blit"]) {
			encode_blits(c, cb, step);
		} else {
			@throw failure(@"unknown step kind %@", kind);
		}
		if (step[@"signal_events"] && open) {
			update_fences(c, open, open_step);
			[open endEncoding];
			open = nil;
		}
		for (NSArray *s in step[@"signal_events"])
			[cb encodeSignalEvent:event_named(c, s[0]) value:[s[1] unsignedLongLongValue]];
	}
	if (open) {
		update_fences(c, open, open_step);
		[open endEncoding];
	}
	/* Values the host signals once everything is committed, after a
	 * delay, so the GPU's waits for them are real. */
	NSArray *host = spec[@"host_signals"];
	for (NSArray *h in host)
		event_named(c, h[0]);
	if (host.count)
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
			for (NSArray *h in host)
				((id<MTLSharedEvent>)c.events[h[0]]).signaledValue = [h[1] unsignedLongLongValue];
		});
	/* Listeners the host registers for values the GPU signals. */
	MTLSharedEventListener *listener = nil;
	NSMutableSet *heard = [NSMutableSet new];
	for (NSArray *l in spec[@"listen"]) {
		listener = listener ?: [[MTLSharedEventListener alloc] initWithDispatchQueue:dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0)];
		id<MTLSharedEvent> event = (id<MTLSharedEvent>)event_named(c, l[0]);
		NSString *name = l[2];
		[event notifyListener:listener atValue:[l[1] unsignedLongLongValue] block:^(id<MTLSharedEvent> e, uint64_t value) {
			@synchronized(heard) {
				[heard addObject:name];
			}
		}];
	}
	wait_for(cb, spec);
	for (NSArray *l in spec[@"listen"]) {
		BOOL got = NO;
		for (int k = 0; k < 200 && !got; k++) {
			@synchronized(heard) {
				got = [heard containsObject:l[2]];
			}
			if (!got)
				usleep(10000);
		}
		uint32_t *out = c.buffers[l[2]].contents;
		out[0] = got;
		out[1] = (uint32_t)((id<MTLSharedEvent>)c.events[l[0]]).signaledValue;
	}
	if (spec[@"handlers"]) {
		/* Completion in commit order, each after its scheduling, and the
		 * last buffer's final status. */
		for (int k = 0; k < 200; k++) {
			@synchronized(handlers) {
				if (handlers.completed.count == committed)
					break;
			}
			usleep(10000);
		}
		uint32_t *out = c.buffers[spec[@"handlers"]].contents;
		@synchronized(handlers) {
			for (NSUInteger k = 0; k < handlers.completed.count && k < 8; k++)
				out[k] = handlers.completed[k].unsignedIntValue;
			out[8] = handlers.scheduled_first;
			out[9] = (uint32_t)cb.status;
		}
	}
}

static void store_outputs(Case *c, id<MTLCommandQueue> queue, NSDictionary *spec)
{
	timing = NO;
	for (NSDictionary *o in spec[@"outputs"]) {
		NSString *name = o[@"name"];
		NSString *path = [c.dir stringByAppendingPathComponent:[(o[@"as"] ?: name) stringByAppendingString:@".bin"]];
		if (c.buffers[name]) {
			id<MTLBuffer> b = c.buffers[name], shared = b;
			if (b.storageMode == MTLStorageModePrivate)
				shared = [c.device newBufferWithLength:b.length options:MTLResourceStorageModeShared];
			if (b.storageMode != MTLStorageModeShared)
				blit_now(c, ^(id<MTLBlitCommandEncoder> e) {
					if (shared != b)
						[e copyFromBuffer:b sourceOffset:0 toBuffer:shared destinationOffset:0 size:b.length];
					else
						[e synchronizeResource:b];
				});
			NSUInteger length = number(o, @"length", b.length);
			[[NSData dataWithBytes:shared.contents length:MIN(length, b.length)] writeToFile:path atomically:YES];
			continue;
		}
		id<MTLTexture> t = c.textures[name];
		if (!t)
			@throw failure(@"output %@ is neither a buffer nor a texture", name);
		NSUInteger total;
		NSArray *regions = regions_of(t, o[@"aspect"], &total);
		if (t.storageMode != MTLStorageModePrivate && !t.buffer) {
			/* Read back by the CPU, after a synchronization when managed. */
			if (t.storageMode == MTLStorageModeManaged)
				blit_now(c, ^(id<MTLBlitCommandEncoder> e) {
					[e synchronizeResource:t];
				});
			NSMutableData *out = [NSMutableData dataWithLength:total];
			for (NSValue *v in regions) {
				struct region r;
				[v getValue:&r];
				[t getBytes:(uint8_t *)out.mutableBytes + r.offset bytesPerRow:r.bytes_per_row bytesPerImage:r.bytes_per_image
				 fromRegion:MTLRegionMake3D(0, 0, 0, r.size.width, r.size.height, r.size.depth) mipmapLevel:r.level slice:r.slice];
			}
			[out writeToFile:path atomically:YES];
			continue;
		}
		id<MTLBuffer> staging = [c.device newBufferWithLength:MAX(total, 16) options:MTLResourceStorageModeShared];
		id<MTLCommandBuffer> cb = [queue commandBuffer];
		id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
		for (NSValue *v in regions) {
			struct region r;
			[v getValue:&r];
			[e copyFromTexture:t sourceSlice:r.slice sourceLevel:r.level sourceOrigin:MTLOriginMake(0, 0, 0)
				 sourceSize:r.size toBuffer:staging destinationOffset:r.offset
			    destinationBytesPerRow:r.bytes_per_row destinationBytesPerImage:r.bytes_per_image
					   options:blit_option(t.pixelFormat, o[@"aspect"])];
		}
		[e endEncoding];
		wait_for(cb, spec);
		[[NSData dataWithBytes:staging.contents length:total] writeToFile:path atomically:YES];
	}
}


static NSDictionary<NSString *, NSNumber *> *gpu_families(void)
{
	return @{
		@"apple1" : @(MTLGPUFamilyApple1), @"apple2" : @(MTLGPUFamilyApple2), @"apple3" : @(MTLGPUFamilyApple3),
		@"apple4" : @(MTLGPUFamilyApple4), @"apple5" : @(MTLGPUFamilyApple5), @"apple6" : @(MTLGPUFamilyApple6),
		@"apple7" : @(MTLGPUFamilyApple7), @"apple8" : @(MTLGPUFamilyApple8), @"apple9" : @(MTLGPUFamilyApple9),
		@"apple10" : @(MTLGPUFamilyApple10), @"mac2" : @(MTLGPUFamilyMac2), @"common1" : @(MTLGPUFamilyCommon1),
		@"common2" : @(MTLGPUFamilyCommon2), @"common3" : @(MTLGPUFamilyCommon3), @"metal3" : @(MTLGPUFamilyMetal3),
		@"metal4" : @(MTLGPUFamilyMetal4),
	};
}

/* Whether the device has a feature a case names; nil for a name the runner
 * does not know, which is an error in the plan. */
static BOOL has_counter_set(id<MTLDevice> d, NSString *name)
{
	for (id<MTLCounterSet> set in d.counterSets)
		if ([set.name isEqualToString:name])
			return YES;
	return NO;
}

static BOOL logging_available(void)
{
	if (@available(macOS 15.0, *))
		return YES;
	return NO;
}

static NSNumber *feature(id<MTLDevice> d, NSString *name)
{
	if ([name hasPrefix:@"samples"])
		return @([d supportsTextureSampleCount:(NSUInteger)[[name substringFromIndex:7] integerValue]]);
	NSDictionary *t = @{
		@"function_pointers" : @(d.supportsFunctionPointers),
		@"function_pointers_render" : @(d.supportsFunctionPointersFromRender),
		@"raytracing" : @(d.supportsRaytracing),
		@"dynamic_libraries" : @(d.supportsDynamicLibraries),
		@"render_dynamic_libraries" : @(d.supportsRenderDynamicLibraries),
		@"float32_filtering" : @(d.supports32BitFloatFiltering),
		@"float32_msaa" : @(d.supports32BitMSAA),
		@"bc_compression" : @(d.supportsBCTextureCompression),
		@"query_texture_lod" : @(d.supportsQueryTextureLOD),
		@"barycentrics" : @(d.supportsShaderBarycentricCoordinates),
		@"pull_model_interpolation" : @(d.supportsPullModelInterpolation),
		@"raster_order_groups" : @(d.rasterOrderGroupsSupported),
		@"programmable_sample_positions" : @(d.programmableSamplePositionsSupported),
		@"depth24_stencil8" : @(d.depth24Stencil8PixelFormatSupported),
		@"argument_buffers_tier2" : @(d.argumentBuffersSupport >= MTLArgumentBuffersTier2),
		@"read_write_textures_tier2" : @(d.readWriteTextureSupport >= MTLReadWriteTextureTier2),
		@"primitive_motion_blur" : @(d.supportsPrimitiveMotionBlur),
		@"vertex_amplification2" : @([d supportsVertexAmplificationCount:2]),
		@"simd_reduction" : @([d supportsFamily:MTLGPUFamilyApple7] || [d supportsFamily:MTLGPUFamilyMac2]),
		@"counters_stage_boundary" : @([d supportsCounterSampling:MTLCounterSamplingPointAtStageBoundary]),
		@"counter_set_timestamp" : @(has_counter_set(d, MTLCommonCounterSetTimestamp)),
		@"counter_set_statistic" : @(has_counter_set(d, MTLCommonCounterSetStatistic)),
		@"logging" : @(logging_available()),
	};
	return t[name];
}

/* The case's unmet requirements, or nil when the device has them all. */
static NSString *unmet(id<MTLDevice> d, NSDictionary *requires)
{
	NSMutableArray *missing = [NSMutableArray new];
	for (NSString *family in requires[@"families"]) {
		if (![d supportsFamily:lookup(gpu_families(), @"GPU family", family)])
			[missing addObject:family];
	}
	for (NSString *name in requires[@"features"]) {
		NSNumber *has = feature(d, name);
		if (!has)
			@throw failure(@"unknown feature %@", name);
		if (!has.boolValue)
			[missing addObject:name];
	}
	return missing.count ? [missing componentsJoinedByString:@", "] : nil;
}

/* Every capability query MTLDevice answers, for comparing what two
 * devices claim. */
static NSDictionary *device_properties(id<MTLDevice> d)
{
	NSMutableDictionary *p = [NSMutableDictionary new];
	NSMutableDictionary *families = [NSMutableDictionary new];
	[gpu_families() enumerateKeysAndObjectsUsingBlock:^(NSString *k, NSNumber *v, BOOL *stop) {
		families[k] = @([d supportsFamily:v.integerValue]);
	}];
	p[@"families"] = families;
	NSMutableDictionary *features = [NSMutableDictionary new];
	for (NSString *name in @[ @"function_pointers", @"function_pointers_render", @"raytracing", @"dynamic_libraries",
				   @"render_dynamic_libraries", @"float32_filtering", @"float32_msaa", @"bc_compression",
				   @"query_texture_lod", @"barycentrics", @"pull_model_interpolation", @"raster_order_groups",
				   @"programmable_sample_positions", @"depth24_stencil8", @"argument_buffers_tier2",
				   @"read_write_textures_tier2", @"primitive_motion_blur", @"vertex_amplification2",
				   @"samples1", @"samples2", @"samples4", @"samples8", @"samples16" ])
		features[name] = feature(d, name);
	p[@"features"] = features;
	MTLSize tg = d.maxThreadsPerThreadgroup;
	p[@"limits"] = @{
		@"max_threads_per_threadgroup" : @[ @(tg.width), @(tg.height), @(tg.depth) ],
		@"max_threadgroup_memory" : @(d.maxThreadgroupMemoryLength),
		@"max_buffer_length" : @(d.maxBufferLength),
		@"max_argument_buffer_samplers" : @(d.maxArgumentBufferSamplerCount),
		@"recommended_max_working_set" : @(d.recommendedMaxWorkingSetSize),
		@"sparse_tile_bytes" : @(d.sparseTileSizeInBytes),
		@"argument_buffers_tier" : @(d.argumentBuffersSupport),
		@"read_write_texture_tier" : @(d.readWriteTextureSupport),
		@"max_transfer_rate" : @(d.maxTransferRate),
		@"linear_texture_alignment_rgba8" : @([d minimumLinearTextureAlignmentForPixelFormat:MTLPixelFormatRGBA8Unorm]),
		@"linear_texture_alignment_rgba32f" : @([d minimumLinearTextureAlignmentForPixelFormat:MTLPixelFormatRGBA32Float]),
		@"texture_buffer_alignment_r8" : @([d minimumTextureBufferAlignmentForPixelFormat:MTLPixelFormatR8Unorm]),
	};
	p[@"identity"] = @{
		@"name" : d.name, @"unified_memory" : @(d.hasUnifiedMemory), @"low_power" : @(d.isLowPower),
		@"headless" : @(d.isHeadless), @"removable" : @(d.isRemovable), @"location" : @(d.location),
		@"architecture" : d.architecture.name ?: @"",
	};
	NSMutableDictionary *positions = [NSMutableDictionary new];
	for (NSUInteger count = 2; count <= 8; count *= 2) {
		if (![d supportsTextureSampleCount:count])
			continue;
		MTLSamplePosition sp[16];
		[d getDefaultSamplePositions:sp count:count];
		NSMutableArray *list = [NSMutableArray new];
		for (NSUInteger i = 0; i < count; i++)
			[list addObject:@[ @(sp[i].x), @(sp[i].y) ]];
		positions[[NSString stringWithFormat:@"%lu", (unsigned long)count]] = list;
	}
	p[@"sample_positions"] = positions;
	return p;
}

/* An indirect command buffer of dispatches or draws, and the commands the
 * CPU encodes into it. A draw command inherits its pipeline from the
 * executing encoder; a dispatch names its function or inherits too. */
static id<MTLIndirectCommandBuffer> make_icb(Case *c, NSDictionary *b)
{
	MTLIndirectCommandBufferDescriptor *d = [MTLIndirectCommandBufferDescriptor new];
	BOOL draw = [b[@"type"] isEqualToString:@"draw"];
	d.commandTypes = draw ? MTLIndirectCommandTypeDraw | MTLIndirectCommandTypeDrawIndexed
			      : MTLIndirectCommandTypeConcurrentDispatch | MTLIndirectCommandTypeConcurrentDispatchThreads;
	/* Draws inherit the executing encoder's pipeline unless told not to;
	 * their commands then set their own. */
	d.inheritPipelineState = b[@"inherit_pipeline"] ? [b[@"inherit_pipeline"] boolValue] : draw;
	d.inheritBuffers = [b[@"inherit_buffers"] boolValue];
	NSUInteger bindings = number(b, @"max_buffers", 8);
	if (draw) {
		d.maxVertexBufferBindCount = bindings;
		d.maxFragmentBufferBindCount = bindings;
	} else {
		d.maxKernelBufferBindCount = bindings;
	}
	id<MTLIndirectCommandBuffer> icb = [c.device newIndirectCommandBufferWithDescriptor:d
									 maxCommandCount:number(b, @"count", 1)
										 options:0];
	if (!icb)
		@throw failure(@"indirect command buffer %@ creation failed", b[@"name"]);
	icb.label = b[@"name"];
	[c.resident addObject:icb];
	NSArray *commands = b[@"commands"] ?: @[];
	for (NSUInteger k = 0; k < commands.count; k++) {
		NSDictionary *command = commands[k];
		if (draw) {
			id<MTLIndirectRenderCommand> r = [icb indirectRenderCommandAtIndex:k];
			for (NSDictionary *u in command[@"buffers"]) {
				id<MTLBuffer> buffer = c.buffers[u[@"name"]];
				[c.resident addObject:buffer];
				if ([u[@"stage"] isEqualToString:@"vertex"])
					[r setVertexBuffer:buffer offset:number(u, @"offset", 0) atIndex:number(u, @"index", 0)];
				else
					[r setFragmentBuffer:buffer offset:number(u, @"offset", 0) atIndex:number(u, @"index", 0)];
			}
			NSDictionary *primitives = @{@"point" : @(MTLPrimitiveTypePoint), @"triangle" : @(MTLPrimitiveTypeTriangle),
						     @"triangle_strip" : @(MTLPrimitiveTypeTriangleStrip)};
			MTLPrimitiveType primitive = lookup(primitives, @"primitive", command[@"primitive"] ?: @"triangle");
			if (command[@"indices"]) {
				id<MTLBuffer> indices = c.buffers[command[@"indices"]];
				[c.resident addObject:indices];
				[r drawIndexedPrimitives:primitive indexCount:number(command, @"index_count", 3)
					       indexType:[command[@"index_type"] isEqualToString:@"uint32"] ? MTLIndexTypeUInt32 : MTLIndexTypeUInt16
					     indexBuffer:indices indexBufferOffset:number(command, @"index_offset", 0)
					   instanceCount:number(command, @"instance_count", 1)
					      baseVertex:[command[@"base_vertex"] integerValue]
					    baseInstance:number(command, @"base_instance", 0)];
			} else {
				[r drawPrimitives:primitive vertexStart:number(command, @"vertex_start", 0)
				      vertexCount:number(command, @"vertex_count", 3)
				    instanceCount:number(command, @"instance_count", 1)
				     baseInstance:number(command, @"base_instance", 0)];
			}
		} else {
			id<MTLIndirectComputeCommand> k_ = [icb indirectComputeCommandAtIndex:k];
			if (command[@"function"]) {
				id<MTLLibrary> library = library_named(c.device, c.plan, c.spec[@"library"], c.libraries);
				MTLComputePipelineDescriptor *pd = [MTLComputePipelineDescriptor new];
				pd.computeFunction = function_named(library, command[@"function"], nil);
				pd.supportIndirectCommandBuffers = YES;
				NSError *error = nil;
				id<MTLComputePipelineState> pipeline = [c.device newComputePipelineStateWithDescriptor:pd
												      options:MTLPipelineOptionNone
												   reflection:nil
													error:&error];
				if (!pipeline)
					@throw failure(@"indirect compute pipeline: %@", error.localizedDescription);
				/* The command buffer does not retain its pipelines. */
				[c.resident addObject:pipeline];
				[k_ setComputePipelineState:pipeline];
			}
			for (NSDictionary *u in command[@"buffers"]) {
				id<MTLBuffer> buffer = c.buffers[u[@"name"]];
				[c.resident addObject:buffer];
				[k_ setKernelBuffer:buffer offset:number(u, @"offset", 0) atIndex:number(u, @"index", 0)];
			}
			NSArray *g = command[@"threadgroups"] ?: @[ @1 ], *t = command[@"threadgroup"] ?: @[ @64 ];
			MTLSize groups = MTLSizeMake([g[0] unsignedIntegerValue], g.count > 1 ? [g[1] unsignedIntegerValue] : 1,
						     g.count > 2 ? [g[2] unsignedIntegerValue] : 1);
			MTLSize threads = MTLSizeMake([t[0] unsignedIntegerValue], t.count > 1 ? [t[1] unsignedIntegerValue] : 1,
						      t.count > 2 ? [t[2] unsignedIntegerValue] : 1);
			[k_ concurrentDispatchThreadgroups:groups threadsPerThreadgroup:threads];
			/* The command waits for every earlier command of the buffer. */
			if ([command[@"barrier"] boolValue])
				[k_ setBarrier];
		}
	}
	return icb;
}

/* Work Apple's frameworks encode with their own shaders: an MPS matrix
 * product and box filter, and a Core Image filter, each over the case's
 * resources. */
static void run_framework(Case *c, id<MTLCommandQueue> queue, NSDictionary *spec)
{
	NSDictionary *f = spec[@"framework"];
	NSString *kind = f[@"kind"];
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	if ([kind hasPrefix:@"mps"] && !MPSSupportsMTLDevice(c.device))
		@throw [NSException exceptionWithName:@"CaseUnsupported" reason:@"MPS does not support the device" userInfo:nil];
	if ([kind isEqualToString:@"mps_matrix_multiply"]) {
		NSUInteger m = number(f, @"rows", 1), n = number(f, @"columns", 1), k = number(f, @"interior", 1);
		MPSMatrix *(^matrix)(NSString *, NSUInteger, NSUInteger) = ^(NSString *name, NSUInteger rows, NSUInteger columns) {
			MPSMatrixDescriptor *d = [MPSMatrixDescriptor matrixDescriptorWithRows:rows columns:columns
										  rowBytes:columns * sizeof(float)
										  dataType:MPSDataTypeFloat32];
			return [[MPSMatrix alloc] initWithBuffer:c.buffers[name] descriptor:d];
		};
		MPSMatrixMultiplication *mm = [[MPSMatrixMultiplication alloc] initWithDevice:c.device transposeLeft:NO transposeRight:NO
										   resultRows:m resultColumns:n interiorColumns:k
											alpha:1.0 beta:0.0];
		[mm encodeToCommandBuffer:cb leftMatrix:matrix(@"a", m, k) rightMatrix:matrix(@"b", k, n) resultMatrix:matrix(@"c", m, n)];
	} else if ([kind isEqualToString:@"mps_image_box"]) {
		MPSImageBox *box = [[MPSImageBox alloc] initWithDevice:c.device kernelWidth:3 kernelHeight:3];
		box.edgeMode = MPSImageEdgeModeClamp;
		[box encodeToCommandBuffer:cb sourceTexture:c.textures[@"in"] destinationTexture:c.textures[@"out"]];
	} else if ([kind isEqualToString:@"core_image_invert"]) {
		/* No colour management: the filter sees the texels as stored. */
		CIContext *context = [CIContext contextWithMTLDevice:c.device
							     options:@{kCIContextWorkingColorSpace : [NSNull null],
								       kCIContextOutputColorSpace : [NSNull null]}];
		CIImage *image = [CIImage imageWithMTLTexture:c.textures[@"in"] options:@{kCIImageColorSpace : [NSNull null]}];
		CIFilter *invert = [CIFilter filterWithName:@"CIColorInvert"];
		[invert setValue:image forKey:kCIInputImageKey];
		id<MTLTexture> out = c.textures[@"out"];
		/* A null output space skips colour matching, though the header marks it nonnull. */
		CGColorSpaceRef unmatched = NULL;
		[context render:invert.outputImage toMTLTexture:out commandBuffer:cb
			 bounds:CGRectMake(0, 0, out.width, out.height) colorSpace:unmatched];
	} else {
		@throw failure(@"unknown framework work %@", kind);
	}
	wait_for(cb, spec);
}

/*
 * Host work around the device: drawables of a layer, IOSurface-backed
 * textures, textures and events another process opens, binary archives,
 * the errors creation calls report, command buffer status and order,
 * purgeable state, and work at scale. Each writes what it observed into
 * the case's buffers as plain numbers; the plan holds the expectations.
 */
static void put(Case *c, NSString *buffer, NSUInteger index, uint32_t value)
{
	id<MTLBuffer> b = c.buffers[buffer];
	if (!b || (index + 1) * sizeof(uint32_t) > b.length)
		@throw failure(@"no room for observation %lu in %@", (unsigned long)index, buffer);
	((uint32_t *)b.contents)[index] = value;
}

static id<MTLComputePipelineState> host_pipeline(Case *c, NSString *function)
{
	id<MTLLibrary> library = library_named(c.device, c.plan, c.spec[@"library"], c.libraries);
	NSError *error = nil;
	id<MTLComputePipelineState> p = [c.device newComputePipelineStateWithFunction:function_named(library, function, nil)
										error:&error];
	if (!p)
		@throw failure(@"pipeline %@: %@", function, error.localizedDescription);
	return p;
}

static void dispatch_one(id<MTLComputeCommandEncoder> e, id<MTLComputePipelineState> p, NSArray<id<MTLBuffer>> *buffers,
			 uint32_t constant, MTLSize threads)
{
	[e setComputePipelineState:p];
	for (NSUInteger i = 0; i < buffers.count; i++)
		[e setBuffer:buffers[i] offset:0 atIndex:i];
	[e setBytes:&constant length:sizeof constant atIndex:buffers.count];
	[e dispatchThreads:threads threadsPerThreadgroup:MTLSizeMake(MIN(threads.width, 64), 1, 1)];
}

static id<MTLRenderPipelineState> host_render_pipeline(Case *c, MTLRenderPipelineDescriptor *d, NSString *vertex,
						       NSString *fragment, MTLPixelFormat format, NSError **error)
{
	id<MTLLibrary> library = library_named(c.device, c.plan, c.spec[@"library"], c.libraries);
	d.vertexFunction = function_named(library, vertex, nil);
	d.fragmentFunction = function_named(library, fragment, nil);
	d.colorAttachments[0].pixelFormat = format;
	return [c.device newRenderPipelineStateWithDescriptor:d error:error];
}

/* Clears a target, then draws its left half in `color`. */
static void clear_and_draw_left(Case *c, id<MTLCommandBuffer> cb, id<MTLRenderPipelineState> p, id<MTLTexture> t,
				NSArray *clear, NSArray *color)
{
	MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
	pass.colorAttachments[0].texture = t;
	pass.colorAttachments[0].loadAction = MTLLoadActionClear;
	pass.colorAttachments[0].storeAction = MTLStoreActionStore;
	pass.colorAttachments[0].clearColor =
		MTLClearColorMake([clear[0] doubleValue], [clear[1] doubleValue], [clear[2] doubleValue], [clear[3] doubleValue]);
	id<MTLRenderCommandEncoder> e = [cb renderCommandEncoderWithDescriptor:pass];
	float rgba[4] = {[color[0] floatValue], [color[1] floatValue], [color[2] floatValue], [color[3] floatValue]};
	[e setRenderPipelineState:p];
	[e setFragmentBytes:rgba length:sizeof rgba atIndex:0];
	[e drawPrimitives:MTLPrimitiveTypeTriangleStrip vertexStart:0 vertexCount:4];
	[e endEncoding];
}

/* Drawables of a layer in no window: each rendered, read back unless the
 * layer is framebuffer only, and presented. */
static void host_drawables(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	MTLPixelFormat format = lookup(pixel_formats(), @"pixel format", h[@"format"]);
	NSUInteger w = number(h, @"width", 1), height = number(h, @"height", 1), count = number(h, @"count", 1), block = 1;
	BOOL framebuffer_only = [h[@"framebuffer_only"] boolValue];
	CAMetalLayer *layer = [CAMetalLayer layer];
	layer.device = c.device;
	layer.pixelFormat = format;
	layer.framebufferOnly = framebuffer_only;
	layer.drawableSize = CGSizeMake(w, height);
	layer.maximumDrawableCount = 3;
	NSError *error = nil;
	id<MTLRenderPipelineState> p =
		host_render_pipeline(c, [MTLRenderPipelineDescriptor new], @"vert_left_half", @"frag_constant", format, &error);
	if (!p)
		@throw failure(@"drawable pipeline: %@", error.localizedDescription);
	NSUInteger texel = pixel_bytes(format, &block), image = w * height * texel;
	for (NSUInteger i = 0; i < count; i++) {
		id<CAMetalDrawable> drawable = [layer nextDrawable];
		if (!drawable)
			@throw failure(@"no drawable %lu", (unsigned long)i);
		id<MTLTexture> t = drawable.texture;
		NSUInteger at = i * 5;
		put(c, @"props", at, (uint32_t)t.width);
		put(c, @"props", at + 1, (uint32_t)t.height);
		put(c, @"props", at + 2, (uint32_t)t.pixelFormat);
		put(c, @"props", at + 3, (t.usage & MTLTextureUsageRenderTarget) != 0);
		put(c, @"props", at + 4, (t.usage & MTLTextureUsageShaderRead) != 0);
		id<MTLCommandBuffer> cb = [queue commandBuffer];
		clear_and_draw_left(c, cb, p, t, h[@"clears"][i], h[@"color"]);
		if (!framebuffer_only) {
			id<MTLBlitCommandEncoder> b = [cb blitCommandEncoder];
			[b copyFromTexture:t sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0)
				sourceSize:MTLSizeMake(w, height, 1) toBuffer:c.buffers[@"out"] destinationOffset:i * image
			   destinationBytesPerRow:w * texel destinationBytesPerImage:image];
			[b endEncoding];
		}
		[cb presentDrawable:drawable];
		wait_for(cb, c.spec);
	}
}

static IOSurfaceRef make_surface(NSDictionary *properties)
{
	IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)properties);
	if (!s)
		@throw failure(@"IOSurfaceCreate refused %@", properties);
	return s;
}

/* Copies tight rows into a surface plane, or out of it, under its lock. */
static void surface_rows(IOSurfaceRef s, size_t plane, NSData *in, NSMutableData *out, size_t row, size_t rows)
{
	IOSurfaceLock(s, in ? 0 : kIOSurfaceLockReadOnly, NULL);
	uint8_t *base = IOSurfaceGetBaseAddressOfPlane(s, plane);
	size_t stride = IOSurfaceGetBytesPerRowOfPlane(s, plane);
	for (size_t y = 0; y < rows; y++) {
		if (in)
			memcpy(base + y * stride, (const uint8_t *)in.bytes + y * row, row);
		else
			memcpy((uint8_t *)out.mutableBytes + y * row, base + y * stride, row);
	}
	IOSurfaceUnlock(s, in ? 0 : kIOSurfaceLockReadOnly, NULL);
}

static id<MTLTexture> surface_texture(Case *c, IOSurfaceRef s, size_t plane, MTLPixelFormat format, MTLTextureUsage usage)
{
	MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:format
										     width:IOSurfaceGetWidthOfPlane(s, plane)
										    height:IOSurfaceGetHeightOfPlane(s, plane)
										 mipmapped:NO];
	d.usage = usage;
	d.storageMode = c.device.hasUnifiedMemory ? MTLStorageModeShared : MTLStorageModeManaged;
	id<MTLTexture> t = [c.device newTextureWithDescriptor:d iosurface:s plane:plane];
	if (!t)
		@throw failure(@"no texture over plane %zu", plane);
	return t;
}

static NSData *contents(id<MTLBuffer> b)
{
	return [NSData dataWithBytes:b.contents length:b.length];
}

/* A BGRA surface the CPU fills and a kernel inverts into a second one the
 * CPU reads; then a two-plane 4:2:0 surface a kernel reads both planes of. */
static void host_iosurface(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	size_t w = number(h, @"width", 1), height = number(h, @"height", 1);
	NSDictionary *bgra = @{
		(__bridge id)kIOSurfaceWidth : @(w), (__bridge id)kIOSurfaceHeight : @(height), (__bridge id)kIOSurfaceBytesPerElement : @4,
		(__bridge id)kIOSurfacePixelFormat : @((uint32_t)'BGRA'),
		(__bridge id)kIOSurfaceBytesPerRow : @(IOSurfaceAlignProperty(kIOSurfaceBytesPerRow, w * 4)),
	};
	IOSurfaceRef src = make_surface(bgra), dst = make_surface(bgra);
	surface_rows(src, 0, contents(c.buffers[@"in"]), nil, w * 4, height);
	id<MTLTexture> ts = surface_texture(c, src, 0, MTLPixelFormatBGRA8Unorm, MTLTextureUsageShaderRead);
	id<MTLTexture> td = surface_texture(c, dst, 0, MTLPixelFormatBGRA8Unorm, MTLTextureUsageShaderWrite);
	put(c, @"props", 0, ts.iosurface == src);
	put(c, @"props", 1, (uint32_t)ts.iosurfacePlane);
	put(c, @"props", 2, (uint32_t)td.width);
	put(c, @"props", 3, (uint32_t)td.height);

	size_t uw = w / 2, uh = height / 2;
	size_t y_row = IOSurfaceAlignProperty(kIOSurfacePlaneBytesPerRow, w);
	size_t uv_row = IOSurfaceAlignProperty(kIOSurfacePlaneBytesPerRow, uw * 2);
	size_t uv_offset = IOSurfaceAlignProperty(kIOSurfacePlaneOffset, y_row * height);
	NSDictionary *planar = @{
		(__bridge id)kIOSurfaceWidth : @(w), (__bridge id)kIOSurfaceHeight : @(height),
		(__bridge id)kIOSurfacePixelFormat : @((uint32_t)'420v'),
		(__bridge id)kIOSurfaceAllocSize : @(uv_offset + uv_row * uh),
		(__bridge id)kIOSurfacePlaneInfo : @[
			@{(__bridge id)kIOSurfacePlaneWidth : @(w), (__bridge id)kIOSurfacePlaneHeight : @(height),
			  (__bridge id)kIOSurfacePlaneBytesPerElement : @1, (__bridge id)kIOSurfacePlaneBytesPerRow : @(y_row),
			  (__bridge id)kIOSurfacePlaneOffset : @0, (__bridge id)kIOSurfacePlaneSize : @(y_row * height)},
			@{(__bridge id)kIOSurfacePlaneWidth : @(uw), (__bridge id)kIOSurfacePlaneHeight : @(uh),
			  (__bridge id)kIOSurfacePlaneBytesPerElement : @2, (__bridge id)kIOSurfacePlaneBytesPerRow : @(uv_row),
			  (__bridge id)kIOSurfacePlaneOffset : @(uv_offset), (__bridge id)kIOSurfacePlaneSize : @(uv_row * uh)},
		],
	};
	IOSurfaceRef yuv = make_surface(planar);
	surface_rows(yuv, 0, contents(c.buffers[@"luma"]), nil, w, height);
	surface_rows(yuv, 1, contents(c.buffers[@"chroma"]), nil, uw * 2, uh);
	id<MTLTexture> ty = surface_texture(c, yuv, 0, MTLPixelFormatR8Unorm, MTLTextureUsageShaderRead);
	id<MTLTexture> tc = surface_texture(c, yuv, 1, MTLPixelFormatRG8Unorm, MTLTextureUsageShaderRead);

	id<MTLCommandBuffer> cb = [queue commandBuffer];
	id<MTLComputeCommandEncoder> e = [cb computeCommandEncoder];
	[e setComputePipelineState:host_pipeline(c, @"surface_invert")];
	[e setTexture:ts atIndex:0];
	[e setTexture:td atIndex:1];
	[e dispatchThreads:MTLSizeMake(w, height, 1) threadsPerThreadgroup:MTLSizeMake(8, 8, 1)];
	[e setComputePipelineState:host_pipeline(c, @"surface_planes")];
	[e setTexture:ty atIndex:0];
	[e setTexture:tc atIndex:1];
	[e setBuffer:c.buffers[@"planes"] offset:0 atIndex:0];
	[e dispatchThreads:MTLSizeMake(w, height, 1) threadsPerThreadgroup:MTLSizeMake(8, 8, 1)];
	[e endEncoding];
	if (td.storageMode == MTLStorageModeManaged) {
		id<MTLBlitCommandEncoder> b = [cb blitCommandEncoder];
		[b synchronizeResource:td];
		[b endEncoding];
	}
	wait_for(cb, c.spec);
	NSMutableData *out = [NSMutableData dataWithLength:w * 4 * height];
	surface_rows(dst, 0, nil, out, w * 4, height);
	memcpy(c.buffers[@"out"].contents, out.bytes, MIN(out.length, c.buffers[@"out"].length));
	CFRelease(src);
	CFRelease(dst);
	CFRelease(yuv);
}

/* What another process does to a texture and event this one shares. */
@protocol Sharer
- (void)writeRows:(NSData *)rows into:(MTLSharedTextureHandle *)texture
	    after:(MTLSharedEventHandle *)event value:(uint64_t)value
	    reply:(void (^)(NSString *error))reply;
@end

static NSString *const share_service = @"com.stela.metal-suite.share";

/* The share service: opens the handles with its own device, waits on the
 * event, copies rows into the texture's top and signals the next value. */
@interface ShareService : NSObject <NSXPCListenerDelegate, Sharer>
@end
@implementation ShareService
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection
{
	connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(Sharer)];
	connection.exportedObject = self;
	[connection resume];
	return YES;
}

- (void)writeRows:(NSData *)rows into:(MTLSharedTextureHandle *)handle
	    after:(MTLSharedEventHandle *)event_handle value:(uint64_t)value
	    reply:(void (^)(NSString *error))reply
{
	id<MTLDevice> device = MTLCreateSystemDefaultDevice();
	id<MTLTexture> t = [device newSharedTextureWithHandle:handle];
	id<MTLSharedEvent> event = [device newSharedEventWithHandle:event_handle];
	if (!t || !event) {
		reply(@"the service could not open the shared texture or event");
		return;
	}
	NSUInteger row = t.width * 4, count = rows.length / row;
	id<MTLBuffer> staging = [device newBufferWithBytes:rows.bytes length:rows.length options:MTLResourceStorageModeShared];
	id<MTLCommandBuffer> cb = [[device newCommandQueue] commandBuffer];
	[cb encodeWaitForEvent:event value:value];
	id<MTLBlitCommandEncoder> b = [cb blitCommandEncoder];
	[b copyFromBuffer:staging sourceOffset:0 sourceBytesPerRow:row sourceBytesPerImage:rows.length
	       sourceSize:MTLSizeMake(t.width, count, 1) toTexture:t destinationSlice:0 destinationLevel:0
	destinationOrigin:MTLOriginMake(0, 0, 0)];
	[b endEncoding];
	[cb encodeSignalEvent:event value:value + 1];
	[cb commit];
	[cb waitUntilCompleted];
	reply(cb.error ? cb.error.localizedDescription : nil);
}
@end

static int serve_shares(void)
{
	ShareService *service = [ShareService new];
	NSXPCListener *listener = [NSXPCListener serviceListener];
	listener.delegate = service;
	[listener resume];
	return 0;
}

/* This process clears a shared texture and signals 1; the share service
 * waits for 1, writes the top rows and signals 2; this process waits for
 * 2 and reads the texture back. */
static void host_share(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	NSUInteger w = number(h, @"width", 1), height = number(h, @"height", 1);
	MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
										     width:w
										    height:height
										 mipmapped:NO];
	d.storageMode = MTLStorageModePrivate;
	d.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
	id<MTLTexture> t = [c.device newSharedTextureWithDescriptor:d];
	id<MTLSharedEvent> event = [c.device newSharedEvent];
	if (!t || !event)
		@throw failure(@"no shared texture or event");
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
	pass.colorAttachments[0].texture = t;
	pass.colorAttachments[0].loadAction = MTLLoadActionClear;
	pass.colorAttachments[0].storeAction = MTLStoreActionStore;
	NSArray *k = h[@"clear"];
	pass.colorAttachments[0].clearColor =
		MTLClearColorMake([k[0] doubleValue], [k[1] doubleValue], [k[2] doubleValue], [k[3] doubleValue]);
	[[cb renderCommandEncoderWithDescriptor:pass] endEncoding];
	[cb encodeSignalEvent:event value:1];
	[cb commit];

	NSXPCConnection *connection = [[NSXPCConnection alloc] initWithServiceName:share_service];
	connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(Sharer)];
	[connection resume];
	__block NSString *problem = nil;
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	id<Sharer> sharer = [connection remoteObjectProxyWithErrorHandler:^(NSError *e) {
		problem = e.localizedDescription ?: @"connection failed";
		dispatch_semaphore_signal(done);
	}];
	[sharer writeRows:contents(c.buffers[@"rows"]) into:[t newSharedTextureHandle]
		    after:[event newSharedEventHandle] value:1
		    reply:^(NSString *error) {
			    problem = error;
			    dispatch_semaphore_signal(done);
		    }];
	long late = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
	[connection invalidate];
	if (late)
		@throw failure(@"the share service did not answer");
	if (problem)
		@throw failure(@"share service: %@", problem);

	id<MTLCommandBuffer> read = [queue commandBuffer];
	[read encodeWaitForEvent:event value:2];
	id<MTLBlitCommandEncoder> b = [read blitCommandEncoder];
	[b copyFromTexture:t sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(w, height, 1)
		  toBuffer:c.buffers[@"out"] destinationOffset:0 destinationBytesPerRow:w * 4
	  destinationBytesPerImage:w * 4 * height];
	[b endEncoding];
	wait_for(read, c.spec);
	put(c, @"props", 0, (uint32_t)event.signaledValue);
}

/* An archive given a compute and a render pipeline's functions, written to
 * a file and loaded again: pipelines it holds are created though a miss
 * would fail them, and one it does not hold fails. */
static void host_archive(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	id<MTLLibrary> library = library_named(c.device, c.plan, c.spec[@"library"], c.libraries);
	NSError *error = nil;
	id<MTLBinaryArchive> archive = [c.device newBinaryArchiveWithDescriptor:[MTLBinaryArchiveDescriptor new] error:&error];
	put(c, @"props", 0, archive != nil);
	MTLComputePipelineDescriptor *compute = [MTLComputePipelineDescriptor new];
	compute.computeFunction = function_named(library, @"archived", nil);
	put(c, @"props", 1, [archive addComputePipelineFunctionsWithDescriptor:compute error:&error]);
	MTLRenderPipelineDescriptor *render = [MTLRenderPipelineDescriptor new];
	render.vertexFunction = function_named(library, @"vert_left_half", nil);
	render.fragmentFunction = function_named(library, @"frag_constant", nil);
	render.colorAttachments[0].pixelFormat = MTLPixelFormatRGBA8Unorm;
	put(c, @"props", 2, [archive addRenderPipelineFunctionsWithDescriptor:render error:&error]);
	NSURL *url = [NSURL fileURLWithPath:[NSTemporaryDirectory()
						    stringByAppendingPathComponent:[NSString stringWithFormat:@"stela-suite-%d.metallib",
													       getpid()]]];
	put(c, @"props", 3, [archive serializeToURL:url error:&error]);
	MTLBinaryArchiveDescriptor *from_file = [MTLBinaryArchiveDescriptor new];
	from_file.url = url;
	id<MTLBinaryArchive> loaded = [c.device newBinaryArchiveWithDescriptor:from_file error:&error];
	put(c, @"props", 4, loaded != nil);
	compute.binaryArchives = loaded ? @[ loaded ] : @[];
	id<MTLComputePipelineState> hit = [c.device newComputePipelineStateWithDescriptor:compute
										  options:MTLPipelineOptionFailOnBinaryArchiveMiss
									       reflection:nil
										    error:&error];
	put(c, @"props", 5, hit != nil);
	MTLComputePipelineDescriptor *other = [MTLComputePipelineDescriptor new];
	other.computeFunction = function_named(library, @"not_archived", nil);
	other.binaryArchives = compute.binaryArchives;
	put(c, @"props", 6, [c.device newComputePipelineStateWithDescriptor:other options:MTLPipelineOptionFailOnBinaryArchiveMiss
							     reflection:nil
								  error:&error] == nil);
	render.binaryArchives = compute.binaryArchives;
	put(c, @"props", 7, [c.device newRenderPipelineStateWithDescriptor:render options:MTLPipelineOptionFailOnBinaryArchiveMiss
							    reflection:nil
								 error:&error] != nil);
	[[NSFileManager defaultManager] removeItemAtURL:url error:nil];
	if (!hit)
		return;
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	id<MTLComputeCommandEncoder> e = [cb computeCommandEncoder];
	id<MTLBuffer> data = c.buffers[@"data"];
	dispatch_one(e, hit, @[ data ], 0, MTLSizeMake(data.length / 4, 1, 1));
	[e endEncoding];
	wait_for(cb, c.spec);
}

/* The errors creation calls report for bad input, a command buffer's
 * status through its life, and command buffers running in the order they
 * were enqueued rather than committed. */
static void host_errors(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	NSError *error = nil;
	id<MTLLibrary> broken = [c.device newLibraryWithSource:@"kernel void broken(" options:nil error:&error];
	put(c, @"props", 0, broken == nil);
	put(c, @"props", 1, [error.domain isEqualToString:MTLLibraryErrorDomain]);
	put(c, @"props", 2, (uint32_t)error.code);
	id<MTLLibrary> library = library_named(c.device, c.plan, c.spec[@"library"], c.libraries);
	put(c, @"props", 3, [library newFunctionWithName:@"absent"] == nil);
	error = nil;
	put(c, @"props", 4,
	    host_render_pipeline(c, [MTLRenderPipelineDescriptor new], @"vert_left_half", @"frag_unwritten_input",
				 MTLPixelFormatRGBA8Unorm, &error) == nil &&
		    error != nil);

	MTLCommandBufferDescriptor *d = [MTLCommandBufferDescriptor new];
	d.errorOptions = MTLCommandBufferErrorOptionEncoderExecutionStatus;
	id<MTLCommandBuffer> cb = [queue commandBufferWithDescriptor:d];
	put(c, @"props", 5, (uint32_t)cb.status);
	[cb enqueue];
	put(c, @"props", 6, (uint32_t)cb.status);
	[[cb blitCommandEncoder] endEncoding];
	wait_for(cb, c.spec);
	put(c, @"props", 7, (uint32_t)cb.status);
	put(c, @"props", 8, cb.error == nil);

	id<MTLComputePipelineState> digit = host_pipeline(c, @"append_digit");
	id<MTLCommandBuffer> first = [queue commandBuffer], second = [queue commandBuffer];
	[second enqueue];
	[first enqueue];
	for (id<MTLCommandBuffer> each in @[ first, second ]) {
		id<MTLComputeCommandEncoder> e = [each computeCommandEncoder];
		dispatch_one(e, digit, @[ c.buffers[@"order"] ], each == first ? 1 : 2, MTLSizeMake(1, 1, 1));
		[e endEncoding];
	}
	[first commit];
	wait_for(second, c.spec);
	[first waitUntilCompleted];
}

/* The state setPurgeableState: returns, which is the one before it: for a
 * buffer, a private texture and a heap, through empty and back. */
static void host_purgeable(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
										      width:64
										     height:64
										  mipmapped:NO];
	td.storageMode = MTLStorageModePrivate;
	MTLHeapDescriptor *hd = [MTLHeapDescriptor new];
	hd.size = 1 << 20;
	hd.storageMode = MTLStorageModePrivate;
	NSArray *resources = @[
		[c.device newBufferWithLength:1 << 16 options:MTLResourceStorageModeShared], [c.device newTextureWithDescriptor:td],
		[c.device newHeapWithDescriptor:hd]
	];
	MTLPurgeableState steps[] = {MTLPurgeableStateKeepCurrent, MTLPurgeableStateEmpty,       MTLPurgeableStateKeepCurrent,
				     MTLPurgeableStateNonVolatile, MTLPurgeableStateKeepCurrent, MTLPurgeableStateVolatile};
	NSUInteger at = 0;
	for (id r in resources)
		for (size_t i = 0; i < sizeof steps / sizeof *steps; i++)
			put(c, @"props", at++, (uint32_t)[r setPurgeableState:steps[i]]);
}

/* Many dispatches in one encoder, many command buffers in one queue,
 * threads encoding into one queue at once, and queues adding at once. */
static void host_streams(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	NSUInteger dispatches = number(h, @"dispatches", 1), buffers = number(h, @"command_buffers", 1);
	NSUInteger threads = number(h, @"threads", 1), each = number(h, @"per_thread", 1);
	id<MTLBuffer> counts = c.buffers[@"counts"];
	id<MTLComputePipelineState> bump = host_pipeline(c, @"bump"), add = host_pipeline(c, @"bump_atomic");
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	id<MTLComputeCommandEncoder> e = [cb computeCommandEncoder];
	for (NSUInteger i = 0; i < dispatches; i++)
		dispatch_one(e, bump, @[ counts ], 0, MTLSizeMake(1, 1, 1));
	[e endEncoding];
	wait_for(cb, c.spec);
	for (NSUInteger i = 0; i < buffers; i++) {
		cb = [queue commandBuffer];
		e = [cb computeCommandEncoder];
		dispatch_one(e, bump, @[ counts ], 1, MTLSizeMake(1, 1, 1));
		[e endEncoding];
		if (i + 1 < buffers)
			[cb commit];
	}
	wait_for(cb, c.spec);
	NSMutableArray *queues = [NSMutableArray new];
	for (NSUInteger t = 0; t < threads; t++)
		[queues addObject:[c.device newCommandQueue]];
	for (int phase = 0; phase < 2; phase++) {
		dispatch_apply(threads, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t t) {
			id<MTLCommandQueue> q = phase ? queues[t] : queue;
			id<MTLCommandBuffer> last = nil;
			for (NSUInteger i = 0; i < each; i++) {
				last = [q commandBuffer];
				id<MTLComputeCommandEncoder> te = [last computeCommandEncoder];
				dispatch_one(te, phase ? add : bump, @[ counts ], phase ? (uint32_t)(2 + threads) : (uint32_t)(2 + t),
					     MTLSizeMake(1, 1, 1));
				[te endEncoding];
				[last commit];
			}
			[last waitUntilCompleted];
		});
	}
}

/* Buffers and textures made, used by a command buffer and dropped before
 * it runs, many times over: what each held must reach the output. */
static void host_churn(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	NSUInteger rounds = number(h, @"rounds", 1), size = number(h, @"size", 4096);
	MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatR32Uint
										      width:64
										     height:64
										  mipmapped:NO];
	td.storageMode = MTLStorageModePrivate;
	td.usage = MTLTextureUsageRenderTarget;
	id<MTLCommandBuffer> cb = nil;
	for (NSUInteger i = 0; i < rounds; i++) {
		@autoreleasepool {
			id<MTLBuffer> b = [c.device newBufferWithLength:size options:MTLResourceStorageModeShared];
			uint32_t word = (uint32_t)(i * 2654435761u);
			memset_pattern4(b.contents, &word, size);
			id<MTLTexture> t = [c.device newTextureWithDescriptor:td];
			cb = [queue commandBuffer];
			MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
			pass.colorAttachments[0].texture = t;
			pass.colorAttachments[0].loadAction = MTLLoadActionClear;
			pass.colorAttachments[0].storeAction = MTLStoreActionStore;
			pass.colorAttachments[0].clearColor = MTLClearColorMake(i, 0, 0, 0);
			[[cb renderCommandEncoderWithDescriptor:pass] endEncoding];
			id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
			[e copyFromBuffer:b sourceOffset:(i * 4096) % size toBuffer:c.buffers[@"words"] destinationOffset:i * 4 size:4];
			[e copyFromTexture:t sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(i % 64, i / 64 % 64, 0)
				sourceSize:MTLSizeMake(1, 1, 1) toBuffer:c.buffers[@"texels"] destinationOffset:i * 4
			   destinationBytesPerRow:4 destinationBytesPerImage:4];
			[e endEncoding];
			if (i + 1 < rounds)
				[cb commit];
		}
	}
	wait_for(cb, c.spec);
}

/* A private buffer past 4 GiB: kernels stamp windows below 2 GiB, across
 * 2 and 4 GiB and at its end, a fill lands past 4 GiB, and blits bring
 * each back. */
static void host_large_buffer(Case *c, id<MTLCommandQueue> queue, NSDictionary *h)
{
	NSUInteger length = number(h, @"length", 0);
	if (c.device.maxBufferLength < length)
		@throw [NSException exceptionWithName:@"CaseUnsupported" reason:@"maxBufferLength" userInfo:nil];
	id<MTLBuffer> big = [c.device newBufferWithLength:length options:MTLResourceStorageModePrivate];
	if (!big)
		@throw failure(@"no %lu-byte buffer", (unsigned long)length);
	id<MTLComputePipelineState> stamp = host_pipeline(c, @"stamp");
	id<MTLCommandBuffer> cb = [queue commandBuffer];
	id<MTLComputeCommandEncoder> e = [cb computeCommandEncoder];
	for (NSArray *w in h[@"windows"])
		dispatch_one(e, stamp, @[ big ], [w[0] unsignedIntValue], MTLSizeMake([w[1] unsignedIntegerValue], 1, 1));
	[e endEncoding];
	id<MTLBlitCommandEncoder> b = [cb blitCommandEncoder];
	NSArray *fill = h[@"fill"];
	[b fillBuffer:big range:NSMakeRange([fill[0] unsignedIntegerValue], [fill[1] unsignedIntegerValue]) value:[fill[2] unsignedCharValue]];
	NSUInteger at = 0;
	for (NSArray *w in h[@"windows"]) {
		NSUInteger bytes = [w[1] unsignedIntegerValue] * 4;
		[b copyFromBuffer:big sourceOffset:[w[0] unsignedIntegerValue] * 4 toBuffer:c.buffers[@"out"] destinationOffset:at size:bytes];
		at += bytes;
	}
	[b copyFromBuffer:big sourceOffset:[fill[0] unsignedIntegerValue] toBuffer:c.buffers[@"out"] destinationOffset:at
		     size:[fill[1] unsignedIntegerValue]];
	[b endEncoding];
	wait_for(cb, c.spec);
}

static void run_host(Case *c, id<MTLCommandQueue> queue, NSDictionary *spec)
{
	NSDictionary *h = spec[@"host"];
	NSDictionary *work = @{
		@"drawables" : [NSValue valueWithPointer:host_drawables],
		@"iosurface" : [NSValue valueWithPointer:host_iosurface],
		@"share" : [NSValue valueWithPointer:host_share],
		@"archive" : [NSValue valueWithPointer:host_archive],
		@"errors" : [NSValue valueWithPointer:host_errors],
		@"purgeable" : [NSValue valueWithPointer:host_purgeable],
		@"streams" : [NSValue valueWithPointer:host_streams],
		@"churn" : [NSValue valueWithPointer:host_churn],
		@"large_buffer" : [NSValue valueWithPointer:host_large_buffer],
	};
	NSValue *v = work[h[@"kind"]];
	if (!v)
		@throw failure(@"unknown host work %@", h[@"kind"]);
	((void (*)(Case *, id<MTLCommandQueue>, NSDictionary *))v.pointerValue)(c, queue, h);
}

static void run_case(id<MTLDevice> device, id<MTLCommandQueue> queue, NSDictionary *plan, NSDictionary *spec,
		     NSString *dir, NSMutableDictionary *libraries)
{
	Case *c = [Case new];
	c.spec = spec;
	c.name = spec[@"name"];
	c.dir = dir;
	c.device = device;
	c.buffers = [NSMutableDictionary new];
	c.textures = [NSMutableDictionary new];
	c.samplers = [NSMutableDictionary new];
	c.resident = [NSMutableArray new];
	c.fences = [NSMutableDictionary new];
	c.events = [NSMutableDictionary new];
	c.icbs = [NSMutableDictionary new];
	c.heaps = [NSMutableDictionary new];
	c.libraries = libraries;
	c.plan = plan;
	c.queue = queue;
	NSString *missing = unmet(device, spec[@"requires"]);
	if (missing)
		@throw [NSException exceptionWithName:@"CaseUnsupported" reason:missing userInfo:nil];
	for (NSDictionary *h in spec[@"heaps"])
		c.heaps[h[@"name"]] = make_heap(c, h);
	for (NSDictionary *b in spec[@"buffers"])
		c.buffers[b[@"name"]] = make_buffer(c, b);
	for (NSDictionary *t in spec[@"textures"])
		c.textures[t[@"name"]] = make_texture(c, t, queue);
	for (NSDictionary *s in spec[@"samplers"])
		c.samplers[s[@"name"]] = make_sampler(c, s);
	for (NSDictionary *b in spec[@"icbs"])
		c.icbs[b[@"name"]] = make_icb(c, b);
	for (NSDictionary *a in spec[@"arguments"])
		encode_arguments(c, a);
	NSString *kind = spec[@"kind"];
	if ([kind isEqualToString:@"device"]) {
		write_json([dir stringByAppendingPathComponent:@"properties.json"], device_properties(device));
		return;
	}
	if ([kind isEqualToString:@"blit"]) {
		run_blits(c, queue, spec);
	} else if ([kind isEqualToString:@"framework"]) {
		run_framework(c, queue, spec);
	} else if ([kind isEqualToString:@"host"]) {
		run_host(c, queue, spec);
	} else if ([kind isEqualToString:@"sequence"]) {
		run_sequence(c, queue, plan, spec, libraries);
	} else {
		id<MTLLibrary> library = library_named(device, plan, spec[@"library"], libraries);
		if ([kind isEqualToString:@"compute"])
			run_compute(c, queue, library, spec);
		else if ([kind isEqualToString:@"render"])
			run_render(c, queue, library, spec);
		else
			@throw failure(@"unknown case kind %@", kind);
	}
	store_outputs(c, queue, spec);
}

int main(int argc, const char **argv)
{
	@autoreleasepool {
		/* Launched by launchd as the bundle's share service. */
		if (getenv("XPC_SERVICE_NAME"))
			return serve_shares();
		if (argc < 3) {
			fprintf(stderr, "usage: %s PLAN_DIR RESULTS_DIR [--only SUBSTRING]... [--skip-done]\n", argv[0]);
			return 64;
		}
		plan_dir = [NSString stringWithUTF8String:argv[1]];
		NSString *results = [NSString stringWithUTF8String:argv[2]];
		NSMutableArray *only = [NSMutableArray new];
		BOOL skip_done = NO;
		for (int i = 3; i < argc; i++) {
			if (!strcmp(argv[i], "--only") && i + 1 < argc)
				[only addObject:[NSString stringWithUTF8String:argv[++i]]];
			else if (!strcmp(argv[i], "--skip-done"))
				skip_done = YES;
			else {
				fprintf(stderr, "unknown argument %s\n", argv[i]);
				return 64;
			}
		}
		NSData *plan_bytes = [NSData dataWithContentsOfFile:[plan_dir stringByAppendingPathComponent:@"plan.json"]];
		NSDictionary *plan = plan_bytes ? [NSJSONSerialization JSONObjectWithData:plan_bytes options:0 error:nil] : nil;
		if (!plan) {
			fprintf(stderr, "cannot read %s/plan.json\n", argv[1]);
			return 66;
		}
		id<MTLDevice> device = MTLCreateSystemDefaultDevice();
		if (!device) {
			fprintf(stderr, "no Metal device\n");
			return 69;
		}
		id<MTLCommandQueue> queue = [device newCommandQueue];
		NSFileManager *fm = [NSFileManager defaultManager];
		[fm createDirectoryAtPath:results withIntermediateDirectories:YES attributes:nil error:nil];
		write_json([results stringByAppendingPathComponent:@"device.json"], @{
			@"name" : device.name,
			@"os" : [[NSProcessInfo processInfo] operatingSystemVersionString],
			@"plan" : plan[@"digest"] ?: @"",
		});
		NSMutableDictionary *libraries = [NSMutableDictionary new];
		unsigned ok = 0, failed = 0, skipped = 0;
		for (NSDictionary *spec in plan[@"cases"]) {
			NSString *name = spec[@"name"];
			if (only.count) {
				BOOL match = NO;
				for (NSString *o in only)
					match |= [name containsString:o];
				if (!match)
					continue;
			}
			NSString *dir = [results stringByAppendingPathComponent:name];
			NSString *status_path = [dir stringByAppendingPathComponent:@"status.json"];
			if (skip_done && [fm fileExistsAtPath:status_path])
				continue;
			[fm removeItemAtPath:dir error:nil];
			[fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
			write_json(status_path, @{@"status" : @"running"});
			NSDate *start = [NSDate date];
			gpu_seconds = 0;
			timing = YES;
			@try {
				@autoreleasepool {
					run_case(device, queue, plan, spec, dir, libraries);
				}
				write_json(status_path, @{@"status" : @"ok", @"seconds" : @(-[start timeIntervalSinceNow]),
							  @"gpu_ms" : @(gpu_seconds * 1000.0)});
				ok++;
			} @catch (NSException *e) {
				BOOL timeout = [e.name isEqualToString:@"CaseTimeout"];
				BOOL unsupported = [e.name isEqualToString:@"CaseUnsupported"];
				write_json(status_path, @{@"status" : timeout ? @"timeout" : unsupported ? @"unsupported" : @"error",
							  @"error" : e.reason ?: e.name});
				if (unsupported) {
					skipped++;
					continue;
				}
				fprintf(stderr, "%s: %s\n", name.UTF8String, (e.reason ?: e.name).UTF8String);
				failed++;
				if (timeout)
					return 2;
			}
		}
		printf("%u ok, %u failed, %u unsupported\n", ok, failed, skipped);
	}
	return 0;
}
