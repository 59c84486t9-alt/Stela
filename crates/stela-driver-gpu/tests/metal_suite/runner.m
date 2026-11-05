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
 */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
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
			@"bc7_rgbaunorm" : @(MTLPixelFormatBC7_RGBAUnorm),
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

static MTLResourceOptions buffer_options(NSDictionary *b)
{
	MTLResourceOptions options = MTLResourceStorageModeShared;
	if ([b[@"untracked"] boolValue])
		options |= MTLResourceHazardTrackingModeUntracked;
	return options;
}

/* A buffer of `length` bytes: from the device, or from the named heap at
 * an offset when that heap places its resources. */
static id<MTLBuffer> allocate_buffer(Case *c, NSDictionary *b, NSUInteger length)
{
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

static id<MTLBuffer> make_buffer(Case *c, NSDictionary *b)
{
	id<MTLBuffer> buffer;
	if (b[@"file"]) {
		NSData *data = read_file(b[@"file"]);
		NSUInteger length = MAX(number(b, @"length", data.length), data.length);
		buffer = allocate_buffer(c, b, MAX(length, 16));
		if (buffer && !b[@"alias_of"])
			memcpy(buffer.contents, data.bytes, data.length);
	} else {
		NSUInteger length = number(b, @"length", 16);
		buffer = allocate_buffer(c, b, MAX(length, 16));
		/* An alias keeps the bytes of the resource it overlaps. */
		if (buffer && !b[@"alias_of"])
			memset(buffer.contents, (int)number(b, @"fill", 0), buffer.length);
	}
	if (!buffer)
		@throw failure(@"buffer %@ allocation failed", b[@"name"]);
	buffer.label = b[@"name"];
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
	case MTLPixelFormatA1BGR5Unorm: case MTLPixelFormatABGR4Unorm: case MTLPixelFormatBGR5A1Unorm:
	case MTLPixelFormatDepth16Unorm:
		return 2;
	case MTLPixelFormatRG32Uint: case MTLPixelFormatRG32Sint: case MTLPixelFormatRG32Float:
	case MTLPixelFormatRGBA16Unorm: case MTLPixelFormatRGBA16Snorm: case MTLPixelFormatRGBA16Uint:
	case MTLPixelFormatRGBA16Sint: case MTLPixelFormatRGBA16Float:
		return 8;
	case MTLPixelFormatRGBA32Uint: case MTLPixelFormatRGBA32Sint: case MTLPixelFormatRGBA32Float:
		return 16;
	case MTLPixelFormatBC1_RGBA: case MTLPixelFormatBC4_RUnorm:
		*block = 4;
		return 8;
	case MTLPixelFormatBC3_RGBA: case MTLPixelFormatBC5_RGUnorm: case MTLPixelFormatBC7_RGBAUnorm:
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
	if (t.pixelFormat == MTLPixelFormatDepth32Float_Stencil8)
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
	if (f == MTLPixelFormatDepth32Float_Stencil8)
		return [aspect isEqualToString:@"stencil"] ? MTLBlitOptionStencilFromDepthStencil : MTLBlitOptionDepthFromDepthStencil;
	return MTLBlitOptionNone;
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
										      usage:MTLTextureUsageShaderRead];
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
	d.storageMode = MTLStorageModePrivate;
	MTLTextureUsage usage = 0;
	for (NSString *u in t[@"usage"] ?: @[ @"read" ]) {
		if ([u isEqualToString:@"read"]) usage |= MTLTextureUsageShaderRead;
		else if ([u isEqualToString:@"write"]) usage |= MTLTextureUsageShaderWrite;
		else if ([u isEqualToString:@"render"]) usage |= MTLTextureUsageRenderTarget;
		else if ([u isEqualToString:@"atomic"]) usage |= MTLTextureUsageShaderAtomic;
		else if ([u isEqualToString:@"view"]) usage |= MTLTextureUsagePixelFormatView;
		else @throw failure(@"unknown texture usage %@", u);
	}
	d.usage = usage;
	id<MTLTexture> texture;
	if (t[@"heap"]) {
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

static void bind_compute(Case *c, id<MTLComputeCommandEncoder> e, NSDictionary *spec)
{
	for (NSDictionary *b in spec[@"buffers"])
		if (b[@"index"])
			[e setBuffer:c.buffers[b[@"name"]] offset:number(b, @"offset", 0) atIndex:number(b, @"index", 0)];
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
		if ([stage isEqualToString:@"vertex"] || [stage isEqualToString:@"both"])
			[e setVertexBuffer:buffer offset:offset atIndex:index];
		if ([stage isEqualToString:@"fragment"] || [stage isEqualToString:@"both"])
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
	id<MTLComputePipelineState> pipeline = [c.device newComputePipelineStateWithDescriptor:d
										       options:MTLPipelineOptionNone
										    reflection:nil
											 error:&error];
	if (!pipeline)
		@throw failure(@"compute pipeline: %@", error.localizedDescription);
	id<MTLComputeCommandEncoder> e = open ?: [cb computeCommandEncoder];
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
	id<MTLCommandBuffer> cb = [queue commandBuffer];
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
		/* An array target is layered: the vertex function picks the slice. */
		if (t.textureType == MTLTextureType2DArray || t.textureType == MTLTextureType2DMultisampleArray)
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
			pass.depthAttachment.resolveTexture = c.textures[a[@"resolve"]];
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
		[e drawPrimitives:primitive indirectBuffer:c.buffers[i[@"buffer"]] indirectBufferOffset:number(i, @"offset", 0)];
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

/* Steps of compute, render and blit work over the case's resources, in one
 * command buffer unless a step starts a new one. A compute step may
 * continue the previous compute encoder; a step may wait for and update
 * fences, and wait for or signal an event's value between encoders. Every
 * command buffer is committed in order and the last one waited for. */
static void run_sequence(Case *c, id<MTLCommandQueue> queue, NSDictionary *plan, NSDictionary *spec,
			 NSMutableDictionary *libraries)
{
	id<MTLCommandBuffer> cb = [queue commandBuffer];
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
		if ([step[@"new_command_buffer"] boolValue]) {
			[cb commit];
			cb = [queue commandBuffer];
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
	wait_for(cb, spec);
}

static void store_outputs(Case *c, id<MTLCommandQueue> queue, NSDictionary *spec)
{
	timing = NO;
	for (NSDictionary *o in spec[@"outputs"]) {
		NSString *name = o[@"name"];
		NSString *path = [c.dir stringByAppendingPathComponent:[(o[@"as"] ?: name) stringByAppendingString:@".bin"]];
		if (c.buffers[name]) {
			id<MTLBuffer> b = c.buffers[name];
			NSUInteger length = number(o, @"length", b.length);
			[[NSData dataWithBytes:b.contents length:MIN(length, b.length)] writeToFile:path atomically:YES];
			continue;
		}
		id<MTLTexture> t = c.textures[name];
		if (!t)
			@throw failure(@"output %@ is neither a buffer nor a texture", name);
		NSUInteger total;
		NSArray *regions = regions_of(t, o[@"aspect"], &total);
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
