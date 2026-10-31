/*
 * What the bundle uses of Metal, declared here since no SDK takes part in the
 * build: its value types, the protocols its objects conform to, and the
 * accessors of the descriptors applications pass in. Values are the public
 * headers'. The accessors are a category nothing implements, so they only tell
 * the compiler what a message returns.
 */
#pragma once

#include "Apple.h"

typedef struct {
	NSUInteger width, height, depth;
} MTLSize;
typedef struct {
	NSUInteger x, y, z;
} MTLOrigin;
typedef struct {
	MTLOrigin origin;
	MTLSize size;
} MTLRegion;
typedef struct {
	NSUInteger size, align;
} MTLSizeAndAlign;
typedef struct {
	NSUInteger accelerationStructureSize, buildScratchBufferSize, refitScratchBufferSize;
} MTLAccelerationStructureSizes;
typedef struct {
	double red, green, blue, alpha;
} MTLClearColor;
typedef struct {
	double originX, originY, width, height, znear, zfar;
} MTLViewport;
typedef struct {
	NSUInteger x, y, width, height;
} MTLScissorRect;
typedef struct {
	float x, y;
} MTLSamplePosition;
typedef struct {
	uint8_t red, green, blue, alpha;
} MTLTextureSwizzleChannels;
typedef struct {
	uint32_t viewportArrayIndexOffset, renderTargetArrayIndexOffset;
} MTLVertexAmplificationViewMapping;
typedef struct {
	uint64_t _impl;
} MTLResourceID;
typedef struct {
	NSUInteger location, length;
} MTLCounterResultRange;
typedef uint64_t MTLTimestamp;
typedef uint64_t MTLGPUAddress;

enum {
	MTLStorageModeShared = 0,
	MTLStorageModeManaged = 1,
	MTLStorageModePrivate = 2,
	MTLStorageModeMemoryless = 3,
};
#define MTLResourceCPUCacheModeShift 0
#define MTLResourceCPUCacheModeMask (0xfUL << MTLResourceCPUCacheModeShift)
#define MTLResourceStorageModeShift 4
#define MTLResourceStorageModeMask (0xfUL << MTLResourceStorageModeShift)
#define MTLResourceHazardTrackingModeShift 8
#define MTLResourceHazardTrackingModeMask (0x3UL << MTLResourceHazardTrackingModeShift)
enum {
	MTLPurgeableStateKeepCurrent = 1,
	MTLPurgeableStateNonVolatile = 2,
	MTLPurgeableStateVolatile = 3,
	MTLPurgeableStateEmpty = 4,
};
enum {
	MTLFeatureSet_macOS_GPUFamily1_v1 = 10000,
	MTLFeatureSet_macOS_ReadWriteTextureTier2 = 10002,
	MTLFeatureSet_macOS_GPUFamily1_v4 = 10004,
	MTLFeatureSet_macOS_GPUFamily2_v1 = 10005,
};
enum {
	MTLGPUFamilyMac1 = 2001,
	MTLGPUFamilyMac2 = 2002,
};
enum {
	MTLFunctionTypeVertex = 1,
	MTLFunctionTypeFragment = 2,
	MTLFunctionTypeKernel = 3,
	MTLFunctionTypeVisible = 5,
	MTLFunctionTypeIntersection = 6,
	MTLFunctionTypeMesh = 7,
	MTLFunctionTypeObject = 8,
};
enum {
	MTLCommandBufferStatusNotEnqueued = 0,
	MTLCommandBufferStatusEnqueued = 1,
	MTLCommandBufferStatusCommitted = 2,
	MTLCommandBufferStatusScheduled = 3,
	MTLCommandBufferStatusCompleted = 4,
	MTLCommandBufferStatusError = 5,
};
enum {
	MTLCommandBufferErrorNone = 0,
	MTLCommandBufferErrorInternal = 1,
	MTLCommandBufferErrorTimeout = 2,
	MTLCommandBufferErrorPageFault = 3,
	MTLCommandBufferErrorOutOfMemory = 8,
	MTLCommandBufferErrorInvalidResource = 9,
	MTLCommandBufferErrorMemoryless = 10,
	MTLCommandBufferErrorDeviceRemoved = 11,
	MTLCommandBufferErrorNotPermitted = 7,
};
enum {
	MTLLibraryErrorUnsupported = 1,
	MTLLibraryErrorInternal = 2,
	MTLLibraryErrorCompileFailure = 3,
	MTLLibraryErrorFunctionNotFound = 5,
	MTLLibraryErrorFileNotFound = 6,
};
enum {
	MTLLibraryTypeExecutable = 0,
	MTLLibraryTypeDynamic = 1,
};
enum {
	MTLIOErrorInternal = 2,
};
enum {
	MTLLogStateErrorInvalid = 2,
};
enum {
	MTLSparseTextureRegionAlignmentModeOutward = 0,
	MTLSparseTextureRegionAlignmentModeInward = 1,
};
enum {
	MTLLibraryOptimizationLevelDefault = 0,
	MTLLibraryOptimizationLevelSize = 1,
};
enum {
	MTLCompileSymbolVisibilityDefault = 0,
	MTLCompileSymbolVisibilityHidden = 1,
};
enum {
	MTLDynamicLibraryErrorInvalidFile = 1,
	MTLDynamicLibraryErrorUnsupported = 5,
};
enum {
	MTLBinaryArchiveErrorInvalidFile = 1,
	MTLBinaryArchiveErrorUnexpectedElement = 2,
	MTLBinaryArchiveErrorCompilationFailure = 3,
	MTLBinaryArchiveErrorInternalError = 4,
};
enum {
	MTLPipelineOptionNone = 0,
	MTLPipelineOptionArgumentInfo = 1 << 0,
	MTLPipelineOptionBindingInfo = 1 << 0,
	MTLPipelineOptionBufferTypeInfo = 1 << 1,
	MTLPipelineOptionFailOnBinaryArchiveMiss = 1 << 2,
};
enum {
	MTLDataTypeNone = 0,
	MTLDataTypeStruct = 1,
	MTLDataTypeArray = 2,
	MTLDataTypeFloat = 3,
	MTLDataTypeHalf = 16,
	MTLDataTypeInt = 29,
	MTLDataTypeUInt = 33,
	MTLDataTypeShort = 37,
	MTLDataTypeUShort = 41,
	MTLDataTypeChar = 45,
	MTLDataTypeUChar = 49,
	MTLDataTypeBool = 53,
	MTLDataTypeTexture = 58,
	MTLDataTypePointer = 60,
	MTLDataTypeLong = 81,
	MTLDataTypeULong = 85,
};
enum {
	MTLBindingTypeBuffer = 0,
};
enum {
	MTLTextureTypeCube = 5,
	MTLTextureTypeCubeArray = 6,
};
enum {
	MTLBarrierScopeBuffers = 1 << 0,
	MTLBarrierScopeTextures = 1 << 1,
	MTLBarrierScopeRenderTargets = 1 << 2,
};
enum {
	MTLCullModeNone = 0,
	MTLWindingClockwise = 0,
	MTLTriangleFillModeFill = 0,
	MTLDepthClipModeClip = 0,
	MTLVisibilityResultModeDisabled = 0,
	MTLCompareFunctionAlways = 7,
	MTLStencilOperationKeep = 0,
};
enum {
	MTLCounterSampleBufferErrorInternal = 2,
};
enum {
	MTLDispatchTypeSerial = 0,
	MTLDispatchTypeConcurrent = 1,
};
enum {
	MTLIndirectCommandTypeDraw = 1 << 0,
	MTLIndirectCommandTypeDrawIndexed = 1 << 1,
	MTLIndirectCommandTypeDrawPatches = 1 << 2,
	MTLIndirectCommandTypeDrawIndexedPatches = 1 << 3,
	MTLIndirectCommandTypeConcurrentDispatch = 1 << 5,
	MTLIndirectCommandTypeConcurrentDispatchThreads = 1 << 6,
	MTLIndirectCommandTypeDrawMeshThreadgroups = 1 << 7,
	MTLIndirectCommandTypeDrawMeshThreads = 1 << 8,
};
enum {
	MTLRenderStageVertex = 1 << 0,
	MTLRenderStageFragment = 1 << 1,
	MTLRenderStageTile = 1 << 2,
	MTLRenderStageObject = 1 << 3,
	MTLRenderStageMesh = 1 << 4,
};
#define MTLAttributeStrideStatic UINT64_MAX
#define MTLCounterDontSample ((NSUInteger)-1)
#define MTLCounterErrorValue UINT64_MAX

/* Local definitions of a protocol resolve to Metal's by name at load. */
#define STELA_PROTOCOLS(X)                                                                         \
	X(MTLResource)                                                                             \
	X(MTLAllocation)                                                                           \
	X(MTLBuffer)                                                                               \
	X(MTLTexture)                                                                              \
	X(MTLHeap)                                                                                 \
	X(MTLSamplerState)                                                                         \
	X(MTLDepthStencilState)                                                                    \
	X(MTLFence)                                                                                \
	X(MTLEvent)                                                                                \
	X(MTLSharedEvent)                                                                          \
	X(MTLLibrary)                                                                              \
	X(MTLFunction)                                                                             \
	X(MTLFunctionHandle)                                                                       \
	X(MTLVisibleFunctionTable)                                                                 \
	X(MTLArgumentEncoder)                                                                      \
	X(MTLRenderPipelineState)                                                                  \
	X(MTLComputePipelineState)                                                                 \
	X(MTLCommandQueue)                                                                         \
	X(MTLCommandBuffer)                                                                        \
	X(MTLCommandEncoder)                                                                       \
	X(MTLBlitCommandEncoder)                                                                   \
	X(MTLComputeCommandEncoder)                                                                \
	X(MTLRenderCommandEncoder)                                                                 \
	X(MTLResourceStateCommandEncoder)                                                          \
	X(MTLParallelRenderCommandEncoder)                                                         \
	X(MTLIndirectCommandBuffer)                                                                \
	X(MTLIndirectRenderCommand)                                                                \
	X(MTLIndirectComputeCommand)                                                               \
	X(MTLCounterSet)                                                                           \
	X(MTLCounter)                                                                              \
	X(MTLCounterSampleBuffer)                                                                  \
	X(MTLBinding)                                                                              \
	X(MTLBufferBinding)                                                                        \
	X(MTLTextureBinding)                                                                       \
	X(MTLThreadgroupBinding)                                                                   \
	X(MTLObjectPayloadBinding)                                                                 \
	X(MTLDrawable)                                                                             \
	X(MTLDynamicLibrary)                                                                       \
	X(MTLBinaryArchive)                                                                        \
	X(MTLResidencySet)

#define STELA_DECLARE_PROTOCOL(name) @protocol name @end
STELA_PROTOCOLS(STELA_DECLARE_PROTOCOL)

/* The accessors of Metal's descriptors. */
@interface NSObject (StelaDescriptors)
- (BOOL)respondsToSelector:(SEL)selector;
- (id)objectAtIndexedSubscript:(NSUInteger)index;
- (NSString *)label;
/* MTLResidencySetDescriptor. */
- (NSUInteger)initialCapacity;
/* MTLAllocation. */
- (NSUInteger)allocatedSize;
/* MTLCompileOptions. */
- (NSUInteger)languageVersion;
- (NSUInteger)mathMode;
- (NSUInteger)mathFloatingPointFunctions;
- (NSUInteger)optimizationLevel;
- (NSUInteger)compileSymbolVisibility;
- (NSUInteger)libraryType;
- (BOOL)preserveInvariance;
- (BOOL)enableLogging;
- (NSDictionary *)preprocessorMacros;
- (NSString *)installName;
- (NSArray *)libraries;
/* MTLTextureDescriptor and MTLHeapDescriptor. */
- (NSUInteger)textureType;
- (NSUInteger)pixelFormat;
- (NSUInteger)width;
- (NSUInteger)height;
- (NSUInteger)depth;
- (NSUInteger)mipmapLevelCount;
- (NSUInteger)sampleCount;
- (NSUInteger)arrayLength;
- (NSUInteger)resourceOptions;
- (NSUInteger)usage;
- (MTLTextureSwizzleChannels)swizzle;
- (NSUInteger)size;
- (NSUInteger)type;
- (NSUInteger)sparsePageSize;
/* MTLSamplerDescriptor. */
- (NSUInteger)minFilter;
- (NSUInteger)magFilter;
- (NSUInteger)mipFilter;
- (NSUInteger)maxAnisotropy;
- (NSUInteger)sAddressMode;
- (NSUInteger)tAddressMode;
- (NSUInteger)rAddressMode;
- (NSUInteger)borderColor;
- (NSUInteger)reductionMode;
- (NSUInteger)compareFunction;
- (float)lodMinClamp;
- (float)lodMaxClamp;
- (BOOL)normalizedCoordinates;
/* MTLDepthStencilDescriptor. */
- (NSUInteger)depthCompareFunction;
- (BOOL)isDepthWriteEnabled;
- (id)frontFaceStencil;
- (id)backFaceStencil;
- (NSUInteger)stencilCompareFunction;
- (NSUInteger)stencilFailureOperation;
- (NSUInteger)depthFailureOperation;
- (NSUInteger)depthStencilPassOperation;
- (uint32_t)readMask;
/* writeMask of a stencil and of a color attachment. */
- (NSUInteger)writeMask;
/* Pipeline descriptors. */
- (id)vertexFunction;
- (id)fragmentFunction;
- (id)computeFunction;
- (id)objectFunction;
- (id)meshFunction;
- (id)vertexDescriptor;
- (id)stageInputDescriptor;
- (id)colorAttachments;
- (NSUInteger)depthAttachmentPixelFormat;
- (NSUInteger)stencilAttachmentPixelFormat;
- (NSUInteger)rasterSampleCount;
- (BOOL)isAlphaToCoverageEnabled;
- (BOOL)isAlphaToOneEnabled;
- (BOOL)isRasterizationEnabled;
- (NSUInteger)maxVertexAmplificationCount;
- (NSUInteger)inputPrimitiveTopology;
- (NSUInteger)tessellationPartitionMode;
- (NSUInteger)maxTessellationFactor;
- (BOOL)isTessellationFactorScaleEnabled;
- (NSUInteger)tessellationFactorFormat;
- (NSUInteger)tessellationControlPointIndexType;
- (NSUInteger)tessellationFactorStepFunction;
- (NSUInteger)tessellationOutputWindingOrder;
- (BOOL)supportIndirectCommandBuffers;
- (id)vertexLinkedFunctions;
- (id)fragmentLinkedFunctions;
- (id)objectLinkedFunctions;
- (id)meshLinkedFunctions;
- (id)linkedFunctions;
- (id)functions;
- (id)privateFunctions;
- (id)binaryFunctions;
- (id)vertexPreloadedLibraries;
- (id)fragmentPreloadedLibraries;
- (id)preloadedLibraries;
- (id)binaryArchives;
- (id)url;
- (NSUInteger)maxVertexCallStackDepth;
- (NSUInteger)maxFragmentCallStackDepth;
- (NSUInteger)maxCallStackDepth;
- (NSUInteger)maxTotalThreadsPerThreadgroup;
- (NSUInteger)maxTotalThreadsPerObjectThreadgroup;
- (NSUInteger)maxTotalThreadsPerMeshThreadgroup;
- (NSUInteger)payloadMemoryLength;
- (BOOL)threadGroupSizeIsMultipleOfThreadExecutionWidth;
- (BOOL)objectThreadgroupSizeIsMultipleOfThreadExecutionWidth;
- (BOOL)meshThreadgroupSizeIsMultipleOfThreadExecutionWidth;
- (BOOL)isBlendingEnabled;
- (NSUInteger)sourceRGBBlendFactor;
- (NSUInteger)destinationRGBBlendFactor;
- (NSUInteger)rgbBlendOperation;
- (NSUInteger)sourceAlphaBlendFactor;
- (NSUInteger)destinationAlphaBlendFactor;
- (NSUInteger)alphaBlendOperation;
- (id)attributes;
- (id)layouts;
- (NSUInteger)format;
- (NSUInteger)offset;
- (NSUInteger)bufferIndex;
- (NSUInteger)stride;
- (NSUInteger)stepFunction;
- (NSUInteger)stepRate;
- (NSUInteger)indexType;
- (NSUInteger)indexBufferIndex;
/* MTLRenderPassDescriptor. */
- (id)depthAttachment;
- (id)stencilAttachment;
- (id)visibilityResultBuffer;
- (NSUInteger)renderTargetArrayLength;
- (NSUInteger)renderTargetWidth;
- (NSUInteger)renderTargetHeight;
- (NSUInteger)defaultRasterSampleCount;
- (NSUInteger)imageblockSampleLength;
- (NSUInteger)threadgroupMemoryLength;
- (NSUInteger)tileWidth;
- (NSUInteger)tileHeight;
- (id)rasterizationRateMap;
- (id)sampleBufferAttachments;
- (NSUInteger)getSamplePositions:(MTLSamplePosition *)positions count:(NSUInteger)count;
- (id)texture;
- (NSUInteger)level;
- (NSUInteger)slice;
- (NSUInteger)depthPlane;
- (id)resolveTexture;
- (NSUInteger)resolveLevel;
- (NSUInteger)resolveSlice;
- (NSUInteger)resolveDepthPlane;
- (NSUInteger)loadAction;
- (NSUInteger)storeAction;
- (NSUInteger)storeActionOptions;
- (MTLClearColor)clearColor;
- (double)clearDepth;
- (uint32_t)clearStencil;
- (NSUInteger)depthResolveFilter;
- (NSUInteger)stencilResolveFilter;
- (id)sampleBuffer;
- (NSUInteger)startOfEncoderSampleIndex;
- (NSUInteger)endOfEncoderSampleIndex;
- (NSUInteger)startOfVertexSampleIndex;
- (NSUInteger)endOfVertexSampleIndex;
- (NSUInteger)startOfFragmentSampleIndex;
- (NSUInteger)endOfFragmentSampleIndex;
/* MTLIndirectCommandBufferDescriptor. */
- (NSUInteger)commandTypes;
- (BOOL)inheritPipelineState;
- (BOOL)inheritBuffers;
- (BOOL)inheritCullMode;
- (BOOL)inheritDepthStencilState;
- (BOOL)inheritDepthBias;
- (BOOL)inheritDepthClipMode;
- (BOOL)inheritFrontFacingWinding;
- (BOOL)inheritTriangleFillMode;
- (NSUInteger)maxVertexBufferBindCount;
- (NSUInteger)maxFragmentBufferBindCount;
- (NSUInteger)maxKernelBufferBindCount;
- (NSUInteger)maxKernelThreadgroupMemoryBindCount;
- (NSUInteger)maxObjectBufferBindCount;
- (NSUInteger)maxMeshBufferBindCount;
- (BOOL)supportRayTracing;
- (BOOL)supportDynamicAttributeStride;
/* MTLCounterSampleBufferDescriptor. */
- (id)counterSet;
/* MTLArgumentDescriptor. */
- (NSUInteger)dataType;
- (NSUInteger)index;
- (NSUInteger)constantBlockAlignment;
/* MTLFunctionDescriptor and MTLComputePassDescriptor. */
- (id)constantValues;
- (NSUInteger)dispatchType;
- (NSString *)name;
- (void)setComputeFunction:(id)function;
/* MTLDrawable and MTLSharedEventListener. */
- (void)present;
- (void)presentAtTime:(CFTimeInterval)time;
- (void)presentAfterMinimumDuration:(CFTimeInterval)duration;
- (dispatch_queue_t)dispatchQueue;
/* MTLCommandQueueDescriptor and MTLCommandBufferDescriptor. */
- (NSUInteger)maxCommandBufferCount;
- (BOOL)retainedReferences;
/* MTLVisibleFunctionTableDescriptor. */
- (NSUInteger)functionCount;
/* NSBundle. */
- (NSURL *)URLForResource:(NSString *)name withExtension:(NSString *)extension;
@end

/* Metal's device base class, which Metal requires of a plugin's device. */
@interface _MTLDevice : NSObject
- (void)initWorkarounds;
@end

extern NSString *const MTLLibraryErrorDomain;
extern NSString *const MTLIOErrorDomain;
extern NSString *const MTLLogStateErrorDomain;
extern NSString *const MTLDynamicLibraryDomain;
extern NSString *const MTLBinaryArchiveDomain;
extern NSString *const MTLCommandBufferErrorDomain;
extern NSString *const MTLCounterErrorDomain;
extern NSString *const MTLCommonCounterSetTimestamp;
extern NSString *const MTLCommonCounterSetStatistic;
extern NSString *const MTLCommonCounterTimestamp;
