/* SPDX-License-Identifier: MIT */
#import "library_internal.h"
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#include <string.h>

#define INPUT_LIMIT (64u * 1024u * 1024u)
#define ENTRY_LIMIT 256u

static void LibraryError(NSError **error, MTLLibraryError code, NSString *detail)
{
   if (error)
      *error = [NSError errorWithDomain:MTLLibraryErrorDomain code:(NSInteger)code
         userInfo:@{NSLocalizedDescriptionKey:detail}];
}
static NSData *Digest(NSData *bytes, NSRange range)
{
   uint8_t result[32];
   CC_SHA256((const uint8_t *)bytes.bytes + range.location, (CC_LONG)range.length, result);
   return [NSData dataWithBytes:result length:sizeof(result)];
}
static BOOL Span(uint64_t offset, uint64_t length, NSUInteger limit)
{
   return length && offset <= limit && length <= limit - offset;
}
static BOOL Nonzero(const uint8_t *bytes, size_t length)
{
   uint8_t result = 0;
   for (size_t i = 0; i < length; i++) result |= bytes[i];
   return result != 0;
}
static BOOL SameDigest(NSData *actual, const uint8_t expected[32])
{
   return [actual isEqualToData:[NSData dataWithBytes:expected length:32]];
}
static NSData *RangeDigest(NSData *bytes, NSRange range, NSMutableDictionary *cache)
{
   NSString *key = [NSString stringWithFormat:@"%llu:%llu",
      (unsigned long long)range.location, (unsigned long long)range.length];
   NSData *digest = cache[key];
   if (!digest) { digest = Digest(bytes,range); cache[key] = digest; }
   return digest;
}

/* Genuine public reflection implementations. No Apple private reflection
 * containers, ivars, initializers or C++ data are used. Each object owns its
 * strings/children and contains only already validated AIR reflection facts. */
static MTLDataType PrimitiveDataType(enum stela_air_primitive primitive, unsigned components)
{
   static const MTLDataType types[][4] = {
      {MTLDataTypeChar,MTLDataTypeChar2,MTLDataTypeChar3,MTLDataTypeChar4},
      {MTLDataTypeUChar,MTLDataTypeUChar2,MTLDataTypeUChar3,MTLDataTypeUChar4},
      {MTLDataTypeShort,MTLDataTypeShort2,MTLDataTypeShort3,MTLDataTypeShort4},
      {MTLDataTypeUShort,MTLDataTypeUShort2,MTLDataTypeUShort3,MTLDataTypeUShort4},
      {MTLDataTypeInt,MTLDataTypeInt2,MTLDataTypeInt3,MTLDataTypeInt4},
      {MTLDataTypeUInt,MTLDataTypeUInt2,MTLDataTypeUInt3,MTLDataTypeUInt4},
      {MTLDataTypeLong,MTLDataTypeLong2,MTLDataTypeLong3,MTLDataTypeLong4},
      {MTLDataTypeULong,MTLDataTypeULong2,MTLDataTypeULong3,MTLDataTypeULong4},
      {MTLDataTypeFloat,MTLDataTypeFloat2,MTLDataTypeFloat3,MTLDataTypeFloat4},
   };
   if (primitive < STELA_AIR_CHAR || primitive > STELA_AIR_FLOAT || !components || components > 4)
      return MTLDataTypeNone;
   return types[primitive-STELA_AIR_CHAR][components-1];
}
static MTLBindingAccess BindingAccess(enum stela_air_buffer_access access)
{
   switch (access) {
   case STELA_AIR_READ: return MTLBindingAccessReadOnly;
   case STELA_AIR_WRITE: return MTLBindingAccessWriteOnly;
   case STELA_AIR_READ_WRITE: return MTLBindingAccessReadWrite;
   }
   __builtin_unreachable(); /* Validated before construction. */
}
@interface STELAMetalPointerType : MTLPointerType
- (instancetype)initWithArgument:(const struct stela_air_argument_info *)argument;
@end
@implementation STELAMetalPointerType {
   MTLDataType _element;
   MTLBindingAccess _access;
   NSUInteger _alignment, _dataSize;
}
- (instancetype)initWithArgument:(const struct stela_air_argument_info *)arg
{
   self = [super init];
   if (self) {
      _element = PrimitiveDataType(arg->primitive,arg->type_components);
      _access = BindingAccess(arg->buffer.access);
      _alignment = arg->buffer.type_alignment; _dataSize = arg->buffer.type_size;
   }
   return self;
}
- (MTLDataType)dataType { return MTLDataTypePointer; }
- (MTLDataType)elementType { return _element; }
- (MTLBindingAccess)access { return _access; }
- (NSUInteger)alignment { return _alignment; }
- (NSUInteger)dataSize { return _dataSize; }
- (BOOL)elementIsArgumentBuffer { return NO; }
- (MTLStructType *)elementStructType { return nil; } /* Validated primitive. */
- (MTLArrayType *)elementArrayType { return nil; }
@end

@interface STELAMetalBinding : NSObject <MTLBinding>
@property (readonly) NSString *name;
@property (readonly) MTLBindingType type;
@property (readonly) MTLBindingAccess access;
@property (readonly) NSUInteger index;
@property (readonly, getter=isUsed) BOOL used;
@property (readonly, getter=isArgument) BOOL argument;
@property (readonly) NSUInteger alignment, dataSize;
@property (readonly) MTLDataType dataType;
- (instancetype)initWithArgument:(const struct stela_air_argument_info *)argument;
@end
@implementation STELAMetalBinding
- (instancetype)initWithArgument:(const struct stela_air_argument_info *)arg
{
   self = [super init];
   if (self) {
      _name = [[NSString alloc] initWithBytes:arg->name length:arg->name_bytes encoding:NSUTF8StringEncoding];
      _type = arg->buffer.address_space == 1 ? MTLBindingTypeBuffer : MTLBindingTypeThreadgroupMemory;
      _access = BindingAccess(arg->buffer.access); _index = arg->buffer.index;
      _used = arg->used; _argument = YES;
      _alignment = arg->buffer.type_alignment; _dataSize = arg->buffer.type_size;
      _dataType = PrimitiveDataType(arg->primitive,arg->type_components);
   }
   return self;
}
@end
@interface STELAMetalBufferBinding : STELAMetalBinding <MTLBufferBinding>
@end
@implementation STELAMetalBufferBinding {
   MTLPointerType *_pointer;
}
- (instancetype)initWithArgument:(const struct stela_air_argument_info *)arg
{
   self = [super initWithArgument:arg];
   if (self) _pointer = [[STELAMetalPointerType alloc] initWithArgument:arg];
   return self;
}
- (NSUInteger)bufferAlignment { return self.alignment; }
- (NSUInteger)bufferDataSize { return self.dataSize; }
- (MTLDataType)bufferDataType { return self.dataType; }
- (MTLStructType *)bufferStructType { return nil; }
- (MTLPointerType *)bufferPointerType { return _pointer; }
@end
@interface STELAMetalThreadgroupBinding : STELAMetalBinding <MTLThreadgroupBinding>
@end
@implementation STELAMetalThreadgroupBinding
- (NSUInteger)threadgroupMemoryAlignment { return self.alignment; }
- (NSUInteger)threadgroupMemoryDataSize { return self.dataSize; }
@end
@interface STELAMetalReflection : MTLFunctionReflection
- (instancetype)initWithBindings:(NSArray<id<MTLBinding>> *)bindings;
@end
@implementation STELAMetalReflection {
   NSArray<id<MTLBinding>> *_bindings;
}
- (instancetype)initWithBindings:(NSArray<id<MTLBinding>> *)bindings
{
   self = [super init];
   if (self) _bindings = [bindings copy];
   return self;
}
- (NSArray<id<MTLBinding>> *)bindings { return _bindings; }
- (NSString *)userAnnotation { return nil; } /* Admission proves absence. */
@end

static MTLFunctionReflection *CreateReflection(const struct stela_metal_function_record *record)
{
   if (record->reserved_arguments || record->argument_count > AIR_MAX_ARGUMENTS ||
       (record->argument_count && !record->arguments)) return nil;
   BOOL ordinals[AIR_MAX_ARGUMENTS] = {0};
   BOOL indices[2][AIR_MAX_ARGUMENTS] = {{0}};
   NSMutableArray<id<MTLBinding>> *bindings = [NSMutableArray array];
   for (uint32_t i = 0; i < record->argument_count; i++) {
      const struct stela_air_argument_info *arg = &record->arguments[i];
      if (arg->buffer.argument >= record->argument_count || ordinals[arg->buffer.argument]) return nil;
      ordinals[arg->buffer.argument] = YES;
      if (arg->kind == 2) { /* Invocation builtins are not bound resources. */
         if (arg->components != 1 && arg->components != 3) return nil;
         continue;
      }
      if (arg->kind != 1 || !arg->plain_buffer_type ||
          PrimitiveDataType(arg->primitive,arg->type_components) == MTLDataTypeNone ||
          !arg->name || !arg->name_bytes || arg->name_bytes > 4096 ||
          memchr(arg->name,0,arg->name_bytes) ||
          (arg->buffer.address_space != 1 && arg->buffer.address_space != 3) ||
          arg->buffer.index >= AIR_MAX_ARGUMENTS || arg->buffer.access < STELA_AIR_READ ||
          arg->buffer.access > STELA_AIR_READ_WRITE) return nil;
      unsigned space = arg->buffer.address_space == 1 ? 0 : 1;
      if (indices[space][arg->buffer.index]) return nil;
      indices[space][arg->buffer.index] = YES;
      unsigned scalar = arg->primitive <= STELA_AIR_UCHAR ? 1 : arg->primitive <= STELA_AIR_USHORT ? 2 :
         arg->primitive == STELA_AIR_LONG || arg->primitive == STELA_AIR_ULONG ? 8 : 4;
      unsigned extent = scalar * (arg->type_components == 3 ? 4 : arg->type_components);
      if (arg->buffer.type_size != extent || arg->buffer.type_alignment != extent ||
          ![[NSString alloc] initWithBytes:arg->name length:arg->name_bytes encoding:NSUTF8StringEncoding]) return nil;
      STELAMetalBinding *binding = space == 0 ? [[STELAMetalBufferBinding alloc] initWithArgument:arg] :
         [[STELAMetalThreadgroupBinding alloc] initWithArgument:arg];
      [bindings addObject:binding];
   }
   return [[STELAMetalReflection alloc] initWithBindings:bindings];
}

@interface STELAMetalFunctionSnapshot ()
- (instancetype)initWithInput:(NSData *)input record:(const struct stela_metal_function_record *)record
   manifest:(const struct stela_metal_library_manifest *)manifest target:(NSString *)target
   reflection:(MTLFunctionReflection *)reflection;
@end
@implementation STELAMetalFunctionSnapshot
- (instancetype)initWithInput:(NSData *)input record:(const struct stela_metal_function_record *)r
   manifest:(const struct stela_metal_library_manifest *)m target:(NSString *)target
   reflection:(MTLFunctionReflection *)reflection
{
   self = [super init];
   if (self) {
      _originalInput = input;
      _rawAIRRange = NSMakeRange((NSUInteger)r->air_offset,(NSUInteger)r->air_bytes);
      _entryName = [[NSString alloc] initWithBytes:r->name length:(NSUInteger)r->name_bytes encoding:NSUTF8StringEncoding];
      _targetTriple = [target copy]; _reflection = reflection;
      _originalSHA256 = [NSData dataWithBytes:m->input.original_sha256 length:32];
      _moduleSHA256 = [NSData dataWithBytes:r->entry.module_sha256 length:32];
      _rawAIRSHA256 = [NSData dataWithBytes:r->air_sha256 length:32];
      _sourceSHA256 = [NSData dataWithBytes:m->source_sha256 length:32];
      _compilerBuildIdentity = [NSData dataWithBytes:&m->build length:sizeof(m->build)];
      _compilerProfile = m->compiler_profile; _requestLanguage = m->request_language;
      _requestFastMath = m->request_fast_math != 0;
      _airMajor = r->entry.air_major; _airMinor = r->entry.air_minor;
      _languageMajor = r->entry.language_major; _languageMinor = r->entry.language_minor;
   }
   return self;
}
@end

@interface STELAMetalLibrary : NSObject <MTLLibrary>
@property (nullable, copy, atomic) NSString *label;
@property (readonly) id<MTLDevice> device;
@property (readonly) NSArray<NSString *> *functionNames;
@property (readonly) MTLLibraryType type;
@property (readonly, nullable) NSString *installName;
- (instancetype)initWithDevice:(id<MTLDevice>)device entries:(NSDictionary *)entries
   reflectionAvailable:(BOOL)reflectionAvailable;
- (id<MTLFunction>)function:(NSString *)name error:(NSError **)error;
@end
@interface STELAMetalFunction : NSObject <MTLFunction>
@property (nullable, copy, atomic) NSString *label;
@property (readonly) STELAMetalFunctionSnapshot *snapshot;
- (instancetype)initWithLibrary:(STELAMetalLibrary *)library snapshot:(STELAMetalFunctionSnapshot *)snapshot;
@end

@implementation STELAMetalFunction {
   STELAMetalLibrary *_library;
}
- (instancetype)initWithLibrary:(STELAMetalLibrary *)library snapshot:(STELAMetalFunctionSnapshot *)snapshot
{
   self = [super init];
   if (self) { _library = library; _snapshot = snapshot; }
   return self;
}
- (id<MTLDevice>)device { return _library.device; }
- (NSString *)name { return _snapshot.entryName; }
- (MTLFunctionType)functionType { return MTLFunctionTypeKernel; }
- (MTLPatchType)patchType { return MTLPatchTypeNone; }
- (NSInteger)patchControlPointCount { return -1; }
- (NSArray<MTLVertexAttribute *> *)vertexAttributes { return nil; } /* Compute. */
- (NSArray<MTLAttribute *> *)stageInputAttributes { return nil; } /* Compute. */
- (NSDictionary<NSString *,MTLFunctionConstant *> *)functionConstantsDictionary { return @{}; }
- (MTLFunctionOptions)options { return MTLFunctionOptionNone; }
- (id<MTLArgumentEncoder>)newArgumentEncoderWithBufferIndex:(NSUInteger)index
{
   /* Only manifest-proven primitive-buffer functions are constructed. There is
    * no declared argument-buffer structure at ANY index for this function.
    * Do not return nil from this nonnull API or construct a fake encoder. */
   [NSException raise:NSInvalidArgumentException format:@"Function %@ declares no argument buffer at index %llu",
      self.name,(unsigned long long)index];
   __builtin_unreachable();
}
/* Implement the original public deprecated selector with its exact ARC type. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
- (id<MTLArgumentEncoder>)newArgumentEncoderWithBufferIndex:(NSUInteger)index
   reflection:(MTLAutoreleasedArgument *)reflection
{
   (void)reflection;
   return [self newArgumentEncoderWithBufferIndex:index];
}
#pragma clang diagnostic pop
@end

@implementation STELAMetalLibrary {
   NSDictionary<NSString *,STELAMetalFunctionSnapshot *> *_entries;
   BOOL _reflectionAvailable;
}
- (instancetype)initWithDevice:(id<MTLDevice>)device entries:(NSDictionary *)entries
   reflectionAvailable:(BOOL)reflectionAvailable
{
   self = [super init];
   if (self) { _device = device; _entries = [entries copy];
      _reflectionAvailable = reflectionAvailable;
      _functionNames = [[_entries allKeys] sortedArrayUsingSelector:@selector(compare:)]; }
   return self;
}
- (MTLLibraryType)type { return MTLLibraryTypeExecutable; }
- (NSString *)installName { return nil; } /* Executable libraries have none. */
- (id<MTLFunction>)function:(NSString *)name error:(NSError **)error
{
   if (error) *error = nil;
   STELAMetalFunctionSnapshot *snapshot = [name isKindOfClass:NSString.class] ? _entries[name] : nil;
   if (!snapshot) { LibraryError(error,MTLLibraryErrorFunctionNotFound,@"Function not found in this library"); return nil; }
   return [[STELAMetalFunction alloc] initWithLibrary:self snapshot:snapshot];
}
- (id<MTLFunction>)newFunctionWithName:(NSString *)name { return [self function:name error:NULL]; }
- (id<MTLFunction>)newFunctionWithName:(NSString *)name constantValues:(MTLFunctionConstantValues *)values error:(NSError **)error
{
   if (values) { LibraryError(error,MTLLibraryErrorUnsupported,@"Function constant specialization is not implemented"); return nil; }
   return [self function:name error:error];
}
- (void)newFunctionWithName:(NSString *)name constantValues:(MTLFunctionConstantValues *)values
   completionHandler:(void (^)(id<MTLFunction>,NSError *))handler
{
   if (!handler) [NSException raise:NSInvalidArgumentException format:@"A completion handler is required"];
   NSString *saved = [name copy]; MTLFunctionConstantValues *constants = [values copy];
   void (^completion)(id<MTLFunction>,NSError *) = [handler copy];
   dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
      NSError *error = nil;
      id<MTLFunction> function = [self newFunctionWithName:saved constantValues:constants error:&error];
      completion(function,error);
   });
}
- (id<MTLFunction>)newFunctionWithDescriptor:(MTLFunctionDescriptor *)descriptor error:(NSError **)error
{
   if (![descriptor isKindOfClass:MTLFunctionDescriptor.class] ||
       [descriptor isKindOfClass:MTLIntersectionFunctionDescriptor.class] ||
       descriptor.options != MTLFunctionOptionNone || descriptor.specializedName || descriptor.binaryArchives.count) {
      LibraryError(error,MTLLibraryErrorUnsupported,@"Unsupported function descriptor, options or archive lookup");
      return nil;
   }
   return [self newFunctionWithName:descriptor.name constantValues:descriptor.constantValues error:error];
}
- (void)newFunctionWithDescriptor:(MTLFunctionDescriptor *)descriptor
   completionHandler:(void (^)(id<MTLFunction>,NSError *))handler
{
   if (!handler) [NSException raise:NSInvalidArgumentException format:@"A completion handler is required"];
   MTLFunctionDescriptor *saved = [descriptor copy];
   void (^completion)(id<MTLFunction>,NSError *) = [handler copy];
   dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
      NSError *error = nil; id<MTLFunction> function = [self newFunctionWithDescriptor:saved error:&error];
      completion(function,error);
   });
}
- (id<MTLFunction>)newIntersectionFunctionWithDescriptor:(MTLIntersectionFunctionDescriptor *)descriptor error:(NSError **)error
{
   (void)descriptor; LibraryError(error,MTLLibraryErrorUnsupported,@"Intersection functions are not implemented"); return nil;
}
- (void)newIntersectionFunctionWithDescriptor:(MTLIntersectionFunctionDescriptor *)descriptor
   completionHandler:(void (^)(id<MTLFunction>,NSError *))handler
{
   (void)descriptor;
   if (!handler) [NSException raise:NSInvalidArgumentException format:@"A completion handler is required"];
   void (^completion)(id<MTLFunction>,NSError *) = [handler copy];
   dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
      NSError *error = nil; LibraryError(&error,MTLLibraryErrorUnsupported,@"Intersection functions are not implemented");
      completion(nil,error);
   });
}
- (MTLFunctionReflection *)reflectionForFunctionWithName:(NSString *)name
{
   /* The public contract also requires a deployment target of macOS13+. */
   if (!_reflectionAvailable || ![name isKindOfClass:NSString.class] || !_entries[name]) return nil;
   return _entries[name].reflection;
}
@end

id<MTLLibrary> STELAMetalCreateLibrary(id<MTLDevice> device, NSData *original,
   const struct stela_metal_library_manifest *m, NSError **error)
{
   if (error) *error = nil;
   if (!device || ![device conformsToProtocol:@protocol(MTLDevice)] ||
       ![original isKindOfClass:NSData.class] || !m || m->size != sizeof(*m) ||
       m->abi != STELA_METAL_LIBRARY_ABI || m->reserved || m->flags & ~STELA_METAL_LIBRARY_SOURCE_COMPILED ||
       !m->entry_count || m->entry_count > ENTRY_LIMIT || !m->entries ||
       m->input.size != sizeof(m->input) || m->input.abi != STELA_METAL_INPUT_ABI ||
       !original.length || original.length > INPUT_LIMIT || m->input.original_bytes != original.length ||
       !m->target || !m->target_bytes || m->target_bytes > 1024 || memchr(m->target,0,(size_t)m->target_bytes) ||
       m->request_fast_math > 1 || m->compiler_profile > STELA_MSL_APPLE_32023_MACOS_27_2_ARM64) {
      LibraryError(error,MTLLibraryErrorUnsupported,@"Invalid/unqualified library manifest, device or input bounds"); return nil;
   }
   if ((m->input.kind != STELA_METAL_INPUT_MTLB && m->input.kind != STELA_METAL_INPUT_RAW_AIR) ||
       (m->input.kind == STELA_METAL_INPUT_MTLB && (m->input.format_major != 2 ||
          m->input.library_kind != 0 || m->input.entry_count != m->entry_count)) ||
       (m->input.kind == STELA_METAL_INPUT_RAW_AIR && !(m->flags & STELA_METAL_LIBRARY_SOURCE_COMPILED))) {
      LibraryError(error,MTLLibraryErrorUnsupported,@"Unsupported library kind or raw-input provenance"); return nil;
   }
   NSString *target = [[NSString alloc] initWithBytes:m->target length:(NSUInteger)m->target_bytes encoding:NSUTF8StringEncoding];
   if (!target) { LibraryError(error,MTLLibraryErrorUnsupported,@"Invalid target encoding"); return nil; }
   if (m->flags & STELA_METAL_LIBRARY_SOURCE_COMPILED) {
      if (m->compiler_profile != STELA_MSL_APPLE_32023_MACOS_27_2_ARM64 || m->request_language != 0x40001 ||
          !m->request_fast_math || ![target isEqualToString:@"air64_v29-apple-macosx27.2.0"] ||
          !Nonzero(m->source_sha256,32) || !Nonzero(m->build.gpucompiler_uuid,16) ||
          !Nonzero(m->build.implementation_uuid,16) || !Nonzero(m->build.llvm_uuid,16) ||
          !Nonzero(m->build.lazy_library_sha256,32) || !Nonzero(m->build.metal_stdlib_sha256,32) ||
          !Nonzero(m->build.metal_types_sha256,32)) {
         LibraryError(error,MTLLibraryErrorUnsupported,@"Source result lacks the qualified compiler/request identity"); return nil;
      }
   } else if (m->compiler_profile || m->request_language || m->request_fast_math ||
              Nonzero(m->source_sha256,32) || Nonzero((const uint8_t *)&m->build,sizeof(m->build))) {
      LibraryError(error,MTLLibraryErrorUnsupported,@"Precompiled input cannot imply source/compiler authentication"); return nil;
   }
   /* -copy may return an immutable NSData unchanged, including externally
    * borrowed no-copy storage. Take an actual owned byte snapshot before the
    * caller/helper lease can end; no manifest or external byte pointer escapes. */
   NSData *input = [[NSData alloc] initWithBytes:original.bytes length:original.length];
   NSMutableDictionary *digests = [NSMutableDictionary dictionary];
   if (!SameDigest(RangeDigest(input,NSMakeRange(0,input.length),digests),m->input.original_sha256)) {
      LibraryError(error,MTLLibraryErrorUnsupported,@"Original input digest mismatch"); return nil;
   }
   NSMutableDictionary *entries = [NSMutableDictionary dictionary];
   for (uint32_t i = 0; i < m->entry_count; i++) {
      const struct stela_metal_function_record *r = &m->entries[i];
      if (r->size != sizeof(*r) || r->abi != STELA_METAL_LIBRARY_ABI || r->reserved ||
          r->flags != (STELA_METAL_ENTRY_NO_CONSTANTS | STELA_METAL_ENTRY_PLAIN_BUFFERS |
             STELA_METAL_ENTRY_COMPLETE_REFLECTION) ||
          r->entry.size != sizeof(r->entry) || r->entry.abi != STELA_METAL_INPUT_ABI || r->entry.reserved ||
          r->entry.kind != 2 || !r->name || !r->name_bytes || r->name_bytes > 4096 ||
          memchr(r->name,0,(size_t)r->name_bytes) ||
          !Span(r->entry.module_offset,r->entry.module_bytes,input.length) ||
          !Span(r->air_offset,r->air_bytes,input.length) || r->air_bytes < 4 ||
          r->air_offset < r->entry.module_offset || r->air_bytes > r->entry.module_bytes ||
          r->air_offset-r->entry.module_offset > r->entry.module_bytes-r->air_bytes ||
          memcmp((const uint8_t *)input.bytes+r->air_offset,"BC\xc0\xde",4)) {
         LibraryError(error,MTLLibraryErrorUnsupported,@"Invalid function manifest/ranges or noncompute entry"); return nil;
      }
      if ((m->flags & STELA_METAL_LIBRARY_SOURCE_COMPILED) &&
          (r->entry.air_major != 2 || r->entry.air_minor != 9 ||
           r->entry.language_major != 4 || r->entry.language_minor != 1)) {
         LibraryError(error,MTLLibraryErrorUnsupported,@"Source metadata differs from qualified profile"); return nil;
      }
      NSString *name = [[NSString alloc] initWithBytes:r->name length:(NSUInteger)r->name_bytes encoding:NSUTF8StringEncoding];
      if (!name || entries[name] ||
          !SameDigest(RangeDigest(input,NSMakeRange((NSUInteger)r->entry.module_offset,(NSUInteger)r->entry.module_bytes),digests),r->entry.module_sha256) ||
          !SameDigest(RangeDigest(input,NSMakeRange((NSUInteger)r->air_offset,(NSUInteger)r->air_bytes),digests),r->air_sha256)) {
         LibraryError(error,MTLLibraryErrorUnsupported,@"Duplicate/invalid entry name or module digest mismatch"); return nil;
      }
      MTLFunctionReflection *reflection = CreateReflection(r);
      if (!reflection) {
         LibraryError(error,MTLLibraryErrorUnsupported,@"Incomplete/unsupported function reflection"); return nil;
      }
      STELAMetalFunctionSnapshot *snapshot = [[STELAMetalFunctionSnapshot alloc]
         initWithInput:input record:r manifest:m target:target reflection:reflection];
      entries[name] = snapshot;
   }
   return [[STELAMetalLibrary alloc] initWithDevice:device entries:entries
      reflectionAvailable:m->input.kind == STELA_METAL_INPUT_RAW_AIR || m->input.minimum_os_major >= 13];
}

STELAMetalFunctionSnapshot *STELAMetalCopyFunctionSnapshot(id<MTLFunction> function,
   id<MTLDevice> expected, NSError **error)
{
   if (error) *error = nil;
   if (![function isKindOfClass:STELAMetalFunction.class] || !expected || function.device != expected) {
      LibraryError(error,MTLLibraryErrorUnsupported,@"Function implementation or creating device mismatch"); return nil;
   }
   return ((STELAMetalFunction *)function).snapshot;
}
