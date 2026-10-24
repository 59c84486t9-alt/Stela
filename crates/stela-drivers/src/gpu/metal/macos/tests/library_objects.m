/* SPDX-License-Identifier: MIT */
/* Explicit host object test: real canonical assembler, real host MTLDevice,
 * real first-party constructors. No fake device, positive manifest, pipeline,
 * command submission, private Metal ABI or direct/private source-compiler invocation.
 * Native public library loading may perform unobserved implementation work. */
#import "../library_internal.h"
#include "../../../compiler/library_assembly.h"
#include "llvm-c/Core.h"
#import <CommonCrypto/CommonDigest.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <sys/sysctl.h>
#import <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define INPUT_LIMIT (64u * 1024u * 1024u)
#define CHECK(test, detail) do { if (!(test)) \
   [NSException raise:@"STELATestFailure" format:@"%@", (detail)]; } while (0)

static NSMutableArray<NSDictionary *> *Cases;

static NSString *Hex(NSData *data)
{
   const unsigned char *bytes = data.bytes;
   NSMutableString *result = [NSMutableString stringWithCapacity:data.length*2];
   for (NSUInteger i = 0; i < data.length; i++) [result appendFormat:@"%02x",bytes[i]];
   return result;
}
static NSString *Digest(NSData *data)
{
   CHECK(data.length <= INPUT_LIMIT,@"Digest input exceeds fixture bound");
   unsigned char result[32];
   CC_SHA256(data.bytes,(CC_LONG)data.length,result);
   return Hex([NSData dataWithBytes:result length:sizeof(result)]);
}
static NSMutableData *ReadInput(const char *path)
{
   int fd = open(path,O_RDONLY | O_CLOEXEC | O_NONBLOCK);
   CHECK(fd >= 0,@"Cannot open input snapshot");
   struct stat info;
   if (fstat(fd,&info) || !S_ISREG(info.st_mode) || info.st_size < 4 ||
       (uint64_t)info.st_size > INPUT_LIMIT) {
      close(fd); CHECK(NO,@"Invalid bounded regular input file");
   }
   NSMutableData *data = [NSMutableData data];
   unsigned char block[16384];
   for (;;) {
      ssize_t count = read(fd,block,sizeof(block));
      if (count < 0 && errno == EINTR) continue;
      if (count < 0) { close(fd); CHECK(NO,@"Input read failed"); }
      if (!count) break;
      if ((NSUInteger)count > INPUT_LIMIT-data.length) {
         close(fd); CHECK(NO,@"Input grew beyond fixture bound");
      }
      [data appendBytes:block length:(NSUInteger)count];
   }
   close(fd);
   CHECK(data.length >= 4,@"Truncated input snapshot");
   return data;
}
static void Test(NSString *name, void (^body)(void))
{
   @try {
      body();
      [Cases addObject:@{@"id":name,@"outcome":@"PASS",@"detail":@""}];
   } @catch (NSException *exception) {
      NSString *outcome = [exception.name isEqualToString:@"STELATestInconclusive"] ? @"INCONCLUSIVE" : @"FAIL";
      [Cases addObject:@{@"id":name,@"outcome":outcome,@"detail":exception.reason ?: @"Exception"}];
      @throw;
   }
}
static NSError *Sentinel(void)
{
   return [NSError errorWithDomain:@"stela.test.sentinel" code:1 userInfo:nil];
}
static void CheckError(NSError *error, MTLLibraryError code)
{
   CHECK([error.domain isEqualToString:MTLLibraryErrorDomain] && error.code == (NSInteger)code,
      @"Wrong library refusal error");
}
static NSDictionary *Reflection(MTLFunctionReflection *reflection)
{
   CHECK(reflection != nil,@"Missing genuine reflection");
   NSMutableArray *rows = [NSMutableArray array];
   for (id<MTLBinding> binding in reflection.bindings) {
      NSMutableDictionary *row = [@{@"name":binding.name,@"type":@(binding.type),
         @"access":@(binding.access),@"index":@(binding.index),
         @"used":@([binding isUsed]),@"argument":@([binding isArgument])} mutableCopy];
      if (binding.type == MTLBindingTypeBuffer) {
         id<MTLBufferBinding> buffer = (id)binding;
         MTLPointerType *pointer = buffer.bufferPointerType;
         CHECK(pointer != nil && !pointer.elementIsArgumentBuffer &&
            pointer.elementStructType == nil && pointer.elementArrayType == nil,
            @"Admitted primitive pointer reflection changed");
         row[@"alignment"] = @(buffer.bufferAlignment);
         row[@"size"] = @(buffer.bufferDataSize);
         row[@"data_type"] = @(buffer.bufferDataType);
         row[@"element_type"] = @(pointer.elementType);
         row[@"pointer_size"] = @(pointer.dataSize);
         row[@"pointer_alignment"] = @(pointer.alignment);
         row[@"pointer_access"] = @(pointer.access);
      } else {
         CHECK(binding.type == MTLBindingTypeThreadgroupMemory,@"Unadmitted reflection binding");
         id<MTLThreadgroupBinding> shared = (id)binding;
         row[@"alignment"] = @(shared.threadgroupMemoryAlignment);
         row[@"size"] = @(shared.threadgroupMemoryDataSize);
      }
      [rows addObject:row];
   }
   return @{@"bindings":rows,@"annotation":reflection.userAnnotation ?: [NSNull null]};
}
static NSDictionary *Identity(STELAMetalFunctionSnapshot *snapshot)
{
   return @{
      @"original_sha256":Hex(snapshot.originalSHA256),
      @"module_sha256":Hex(snapshot.moduleSHA256),
      @"raw_air_sha256":Hex(snapshot.rawAIRSHA256),
      @"source_sha256":Hex(snapshot.sourceSHA256),
      @"compiler_build_sha256":Digest(snapshot.compilerBuildIdentity),
      @"entry":snapshot.entryName,@"raw_offset":@(snapshot.rawAIRRange.location),
      @"raw_bytes":@(snapshot.rawAIRRange.length),@"target":snapshot.targetTriple,
      @"compiler_profile":@(snapshot.compilerProfile),@"request_language":@(snapshot.requestLanguage),
      @"request_fast_math":@(snapshot.requestFastMath),@"air_major":@(snapshot.airMajor),
      @"air_minor":@(snapshot.airMinor),@"language_major":@(snapshot.languageMajor),
      @"language_minor":@(snapshot.languageMinor)
   };
}
static void CheckSnapshot(STELAMetalFunctionSnapshot *snapshot,
   NSDictionary *identity, NSDictionary *reflection)
{
   CHECK(snapshot && [Identity(snapshot) isEqual:identity] &&
      [Reflection(snapshot.reflection) isEqual:reflection],@"Actual immutable function snapshot changed");
   CHECK([Digest(snapshot.originalInput) isEqualToString:identity[@"original_sha256"]],@"Owned original input changed");
   NSRange range = snapshot.rawAIRRange;
   CHECK(range.location <= snapshot.originalInput.length && range.length <= snapshot.originalInput.length-range.location,
      @"Owned raw AIR range escaped input");
   CHECK([Digest([snapshot.originalInput subdataWithRange:range]) isEqualToString:identity[@"raw_air_sha256"]],
      @"Owned raw AIR changed");
}
static void CheckFunction(id<MTLFunction> function, id<MTLDevice> device,
   NSString *publicName, NSDictionary *identity, NSDictionary *reflection)
{
   CHECK(function != nil && function.device == device && [function.name isEqualToString:publicName],
      @"Wrong function/device/public identity");
   NSDictionary *constants = function.functionConstantsDictionary;
   CHECK(function.functionType == MTLFunctionTypeKernel && function.options == MTLFunctionOptionNone &&
      function.patchType == MTLPatchTypeNone && function.patchControlPointCount == -1 &&
      constants != nil && constants.count == 0,@"Admitted compute metadata changed");
   NSError *error = Sentinel();
   STELAMetalFunctionSnapshot *snapshot = STELAMetalCopyFunctionSnapshot(function,device,&error);
   CHECK(snapshot && !error,@"Actual function snapshot lookup failed");
   CheckSnapshot(snapshot,identity,reflection);
}
static id<MTLLibrary> MakeLibrary(id<MTLDevice> device, NSData *input,
   const struct stela_metal_library_manifest *manifest)
{
   NSError *error = Sentinel();
   id<MTLLibrary> library = STELAMetalCreateLibrary(device,input,manifest,&error);
   CHECK(library != nil && !error && library.device == device,@"Actual library construction failed");
   return library;
}
/* Unique synchronous subjects: neither a pending dispatch block nor the main
 * suite baseline owns these libraries. Drain all observation temporaries before
 * checking release so autoreleased getter results cannot mask retention. */
static void FunctionOwnerCheck(id<MTLDevice> device, NSData *input,
   const struct stela_metal_library_manifest *manifest, NSString *entry,
   NSDictionary *identity, NSDictionary *reflection)
{
   __attribute__((objc_precise_lifetime)) id<MTLFunction> survivor = nil;
   __weak id<MTLLibrary> weakLibrary = nil;
   __weak id<MTLFunction> weakFunction = nil;
   @autoreleasepool {
      id<MTLLibrary> library = MakeLibrary(device,input,manifest);
      id<MTLFunction> function = [library newFunctionWithName:entry];
      CHECK(function != nil,@"Unique ownership subject did not create function");
      weakLibrary = library; weakFunction = function; survivor = function;
      function = nil; library = nil;
   }
   @autoreleasepool {
      CHECK(weakLibrary != nil && weakFunction == survivor,@"Sole surviving function lost creating library");
      CheckFunction(survivor,device,entry,identity,reflection);
   }
   @autoreleasepool { survivor = nil; }
   CHECK(weakFunction == nil && weakLibrary == nil,@"Unique function/library survived final owner release");
}
static void SnapshotOwnerCheck(id<MTLDevice> device, NSData *input,
   const struct stela_metal_library_manifest *manifest, NSString *entry,
   NSDictionary *identity, NSDictionary *reflection)
{
   __attribute__((objc_precise_lifetime)) STELAMetalFunctionSnapshot *survivor = nil;
   __weak id<MTLLibrary> weakLibrary = nil;
   __weak id<MTLFunction> weakFunction = nil;
   __weak STELAMetalFunctionSnapshot *weakSnapshot = nil;
   @autoreleasepool {
      id<MTLLibrary> library = MakeLibrary(device,input,manifest);
      id<MTLFunction> function = [library newFunctionWithName:entry];
      CHECK(function != nil,@"Unique snapshot subject did not create function");
      NSError *diagnostic = Sentinel();
      survivor = STELAMetalCopyFunctionSnapshot(function,device,&diagnostic);
      CHECK(survivor && !diagnostic,@"Unique snapshot lookup failed");
      weakSnapshot = survivor; weakLibrary = library; weakFunction = function;
      function = nil; library = nil;
   }
   CHECK(weakFunction == nil && weakLibrary == nil,@"Snapshot subject still has another function/library owner");
   @autoreleasepool { CheckSnapshot(survivor,identity,reflection); }
   @autoreleasepool { survivor = nil; }
   CHECK(weakSnapshot == nil,@"Unique snapshot survived final owner release");
}
static MTLFunctionConstantValues *Values(void)
{
   MTLFunctionConstantValues *values = [MTLFunctionConstantValues new];
   uint32_t number = 17;
   [values setConstantValue:&number type:MTLDataTypeUInt atIndex:0];
   [values setConstantValue:&number type:MTLDataTypeUInt withName:@"stela_unmatched_constant"];
   return values;
}
static BOOL Wait(dispatch_semaphore_t semaphore)
{
   return dispatch_semaphore_wait(semaphore,dispatch_time(DISPATCH_TIME_NOW,(int64_t)(5*NSEC_PER_SEC))) == 0;
}

enum AsyncMode { AsyncValues, AsyncMissing, AsyncDescriptor, AsyncUnsupported, AsyncArchive, AsyncIntersection };
static void AsyncCheck(enum AsyncMode mode, id<MTLDevice> device, NSData *input,
   const struct stela_metal_library_manifest *manifest, NSString *entry,
   NSDictionary *identity, NSDictionary *reflection, id<MTLBinaryArchive> archive)
{
   dispatch_semaphore_t entered = dispatch_semaphore_create(0);
   dispatch_semaphore_t release = dispatch_semaphore_create(0);
   dispatch_semaphore_t done = dispatch_semaphore_create(0);
   NSObject *lock = [NSObject new];
   __block NSUInteger calls = 0;
   __block NSString *failure = nil;
   __weak id<MTLLibrary> weakLibrary;
   @autoreleasepool {
      id<MTLLibrary> library = MakeLibrary(device,input,manifest);
      weakLibrary = library;
      NSMutableString *name = [entry mutableCopy];
      if (mode == AsyncMissing) {
         [name appendString:@"__missing"];
         while ([library.functionNames containsObject:name]) [name appendString:@"_"];
      }
      MTLFunctionConstantValues *values = Values();
      MTLFunctionDescriptor *descriptor = [MTLFunctionDescriptor functionDescriptor];
      descriptor.name = name; descriptor.constantValues = values;
      if (mode == AsyncArchive) descriptor.binaryArchives = @[archive];
      if (mode == AsyncUnsupported) descriptor.options = MTLFunctionOptionCompileToBinary;
      void (^completion)(id<MTLFunction>,NSError *) = ^(id<MTLFunction> function, NSError *error) {
         @synchronized(lock) { calls++; }
         dispatch_semaphore_signal(entered);
         @try {
            CHECK(Wait(release),@"Caller-release gate timed out");
            if (mode == AsyncMissing) {
               CHECK(!function,@"Missing async name created a function");
               CheckError(error,MTLLibraryErrorFunctionNotFound);
            } else if (mode == AsyncUnsupported || mode == AsyncArchive || mode == AsyncIntersection) {
               CHECK(!function,@"Unsupported async descriptor succeeded");
               CheckError(error,MTLLibraryErrorUnsupported);
            } else {
               CHECK(!error,@"Unmatched values produced async diagnostics");
               CheckFunction(function,device,entry,identity,reflection);
            }
         } @catch (NSException *exception) {
            @synchronized(lock) { failure = [exception.reason copy] ?: @"Async exception"; }
         }
         dispatch_semaphore_signal(done);
      };
      if (mode == AsyncDescriptor || mode == AsyncUnsupported || mode == AsyncArchive)
         [library newFunctionWithDescriptor:descriptor completionHandler:completion];
      else if (mode == AsyncIntersection) {
         MTLIntersectionFunctionDescriptor *intersection = [MTLIntersectionFunctionDescriptor new];
         intersection.name = name;
         [library newIntersectionFunctionWithDescriptor:intersection completionHandler:completion];
      } else [library newFunctionWithName:name constantValues:values completionHandler:completion];
      /* Mutation occurs after the API returned, never racing its sync copy. */
      [name appendString:@"__caller_mutated"];
      [values reset]; descriptor.name = @"stela_missing_after_submit"; descriptor.constantValues = nil; descriptor.binaryArchives = nil;
      library = nil; name = nil; values = nil; descriptor = nil; completion = nil;
   }
   CHECK(Wait(entered),@"Async completion did not enter");
   /* This pending-callback assertion checks live callback state only: the
    * production dispatch block may still own the library. FunctionOwnerCheck
    * independently checks the returned function's library ownership. */
   if (mode == AsyncValues || mode == AsyncDescriptor)
      CHECK(weakLibrary != nil,@"Async function lost its library owner");
   dispatch_semaphore_signal(release);
   CHECK(Wait(done),@"Async completion did not finish");
   @synchronized(lock) {
      CHECK(calls == 1,@"Async callback count differs");
      CHECK(failure == nil,failure ?: @"Async assertion failed");
   }
}
static void Refuse(id<MTLDevice> device, NSData *input,
   const struct stela_metal_library_manifest *manifest)
{
   NSError *error = nil;
   CHECK(STELAMetalCreateLibrary(device,input,manifest,&error) == nil,@"Invalid constructor input succeeded");
   CheckError(error,MTLLibraryErrorUnsupported);
}
static NSDictionary *LlvmIdentity(void)
{
   unsigned major, minor, patch;
   LLVMGetVersion(&major,&minor,&patch);
   Dl_info info = {0};
   NSString *path = dladdr((const void *)&LLVMGetVersion,&info) && info.dli_fname ?
      [NSString stringWithUTF8String:info.dli_fname] : @"";
   return @{@"major":@(major),@"minor":@(minor),@"patch":@(patch),@"loaded_path":path ?: @""};
}
/* Public symbol origins identify the actual retained runtime images. This
 * bounded digest covers only their Mach-O headers/load commands, not mapped
 * text or entire files. SDK link stubs are independently bound by the runner. */
static NSDictionary *FrameworkIdentity(NSString *symbol, const void *address)
{
   Dl_info image = {0};
   if (!dladdr(address,&image) || !image.dli_fbase || !image.dli_fname)
      [NSException raise:@"STELATestInconclusive" format:@"Missing runtime image origin for %@",symbol];
   const struct mach_header_64 *header = image.dli_fbase;
   if (header->magic != MH_MAGIC_64 || !header->ncmds || header->sizeofcmds > 1024u*1024u ||
       header->ncmds > header->sizeofcmds/sizeof(struct load_command))
      [NSException raise:@"STELATestInconclusive" format:@"Unqualified runtime Mach-O header for %@",symbol];
   const unsigned char *cursor = (const void *)(header+1);
   size_t remaining = header->sizeofcmds;
   NSString *uuid = nil;
   for (uint32_t i = 0; i < header->ncmds; i++) {
      if (remaining < sizeof(struct load_command))
         [NSException raise:@"STELATestInconclusive" format:@"Truncated runtime load commands"];
      const struct load_command *command = (const void *)cursor;
      if (command->cmdsize < sizeof(*command) || command->cmdsize > remaining)
         [NSException raise:@"STELATestInconclusive" format:@"Invalid runtime load-command extent"];
      if (command->cmd == LC_UUID) {
         if (uuid || command->cmdsize != sizeof(struct uuid_command))
            [NSException raise:@"STELATestInconclusive" format:@"Ambiguous runtime image UUID"];
         const struct uuid_command *identity = (const void *)command;
         uuid = Hex([NSData dataWithBytes:identity->uuid length:sizeof(identity->uuid)]);
      }
      cursor += command->cmdsize; remaining -= command->cmdsize;
   }
   if (!uuid || remaining)
      [NSException raise:@"STELATestInconclusive" format:@"Incomplete runtime image UUID/commands"];
   NSString *path = [NSString stringWithUTF8String:image.dli_fname];
   if (!path.length) [NSException raise:@"STELATestInconclusive" format:@"Unrepresentable runtime image path"];
   size_t bytes = sizeof(*header)+header->sizeofcmds;
   return @{@"symbol":symbol,@"loaded_path":path,@"image_uuid":uuid,@"header_bytes":@(bytes),
      @"header_load_commands_sha256":Digest([NSData dataWithBytes:header length:bytes]),
      @"digest_scope":@"mach_header_64_and_load_commands_only"};
}
static NSString *OSBuild(void)
{
   char bytes[128] = {0}; size_t size = sizeof(bytes);
   if (sysctlbyname("kern.osversion",bytes,&size,NULL,0) || !size || size > sizeof(bytes) || bytes[size-1])
      [NSException raise:@"STELATestInconclusive" format:@"Actual host OS build unavailable"];
   NSString *build = [NSString stringWithUTF8String:bytes];
   if (!build.length) [NSException raise:@"STELATestInconclusive" format:@"Actual host OS build is empty"];
   return build;
}
int main(int argc, const char **argv)
{
   @autoreleasepool {
      if (argc != 4) { fputs("usage: library_objects INPUT ENTRY EXPECTED_SHA256\n",stderr); return 1; }
#if defined(__x86_64__)
      NSString *architecture = @"x86_64";
#elif defined(__aarch64__) || defined(__arm64__)
      NSString *architecture = @"aarch64";
#else
#error "Only an explicitly runnable host ABI is supported"
#endif
      NSProcessInfo *process = [NSProcessInfo processInfo];
      NSString *entry = [NSString stringWithUTF8String:argv[2]];
      NSString *expected = [NSString stringWithUTF8String:argv[3]];
      Cases = [NSMutableArray array];
      NSMutableDictionary *record = [@{@"schema":@1,@"suite":@"stela-metal-library-objects-v1",
         @"outcome":@"FAIL",@"reason":@"",@"cases":Cases,@"input_sha256":expected ?: @"",
         @"input_bytes":@0,@"entry":entry ?: @"",
         @"host":@{@"architecture":architecture,@"os_major":@(process.operatingSystemVersion.majorVersion),
            @"os_version":process.operatingSystemVersionString,@"os_build":@""},
         @"device":[NSNull null],@"llvm":LlvmIdentity(),@"frameworks":[NSNull null],@"provenance":[NSNull null],
         @"gpu_work_submitted":@NO,@"guest_device_qualified":@NO,@"full_api_completion":@NO} mutableCopy];
      __block struct stela_metal_assembly *owner = NULL;
      int result = 1;
      @try {
         CHECK(entry.length && [entry lengthOfBytesUsingEncoding:NSUTF8StringEncoding] <= 4096 && expected.length == 64,
            @"Invalid test arguments");
         NSMutableData *input = ReadInput(argv[1]);
         record[@"input_bytes"] = @(input.length);
         CHECK([Digest(input) isEqualToString:expected],@"Evidence snapshot digest differs");
         NSMutableDictionary *host = [record[@"host"] mutableCopy]; host[@"os_build"] = OSBuild(); record[@"host"] = host;
         record[@"frameworks"] = @[
            FrameworkIdentity(@"NSStringFromClass",(const void *)&NSStringFromClass),
            FrameworkIdentity(@"CFGetTypeID",(const void *)&CFGetTypeID),
            FrameworkIdentity(@"MTLCreateSystemDefaultDevice",(const void *)&MTLCreateSystemDefaultDevice)
         ];
         CHECK([record[@"llvm"][@"major"] unsignedIntValue] == 23,@"Runtime requires LLVM23");
         struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
         struct stela_metal_assembly_error assemblyError;
         enum stela_metal_assembly_status status = stela_metal_assemble_archive(&options,input.bytes,input.length,&owner,&assemblyError);
         CHECK(status == STELA_METAL_ASSEMBLY_OK && owner != NULL,
            ([NSString stringWithFormat:@"Actual canonical assembler refused input: %s",assemblyError.detail]));
         const struct stela_metal_library_manifest *manifest = stela_metal_assembly_manifest(owner);
         CHECK(manifest != NULL,@"Assembler published no compute manifest");
         if (process.operatingSystemVersion.majorVersion < 26)
            [NSException raise:@"STELATestInconclusive" format:@"Host OS lacks required public object APIs"];
         id<MTLDevice> device = MTLCreateSystemDefaultDevice();
         if (!device) [NSException raise:@"STELATestInconclusive" format:@"INCONCLUSIVE_NO_HOST_METAL_DEVICE"];
         record[@"device"] = @{@"name":device.name,@"registry_id":@(device.registryID)};
         id<MTLLibrary> library = MakeLibrary(device,input,manifest);
         id<MTLFunction> baseline = [library newFunctionWithName:entry];
         CHECK(baseline != nil,@"Caller-selected entry is absent from genuine library");
         NSError *error = nil;
         STELAMetalFunctionSnapshot *snapshot = STELAMetalCopyFunctionSnapshot(baseline,device,&error);
         CHECK(snapshot != nil && !error,@"No genuine baseline snapshot");
         NSDictionary *identity = Identity(snapshot), *reflection = Reflection(snapshot.reflection);
         record[@"provenance"] = identity;
         NSArray *exports = [library.functionNames copy];
         Test(@"baseline", ^{
            CHECK([exports containsObject:entry] && library.type == MTLLibraryTypeExecutable,@"Wrong finite exports/type");
            CheckFunction(baseline,device,entry,identity,reflection);
         });
         Test(@"empty_values", ^{
            NSError *diagnostic = Sentinel();
            id<MTLFunction> function = [library newFunctionWithName:entry constantValues:[MTLFunctionConstantValues new] error:&diagnostic];
            CHECK(!diagnostic,@"Empty unmatched values produced a diagnostic");
            CheckFunction(function,device,entry,identity,reflection);
         });
         Test(@"indexed_values", ^{
            MTLFunctionConstantValues *values = [MTLFunctionConstantValues new]; uint32_t value = 7;
            [values setConstantValue:&value type:MTLDataTypeUInt atIndex:0];
            NSError *diagnostic = Sentinel();
            id<MTLFunction> function = [library newFunctionWithName:entry constantValues:values error:&diagnostic];
            CHECK(!diagnostic,@"Unmatched indexed value produced a diagnostic");
            CheckFunction(function,device,entry,identity,reflection);
         });
         Test(@"named_values", ^{
            MTLFunctionConstantValues *values = [MTLFunctionConstantValues new]; uint32_t value = 9;
            [values setConstantValue:&value type:MTLDataTypeUInt withName:@"stela_unmatched_constant"];
            NSError *diagnostic = Sentinel();
            id<MTLFunction> function = [library newFunctionWithName:entry constantValues:values error:&diagnostic];
            CHECK(!diagnostic,@"Unmatched named value produced a diagnostic");
            CheckFunction(function,device,entry,identity,reflection);
         });
         NSString *missing = [entry stringByAppendingString:@"__stela_missing"];
         while ([exports containsObject:missing]) missing = [missing stringByAppendingString:@"_"];
         Test(@"missing_name", ^{
            NSError *diagnostic = Sentinel();
            CHECK([library newFunctionWithName:missing constantValues:Values() error:&diagnostic] == nil,@"Missing name succeeded");
            CheckError(diagnostic,MTLLibraryErrorFunctionNotFound);
         });
         Test(@"optional_error", ^{
            CheckFunction([library newFunctionWithName:entry constantValues:Values() error:NULL],device,entry,identity,reflection);
            CHECK([library newFunctionWithName:missing constantValues:Values() error:NULL] == nil,@"Missing name with optional error succeeded");
         });
         Test(@"value_mutation", ^{
            MTLFunctionConstantValues *values = Values();
            id<MTLFunction> function = [library newFunctionWithName:entry constantValues:values error:NULL];
            [values reset]; values = nil;
            CheckFunction(function,device,entry,identity,reflection);
         });
         Test(@"async_values", ^{ AsyncCheck(AsyncValues,device,input,manifest,entry,identity,reflection,nil); });
         Test(@"async_missing", ^{ AsyncCheck(AsyncMissing,device,input,manifest,entry,identity,reflection,nil); });
         Test(@"descriptor_values", ^{
            MTLFunctionDescriptor *descriptor = [MTLFunctionDescriptor functionDescriptor];
            descriptor.name = entry; descriptor.constantValues = Values();
            NSError *diagnostic = Sentinel();
            id<MTLFunction> function = [library newFunctionWithDescriptor:descriptor error:&diagnostic];
            CHECK(!diagnostic,@"Descriptor unmatched values produced diagnostics");
            descriptor.name = missing; [descriptor.constantValues reset]; descriptor.constantValues = nil;
            CheckFunction(function,device,entry,identity,reflection);
         });
         Test(@"async_descriptor", ^{ AsyncCheck(AsyncDescriptor,device,input,manifest,entry,identity,reflection,nil); });
         Test(@"constructor_refusals", ^{
            struct stela_metal_library_manifest copy = *manifest;
            struct stela_metal_function_record *entries = malloc(copy.entry_count*sizeof(*entries));
            CHECK(entries != NULL,@"Negative-control allocation failed");
            memcpy(entries,copy.entries,copy.entry_count*sizeof(*entries)); copy.entries = entries;
            @try {
               copy.abi++; Refuse(device,input,&copy); copy.abi--;
               copy.reserved = 1; Refuse(device,input,&copy); copy.reserved = 0;
               uint32_t flags = entries[0].flags;
               entries[0].flags &= ~STELA_METAL_ENTRY_NO_CONSTANTS; Refuse(device,input,&copy); entries[0].flags = flags;
               uint32_t kind = entries[0].entry.kind;
               entries[0].entry.kind = 0; Refuse(device,input,&copy); entries[0].entry.kind = kind;
               uint64_t offset = entries[0].air_offset;
               entries[0].air_offset = UINT64_MAX; Refuse(device,input,&copy); entries[0].air_offset = offset;
               entries[0].entry.module_sha256[0] ^= 1; Refuse(device,input,&copy); entries[0].entry.module_sha256[0] ^= 1;
               NSMutableData *changed = [input mutableCopy]; ((uint8_t *)changed.mutableBytes)[0] ^= 1;
               Refuse(device,changed,manifest);
            } @finally { free(entries); }
         });
         Test(@"descriptor_refusals", ^{
            MTLFunctionDescriptor *descriptor = [MTLFunctionDescriptor functionDescriptor];
            descriptor.name = entry; descriptor.options = MTLFunctionOptionCompileToBinary;
            NSError *diagnostic = nil;
            CHECK([library newFunctionWithDescriptor:descriptor error:&diagnostic] == nil,@"Unsupported options succeeded");
            CheckError(diagnostic,MTLLibraryErrorUnsupported);
            MTLIntersectionFunctionDescriptor *intersection = [MTLIntersectionFunctionDescriptor new];
            intersection.name = entry; diagnostic = nil;
            CHECK([library newFunctionWithDescriptor:intersection error:&diagnostic] == nil,@"Intersection generic descriptor succeeded");
            CheckError(diagnostic,MTLLibraryErrorUnsupported); diagnostic = nil;
            CHECK([library newIntersectionFunctionWithDescriptor:intersection error:&diagnostic] == nil,@"Intersection factory succeeded");
            CheckError(diagnostic,MTLLibraryErrorUnsupported);
            AsyncCheck(AsyncUnsupported,device,input,manifest,entry,identity,reflection,nil);
            AsyncCheck(AsyncIntersection,device,input,manifest,entry,identity,reflection,nil);
         });
         Test(@"archive_refusal", ^{
            NSError *diagnostic = nil;
            id<MTLBinaryArchive> archive = [device newBinaryArchiveWithDescriptor:[MTLBinaryArchiveDescriptor new] error:&diagnostic];
            if (!archive) [NSException raise:@"STELATestInconclusive" format:@"Real host binary archive unavailable for required refusal control"];
            MTLFunctionDescriptor *descriptor = [MTLFunctionDescriptor functionDescriptor];
            descriptor.name = entry; descriptor.binaryArchives = @[archive]; diagnostic = nil;
            CHECK([library newFunctionWithDescriptor:descriptor error:&diagnostic] == nil,@"Unimplemented archive lookup succeeded");
            CheckError(diagnostic,MTLLibraryErrorUnsupported);
            AsyncCheck(AsyncArchive,device,input,manifest,entry,identity,reflection,archive);
         });
         Test(@"function_library_ownership", ^{
            FunctionOwnerCheck(device,input,manifest,entry,identity,reflection);
         });
         Test(@"snapshot_ownership", ^{
            SnapshotOwnerCheck(device,input,manifest,entry,identity,reflection);
         });
         Test(@"owned_input", ^{
            /* No manifest/entry pointer is accessed after this destruction. */
            stela_metal_assembly_destroy(&owner);
            memset(input.mutableBytes,0,input.length);
            CheckFunction(baseline,device,entry,identity,reflection);
            CHECK([library.functionNames isEqual:exports],@"Export table changed after caller retirement");
         });
         record[@"outcome"] = @"PASS"; result = 0;
      } @catch (NSException *exception) {
         BOOL inconclusive = [exception.name isEqualToString:@"STELATestInconclusive"];
         record[@"outcome"] = inconclusive ? @"INCONCLUSIVE" : @"FAIL";
         record[@"reason"] = exception.reason ?: @"Exception";
         result = inconclusive ? 3 : 1;
      } @finally { stela_metal_assembly_destroy(&owner); }
      NSError *jsonError = nil;
      NSData *output = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingSortedKeys error:&jsonError];
      if (!output || output.length > 1024u*1024u || fwrite(output.bytes,1,output.length,stdout) != output.length || fputc('\n',stdout) == EOF) {
         fputs("Cannot write bounded runtime record\n",stderr); return 1;
      }
      return result;
   }
}
