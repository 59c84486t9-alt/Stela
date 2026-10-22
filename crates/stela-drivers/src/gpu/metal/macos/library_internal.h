/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_LIBRARY_INTERNAL_H
#define STELA_METAL_LIBRARY_INTERNAL_H
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "library_manifest.h"

NS_ASSUME_NONNULL_BEGIN

/* Immutable first-party pipeline input, never Apple libraryData/functionData.
 * The complete downstream device pipeline override must validate actual device
 * support, request/specialization/bindings and invoke the real compiler/backend.
 * This object cannot itself produce a successful Metal pipeline. */
@interface STELAMetalFunctionSnapshot : NSObject
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
@property (nonatomic, readonly) NSData *originalInput;
@property (nonatomic, readonly) NSRange rawAIRRange;
@property (nonatomic, readonly) NSString *entryName;
@property (nonatomic, readonly) NSString *targetTriple;
@property (nonatomic, readonly) MTLFunctionReflection *reflection;
@property (nonatomic, readonly) NSData *originalSHA256;
@property (nonatomic, readonly) NSData *moduleSHA256;
@property (nonatomic, readonly) NSData *rawAIRSHA256;
@property (nonatomic, readonly) NSData *sourceSHA256;
@property (nonatomic, readonly) NSData *compilerBuildIdentity;
@property (nonatomic, readonly) uint32_t compilerProfile;
@property (nonatomic, readonly) uint32_t requestLanguage;
@property (nonatomic, readonly) BOOL requestFastMath;
@property (nonatomic, readonly) uint32_t airMajor;
@property (nonatomic, readonly) uint32_t airMinor;
@property (nonatomic, readonly) uint32_t languageMajor;
@property (nonatomic, readonly) uint32_t languageMinor;
@end

/* Requires a real creating device supplied by the registered device owner;
 * creates no device, connection, service or backend. Failure returns nil and a
 * public MTLLibraryErrorDomain error. Source compiler invocation/option mapping
 * is deliberately outside this object boundary and stays profile-qualified.
 * Original bytes are copied to immutable Foundation storage before publication.
 * All manifest/header fields and original/module/raw hashes are checked first.
 */
FOUNDATION_EXPORT id<MTLLibrary> _Nullable STELAMetalCreateLibrary(id<MTLDevice> device,
   NSData *original, const struct stela_metal_library_manifest *manifest,
   NSError * _Nullable __autoreleasing * _Nullable error);

/* Returns nil on device/implementation mismatch, never invokes inherited Apple
 * libraryData/compiler methods. The returned immutable object retains bytes. */
FOUNDATION_EXPORT STELAMetalFunctionSnapshot * _Nullable STELAMetalCopyFunctionSnapshot(
   id<MTLFunction> function, id<MTLDevice> expectedDevice,
   NSError * _Nullable __autoreleasing * _Nullable error);
NS_ASSUME_NONNULL_END
#endif
