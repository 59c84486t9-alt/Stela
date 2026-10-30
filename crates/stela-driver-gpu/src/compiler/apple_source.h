/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_APPLE_SOURCE_H
#define STELA_METAL_APPLE_SOURCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A compiler profile identifies an observed Apple compiler ABI/build, not a GPU
 * family, Metal hardware feature set, or guest CPU capability advertisement. */
enum stela_msl_apple_profile {
   STELA_MSL_APPLE_32023_MACOS_27_2_ARM64 = 1,
};

enum stela_msl_status {
   STELA_MSL_OK,
   STELA_MSL_INPUT,
   STELA_MSL_UNSUPPORTED_HOST,
   STELA_MSL_UNQUALIFIED_CONFIG,
   STELA_MSL_LIBRARY,
   STELA_MSL_BUILD_MISMATCH,
   STELA_MSL_SYMBOL,
   STELA_MSL_RESOURCE,
   STELA_MSL_ALLOCATION,
   STELA_MSL_COMPILE_FAILED,
   STELA_MSL_INVALID_AIR,
};

struct stela_msl_error {
   enum stela_msl_status status;
   char detail[256];
};

struct stela_msl_apple_config {
   enum stela_msl_apple_profile profile;
   size_t max_source_bytes; /* 1..64 MiB. */
   size_t max_air_bytes; /* 4..64 MiB. */
   /* The private diagnostic allocator's matching disposal contract remains
    * unqualified. Requiring detailed diagnostics returns an explicit refusal;
    * otherwise CompileLog=NULL yields typed failure without leaking a log. */
   bool require_detailed_diagnostics;
};

struct stela_msl_request {
   const void *source; /* Original bytes, length excludes any terminating NUL. */
   size_t source_bytes;
   uint32_t language_version; /* Qualified independent source path: 0x40001. */
   bool fast_math; /* Qualified option: true. Other modes are explicit refusals. */
   const char *target_triple; /* Qualified target: air64_v29-apple-macosx27.2.0. */
};

struct stela_msl_build_identity {
   uint8_t gpucompiler_uuid[16];
   uint8_t implementation_uuid[16];
   uint8_t llvm_uuid[16];
   uint8_t lazy_library_sha256[32];
   uint8_t metal_stdlib_sha256[32];
   uint8_t metal_types_sha256[32];
};

struct stela_msl_output {
   uint8_t *air; /* Owned libc allocation; original complete wrapped/raw AIR. */
   size_t air_bytes;
   uint8_t source_sha256[32];
   uint8_t air_sha256[32];
   struct stela_msl_build_identity build;
};

struct stela_msl_apple_compiler;

struct stela_msl_apple_config stela_msl_apple_default_config(void);
enum stela_msl_status stela_msl_apple_validate_config(
   const struct stela_msl_apple_config *config, struct stela_msl_error *error);
enum stela_msl_status stela_msl_apple_validate_request(
   const struct stela_msl_apple_config *config, const struct stela_msl_request *request,
   struct stela_msl_error *error);

/* Native ARM macOS user-space component. The existing Apple compiler supplies
 * MSL parsing, standard headers, optimization and AIR emission. No MTLDevice,
 * IOKit/GPU object, command, Metal API facade or freestanding service is created.
 * A dedicated compiler process supplies its normal Darwin services and owns
 * external watchdog/cancellation policy. This library does not install alarms,
 * mutate process settings, or construct C++ compiler objects across an ABI.
 *
 * The current exact profile checks the compiler/LLVM UUIDs and matching lazy
 * library hash before any private compiler call. Unknown builds are refused.
 * All private requests made through this component are serialized; concurrent
 * close/compile on the same handle is a caller ownership error. */
enum stela_msl_status stela_msl_apple_open(
   const struct stela_msl_apple_config *config,
   struct stela_msl_apple_compiler **compiler, struct stela_msl_error *error);
void stela_msl_apple_close(struct stela_msl_apple_compiler *compiler);

/* Output must be zero-initialized/unowned. Failure leaves it unchanged. Each
 * compile owns its matching Apple LLVM context/compiler/buffer, copies AIR to
 * ordinary owned bytes, and disposes all Apple objects before returning. The
 * result has no LLVM/dylib lifetime dependency. The caller records the request's
 * target, language, math option and exact profile beside these identities, then
 * uses the production AIR parser/bridge; a magic check is not LLVM verification.
 * This source subset qualification does not establish complete Metal support. */
enum stela_msl_status stela_msl_apple_compile(
   struct stela_msl_apple_compiler *compiler, const struct stela_msl_request *request,
   struct stela_msl_output *output, struct stela_msl_error *error);
void stela_msl_output_destroy(struct stela_msl_output *output);

#ifdef __cplusplus
}
#endif

#endif
