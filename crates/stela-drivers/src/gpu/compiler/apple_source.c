/* SPDX-License-Identifier: MIT */
#include "apple_source.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSL_LIMIT (64u * 1024u * 1024u)
static const char qualified_target[] = "air64_v29-apple-macosx27.2.0";

static enum stela_msl_status
report(struct stela_msl_error *error, enum stela_msl_status status,
       const char *format, ...)
{
   if (error) {
      error->status = status;
      va_list arguments;
      va_start(arguments, format);
      vsnprintf(error->detail, sizeof(error->detail), format, arguments);
      va_end(arguments);
   }
   return status;
}

struct stela_msl_apple_config
stela_msl_apple_default_config(void)
{
   return (struct stela_msl_apple_config) {
      .profile = STELA_MSL_APPLE_32023_MACOS_27_2_ARM64,
      .max_source_bytes = MSL_LIMIT, .max_air_bytes = MSL_LIMIT,
   };
}

enum stela_msl_status
stela_msl_apple_validate_config(const struct stela_msl_apple_config *config,
                                struct stela_msl_error *error)
{
   if (!config || !config->max_source_bytes || config->max_source_bytes > MSL_LIMIT ||
       config->max_air_bytes < 4 || config->max_air_bytes > MSL_LIMIT)
      return report(error, STELA_MSL_INPUT, "invalid compiler input/output bounds");
   if (config->profile != STELA_MSL_APPLE_32023_MACOS_27_2_ARM64 ||
       config->require_detailed_diagnostics)
      return report(error, STELA_MSL_UNQUALIFIED_CONFIG,
                    "unqualified compiler profile or diagnostic ownership requirement");
   return report(error, STELA_MSL_OK, "");
}

enum stela_msl_status
stela_msl_apple_validate_request(const struct stela_msl_apple_config *config,
                                const struct stela_msl_request *request,
                                struct stela_msl_error *error)
{
   enum stela_msl_status status = stela_msl_apple_validate_config(config, error);
   if (status != STELA_MSL_OK)
      return status;
   if (!request || !request->source || !request->source_bytes ||
       request->source_bytes > config->max_source_bytes ||
       memchr(request->source, '\0', request->source_bytes))
      return report(error, STELA_MSL_INPUT, "invalid source length, bounds or embedded NUL");
   if (request->language_version != 0x40001 || !request->fast_math ||
       !request->target_triple || strcmp(request->target_triple, qualified_target))
      return report(error, STELA_MSL_UNQUALIFIED_CONFIG,
                    "independent source profile requires Metal 4.1, fast math and target %s",
                    qualified_target);
   return report(error, STELA_MSL_OK, "");
}

void
stela_msl_output_destroy(struct stela_msl_output *output)
{
   if (output) {
      free(output->air);
      memset(output, 0, sizeof(*output));
   }
}

#if defined(__APPLE__) && defined(__arm64__)
#include "llvm-c/Core.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

/* Reverse-engineered exact C ABI, version pinned below. No C++ object layout or
 * allocator crosses this interface. Header arrays are always NULL/count zero;
 * nonzero header-count semantics are not exposed by this component. */
typedef void *(*apple_create)(int debug_mode);
typedef void (*apple_destroy)(void *compiler);
typedef int (*apple_target)(void *compiler, const char *triple);
typedef int (*apple_compile)(void *compiler, LLVMContextRef context, const char *source,
                             const char *const *headers, const char *const *header_names,
                             size_t header_count, const char *options,
                             char **compile_log, LLVMMemoryBufferRef *output);

struct stela_msl_apple_compiler {
   struct stela_msl_apple_config config;
   struct stela_msl_build_identity build;
   void *gpu_library;
   void *llvm_library;
   apple_create create;
   apple_destroy destroy;
   apple_target target;
   apple_compile compile;
   __typeof__(&LLVMContextCreate) context_create;
   __typeof__(&LLVMContextDispose) context_dispose;
   __typeof__(&LLVMGetBufferStart) buffer_start;
   __typeof__(&LLVMGetBufferSize) buffer_size;
   __typeof__(&LLVMDisposeMemoryBuffer) buffer_dispose;
};

#define APPLE_ROOT "/System/Library/PrivateFrameworks/GPUCompiler.framework/Versions/32023/Libraries/"
#define METAL_INCLUDE APPLE_ROOT "lib/clang/32023/include/metal"
static const char qualified_options[] = "-x metal -std=metal4.1 -ffast-math -I"
   METAL_INCLUDE " -finclude-default-header";
static const uint8_t gpu_uuid[16] = {
   0x84,0x07,0xc6,0x0c,0xc7,0x0b,0x3b,0x1c,0x81,0x7d,0x9e,0x62,0x33,0xf5,0xee,0x6c};
static const uint8_t llvm_uuid[16] = {
   0xbf,0x7e,0x70,0x5c,0x2f,0xe2,0x3c,0x0c,0xaa,0xa8,0xd6,0x7d,0x03,0xb9,0xd9,0xe0};
static const uint8_t implementation_uuid[16] = {
   0xcc,0xea,0x54,0xf6,0x74,0x8f,0x3e,0x98,0x9f,0x8c,0xda,0xc7,0xe4,0x6b,0x68,0x1a};
static const uint8_t lazy_sha256[32] = {
   0xf6,0xf3,0x96,0xf1,0xde,0x9d,0xa1,0x5a,0xde,0x12,0x7b,0x54,0xad,0xc2,0x0a,0x82,
   0xa2,0xd4,0x82,0xe8,0x34,0x53,0xbc,0x67,0xa5,0x5e,0x34,0x91,0x9f,0xb8,0xb8,0x9b};
static pthread_mutex_t compiler_lock = PTHREAD_MUTEX_INITIALIZER;

static bool
image_uuid(const struct mach_header *header, uint8_t uuid[16])
{
   const struct mach_header_64 *h = (const void *)header;
   if (!h || h->magic != MH_MAGIC_64 || h->ncmds > 1024 || h->sizeofcmds > 1024 * 1024)
      return false;
   const uint8_t *command = (const void *)(h + 1), *end = command + h->sizeofcmds;
   bool found = false;
   for (unsigned i = 0; i < h->ncmds; i++) {
      if ((size_t)(end - command) < sizeof(struct load_command))
         return false;
      const struct load_command *c = (const void *)command;
      if (c->cmdsize < sizeof(*c) || c->cmdsize > (size_t)(end - command))
         return false;
      if (c->cmd == LC_UUID) {
         if (found || c->cmdsize != sizeof(struct uuid_command))
            return false;
         memcpy(uuid, ((const struct uuid_command *)c)->uuid, 16);
         found = true;
      }
      command += c->cmdsize;
   }
   return found;
}

static void *
qualified_symbol(void *library, const char *name, const uint8_t expected_uuid[16])
{
   void *symbol = dlsym(library, name);
   Dl_info image = {0};
   uint8_t uuid[16];
   return symbol && dladdr(symbol, &image) && image_uuid(image.dli_fbase, uuid) &&
          !memcmp(uuid, expected_uuid, 16) ? symbol : NULL;
}

static bool
hash_file(const char *path, size_t maximum, uint8_t digest[32])
{
   int file = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
   if (file < 0)
      return false;
   struct stat metadata = {0};
   bool valid = !fstat(file, &metadata) && S_ISREG(metadata.st_mode) &&
                metadata.st_size > 0 && (uint64_t)metadata.st_size <= maximum;
   CC_SHA256_CTX hash;
   CC_SHA256_Init(&hash);
   uint8_t buffer[8192];
   size_t consumed = 0;
   while (valid) {
      ssize_t size = read(file, buffer, sizeof(buffer));
      if (size < 0 && errno == EINTR)
         continue;
      if (size < 0 || (size_t)size > maximum - consumed) {
         valid = false;
         break;
      }
      if (!size)
         break;
      consumed += (size_t)size;
      CC_SHA256_Update(&hash, buffer, (CC_LONG)size);
   }
   valid &= consumed == (uint64_t)metadata.st_size;
   valid &= !close(file);
   if (valid)
      CC_SHA256_Final(digest, &hash);
   return valid;
}

void
stela_msl_apple_close(struct stela_msl_apple_compiler *compiler)
{
   if (compiler) {
      if (compiler->gpu_library)
         dlclose(compiler->gpu_library);
      if (compiler->llvm_library)
         dlclose(compiler->llvm_library);
      free(compiler);
   }
}

enum stela_msl_status
stela_msl_apple_open(const struct stela_msl_apple_config *config,
                     struct stela_msl_apple_compiler **output,
                     struct stela_msl_error *error)
{
   enum stela_msl_status status = stela_msl_apple_validate_config(config, error);
   if (status != STELA_MSL_OK)
      return status;
   if (!output || *output)
      return report(error, STELA_MSL_INPUT, "compiler output handle must be empty");
   struct stela_msl_apple_compiler *c = calloc(1, sizeof(*c));
   if (!c)
      return report(error, STELA_MSL_ALLOCATION, "compiler adapter allocation failed");
   c->config = *config;
   if (!hash_file(APPLE_ROOT "libGPUCompilerImplLazy.dylib", 256u * 1024u * 1024u,
                  c->build.lazy_library_sha256) ||
       memcmp(c->build.lazy_library_sha256, lazy_sha256, 32)) {
      status = report(error, STELA_MSL_BUILD_MISMATCH, "unqualified Apple lazy compiler image");
      goto fail;
   }
   if (!hash_file(METAL_INCLUDE "/metal_stdlib", 4u * 1024u * 1024u, c->build.metal_stdlib_sha256) ||
       !hash_file(METAL_INCLUDE "/metal_types", 4u * 1024u * 1024u, c->build.metal_types_sha256)) {
      status = report(error, STELA_MSL_RESOURCE, "matching Apple Metal standard headers unavailable");
      goto fail;
   }
   c->gpu_library = dlopen(APPLE_ROOT "libGPUCompiler.dylib", RTLD_NOW | RTLD_LOCAL);
   c->llvm_library = dlopen(APPLE_ROOT "libLLVM.dylib", RTLD_NOW | RTLD_LOCAL);
   if (!c->gpu_library || !c->llvm_library) {
      status = report(error, STELA_MSL_LIBRARY, "matching Apple compiler/LLVM could not load");
      goto fail;
   }
   bool implementation_matches = false;
   for (unsigned i = 0; i < _dyld_image_count(); i++) {
      const char *path = _dyld_get_image_name(i);
      if (path && !strcmp(path, APPLE_ROOT "libGPUCompilerImpl.dylib")) {
         implementation_matches = image_uuid(_dyld_get_image_header(i), c->build.implementation_uuid) &&
            !memcmp(c->build.implementation_uuid, implementation_uuid, 16);
         break;
      }
   }
   if (!implementation_matches) {
      status = report(error, STELA_MSL_BUILD_MISMATCH, "unqualified Apple compiler implementation image");
      goto fail;
   }
#define LOAD(field, library, name, uuid) do { \
   c->field = (__typeof__(c->field))qualified_symbol(c->library, name, uuid); \
   if (!c->field) { status = report(error, STELA_MSL_SYMBOL, "unqualified compiler symbol: %s", name); goto fail; } \
} while (0)
   LOAD(create, gpu_library, "MTLGPUCompilerCreate", gpu_uuid);
   LOAD(destroy, gpu_library, "MTLGPUCompilerDestroy", gpu_uuid);
   LOAD(target, gpu_library, "MTLGPUCompilerSetTargetTriple", gpu_uuid);
   LOAD(compile, gpu_library, "MTLGPUCompilerCompileFromSourceToBuffer", gpu_uuid);
   LOAD(context_create, llvm_library, "LLVMContextCreate", llvm_uuid);
   LOAD(context_dispose, llvm_library, "LLVMContextDispose", llvm_uuid);
   LOAD(buffer_start, llvm_library, "LLVMGetBufferStart", llvm_uuid);
   LOAD(buffer_size, llvm_library, "LLVMGetBufferSize", llvm_uuid);
   LOAD(buffer_dispose, llvm_library, "LLVMDisposeMemoryBuffer", llvm_uuid);
#undef LOAD
   memcpy(c->build.gpucompiler_uuid, gpu_uuid, 16);
   memcpy(c->build.llvm_uuid, llvm_uuid, 16);
   *output = c;
   return report(error, STELA_MSL_OK, "");
fail:
   stela_msl_apple_close(c);
   return status;
}

enum stela_msl_status
stela_msl_apple_compile(struct stela_msl_apple_compiler *compiler,
                        const struct stela_msl_request *request,
                        struct stela_msl_output *output, struct stela_msl_error *error)
{
   if (!compiler || !output || output->air || output->air_bytes)
      return report(error, STELA_MSL_INPUT, "compiler/output ownership is invalid");
   enum stela_msl_status status = stela_msl_apple_validate_request(&compiler->config, request, error);
   if (status != STELA_MSL_OK)
      return status;
   const size_t source_bytes = request->source_bytes;
   char *source = malloc(source_bytes + 1);
   if (!source)
      return report(error, STELA_MSL_ALLOCATION, "source buffer allocation failed");
   memcpy(source, request->source, source_bytes);
   source[source_bytes] = '\0';
   if (pthread_mutex_lock(&compiler_lock)) {
      free(source);
      return report(error, STELA_MSL_LIBRARY, "compiler process serialization failed");
   }
   struct stela_msl_output result = {.build = compiler->build};
   LLVMContextRef context = compiler->context_create();
   void *gpu = context ? compiler->create(0) : NULL;
   LLVMMemoryBufferRef buffer = NULL;
   if (!context || !gpu) {
      status = report(error, STELA_MSL_ALLOCATION, "Apple compiler/context allocation failed");
   } else if (!compiler->target(gpu, qualified_target)) {
      status = report(error, STELA_MSL_UNQUALIFIED_CONFIG, "Apple compiler refused qualified target");
   } else if (!compiler->compile(gpu, context, source, NULL, NULL, 0,
                                 qualified_options, NULL, &buffer)) {
      status = report(error, STELA_MSL_COMPILE_FAILED,
                      "Apple MSL compiler rejected source; detailed diagnostic ownership unqualified");
   } else {
      size_t length = buffer ? compiler->buffer_size(buffer) : 0;
      const char *bytes = buffer ? compiler->buffer_start(buffer) : NULL;
      bool magic = bytes && length >= 4 &&
         (!memcmp(bytes, "BC\xc0\xde", 4) ||
          (length >= 20 && !memcmp(bytes, "\xde\xc0\x17\x0b", 4)));
      if (!magic || length > compiler->config.max_air_bytes) {
         status = report(error, STELA_MSL_INVALID_AIR, "Apple compiler output framing/size refused");
      } else if (!(result.air = malloc(length))) {
         status = report(error, STELA_MSL_ALLOCATION, "AIR output allocation failed");
      } else {
         memcpy(result.air, bytes, length);
         result.air_bytes = length;
         CC_SHA256(source, (CC_LONG)source_bytes, result.source_sha256);
         CC_SHA256(bytes, (CC_LONG)length, result.air_sha256);
         status = STELA_MSL_OK;
      }
   }
   if (buffer)
      compiler->buffer_dispose(buffer);
   if (gpu)
      compiler->destroy(gpu);
   if (context)
      compiler->context_dispose(context);
   pthread_mutex_unlock(&compiler_lock);
   free(source);
   if (status == STELA_MSL_OK) {
      *output = result;
      return report(error, STELA_MSL_OK, "");
   }
   stela_msl_output_destroy(&result);
   return status;
}

#else
enum stela_msl_status
stela_msl_apple_open(const struct stela_msl_apple_config *config,
                     struct stela_msl_apple_compiler **compiler,
                     struct stela_msl_error *error)
{
   (void)config; (void)compiler;
   return report(error, STELA_MSL_UNSUPPORTED_HOST, "native ARM macOS compiler process required");
}
void stela_msl_apple_close(struct stela_msl_apple_compiler *compiler) { (void)compiler; }
enum stela_msl_status
stela_msl_apple_compile(struct stela_msl_apple_compiler *compiler,
                        const struct stela_msl_request *request,
                        struct stela_msl_output *output, struct stela_msl_error *error)
{
   (void)compiler; (void)request; (void)output;
   return report(error, STELA_MSL_UNSUPPORTED_HOST, "native ARM macOS compiler process required");
}
#endif
