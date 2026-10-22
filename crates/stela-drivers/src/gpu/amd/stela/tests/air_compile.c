/* SPDX-License-Identifier: MIT */
/* Hosted ownership/ABI and retained compiler tests only. Target/VM facts and
 * upload addresses are CPU models; no initialized physical GPU is claimed. */
#include "../hosted/air_compile.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/sid.h"
#include "amd/compiler/aco_interface.h"
#include "stela/tests/air_test_fixture.h"
#include "stela/tests/targets/amd.h"
#include "stela/tests/threadgroup_record.h"
#include "util/ralloc.h"
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#error "Owned compilation tests require active assertions"
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); abort(); } } while (0)

/* Test-object-only renaming of the new owner's direct libc allocations. Mesa,
 * LLVM, Rust and Foundation retain their original allocators. */
static unsigned allocations, fail_allocation, live_allocations;
void *stela_amd_air_test_malloc(size_t size);
void *stela_amd_air_test_calloc(size_t count, size_t size);
void stela_amd_air_test_free(void *pointer);
void *stela_amd_air_test_malloc(size_t size)
{
   if (++allocations == fail_allocation)
      return NULL;
   void *p = malloc(size);
   if (p) live_allocations++;
   return p;
}
void *stela_amd_air_test_calloc(size_t count, size_t size)
{
   if (++allocations == fail_allocation)
      return NULL;
   void *p = calloc(count, size);
   if (p) live_allocations++;
   return p;
}
void stela_amd_air_test_free(void *pointer)
{
   if (pointer) { CHECK(live_allocations); live_allocations--; }
   free(pointer);
}

struct bytes { uint8_t *data; size_t size; };
static void append(struct bytes *bytes, const void *data, size_t size)
{
   CHECK(size <= SIZE_MAX - bytes->size);
   bytes->data = realloc(bytes->data, bytes->size + size);
   CHECK(bytes->data);
   memcpy(bytes->data + bytes->size, data, size);
   bytes->size += size;
}
static void little(void *data, uint64_t value, unsigned bytes)
{
   for (unsigned i = 0; i < bytes; i++) ((uint8_t *)data)[i] = (uint8_t)(value >> (8 * i));
}
static void tag(struct bytes *bytes, const char name[4], const void *data, size_t size)
{
   CHECK(size <= UINT16_MAX);
   uint8_t length[2]; little(length, size, 2);
   append(bytes, name, 4); append(bytes, length, 2); append(bytes, data, size);
}
static void digest(const void *bytes, size_t size, uint8_t output[32])
{
   CHECK(size <= AIR_MAX_BITCODE_BYTES);
   CC_SHA256(bytes, (CC_LONG)size, output);
}
/* Own one-entry framing fixture, never a second parser. The production Rust
 * parser and shared inspector independently validate all original extents. */
static struct bytes archive(const void *air, size_t size, const char *name,
                            unsigned air_minor, unsigned major, unsigned minor,
                            unsigned os_major, unsigned os_minor)
{
   struct bytes record = {0}; uint8_t prefix[4] = {0}, kind = 2, hash[32];
   append(&record, prefix, 4); tag(&record, "NAME", name, strlen(name) + 1);
   tag(&record, "TYPE", &kind, 1); digest(air, size, hash); tag(&record, "HASH", hash, 32);
   uint8_t length[8], offsets[24] = {0}, versions[8]; little(length, size, 8);
   tag(&record, "MDSZ", length, 8); tag(&record, "OFFT", offsets, 24);
   little(versions, 2, 2); little(versions + 2, air_minor, 2);
   little(versions + 4, major, 2); little(versions + 6, minor, 2);
   tag(&record, "VERS", versions, 8); append(&record, "ENDT", 4); little(record.data, record.size, 4);
   uint8_t header[88] = {0}; memcpy(header, "MTLB", 4);
   little(header + 4, 0x8001, 2); little(header + 6, 2, 2); little(header + 8, 9, 2);
   header[11] = 0x81; little(header + 12, os_major, 2); little(header + 14, os_minor, 2);
   size_t start = 92 + record.size;
   little(header + 16, start + size, 8); little(header + 24, 88, 8); little(header + 32, record.size, 8);
   little(header + 40, start, 8); little(header + 56, start, 8);
   little(header + 72, start, 8); little(header + 80, size, 8);
   struct bytes result = {0}; append(&result, header, sizeof(header));
   little(prefix, 1, 4); append(&result, prefix, 4); append(&result, record.data, record.size);
   append(&result, air, size); free(record.data); return result;
}
static struct stela_metal_assembly *assemble(const struct bytes *bytes)
{
   struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error; struct stela_metal_assembly *library = NULL;
   enum stela_metal_assembly_status status = stela_metal_assemble_archive(
      &options, bytes->data, bytes->size, &library, &error);
   if (status) fprintf(stderr, "assembly refused: %u %s\n", status, error.detail);
   CHECK(status == STELA_METAL_ASSEMBLY_OK && library);
   return library;
}
static struct stela_metal_assembly *fixture(LLVMMemoryBufferRef air)
{
   struct bytes bytes = archive(LLVMGetBufferStart(air), LLVMGetBufferSize(air), "kernel", 8, 4, 0, 26, 7);
   struct stela_metal_assembly *library = assemble(&bytes); free(bytes.data); return library;
}
static struct stela_metal_assembly *two_entries(LLVMMemoryBufferRef air)
{
   size_t size = LLVMGetBufferSize(air);
   struct bytes a = archive(LLVMGetBufferStart(air), size, "kernel", 8, 4, 0, 26, 7);
   struct bytes b = archive(LLVMGetBufferStart(air), size, "other", 8, 4, 0, 26, 7);
   size_t a_record = a.size - 92 - size, b_record = b.size - 92 - size;
   size_t start = 92 + a_record + b_record;
   uint8_t header[88], count[4]; memcpy(header, a.data, sizeof(header));
   little(header + 16, start + size, 8); little(header + 32, a_record + b_record, 8);
   little(header + 40, start, 8); little(header + 56, start, 8); little(header + 72, start, 8);
   little(count, 2, 4);
   struct bytes bytes = {0}; append(&bytes, header, sizeof(header)); append(&bytes, count, 4);
   append(&bytes, a.data + 92, a_record); append(&bytes, b.data + 92, b_record);
   append(&bytes, LLVMGetBufferStart(air), size);
   struct stela_metal_assembly *library = assemble(&bytes);
   free(a.data); free(b.data); free(bytes.data); return library;
}
static struct radeon_info model(enum radeon_family family, bool graphics)
{
   struct radeon_info info = {
      .family = family, .gfx_level = ac_get_gfx_level(family), .has_graphics = graphics,
      .num_cu = 8, .num_se = 2, .max_se = 2, .spi_cu_en = UINT32_MAX,
      .max_good_cu_per_sa = 4, .max_sa_per_se = 1,
      .virtual_address_max = UINT64_C(0x800000000000), .virtual_address_alignment = 4096,
      .tcc_cache_line_size = 128,
   };
   ac_fill_compiler_info(&info, NULL, false);
   info.instr_prefetch_distance = info.gfx_level >= GFX11 ? 4 : 0;
   return info;
}
static struct stela_amd_air_options options(unsigned wave)
{
   return (struct stela_amd_air_options) {
      .size = sizeof(struct stela_amd_air_options), .abi = STELA_AMD_AIR_ABI,
      .wave_size = wave, .workgroup_size = {32, 1, 1}, .max_instructions = 4096,
      .max_code_bytes = 1024u * 1024u,
   };
}
static struct stela_amd_air_compilation *compile(const struct radeon_info *info,
   struct stela_metal_assembly *library, const struct stela_amd_air_options *opts,
   enum stela_amd_air_status expected)
{
   struct stela_amd_air_compilation *result = NULL; struct stela_amd_air_error error;
#ifdef STELA_AMD_AIR_ALLOC_TEST
   unsigned baseline = live_allocations;
#endif
   enum stela_amd_air_status status = stela_amd_air_compile(info, library, 0, opts, &result, &error);
   if (status != expected) fprintf(stderr, "compile %s: %u expected %u: %s (AIR %u %s)\n",
      ac_get_family_name(info->family), status, expected, error.detail, error.air.kind, error.air.detail);
   CHECK(status == expected && error.status == status && (result != NULL) == (status == STELA_AMD_AIR_OK));
#ifdef STELA_AMD_AIR_ALLOC_TEST
   if (status != STELA_AMD_AIR_OK) CHECK(live_allocations == baseline);
#endif
   return result;
}
static void destroy(struct stela_amd_air_compilation **owner)
{
   stela_amd_air_destroy(owner); CHECK(!*owner);
   stela_amd_air_destroy(owner); stela_amd_air_destroy(NULL);
}
struct reference {const struct stela_amd_air_compilation *owner; unsigned count;};
static void reference_binary(void **private, const struct ac_shader_config *config,
   const char *ir, unsigned ir_size, const char *assembly, unsigned assembly_size,
   struct amd_stats *stats, uint32_t exec_size, const uint32_t *code, uint32_t code_dw,
   const struct aco_symbol *symbols, unsigned symbol_count,
   const struct ac_shader_debug_info *debug, unsigned debug_count)
{
   (void)ir; (void)ir_size; (void)assembly; (void)assembly_size; (void)stats;
   (void)symbols; (void)debug; (void)debug_count;
   struct reference *ref = *private;
   const struct stela_amd_compute_binary *binary = stela_amd_air_binary(ref->owner);
   CHECK(!ref->count++ && !symbol_count && exec_size == binary->executable_bytes && code_dw * 4 == binary->code_bytes &&
      !memcmp(code, stela_amd_air_code(ref->owner), binary->code_bytes) &&
      !memcmp(config, binary->config, sizeof(*config)));
}
static uint32_t
register_word(const uint32_t *words, unsigned count, unsigned reg)
{
   for (unsigned cursor = 0; cursor < count;) {
      const unsigned header = words[cursor], length = ((header >> 16) & 0x3fff) + 2;
      CHECK(header >> 30 == 3 && length <= count - cursor &&
            ((header >> 8) & 255) == PKT3_SET_SH_REG && length >= 3);
      const unsigned start = 0xb000 + 4 * words[cursor + 1];
      for (unsigned i = 2; i < length; i++) {
         if (start + 4 * (i - 2) == reg)
            return words[cursor + i];
      }
      cursor += length;
   }
   CHECK(false);
   return 0;
}

/* A fixture's compile target: "<fixture>/<family>.wave<N>". */
static void owned_target(char name[64], const char *fixture, enum radeon_family family, unsigned wave)
{
   snprintf(name, 64, "%s/%s.wave%u", fixture, ac_get_family_name(family), wave);
}
static void expect_owned(const char *fixture, enum radeon_family family, unsigned wave)
{
   char target[64];
   owned_target(target, fixture, family, wave);
   record_expect(target, stela_amd_aco_hold(family));
}
static void validate_result(const struct radeon_info *info, struct stela_amd_air_compilation *owner,
                            const char *fixture)
{
   const struct stela_amd_compute_binary *binary = stela_amd_air_binary(owner);
   const struct stela_amd_air_provenance *p = stela_amd_air_provenance(owner);
   uint32_t count; const struct stela_amd_air_binding *bindings = stela_amd_air_bindings(owner, &count);
   CHECK(binary && p && bindings && stela_amd_air_code(owner));
   CHECK(binary->code_bytes >= binary->executable_bytes && binary->executable_bytes > 0 &&
      binary->shader->options && binary->config->num_vgprs && binary->args->return_count == 0);
   CHECK(binary->family == info->family && binary->gfx_level == info->gfx_level);
   CHECK(!memcmp(&p->compiler_info, &info->compiler_info, sizeof(p->compiler_info)));
   CHECK(p->pci_id == info->pci_id && p->pci_rev_id == info->pci_rev_id && p->has_graphics == info->has_graphics);
   CHECK(binary->shader->options->max_workgroup_invocations >= 32 && p->name && p->target);
   nir_validate_shader((nir_shader *)binary->shader, "retained owned compile result");
   /* Original backend callback is an independent byte/config oracle for the
    * owner's copied result. Compile a real NIR clone through unchanged ACO;
    * inspection below also happens after its temporary vectors are destroyed. */
   nir_shader *copy = nir_shader_clone(NULL, binary->shader);
   CHECK(copy);
   const struct aco_compiler_options opts = {.compiler_info = &info->compiler_info,
      .family = info->family, .gfx_level = info->gfx_level};
   const struct aco_shader_info shader_info = {.hw_stage = AC_HW_COMPUTE_SHADER,
      .lds_size = binary->shader->info.shared_size,
      .wave_size = (uint8_t)binary->wave_size, .workgroup_size =
         binary->shader->info.workgroup_size[0] * binary->shader->info.workgroup_size[1] * binary->shader->info.workgroup_size[2]};
   struct reference ref = {.owner = owner}; void *private = &ref;
   aco_compile_shader(&opts, &shader_info, 1, &copy, binary->args, reference_binary, &private);
   CHECK(ref.count == 1); ralloc_free(copy);
   struct stela_amd_compute_binding runtime[STELA_AMD_AIR_MAX_BUFFERS] = {0};
   bool seen[AC_MAX_ARGS] = {false};
   nir_foreach_function_impl(impl, (nir_shader *)binary->shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic) continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            if (intr->intrinsic == nir_intrinsic_load_scalar_arg_amd && nir_intrinsic_base(intr) < AC_MAX_ARGS)
               seen[nir_intrinsic_base(intr)] = true;
         }
      }
   }
   for (unsigned i = 0; i < count; i++) {
      struct ac_arg arg = bindings[i].argument;
      CHECK(arg.used && arg.arg_index < binary->args->arg_count &&
         binary->args->args[arg.arg_index].file == AC_ARG_SGPR &&
         binary->args->args[arg.arg_index].offset == 2 * i && binary->args->args[arg.arg_index].size == 2);
      runtime[i] = (struct stela_amd_compute_binding) {.argument = arg,
         .view = {.allocation_va = UINT64_C(0x100000) + (uint64_t)i * 4096,
            .allocation_bytes = 4096, .range = 4096, .required_alignment = bindings[i].buffer.type_alignment}};
      CHECK(bindings[i].buffer.address_space == 1 && bindings[i].buffer.type_alignment);
      bool used = false;
      for (unsigned a = 0; a < p->argument_count; a++)
         if (p->arguments[a].buffer.argument == bindings[i].buffer.argument) used = p->arguments[a].used;
      if (used) CHECK(seen[arg.arg_index]);
   }
   const unsigned padded = ac_align_shader_binary_for_prefetch(info->gfx_level,
      info->instr_prefetch_distance, binary->code_bytes);
   struct stela_amd_buffer_view code = {.allocation_va = UINT64_C(0x400000),
      .allocation_bytes = padded, .range = padded, .required_alignment = 256};
   struct stela_amd_compute_pipeline pipeline;
   enum stela_amd_compute_status status = stela_amd_build_compute_pipeline(info, binary, &code, runtime, count, &pipeline);
   if (binary->config->scratch_bytes_per_wave)
      CHECK(status == STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE);
   else if (count)
      CHECK(status == STELA_AMD_COMPUTE_OK && pipeline.user_sgpr_count == 2 * count);
   else {
      CHECK(status == STELA_AMD_COMPUTE_OK && !pipeline.user_sgpr_count &&
         !G_00B84C_USER_SGPR(pipeline.rsrc2));
      struct stela_amd_compute_pipeline null_bindings;
      CHECK(stela_amd_build_compute_pipeline(info, binary, &code, NULL, 0, &null_bindings) == STELA_AMD_COMPUTE_OK &&
         !memcmp(&pipeline, &null_bindings, sizeof(pipeline)));
      uint32_t words[256], written;
      CHECK(stela_amd_compute_pipeline(info, &pipeline, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK && written);
      bool resource_word = false;
      for (unsigned cursor = 0; cursor < written;) {
         const uint32_t header = words[cursor], length = ((header >> 16) & 0x3fff) + 2;
         CHECK(header >> 30 == 3 && length <= written - cursor && length >= 3 &&
            ((header >> 8) & 255) == PKT3_SET_SH_REG);
         const uint32_t start = 0xb000 + words[cursor + 1] * 4;
         for (unsigned i = 2; i < length; i++) {
            const uint32_t reg = start + (i - 2) * 4;
            CHECK(reg < R_00B900_COMPUTE_USER_DATA_0 || reg >= R_00B900_COMPUTE_USER_DATA_0 + 4 * STELA_AMD_COMPUTE_USER_SGPRS);
            if (reg == R_00B84C_COMPUTE_PGM_RSRC2) {
               CHECK(words[cursor + i] == pipeline.rsrc2 && !G_00B84C_USER_SGPR(words[cursor + i]));
               resource_word = true;
            }
         }
         cursor += length;
      }
      CHECK(resource_word);
      const struct stela_amd_compute_pipeline preserved = pipeline;
      CHECK(stela_amd_build_compute_pipeline(info, binary, &code, NULL, 1, &pipeline) == STELA_AMD_COMPUTE_INVALID &&
         !memcmp(&pipeline, &preserved, sizeof(pipeline)));
      struct ac_shader_config scratch = *binary->config; scratch.scratch_bytes_per_wave = 1024;
      struct stela_amd_compute_binary unowned = *binary; unowned.config = &scratch;
      CHECK(stela_amd_build_compute_pipeline(info, &unowned, &code, NULL, 0, &pipeline) == STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE &&
         !memcmp(&pipeline, &preserved, sizeof(pipeline)));
   }
   CHECK(binary->config->lds_size == binary->shader->info.shared_size);
   if (status == STELA_AMD_COMPUTE_OK) {
      CHECK(G_00B84C_LDS_SIZE(pipeline.rsrc2) == ac_shader_encode_lds_size(
         binary->shader->info.shared_size, info->gfx_level, MESA_SHADER_COMPUTE));
      uint32_t words[256], written;
      CHECK(stela_amd_compute_pipeline(info, &pipeline, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
      CHECK(register_word(words, written, R_00B84C_COMPUTE_PGM_RSRC2) == pipeline.rsrc2);
      const struct stela_amd_compute_pipeline preserved = pipeline;
      struct ac_shader_config incompatible = *binary->config;
      incompatible.lds_size = binary->shader->info.shared_size ? 0 : 1;
      struct stela_amd_compute_binary wrong_lds = *binary; wrong_lds.config = &incompatible;
      CHECK(stela_amd_build_compute_pipeline(info, &wrong_lds, &code, runtime, count, &pipeline) == STELA_AMD_COMPUTE_UNSUPPORTED &&
         !memcmp(&pipeline, &preserved, sizeof(pipeline)));
   }
   char target[64];
   owned_target(target, fixture, info->family, binary->wave_size);
   record_compiled(target, binary->code_bytes);
   record_object("facts");
   record_uint("buffers", count);
   record_uint("executable_bytes", binary->executable_bytes);
   record_blake3("code_blake3", stela_amd_air_code(owner), binary->code_bytes);
   record_uint("sgprs", binary->config->num_sgprs);
   record_uint("vgprs", binary->config->num_vgprs);
   record_uint("lds", binary->config->lds_size);
   record_uint("scratch", binary->config->scratch_bytes_per_wave);
   record_uint("float_mode", binary->config->float_mode);
   record_threadgroup(&p->threadgroup, binary->shader->info.shared_size);
   record_end();
}

static void text_append(char *text, size_t capacity, const char *format, ...)
{
   size_t length = strlen(text); CHECK(length < capacity);
   va_list args; va_start(args, format); int bytes = vsnprintf(text + length, capacity - length, format, args);
   va_end(args); CHECK(bytes >= 0 && (size_t)bytes < capacity - length);
}
static LLVMMemoryBufferRef multibuffer(unsigned count)
{
   CHECK(count <= 9);
   char prefix[4096] = "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
      "target triple = \"air64_v28-apple-macosx26.7.0\"\ndefine void @kernel(i32 %tid";
   char body[8192] = "%index = zext i32 %tid to i64\n", metadata[16384] = "}\n"
      "!air.version = !{!0}\n!air.language_version = !{!1}\n!air.kernel = !{!2}\n"
      "!0 = !{i32 2, i32 8, i32 0}\n!1 = !{!\"Metal\", i32 4, i32 0, i32 0}\n"
      "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5";
   for (unsigned i = 0; i < count; i++) {
      text_append(prefix, sizeof(prefix), ", ptr addrspace(1) %%b%u", i);
      text_append(body, sizeof(body), "%%p%u = getelementptr i32, ptr addrspace(1) %%b%u, i64 %%index\n"
         "%%v%u = load i32, ptr addrspace(1) %%p%u, align 4\n"
         "%%x%u = add i32 %%v%u, %u\nstore i32 %%x%u, ptr addrspace(1) %%p%u, align 4\n",
         i, i, i, i, i, i, i + 1, i, i);
      text_append(metadata, sizeof(metadata), ",!%u", i + 6);
   }
   text_append(prefix, sizeof(prefix), ") {\n"); text_append(body, sizeof(body), "ret void\n");
   text_append(metadata, sizeof(metadata), "}\n!5 = !{i32 0, !\"air.thread_position_in_grid\","
      " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"tid\"}\n");
   for (unsigned i = 0; i < count; i++)
      text_append(metadata, sizeof(metadata), "!%u = !{i32 %u, !\"air.buffer\", !\"air.location_index\", i32 %u, i32 1,"
         " !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"
         " !\"air.arg_type_align_size\", i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"buffer%u\"}\n",
         i + 6, i + 1, (i * 7 + 3) % 31, i);
   return stela_air_test_custom_bitcode(prefix, body, metadata, "");
}

static void failures(struct stela_metal_assembly *library, const struct radeon_info *info)
{
   struct stela_amd_air_options valid = options(64), bad;
   const struct {unsigned field, value; enum stela_amd_air_status status;} cases[] = {
      {0, 0, STELA_AMD_AIR_INVALID}, {1, 0, STELA_AMD_AIR_INVALID},
      {2, 0, STELA_AMD_AIR_UNSUPPORTED}, {3, 0, STELA_AMD_AIR_UNSUPPORTED},
      {4, UINT32_MAX, STELA_AMD_AIR_UNSUPPORTED}, {5, 0, STELA_AMD_AIR_LIMIT},
      {6, 0, STELA_AMD_AIR_LIMIT}, {6, UINT32_MAX, STELA_AMD_AIR_LIMIT},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      bad = valid;
      switch (cases[i].field) {
      case 0: bad.size = cases[i].value; break; case 1: bad.abi = cases[i].value; break;
      case 2: bad.wave_size = cases[i].value; break; case 3: bad.workgroup_size[0] = cases[i].value; break;
      case 4: bad.workgroup_size[2] = cases[i].value; break; case 5: bad.max_instructions = cases[i].value; break;
      case 6: bad.max_code_bytes = cases[i].value; break;
      }
      CHECK(!compile(info, library, &bad, cases[i].status));
   }
   bad = valid; bad.fp_profile = (enum stela_air_fp_profile)99;
   CHECK(!compile(info, library, &bad, STELA_AMD_AIR_UNSUPPORTED));
   bad = valid; bad.max_code_bytes = 4;
   CHECK(!compile(info, library, &bad, STELA_AMD_AIR_LIMIT));
   bad = valid; bad.max_instructions = 1;
   CHECK(!compile(info, library, &bad, STELA_AMD_AIR_FRONTEND));
   struct radeon_info missing = *info; missing.virtual_address_max = 0;
   CHECK(!compile(&missing, library, &valid, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE));
   missing = *info; missing.compiler_info.max_sgpr_alloc = 1;
   missing.compiler_info.min_sgpr_alloc = missing.compiler_info.sgpr_alloc_granularity = 1;
   CHECK(!compile(&missing, library, &valid, STELA_AMD_AIR_UNSUPPORTED));
   missing = *info; missing.compiler_info.num_physical_sgprs_per_simd = 0;
   CHECK(!compile(&missing, library, &valid, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE));
   missing = *info; missing.compiler_info.num_physical_wave64_vgprs_per_simd = UINT32_MAX;
   CHECK(!compile(&missing, library, &valid, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE));
   missing = *info; missing.compiler_info.wave64_vgpr_alloc_granularity = 0;
   CHECK(!compile(&missing, library, &valid, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE));
   missing = *info; missing.compiler_info.lds_size_per_workgroup = UINT32_MAX;
   CHECK(!compile(&missing, library, &valid, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE));
   missing = *info; missing.compiler_info.num_physical_wave64_vgprs_per_simd = UINT16_MAX / 2 + 1;
   bad = valid; bad.wave_size = 32;
   CHECK(!compile(&missing, library, &bad, STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE));
   struct radeon_info cdna = model(CHIP_MI100, false);
   CHECK(!compile(&cdna, library, &valid, STELA_AMD_AIR_UNSUPPORTED));
   struct radeon_info gfx121 = model(CHIP_GFX1210, true);
   CHECK(!compile(&gfx121, library, &valid, STELA_AMD_AIR_UNSUPPORTED));
   struct stela_amd_air_error error; struct stela_amd_air_compilation *owner = NULL;
   CHECK(stela_amd_air_compile(info, library, UINT32_MAX, &valid, &owner, &error) == STELA_AMD_AIR_INVALID && !owner);
   owner = compile(info, library, &valid, STELA_AMD_AIR_OK);
   struct stela_amd_air_compilation *same = owner;
   CHECK(stela_amd_air_compile(info, library, 0, &valid, &owner, &error) == STELA_AMD_AIR_INVALID && owner == same);
   destroy(&owner);
}
/* Every manifest target; the owned compiler refuses the families ACO holds. */
static void targets(struct stela_metal_assembly *library, enum stela_air_fp_profile profile, const char *fixture)
{
   for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
      const enum radeon_family family = stela_amd_targets[i];
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2)
         expect_owned(fixture, family, wave);
   }
   for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
      const enum radeon_family family = stela_amd_targets[i];
      struct radeon_info info = model(family, stela_amd_has_graphics(family));
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
         struct stela_amd_air_options opts = options(wave); opts.fp_profile = profile;
         if (stela_amd_aco_hold(family)) {
            char target[64];
            owned_target(target, fixture, family, wave);
            CHECK(!compile(&info, library, &opts, STELA_AMD_AIR_UNSUPPORTED));
            record_held(target, stela_amd_aco_hold(family));
            continue;
         }
         struct stela_amd_air_compilation *owner = compile(&info, library, &opts, STELA_AMD_AIR_OK);
         validate_result(&info, owner, fixture); destroy(&owner);
      }
   }
}
static void original_tests(void)
{
   LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_test_store_body, "");
   struct stela_metal_assembly *library = fixture(air);
   LLVMDisposeMemoryBuffer(air);
   targets(library, STELA_AIR_FP_IEEE_DEFAULT, "original-integer");
   struct radeon_info info = model(CHIP_NAVI31, true);
   failures(library, &info);
   struct stela_amd_air_options three_d = options(32);
   three_d.workgroup_size[0] = 4; three_d.workgroup_size[1] = 2; three_d.workgroup_size[2] = 3;
   expect_owned("3d-workgroup", info.family, 32);
   struct stela_amd_air_compilation *specialized = compile(&info, library, &three_d, STELA_AMD_AIR_OK);
   const struct stela_amd_air_provenance *specialization = stela_amd_air_provenance(specialized);
   CHECK(!memcmp(&specialization->options, &three_d, sizeof(three_d)));
   for (unsigned axis = 0; axis < 3; axis++)
      CHECK(stela_amd_air_binary(specialized)->shader->info.workgroup_size[axis] == three_d.workgroup_size[axis]);
   validate_result(&info, specialized, "3d-workgroup"); destroy(&specialized);
   struct stela_amd_air_options opts = options(64);
   expect_owned("eight-buffer", info.family, 64);
   expect_owned("after-other-owner-destroy", info.family, 64);
   expect_owned("selected-second-entry", info.family, 64);
   struct stela_amd_air_compilation *owner = compile(&info, library, &opts, STELA_AMD_AIR_OK);
   const struct stela_metal_library_manifest *m = stela_metal_assembly_manifest(library);
   const struct stela_amd_air_provenance *p = stela_amd_air_provenance(owner);
   CHECK(!memcmp(&p->input, &m->input, sizeof(p->input)) &&
      !memcmp(&p->entry, &m->entries[0].entry, sizeof(p->entry)) &&
      !memcmp(p->air_sha256, m->entries[0].air_sha256, 32) &&
      p->air_offset == m->entries[0].air_offset && p->air_bytes == m->entries[0].air_bytes &&
      p->arguments[1].name != m->entries[0].arguments[1].name &&
      !strcmp(p->arguments[1].name, m->entries[0].arguments[1].name));
   stela_metal_assembly_destroy(&library);
   CHECK(!strcmp(p->name, "kernel") && !strcmp(p->target, "air64_v28-apple-macosx26.7.0") &&
      !strcmp(p->arguments[1].type_name, "uint"));
   /* Hold one shader/options/type reference across creation/destruction of a
    * distinct owner: no borrowed assembly or prematurely released type state. */
   air = multibuffer(8); library = fixture(air); LLVMDisposeMemoryBuffer(air);
   struct stela_amd_air_compilation *second = compile(&info, library, &opts, STELA_AMD_AIR_OK);
   uint32_t count; const struct stela_amd_air_binding *bindings = stela_amd_air_bindings(second, &count);
   CHECK(count == 8);
   for (unsigned i = 0; i < count; i++) CHECK(bindings[i].buffer.index == (i * 7 + 3) % 31 && bindings[i].buffer.argument == i + 1);
   validate_result(&info, second, "eight-buffer"); destroy(&second);
   validate_result(&info, owner, "after-other-owner-destroy"); destroy(&owner);
   stela_metal_assembly_destroy(&library);
   const char *selected_metadata = "}\n!air.version = !{!0}\n!air.language_version = !{!1}\n"
      "!air.kernel = !{!2,!7}\n!0 = !{i32 2, i32 8, i32 0}\n"
      "!1 = !{!\"Metal\", i32 4, i32 0, i32 0}\n!2 = !{ptr @kernel, !3, !4}\n"
      "!3 = !{}\n!4 = !{!5,!6}\n!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\"}\n"
      "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 13, i32 1, !\"air.write\","
      " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
      " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"result\"}\n!7 = !{ptr @other, !3, !4}\n";
   air = stela_air_test_custom_bitcode(stela_air_test_prefix,
      "store i32 11, ptr addrspace(1) %out, align 4\nret void\n", selected_metadata,
      "define void @other(i32 %tid, ptr addrspace(1) %out) {\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n}\n");
   library = two_entries(air); LLVMDisposeMemoryBuffer(air);
   struct stela_amd_air_error selected_error;
   CHECK(stela_amd_air_compile(&info, library, 1, &opts, &owner, &selected_error) == STELA_AMD_AIR_OK && owner);
   stela_metal_assembly_destroy(&library);
   p = stela_amd_air_provenance(owner);
   CHECK(p->selected_entry == 1 && !strcmp(p->name, "other") && p->input.entry_count == 2 &&
      p->arguments[1].buffer.index == 13 && p->arguments[1].buffer.access == STELA_AIR_WRITE &&
      !p->arguments[0].name && p->arguments[0].name_bytes == 0);
   unsigned selected_stores = 0;
   nir_foreach_function_impl(impl, (nir_shader *)stela_amd_air_binary(owner)->shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic) continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            if (intr->intrinsic == nir_intrinsic_store_global_amd || intr->intrinsic == nir_intrinsic_store_global) {
               CHECK(nir_src_is_const(intr->src[0]) && nir_src_as_uint(intr->src[0]) == 99); selected_stores++;
            }
         }
      }
   }
   CHECK(selected_stores == 1); validate_result(&info, owner, "selected-second-entry"); destroy(&owner);
   air = multibuffer(9); library = fixture(air); LLVMDisposeMemoryBuffer(air);
   CHECK(!compile(&info, library, &opts, STELA_AMD_AIR_UNSUPPORTED)); stela_metal_assembly_destroy(&library);
   air = stela_air_test_bitcode("call void @unsupported()\nret void\n", "declare void @unsupported()\n");
   library = fixture(air); LLVMDisposeMemoryBuffer(air);
   CHECK(!compile(&info, library, &opts, STELA_AMD_AIR_FRONTEND)); stela_metal_assembly_destroy(&library);
   /* Original LLVM fixture with complete AS3 argument reflection and no module
    * globals: distinguish this leaf's dispatch-specialization refusal from the
    * canonical library owner's separate incomplete-global reflection refusal. */
   air = stela_air_test_custom_bitcode(
      "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
      "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
      "define void @kernel(i32 %tid, ptr addrspace(3) %scratch) {\n",
      "store i32 %tid, ptr addrspace(3) %scratch, align 4\nret void\n",
      "}\n!air.version = !{!0}\n!air.language_version = !{!1}\n!air.kernel = !{!2}\n"
      "!0 = !{i32 2, i32 9, i32 0}\n!1 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
      "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5,!6}\n"
      "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"tid\"}\n"
      "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 7, i32 1, !\"air.read_write\","
      " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
      " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"scratch\"}\n", "");
   struct bytes shared_bytes = archive(LLVMGetBufferStart(air), LLVMGetBufferSize(air), "kernel", 9, 4, 1, 27, 2);
   library = assemble(&shared_bytes); free(shared_bytes.data); LLVMDisposeMemoryBuffer(air);
   CHECK(!compile(&info, library, &opts, STELA_AMD_AIR_UNSUPPORTED)); stela_metal_assembly_destroy(&library);
   for (unsigned n = 0; n <= 8; n++) {
      air = multibuffer(n); library = fixture(air); LLVMDisposeMemoryBuffer(air);
      char fixture[32];
      snprintf(fixture, sizeof(fixture), "buffers-%u", n);
      targets(library, STELA_AIR_FP_IEEE_DEFAULT, fixture);
      stela_metal_assembly_destroy(&library);
   }
#ifdef STELA_AMD_AIR_ALLOC_TEST
   air = stela_air_test_bitcode(stela_air_test_store_body, ""); library = fixture(air); LLVMDisposeMemoryBuffer(air);
   allocations = 0; owner = compile(&info, library, &opts, STELA_AMD_AIR_OK);
   unsigned total = allocations; CHECK(total == 3); destroy(&owner);
   for (unsigned fail = 1; fail <= total; fail++) {
      allocations = 0; fail_allocation = fail;
      CHECK(!compile(&info, library, &opts, STELA_AMD_AIR_ALLOCATION) && !live_allocations);
   }
   fail_allocation = 0; owner = compile(&info, library, &opts, STELA_AMD_AIR_OK); destroy(&owner);
   stela_metal_assembly_destroy(&library);
#endif
   CHECK(!stela_amd_air_binary(NULL) && !stela_amd_air_code(NULL) && !stela_amd_air_provenance(NULL));
   count = UINT32_MAX; CHECK(!stela_amd_air_bindings(NULL, &count) && !count);
}

static struct bytes read_file(const char *path)
{
   FILE *f = fopen(path, "rb"); CHECK(f && !fseek(f, 0, SEEK_END)); long size = ftell(f);
   CHECK(size > 0 && size <= AIR_MAX_BITCODE_BYTES && !fseek(f, 0, SEEK_SET));
   struct bytes b = {.data = malloc((size_t)size), .size = (size_t)size}; CHECK(b.data);
   CHECK(fread(b.data, 1, b.size, f) == b.size && fgetc(f) == EOF && !ferror(f) && !fclose(f)); return b;
}
struct input_facts {const char *name; unsigned air_minor, major, minor, os_major, os_minor; bool found;};
static bool facts(const struct stela_air_inspection *inspection, const struct stela_air_entry *entry, void *data)
{
   struct input_facts *f = data;
   if (strlen(f->name) != entry->name_bytes || memcmp(f->name, entry->name, entry->name_bytes)) return true;
   f->found = true; f->air_minor = inspection->air_minor; f->major = inspection->language_major; f->minor = inspection->language_minor;
   CHECK(sscanf(inspection->target, "air64_v%*u-apple-macosx%u.%u.", &f->os_major, &f->os_minor) == 2);
   return true;
}
static void real_input(int argc, char **argv)
{
   CHECK(argc == 4 || argc == 5); /* --input RAW_AIR ENTRY [qualified FP profile number] */
   struct bytes air = read_file(argv[2]); struct input_facts f = {.name = argv[3]}; struct stela_air_error error;
   CHECK(stela_air_inspect(air.data, air.size, 256, facts, &f, &error) && f.found);
   struct bytes bytes = archive(air.data, air.size, f.name, f.air_minor, f.major, f.minor, f.os_major, f.os_minor);
   struct stela_metal_assembly *library = assemble(&bytes); free(air.data); free(bytes.data);
   enum stela_air_fp_profile profile = argc == 5 ? (enum stela_air_fp_profile)strtoul(argv[4], NULL, 10) : STELA_AIR_FP_IEEE_DEFAULT;
   targets(library, profile, "unchanged-original-file"); stela_metal_assembly_destroy(&library);
}
static void source_input(int argc, char **argv)
{
   CHECK(argc == 5); /* --source ORIGINAL_MSL ORIGINAL_ADAPTER_AIR INDEPENDENT_RECEIPT_IDENTITY_208_BYTES */
   struct bytes source = read_file(argv[2]), air = read_file(argv[3]), identity = read_file(argv[4]); CHECK(identity.size == 208);
   struct stela_msl_output compiled = {.air = air.data, .air_bytes = air.size};
   memcpy(compiled.source_sha256, identity.data, 32); memcpy(compiled.air_sha256, identity.data + 32, 32);
   memcpy(&compiled.build, identity.data + 64, sizeof(compiled.build));
   struct stela_msl_apple_config config = stela_msl_apple_default_config();
   struct stela_msl_request request = {.source = source.data, .source_bytes = source.size, .language_version = 0x40001,
      .fast_math = true, .target_triple = "air64_v29-apple-macosx27.2.0"};
   struct stela_metal_assembly_options assembly_options = stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error; struct stela_metal_assembly *library = NULL;
   CHECK(stela_metal_assemble_source(&assembly_options, &config, &request, &compiled, &library, &error) == STELA_METAL_ASSEMBLY_OK);
   struct radeon_info info = model(CHIP_NAVI31, true); struct stela_amd_air_options opts = options(32);
   opts.fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
   expect_owned("original-source-owner", info.family, 32);
   struct stela_amd_air_compilation *owner = compile(&info, library, &opts, STELA_AMD_AIR_OK);
   free(air.data); free(source.data); stela_metal_assembly_destroy(&library);
   const struct stela_amd_air_provenance *p = stela_amd_air_provenance(owner);
   CHECK(p->library_flags == STELA_METAL_LIBRARY_SOURCE_COMPILED && p->compiler_profile == config.profile &&
      p->request_language == 0x40001 && p->request_fast_math == 1 &&
      !memcmp(p->source_sha256, identity.data, 32) && !memcmp(p->input.original_sha256, identity.data + 32, 32) &&
      !memcmp(&p->build, identity.data + 64, sizeof(p->build)));
   free(identity.data); validate_result(&info, owner, "original-source-owner"); destroy(&owner);
}
static void requested_threadgroups(int argc,char **argv,struct stela_metal_threadgroup_request_row *rows)
{
    CHECK(argc>=6&&argc-5<=(int)AIR_MAX_ARGUMENTS);
    for(int i=5;i<argc;i++) {
        char *end;errno=0;CHECK(argv[i][0]>='0'&&argv[i][0]<='9');
        unsigned long long index=strtoull(argv[i],&end,10);CHECK(!errno&&index<=UINT32_MAX&&*end==':');
        const char *start=end+1;CHECK(*start>='0'&&*start<='9');errno=0;
        unsigned long long bytes=strtoull(start,&end,10);CHECK(!errno&&!*end);
        rows[i-5]=(struct stela_metal_threadgroup_request_row){.index=(uint32_t)index,.bytes=(uint64_t)bytes};
    }
}
static void threadgroup_input(int argc,char **argv)
{
    struct stela_metal_threadgroup_request_row rows[AIR_MAX_ARGUMENTS]={0};requested_threadgroups(argc,argv,rows);
    char *end;errno=0;unsigned long workgroup=strtoul(argv[4],&end,10);CHECK(!errno&&!*end&&workgroup&&workgroup<=1024);
    struct stela_metal_threadgroup_request request={.size=sizeof(request),.abi=STELA_METAL_THREADGROUP_ABI,
        .count=(uint32_t)(argc-5),.rows=rows};
    struct bytes air=read_file(argv[2]);struct input_facts f={.name=argv[3]};struct stela_air_error air_error;
    CHECK(stela_air_inspect(air.data,air.size,256,facts,&f,&air_error)&&f.found);
    struct bytes bytes=archive(air.data,air.size,f.name,f.air_minor,f.major,f.minor,f.os_major,f.os_minor);
    struct stela_metal_assembly *library=assemble(&bytes);free(bytes.data);free(air.data);
    for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
        const enum radeon_family family = stela_amd_targets[i];
        for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2)
            expect_owned("threadgroup", family, wave);
    }
    for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
        const enum radeon_family family = stela_amd_targets[i];
        struct radeon_info info = model(family, stela_amd_has_graphics(family));
        for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
            struct stela_amd_air_options opts = options(wave); opts.workgroup_size[0] = (uint32_t)workgroup;
            struct stela_amd_air_compilation *owner = NULL; struct stela_amd_air_error error;
            const enum stela_amd_air_status status =
                stela_amd_air_compile_specialized(&info, library, 0, &opts, &request, &owner, &error);
            if (stela_amd_aco_hold(family)) {
                char target[64];
                owned_target(target, "threadgroup", family, wave);
                CHECK(status == STELA_AMD_AIR_UNSUPPORTED && !owner);
                record_held(target, stela_amd_aco_hold(family));
                continue;
            }
            CHECK(status == STELA_AMD_AIR_OK && owner);
            const struct stela_amd_air_provenance *p = stela_amd_air_provenance(owner);
            if (i == 0) {
                struct stela_metal_threadgroup_request bad_request = request;
                struct stela_amd_air_compilation *failed = NULL;
                bad_request.size--;
                CHECK(stela_amd_air_compile_specialized(&info, library, 0, &opts, &bad_request, &failed, &error) == STELA_AMD_AIR_INVALID && !failed);
                bad_request = request; bad_request.count = 0;
                CHECK(stela_amd_air_compile_specialized(&info, library, 0, &opts, &bad_request, &failed, &error) == STELA_AMD_AIR_UNSUPPORTED && !failed);
                bad_request = request;
                struct stela_metal_threadgroup_request_row bad_rows[AIR_MAX_ARGUMENTS]; memcpy(bad_rows, rows, sizeof(rows));
                bad_request.rows = bad_rows; bad_rows[0].bytes = 0;
                CHECK(stela_amd_air_compile_specialized(&info, library, 0, &opts, &bad_request, &failed, &error) == STELA_AMD_AIR_UNSUPPORTED && !failed);
                bad_rows[0].bytes = UINT64_C(0x100000000);
                CHECK(stela_amd_air_compile_specialized(&info, library, 0, &opts, &bad_request, &failed, &error) == STELA_AMD_AIR_LIMIT && !failed);
#ifdef STELA_AMD_AIR_ALLOC_TEST
                unsigned baseline = live_allocations;
                bad_request = request;
                for (unsigned fail = 1; fail <= 3; fail++) {
                    allocations = 0; fail_allocation = fail;
                    CHECK(stela_amd_air_compile_specialized(&info, library, 0, &opts, &bad_request, &failed, &error) == STELA_AMD_AIR_ALLOCATION && !failed && live_allocations == baseline);
                }
                fail_allocation = 0;
#endif
            }
            CHECK(p->threadgroup.count == request.count && stela_metal_threadgroup_matches(&p->threadgroup, &request));
            struct stela_metal_threadgroup_request_row saved[AIR_MAX_ARGUMENTS]; memcpy(saved, rows, sizeof(rows));
            rows[0].bytes += 16; CHECK(!stela_metal_threadgroup_matches(&p->threadgroup, &request));
            memset(rows, 0, sizeof(rows));
            CHECK(p->threadgroup.bindings[0].bytes && p->threadgroup.bindings[0].alignment >= 16);
            memcpy(rows, saved, sizeof(rows)); CHECK(stela_metal_threadgroup_matches(&p->threadgroup, &request));
            validate_result(&info, owner, "threadgroup");
            CHECK(stela_metal_threadgroup_matches(&p->threadgroup, &request)); destroy(&owner);
        }
    }
    stela_metal_assembly_destroy(&library);
}
static void shared_refusal(int argc, char **argv)
{
   CHECK(argc == 4);
   struct bytes air = read_file(argv[2]); struct input_facts f = {.name = argv[3]}; struct stela_air_error air_error;
   CHECK(stela_air_inspect(air.data, air.size, 256, facts, &f, &air_error) && f.found);
   struct bytes bytes = archive(air.data, air.size, f.name, f.air_minor, f.major, f.minor, f.os_major, f.os_minor);
   struct stela_metal_assembly_options opts = stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error; struct stela_metal_assembly *library = NULL;
   char target[64];
   owned_target(target, "shared-refusal", CHIP_NAVI31, 32);
   record_expect_refusal(target, STELA_REFUSAL_DYNAMIC_THREADGROUP);
   enum stela_metal_assembly_status status = stela_metal_assemble_archive(&opts, bytes.data, bytes.size, &library, &error);
   if (status == STELA_METAL_ASSEMBLY_OK) {
      struct radeon_info info = model(CHIP_NAVI31, true); struct stela_amd_air_options compile_options = options(32);
      CHECK(!compile(&info, library, &compile_options, STELA_AMD_AIR_UNSUPPORTED));
      record_refused(target, STELA_REFUSAL_DYNAMIC_THREADGROUP);
   } else {
      CHECK(status == STELA_METAL_ASSEMBLY_REFLECTION && !library);
      record_refused(target, "canonical-reflection-incomplete");
   }
   stela_metal_assembly_destroy(&library); free(bytes.data); free(air.data);
}
#ifdef STELA_AMD_AIR_CAPTURE_TEST
/* Deliberately invalid borrowed backend-output records, confined to this
 * separately linked rejection test. No successful fake binary is published. */
static unsigned bad_capture;
void stela_amd_air_bad_backend(const struct aco_compiler_options *options,
   const struct aco_shader_info *info, unsigned count, nir_shader *const *shaders,
   const struct ac_shader_args *args, aco_callback *callback, void **private);
void stela_amd_air_bad_backend(const struct aco_compiler_options *options,
   const struct aco_shader_info *info, unsigned count, nir_shader *const *shaders,
   const struct ac_shader_args *args, aco_callback *callback, void **private)
{
   (void)options; (void)info; (void)count; (void)shaders; (void)args;
   struct ac_shader_config config = {.num_vgprs = 8, .num_sgprs = 8};
   const uint32_t invalid_test_bytes[2] = {0, 0};
   callback(private, bad_capture == 0 ? NULL : &config, NULL, 0, NULL, 0, NULL,
      bad_capture == 2 ? 0 : bad_capture == 4 ? 12 : bad_capture == 5 ? 3 : 4,
      bad_capture == 1 ? NULL : invalid_test_bytes,
      bad_capture == 3 ? UINT32_MAX : 2, NULL, bad_capture == 6 ? 1 : 0, NULL, 0);
   if (bad_capture == 7) callback(private, &config, NULL, 0, NULL, 0, NULL, 4,
      invalid_test_bytes, 2, NULL, 0, NULL, 0);
}
static void invalid_capture_tests(void)
{
   LLVMMemoryBufferRef air = stela_air_test_bitcode(stela_air_test_store_body, "");
   struct stela_metal_assembly *library = fixture(air); LLVMDisposeMemoryBuffer(air);
   struct radeon_info info = model(CHIP_NAVI31, true); struct stela_amd_air_options opts = options(32);
   for (bad_capture = 0; bad_capture < 8; bad_capture++) {
      CHECK(!compile(&info, library, &opts,
         bad_capture == 6 ? STELA_AMD_AIR_UNSUPPORTED : STELA_AMD_AIR_BACKEND));
   }
   stela_metal_assembly_destroy(&library);
   puts("invalid borrowed backend-output records refused atomically; no fake code published");
}
#endif
int main(int argc, char **argv)
{
#ifdef STELA_AMD_AIR_CAPTURE_TEST
   (void)argc; (void)argv; invalid_capture_tests();
#else
   if (argc == 1) original_tests();
   else if (!strcmp(argv[1], "--input")) real_input(argc, argv);
   else if (!strcmp(argv[1], "--source")) source_input(argc, argv);
   else if(!strcmp(argv[1],"--threadgroup"))threadgroup_input(argc,argv);
    else if (!strcmp(argv[1], "--shared-refusal")) shared_refusal(argc, argv);
   else CHECK(false);
#endif
#ifdef STELA_AMD_AIR_ALLOC_TEST
   CHECK(!live_allocations);
#endif
   return 0;
}
