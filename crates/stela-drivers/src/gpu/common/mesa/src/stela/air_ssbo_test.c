/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "air_test_fixture.h"
#include "util/ralloc.h"

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static const nir_shader_compiler_options nir_options = {0};

static bool
bind_ssbo(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   CHECK(buffer->argument == 1 && buffer->index == 7 && buffer->address_space == 1);
   CHECK(buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 && buffer->type_alignment == 4);
   *slot = *(unsigned *)data;
   return true;
}

static nir_shader *
translate(const char *body, unsigned slot)
{
   LLVMMemoryBufferRef bitcode = stela_air_test_bitcode(body, "");
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_ssbo = bind_ssbo, .ssbo_count = 3, .binding_data = &slot,
   };
   struct stela_air_error error;
   nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode),
      "kernel", &nir_options, &options, &error);
   LLVMDisposeMemoryBuffer(bitcode);
   if (!nir)
      fprintf(stderr, "%s\n", error.detail);
   CHECK(nir && nir->info.num_ssbos == 3);
   return nir;
}

/* Substitute an exact resource-size ABI response only in this semantics test.
 * Production retains get_ssbo_size and uses the actual native bound surface. */
static void
set_size(nir_shader *nir, uint32_t bytes)
{
   unsigned queries = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr_safe(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (intrinsic->intrinsic != nir_intrinsic_get_ssbo_size)
               continue;
            CHECK(intrinsic->def.bit_size == 32 && intrinsic->def.num_components == 1);
            CHECK(nir_src_is_const(intrinsic->src[0]) && nir_src_as_uint(intrinsic->src[0]) == 2);
            nir_builder b = nir_builder_at(nir_before_instr(instr));
            nir_def_rewrite_uses(&intrinsic->def, nir_imm_int(&b, bytes));
            nir_instr_remove(instr);
            queries++;
         }
      }
   }
   CHECK(queries);
   bool progress;
   do {
      progress = nir_opt_constant_folding(nir);
      progress |= nir_opt_dead_cf(nir);
      progress |= nir_opt_dce(nir);
   } while (progress);
   nir_validate_shader(nir, "AIR SSBO size and offset semantics");
}

static void
check_accesses(nir_shader *nir, unsigned loads, unsigned stores,
                uint64_t store_offset, uint64_t store_value)
{
   unsigned actual_loads = 0, actual_stores = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            CHECK(intrinsic->intrinsic != nir_intrinsic_load_global &&
                  intrinsic->intrinsic != nir_intrinsic_store_global);
            if (intrinsic->intrinsic == nir_intrinsic_load_ssbo)
               actual_loads++;
            if (intrinsic->intrinsic == nir_intrinsic_store_ssbo) {
               CHECK(nir_src_is_const(intrinsic->src[1]) && nir_src_as_uint(intrinsic->src[1]) == 2);
               CHECK(nir_src_is_const(intrinsic->src[2]) && nir_src_as_uint(intrinsic->src[2]) == store_offset);
               CHECK(nir_src_is_const(intrinsic->src[0]) && nir_src_as_uint(intrinsic->src[0]) == store_value);
               actual_stores++;
            }
         }
      }
   }
   CHECK(actual_loads == loads && actual_stores == stores);
}

static void
store_case(uint64_t offset, uint32_t size, bool valid)
{
   char body[512];
   snprintf(body, sizeof(body),
      "%%address = getelementptr i8, ptr addrspace(1) %%out, i64 %llu\n"
      "store i32 123, ptr addrspace(1) %%address, align 1\nret void\n",
      (unsigned long long)offset);
   nir_shader *nir = translate(body, 2);
   set_size(nir, size);
   check_accesses(nir, 0, valid ? 1 : 0, offset, 123);
   ralloc_free(nir);
}

static void
view_validation(void)
{
   struct stela_air_ssbo_view view = {
      .slot = 2, .buffer_size = 4096, .offset = 16, .size = 64,
      .access = STELA_AIR_READ_WRITE, .available_access = STELA_AIR_READ_WRITE,
      .alignment = 4,
   };
   CHECK(stela_air_ssbo_view_valid(&view, 3));
   CHECK(!stela_air_ssbo_view_valid(&view, 2));
   CHECK(!stela_air_ssbo_view_valid(&view, 0));
   CHECK(!stela_air_ssbo_view_valid(&view, 256));
   CHECK(!stela_air_ssbo_view_valid(NULL, 3));
   view.available_access = STELA_AIR_READ;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.access = STELA_AIR_READ;
   CHECK(stela_air_ssbo_view_valid(&view, 3));
   view.access = 0;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.access = STELA_AIR_READ_WRITE;
   view.available_access = STELA_AIR_READ_WRITE;
   view.alignment = 3;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.alignment = 4;
   view.offset = 17;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.offset = 16;
   view.size = 0;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.size = 4096;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.offset = 4097;
   view.size = 1;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.buffer_size = UINT64_MAX;
   view.alignment = 1;
   view.offset = UINT64_MAX - 1;
   view.size = 2;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
   view.size = 1;
   CHECK(stela_air_ssbo_view_valid(&view, 3));
   view.offset = 0;
   view.size = UINT32_MAX;
   CHECK(stela_air_ssbo_view_valid(&view, 3));
   view.size++;
   CHECK(!stela_air_ssbo_view_valid(&view, 3));
}

static nir_def *
unused_global(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   CHECK(false); /* Mixed mode is rejected before a callback is invoked. */
   return NULL;
}

static bool
duplicate_slot(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   CHECK(buffer->argument == 1 || buffer->argument == 2);
   *slot = 2;
   return true;
}

static void
binding_refusals(void)
{
   LLVMMemoryBufferRef bitcode = stela_air_test_bitcode(stela_air_test_store_body, "");
   unsigned slot = 3;
   struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_ssbo = bind_ssbo, .ssbo_count = 3, .binding_data = &slot,
   };
   struct stela_air_error error;
   CHECK(!stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode), "kernel", &nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_ARGUMENT);
   options.ssbo_count = 0;
   CHECK(!stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode), "kernel", &nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_INPUT);
   options.ssbo_count = 256;
   CHECK(!stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode), "kernel", &nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_INPUT);
   options.ssbo_count = 3;
   options.bind_buffer = unused_global;
   CHECK(!stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode), "kernel", &nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_INPUT);
   LLVMDisposeMemoryBuffer(bitcode);
   const char *prefix =
      "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
      "target triple = \"air64_v28-apple-macosx26.7.0\"\n"
      "define void @kernel(i32 %tid, ptr addrspace(1) %out, ptr addrspace(1) %other) {\n";
   const char *before = "!4 = !{!5,!6}";
   const char *at = strstr(stela_air_test_metadata, before);
   CHECK(at);
   char metadata[4096];
   snprintf(metadata, sizeof(metadata), "%.*s!4 = !{!5,!6,!7}%s",
      (int)(at - stela_air_test_metadata), stela_air_test_metadata, at + strlen(before));
   bitcode = stela_air_test_custom_bitcode(prefix, "ret void\n", metadata,
      "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 8, i32 1,"
      " !\"air.read_write\", !\"air.address_space\", i32 1}\n");
   options.bind_buffer = NULL;
   options.bind_ssbo = duplicate_slot;
   CHECK(!stela_air_to_nir(LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode), "kernel", &nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_ARGUMENT);
   LLVMDisposeMemoryBuffer(bitcode);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   view_validation();
   binding_refusals();
   store_case(0, 64, true);
   store_case(60, 64, true);
   store_case(61, 64, false);
   store_case(UINT64_C(0x100000004), 64, false);
   store_case(UINT64_MAX - 3, 64, false);
   store_case(0, 0, false);
   store_case(0, 3, false);
   store_case(UINT32_MAX - 4, UINT32_MAX, true);
   store_case(UINT32_MAX - 3, UINT32_MAX, false);
   const char *body =
      "%address = getelementptr i8, ptr addrspace(1) %out, i64 4294967300\n"
      "%value = load i32, ptr addrspace(1) %address, align 1\n"
      "store i32 %value, ptr addrspace(1) %out, align 4\nret void\n";
   nir_shader *nir = translate(body, 2);
   set_size(nir, 64);
   check_accesses(nir, 0, 1, 0, 0);
   ralloc_free(nir);
   glsl_type_singleton_decref();
   puts("AIR SSBO exact-view validation, 64-bit offset bounds and refusal tests passed");
   return 0;
}
