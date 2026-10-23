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
      "%%alias = bitcast ptr addrspace(1) %%address to ptr addrspace(1)\n"
      "store i32 123, ptr addrspace(1) %%alias, align 1\nret void\n",
      (unsigned long long)offset);
   nir_shader *nir = translate(body, 2);
   set_size(nir, size);
   check_accesses(nir, 0, valid ? 1 : 0, offset, 123);
   ralloc_free(nir);
}

static void
conditional_accesses(void)
{
   const char *body =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\n%lp = getelementptr i8, ptr addrspace(1) %out, i64 4294967300\n"
      "%l = load i32, ptr addrspace(1) %lp, align 1\n"
      "%ls = getelementptr i8, ptr addrspace(1) %out, i64 4\n"
      "store i32 55, ptr addrspace(1) %ls, align 4\nbr label %join\n"
      "right:\n%rs = getelementptr i8, ptr addrspace(1) %out, i64 8\n"
      "store i32 66, ptr addrspace(1) %rs, align 4\nbr label %join\n"
      "join:\n%v = phi i32 [%l, %left], [37, %right]\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n";
   for (unsigned tid = 0; tid < 2; tid++) {
      const unsigned sizes[] = {0, 6, 64};
      for (unsigned i = 0; i < ARRAY_SIZE(sizes); i++) {
         nir_shader *nir = translate(body, 2);
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_block(block, impl) {
               nir_foreach_instr_safe(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
                  if (intrinsic->intrinsic != nir_intrinsic_load_workgroup_id &&
                      intrinsic->intrinsic != nir_intrinsic_load_local_invocation_id)
                     continue;
                  nir_builder b = nir_builder_at(nir_before_instr(instr));
                  nir_def *id = nir_imm_ivec3(&b,
                     intrinsic->intrinsic == nir_intrinsic_load_workgroup_id ? 0 : tid, 0, 0);
                  nir_def_rewrite_uses(&intrinsic->def, id);
                  nir_instr_remove(instr);
               }
            }
         }
         set_size(nir, sizes[i]);
         unsigned stores = 0;
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_block(block, impl) {
               CHECK(nir_block_get_following_if(block) == NULL);
               nir_foreach_instr(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
                  CHECK(intrinsic->intrinsic != nir_intrinsic_load_ssbo);
                  if (intrinsic->intrinsic != nir_intrinsic_store_ssbo)
                     continue;
                  uint32_t expected_offset = sizes[i] == 64 && !stores ? (tid ? 8 : 4) : 0;
                  uint32_t expected_value = expected_offset ? (tid ? 66 : 55) : (tid ? 37 : 0);
                  CHECK(nir_src_is_const(intrinsic->src[2]) && nir_src_as_uint(intrinsic->src[2]) == expected_offset);
                  CHECK(nir_src_is_const(intrinsic->src[0]) && nir_src_as_uint(intrinsic->src[0]) == expected_value);
                  stores++;
               }
            }
         }
         CHECK(stores == (sizes[i] == 64 ? 2 : sizes[i] ? 1 : 0));
         ralloc_free(nir);
      }
   }
}

static void
loop_guarded_phis(void)
{
   const char *body =
      "entry:\n%rounds = add i32 %tid, 1\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%value = phi i32 [11, %entry], [%loaded, %latch]\n"
      "%more = icmp ult i32 %i, %rounds\nbr i1 %more, label %body, label %exit\n"
      "body:\n%p = getelementptr i32, ptr addrspace(1) %out, i32 %i\n"
      "store i32 %value, ptr addrspace(1) %p, align 4\nbr label %latch\n"
      "latch:\n%high = getelementptr i8, ptr addrspace(1) %out, i64 4294967300\n"
      "%loaded = load i32, ptr addrspace(1) %high, align 1\n"
      "%next = add i32 %i, 1\nbr label %header\n"
      "exit:\n%result = getelementptr i32, ptr addrspace(1) %out, i32 3\n"
      "store i32 %value, ptr addrspace(1) %result, align 4\nret void\n";
   const uint32_t sizes[] = {0, 4, 14, 16, 64};
   static const nir_shader_compiler_options unroll = {.max_unroll_iterations = 16};
   for (unsigned tid = 0; tid < 3; tid++) {
      for (unsigned size = 0; size < ARRAY_SIZE(sizes); size++) {
         nir_shader *nir = translate(body, 2);
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_block(block, impl) {
               nir_foreach_instr_safe(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
                  if (in->intrinsic != nir_intrinsic_load_workgroup_id &&
                      in->intrinsic != nir_intrinsic_load_local_invocation_id)
                     continue;
                  nir_builder b = nir_builder_at(nir_before_instr(instr));
                  nir_def_rewrite_uses(&in->def, nir_imm_ivec3(&b,
                     in->intrinsic == nir_intrinsic_load_workgroup_id ? 0 : tid, 0, 0));
                  nir_instr_remove(instr);
               }
            }
         }
         set_size(nir, sizes[size]);
         nir->options = &unroll;
         bool progress;
         do {
            progress = nir_opt_loop_unroll(nir);
            progress |= nir_opt_constant_folding(nir);
            progress |= nir_opt_dead_cf(nir);
            progress |= nir_opt_remove_phis(nir);
            progress |= nir_opt_copy_prop(nir);
            progress |= nir_opt_dce(nir);
         } while (progress);
         nir_validate_shader(nir, "AIR guarded backedge PHIs and exact effects");
         uint32_t offsets[4], values[4];
         unsigned expected = 0, actual = 0;
         for (unsigned iteration = 0; iteration <= tid; iteration++) {
            if (sizes[size] >= 4 * iteration + 4) {
               offsets[expected] = 4 * iteration;
               values[expected++] = iteration ? 0 : 11;
            }
         }
         if (sizes[size] >= 16) {
            offsets[expected] = 12;
            values[expected++] = 0;
         }
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_cf_node(node, &impl->body)
               CHECK(node->type != nir_cf_node_loop);
            nir_foreach_block(block, impl) {
               CHECK(nir_block_get_following_if(block) == NULL);
               nir_foreach_instr(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
                  CHECK(in->intrinsic != nir_intrinsic_load_ssbo &&
                        in->intrinsic != nir_intrinsic_load_global &&
                        in->intrinsic != nir_intrinsic_store_global);
                  if (in->intrinsic != nir_intrinsic_store_ssbo)
                     continue;
                  CHECK(actual < expected);
                  CHECK(nir_src_is_const(in->src[1]) && nir_src_as_uint(in->src[1]) == 2);
                  CHECK(nir_src_is_const(in->src[2]) && nir_src_as_uint(in->src[2]) == offsets[actual]);
                  CHECK(nir_src_is_const(in->src[0]) && nir_src_as_uint(in->src[0]) == values[actual]);
                  actual++;
               }
            }
         }
         CHECK(actual == expected);
         ralloc_free(nir);
      }
   }
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
   conditional_accesses();
   loop_guarded_phis();
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
   puts("AIR SSBO exact-view validation, conditional effects, 64-bit bounds and refusal tests passed");
   return 0;
}
