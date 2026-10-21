/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "llvm-c/BitWriter.h"
#include "llvm-c/Core.h"
#include "llvm-c/IRReader.h"
#include "util/ralloc.h"
#include "util/blake3/blake3.h"
#include "probe_report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef STELA_AIR_TEST_NAK
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#endif

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

#include "air_test_fixture.h"

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   unsigned *count = data;
   CHECK(buffer->argument == 1 && buffer->index == 7 && buffer->address_space == 1);
   CHECK((buffer->access == STELA_AIR_READ_WRITE || buffer->access == STELA_AIR_READ) &&
         buffer->type_size == 4 && buffer->type_alignment == 4);
   (*count)++;
   return nir_imm_int64(b, 0x100000); /* Compile fixture only, never runtime ABI. */
}

static const nir_shader_compiler_options test_nir_options = {0};

static nir_shader *
translate(LLVMMemoryBufferRef input, const nir_shader_compiler_options *nir_options,
          unsigned budget, struct stela_air_error *error)
{
   unsigned bindings = 0;
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = budget,
      .bind_buffer = bind_buffer, .binding_data = &bindings,
   };
   nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                     "kernel", nir_options, &options, error);
   if (nir) {
      CHECK(bindings == 1);
      CHECK(nir->info.workgroup_size[0] == 32 && nir->info.workgroup_size[1] == 1 && nir->info.workgroup_size[2] == 1);
      CHECK(error->kind == STELA_AIR_OK);
   }
   return nir;
}

static void
expect_refusal(const char *body, const char *extra, unsigned budget,
               enum stela_air_error_kind expected)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, extra);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, budget, &error);
   if (nir || error.kind != expected)
      fprintf(stderr, "refusal wanted %u, got %u: %s\n", expected, error.kind, error.detail);
   CHECK(!nir && error.kind == expected && error.detail[0]);
   LLVMDisposeMemoryBuffer(input);
}

static void
constant_store_layout(const char *prefix, const char *body,
                      uint64_t expected, uint64_t address)
{
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(prefix, body, stela_air_test_metadata, "");
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, 100, &error);
   if (!nir)
      fprintf(stderr, "constant shader: %s\n", error.detail);
   CHECK(nir);
   while (nir_opt_constant_folding(nir)) {}
   nir_opt_dce(nir);
   unsigned stores = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (intrinsic->intrinsic != nir_intrinsic_store_global)
               continue;
            CHECK(nir_src_is_const(intrinsic->src[0]));
            CHECK(nir_src_as_uint(intrinsic->src[0]) == expected);
            CHECK(nir_src_is_const(intrinsic->src[1]));
            CHECK(nir_src_as_uint(intrinsic->src[1]) == address);
            stores++;
         }
      }
   }
   CHECK(stores == 1);
   nir_validate_shader(nir, "AIR constant semantics");
   ralloc_free(nir);
   LLVMDisposeMemoryBuffer(input);
}

static void
constant_store(const char *body, uint64_t expected, uint64_t address)
{
   constant_store_layout(stela_air_test_prefix, body, expected, address);
}

static void
constant_semantics(void)
{
   /* Validate low-bit truncation, sign extension from i1, signed comparison,
    * selection, vector channels and LLVM struct padding in the emitted NIR. */
   constant_store(
      "%low = trunc i32 2 to i1\n"
      "%sign = sext i1 true to i32\n"
      "%zero = zext i1 %low to i32\n"
      "%negative = icmp slt i32 %sign, %zero\n"
      "%selected = select i1 %negative, i32 123, i32 456\n"
      "%vec = insertelement <2 x i32> <i32 8, i32 9>, i32 %selected, i32 1\n"
      "%value = extractelement <2 x i32> %vec, i32 1\n"
      "%address = getelementptr {i8, i32, [3 x i16]}, ptr addrspace(1) %out, i32 0, i32 2, i32 2\n"
      "store i32 %value, ptr addrspace(1) %address, align 4\n"
      "ret void\n", 123, 0x10000c);
   constant_store("%v = add i8 127, 1\n%s = sext i8 %v to i32\nstore i32 %s, ptr addrspace(1) %out, align 4\nret void\n", 0xffffff80, 0x100000);
   constant_store("%v = lshr i8 -1, 3\n%s = zext i8 %v to i32\nstore i32 %s, ptr addrspace(1) %out, align 4\nret void\n", 31, 0x100000);
   constant_store("%v = ashr i8 -128, 3\n%s = sext i8 %v to i32\nstore i32 %s, ptr addrspace(1) %out, align 4\nret void\n", 0xfffffff0, 0x100000);
   constant_store("%v = shl i16 1, 15\n%s = zext i16 %v to i32\nstore i32 %s, ptr addrspace(1) %out, align 4\nret void\n", 32768, 0x100000);
   constant_store("%address = getelementptr i32, ptr addrspace(1) %out, i1 true\nstore i32 17, ptr addrspace(1) %address, align 4\nret void\n", 17, 0xffffc);
   constant_store("%address = getelementptr <3 x i32>, ptr addrspace(1) %out, i32 1\nstore i32 23, ptr addrspace(1) %address, align 4\nret void\n", 23, 0x100010);
   const char *overaligned =
      "target datalayout = \"e-p:64:64-i32:64-i64:64-v64:64-n8:16:32\"\n"
      "target triple = \"air64_v28-apple-macosx26.7.0\"\n"
      "define void @kernel(i32 %tid, ptr addrspace(1) %out) {\n";
   /* LLVM 23 getSequentialElementStride: vector elements use packed store
    * size (+4 here), arrays/root steps use ABI allocation size (+8 here). */
   constant_store_layout(overaligned,
      "%address = getelementptr <2 x i32>, ptr addrspace(1) %out, i32 0, i32 1\n"
      "store i32 37, ptr addrspace(1) %address, align 4\nret void\n", 37, 0x100004);
   constant_store_layout(overaligned,
      "%address = getelementptr [2 x <2 x i32>], ptr addrspace(1) %out, i32 0, i32 1, i32 1\n"
      "store i32 41, ptr addrspace(1) %address, align 4\nret void\n", 41, 0x10000c);
   constant_store_layout(overaligned,
      "%address = getelementptr [2 x i32], ptr addrspace(1) %out, i32 0, i32 1\n"
      "store i32 43, ptr addrspace(1) %address, align 4\nret void\n", 43, 0x100008);
}

/* Original LLVM fixture: each branch has an observable store, and the nested
 * results flow through edge-specific PHIs. Incoming order deliberately differs
 * from traversal order. No Apple compiler output is synthesized or relabelled. */
static const char *conditional_body =
   "entry:\n"
   "%outer = icmp ult i32 %tid, 16\n"
   "%bit = and i32 %tid, 1\n"
   "%even = icmp eq i32 %bit, 0\n"
   "br i1 %outer, label %left, label %right\n"
   "left:\n"
   "store i32 11, ptr addrspace(1) %out, align 4\n"
   "br i1 %even, label %le, label %lo\n"
   "le:\n%lep = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
   "store i32 21, ptr addrspace(1) %lep, align 4\n"
   "%lev = add i32 %tid, 100\nbr label %lj\n"
   "lo:\n%lop = getelementptr i32, ptr addrspace(1) %out, i32 2\n"
   "store i32 22, ptr addrspace(1) %lop, align 4\n"
   "%lov = add i32 %tid, 200\nbr label %lj\n"
   "lj:\n%lv = phi i32 [%lov, %lo], [%lev, %le]\nbr label %join\n"
   "right:\n%rp = getelementptr i32, ptr addrspace(1) %out, i32 3\n"
   "store i32 12, ptr addrspace(1) %rp, align 4\n"
   "br i1 %even, label %re, label %ro\n"
   "re:\n%rep = getelementptr i32, ptr addrspace(1) %out, i32 4\n"
   "store i32 23, ptr addrspace(1) %rep, align 4\n"
   "%rev = add i32 %tid, 300\nbr label %rj\n"
   "ro:\n%rop = getelementptr i32, ptr addrspace(1) %out, i32 5\n"
   "store i32 24, ptr addrspace(1) %rop, align 4\n"
   "%rov = add i32 %tid, 400\nbr label %rj\n"
   "rj:\n%rv = phi i32 [%rev, %re], [%rov, %ro]\nbr label %join\n"
   "join:\n"
   "%value = phi i32 [%rv, %rj], [%lv, %lj]\n"
   "%flag = phi i1 [true, %lj], [false, %rj]\n"
   "%vec = phi <2 x i32> [<i32 5, i32 6>, %lj], [<i32 7, i32 8>, %rj]\n"
   "%fp = getelementptr i32, ptr addrspace(1) %out, i32 8\n"
   "store i32 %value, ptr addrspace(1) %fp, align 4\n"
   "%flag32 = zext i1 %flag to i32\n"
   "%bp = getelementptr i32, ptr addrspace(1) %out, i32 9\n"
   "store i32 %flag32, ptr addrspace(1) %bp, align 4\n"
   "%element = extractelement <2 x i32> %vec, i32 1\n"
   "%vp = getelementptr i32, ptr addrspace(1) %out, i32 10\n"
   "store i32 %element, ptr addrspace(1) %vp, align 4\nret void\n";

static nir_shader *
translate_body(const char *body)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, "");
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, 1000, &error);
   if (!nir)
      fprintf(stderr, "control-flow fixture: %s\n", error.detail);
   CHECK(nir);
   LLVMDisposeMemoryBuffer(input);
   return nir;
}

/* Specialize only the documented invocation inputs. Original NIR optimizers
 * then fold branch conditions and remove unselected effects; this is not a new
 * shader interpreter. Production keeps the real invocation intrinsics. */
static void
specialize_invocation(nir_shader *nir, uint32_t tid)
{
   unsigned ids = 0;
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
            uint32_t x = intrinsic->intrinsic == nir_intrinsic_load_workgroup_id ? tid / 32 : tid % 32;
            nir_def_rewrite_uses(&intrinsic->def, nir_imm_ivec3(&b, x, 0, 0));
            nir_instr_remove(instr);
            ids++;
         }
      }
   }
   CHECK(ids == 2);
   bool progress;
   do {
      progress = nir_opt_constant_folding(nir);
      progress |= nir_opt_dead_cf(nir);
      progress |= nir_opt_remove_phis(nir);
      progress |= nir_opt_copy_prop(nir);
      progress |= nir_opt_dce(nir);
   } while (progress);
   nir_validate_shader(nir, "AIR specialized conditional effects");
}

static void
check_stores(nir_shader *nir, const uint64_t *addresses, const uint32_t *values, unsigned count)
{
   unsigned stores = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         CHECK(nir_block_get_following_if(block) == NULL);
         nir_foreach_instr(instr, block) {
            CHECK(instr->type != nir_instr_type_phi);
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            CHECK(intrinsic->intrinsic != nir_intrinsic_load_global);
            if (intrinsic->intrinsic != nir_intrinsic_store_global)
               continue;
            CHECK(stores < count);
            CHECK(nir_src_is_const(intrinsic->src[0]) && nir_src_as_uint(intrinsic->src[0]) == values[stores]);
            CHECK(nir_src_is_const(intrinsic->src[1]) && nir_src_as_uint(intrinsic->src[1]) == addresses[stores]);
            stores++;
         }
      }
   }
   CHECK(stores == count);
}

static void
conditional_semantics(void)
{
   /* Independent expected effects of the LLVM source, including order. */
   const struct {
      uint32_t tid;
      uint64_t addresses[5];
      uint32_t values[5];
   } paths[] = {
      {0, {0x100000, 0x100004, 0x100020, 0x100024, 0x100028}, {11, 21, 100, 1, 6}},
      {1, {0x100000, 0x100008, 0x100020, 0x100024, 0x100028}, {11, 22, 201, 1, 6}},
      {16, {0x10000c, 0x100010, 0x100020, 0x100024, 0x100028}, {12, 23, 316, 0, 8}},
      {17, {0x10000c, 0x100014, 0x100020, 0x100024, 0x100028}, {12, 24, 417, 0, 8}},
      {UINT32_MAX, {0x10000c, 0x100014, 0x100020, 0x100024, 0x100028}, {12, 24, 399, 0, 8}},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(paths); i++) {
      nir_shader *nir = translate_body(conditional_body);
      specialize_invocation(nir, paths[i].tid);
      check_stores(nir, paths[i].addresses, paths[i].values, 5);
      ralloc_free(nir);
   }
   const char *triangle =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %join, label %other\n"
      "other:\n%v = add i32 %tid, 9\nbr label %join\n"
      "join:\n%p = phi i32 [7, %entry], [%v, %other]\n"
      "store i32 %p, ptr addrspace(1) %out, align 4\nret void\n";
   for (unsigned tid = 0; tid < 2; tid++) {
      nir_shader *nir = translate_body(triangle);
      specialize_invocation(nir, tid);
      const uint64_t address = 0x100000;
      const uint32_t value = tid ? 10 : 7;
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
   }
   constant_store("entry:\nbr label %next\nnext:\n%p = phi i32 [23, %entry]\n"
      "store i32 %p, ptr addrspace(1) %out, align 4\nret void\n", 23, 0x100000);

   const char *indexed =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%index = phi i64 [-1, %left], [2, %right]\n"
      "%p = getelementptr i32, ptr addrspace(1) %out, i64 %index\n"
      "store i32 29, ptr addrspace(1) %p, align 4\nret void\n";
   const char *sequential =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%v = phi i8 [7, %left], [9, %right]\n"
      "%c2 = icmp eq i8 %v, 7\nbr i1 %c2, label %left2, label %right2\n"
      "left2:\n%l = add i8 %v, 3\nbr label %join2\n"
      "right2:\n%r = add i8 %v, 4\nbr label %join2\n"
      "join2:\n%v2 = phi i8 [%l, %left2], [%r, %right2]\n"
      "%value = zext i8 %v2 to i32\n"
      "store i32 %value, ptr addrspace(1) %out, align 4\nret void\n";
   for (unsigned tid = 0; tid < 2; tid++) {
      nir_shader *nir = translate_body(indexed);
      specialize_invocation(nir, tid);
      uint64_t address = tid ? 0x100008 : 0xffffc;
      uint32_t value = 29;
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
      nir = translate_body(sequential);
      specialize_invocation(nir, tid);
      address = 0x100000;
      value = tid ? 13 : 10;
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
   }

   /* Loads must stay on their original path. After specialization, exactly one
    * load remains and its result is the selected PHI's stored value. */
   const char *loads =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\n%lp = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "%l = load i32, ptr addrspace(1) %lp, align 4\nbr label %join\n"
      "right:\n%rp = getelementptr i32, ptr addrspace(1) %out, i32 2\n"
      "%r = load i32, ptr addrspace(1) %rp, align 4\nbr label %join\n"
      "join:\n%v = phi i32 [%r, %right], [%l, %left]\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n";
   for (unsigned tid = 0; tid < 2; tid++) {
      nir_shader *nir = translate_body(loads);
      specialize_invocation(nir, tid);
      unsigned load_count = 0, store_count = 0;
      nir_def *loaded = NULL;
      nir_foreach_function_impl(impl, nir) {
         nir_foreach_block(block, impl) {
            CHECK(nir_block_get_following_if(block) == NULL);
            nir_foreach_instr(instr, block) {
               if (instr->type != nir_instr_type_intrinsic)
                  continue;
               nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
               if (intrinsic->intrinsic == nir_intrinsic_load_global) {
                  CHECK(nir_src_is_const(intrinsic->src[0]));
                  CHECK(nir_src_as_uint(intrinsic->src[0]) == (tid ? 0x100008 : 0x100004));
                  loaded = &intrinsic->def;
                  load_count++;
               } else if (intrinsic->intrinsic == nir_intrinsic_store_global) {
                  CHECK(loaded && intrinsic->src[0].ssa == loaded);
                  CHECK(nir_src_is_const(intrinsic->src[1]) && nir_src_as_uint(intrinsic->src[1]) == 0x100000);
                  store_count++;
               }
            }
         }
      }
      CHECK(load_count == 1 && store_count == 1);
      ralloc_free(nir);
   }
}

static void
conditional_refusals(void)
{
   expect_refusal("entry:\nbr label %loop\nloop:\nbr label %loop\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("entry:\nbr label %loop\nloop:\n%c = icmp eq i32 %tid, 0\n"
      "br i1 %c, label %loop, label %exit\nexit:\nret void\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("ret void\ndead:\nbr label %dead\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nret void\nright:\nret void\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("switch i32 %tid, label %exit [i32 0, label %other]\n"
      "other:\nbr label %exit\nexit:\nret void\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("unreachable\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("%c = icmp eq i32 %tid, 0\nbr i1 %c, label %same, label %same\n"
      "same:\nret void\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %join\n"
      "left:\nbr i1 %c, label %inner, label %join\ninner:\nbr label %join\njoin:\nret void\n",
      "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %a, label %b\n"
      "a:\nbr i1 %c, label %cblock, label %d\nb:\nbr label %d\n"
      "cblock:\nbr label %join\nd:\nbr label %join\njoin:\nret void\n",
      "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal("%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(1) [%out, %left], [%out, %right]\nret void\n",
      "", 100, STELA_AIR_TYPE);
   /* Malformed SSA remains an LLVM verifier refusal, not a guessed PHI edge. */
   expect_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%p = phi i32 [1, %left], [2, %entry]\nret void\n", "", 100, STELA_AIR_VERIFY);
   expect_refusal(conditional_body, "", 20, STELA_AIR_LIMIT);

   char body[32768];
   size_t used;
   for (unsigned blocks = 128; blocks <= 129; blocks++) {
      used = (size_t)snprintf(body, sizeof(body), "entry:\nbr label %%b0\n");
      for (unsigned i = 0; i < blocks - 2; i++)
         used += (size_t)snprintf(body + used, sizeof(body) - used,
            "b%u:\nbr label %%b%u\n", i, i + 1);
      snprintf(body + used, sizeof(body) - used, "b%u:\nret void\n", blocks - 2);
      if (blocks == 129) {
         expect_refusal(body, "", 1000, STELA_AIR_LIMIT);
      } else {
         nir_shader *nir = translate_body(body);
         ralloc_free(nir);
      }
   }

   for (unsigned phis = 128; phis <= 129; phis++) {
      used = (size_t)snprintf(body, sizeof(body),
         "entry:\n%%c = icmp eq i32 %%tid, 0\nbr i1 %%c, label %%left, label %%right\n"
         "left:\nbr label %%join\nright:\nbr label %%join\njoin:\n");
      for (unsigned i = 0; i < phis; i++)
         used += (size_t)snprintf(body + used, sizeof(body) - used,
            "%%p%u = phi i32 [1, %%left], [2, %%right]\n", i);
      snprintf(body + used, sizeof(body) - used,
         "store i32 %%p%u, ptr addrspace(1) %%out, align 4\nret void\n", phis - 1);
      if (phis == 129) {
         expect_refusal(body, "", 1000, STELA_AIR_LIMIT);
      } else {
         for (unsigned tid = 0; tid < 2; tid++) {
            nir_shader *nir = translate_body(body);
            specialize_invocation(nir, tid);
            const uint64_t address = 0x100000;
            const uint32_t value = tid ? 2 : 1;
            check_stores(nir, &address, &value, 1);
            ralloc_free(nir);
         }
      }
   }

   /* Test both sides of the nesting limit with valid separate two-edge joins. */
   for (unsigned depth = 32; depth <= 33; depth++) {
      used = (size_t)snprintf(body, sizeof(body), "entry:\nbr label %%if0\n");
      for (unsigned i = 0; i < depth; i++)
         used += (size_t)snprintf(body + used, sizeof(body) - used,
            "if%u:\n%%c%u = icmp eq i32 %%tid, %u\nbr i1 %%c%u, label %%if%u, label %%else%u\n",
            i, i, i, i, i + 1, i);
      used += (size_t)snprintf(body + used, sizeof(body) - used,
         "if%u:\nbr label %%join%u\n", depth, depth - 1);
      for (unsigned i = depth; i-- > 0;) {
         used += (size_t)snprintf(body + used, sizeof(body) - used,
            "else%u:\nbr label %%join%u\njoin%u:\n", i, i, i);
         if (i)
            used += (size_t)snprintf(body + used, sizeof(body) - used, "br label %%join%u\n", i - 1);
         else
            used += (size_t)snprintf(body + used, sizeof(body) - used, "ret void\n");
      }
      if (depth == 33) {
         expect_refusal(body, "", 1000, STELA_AIR_LIMIT);
      } else {
         nir_shader *nir = translate_body(body);
         specialize_invocation(nir, 0);
         check_stores(nir, NULL, NULL, 0);
         ralloc_free(nir);
      }
   }
}

static char *
replace_once(const char *original, const char *before, const char *after)
{
   const char *at = strstr(original, before);
   CHECK(at);
   size_t bytes = strlen(original) - strlen(before) + strlen(after) + 1;
   char *result = malloc(bytes);
   CHECK(result);
   snprintf(result, bytes, "%.*s%s%s", (int)(at - original), original, after, at + strlen(before));
   return result;
}

static void
metadata_refusal(const char *before, const char *after, enum stela_air_error_kind expected)
{
   char *metadata = replace_once(stela_air_test_metadata, before, after);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(stela_air_test_prefix,
      stela_air_test_store_body, metadata, "");
   struct stela_air_error error;
   CHECK(!translate(input, &test_nir_options, 100, &error));
   if (error.kind != expected)
      fprintf(stderr, "metadata refusal wanted %u got %u: %s\n", expected, error.kind, error.detail);
   CHECK(error.kind == expected);
   LLVMDisposeMemoryBuffer(input);
   free(metadata);
}

static void
module_flag_test(const char *extra, enum stela_air_error_kind expected)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(stela_air_test_store_body, extra);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, 100, &error);
   if (error.kind != expected)
      fprintf(stderr, "module flag wanted %u got %u: %s\n", expected, error.kind, error.detail);
   CHECK(error.kind == expected && (nir != NULL) == (expected == STELA_AIR_OK));
   ralloc_free(nir);
   LLVMDisposeMemoryBuffer(input);
}

static void
tests(void)
{
   struct stela_air_error error;
   LLVMMemoryBufferRef input = stela_air_test_bitcode(stela_air_test_store_body, "");
   nir_shader *nir = translate(input, &test_nir_options, 100, &error);
   if (!nir)
      fprintf(stderr, "store shader: %s\n", error.detail);
   CHECK(nir);
   nir_print_shader(nir, stdout);
   ralloc_free(nir);
   CHECK(!translate(input, &test_nir_options, 1, &error) && error.kind == STELA_AIR_LIMIT);
   LLVMDisposeMemoryBuffer(input);
   constant_semantics();
   conditional_semantics();
   conditional_refusals();
   metadata_refusal("i32 2, i32 8, i32 0", "i32 2, i32 10, i32 0", STELA_AIR_METADATA);
   metadata_refusal("i32 2, i32 8, i32 0", "i32 2, i32 9, i32 0", STELA_AIR_TARGET);
   metadata_refusal("i32 4, i32 0, i32 0", "i32 4, i32 1, i32 0", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11,!12,!13}\n"
      "!11 = !{i32 1, !\"wchar_size\", i32 4}\n"
      "!12 = !{i32 7, !\"frame-pointer\", i32 2}\n"
      "!13 = !{i32 7, !\"air.max_device_buffers\", i32 31}\n", STELA_AIR_OK);
   module_flag_test("!llvm.module.flags = !{!11}\n"
      "!11 = !{i32 7, !\"air.max_device_buffers\", i32 7}\n", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11}\n"
      "!11 = !{i32 7, !\"air.max_device_buffers\", i32 0}\n", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11}\n"
      "!11 = !{i32 1, !\"air.max_device_buffers\", i32 31}\n", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11}\n"
      "!11 = !{i32 7, !\"air.future_semantics\", i32 31}\n", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11}\n"
      "!11 = !{i32 1, !\"wchar_size\", i32 8}\n", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11}\n"
      "!11 = !{i32 7, !\"frame-pointer\", i32 3}\n", STELA_AIR_METADATA);
   module_flag_test("!llvm.module.flags = !{!11,!12}\n"
      "!11 = !{i32 7, !\"air.max_device_buffers\", i32 31}\n"
      "!12 = !{i32 7, !\"air.max_device_buffers\", i32 32}\n", STELA_AIR_VERIFY);
   char *disabled_fetch = replace_once(stela_air_test_metadata,
      "air.compile.framebuffer_fetch_enable", "air.compile.framebuffer_fetch_disable");
   input = stela_air_test_custom_bitcode(stela_air_test_prefix,
      stela_air_test_store_body, disabled_fetch, "");
   nir = translate(input, &test_nir_options, 100, &error);
   CHECK(nir && error.kind == STELA_AIR_OK);
   ralloc_free(nir);
   LLVMDisposeMemoryBuffer(input);
   free(disabled_fetch);
   metadata_refusal("air.read_write", "air.read", STELA_AIR_MEMORY);
   metadata_refusal("i32 7, i32 1", "i32 7, i32 2", STELA_AIR_METADATA);
   metadata_refusal("air.thread_position_in_grid", "air.threadgroup_position_in_grid", STELA_AIR_ARGUMENT);
   metadata_refusal("air.arg_type_align_size\", i32 4", "air.arg_type_align_size\", i32 3", STELA_AIR_METADATA);
   metadata_refusal("air.compile.fast_math_enable", "air.compile.future_semantics", STELA_AIR_METADATA);
   expect_refusal("%v = fadd float 1.0, 2.0\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%v = load volatile i32, ptr addrspace(1) %out, align 4\nret void\n", "", 100, STELA_AIR_MEMORY);
   expect_refusal("%v = load atomic i32, ptr addrspace(1) %out monotonic, align 4\nret void\n", "", 100, STELA_AIR_MEMORY);
   expect_refusal("%v = udiv i32 %tid, 2\nret void\n", "", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("%v = freeze i32 poison\nret void\n", "", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("call void @helper()\nret void\n", "declare void @helper()\n", 100, STELA_AIR_TYPE);
   expect_refusal("store i32 %later, ptr addrspace(1) %out, align 4\n%later = add i32 %tid, 1\nret void\n", "", 100, STELA_AIR_VERIFY);
   expect_refusal("ret void\n", "!air.function_constants = !{!3}\n", 100, STELA_AIR_METADATA);
   expect_refusal("%v = add i32 undef, 1\nret void\n", "", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("%address = inttoptr i64 1048576 to ptr addrspace(1)\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%address = getelementptr <8 x i1>, ptr addrspace(1) %out, i32 0, i32 1\nret void\n", "", 100, STELA_AIR_VERIFY);
   expect_refusal("%address = getelementptr <vscale x 4 x i32>, ptr addrspace(1) %out, i32 1\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%address = getelementptr [2 x <vscale x 4 x i32>], ptr addrspace(1) %out, i32 1\nret void\n", "", 100, STELA_AIR_TYPE);
   const struct stela_air_options options = {.workgroup_size = {32, 1, 1}, .max_instructions = 100};
   const char malformed[] = "BC\xc0\xde\0\0\0\0";
   CHECK(!stela_air_to_nir(malformed, sizeof(malformed), "kernel", &test_nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_BITCODE);
   CHECK(!stela_air_to_nir(NULL, 0, "kernel", &test_nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_INPUT);
   input = stela_air_test_bitcode(stela_air_test_store_body, "");
   CHECK(!stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input), "kernel", &test_nir_options, &options, &error));
   CHECK(error.kind == STELA_AIR_ARGUMENT); /* A missing binding cannot succeed. */
   LLVMDisposeMemoryBuffer(input);
   puts("AIR input, metadata, integer/GEP/conditional effects and refusal tests passed");
}

#ifdef STELA_AIR_TEST_NAK
static void
digest(const void *bytes, size_t size, char out[2 * BLAKE3_OUT_LEN + 1])
{
   blake3_hasher hasher;
   uint8_t hash[BLAKE3_OUT_LEN];
   blake3_hasher_init(&hasher);
   blake3_hasher_update(&hasher, bytes, size);
   blake3_hasher_finalize(&hasher, hash, sizeof(hash));
   static const char hex[] = "0123456789abcdef";
   for (unsigned i = 0; i < sizeof(hash); i++) {
      out[2 * i] = hex[hash[i] >> 4];
      out[2 * i + 1] = hex[hash[i] & 15];
   }
   out[2 * BLAKE3_OUT_LEN] = 0;
}

static void
nak_codegen(const char *body, const char *label)
{
   const unsigned targets[] = {75, 80, 86, 87, 89, 90, 100, 104, 120};
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, "");
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
      const struct nv_device_info dev = {.sm = targets[i], .max_warps_per_mp = 32};
      const struct nak_constant_offset_info layout = {
         .sample_info_cb = 0, .sample_locations_offset = 0,
         .sample_masks_offset = 256, .printf_cb = 0, .printf_buffer_offset = 512,
      };
      struct nak_compiler *compiler = nak_compiler_create(&dev, &layout, &layout);
      CHECK(compiler);
      struct stela_air_error error;
      nir_shader *nir = translate(input, nak_nir_options(compiler), 1000, &error);
      if (!nir)
         fprintf(stderr, "NAK AIR: %s\n", error.detail);
      CHECK(nir);
      nak_preprocess_nir(nir, compiler);
      /* nak_compile_shader owns postprocessing, including structured->goto
       * lowering. Calling that phase twice is invalid for real control flow. */
      struct nak_shader_bin *bin = nak_compile_shader(nir, true, compiler, 0, NULL, false);
      CHECK(bin && bin->code && bin->code_size && bin->info.num_instrs > 2);
      CHECK(bin->info.sm == targets[i] && bin->info.stage == MESA_SHADER_COMPUTE);
      char target[64], input_hash[2 * BLAKE3_OUT_LEN + 1], code_hash[2 * BLAKE3_OUT_LEN + 1];
      if (!strcmp(label, "integer"))
         snprintf(target, sizeof(target), "sm%u", targets[i]);
      else
         snprintf(target, sizeof(target), "sm%u.%s", targets[i], label);
      digest(LLVMGetBufferStart(input), LLVMGetBufferSize(input), input_hash);
      digest(bin->code, bin->code_size, code_hash);
      probe_compiled("air-nak", target, bin->code_size);
      printf("STELA_AIR_NVIDIA_OUTPUT {\"target\":\"%s\",\"entry\":\"kernel\","
             "\"input_blake3\":\"%s\",\"code_blake3\":\"%s\",\"workgroup\":[32,1,1],"
             "\"buffer_index\":7,\"fixture_va\":1048576,\"hardware_executed\":false}\n",
             target, input_hash, code_hash);
      printf("AIR %s->LLVM->NIR->NAK SM%u: %u bytes, %u instructions\n", label, targets[i], bin->code_size, bin->info.num_instrs);
      if (bin->asm_str)
         puts(bin->asm_str);
      nak_shader_bin_destroy(bin);
      ralloc_free(nir);
      nak_compiler_destroy(compiler);
   }
   LLVMDisposeMemoryBuffer(input);
}
#endif

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   tests();
#ifdef STELA_AIR_TEST_NAK
   nak_codegen(stela_air_test_store_body, "integer");
   nak_codegen(conditional_body, "nested-conditional");
#endif
   glsl_type_singleton_decref();
   return 0;
}
