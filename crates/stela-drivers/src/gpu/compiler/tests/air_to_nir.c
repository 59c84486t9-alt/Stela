/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "llvm-c/BitWriter.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/Core.h"
#include "llvm-c/IRReader.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef STELA_AIR_TEST_NAK
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include "probe_report.h"
#include "targets/nvidia.h"
#endif

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

#include "air_test_fixture.h"
#include "air_effect_oracle.h"

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
static const nir_shader_compiler_options extended_compare_options = {
   .has_fneo_fcmpu = true, .has_ford_funord = true,
};

/* A lexical store list is an execution trace only after every region folds.
 * In particular, one store in a nonterminating loop is not one finite effect. */
static bool
finite_effect_body(nir_function_impl *impl)
{
   return impl->structured && exec_list_length(&impl->body) == 1;
}

static nir_shader *
translate_profile(LLVMMemoryBufferRef input, const nir_shader_compiler_options *nir_options,
                  unsigned budget, enum stela_air_fp_profile profile, struct stela_air_error *error)
{
   unsigned bindings = 0;
   const struct stela_air_options options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = budget,
      .bind_buffer = bind_buffer, .binding_data = &bindings,
      .fp_profile = profile,
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

static nir_shader *
translate(LLVMMemoryBufferRef input, const nir_shader_compiler_options *nir_options,
          unsigned budget, struct stela_air_error *error)
{
   return translate_profile(input, nir_options, budget, STELA_AIR_FP_IEEE_DEFAULT, error);
}

static void
expect_refusal(const char *body, const char *extra, unsigned budget,
               enum stela_air_error_kind expected)
{
   LLVMMemoryBufferRef input = stela_air_test_bitcode(body, extra);
   struct stela_air_error error;
   nir_shader *nir = translate(input, &test_nir_options, budget, &error);
   if (nir || error.kind != expected) {
      fprintf(stderr, "refusal wanted %u, got %u: %s\n%s\n", expected, error.kind, error.detail, body);
      LLVMContextRef context = LLVMContextCreate();
      LLVMModuleRef module = NULL;
      if (!LLVMParseBitcodeInContext2(context, input, &module)) {
         char *text = LLVMPrintModuleToString(module);
         fprintf(stderr, "decoded refusal fixture:\n%s\n", text);
         LLVMDisposeMessage(text);
         LLVMDisposeModule(module);
      }
      LLVMContextDispose(context);
   }
   CHECK(!nir && error.kind == expected && error.detail[0]);
   LLVMDisposeMemoryBuffer(input);
}

static void
constant_store_options(LLVMMemoryBufferRef input, const nir_shader_compiler_options *nir_options,
                       enum stela_air_fp_profile profile, uint64_t expected, uint64_t address)
{
   struct stela_air_error error;
   nir_shader *nir = translate_profile(input, nir_options, 100, profile, &error);
   if (!nir)
      fprintf(stderr, "constant shader: %s\n", error.detail);
   CHECK(nir);
   while (nir_opt_constant_folding(nir)) {}
   nir_opt_dce(nir);
   unsigned stores = 0;
   nir_foreach_function_impl(impl, nir) {
      CHECK(finite_effect_body(impl));
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
constant_store_profile(LLVMMemoryBufferRef input, enum stela_air_fp_profile profile,
                       uint64_t expected, uint64_t address)
{
   constant_store_options(input, &test_nir_options, profile, expected, address);
}

static void
constant_store_input(LLVMMemoryBufferRef input, uint64_t expected, uint64_t address)
{
   constant_store_profile(input, STELA_AIR_FP_IEEE_DEFAULT, expected, address);
}

static void
constant_store_layout(const char *prefix, const char *body,
                      uint64_t expected, uint64_t address)
{
   constant_store_input(stela_air_test_custom_bitcode(prefix, body, stela_air_test_metadata, ""),
                        expected, address);
}

static void
constant_store(const char *body, uint64_t expected, uint64_t address)
{
   constant_store_layout(stela_air_test_prefix, body, expected, address);
}

static char *replace_once(const char *original, const char *before, const char *after);

static nir_def *
bind_prelude(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   unsigned mode = *(unsigned *)data;
   CHECK((buffer->argument == 1 || buffer->argument == 2) &&
         buffer->index == buffer->argument + 6 && buffer->address_space == 1);
   nir_def *address = nir_imm_int64(b, 0x100000);
   if (mode == 1) {
      nir_if *region = nir_push_if(b, nir_imm_true(b));
      nir_def *yes = nir_imm_int64(b, 0x100000);
      nir_push_else(b, region);
      nir_def *no = nir_imm_int64(b, 0x200000);
      nir_pop_if(b, region);
      address = nir_if_phi(b, yes, no);
   } else if (mode == 2) {
      nir_jump(b, nir_jump_return);
   }
   return address;
}

static void
binding_prelude_contract(void)
{
   for (unsigned layout = 0; layout < 3; layout++) {
      /* Reflection order is independent of LLVM parameter order. Exercise a
       * callback before a later builtin and before a second buffer callback. */
      char *metadata = layout ? replace_once(stela_air_test_metadata, "!4 = !{!5,!6}",
         layout == 1 ? "!4 = !{!6,!5}" : "!4 = !{!6,!7,!5}") : NULL;
      char *prefix = layout == 2 ? replace_once(stela_air_test_prefix,
         "ptr addrspace(1) %out)", "ptr addrspace(1) %out, ptr addrspace(1) %out2)") : NULL;
      const char *extra = layout == 2 ?
         "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 8, i32 1, !\"air.read_write\","
         " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
         " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"second\"}\n" : "";
      LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(prefix ? prefix : stela_air_test_prefix,
         stela_air_test_store_body, metadata ? metadata : stela_air_test_metadata, extra);
      free(prefix); free(metadata);
      for (unsigned mode = 0; mode < 3; mode++) {
         struct stela_air_options options = {
            .workgroup_size = {32, 1, 1}, .max_instructions = 100,
            .bind_buffer = bind_prelude, .binding_data = &mode,
         };
         struct stela_air_error error;
         nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
            "kernel", &test_nir_options, &options, &error);
         if (!mode) {
            CHECK(nir && error.kind == STELA_AIR_OK);
            nir_validate_shader(nir, "straight-line resource binding prelude");
            ralloc_free(nir);
         } else {
            CHECK(!nir && error.kind == STELA_AIR_CONTROL_FLOW && error.detail[0]);
         }
      }
      LLVMDisposeMemoryBuffer(input);
   }
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
   if (getenv("STELA_AIR_CFG_TRACE"))
      fprintf(stderr, "AIR CFG fixture:\n%s\n", body);
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
      if (!finite_effect_body(impl))
         nir_print_shader(nir, stderr);
      CHECK(finite_effect_body(impl));
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
check_executed_stores(nir_shader *nir, const uint64_t *addresses,
                       const uint32_t *values, unsigned count)
{
   struct air_effect_store trace[64];
   CHECK(count <= ARRAY_SIZE(trace));
   struct air_effect_run run = air_effect_execute(nir, 4096, trace, ARRAY_SIZE(trace));
   if (run.status != AIR_EFFECT_COMPLETE) {
      fprintf(stderr, "NIR effects: status%u after%u instructions, %u stores: %s\n",
              run.status, run.instructions, run.stores, run.detail);
      nir_print_shader(nir, stderr);
   }
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == count);
   for (unsigned i = 0; i < count; i++) {
      CHECK(!trace[i].ssbo && trace[i].components == 1 && trace[i].bits == 32);
      CHECK(trace[i].address == addresses[i] && trace[i].values[0].u32 == values[i]);
   }
}

static void
effect_oracle_contract(void)
{
   struct air_effect_store trace[128];
   nir_shader *nir = translate_body("store i32 17, ptr addrspace(1) %out, align 4\nret void\n");
   specialize_invocation(nir, 0);
   CHECK(air_effect_execute(nir, 1, trace, ARRAY_SIZE(trace)).status == AIR_EFFECT_BUDGET);
   CHECK(air_effect_execute(nir, 64, NULL, 0).status == AIR_EFFECT_TRACE_FULL);
   const uint64_t address = 0x100000;
   const uint32_t value = 17;
   check_executed_stores(nir, &address, &value, 1);
   check_stores(nir, &address, &value, 1); /* Keep the independent lexical oracle. */
   ralloc_free(nir);

   const char *cycles[] = {
      "entry:\nbr label %loop\nloop:\nbr label %loop\n",
      "entry:\nbr label %loop\nloop:\nstore i32 17, ptr addrspace(1) %out, align 4\nbr label %loop\n",
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cycles); i++) {
      nir = translate_body(cycles[i]);
      /* Do not run dead-CF optimization on the empty-cycle negative control. */
      nir_opt_dce(nir);
      nir_foreach_function_impl(impl, nir) CHECK(!finite_effect_body(impl));
      struct air_effect_run run = air_effect_execute(nir, 64, trace, ARRAY_SIZE(trace));
      CHECK(run.status == AIR_EFFECT_BUDGET);
      CHECK((run.stores != 0) == (i != 0));
      ralloc_free(nir);
   }

   /* Unknown invocation IDs and actual loads are explicit unsupported results. */
   nir = translate_body("%c = icmp eq i32 %tid, 0\nbr i1 %c, label %a, label %done\n"
      "a:\nstore i32 17, ptr addrspace(1) %out, align 4\nbr label %done\ndone:\nret void\n");
   nir_foreach_function_impl(impl, nir) CHECK(!finite_effect_body(impl));
   CHECK(air_effect_execute(nir, 256, trace, ARRAY_SIZE(trace)).status == AIR_EFFECT_UNSUPPORTED);
   ralloc_free(nir);
   nir = translate_body("%v = load i32, ptr addrspace(1) %out, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   specialize_invocation(nir, 0);
   CHECK(air_effect_execute(nir, 256, trace, ARRAY_SIZE(trace)).status == AIR_EFFECT_UNSUPPORTED);
   ralloc_free(nir);

   /* A direct swap catches sequential PHI publication: b must read OLD a. */
   nir = translate_body("entry:\nbr label %header\nheader:\n"
      "%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%a = phi i32 [11, %entry], [%b, %latch]\n"
      "%b = phi i32 [22, %entry], [%a, %latch]\n"
      "store i32 %a, ptr addrspace(1) %out, align 4\n"
      "%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %b, ptr addrspace(1) %p, align 4\n"
      "%more = icmp ult i32 %i, 1\nbr i1 %more, label %latch, label %exit\n"
      "latch:\n%next = add i32 %i, 1\nbr label %header\nexit:\nret void\n");
   specialize_invocation(nir, 0);
   const uint64_t swap_addresses[] = {0x100000, 0x100004, 0x100000, 0x100004};
   const uint32_t swap_values[] = {11, 22, 22, 11};
   check_executed_stores(nir, swap_addresses, swap_values, ARRAY_SIZE(swap_values));
   ralloc_free(nir);

   /* Retain actual arithmetic (DCE only), exercising widths and vector lanes. */
   nir = translate_body("%b = add i8 -1, 2\nstore i8 %b, ptr addrspace(1) %out, align 1\n"
      "%s = sext i16 -32768 to i64\nstore i64 %s, ptr addrspace(1) %out, align 1\n"
      "%v = add <4 x i16> <i16 -1,i16 32767,i16 0,i16 -32768>, <i16 1,i16 1,i16 1,i16 -1>\n"
      "store <4 x i16> %v, ptr addrspace(1) %out, align 1\nret void\n");
   nir_opt_dce(nir);
   struct air_effect_run run = air_effect_execute(nir, 256, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == 3);
   CHECK(trace[0].bits == 8 && trace[0].components == 1 && trace[0].values[0].u8 == 1);
   CHECK(trace[1].bits == 64 && trace[1].components == 1 && trace[1].values[0].u64 == UINT64_C(0xffffffffffff8000));
   const uint16_t lanes[] = {0, 32768, 1, 32767};
   CHECK(trace[2].bits == 16 && trace[2].components == 4);
   for (unsigned i = 0; i < ARRAY_SIZE(lanes); i++) CHECK(trace[2].values[i].u16 == lanes[i]);
   ralloc_free(nir);

   for (unsigned branch = 0; branch < 2; branch++) {
      nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, &test_nir_options, "SSBO oracle");
      b.shader->info.num_ssbos = 4;
      nir_if *region = nir_push_if(&b, nir_imm_bool(&b, branch));
      nir_store_ssbo(&b, nir_imm_int(&b, 41), nir_imm_int(&b, 2), nir_imm_int(&b, 4), .align_mul = 4);
      nir_push_else(&b, region);
      nir_store_ssbo(&b, nir_imm_int(&b, 43), nir_imm_int(&b, 3), nir_imm_int(&b, 8), .align_mul = 4);
      nir_pop_if(&b, region);
      run = air_effect_execute(b.shader, 256, trace, ARRAY_SIZE(trace));
      CHECK(run.status == AIR_EFFECT_COMPLETE && run.stores == 1);
      CHECK(trace[0].ssbo && trace[0].components == 1 && trace[0].bits == 32);
      CHECK(trace[0].slot == (branch ? 2 : 3) && trace[0].address == (branch ? 4 : 8));
      CHECK(trace[0].values[0].u32 == (branch ? 41 : 43));
      ralloc_free(b.shader);
   }
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, &test_nir_options, "undefined oracle");
   nir_store_global(&b, nir_undef(&b, 1, 32), nir_imm_int64(&b, 0x100000), .align_mul = 4);
   CHECK(air_effect_execute(b.shader, 64, trace, ARRAY_SIZE(trace)).status == AIR_EFFECT_UNDEFINED);
   ralloc_free(b.shader);

   /* A valid return can precede unreachable lexical CF. Follow its real edge,
    * without evaluating either dead branch or mistaking it for completion. */
   b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, &test_nir_options, "dead if after return");
   nir_if *dead = nir_push_if(&b, nir_imm_true(&b));
   nir_store_global(&b, nir_imm_int(&b, 71), nir_imm_int64(&b, 0x100000), .align_mul = 4);
   nir_push_else(&b, dead);
   nir_store_global(&b, nir_imm_int(&b, 73), nir_imm_int64(&b, 0x100004), .align_mul = 4);
   nir_pop_if(&b, dead);
   b.cursor = nir_after_block(nir_start_block(b.impl));
   nir_jump(&b, nir_jump_return);
   run = air_effect_execute(b.shader, 64, trace, ARRAY_SIZE(trace));
   CHECK(run.status == AIR_EFFECT_COMPLETE && !run.stores);
   ralloc_free(b.shader);
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
      check_executed_stores(nir, paths[i].addresses, paths[i].values, 5);
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
         CHECK(finite_effect_body(impl));
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
specialize_loop(nir_shader *nir, uint32_t tid)
{
   /* Original NIR unrolling is a test oracle for finite specialized inputs.
    * Translation/codegen keeps the dynamic loop and never applies this cap. */
   static const nir_shader_compiler_options options = {.max_unroll_iterations = 16};
   specialize_invocation(nir, tid);
   nir->options = &options;
   /* Multiple LLVM latches can leave identical induction updates in opposite
    * arms of an if. Expose their common value with original Mesa passes before
    * asking its loop analysis to recognize the finite specialized induction.
    * Do not speculate loads, stores or discard while flattening pure ALU. */
   const nir_opt_peephole_select_options select = {
      .limit = 64, .expensive_alu_ok = true,
   };
   bool progress;
   do {
      progress = nir_opt_peephole_select(nir, &select);
      progress |= nir_opt_cse(nir);
      progress |= nir_opt_algebraic(nir);
      progress |= nir_opt_if(nir, nir_opt_if_optimize_phi_true_false);
      progress |= nir_opt_loop_unroll(nir);
      progress |= nir_opt_constant_folding(nir);
      progress |= nir_opt_dead_cf(nir);
      progress |= nir_opt_remove_phis(nir);
      progress |= nir_opt_copy_prop(nir);
      progress |= nir_opt_dce(nir);
   } while (progress);
   nir_validate_shader(nir, "AIR specialized natural-loop effects");
}

static const char *loop_body =
   "entry:\n%count = add i32 %tid, 0\nbr label %header\n"
   "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
   "%x = phi i32 [1, %entry], [%y, %latch]\n"
   "%y = phi i32 [2, %entry], [%sum, %latch]\n"
   "%vec = phi <2 x i32> [<i32 3, i32 5>, %entry], [%vnext, %latch]\n"
   "%flag = phi i1 [false, %entry], [%fnext, %latch]\n"
   "%last = phi i32 [99, %entry], [%chosen, %latch]\n"
   "store i32 %i, ptr addrspace(1) %out, align 4\n"
   "%more = icmp ult i32 %i, %count\nbr i1 %more, label %body, label %exit\n"
   "body:\n%bit = and i32 %i, 1\n%even = icmp eq i32 %bit, 0\n"
   "br i1 %even, label %left, label %right\n"
   "left:\n%lp = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
   "store i32 %x, ptr addrspace(1) %lp, align 4\nbr label %latch\n"
   "right:\n%rp = getelementptr i32, ptr addrspace(1) %out, i32 2\n"
   "store i32 %y, ptr addrspace(1) %rp, align 4\nbr label %latch\n"
   "latch:\n%chosen = phi i32 [%x, %left], [%y, %right]\n"
   "%next = add i32 %i, 1\n%sum = add i32 %x, %y\n"
   "%vnext = add <2 x i32> %vec, <i32 1, i32 2>\n%fnext = xor i1 %flag, true\n"
   "br label %header\n"
   "exit:\n%xp = getelementptr i32, ptr addrspace(1) %out, i32 3\n"
   "store i32 %x, ptr addrspace(1) %xp, align 4\n"
   "%yp = getelementptr i32, ptr addrspace(1) %out, i32 4\n"
   "store i32 %y, ptr addrspace(1) %yp, align 4\n"
   "%v0 = extractelement <2 x i32> %vec, i32 0\n"
   "%v0p = getelementptr i32, ptr addrspace(1) %out, i32 5\n"
   "store i32 %v0, ptr addrspace(1) %v0p, align 4\n"
   "%v1 = extractelement <2 x i32> %vec, i32 1\n"
   "%v1p = getelementptr i32, ptr addrspace(1) %out, i32 6\n"
   "store i32 %v1, ptr addrspace(1) %v1p, align 4\n"
   "%flag32 = zext i1 %flag to i32\n"
   "%fp = getelementptr i32, ptr addrspace(1) %out, i32 7\n"
   "store i32 %flag32, ptr addrspace(1) %fp, align 4\n"
   "%lastp = getelementptr i32, ptr addrspace(1) %out, i32 8\n"
   "store i32 %last, ptr addrspace(1) %lastp, align 4\nret void\n";

static void
loop_semantics(void)
{
   /* Independently tabulated simultaneous state (x'=y, y'=x+y). A sequential
    * PHI substitution would produce different state after the first trip. */
   const uint32_t x[] = {1, 2, 3, 5, 8}, y[] = {2, 3, 5, 8, 13};
   for (unsigned trips = 0; trips < ARRAY_SIZE(x); trips++) {
      nir_shader *nir = translate_body(loop_body);
      unsigned loops = 0;
      nir_foreach_function_impl(impl, nir) {
         foreach_list_typed(nir_cf_node, node, node, &impl->body) {
            if (node->type == nir_cf_node_loop)
               loops++;
         }
      }
      CHECK(loops == 1); /* Production NIR retains real dynamic control flow. */
      specialize_loop(nir, trips);
      uint64_t addresses[15];
      uint32_t values[15];
      unsigned effects = 0;
      for (unsigned i = 0; i <= trips; i++) {
         addresses[effects] = 0x100000;
         values[effects++] = i; /* Header runs once even for zero trips. */
         if (i < trips) {
            addresses[effects] = (i & 1) ? 0x100008 : 0x100004;
            values[effects++] = (i & 1) ? y[i] : x[i];
         }
      }
      uint32_t last = trips ? ((trips & 1) ? x[trips - 1] : y[trips - 1]) : 99;
      const uint32_t final[] = {x[trips], y[trips], 3 + trips, 5 + 2 * trips, trips & 1, last};
      for (unsigned i = 0; i < ARRAY_SIZE(final); i++) {
         addresses[effects] = 0x10000c + 4 * i;
         values[effects++] = final[i];
      }
      check_stores(nir, addresses, values, effects);
      ralloc_free(nir);
   }
   const char *sequential =
      "entry:\n%n = and i32 %tid, 3\nbr label %h1\n"
      "h1:\n%i = phi i32 [0, %entry], [%inext, %l1]\n"
      "%x = phi i32 [%xnext, %l1], [10, %entry]\n"
      "%c1 = icmp ult i32 %i, %n\nbr i1 %c1, label %l1, label %between\n"
      "l1:\n%inext = add i32 %i, 1\n%xnext = add i32 %x, 1\nbr label %h1\n"
      "between:\n%first = phi i32 [%x, %h1]\n"
      "store i32 %first, ptr addrspace(1) %out, align 4\nbr label %h2\n"
      "h2:\n%j = phi i32 [0, %between], [%jnext, %l2]\n"
      "%r = phi i32 [%first, %between], [%rnext, %l2]\n"
      "%c2 = icmp ult i32 %j, %n\nbr i1 %c2, label %l2, label %exit\n"
      "l2:\n%jnext = add i32 %j, 1\n%rnext = add i32 %r, 2\nbr label %h2\n"
      "exit:\n%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %r, ptr addrspace(1) %p, align 4\nret void\n";
   for (unsigned trips = 0; trips < 4; trips++) {
      nir_shader *nir = translate_body(sequential);
      specialize_loop(nir, trips);
      const uint64_t addresses[] = {0x100000, 0x100004};
      const uint32_t values[] = {10 + trips, 10 + 3 * trips};
      check_stores(nir, addresses, values, 2);
      ralloc_free(nir);
   }
   const char *conditional =
      "entry:\n%n = and i32 %tid, 3\n%bit = and i32 %tid, 4\n"
      "%take = icmp ne i32 %bit, 0\nbr i1 %take, label %pre, label %other\n"
      "pre:\nbr label %header\n"
      "header:\n%i = phi i32 [0, %pre], [%next, %latch]\n"
      "store i32 %i, ptr addrspace(1) %out, align 4\n"
      "%more = icmp ult i32 %i, %n\nbr i1 %more, label %latch, label %join\n"
      "latch:\n%next = add i32 %i, 1\nbr label %header\n"
      "other:\nbr label %join\n"
      "join:\n%result = phi i32 [%i, %header], [99, %other]\n"
      "%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %result, ptr addrspace(1) %p, align 4\nret void\n";
   for (unsigned tid = 0; tid < 8; tid++) {
      nir_shader *nir = translate_body(conditional);
      specialize_loop(nir, tid);
      unsigned trips = tid & 3, effects = 0;
      uint64_t addresses[5];
      uint32_t values[5];
      if (tid & 4) {
         for (unsigned i = 0; i <= trips; i++) {
            addresses[effects] = 0x100000;
            values[effects++] = i;
         }
      }
      addresses[effects] = 0x100004;
      values[effects++] = (tid & 4) ? trips : 99;
      check_stores(nir, addresses, values, effects);
      ralloc_free(nir);
   }
}

/* Each expected value/effect is derived from the LLVM fixture, independently
 * of the frontend's CFG construction. Original NIR optimization specializes
 * only test inputs; no production trip bound or substitute interpreter exists. */
static void
cfg_semantics(void)
{
   const char *switch_body =
      "entry:\nswitch i32 %tid, label %other [i32 0, label %a i32 5, label %b i32 10, label %c i32 15, label %d]\n"
      "a:\nbr label %join\nb:\nbr label %join\nc:\nbr label %join\nd:\nbr label %join\nother:\nbr label %join\n"
      "join:\n%v = phi i32 [11, %a], [22, %b], [33, %c], [44, %d], [55, %other]\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n";
   const char *early =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nstore i32 7, ptr addrspace(1) %out, align 4\nret void\n"
      "right:\n%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 9, ptr addrspace(1) %p, align 4\nret void\n";
   const char *unordered =
      "entry:\nbr label %def\nuse:\n%v = add i32 %base, 5\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n"
      "def:\n%base = add i32 %tid, 10\nbr label %use\n";
   const char *dead =
      "entry:\nbr label %live\ndead:\n%unused = udiv i32 %tid, 7\nbr label %join\n"
      "live:\n%v = add i32 %tid, 11\nbr label %join\n"
      "join:\n%p = phi i32 [%unused, %dead], [%v, %live]\n"
      "store i32 %p, ptr addrspace(1) %out, align 4\nret void\n";
   const char *duplicate =
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %same, label %same\n"
      "same:\n%p = phi i32 [31, %entry], [31, %entry]\n"
      "store i32 %p, ptr addrspace(1) %out, align 4\nret void\n";
   const char *overlap =
      "entry:\n%c = icmp ult i32 %tid, 2\nbr i1 %c, label %a, label %b\n"
      "a:\n%c2 = icmp eq i32 %tid, 0\nbr i1 %c2, label %cblock, label %d\n"
      "b:\nbr label %d\ncblock:\nbr label %join\nd:\nbr label %join\n"
      "join:\n%p = phi i32 [17, %cblock], [29, %d]\n"
      "store i32 %p, ptr addrspace(1) %out, align 4\nret void\n";
   const uint32_t tids[] = {0, 1, 2, 5, 10, 15, UINT32_MAX};
   for (unsigned i = 0; i < ARRAY_SIZE(tids); i++) {
      uint32_t tid = tids[i];
      const struct { const char *body; uint64_t address; uint32_t value; } cases[] = {
         {switch_body, 0x100000, tid == 0 ? 11 : tid == 5 ? 22 : tid == 10 ? 33 : tid == 15 ? 44 : 55},
         {early, tid ? 0x100004 : 0x100000, tid ? 9 : 7},
         {unordered, 0x100000, tid + 15}, {dead, 0x100000, tid + 11},
         {duplicate, 0x100000, 31}, {overlap, 0x100000, tid ? 29 : 17},
      };
      for (unsigned j = 0; j < ARRAY_SIZE(cases); j++) {
         nir_shader *nir = translate_body(cases[j].body);
         specialize_invocation(nir, tid);
         check_stores(nir, &cases[j].address, &cases[j].value, 1);
         ralloc_free(nir);
      }
   }
   /* Nine original instructions fit, but switch legalization needs additional
    * compares/branches. The caller's budget also bounds that expansion. */
   expect_refusal(switch_body, "", 9, STELA_AIR_LIMIT);

   /* Many cases targeting one block can legalize to a single branch, but the
    * source work must still fit the explicit budget before invoking LLVM. */
   expect_refusal("switch i32 %tid, label %same [i32 0, label %same i32 1, label %same i32 2, label %same]\n"
      "same:\nret void\n", "", 2, STELA_AIR_LIMIT);

   const char *multi_latch =
      "entry:\n%trips = and i32 %tid, 3\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%il, %left], [%ir, %right]\n"
      "%sum = phi i32 [0, %entry], [%sl, %left], [%sr, %right]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %body, label %exit\n"
      "body:\n%parity = and i32 %i, 1\n%even = icmp eq i32 %parity, 0\n"
      "br i1 %even, label %left, label %right\n"
      "left:\n%il = add i32 %i, 1\n%sl = add i32 %sum, 3\nbr label %header\n"
      "right:\n%ir = add i32 %i, 1\n%sr = add i32 %sum, 7\nbr label %header\n"
      "exit:\nstore i32 %sum, ptr addrspace(1) %out, align 4\nret void\n";
   const char *nested =
      "entry:\n%trips = and i32 %tid, 3\nbr label %outer\n"
      "outer:\n%i = phi i32 [0, %entry], [%inext, %inner_exit]\n"
      "%acc = phi i32 [0, %entry], [%anext, %inner_exit]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %pre, label %exit\n"
      "pre:\nbr label %inner\n"
      "inner:\n%j = phi i32 [0, %pre], [%jnext, %body]\n"
      "%sum = phi i32 [%acc, %pre], [%snext, %body]\n"
      "%inside = icmp ult i32 %j, 2\nbr i1 %inside, label %body, label %inner_exit\n"
      "body:\n%base = mul i32 %i, 10\n%v = add i32 %base, %j\n"
      "%snext = add i32 %sum, %v\n%jnext = add i32 %j, 1\nbr label %inner\n"
      "inner_exit:\n%anext = add i32 %sum, 1\n%inext = add i32 %i, 1\nbr label %outer\n"
      "exit:\nstore i32 %acc, ptr addrspace(1) %out, align 4\nret void\n";
   const char *body_exit =
      "entry:\n%stop = and i32 %tid, 3\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%more = icmp ult i32 %i, 6\nbr i1 %more, label %body, label %exit\n"
      "body:\n%done = icmp eq i32 %i, %stop\nbr i1 %done, label %early, label %latch\n"
      "latch:\n%next = add i32 %i, 1\nbr label %header\n"
      "early:\nstore i32 %i, ptr addrspace(1) %out, align 4\nret void\n"
      "exit:\nstore i32 99, ptr addrspace(1) %out, align 4\nret void\n";
   for (unsigned tid = 0; tid < 4; tid++) {
      uint32_t nested_sum = 0, latch_sum = 0;
      for (unsigned i = 0; i < tid; i++) {
         latch_sum += i & 1 ? 7 : 3;
         for (unsigned j = 0; j < 2; j++)
            nested_sum += 10 * i + j;
         nested_sum++;
      }
      const struct { const char *body; uint32_t value; } cases[] = {
         {multi_latch, latch_sum}, {nested, nested_sum}, {body_exit, tid},
      };
      for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
         nir_shader *nir = translate_body(cases[i].body);
         specialize_loop(nir, tid);
         const uint64_t address = 0x100000;
         check_stores(nir, &address, &cases[i].value, 1);
         ralloc_free(nir);
      }
   }
   const char *irreducible =
      "entry:\n%odd = and i32 %tid, 1\n%c = icmp eq i32 %odd, 0\n"
      "br i1 %c, label %a, label %b\n"
      "a:\n%av = phi i32 [0, %entry], [%bn, %b]\n%an = add i32 %av, 1\n"
      "store i32 %an, ptr addrspace(1) %out, align 4\n"
      "%amore = icmp ult i32 %an, 3\nbr i1 %amore, label %b, label %exit\n"
      "b:\n%bv = phi i32 [0, %entry], [%an, %a]\n%bn = add i32 %bv, 1\n"
      "%tag = add i32 %bn, 100\n%p = getelementptr i32, ptr addrspace(1) %out, i32 1\n"
      "store i32 %tag, ptr addrspace(1) %p, align 4\n"
      "%bmore = icmp ult i32 %bn, 3\nbr i1 %bmore, label %a, label %exit\n"
      "exit:\n%result = phi i32 [%an, %a], [%bn, %b]\n"
      "%r = getelementptr i32, ptr addrspace(1) %out, i32 2\n"
      "store i32 %result, ptr addrspace(1) %r, align 4\nret void\n";
   for (unsigned tid = 0; tid < 2; tid++) {
      nir_shader *nir = translate_body(irreducible);
      specialize_loop(nir, tid);
      const uint64_t addresses[2][4] = {
         {0x100000, 0x100004, 0x100000, 0x100008},
         {0x100004, 0x100000, 0x100004, 0x100008},
      };
      const uint32_t values[2][4] = {{1, 102, 3, 3}, {101, 2, 103, 3}};
      check_executed_stores(nir, addresses[tid], values[tid], 4);
      ralloc_free(nir);
   }
}

static void
oracle_fixture_evidence(const char *name, const void *data, size_t bytes)
{
   const char *directory = getenv("STELA_AIR_ORACLE_EVIDENCE");
   if (!directory) return;
   char path[4096];
   int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
   CHECK(length > 0 && (size_t)length < sizeof(path));
   FILE *file = fopen(path, "wb");
   CHECK(file && fwrite(data, 1, bytes, file) == bytes);
   CHECK(!fclose(file));
}

static void
duplicate_phi_reader_contract(void)
{
   /* The bitcode reader reuses a repeated predecessor's first incoming value.
    * Therefore raw unequal-record rejection and cfg_emit's defensive unequal
    * guard are NOT covered by these frontend calls. Preserve the original
    * verifier refusal and explicitly measure this LLVM reader/oracle limit. */
   const char *bodies[] = {
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %same, label %same\n"
      "same:\n%p = phi i32 [31, %entry], [32, %entry]\nret void\n",
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %same, label %same\n"
      "same:\n%p = phi i32 [31, %entry], [32, %entry]\n"
      "store i32 %p, ptr addrspace(1) %out, align 4\nret void\n",
   };
   unsigned major, minor, patch;
   LLVMGetVersion(&major, &minor, &patch);
   char runtime[128];
   int length = snprintf(runtime, sizeof(runtime), "{\"runtime_llvm\":\"%u.%u.%u\"}\n", major, minor, patch);
   CHECK(length > 0 && (size_t)length < sizeof(runtime));
   oracle_fixture_evidence("duplicate-phi-runtime.json", runtime, (size_t)length);
   for (unsigned use = 0; use < ARRAY_SIZE(bodies); use++) {
      size_t bytes = strlen(stela_air_test_prefix) + strlen(bodies[use]) + strlen(stela_air_test_metadata) + 1;
      char *source = malloc(bytes); CHECK(source);
      snprintf(source, bytes, "%s%s%s", stela_air_test_prefix, bodies[use], stela_air_test_metadata);
      LLVMContextRef context = LLVMContextCreate();
      LLVMMemoryBufferRef assembly = LLVMCreateMemoryBufferWithMemoryRangeCopy(source, bytes - 1, "unequal-phi");
      LLVMModuleRef module = NULL;
      char *message = NULL;
      CHECK(!LLVMParseIRInContext(context, assembly, &module, &message));
      LLVMDisposeMessage(message); message = NULL;
      CHECK(LLVMVerifyModule(module, LLVMReturnStatusAction, &message));
      CHECK(message && strstr(message, "different incoming values"));
      char name[128];
      snprintf(name, sizeof(name), "duplicate-phi-%u-original.ll", use);
      oracle_fixture_evidence(name, source, bytes - 1);
      snprintf(name, sizeof(name), "duplicate-phi-%u-verifier.txt", use);
      oracle_fixture_evidence(name, message, strlen(message));
      LLVMDisposeMessage(message);
      LLVMDisposeModule(module); LLVMContextDispose(context); free(source);

      LLVMMemoryBufferRef input = stela_air_test_bitcode(bodies[use], "");
      snprintf(name, sizeof(name), "duplicate-phi-%u-encoded.bc", use);
      oracle_fixture_evidence(name, LLVMGetBufferStart(input), LLVMGetBufferSize(input));
      context = LLVMContextCreate(); module = NULL;
      CHECK(!LLVMParseBitcodeInContext2(context, input, &module));
      message = NULL;
      CHECK(!LLVMVerifyModule(module, LLVMReturnStatusAction, &message));
      LLVMDisposeMessage(message);
      LLVMValueRef phi = LLVMGetFirstInstruction(LLVMGetNextBasicBlock(LLVMGetFirstBasicBlock(LLVMGetNamedFunction(module, "kernel"))));
      CHECK(LLVMGetInstructionOpcode(phi) == LLVMPHI && LLVMCountIncoming(phi) == 2);
      for (unsigned i = 0; i < 2; i++) {
         CHECK(LLVMIsAConstantInt(LLVMGetIncomingValue(phi, i)));
         CHECK(LLVMConstIntGetZExtValue(LLVMGetIncomingValue(phi, i)) == 31);
      }
      char *decoded = LLVMPrintModuleToString(module);
      snprintf(name, sizeof(name), "duplicate-phi-%u-decoded.ll", use);
      oracle_fixture_evidence(name, decoded, strlen(decoded));
      LLVMDisposeMessage(decoded); LLVMDisposeModule(module); LLVMContextDispose(context);
      struct stela_air_error error;
      nir_shader *nir = translate(input, &test_nir_options, 100, &error);
      CHECK(nir && error.kind == STELA_AIR_OK);
      specialize_invocation(nir, 0);
      const uint64_t address = 0x100000;
      const uint32_t value = 31;
      check_executed_stores(nir, &address, &value, use);
      check_stores(nir, &address, &value, use);
      ralloc_free(nir); LLVMDisposeMemoryBuffer(input);
   }
}

static void
pointer_phi_semantics(void)
{
   const char *nested =
      "entry:\n%c = icmp ult i32 %tid, 2\nbr i1 %c, label %choose, label %right\n"
      "choose:\n%zero = icmp eq i32 %tid, 0\nbr i1 %zero, label %a, label %b\n"
      "a:\n%pa = getelementptr i32, ptr addrspace(1) %out, i32 1\nbr label %inner\n"
      "b:\n%pb = getelementptr i32, ptr addrspace(1) %out, i32 2\nbr label %inner\n"
      "inner:\n%left = phi ptr addrspace(1) [%pb, %b], [%pa, %a]\nbr label %join\n"
      "right:\n%pr = getelementptr i32, ptr addrspace(1) %out, i32 3\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(1) [%left, %inner], [%pr, %right]\n"
      "%alias = bitcast ptr addrspace(1) %p to ptr addrspace(1)\n"
      "store i32 73, ptr addrspace(1) %alias, align 4\nret void\n";
   const char *advance =
      "entry:\n%trips = and i32 %tid, 3\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%p = phi ptr addrspace(1) [%out, %entry], [%step, %latch]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %latch, label %exit\n"
      "latch:\n%step = getelementptr i32, ptr addrspace(1) %p, i32 1\n"
      "%next = add i32 %i, 1\nbr label %header\n"
      "exit:\nstore i32 73, ptr addrspace(1) %p, align 4\nret void\n";
   const char *swap =
      "entry:\n%trips = and i32 %tid, 3\n"
      "%base = getelementptr i32, ptr addrspace(1) %out, i32 1\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%a = phi ptr addrspace(1) [%out, %entry], [%b, %latch]\n"
      "%b = phi ptr addrspace(1) [%base, %entry], [%a, %latch]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %latch, label %exit\n"
      "latch:\n%next = add i32 %i, 1\nbr label %header\n"
      "exit:\nstore i32 73, ptr addrspace(1) %a, align 4\n"
      "store i32 97, ptr addrspace(1) %b, align 4\nret void\n";
   const char *dead = "entry:\nbr label %live\ndead:\n%ignored = inttoptr i64 0 to ptr addrspace(1)\nbr label %join\n"
      "live:\nbr label %join\njoin:\n%p = phi ptr addrspace(1) [poison, %dead], [%out, %live]\n"
      "store i32 73, ptr addrspace(1) %p, align 4\nret void\n";
   const char *bodies[] = {nested, advance, swap, dead};
   for (unsigned body = 0; body < ARRAY_SIZE(bodies); body++) {
      for (unsigned tid = 0; tid < 4; tid++) {
         uint64_t addresses[] = {
            UINT64_C(0x100000) + (body == 0 ? 4 * (tid < 2 ? tid + 1 : 3) :
                                    body == 1 ? 4 * tid : body == 2 ? 4 * (tid & 1) : 0),
            UINT64_C(0x100000) + 4 * ((tid & 1) ^ 1),
         };
         const uint32_t values[] = {73, 97};
         unsigned count = body == 2 ? 2 : 1;
         nir_shader *nir = translate_body(bodies[body]);
         specialize_invocation(nir, tid);
         check_executed_stores(nir, addresses, values, count);
         ralloc_free(nir);
         nir = translate_body(bodies[body]);
         specialize_loop(nir, tid);
         check_stores(nir, addresses, values, count);
         ralloc_free(nir);
      }
   }
   /* The same-origin identity loop used to be a blanket type refusal. Retain
    * genuine nontermination as a bounded test-executor failure, not success. */
   nir_shader *nir = translate_body("entry:\nbr label %header\nheader:\n"
      "%p = phi ptr addrspace(1) [%out, %entry], [%p, %latch]\n"
      "store i32 73, ptr addrspace(1) %p, align 4\nbr label %latch\n"
      "latch:\nbr label %header\n");
   specialize_invocation(nir, 0);
   struct air_effect_store trace[64];
   CHECK(air_effect_execute(nir, 64, trace, ARRAY_SIZE(trace)).status == AIR_EFFECT_BUDGET);
   ralloc_free(nir);

   const char *invalid[] = {"undef", "poison", "null"};
   for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
      char body[512];
      snprintf(body, sizeof(body), "entry:\nbr label %%header\nheader:\n"
         "%%p = phi ptr addrspace(1) [%s, %%entry], [%%step, %%latch]\n"
         "%%more = icmp eq i32 %%tid, 0\nbr i1 %%more, label %%latch, label %%exit\n"
         "latch:\n%%step = getelementptr i32, ptr addrspace(1) %%p, i32 1\nbr label %%header\n"
         "exit:\nret void\n", invalid[i]);
      expect_refusal(body, "", 100, STELA_AIR_MEMORY);
   }
   expect_refusal("entry:\n%raw = inttoptr i64 1048576 to ptr addrspace(1)\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(1) [%raw, %entry]\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("entry:\n%unknown = freeze ptr addrspace(1) %out\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(1) [%unknown, %entry]\nret void\n", "", 100, STELA_AIR_TYPE);
   /* LLVM rejects this rootless self-reference on the entry edge before the
    * provenance pass; do not lend it %out's authority through the later join. */
   expect_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %cycle, label %root\n"
      "cycle:\n%p = phi ptr addrspace(1) [%p, %entry], [%p, %cycle]\n"
      "br i1 %c, label %cycle, label %join\nroot:\nbr label %join\n"
      "join:\n%q = phi ptr addrspace(1) [%p, %cycle], [%out, %root]\nret void\n",
      "", 100, STELA_AIR_VERIFY);
   puts("Same-origin pointer PHIs: nested joins, GEP recurrences, parallel swaps and explicit provenance refusals");
}

static void
pointer_equality_semantics(void)
{
   const char *loop =
      "entry:\n%trips = and i32 %tid, 3\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%p = phi ptr addrspace(1) [%out, %entry], [%step, %latch]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %latch, label %exit\n"
      "latch:\n%step = getelementptr i32, ptr addrspace(1) %p, i32 1\n"
      "%next = add i32 %i, 1\nbr label %header\n"
      "exit:\n%eq = icmp eq ptr addrspace(1) %p, %out\n"
      "%ne = icmp ne ptr addrspace(1) %p, %out\n"
      "%a = zext i1 %eq to i32\n%b = zext i1 %ne to i32\n"
      "%b2 = shl i32 %b, 1\n%value = or i32 %a, %b2\n"
      "store i32 %value, ptr addrspace(1) %out, align 4\nret void\n";
   for (unsigned tid = 0; tid < 4; tid++) {
      const uint64_t address = 0x100000;
      const uint32_t value = tid ? 2 : 1;
      nir_shader *nir = translate_body(loop);
      specialize_invocation(nir, tid);
      check_executed_stores(nir, &address, &value, 1);
      ralloc_free(nir);
      nir = translate_body(loop);
      specialize_loop(nir, tid);
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
   }
   /* Non-inbounds GEP arithmetic wraps modulo the pointer width. Adding the
    * same unknown base preserves eq/ne even across that wrap; it cannot
    * justify any signed/unsigned ordering of relative offsets. */
   constant_store("%minus = getelementptr i8, ptr addrspace(1) %out, i64 -1\n"
      "%wrapped = getelementptr i8, ptr addrspace(1) %minus, i64 1\n"
      "%eq = icmp eq ptr addrspace(1) %wrapped, %out\n"
      "%ne = icmp ne ptr addrspace(1) %minus, %out\n"
      "%a = zext i1 %eq to i32\n%b = zext i1 %ne to i32\n"
      "%b2 = shl i32 %b, 1\n%value = or i32 %a, %b2\n"
      "store i32 %value, ptr addrspace(1) %out, align 4\nret void\n", 3, 0x100000);
   constant_store("%p = getelementptr i32, ptr addrspace(1) %out, i32 0\n"
      "%same = icmp eq ptr addrspace(1) %p, %out\n%value = zext i1 %same to i32\n"
      "store i32 %value, ptr addrspace(1) %out, align 4\nret void\n", 1, 0x100000);
   const char *predicates[] = {"ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle"};
   for (unsigned i = 0; i < ARRAY_SIZE(predicates); i++) {
      char body[384];
      snprintf(body, sizeof(body), "%%minus = getelementptr i8, ptr addrspace(1) %%out, i64 -1\n"
         "%%wrapped = getelementptr i8, ptr addrspace(1) %%minus, i64 1\n"
         "%%ordered = icmp %s ptr addrspace(1) %%wrapped, %%out\nret void\n", predicates[i]);
      expect_refusal(body, "", 100, STELA_AIR_TYPE);
   }
   const char *invalid[] = {"null", "undef", "poison"};
   for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
      for (unsigned ne = 0; ne < 2; ne++) {
         char body[192];
         snprintf(body, sizeof(body), "%%same = icmp %s ptr addrspace(1) %%out, %s\nret void\n",
            ne ? "ne" : "eq", invalid[i]);
         expect_refusal(body, "", 100, STELA_AIR_MEMORY);
      }
   }
}

static nir_def *
bind_equal_pointer_roots(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   CHECK(buffer->argument == 1 || buffer->argument == 2);
   (*(unsigned *)data)++;
   return nir_imm_int64(b, 0x100000); /* Equal test values grant no root identity. */
}

static void
pointer_phi_authority_refusals(void)
{
   char *prefix = replace_once(stela_air_test_prefix, "ptr addrspace(1) %out)",
      "ptr addrspace(1) %out, ptr addrspace(1) %other)");
   char *metadata = replace_once(stela_air_test_metadata, "!4 = !{!5,!6}", "!4 = !{!5,!6,!11}");
   const char *body = "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(1) [%out, %left], [%other, %right]\n"
      "store i32 73, ptr addrspace(1) %p, align 4\nret void\n";
   const char *access[] = {"air.read_write", "air.read"};
   for (unsigned i = 0; i < ARRAY_SIZE(access); i++) {
      char extra[512];
      snprintf(extra, sizeof(extra), "!11 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 8, i32 1,"
         " !\"%s\", !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"
         " !\"air.arg_type_align_size\", i32 4}\n", access[i]);
      LLVMMemoryBufferRef raw = stela_air_test_custom_bitcode(prefix, body, metadata, extra);
      unsigned callbacks = 0;
      const struct stela_air_options options = {.workgroup_size = {32, 1, 1},
         .max_instructions = 100, .bind_buffer = bind_equal_pointer_roots, .binding_data = &callbacks};
      struct stela_air_error error;
      CHECK(!stela_air_to_nir(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw), "kernel",
         &test_nir_options, &options, &error));
      CHECK(callbacks == 2 && error.kind == STELA_AIR_MEMORY && strstr(error.detail, "distinct resource"));
      LLVMDisposeMemoryBuffer(raw);
   }
   for (unsigned ne = 0; ne < 2; ne++) {
      char compare_body[256];
      snprintf(compare_body, sizeof(compare_body),
         "%%same = icmp %s ptr addrspace(1) %%out, %%other\nret void\n", ne ? "ne" : "eq");
      LLVMMemoryBufferRef raw = stela_air_test_custom_bitcode(prefix, compare_body, metadata,
         "!11 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 8, i32 1,"
         " !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"
         " !\"air.arg_type_align_size\", i32 4}\n");
      unsigned callbacks = 0;
      const struct stela_air_options options = {.workgroup_size = {32, 1, 1},
         .max_instructions = 100, .bind_buffer = bind_equal_pointer_roots, .binding_data = &callbacks};
      struct stela_air_error error;
      CHECK(!stela_air_to_nir(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw), "kernel",
         &test_nir_options, &options, &error));
      CHECK(callbacks == 2 && error.kind == STELA_AIR_MEMORY && strstr(error.detail, "one validated resource"));
      LLVMDisposeMemoryBuffer(raw);
   }
   free(prefix); free(metadata);
   metadata = replace_once(stela_air_test_metadata, "air.read_write", "air.read");
   LLVMMemoryBufferRef raw = stela_air_test_custom_bitcode(stela_air_test_prefix,
      "entry:\nbr label %join\njoin:\n%p = phi ptr addrspace(1) [%out, %entry]\n"
      "store i32 73, ptr addrspace(1) %p, align 4\nret void\n", metadata, "");
   struct stela_air_error error;
   CHECK(!translate(raw, &test_nir_options, 100, &error) && error.kind == STELA_AIR_MEMORY);
   LLVMDisposeMemoryBuffer(raw); free(metadata);
}

static void
cfg_limits_and_refusals(void)
{
   expect_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%p = phi {i32, i32} [{i32 1, i32 2}, %left], [{i32 3, i32 4}, %right]\nret void\n",
      "", 100, STELA_AIR_TYPE);
   expect_refusal("br i1 poison, label %same, label %same\nsame:\nret void\n",
      "", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("unreachable\n", "", 100, STELA_AIR_CONTROL_FLOW);
   expect_refusal(loop_body, "", 20, STELA_AIR_LIMIT);
   expect_refusal(conditional_body, "", 20, STELA_AIR_LIMIT);
   /* Malformed SSA remains an LLVM verifier refusal. Duplicate CFG edges are
    * allowed only when their PHI values agree, never guessed or overwritten. */
   expect_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nbr label %join\nright:\nbr label %join\n"
      "join:\n%p = phi i32 [1, %left], [2, %entry]\nret void\n", "", 100, STELA_AIR_VERIFY);
   duplicate_phi_reader_contract();
   expect_refusal("entry:\nbr label %header\nheader:\n"
      "%i = phi i32 [0, %entry], [1, %exit]\n"
      "%c = icmp eq i32 %tid, 0\nbr i1 %c, label %latch, label %exit\n"
      "latch:\nbr label %header\nexit:\nret void\n", "", 100, STELA_AIR_VERIFY);

   char body[32768];
   size_t used;
   /* Both sides of each removed pattern limit now have effects to verify. */
   for (unsigned blocks = 128; blocks <= 129; blocks++) {
      used = (size_t)snprintf(body, sizeof(body), "entry:\nbr label %%b0\n");
      for (unsigned i = 0; i < blocks - 2; i++)
         used += (size_t)snprintf(body + used, sizeof(body) - used,
            "b%u:\nbr label %%b%u\n", i, i + 1);
      snprintf(body + used, sizeof(body) - used,
         "b%u:\nstore i32 41, ptr addrspace(1) %%out, align 4\nret void\n", blocks - 2);
      nir_shader *nir = translate_body(body);
      specialize_invocation(nir, 0);
      const uint64_t address = 0x100000;
      const uint32_t value = 41;
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
      expect_refusal(body, "", blocks, STELA_AIR_LIMIT); /* Store adds one. */
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
      for (unsigned tid = 0; tid < 2; tid++) {
         nir_shader *nir = translate_body(body);
         specialize_invocation(nir, tid);
         const uint64_t address = 0x100000;
         const uint32_t value = tid ? 2 : 1;
         check_stores(nir, &address, &value, 1);
         ralloc_free(nir);
      }
   }
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
            used += (size_t)snprintf(body + used, sizeof(body) - used,
               "store i32 43, ptr addrspace(1) %%out, align 4\nret void\n");
      }
      nir_shader *nir = translate_body(body);
      specialize_invocation(nir, 0);
      const uint64_t address = 0x100000;
      const uint32_t value = 43;
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
   }
   /* A dead cycle has no effects; a reachable nonterminating cycle must remain
    * a real loop, rather than an injected return or bounded production loop. */
   nir_shader *nir = translate_body("ret void\ndead:\nbr label %dead\n");
   specialize_invocation(nir, 0);
   check_stores(nir, NULL, NULL, 0);
   ralloc_free(nir);
   nir = translate_body("entry:\nbr label %loop\nloop:\n"
      "store i32 5, ptr addrspace(1) %out, align 4\nbr label %loop\n");
   unsigned loops = 0, stores = 0;
   nir_foreach_function_impl(impl, nir) {
      CHECK(!finite_effect_body(impl)); /* Must never pass a finite trace check. */
      foreach_list_typed(nir_cf_node, node, node, &impl->body)
         loops += node->type == nir_cf_node_loop;
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic)
               stores += nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_store_global;
         }
      }
   }
   CHECK(loops == 1 && stores == 1);
   ralloc_free(nir);
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

static LLVMMemoryBufferRef
ieee_bitcode_extra(const char *prefix, const char *body, const char *extra)
{
   char *metadata = replace_once(stela_air_test_metadata,
      "!air.compile_options = !{!8,!9,!10}", "!air.compile_options = !{!10}");
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(prefix, body, metadata, extra);
   free(metadata);
   return input;
}

static LLVMMemoryBufferRef
ieee_bitcode(const char *prefix, const char *body)
{
   return ieee_bitcode_extra(prefix, body, "");
}

static LLVMMemoryBufferRef
qualified_bitcode(const char *body, const char *extra)
{
   /* Original fixtures for profile checks, not relabelled Apple output or
    * independent evidence that a new compiler/language profile is supported. */
   char *prefix = replace_once(stela_air_test_prefix, "air64_v28-apple-macosx26.7.0", "air64_v29-apple-macosx27.2.0");
   char *air = replace_once(stela_air_test_metadata, "i32 2, i32 8, i32 0", "i32 2, i32 9, i32 0");
   char *metadata = replace_once(air, "i32 4, i32 0, i32 0", "i32 4, i32 1, i32 0");
   char declarations[2048];
   int length = snprintf(declarations, sizeof(declarations),
      "!llvm.ident = !{!11}\n!11 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n%s",
      extra);
   CHECK(length >= 0 && (size_t)length < sizeof(declarations));
   LLVMMemoryBufferRef result = stela_air_test_custom_bitcode(prefix, body, metadata, declarations);
   free(prefix);
   free(air);
   free(metadata);
   return result;
}

static const char *shared_declaration =
   "declare void @air.wg.barrier(i32, i32, i32) convergent\n";
static const char *shared_global_declaration =
   "@scratch = internal addrspace(3) global [64 x i32] undef, align 4\n";
static const char *shared_body =
   "%lane = and i32 %tid, 63\n%idx = zext i32 %lane to i64\n"
   "%p = getelementptr [64 x i32], ptr addrspace(3) @scratch, i64 0, i64 %idx\n"
   "%v = add i32 %lane, 1\nstore i32 %v, ptr addrspace(3) %p, align 4\n"
   "call void @air.wg.barrier(i32 2, i32 5, i32 1) convergent\n"
   "%next = add i32 %lane, 1\n%other = and i32 %next, 63\n%o64 = zext i32 %other to i64\n"
   "%q = getelementptr [64 x i32], ptr addrspace(3) @scratch, i64 0, i64 %o64\n"
   "%loaded = load i32, ptr addrspace(3) %q, align 4\n"
   "store i32 %loaded, ptr addrspace(1) %out, align 4\nret void\n";

static LLVMMemoryBufferRef
shared_bitcode_index(const char *body, bool dynamic, const char *extra, unsigned index)
{
   /* Original LLVM fixtures test the observed ABI; captured Apple modules are
    * separately consumed byte-for-byte, never relabelled or rewritten here. */
   char *prefix = replace_once(stela_air_test_prefix, "air64_v28-apple-macosx26.7.0", "air64_v29-apple-macosx27.2.0");
   char *air = replace_once(stela_air_test_metadata, "i32 2, i32 8, i32 0", "i32 2, i32 9, i32 0");
   char *metadata = replace_once(air, "i32 4, i32 0, i32 0", "i32 4, i32 1, i32 0");
   if (dynamic) {
      char *next = replace_once(prefix, "ptr addrspace(1) %out)",
         "ptr addrspace(1) %out, ptr addrspace(3) %scratch)");
      free(prefix); prefix = next;
      next = replace_once(metadata, "!4 = !{!5,!6}", "!4 = !{!5,!6,!12}");
      free(metadata); metadata = next;
   }
   char argument[512] = "";
   if (dynamic)
      CHECK(snprintf(argument, sizeof(argument),
         "!12 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 %u, i32 1, !\"air.read_write\","
         "!\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4}\n", index) > 0);
   size_t size = strlen(extra) + strlen(argument) + 512;
   char *declarations = malloc(size);
   CHECK(declarations);
   CHECK(snprintf(declarations, size,
      "!llvm.ident = !{!11}\n!11 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
      "!llvm.module.flags = !{!13}\n!13 = !{i32 7, !\"air.max_threadgroup_buffers\", i32 31}\n%s%s",
      argument, extra) > 0);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(prefix, body, metadata, declarations);
   free(declarations); free(prefix); free(air); free(metadata);
   return input;
}

static LLVMMemoryBufferRef
shared_bitcode(const char *body, bool dynamic, const char *extra)
{
   /* Same index7 as AS1 proves these are separate Metal resource namespaces. */
   return shared_bitcode_index(body, dynamic, extra, 7);
}

struct shared_bindings {
   unsigned devices, shared;
   struct stela_air_threadgroup_view view;
};

static nir_def *
shared_bind_device(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   struct shared_bindings *bindings = data;
   return bind_buffer(b, buffer, &bindings->devices);
}

static bool
shared_bind(const struct stela_air_buffer *buffer, struct stela_air_threadgroup_view *view, void *data)
{
   struct shared_bindings *bindings = data;
   CHECK(buffer->argument == 2 && buffer->index == 7 && buffer->address_space == 3 &&
         buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 && buffer->type_alignment == 4);
   bindings->shared++;
   *view = bindings->view;
   return true;
}

static nir_shader *
shared_translate(LLVMMemoryBufferRef input, const nir_shader_compiler_options *nir_options,
                  struct shared_bindings *bindings, unsigned limit, struct stela_air_error *error)
{
   const struct stela_air_options options = {
      .workgroup_size = {64,1,1}, .max_instructions = 1000,
      .bind_buffer = shared_bind_device, .binding_data = bindings,
      .bind_threadgroup = limit ? shared_bind : NULL, .max_threadgroup_bytes = limit,
   };
   return stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input), "kernel",
                           nir_options, &options, error);
}

static void
check_shared_operations(nir_shader *nir, unsigned stores, unsigned loads, unsigned barriers)
{
   unsigned seen_stores = 0, seen_loads = 0, seen_barriers = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            if (intr->intrinsic == nir_intrinsic_store_shared) {
               CHECK(!seen_barriers); /* Publication precedes the rendezvous. */
               seen_stores++;
            } else if (intr->intrinsic == nir_intrinsic_load_shared) {
               CHECK(seen_barriers == barriers);
               seen_loads++;
            } else if (intr->intrinsic == nir_intrinsic_barrier) {
               CHECK(seen_stores == stores && !seen_loads);
               CHECK(nir_intrinsic_execution_scope(intr) == SCOPE_WORKGROUP &&
                     nir_intrinsic_memory_scope(intr) == SCOPE_WORKGROUP &&
                     nir_intrinsic_memory_modes(intr) == nir_var_mem_shared &&
                     nir_intrinsic_memory_semantics(intr) == NIR_MEMORY_ACQ_REL);
               seen_barriers++;
            }
         }
      }
   }
   CHECK(seen_stores == stores && seen_loads == loads && seen_barriers == barriers);
   if (barriers)
      CHECK(nir->info.uses_control_barrier && nir->info.uses_memory_barrier);
   nir_validate_shader(nir, "AIR shared bounds/collective ordering");
}

static void
shared_semantics(void)
{
   char extra[512];
   snprintf(extra, sizeof(extra), "%s%s", shared_global_declaration, shared_declaration);
   LLVMMemoryBufferRef input = shared_bitcode(shared_body, false, extra);
   struct shared_bindings bindings = {.view = {256,4,STELA_AIR_READ_WRITE}};
   struct stela_air_error error;
   nir_shader *nir = shared_translate(input, &test_nir_options, &bindings, 256, &error);
   CHECK(nir && bindings.devices == 1 && !bindings.shared && nir->info.shared_size == 256);
   check_shared_operations(nir, 1, 1, 1);
   ralloc_free(nir);
   CHECK(!shared_translate(input, &test_nir_options, &bindings, 255, &error) && error.kind == STELA_AIR_LIMIT);
   CHECK(!shared_translate(input, &test_nir_options, &bindings, 0, &error) && error.kind == STELA_AIR_LIMIT);
   LLVMDisposeMemoryBuffer(input);

   char *dynamic = replace_once(shared_body, "@scratch", "%scratch");
   char *next = replace_once(dynamic, "@scratch", "%scratch");
   free(dynamic); dynamic = next;
   input = shared_bitcode(dynamic, true, shared_declaration);
   bindings = (struct shared_bindings){.view = {256,4,STELA_AIR_READ_WRITE}};
   nir = shared_translate(input, &test_nir_options, &bindings, 256, &error);
   CHECK(nir && bindings.devices == 1 && bindings.shared == 1 && nir->info.shared_size == 256);
   check_shared_operations(nir, 1, 1, 1);
   ralloc_free(nir);
   const struct stela_air_threadgroup_view invalid[] = {
      {0,4,STELA_AIR_READ_WRITE}, {3,4,STELA_AIR_READ_WRITE},
      {257,4,STELA_AIR_READ_WRITE}, {UINT64_MAX,4,STELA_AIR_READ_WRITE},
      {256,0,STELA_AIR_READ_WRITE}, {256,3,STELA_AIR_READ_WRITE},
      {256,2,STELA_AIR_READ_WRITE}, {256,4,STELA_AIR_READ}, {256,4,4},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
      bindings.view = invalid[i];
      CHECK(!shared_translate(input, &test_nir_options, &bindings, 256, &error));
      CHECK(error.kind == STELA_AIR_ARGUMENT || error.kind == STELA_AIR_LIMIT);
   }
   LLVMDisposeMemoryBuffer(input);
   input = shared_bitcode_index(dynamic, true, shared_declaration, 31);
   bindings.view = (struct stela_air_threadgroup_view){256,4,STELA_AIR_READ_WRITE};
   CHECK(!shared_translate(input, &test_nir_options, &bindings, 256, &error) && error.kind == STELA_AIR_METADATA);
   LLVMDisposeMemoryBuffer(input);
   free(dynamic);

   /* Separate resources use original NIR's required alignment, not a custom
    * allocator. The 8-byte object starts at16 after the 3-byte object. */
   input = shared_bitcode("store i8 1, ptr addrspace(3) @a, align 1\n"
      "store i32 2, ptr addrspace(3) @b, align 4\nret void\n", false,
      "@a = internal addrspace(3) global [3 x i8] undef, align 1\n"
      "@b = internal addrspace(3) global [2 x i32] undef, align 16\n");
   bindings = (struct shared_bindings){0};
   nir = shared_translate(input, &test_nir_options, &bindings, 24, &error);
   CHECK(nir && nir->info.shared_size == 24);
   specialize_invocation(nir, 0);
   unsigned shared_stores = 0;
   nir_foreach_function_impl(impl, nir) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            if (intr->intrinsic != nir_intrinsic_store_shared)
               continue;
            CHECK(nir_src_is_const(intr->src[1]) &&
                  nir_src_as_uint(intr->src[1]) + nir_intrinsic_base(intr) == (shared_stores ? 16 : 0));
            CHECK(nir_src_is_const(intr->src[0]) && nir_src_as_uint(intr->src[0]) == shared_stores + 1);
            shared_stores++;
         }
      }
   }
   CHECK(shared_stores == 2);
   ralloc_free(nir);
   CHECK(!shared_translate(input, &test_nir_options, &bindings, 23, &error) && error.kind == STELA_AIR_LIMIT);
   LLVMDisposeMemoryBuffer(input);

   const uint64_t offsets[] = {0, 15, 16, UINT64_C(1) << 30, UINT64_MAX};
   for (unsigned i = 0; i < ARRAY_SIZE(offsets); i++) {
      char body[512];
      snprintf(body, sizeof(body), "%%p = getelementptr [16 x i32], ptr addrspace(3) @scratch, i64 0, i64 %llu\n"
         "store i32 42, ptr addrspace(3) %%p, align 4\n"
         "%%v = load i32, ptr addrspace(3) %%p, align 4\n"
         "store i32 %%v, ptr addrspace(1) %%out, align 4\nret void\n", (unsigned long long)offsets[i]);
      input = shared_bitcode(body, false, "@scratch = internal addrspace(3) global [16 x i32] undef, align 4\n");
      nir = shared_translate(input, &test_nir_options, &bindings, 64, &error);
      CHECK(nir && nir->info.shared_size == 64);
      specialize_invocation(nir, 0);
      bool valid = i < 2;
      check_shared_operations(nir, valid ? 1 : 0, valid ? 1 : 0, 0);
      if (!valid) {
         const uint64_t address = 0x100000;
         const uint32_t value = 0;
         check_stores(nir, &address, &value, 1);
      }
      ralloc_free(nir);
      LLVMDisposeMemoryBuffer(input);
   }
}

static void
shared_refusal(const char *body, const char *extra, enum stela_air_error_kind expected)
{
   LLVMMemoryBufferRef input = shared_bitcode(body, false, extra);
   struct shared_bindings bindings = {0};
   struct stela_air_error error;
   nir_shader *nir = shared_translate(input, &test_nir_options, &bindings, 256, &error);
   if (nir || error.kind != expected)
      fprintf(stderr, "shared refusal wanted%u got%u: %s\n", expected, error.kind, error.detail);
   CHECK(!nir && error.kind == expected && error.detail[0]);
   LLVMDisposeMemoryBuffer(input);
}

static void
shared_pointer_phi_semantics(void)
{
   const char *body =
      "entry:\n%trips = and i32 %tid, 3\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%p = phi ptr addrspace(3) [@scratch, %entry], [%step, %latch]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %latch, label %exit\n"
      "latch:\n%step = getelementptr i32, ptr addrspace(3) %p, i32 1\n"
      "%next = add i32 %i, 1\nbr label %header\n"
      "exit:\nstore i32 42, ptr addrspace(3) %p, align 4\nret void\n";
   char *dynamic = replace_once(body, "@scratch", "%scratch");
   for (unsigned mode = 0; mode < 2; mode++) {
      LLVMMemoryBufferRef raw = shared_bitcode(mode ? dynamic : body, mode != 0,
         mode ? "" : "@scratch = internal addrspace(3) global [3 x i32] undef, align 4\n");
      for (unsigned tid = 0; tid < 4; tid++) {
         struct shared_bindings bindings = {.view = {12, 4, STELA_AIR_READ_WRITE}};
         struct stela_air_error error;
         nir_shader *nir = shared_translate(raw, &test_nir_options, &bindings, 12, &error);
         if (!nir) fprintf(stderr, "shared pointer PHI: %s\n", error.detail);
         CHECK(nir && nir->info.shared_size == 12 && bindings.shared == mode);
         specialize_loop(nir, tid);
         unsigned stores = 0;
         nir_foreach_function_impl(impl, nir) {
            CHECK(finite_effect_body(impl));
            nir_foreach_block(block, impl) {
               nir_foreach_instr(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
                  CHECK(in->intrinsic == nir_intrinsic_store_shared && tid < 3);
                  CHECK(nir_intrinsic_write_mask(in) == 1 && in->num_components == 1);
                  CHECK(in->src[0].ssa->bit_size == 32 && nir_src_is_const(in->src[0]) &&
                        nir_src_as_uint(in->src[0]) == 42);
                  CHECK(nir_src_is_const(in->src[1]) &&
                        nir_src_as_uint(in->src[1]) + nir_intrinsic_base(in) == 4 * tid);
                  stores++;
               }
            }
         }
         CHECK(stores == (tid < 3 ? 1 : 0));
         ralloc_free(nir);
      }
      LLVMDisposeMemoryBuffer(raw);
   }
   free(dynamic);
   shared_refusal("entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %a, label %b\n"
      "a:\nbr label %join\nb:\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(3) [@one, %a], [@two, %b]\nret void\n",
      "@one = internal addrspace(3) global [1 x i32] undef, align 4\n"
      "@two = internal addrspace(3) global [2 x i32] undef, align 4\n", STELA_AIR_MEMORY);
}

static void
shared_pointer_equality(void)
{
   const char *body =
      "entry:\n%trips = and i32 %tid, 3\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%p = phi ptr addrspace(3) [@scratch, %entry], [%step, %latch]\n"
      "%more = icmp ult i32 %i, %trips\nbr i1 %more, label %latch, label %exit\n"
      "latch:\n%step = getelementptr i32, ptr addrspace(3) %p, i32 1\n"
      "%next = add i32 %i, 1\nbr label %header\n"
      "exit:\n%eq = icmp eq ptr addrspace(3) %p, @scratch\n"
      "%ne = icmp ne ptr addrspace(3) %p, @scratch\n"
      "%a = zext i1 %eq to i32\n%b = zext i1 %ne to i32\n"
      "%b2 = shl i32 %b, 1\n%value = or i32 %a, %b2\n"
      "store i32 %value, ptr addrspace(1) %out, align 4\nret void\n";
   char *first = replace_once(body, "@scratch", "%scratch");
   char *second = replace_once(first, "@scratch", "%scratch"); free(first);
   char *dynamic = replace_once(second, "@scratch", "%scratch"); free(second);
   for (unsigned mode = 0; mode < 2; mode++) {
      LLVMMemoryBufferRef raw = shared_bitcode(mode ? dynamic : body, mode != 0,
         mode ? "" : "@scratch = internal addrspace(3) global [3 x i32] undef, align 4\n");
      for (unsigned tid = 0; tid < 4; tid++) {
         struct shared_bindings bindings = {.view = {12, 4, STELA_AIR_READ_WRITE}};
         struct stela_air_error error;
         nir_shader *nir = shared_translate(raw, &test_nir_options, &bindings, 12, &error);
         CHECK(nir);
         specialize_loop(nir, tid);
         const uint64_t address = 0x100000;
         const uint32_t value = tid ? 2 : 1;
         check_stores(nir, &address, &value, 1);
         check_executed_stores(nir, &address, &value, 1);
         ralloc_free(nir);
      }
      LLVMDisposeMemoryBuffer(raw);
   }
   free(dynamic);
   for (unsigned ne = 0; ne < 2; ne++) {
      char compare_body[192];
      snprintf(compare_body, sizeof(compare_body),
         "%%same = icmp %s ptr addrspace(3) @one, @two\nret void\n", ne ? "ne" : "eq");
      shared_refusal(compare_body,
         "@one = internal addrspace(3) global [3 x i32] undef, align 4\n"
         "@two = internal addrspace(3) global [3 x i32] undef, align 4\n", STELA_AIR_MEMORY);
   }
   shared_refusal("%minus = getelementptr i8, ptr addrspace(3) @scratch, i64 -1\n"
      "%ordered = icmp ult ptr addrspace(3) %minus, @scratch\nret void\n",
      "@scratch = internal addrspace(3) global [3 x i32] undef, align 4\n", STELA_AIR_TYPE);
}

static void
shared_global_dominance(void)
{
   const char *bodies[] = {
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\nstore i32 13, ptr addrspace(3) @s, align 4\nbr label %join\n"
      "right:\nstore i32 17, ptr addrspace(3) @s, align 4\nbr label %join\n"
      "join:\n%v = load i32, ptr addrspace(3) @s, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n",
      "entry:\nbr label %header\n"
      "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%c = icmp ult i32 %i, %tid\nbr i1 %c, label %latch, label %exit\n"
      "latch:\nstore i32 %i, ptr addrspace(3) @s, align 4\n"
      "%next = add i32 %i, 1\nbr label %header\n"
      "exit:\n%v = load i32, ptr addrspace(3) @s, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n",
   };
   for (unsigned body = 0; body < ARRAY_SIZE(bodies); body++) {
      LLVMMemoryBufferRef input = shared_bitcode(bodies[body], false,
         "@s = internal addrspace(3) global i32 undef, align 4\n");
      for (unsigned tid = 0; tid < 4; tid++) {
         struct shared_bindings bindings = {0};
         struct stela_air_error error;
         nir_shader *nir = shared_translate(input, &test_nir_options, &bindings, 4, &error);
         CHECK(nir && nir->info.shared_size == 4);
         /* First use is inside a branch/latch, with later sibling/exit uses.
          * Original validation checks dominance before any specialization. */
         nir_validate_shader(nir, "shared global branch/loop first-use dominance");
         specialize_loop(nir, tid);
         unsigned stores = 0, loads = 0, outputs = 0;
         nir_def *loaded = NULL;
         nir_foreach_function_impl(impl, nir) {
            nir_foreach_block(block, impl) {
               nir_foreach_instr(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
                  if (intr->intrinsic == nir_intrinsic_store_shared) {
                     unsigned expected = body ? stores : (tid ? 17 : 13);
                     CHECK(!loads && nir_src_is_const(intr->src[0]) &&
                           nir_src_as_uint(intr->src[0]) == expected &&
                           nir_src_is_const(intr->src[1]) && !nir_src_as_uint(intr->src[1]) &&
                           !nir_intrinsic_base(intr));
                     stores++;
                  } else if (intr->intrinsic == nir_intrinsic_load_shared) {
                     CHECK(nir_src_is_const(intr->src[0]) && !nir_src_as_uint(intr->src[0]) &&
                           !nir_intrinsic_base(intr));
                     loaded = &intr->def;
                     loads++;
                  } else if (intr->intrinsic == nir_intrinsic_store_global) {
                     CHECK(loaded && intr->src[0].ssa == loaded && nir_src_is_const(intr->src[1]) &&
                           nir_src_as_uint(intr->src[1]) == 0x100000);
                     outputs++;
                  }
               }
            }
         }
         /* Zero-trip retains an undefined shared read, never an invented
          * initialization. Nonzero paths retain exactly their original stores. */
         CHECK(stores == (body ? tid : 1) && loads == 1 && outputs == 1);
         ralloc_free(nir);
      }
      LLVMDisposeMemoryBuffer(input);
   }
}

static void
shared_contracts(void)
{
   const char *flags[] = {"i32 0, i32 5, i32 1", "i32 1, i32 5, i32 1",
      "i32 4, i32 5, i32 1", "i32 6, i32 5, i32 1", "i32 2, i32 0, i32 1",
      "i32 2, i32 2, i32 1", "i32 2, i32 4, i32 1", "i32 2, i32 5, i32 0",
      "i32 2, i32 5, i32 2", "i32 %tid, i32 5, i32 1"};
   for (unsigned i = 0; i < ARRAY_SIZE(flags); i++) {
      char body[256];
      snprintf(body, sizeof(body), "call void @air.wg.barrier(%s) convergent\nret void\n", flags[i]);
      shared_refusal(body, shared_declaration, STELA_AIR_INSTRUCTION);
   }
   shared_refusal("call void @air.wg.barrier(i64 2, i32 5, i32 1) convergent\nret void\n",
      "declare void @air.wg.barrier(i64, i32, i32) convergent\n", STELA_AIR_INSTRUCTION);
   shared_refusal("%v = call i32 @air.wg.barrier(i32 2, i32 5, i32 1) convergent\nret void\n",
      "declare i32 @air.wg.barrier(i32, i32, i32) convergent\n", STELA_AIR_INSTRUCTION);
   shared_refusal("call void @air.wg.barrier(i32 2, i32 5, i32 1)\nret void\n",
      shared_declaration, STELA_AIR_INSTRUCTION);
   shared_refusal("call void @air.wg.barrier(i32 2, i32 5, i32 1) convergent\nret void\n",
      "declare void @air.wg.barrier(i32, i32, i32)\n", STELA_AIR_INSTRUCTION);
   shared_refusal("call void @air.wg.barrier(i32 2, i32 5, i32 1) convergent\nret void\n",
      "define void @air.wg.barrier(i32 %a, i32 %b, i32 %c) convergent { ret void }\n", STELA_AIR_INSTRUCTION);
   shared_refusal("call void @air.wg.barrier(i32 2, i32 5, i32 1) convergent [\"deopt\"(i32 1)]\nret void\n",
      shared_declaration, STELA_AIR_INSTRUCTION);
   const char *globals[] = {
      "@s = internal addrspace(3) global i32 0, align 4\n",
      "@s = internal addrspace(3) global i32 poison, align 4\n",
      "@s = external addrspace(3) global i32\n",
      "@s = internal addrspace(3) constant i32 undef, align 4\n",
      "@s = internal addrspace(1) global i32 undef, align 4\n",
      "@s = internal addrspace(4) global i32 undef, align 4\n",
   };
   for (unsigned i = 0; i < ARRAY_SIZE(globals); i++)
      shared_refusal("ret void\n", globals[i], STELA_AIR_TARGET);
   shared_refusal("ret void\n", "@s = internal addrspace(3) global [4294967296 x i32] undef\n", STELA_AIR_LIMIT);
   shared_refusal("ret void\n", "@s = internal addrspace(3) global {i32,i32} undef\n", STELA_AIR_TYPE);
   shared_refusal("store atomic i32 1, ptr addrspace(3) @s monotonic, align 4\nret void\n",
      "@s = internal addrspace(3) global i32 undef, align 4\n", STELA_AIR_MEMORY);
   shared_refusal("store volatile i32 1, ptr addrspace(3) @s, align 4\nret void\n",
      "@s = internal addrspace(3) global i32 undef, align 4\n", STELA_AIR_MEMORY);
   shared_refusal("ret void\n", "@s = internal addrspace(3) global <vscale x 4 x i32> undef\n", STELA_AIR_VERIFY);
   LLVMMemoryBufferRef old_profile = stela_air_test_bitcode(
      "call void @air.wg.barrier(i32 2, i32 5, i32 1) convergent\nret void\n", shared_declaration);
   struct shared_bindings old_bindings = {0};
   struct stela_air_error old_error;
   CHECK(!shared_translate(old_profile, &test_nir_options, &old_bindings, 256, &old_error) &&
         old_error.kind == STELA_AIR_METADATA);
   LLVMDisposeMemoryBuffer(old_profile);

   /* Collective placement remains exact, even in source regions whose caller
    * must guarantee uniform participation. No frontend speculation/hoisting. */
   const char *placement[] = {
      "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
      "left:\ncall void @air.wg.barrier(i32 2, i32 5, i32 1) convergent\nbr label %join\n"
      "right:\nbr label %join\njoin:\nret void\n",
      "entry:\nbr label %header\nheader:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
      "%c = icmp ult i32 %i, 2\nbr i1 %c, label %latch, label %exit\n"
      "latch:\ncall void @air.wg.barrier(i32 2, i32 5, i32 1) convergent\n"
      "%next = add i32 %i, 1\nbr label %header\nexit:\nret void\n",
   };
   for (unsigned i = 0; i < ARRAY_SIZE(placement); i++) {
      LLVMMemoryBufferRef input = shared_bitcode(placement[i], false, shared_declaration);
      struct shared_bindings bindings = {0};
      struct stela_air_error error;
      nir_shader *nir = shared_translate(input, &test_nir_options, &bindings, 256, &error);
      CHECK(nir);
      unsigned barriers = 0;
      nir_foreach_function_impl(impl, nir) {
         nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
               if (instr->type != nir_instr_type_intrinsic ||
                   nir_instr_as_intrinsic(instr)->intrinsic != nir_intrinsic_barrier)
                  continue;
               CHECK(block->cf_node.parent->type == (i ? nir_cf_node_loop : nir_cf_node_if));
               barriers++;
            }
         }
      }
      CHECK(barriers == 1);
      ralloc_free(nir); LLVMDisposeMemoryBuffer(input);
   }
}

static const char *floating_body =
   "%index = zext i32 %tid to i64\n"
   "%address = getelementptr float, ptr addrspace(1) %out, i64 %index\n"
   "%a = load float, ptr addrspace(1) %address, align 4\n"
   "%b = uitofp i32 %tid to float\n"
   "%s = sitofp i32 %tid to float\n"
   "%sum = fadd float %a, %b\n"
   "%product = fmul float %sum, 1.25\n"
   "%difference = fsub float %s, %a\n"
   "%condition = fcmp olt float %a, 0.0\n"
   "%value = select i1 %condition, float %product, float %difference\n"
   "store float %value, ptr addrspace(1) %address, align 4\nret void\n";

static const char *float_predicates[] = {"false","oeq","ogt","oge","olt","ole","one","ord",
                                        "uno","ueq","ugt","uge","ult","ule","une","true"};

static char *
floating_comparison_body(void)
{
   char *body = calloc(1, 4096);
   CHECK(body);
   size_t used = (size_t)snprintf(body, 4096,
      "%%a = load float, ptr addrspace(1) %%out, align 4\n"
      "%%bp = getelementptr float, ptr addrspace(1) %%out, i32 1\n"
      "%%b = load float, ptr addrspace(1) %%bp, align 4\n");
   for (unsigned p = 0; p < ARRAY_SIZE(float_predicates); p++) {
      used += (size_t)snprintf(body + used, 4096 - used,
         "%%p%u = fcmp %s float %%a, %%b\n%%v%u = zext i1 %%p%u to i32\n"
         "%%s%u = shl i32 %%v%u, %u\n", p, float_predicates[p], p, p, p, p, p);
      if (p)
         used += (size_t)snprintf(body + used, 4096 - used,
            "%%m%u = or i32 %%m%u, %%s%u\n", p, p - 1, p);
      else
         used += (size_t)snprintf(body + used, 4096 - used, "%%m0 = or i32 0, %%s0\n");
      CHECK(used < 4096);
   }
   CHECK(snprintf(body + used, 4096 - used,
      "store i32 %%m15, ptr addrspace(1) %%out, align 4\nret void\n") > 0);
   return body;
}

static void
ieee_store(const char *body, uint32_t expected)
{
   constant_store_input(ieee_bitcode(stela_air_test_prefix, body), expected, 0x100000);
}

static const char *floating_loop_body =
   "entry:\n%count = add i32 %tid, 0\nbr label %header\n"
   "header:\n%i = phi i32 [0, %entry], [%next, %latch]\n"
   "%x = phi float [1.0, %entry], [%xnext, %latch]\n"
   "%v = phi <2 x float> [<float 1.0, float -0.0>, %entry], [%vnext, %latch]\n"
   "store float %x, ptr addrspace(1) %out, align 4\n"
   "%done = icmp uge i32 %i, %count\nbr i1 %done, label %exit, label %latch\n"
   "latch:\n%next = add i32 %i, 1\n%xnext = fadd float %x, 0.5\n"
   "%vnext = fadd <2 x float> %v, <float 0.5, float -0.0>\nbr label %header\n"
   "exit:\n%result = phi float [%x, %header]\n"
   "%v0 = extractelement <2 x float> %v, i32 0\n"
   "%p0 = getelementptr float, ptr addrspace(1) %out, i32 1\n"
   "store float %v0, ptr addrspace(1) %p0, align 4\n"
   "%v1 = extractelement <2 x float> %v, i32 1\n"
   "%p1 = getelementptr float, ptr addrspace(1) %out, i32 2\n"
   "store float %v1, ptr addrspace(1) %p1, align 4\n"
   "%p2 = getelementptr float, ptr addrspace(1) %out, i32 3\n"
   "store float %result, ptr addrspace(1) %p2, align 4\nret void\n";

static void
floating_loop_semantics(void)
{
   const uint32_t values[] = {0x3f800000, 0x3fc00000, 0x40000000, 0x40200000, 0x40400000};
   for (unsigned trips = 0; trips < ARRAY_SIZE(values); trips++) {
      LLVMMemoryBufferRef input = ieee_bitcode(stela_air_test_prefix, floating_loop_body);
      struct stela_air_error error;
      nir_shader *nir = translate(input, &test_nir_options, 1000, &error);
      CHECK(nir);
      LLVMDisposeMemoryBuffer(input);
      specialize_loop(nir, trips);
      uint64_t addresses[8];
      uint32_t expected[8];
      for (unsigned i = 0; i <= trips; i++) {
         addresses[i] = 0x100000;
         expected[i] = values[i];
      }
      addresses[trips + 1] = 0x100004;
      addresses[trips + 2] = 0x100008;
      addresses[trips + 3] = 0x10000c;
      expected[trips + 1] = expected[trips + 3] = values[trips];
      expected[trips + 2] = 0x80000000; /* Carried negative zero remains exact. */
      check_stores(nir, addresses, expected, trips + 4);
      ralloc_free(nir);
   }
}

static void
floating_backend_options(void)
{
   char *body = floating_comparison_body();
   LLVMMemoryBufferRef input = ieee_bitcode(stela_air_test_prefix, body);
   for (unsigned flags = 0; flags < 4; flags++) {
      const nir_shader_compiler_options options = {
         .has_fneo_fcmpu = (flags & 1) != 0,
         .has_ford_funord = (flags & 2) != 0,
      };
      struct stela_air_error error;
      nir_shader *nir = translate(input, &options, 256, &error);
      CHECK(nir);
      unsigned extended = 0, ordered = 0;
      nir_foreach_function_impl(impl, nir) {
         nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
               if (instr->type != nir_instr_type_alu)
                  continue;
               switch (nir_instr_as_alu(instr)->op) {
               case nir_op_fneo: case nir_op_fequ: case nir_op_fltu: case nir_op_fgeu:
                  extended++;
                  break;
               case nir_op_ford: case nir_op_funord:
                  ordered++;
                  break;
               default: break;
               }
            }
         }
      }
      CHECK(extended == ((flags & 1) ? 6 : 0));
      CHECK(ordered == ((flags & 2) ? 2 : 0));
      nir_validate_shader(nir, "AIR comparison compiler options");
      if (!flags) {
         /* Original ELK pass requires canonical comparisons. Exercise the
          * actual bool-width boundary that previously asserted on fneo. */
         CHECK(nir_lower_bool_to_int32(nir));
         nir_validate_shader(nir, "AIR canonical comparison bool lowering");
      }
      ralloc_free(nir);
   }
   LLVMDisposeMemoryBuffer(input);
   free(body);
}

static void
floating_semantics(void)
{
   /* Independent IEEE binary32 boundary results, expressed as exact bits.
    * There is no host decimal parse or approximate numerical comparison. */
   const struct {const char *op; uint32_t a, b, result;} arithmetic[] = {
      {"fadd",0x3f800000,0x33800000,0x3f800000},
      {"fadd",0x3f800000,0x34400000,0x3f800002},
      {"fadd",0x3f800001,0x33800000,0x3f800002},
      {"fadd",1,0,1}, {"fadd",0x007fffff,1,0x00800000},
      {"fsub",0x00800000,0x007fffff,1},
      {"fadd",0x80000000,0x80000000,0x80000000},
      {"fadd",0x80000000,0,0}, {"fsub",0,0,0},
      {"fsub",0x80000000,0,0x80000000},
      {"fmul",0x80000000,0x3f800000,0x80000000},
      {"fmul",0x80000000,0xbf800000,0},
      {"fmul",0x00800000,0x3f000000,0x00400000},
      {"fmul",1,0x3f000000,0}, {"fmul",3,0x3f000000,2},
      {"fmul",0x7f7fffff,0x40000000,0x7f800000},
      {"fmul",0xff7fffff,0x40000000,0xff800000},
      {"fmul",0x7f7fffff,0x3f800000,0x7f7fffff},
   };
   char body[2048];
   for (unsigned i = 0; i < ARRAY_SIZE(arithmetic); i++) {
      snprintf(body, sizeof(body),
         "%%a = bitcast i32 %u to float\n%%b = bitcast i32 %u to float\n"
         "%%v = %s float %%a, %%b\n%%bits = bitcast float %%v to i32\n"
         "store i32 %%bits, ptr addrspace(1) %%out, align 4\nret void\n",
         arithmetic[i].a, arithmetic[i].b, arithmetic[i].op);
      ieee_store(body, arithmetic[i].result);
   }
   const struct {const char *op; uint32_t input, result;} conversions[] = {
      {"sitofp",0,0}, {"sitofp",0xffffffff,0xbf800000},
      {"sitofp",0x80000000,0xcf000000}, {"sitofp",0x7fffffff,0x4f000000},
      {"uitofp",0xffffffff,0x4f800000}, {"uitofp",0x80000000,0x4f000000},
      {"sitofp",16777217,0x4b800000}, {"sitofp",16777219,0x4b800002},
      {"uitofp",16777217,0x4b800000}, {"uitofp",16777219,0x4b800002},
      {"sitofp",0xfeffffff,0xcb800000},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(conversions); i++) {
      snprintf(body, sizeof(body),
         "%%v = %s i32 %u to float\n%%bits = bitcast float %%v to i32\n"
         "store i32 %%bits, ptr addrspace(1) %%out, align 4\nret void\n",
         conversions[i].op, conversions[i].input);
      ieee_store(body, conversions[i].result);
   }
   /* Truth masks for all 16 predicates, in LLVM's documented predicate order.
    * Cases cover signed zeros, finite ordering, infinities and unordered NaN. */
   const struct {uint32_t a, b; uint16_t truth;} comparisons[] = {
      {0,0x80000000,0xaaaa}, {0x3f800000,0x40000000,0xf0f0},
      {0x40000000,0x3f800000,0xcccc}, {0x7fc12345,0x3f800000,0xff00},
      {0x7f800000,0xff800000,0xcccc}, {0x7f800000,0x7f800000,0xaaaa},
      {1,0,0xcccc},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(comparisons); i++) {
      for (unsigned p = 0; p < ARRAY_SIZE(float_predicates); p++) {
         snprintf(body, sizeof(body),
            "%%a = bitcast i32 %u to float\n%%b = bitcast i32 %u to float\n"
            "%%v = fcmp %s float %%a, %%b\n%%value = zext i1 %%v to i32\n"
            "store i32 %%value, ptr addrspace(1) %%out, align 4\nret void\n",
            comparisons[i].a, comparisons[i].b, float_predicates[p]);
         ieee_store(body, (comparisons[i].truth >> p) & 1);
         constant_store_options(ieee_bitcode(stela_air_test_prefix, body), &extended_compare_options,
            STELA_AIR_FP_IEEE_DEFAULT, (comparisons[i].truth >> p) & 1, 0x100000);
      }
   }
   /* Each vector lane has a different relation: unordered, less, greater,
    * equal signed zeros. Both option paths must retain per-lane semantics. */
   const uint16_t vector_truth[] = {0xff00, 0xf0f0, 0xcccc, 0xaaaa};
   for (unsigned p = 0; p < ARRAY_SIZE(float_predicates); p++) {
      for (unsigned lane = 0; lane < ARRAY_SIZE(vector_truth); lane++) {
         snprintf(body, sizeof(body),
            "%%a = bitcast <4 x i32> <i32 2143363909, i32 1065353216, i32 1073741824, i32 0> to <4 x float>\n"
            "%%b = bitcast <4 x i32> <i32 1065353216, i32 1073741824, i32 1065353216, i32 -2147483648> to <4 x float>\n"
            "%%v = fcmp %s <4 x float> %%a, %%b\n%%value = zext <4 x i1> %%v to <4 x i32>\n"
            "%%lane = extractelement <4 x i32> %%value, i32 %u\n"
            "store i32 %%lane, ptr addrspace(1) %%out, align 4\nret void\n", float_predicates[p], lane);
         ieee_store(body, (vector_truth[lane] >> p) & 1);
         constant_store_options(ieee_bitcode(stela_air_test_prefix, body), &extended_compare_options,
            STELA_AIR_FP_IEEE_DEFAULT, (vector_truth[lane] >> p) & 1, 0x100000);
      }
   }
   /* Exact memory/negation/select do not depend on the unqualified private AIR
    * denorm flag, and preserve NaN payload/sign and subnormal storage bits. */
   constant_store("store float -0.0, ptr addrspace(1) %out, align 4\nret void\n", 0x80000000, 0x100000);
   constant_store("store float 1.5, ptr addrspace(1) %out, align 4\nret void\n", 0x3fc00000, 0x100000);
   constant_store("store float 0x7FF82468A0000000, ptr addrspace(1) %out, align 4\nret void\n", 0x7fc12345, 0x100000);
   constant_store("store float 0xFFF82468A0000000, ptr addrspace(1) %out, align 4\nret void\n", 0xffc12345, 0x100000);
   const uint32_t storage[] = {0,0x80000000,1,0x80000001,0x7fc12345,0xffa12345,0x7f800000};
   for (unsigned i = 0; i < ARRAY_SIZE(storage); i++) {
      snprintf(body, sizeof(body),
         "%%a = bitcast i32 %u to float\n%%n = fneg float %%a\n"
         "%%v = select i1 true, float %%n, float 0.0\n"
         "store float %%v, ptr addrspace(1) %%out, align 4\nret void\n", storage[i]);
      constant_store(body, storage[i] ^ 0x80000000, 0x100000);
   }
   const uint32_t vector_expected[] = {0x3f800000,0x80000000,1,0x7f800000};
   for (unsigned channel = 0; channel < 4; channel++) {
      snprintf(body, sizeof(body),
         "%%a = bitcast <4 x i32> <i32 1065353216, i32 -2147483648, i32 1, i32 2139095039> to <4 x float>\n"
         "%%b = bitcast <4 x i32> <i32 864026624, i32 -2147483648, i32 0, i32 2139095039> to <4 x float>\n"
         "%%v = fadd <4 x float> %%a, %%b\n%%lane = extractelement <4 x float> %%v, i32 %u\n"
         "store float %%lane, ptr addrspace(1) %%out, align 4\nret void\n", channel);
      ieee_store(body, vector_expected[channel]);
   }
   for (unsigned tid = 0; tid < 2; tid++) {
      nir_shader *nir = translate_body(
         "entry:\n%c = icmp eq i32 %tid, 0\nbr i1 %c, label %left, label %right\n"
         "left:\n%a = bitcast i32 2143363909 to float\nbr label %join\n"
         "right:\n%b = bitcast i32 2147483649 to float\nbr label %join\n"
         "join:\n%v = phi float [%a, %left], [%b, %right]\n"
         "store float %v, ptr addrspace(1) %out, align 4\nret void\n");
      specialize_invocation(nir, tid);
      const uint64_t address = 0x100000;
      const uint32_t value = tid ? 0x80000001 : 0x7fc12345;
      check_stores(nir, &address, &value, 1);
      ralloc_free(nir);
   }
}

static void
floating_contracts(void)
{
   char body[512];
   const struct {const char *flags; unsigned control;} cases[] = {
      {"",nir_fp_no_fast_math},
      {"nnan",nir_fp_no_fast_math & ~nir_fp_preserve_nan},
      {"ninf",nir_fp_no_fast_math & ~nir_fp_preserve_inf},
      {"nsz",nir_fp_no_fast_math},
      {"contract",nir_fp_no_fast_math & ~nir_fp_no_contract},
      {"reassoc",nir_fp_no_fast_math & ~nir_fp_no_reassoc},
      {"arcp afn",nir_fp_no_fast_math},
      {"reassoc contract arcp afn",nir_fp_preserve_sz_inf_nan | nir_fp_no_transform},
      {"fast",nir_fp_preserve_signed_zero | nir_fp_no_transform},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      snprintf(body, sizeof(body),
         "%%a = load float, ptr addrspace(1) %%out, align 4\n"
         "%%v = fadd %s float %%a, 1.0\n"
         "store float %%v, ptr addrspace(1) %%out, align 4\nret void\n", cases[i].flags);
      LLVMMemoryBufferRef input = ieee_bitcode(stela_air_test_prefix, body);
      struct stela_air_error error;
      nir_shader *nir = translate(input, &test_nir_options, 100, &error);
      CHECK(nir && nir->info.float_controls_execution_mode ==
         (FLOAT_CONTROLS_DENORM_PRESERVE_FP32 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32));
      unsigned adds = 0;
      nir_foreach_function_impl(impl, nir) {
         nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
               if (instr->type == nir_instr_type_alu && nir_instr_as_alu(instr)->op == nir_op_fadd) {
                  CHECK(nir_instr_as_alu(instr)->fp_math_ctrl == cases[i].control);
                  adds++;
               }
            }
         }
      }
      CHECK(adds == 1);
      ralloc_free(nir);
      LLVMDisposeMemoryBuffer(input);
   }
   const char *body_add = "%v = fadd float 1.0, 2.0\nret void\n";
   const char *attributes[] = {"strictfp", "denormal_fpenv(preservesign)",
                              "\"denormal-fp-math\"=\"ieee\"", "\"rounding-math\"=\"true\""};
   for (unsigned i = 0; i < ARRAY_SIZE(attributes); i++) {
      char suffix[128];
      snprintf(suffix, sizeof(suffix), ") %s {", attributes[i]);
      char *prefix = replace_once(stela_air_test_prefix, ") {", suffix);
      LLVMMemoryBufferRef input = ieee_bitcode(prefix, body_add);
      struct stela_air_error error;
      CHECK(!translate(input, &test_nir_options, 100, &error) && error.kind == STELA_AIR_TYPE);
      LLVMDisposeMemoryBuffer(input);
      free(prefix);
   }
   const char *unsupported[] = {
      "%v = fdiv float 1.0, 2.0\nret void\n",
      "%v = frem float 1.0, 2.0\nret void\n",
      "%v = fptosi float 1.0 to i32\nret void\n",
      "%v = fptoui float 1.0 to i32\nret void\n",
   };
   for (unsigned i = 0; i < ARRAY_SIZE(unsupported); i++) {
      LLVMMemoryBufferRef input = ieee_bitcode(stela_air_test_prefix, unsupported[i]);
      struct stela_air_error error;
      CHECK(!translate(input, &test_nir_options, 100, &error) && error.kind == STELA_AIR_INSTRUCTION);
      LLVMDisposeMemoryBuffer(input);
   }
   LLVMMemoryBufferRef constrained = ieee_bitcode_extra(stela_air_test_prefix,
      "%v = call float @llvm.experimental.constrained.fadd.f32(float 1.0, float 2.0, "
      "metadata !\"round.tonearest\", metadata !\"fpexcept.ignore\")\nret void\n",
      "declare float @llvm.experimental.constrained.fadd.f32(float, float, metadata, metadata)\n");
   struct stela_air_error error;
   CHECK(!translate(constrained, &test_nir_options, 100, &error) && error.kind == STELA_AIR_INSTRUCTION);
   LLVMDisposeMemoryBuffer(constrained);
   expect_refusal("%v = fadd half 1.0, 2.0\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%v = fadd double 1.0, 2.0\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%v = bitcast i64 1 to double\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%v = bitcast <2 x i16> <i16 1, i16 2> to float\nret void\n", "", 100, STELA_AIR_TYPE);
}

static void
qualified_floating_semantics(void)
{
   const enum stela_air_fp_profile profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
   const struct {const char *op; uint32_t a, b, result;} arithmetic[] = {
      {"fadd",1,0,0}, {"fadd",0x007fffff,1,0},
      {"fsub",0x00800000,0x007fffff,0x00800000},
      {"fmul",0x00800000,0x3f000000,0},
      {"fmul",0x80800000,0x3f000000,0x80000000},
      {"fadd",0x80000001,0,0}, {"fsub",0x80000001,0,0x80000000},
      {"fmul",0x80000001,0x3f800000,0x80000000},
      {"fadd",0x3f800000,0x33800000,0x3f800000},
      {"fadd",0x3f800000,0x34400000,0x3f800002},
   };
   char body[1024];
   for (unsigned i = 0; i < ARRAY_SIZE(arithmetic); i++) {
      snprintf(body, sizeof(body),
         "%%a = bitcast i32 %u to float\n%%b = bitcast i32 %u to float\n"
         "%%v = %s float %%a, %%b\nstore float %%v, ptr addrspace(1) %%out, align 4\nret void\n",
         arithmetic[i].a, arithmetic[i].b, arithmetic[i].op);
      constant_store_profile(qualified_bitcode(body, ""), profile, arithmetic[i].result, 0x100000);
   }
   constant_store_profile(qualified_bitcode(
      "%a = bitcast i32 1 to float\n%v = fneg float %a\n"
      "store float %v, ptr addrspace(1) %out, align 4\nret void\n", ""), profile, 0x80000001, 0x100000);
   const struct {const char *name; uint32_t input, expected;} conversions[] = {
      {"s",0x80000000,0xcf000000}, {"u",0xffffffff,0x4f800000},
      {"s",16777217,0x4b800000}, {"u",16777219,0x4b800002},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(conversions); i++) {
      char declaration[128];
      snprintf(declaration, sizeof(declaration), "declare float @air.convert.f.f32.%s.i32(i32)\n", conversions[i].name);
      snprintf(body, sizeof(body),
         "%%v = call float @air.convert.f.f32.%s.i32(i32 %u)\n"
         "store float %%v, ptr addrspace(1) %%out, align 4\nret void\n", conversions[i].name, conversions[i].input);
      constant_store_profile(qualified_bitcode(body, declaration), profile, conversions[i].expected, 0x100000);
   }
   LLVMMemoryBufferRef input = qualified_bitcode(floating_body, "");
   struct stela_air_error error;
   nir_shader *nir = translate_profile(input, &test_nir_options, 100, profile, &error);
   CHECK(nir && nir->info.float_controls_execution_mode ==
      (FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32));
   ralloc_free(nir);
   CHECK(!translate(input, &test_nir_options, 100, &error) && error.kind == STELA_AIR_METADATA);
   CHECK(!translate_profile(input, &test_nir_options, 100, (enum stela_air_fp_profile)99, &error) &&
         error.kind == STELA_AIR_INPUT);
   LLVMDisposeMemoryBuffer(input);
   input = ieee_bitcode(stela_air_test_prefix, floating_body);
   CHECK(!translate_profile(input, &test_nir_options, 100, profile, &error) && error.kind == STELA_AIR_METADATA);
   LLVMDisposeMemoryBuffer(input);
   const char *metadata_variants[] = {
      "!llvm.ident = !{!11}\n!11 = !{!\"Apple metal version unknown\"}\n",
      "", /* A matching caller policy cannot replace missing provenance metadata. */
   };
   char *prefix = replace_once(stela_air_test_prefix, "air64_v28-apple-macosx26.7.0", "air64_v29-apple-macosx27.2.0");
   char *air = replace_once(stela_air_test_metadata, "i32 2, i32 8, i32 0", "i32 2, i32 9, i32 0");
   char *metadata = replace_once(air, "i32 4, i32 0, i32 0", "i32 4, i32 1, i32 0");
   for (unsigned i = 0; i < ARRAY_SIZE(metadata_variants); i++) {
      input = stela_air_test_custom_bitcode(prefix, floating_body, metadata, metadata_variants[i]);
      CHECK(!translate_profile(input, &test_nir_options, 100, profile, &error) && error.kind == STELA_AIR_METADATA);
      LLVMDisposeMemoryBuffer(input);
   }
   const char *ident = "!llvm.ident = !{!11}\n!11 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n";
   const char *compile_options[] = {"!air.compile_options = !{!8,!10}", "!air.compile_options = !{!9,!10}"};
   for (unsigned i = 0; i < ARRAY_SIZE(compile_options); i++) {
      char *changed = replace_once(metadata, "!air.compile_options = !{!8,!9,!10}", compile_options[i]);
      input = stela_air_test_custom_bitcode(prefix, floating_body, changed, ident);
      CHECK(!translate_profile(input, &test_nir_options, 100, profile, &error) && error.kind == STELA_AIR_METADATA);
      LLVMDisposeMemoryBuffer(input);
      free(changed);
   }
   input = stela_air_test_custom_bitcode(prefix, floating_body, air, ident); /* MSL 4.0. */
   CHECK(!translate_profile(input, &test_nir_options, 100, profile, &error) && error.kind == STELA_AIR_METADATA);
   LLVMDisposeMemoryBuffer(input);
   input = stela_air_test_bitcode(floating_body, ""); /* AIR 2.8. */
   CHECK(!translate_profile(input, &test_nir_options, 100, profile, &error) && error.kind == STELA_AIR_METADATA);
   LLVMDisposeMemoryBuffer(input);
   free(metadata);
   free(air);
   free(prefix);
   const char *bad_calls[][2] = {
      {"%v = call float @air.convert.f.f32.s.i32(i64 1)\nret void\n",
       "declare float @air.convert.f.f32.s.i32(i64)\n"},
      {"%v = call float @air.convert.f.f32.s.i32(i32 1)\nret void\n",
       "define float @air.convert.f.f32.s.i32(i32 %x) { ret float 0.0 }\n"},
      {"%v = call fastcc float @air.convert.f.f32.s.i32(i32 1)\nret void\n",
       "declare fastcc float @air.convert.f.f32.s.i32(i32)\n"},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(bad_calls); i++) {
      input = qualified_bitcode(bad_calls[i][0], bad_calls[i][1]);
      CHECK(!translate_profile(input, &test_nir_options, 100, profile, &error) && error.kind == STELA_AIR_TYPE);
      LLVMDisposeMemoryBuffer(input);
   }
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

#include "air_division_tests.h"

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
   binding_prelude_contract();
   effect_oracle_contract();
   integer_division_tests();
   conditional_semantics();
   loop_semantics();
   cfg_semantics();
   pointer_phi_semantics();
   pointer_equality_semantics();
   pointer_phi_authority_refusals();
   cfg_limits_and_refusals();
   floating_semantics();
   floating_loop_semantics();
   floating_backend_options();
   floating_contracts();
   qualified_floating_semantics();
   shared_semantics();
   shared_global_dominance();
   shared_pointer_phi_semantics();
   shared_pointer_equality();
   shared_contracts();
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
   expect_refusal("%v = fadd float 1.0, 2.0\nret void\n", "", 100, STELA_AIR_METADATA);
   expect_refusal("%v = load volatile i32, ptr addrspace(1) %out, align 4\nret void\n", "", 100, STELA_AIR_MEMORY);
   expect_refusal("%v = load atomic i32, ptr addrspace(1) %out monotonic, align 4\nret void\n", "", 100, STELA_AIR_MEMORY);
   expect_refusal("%v = freeze i32 poison\nret void\n", "", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("call void @helper()\nret void\n", "declare void @helper()\n", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("store i32 %later, ptr addrspace(1) %out, align 4\n%later = add i32 %tid, 1\nret void\n", "", 100, STELA_AIR_VERIFY);
   expect_refusal("ret void\n", "!air.function_constants = !{!3}\n", 100, STELA_AIR_METADATA);
   expect_refusal("%v = add i32 undef, 1\nret void\n", "", 100, STELA_AIR_INSTRUCTION);
   expect_refusal("%address = inttoptr i64 1048576 to ptr addrspace(1)\nret void\n", "", 100, STELA_AIR_TYPE);
   expect_refusal("%address = bitcast ptr addrspace(1) null to ptr addrspace(1)\nret void\n", "", 100, STELA_AIR_MEMORY);
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
   puts("AIR input, metadata, integer/GEP/conditional/FP32 effects and refusal tests passed");
}

#ifdef STELA_AIR_TEST_NAK
static void
nak_shared_codegen(bool dynamic)
{
   char extra[512];
   snprintf(extra, sizeof(extra), "%s%s", dynamic ? "" : shared_global_declaration, shared_declaration);
   char *body = NULL;
   if (dynamic) {
      char *first = replace_once(shared_body, "@scratch", "%scratch");
      body = replace_once(first, "@scratch", "%scratch");
      free(first);
   }
   LLVMMemoryBufferRef input = shared_bitcode(dynamic ? body : shared_body, dynamic, extra);
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      const struct nv_device_info dev = {.sm = stela_nvidia_sms[i], .max_warps_per_mp = 32};
      struct nak_compiler *compiler = nak_compiler_create(&dev);
      CHECK(compiler);
      struct shared_bindings bindings = {.view = {256,4,STELA_AIR_READ_WRITE}};
      struct stela_air_error error;
      nir_shader *nir = shared_translate(input, nak_nir_options(compiler), &bindings, 256, &error);
      CHECK(nir && bindings.devices == 1 && bindings.shared == (dynamic ? 1 : 0));
      check_shared_operations(nir, 1, 1, 1);
      nak_preprocess_nir(nir, compiler);
      struct nak_shader_bin *bin = nak_compile_shader(nir, true, compiler, 0, NULL, false);
      CHECK(bin && bin->code && bin->code_size && bin->info.cs.smem_size == 256 &&
            bin->info.num_control_barriers == 1);
      CHECK(bin->asm_str && strstr(bin->asm_str, "st.shared") &&
            strstr(bin->asm_str, "ld.shared") && strstr(bin->asm_str, "bar.sync"));
      printf("AIR shared-%s-workgroup64->LLVM->NIR->NAK SM%u: %u bytes, %u instructions, shared256, barriers1\n",
         dynamic ? "dynamic" : "static", stela_nvidia_sms[i], bin->code_size, bin->info.num_instrs);
      puts(bin->asm_str);
      nak_shader_bin_destroy(bin); ralloc_free(nir); nak_compiler_destroy(compiler);
   }
   LLVMDisposeMemoryBuffer(input);
   free(body);
}

static void
nak_target_name(char name[32], unsigned sm, const char *label)
{
   if (!strcmp(label, "integer"))
      snprintf(name, 32, "sm%u", sm);
   else
      snprintf(name, 32, "sm%u.%s", sm, label);
}

static void
nak_codegen(const char *body, const char *label, bool ieee)
{
   char target[32];
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      nak_target_name(target, stela_nvidia_sms[i], label);
      record_expect(target, NULL);
   }
   LLVMMemoryBufferRef input = ieee ? ieee_bitcode(stela_air_test_prefix, body) :
                                    stela_air_test_bitcode(body, "");
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      const unsigned sm = stela_nvidia_sms[i];
      const struct nv_device_info dev = {.sm = sm, .max_warps_per_mp = 32};
      struct nak_compiler *compiler = nak_compiler_create(&dev);
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
      CHECK(bin->info.sm == sm && bin->info.stage == MESA_SHADER_COMPUTE);
      nak_target_name(target, sm, label);
      const uint32_t workgroup[] = {32, 1, 1};
      record_compiled(target, bin->code_size);
      record_object("facts");
      record_str("entry", "kernel");
      record_blake3("input_blake3", LLVMGetBufferStart(input), LLVMGetBufferSize(input));
      record_blake3("code_blake3", bin->code, bin->code_size);
      record_uints("workgroup", workgroup, ARRAY_SIZE(workgroup));
      record_uint("buffer_index", 7);
      record_uint("fixture_va", 0x100000);
      record_end();
      printf("AIR %s->LLVM->NIR->NAK SM%u: %u bytes, %u instructions\n", label, sm, bin->code_size, bin->info.num_instrs);
      if (bin->asm_str)
         puts(bin->asm_str);
      nak_shader_bin_destroy(bin);
      ralloc_free(nir);
      nak_compiler_destroy(compiler);
   }
   LLVMDisposeMemoryBuffer(input);
}
#endif

static bool
inspect_entry(const struct stela_air_inspection *info, const struct stela_air_entry *entry, void *data)
{
   unsigned *count = data;
   CHECK(info->air_minor == 8 && info->language_major == 4 && info->language_minor == 0);
   CHECK(info->denorms_disable && info->fast_math && info->target_bytes == strlen(info->target));
   CHECK(entry->name_bytes == 6 && !memcmp(entry->name, "kernel", 6) && entry->argument_count == 2);
   CHECK(entry->reflection_complete);
   const struct stela_air_argument_info *arg = &entry->arguments[1];
   CHECK(entry->arguments[0].kind == 2 && entry->arguments[0].components == 1);
   CHECK(arg->kind == 1 && arg->buffer.argument == 1 && arg->buffer.index == 7 &&
      arg->buffer.address_space == 1 && arg->buffer.access == STELA_AIR_READ_WRITE &&
      arg->buffer.type_size == 4 && arg->buffer.type_alignment == 4 && arg->plain_buffer_type);
   CHECK(arg->primitive == STELA_AIR_UINT && arg->type_components == 1 &&
      arg->name_bytes == 6 && !memcmp(arg->name, "output", 6) &&
      arg->type_name_bytes == 4 && !memcmp(arg->type_name, "uint", 4));
   (*count)++;
   return true;
}

struct reflection_expectation {
   bool complete, used;
   enum stela_air_primitive primitive;
   unsigned components;
};
static bool
inspect_reflection(const struct stela_air_inspection *info, const struct stela_air_entry *entry, void *data)
{
   (void)info;
   const struct reflection_expectation *expected = data;
   CHECK(entry->argument_count == 2);
   const struct stela_air_argument_info *arg = &entry->arguments[1];
   CHECK(entry->reflection_complete == expected->complete && arg->used == expected->used &&
         arg->primitive == expected->primitive && arg->type_components == expected->components);
   return true;
}
static void
reflection_inspection_case(const char *prefix, const char *body, const char *metadata, const char *extra,
                           bool complete, bool used, enum stela_air_primitive primitive, unsigned components)
{
   struct stela_air_error error;
   struct reflection_expectation expected = {complete, used, primitive, components};
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(prefix, body, metadata, extra);
   CHECK(stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8,
                          inspect_reflection, &expected, &error));
   CHECK(error.kind == STELA_AIR_OK);
   LLVMDisposeMemoryBuffer(input);
}
static void
reflection_inspection_tests(void)
{
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, stela_air_test_metadata,
                              "", true, true, STELA_AIR_UINT, 1);
   const char *scalars[] = {"char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "float"};
   const unsigned scalar_sizes[] = {1,1,2,2,4,4,8,8,4};
   for (unsigned scalar = 0; scalar < 9; scalar++) {
      for (unsigned components = 1; components <= 4; components++) {
         char reflected[96], layout[128];
         if (components == 1)
            snprintf(reflected, sizeof(reflected), "!\"%s\", !\"air.arg_name\", !\"output\"", scalars[scalar]);
         else
            snprintf(reflected, sizeof(reflected), "!\"%s%u\", !\"air.arg_name\", !\"output\"", scalars[scalar], components);
         unsigned extent = scalar_sizes[scalar] * (components == 3 ? 4 : components);
         snprintf(layout, sizeof(layout), "!\"air.arg_type_size\", i32 %u, !\"air.arg_type_align_size\", i32 %u", extent, extent);
         char *typed = replace_once(stela_air_test_metadata, "!\"uint\", !\"air.arg_name\", !\"output\"", reflected);
         char *sized = replace_once(typed, "!\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4", layout);
         reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, sized,
                                    "", true, true, STELA_AIR_CHAR + scalar, components);
         free(typed); free(sized);
      }
   }
   /* AIR use facts are preserved even for a currently unused formal parameter. */
   reflection_inspection_case(stela_air_test_prefix, "ret void\n", stela_air_test_metadata,
                              "", true, false, STELA_AIR_UINT, 1);
   char *metadata = replace_once(stela_air_test_metadata, "!\"uint\", !\"air.arg_name\", !\"output\"",
                                 "!\"UnqualifiedStructure\", !\"air.arg_name\", !\"output\"");
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, metadata,
                              "", false, true, STELA_AIR_PRIMITIVE_UNKNOWN, 0);
   free(metadata);
   metadata = replace_once(stela_air_test_metadata, ", !\"air.arg_name\", !\"output\"", "");
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, metadata,
                              "", false, true, STELA_AIR_UINT, 1);
   free(metadata);
   metadata = replace_once(stela_air_test_metadata, "!\"output\"", "!\"out\\00put\"");
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, metadata,
                              "", false, true, STELA_AIR_UINT, 1);
   free(metadata);
   metadata = replace_once(stela_air_test_metadata, "!\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,", "");
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, metadata,
                              "", false, true, STELA_AIR_UINT, 1);
   free(metadata);
   /* MSL vector3 has four lanes of storage/alignment; no packed-layout guess. */
   metadata = replace_once(stela_air_test_metadata, "!\"uint\", !\"air.arg_name\", !\"output\"",
                                 "!\"uint3\", !\"air.arg_name\", !\"output\"");
   char *sized = replace_once(metadata, "!\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4",
                                       "!\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 16");
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, sized,
                              "", true, true, STELA_AIR_UINT, 3);
   char *packed = replace_once(sized, "!\"air.arg_type_size\", i32 16", "!\"air.arg_type_size\", i32 12");
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, packed,
                              "", false, true, STELA_AIR_UINT, 3);
   free(metadata); free(sized); free(packed);
   char *prefix = replace_once(stela_air_test_prefix, " %out)", " \"unknown-reflection\" %out)");
   reflection_inspection_case(prefix, stela_air_test_store_body, stela_air_test_metadata,
                              "", false, true, STELA_AIR_UINT, 1);
   free(prefix);
   prefix = replace_once(stela_air_test_prefix, ") {", ") #0 {");
   reflection_inspection_case(prefix, stela_air_test_store_body, stela_air_test_metadata,
                              "attributes #0 = { \"unqualified-annotation\"=\"text\" }\n", false, true, STELA_AIR_UINT, 1);
   free(prefix);
   prefix = replace_once(stela_air_test_prefix, ") {", ") !custom !11 {");
   reflection_inspection_case(prefix, stela_air_test_store_body, stela_air_test_metadata,
                              "!11 = !{!\"annotation\"}\n", false, true, STELA_AIR_UINT, 1);
   free(prefix);
   reflection_inspection_case(stela_air_test_prefix, stela_air_test_store_body, stela_air_test_metadata,
                              "@unqualified = constant i32 1\n", false, true, STELA_AIR_UINT, 1);
}

static void
shared_reflection_case(const char *extra, bool complete)
{
   LLVMMemoryBufferRef input = shared_bitcode("ret void\n", false, extra);
   struct reflection_expectation expected = {complete, false, STELA_AIR_UINT, 1};
   struct stela_air_error error;
   CHECK(stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8,
                          inspect_reflection, &expected, &error));
   /* A conservative absent-reflection result must not leak its local failure
    * into otherwise successful original LLVM/module inspection. */
   CHECK(error.kind == STELA_AIR_OK && !error.detail[0]);
   if (complete) {
      struct shared_bindings bindings = {0};
      nir_shader *nir = shared_translate(input, &test_nir_options, &bindings, 0, &error);
      CHECK(nir && !nir->info.shared_size && !bindings.shared);
      check_shared_operations(nir, 0, 0, 0);
      ralloc_free(nir);
   }
   LLVMDisposeMemoryBuffer(input);
}

static void
shared_reflection_tests(void)
{
   const char *good[] = {
      "@s = internal addrspace(3) global i8 undef, align 1\n",
      "@s = internal addrspace(3) global <3 x i16> undef, align 8\n",
      "@s = internal addrspace(3) global [3 x [4 x <4 x float>]] undef, align 16\n",
      "@s = internal unnamed_addr addrspace(3) global [32 x i32] undef, align 4\n",
      "@s = internal addrspace(3) global i64 undef\n", /* Original ABI alignment. */
   };
   for (unsigned i = 0; i < ARRAY_SIZE(good); i++)
      shared_reflection_case(good[i], true);
   const char *bad[] = {
      "@s = internal addrspace(1) global i32 undef, align 4\n",
      "@s = internal addrspace(3) constant i32 undef, align 4\n",
      "@s = external addrspace(3) global i32\n",
      "@s = internal thread_local addrspace(3) global i32 undef, align 4\n",
      "@s = internal addrspace(3) externally_initialized global i32 undef, align 4\n",
      "@s = internal addrspace(3) global i32 0, align 4\n",
      "@s = internal addrspace(3) global i32 poison, align 4\n",
      "@s = internal addrspace(3) global i32 undef, section \"unqualified\", align 4\n",
      "@s = internal addrspace(3) global i32 undef, align 4, !custom !77\n!77 = !{!\"unqualified\"}\n",
      "@s = internal addrspace(3) global [0 x i32] undef, align 4\n",
      "@s = internal addrspace(3) global [4294967296 x i32] undef, align 4\n",
      "@s = internal addrspace(3) global {i32,i32} undef, align 4\n",
      "@s = internal addrspace(3) global half undef, align 2\n",
      "@s = internal addrspace(3) global i1 undef, align 1\n",
      "@s = internal addrspace(3) global <8 x i32> undef, align 32\n",
   };
   for (unsigned i = 0; i < ARRAY_SIZE(bad); i++)
      shared_reflection_case(bad[i], false);
   shared_refusal("ret void\n", bad[8], STELA_AIR_TARGET);
   /* Recursion/count are bounded before target-layout size/alignment queries. */
   char nested[1024] = "@s = internal addrspace(3) global ";
   for (unsigned i = 0; i < 33; i++) strcat(nested, "[1 x ");
   strcat(nested, "i32");
   for (unsigned i = 0; i < 33; i++) strcat(nested, "]");
   strcat(nested, " undef, align 4\n");
   shared_reflection_case(nested, false);
   shared_refusal("ret void\n", nested, STELA_AIR_LIMIT);
   char globals[16384] = {0};
   size_t used = 0;
   for (unsigned i = 0; i <= AIR_MAX_ARGUMENTS; i++) {
      int n = snprintf(globals + used, sizeof(globals) - used,
                       "@s%u = internal addrspace(3) global i32 undef, align 4\n", i);
      CHECK(n > 0 && (size_t)n < sizeof(globals) - used); used += (size_t)n;
   }
   shared_reflection_case(globals, false);
   shared_refusal("ret void\n", globals, STELA_AIR_LIMIT);
   /* Old AIR2.8 unused shared globals still allocate nothing in the executable
    * path; they cannot gain a new qualified reflection profile by this change. */
   reflection_inspection_case(stela_air_test_prefix, "ret void\n", stela_air_test_metadata,
                              good[3], false, false, STELA_AIR_UINT, 1);
   LLVMMemoryBufferRef input = stela_air_test_bitcode("ret void\n", good[3]);
   struct shared_bindings bindings = {0}; struct stela_air_error error;
   nir_shader *nir = shared_translate(input, &test_nir_options, &bindings, 0, &error);
   CHECK(nir && !nir->info.shared_size); ralloc_free(nir); LLVMDisposeMemoryBuffer(input);
   puts("AIR static-shared reflection, observational diagnostics, bounds and unused-allocation tests passed");
}

static void
inspection_tests(void)
{
   struct stela_air_error error;
   unsigned calls = 0;
   LLVMMemoryBufferRef input = stela_air_test_bitcode(stela_air_test_store_body, "");
   CHECK(stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8, inspect_entry, &calls, &error));
   CHECK(calls == 1 && error.kind == STELA_AIR_OK);
   CHECK(!stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 0, inspect_entry, &calls, &error));
   CHECK(error.kind == STELA_AIR_INPUT && calls == 1);
   LLVMDisposeMemoryBuffer(input);
   char *metadata = replace_once(stela_air_test_metadata, "!air.kernel = !{!2}", "!air.kernel = !{!2, !2}");
   input = stela_air_test_custom_bitcode(stela_air_test_prefix, stela_air_test_store_body, metadata, "");
   calls = 0;
   CHECK(!stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8, inspect_entry, &calls, &error));
   CHECK(error.kind == STELA_AIR_METADATA && calls == 0); /* No partial manifest. */
   LLVMDisposeMemoryBuffer(input); free(metadata);
   metadata = replace_once(stela_air_test_metadata, "i32 7, i32 1", "i32 128, i32 1");
   input = stela_air_test_custom_bitcode(stela_air_test_prefix, stela_air_test_store_body, metadata, "");
   CHECK(!stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8, inspect_entry, &calls, &error));
   CHECK(error.kind == STELA_AIR_METADATA && calls == 0);
   LLVMDisposeMemoryBuffer(input); free(metadata);
   /* Preserve the original integer shape rule: a scalar or uint3 builtin,
    * never a one-lane LLVM vector masquerading as a scalar argument. */
   char *prefix = replace_once(stela_air_test_prefix, "i32 %tid", "<1 x i32> %tid");
   input = stela_air_test_custom_bitcode(prefix, "ret void\n", stela_air_test_metadata, "");
   CHECK(!stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8, inspect_entry, &calls, &error));
   CHECK(error.kind == STELA_AIR_ARGUMENT && calls == 0);
   nir_shader *invalid_shape = translate(input, &test_nir_options, 100, &error);
   CHECK(!invalid_shape && error.kind == STELA_AIR_ARGUMENT);
   LLVMDisposeMemoryBuffer(input); free(prefix);
   /* Inspection is NOT a promise that a body/resource/pipeline can compile. */
   input = stela_air_test_bitcode("call void @unknown()\nret void\n", "declare void @unknown()\n");
   CHECK(stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 8, inspect_entry, &calls, &error));
   CHECK(calls == 1);
   nir_shader *nir = translate(input, &test_nir_options, 100, &error);
   CHECK(!nir && error.kind == STELA_AIR_INSTRUCTION);
   LLVMDisposeMemoryBuffer(input);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   tests();
   inspection_tests();
   reflection_inspection_tests();
   shared_reflection_tests();
#ifdef STELA_AIR_TEST_NAK
   nak_codegen(stela_air_test_store_body, "integer", false);
   nak_codegen(conditional_body, "nested-conditional", false);
   nak_codegen(loop_body, "natural-loop", false);
   nak_codegen(floating_body, "ieee-fp32", true);
   nak_codegen(floating_loop_body, "ieee-fp32-natural-loop", true);
   char *comparisons = floating_comparison_body();
   nak_codegen(comparisons, "ieee-fp32-comparisons", true);
   free(comparisons);
   nak_shared_codegen(false);
   nak_shared_codegen(true);
#endif
   glsl_type_singleton_decref();
   return 0;
}
