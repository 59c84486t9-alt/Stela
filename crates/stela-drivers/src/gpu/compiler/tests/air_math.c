/* SPDX-License-Identifier: MIT */
/* AIR and LLVM math, conversions, half arithmetic, derivatives and discard.
 * Original LLVM IR fixtures in the call forms air_math.c documents; no Apple
 * output. Exact results are checked by folding each call's NIR. */
#include "../metal_abi.h"
#include "compiler/air_to_nir.h"
#include "air_test_fixture.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef NDEBUG
#error "These tests require active assertions"
#endif

static const nir_shader_compiler_options nir_options = {.max_unroll_iterations = 32};

static const char *module =
   "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
   "target triple = \"air64_v29-apple-macosx27.2.0\"\n";

static const char *versions =
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

static const char *kernel_metadata =
   "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n";

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};

static nir_shader *
kernel(const char *declarations, const char *type, const char *expression,
       struct stela_air_error *error)
{
   char body[2048], all[2048];
   snprintf(body, sizeof(body),
            "define void @kernel(ptr addrspace(1) %%out) {\n%%r = %s\n"
            "store %s %%r, ptr addrspace(1) %%out, align 2\nret void\n}\n",
            expression, type);
   snprintf(all, sizeof(all), "%s%s", kernel_metadata, versions);
   LLVMMemoryBufferRef input =
      stela_air_test_custom_bitcode(module, declarations, body, all);
   const struct stela_air_options o = {
      .workgroup_size = {1, 1, 1}, .max_instructions = 10000,
      .bind_buffer = stela_metal_bind_buffer, .binding_data = &primary,
      .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41,
   };
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

/* The bits the kernel stores for `expression`, a call of `declaration`. */
static uint64_t
fold(const char *declaration, const char *type, const char *expression)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(declaration, type, expression, &error);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", expression, error.kind, error.detail);
   assert(shader);
   while (nir_opt_constant_folding(shader))
      ;
   nir_intrinsic_instr *store = NULL;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_store_global)
               store = nir_instr_as_intrinsic(instr);
         }
      }
   }
   if (!store || !nir_src_is_const(store->src[0]))
      nir_print_shader(shader, stderr);
   assert(store && nir_src_is_const(store->src[0]));
   uint64_t bits = nir_src_as_uint(store->src[0]);
   ralloc_free(shader);
   return bits;
}

static uint32_t
f32(float value)
{
   uint32_t bits;
   memcpy(&bits, &value, sizeof(bits));
   return bits;
}

#define CHECK_FOLD(declaration, type, expression, expected)                                        \
   do {                                                                                            \
      uint64_t folded = fold(declaration, type, expression);                                       \
      if (folded != (uint64_t)(expected))                                                          \
         fprintf(stderr, "%s: %#llx, expected %#llx\n", expression, (unsigned long long)folded,     \
                 (unsigned long long)(expected));                                                  \
      assert(folded == (uint64_t)(expected));                                                      \
   } while (0)

static void
floating_functions_follow_metal(void)
{
   CHECK_FOLD("declare float @air.round.f32(float)\n", "float", "call float @air.round.f32(float 2.5)",
              f32(3.0f));
   CHECK_FOLD("declare float @llvm.round.f32(float)\n", "float",
              "call float @llvm.round.f32(float -0.5)", f32(-1.0f));
   CHECK_FOLD("declare float @air.fract.f32(float)\n", "float", "call float @air.fract.f32(float -0.25)",
              f32(0.75f));
   CHECK_FOLD("declare float @air.fast_fmod.f32(float, float)\n", "float",
              "call float @air.fast_fmod.f32(float -7.0, float 3.0)", f32(-1.0f));
   CHECK_FOLD("", "float", "frem fast float -7.0, 3.0", f32(-1.0f));
   CHECK_FOLD("declare float @air.copysign.f32(float, float)\n", "float",
              "call float @air.copysign.f32(float 2.0, float -0.0)", f32(-2.0f));
   CHECK_FOLD("declare float @air.fmedian3.f32(float, float, float)\n", "float",
              "call float @air.fmedian3.f32(float 3.0, float 1.0, float 2.0)", f32(2.0f));
   CHECK_FOLD("declare float @air.fast_clamp.f32(float, float, float)\n", "float",
              "call float @air.fast_clamp.f32(float 5.0, float 0.0, float 1.0)", f32(1.0f));
   CHECK_FOLD("declare float @air.mix.f32(float, float, float)\n", "float",
              "call float @air.mix.f32(float 0.0, float 10.0, float 0.25)", f32(2.5f));
   CHECK_FOLD("declare float @air.dot.v3f32(<3 x float>, <3 x float>)\n", "float",
              "call float @air.dot.v3f32(<3 x float> <float 1.0, float 2.0, float 3.0>,"
              " <3 x float> <float 4.0, float 5.0, float 6.0>)",
              f32(32.0f));
   CHECK_FOLD("declare float @air.fast_length.v2f32(<2 x float>)\n", "float",
              "call float @air.fast_length.v2f32(<2 x float> <float 3.0, float 4.0>)", f32(5.0f));
   CHECK_FOLD("declare float @llvm.fma.f32(float, float, float)\n", "float",
              "call float @llvm.fma.f32(float 2.0, float 3.0, float 1.0)", f32(7.0f));
   CHECK_FOLD("", "float", "fdiv fast float 1.0, 4.0", f32(0.25f));
   CHECK_FOLD("declare float @llvm.sqrt.f32(float)\n", "float",
              "call afn float @llvm.sqrt.f32(float 16.0)", f32(4.0f));
   /* Half precision, with transcendental functions evaluated in float. */
   CHECK_FOLD("", "half", "fadd half 0xH3C00, 0xH3C00", 0x4000);
   CHECK_FOLD("", "half", "fneg half 0xH3C00", 0xbc00);
   CHECK_FOLD("declare half @air.sqrt.f16(half)\n", "half", "call half @air.sqrt.f16(half 0xH4400)",
              0x4000);
}

static void
integer_functions_follow_metal(void)
{
   CHECK_FOLD("declare i32 @air.clz.i32(i32, i1)\n", "i32", "call i32 @air.clz.i32(i32 1, i1 false)", 31);
   CHECK_FOLD("declare i16 @air.clz.i16(i16, i1)\n", "i16", "call i16 @air.clz.i16(i16 1, i1 false)", 15);
   CHECK_FOLD("declare i32 @air.ctz.i32(i32, i1)\n", "i32", "call i32 @air.ctz.i32(i32 0, i1 false)", 32);
   CHECK_FOLD("declare i64 @air.ctz.i64(i64, i1)\n", "i64",
              "call i64 @air.ctz.i64(i64 4294967296, i1 false)", 32);
   CHECK_FOLD("declare i32 @air.popcount.i32(i32)\n", "i32", "call i32 @air.popcount.i32(i32 255)", 8);
   CHECK_FOLD("declare i32 @air.reverse_bits.i32(i32)\n", "i32",
              "call i32 @air.reverse_bits.i32(i32 1)", 0x80000000u);
   CHECK_FOLD("declare i16 @air.reverse_bits.i16(i16)\n", "i16",
              "call i16 @air.reverse_bits.i16(i16 1)", 0x8000);
   CHECK_FOLD("declare i32 @air.max.s.i32(i32, i32)\n", "i32",
              "call i32 @air.max.s.i32(i32 -1, i32 1)", 1);
   CHECK_FOLD("declare i32 @air.max.u.i32(i32, i32)\n", "i32",
              "call i32 @air.max.u.i32(i32 -1, i32 1)", 0xffffffffu);
   CHECK_FOLD("declare i32 @air.mul_hi.u.i32(i32, i32)\n", "i32",
              "call i32 @air.mul_hi.u.i32(i32 -1, i32 2)", 1);
   CHECK_FOLD("declare i8 @air.add_sat.u.i8(i8, i8)\n", "i8",
              "call i8 @air.add_sat.u.i8(i8 -6, i8 10)", 0xff);
   CHECK_FOLD("declare i32 @llvm.abs.i32(i32, i1)\n", "i32",
              "call i32 @llvm.abs.i32(i32 -5, i1 false)", 5);
}

static void
conversions_follow_their_names(void)
{
   CHECK_FOLD("declare i32 @air.convert.s.i32.f.f32(float)\n", "i32",
              "call i32 @air.convert.s.i32.f.f32(float -2.75)", 0xfffffffeu);
   CHECK_FOLD("declare half @air.convert.f.f16.f.f32(float)\n", "half",
              "call half @air.convert.f.f16.f.f32(float 1.5)", 0x3e00);
   CHECK_FOLD("declare float @air.convert.f.f32.u.i16(i16)\n", "float",
              "call float @air.convert.f.f32.u.i16(i16 -1)", f32(65535.0f));
   CHECK_FOLD("declare i32 @air.convert.s.i32.s.i16(i16)\n", "i32",
              "call i32 @air.convert.s.i32.s.i16(i16 -2)", 0xfffffffeu);
   CHECK_FOLD("declare i32 @air.convert.u.i32.u.i16(i16)\n", "i32",
              "call i32 @air.convert.u.i32.u.i16(i16 -2)", 65534);
   CHECK_FOLD("", "half", "fptrunc float 2.0 to half", 0x4000);
   CHECK_FOLD("", "float", "fpext half 0xH3C00 to float", f32(1.0f));
   CHECK_FOLD("", "i16", "fptosi float -3.5 to i16", 0xfffd);
   CHECK_FOLD("", "float", "uitofp i8 -56 to float", f32(200.0f));
   CHECK_FOLD("", "float", "sitofp i1 true to float", f32(-1.0f));
   CHECK_FOLD("", "i32", "bitcast <2 x half> <half 0xH3C00, half 0xH4000> to i32", 0x40003c00u);
}

static void
refuses_misnamed_and_misplaced_functions(void)
{
   const struct {
      const char *declaration, *type, *expression;
      enum stela_air_error_kind kind;
   } cases[] = {
      /* Derivatives need a fragment function. */
      {"declare float @air.dfdx.f32(float)\n", "float", "call float @air.dfdx.f32(float 1.0)",
       STELA_AIR_INSTRUCTION},
      /* A conversion's name spells its types. */
      {"declare i16 @air.convert.s.i32.f.f32(float)\n", "i16",
       "call i16 @air.convert.s.i32.f.f32(float 1.0)", STELA_AIR_INSTRUCTION},
      {"declare float @air.convert.s.f32.f.f32(float)\n", "float",
       "call float @air.convert.s.f32.f.f32(float 1.0)", STELA_AIR_INSTRUCTION},
      /* NIR's accuracy is Metal's fast accuracy, not its precise one. */
      {"declare float @air.sqrt.f32(float)\n", "float", "call float @air.sqrt.f32(float 1.0)",
       STELA_AIR_INSTRUCTION},
      {"declare float @llvm.sqrt.f32(float)\n", "float", "call float @llvm.sqrt.f32(float 1.0)",
       STELA_AIR_INSTRUCTION},
      {"", "float", "fdiv float 1.0, 4.0", STELA_AIR_INSTRUCTION},
      {"", "float", "frem nnan float 1.0, 4.0", STELA_AIR_INSTRUCTION},
      /* A function's name spells its overload. */
      {"declare float @air.sqrt.f16(float)\n", "float", "call float @air.sqrt.f16(float 1.0)",
       STELA_AIR_INSTRUCTION},
      {"declare float @air.fast_frobnicate.f32(float)\n", "float",
       "call float @air.fast_frobnicate.f32(float 1.0)", STELA_AIR_INSTRUCTION},
      {"declare float @air.dot.v2f32(<2 x float>, <2 x float>)\n", "float",
       "call float @air.dot.v2f32(<2 x float> zeroinitializer, <2 x float> <float 1.0, float 2.0>)",
       STELA_AIR_OK},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      struct stela_air_error error = {0};
      nir_shader *shader = kernel(cases[i].declaration, cases[i].type, cases[i].expression, &error);
      if ((shader != NULL) != (cases[i].kind == STELA_AIR_OK) || error.kind != cases[i].kind)
         fprintf(stderr, "case %u: %u %s\n", i, error.kind, error.detail);
      assert((shader != NULL) == (cases[i].kind == STELA_AIR_OK) && error.kind == cases[i].kind);
      ralloc_free(shader);
   }
}

/* Only shaders with half arithmetic declare half float controls. */
static void
half_declares_its_float_controls(void)
{
   const unsigned single = FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32;
   const unsigned half = FLOAT_CONTROLS_DENORM_PRESERVE_FP16 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP16;
   const struct {
      const char *type, *expression;
      unsigned controls;
   } cases[] = {
      {"float", "fadd float 1.0, 2.0", single},
      {"half", "fadd half 0xH3C00, 0xH3C00", single | half},
      {"float", "fpext half 0xH3C00 to float", single | half},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      struct stela_air_error error = {0};
      nir_shader *shader = kernel("", cases[i].type, cases[i].expression, &error);
      assert(shader && shader->info.float_controls_execution_mode == cases[i].controls);
      ralloc_free(shader);
   }
}

static void
fragments_take_derivatives_and_discard(void)
{
   const char *body =
      "declare <4 x float> @air.dfdx.v4f32(<4 x float>)\n"
      "declare <4 x float> @air.fwidth.v4f32(<4 x float>)\n"
      "declare void @air.discard_fragment()\n"
      "define <4 x float> @fragment(<4 x float> %position) {\n"
      "%d = call <4 x float> @air.dfdx.v4f32(<4 x float> %position)\n"
      "%w = call <4 x float> @air.fwidth.v4f32(<4 x float> %position)\n"
      "%s = fadd <4 x float> %d, %w\n"
      "call void @air.discard_fragment()\n"
      "ret <4 x float> %s\n}\n";
   const char *metadata =
      "!air.fragment = !{!2}\n!2 = !{ptr @fragment, !3, !4}\n!3 = !{!30}\n"
      "!30 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\","
      " !\"air.arg_name\", !\"color\"}\n"
      "!4 = !{!40}\n"
      "!40 = !{i32 0, !\"air.position\", !\"air.center\", !\"air.no_perspective\","
      " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n";
   char all[2048];
   snprintf(all, sizeof(all), "%s%s", metadata, versions);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, all, "");
   struct stela_air_stage_options o = {
      .stage = STELA_AIR_FRAGMENT, .max_varying_slots = 16,
      .resources = {.max_instructions = 10000, .bind_buffer = stela_metal_bind_buffer,
                    .binding_data = &primary, .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41},
   };
   struct stela_air_error error = {0};
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               "fragment", &nir_options, &o, &error);
   LLVMDisposeMemoryBuffer(input);
   if (!shader)
      fprintf(stderr, "fragment: %u %s\n", error.kind, error.detail);
   assert(shader);
   unsigned ddx = 0, ddy = 0, demote = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_op op = nir_instr_as_intrinsic(instr)->intrinsic;
            ddx += op == nir_intrinsic_ddx;
            ddy += op == nir_intrinsic_ddy;
            demote += op == nir_intrinsic_demote;
         }
      }
   }
   assert(ddx == 2 && ddy == 1 && demote == 1);
   ralloc_free(shader);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   floating_functions_follow_metal();
   integer_functions_follow_metal();
   conversions_follow_their_names();
   refuses_misnamed_and_misplaced_functions();
   half_declares_its_float_controls();
   fragments_take_derivatives_and_discard();
   glsl_type_singleton_decref();
   puts("air math: ok");
   return 0;
}
