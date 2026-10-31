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
#ifdef STELA_AIR_TEST_NAK
#include "air_test_nak.h"
#endif
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
translate(const char *declarations, const char *body, const nir_shader_compiler_options *options,
          stela_air_bind_buffer bind, struct stela_air_error *error)
{
   char definition[2048], all[2048];
   snprintf(definition, sizeof(definition), "define void @kernel(ptr addrspace(1) %%out) {\n%s}\n", body);
   snprintf(all, sizeof(all), "%s%s", kernel_metadata, versions);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, declarations, definition, all);
   const struct stela_air_options o = {
      .workgroup_size = {1, 1, 1}, .max_instructions = 10000,
      .bind_buffer = bind, .binding_data = &primary,
      .fp_profile = STELA_AIR_FP_METAL, .max_private_bytes = 64,
   };
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static nir_shader *
kernel(const char *declarations, const char *type, const char *expression,
       struct stela_air_error *error)
{
   char body[1024];
   snprintf(body, sizeof(body), "%%r = %s\nstore %s %%r, ptr addrspace(1) %%out, align 2\nret void\n",
            expression, type);
   return translate(declarations, body, &nir_options, stela_metal_bind_buffer, error);
}

#ifdef STELA_AIR_TEST_NAK
/* NAK takes lowered push constants, so its compiles bind a fixed address. */
static nir_def *
fixed_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   return nir_imm_int64(b, 0x100000); /* Compile fixture only. */
}

struct fixture {
   const char *declarations, *body;
};

static nir_shader *
nak_translate(const nir_shader_compiler_options *options, void *data)
{
   const struct fixture *fixture = data;
   struct stela_air_error error;
   return translate(fixture->declarations, fixture->body, options, fixed_buffer, &error);
}
#endif

/* The bits of the value the last `intrinsic` stores in `shader`, its
 * operations folded; frees the shader. */
static uint64_t
stored(nir_shader *shader, nir_intrinsic_op intrinsic)
{
   while (nir_opt_constant_folding(shader))
      ;
   nir_intrinsic_instr *store = NULL;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                nir_instr_as_intrinsic(instr)->intrinsic == intrinsic)
               store = nir_instr_as_intrinsic(instr);
         }
      }
   }
   /* Global and scratch stores take their value first. */
   if (!store || !nir_src_is_const(store->src[0]))
      nir_print_shader(shader, stderr);
   assert(store && nir_src_is_const(store->src[0]));
   uint64_t bits = nir_src_as_uint(store->src[0]);
   ralloc_free(shader);
   return bits;
}

/* The kernel `body` stores through %out, which must translate. */
static nir_shader *
translated(const char *declarations, const char *body)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(declarations, body, &nir_options, stela_metal_bind_buffer, &error);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", body, error.kind, error.detail);
   assert(shader);
   return shader;
}

/* The bits of %r, of `type`, once `setup` defines it. */
static uint64_t
fold_body(const char *declarations, const char *setup, const char *type)
{
   char body[1024];
   snprintf(body, sizeof(body), "%sstore %s %%r, ptr addrspace(1) %%out, align 2\nret void\n",
            setup, type);
   return stored(translated(declarations, body), nir_intrinsic_store_global);
}

/* The bits the kernel stores for `expression`, a call of `declaration`. */
static uint64_t
fold(const char *declaration, const char *type, const char *expression)
{
   char setup[512];
   snprintf(setup, sizeof(setup), "%%r = %s\n", expression);
   return fold_body(declaration, setup, type);
}

/* The bits of lane `lane` of the `vector` a call of `declaration` returns. */
static uint64_t
fold_lane(const char *declaration, const char *vector, const char *type, const char *call,
          unsigned lane)
{
   char setup[512];
   snprintf(setup, sizeof(setup), "%%v = %s\n%%r = extractelement %s %%v, i32 %u\n", call, vector,
            lane);
   return fold_body(declaration, setup, type);
}

/* The bits a call of `declaration` stores through its thread pointer %p, an
 * alloca of `pointee`, and those of its `type` result in `result`. */
static uint64_t
fold_second(const char *declaration, const char *pointee, const char *type, const char *call,
            uint64_t *result)
{
   char body[1024];
   snprintf(body, sizeof(body),
            "%%p = alloca %s, align 16\n%%r = %s\nstore %s %%r, ptr addrspace(1) %%out, align 2\n"
            "ret void\n", pointee, call, type);
   nir_shader *shader = translated(declaration, body);
   *result = stored(nir_shader_clone(NULL, shader), nir_intrinsic_store_global);
   return stored(shader, nir_intrinsic_store_scratch);
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
   /* sign keeps zeros' signs and makes NaN 0. */
   CHECK_FOLD("declare float @air.sign.f32(float)\n", "float", "call float @air.sign.f32(float -3.0)",
              f32(-1.0f));
   CHECK_FOLD("declare float @air.sign.f32(float)\n", "float", "call float @air.sign.f32(float -0.0)",
              0x80000000u);
   CHECK_FOLD("declare float @air.sign.f32(float)\n", "float",
              "call float @air.sign.f32(float 0x7FF8000000000000)", 0);
   CHECK_FOLD("declare half @air.sign.f16(half)\n", "half", "call half @air.sign.f16(half 0xH4500)",
              0x3c00);
   /* nextafter steps one representable value, from zero to a subnormal. */
   CHECK_FOLD("declare float @air.nextafter.f32(float, float)\n", "float",
              "call float @air.nextafter.f32(float 1.0, float 2.0)", 0x3f800001u);
   CHECK_FOLD("declare float @air.nextafter.f32(float, float)\n", "float",
              "call float @air.nextafter.f32(float 1.0, float 0.0)", 0x3f7fffffu);
   CHECK_FOLD("declare float @air.nextafter.f32(float, float)\n", "float",
              "call float @air.nextafter.f32(float -1.0, float 0.0)", 0xbf7fffffu);
   CHECK_FOLD("declare float @air.nextafter.f32(float, float)\n", "float",
              "call float @air.nextafter.f32(float -0.0, float 1.0)", 1);
   CHECK_FOLD("declare float @air.nextafter.f32(float, float)\n", "float",
              "call float @air.nextafter.f32(float 2.0, float 2.0)", f32(2.0f));
   CHECK_FOLD("declare float @air.ldexp.f32(float, i32)\n", "float",
              "call float @air.ldexp.f32(float 1.5, i32 3)", f32(12.0f));
   CHECK_FOLD("declare float @air.fast_ldexp.f32(float, i32)\n", "float",
              "call float @air.fast_ldexp.f32(float 1.0, i32 -2)", f32(0.25f));
   CHECK_FOLD("declare half @air.ldexp.f16(half, i32)\n", "half",
              "call half @air.ldexp.f16(half 0xH3C00, i32 -1)", 0x3800);
   /* ilogb is Apple's library's, with Darwin's results for zero and
    * infinity. */
   CHECK_FOLD("declare i32 @___metal_ilogb_float(float, i32)\n", "i32",
              "call i32 @___metal_ilogb_float(float 10.0, i32 0)", 3);
   CHECK_FOLD("declare i32 @___metal_ilogb_float(float, i32)\n", "i32",
              "call i32 @___metal_ilogb_float(float 0.0, i32 1)", 0x80000000u);
   CHECK_FOLD("declare i32 @___metal_ilogb_float(float, i32)\n", "i32",
              "call i32 @___metal_ilogb_float(float 0x7FF0000000000000, i32 0)", 0x7fffffffu);
   CHECK_FOLD("declare i32 @___metal_ilogb_half(half, i32)\n", "i32",
              "call i32 @___metal_ilogb_half(half 0xH0001, i32 0)", (uint32_t)-24);
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
   CHECK_FOLD("declare i32 @air.abs_diff.s.i32(i32, i32)\n", "i32",
              "call i32 @air.abs_diff.s.i32(i32 -5, i32 3)", 8);
   CHECK_FOLD("declare i8 @air.abs_diff.s.i8(i8, i8)\n", "i8",
              "call i8 @air.abs_diff.s.i8(i8 -128, i8 127)", 0xff);
   CHECK_FOLD("declare i8 @air.abs_diff.u.i8(i8, i8)\n", "i8",
              "call i8 @air.abs_diff.u.i8(i8 5, i8 -6)", 245);
   /* Halved sums round down, or up for rhadd, without overflowing. */
   CHECK_FOLD("declare i32 @air.hadd.s.i32(i32, i32)\n", "i32",
              "call i32 @air.hadd.s.i32(i32 -3, i32 0)", 0xfffffffeu);
   CHECK_FOLD("declare i8 @air.hadd.u.i8(i8, i8)\n", "i8", "call i8 @air.hadd.u.i8(i8 -1, i8 -1)", 0xff);
   CHECK_FOLD("declare i8 @air.rhadd.u.i8(i8, i8)\n", "i8", "call i8 @air.rhadd.u.i8(i8 -2, i8 -1)", 0xff);
   CHECK_FOLD("declare i32 @air.rhadd.s.i32(i32, i32)\n", "i32",
              "call i32 @air.rhadd.s.i32(i32 -3, i32 0)", 0xffffffffu);
   CHECK_FOLD("declare i32 @air.mad_hi.u.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.mad_hi.u.i32(i32 -1, i32 2, i32 1)", 2);
   /* mad_sat saturates the exact x * y + z. */
   CHECK_FOLD("declare i32 @air.mad_sat.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.mad_sat.s.i32(i32 65536, i32 65536, i32 0)", 0x7fffffffu);
   CHECK_FOLD("declare i32 @air.mad_sat.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.mad_sat.s.i32(i32 -65536, i32 65536, i32 0)", 0x80000000u);
   CHECK_FOLD("declare i32 @air.mad_sat.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.mad_sat.s.i32(i32 3, i32 4, i32 -20)", (uint32_t)-8);
   CHECK_FOLD("declare i8 @air.mad_sat.u.i8(i8, i8, i8)\n", "i8",
              "call i8 @air.mad_sat.u.i8(i8 15, i8 16, i8 15)", 0xff);
   CHECK_FOLD("declare i8 @air.mad_sat.u.i8(i8, i8, i8)\n", "i8",
              "call i8 @air.mad_sat.u.i8(i8 15, i8 16, i8 14)", 0xfe);
   CHECK_FOLD("declare i64 @air.mad_sat.s.i64(i64, i64, i64)\n", "i64",
              "call i64 @air.mad_sat.s.i64(i64 9223372036854775807, i64 1, i64 1)", INT64_MAX);
   CHECK_FOLD("declare i64 @air.mad_sat.s.i64(i64, i64, i64)\n", "i64",
              "call i64 @air.mad_sat.s.i64(i64 -1, i64 1, i64 -9223372036854775808)", INT64_MIN);
   CHECK_FOLD("declare i64 @air.mad_sat.u.i64(i64, i64, i64)\n", "i64",
              "call i64 @air.mad_sat.u.i64(i64 -1, i64 1, i64 1)", UINT64_MAX);
   CHECK_FOLD("declare i32 @air.max3.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.max3.s.i32(i32 1, i32 -5, i32 3)", 3);
   CHECK_FOLD("declare i32 @air.min3.u.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.min3.u.i32(i32 1, i32 -5, i32 3)", 1);
   CHECK_FOLD("declare i32 @air.median3.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.median3.s.i32(i32 1, i32 -5, i32 3)", 1);
   CHECK_FOLD("declare i32 @air.mul24.s.i32(i32, i32)\n", "i32",
              "call i32 @air.mul24.s.i32(i32 -3, i32 4)", (uint32_t)-12);
   CHECK_FOLD("declare i32 @air.mad24.u.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.mad24.u.i32(i32 3, i32 4, i32 5)", 17);
   /* Rotations take their count modulo the width. */
   CHECK_FOLD("declare i32 @air.rotate.i32(i32, i32)\n", "i32",
              "call i32 @air.rotate.i32(i32 -2147483647, i32 1)", 3);
   CHECK_FOLD("declare i8 @air.rotate.i8(i8, i8)\n", "i8", "call i8 @air.rotate.i8(i8 -127, i8 9)", 3);
   CHECK_FOLD("declare i32 @air.rotate.i32(i32, i32)\n", "i32",
              "call i32 @air.rotate.i32(i32 5, i32 32)", 5);
   /* Bit fields: signed extraction extends the field's sign; an empty
    * field reads 0 and writes nothing. */
   CHECK_FOLD("declare i32 @air.extract_bits.u.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.extract_bits.u.i32(i32 43981, i32 4, i32 8)", 0xbc);
   CHECK_FOLD("declare i32 @air.extract_bits.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.extract_bits.s.i32(i32 240, i32 4, i32 4)", 0xffffffffu);
   CHECK_FOLD("declare i32 @air.extract_bits.s.i32(i32, i32, i32)\n", "i32",
              "call i32 @air.extract_bits.s.i32(i32 240, i32 4, i32 0)", 0);
   CHECK_FOLD("declare i16 @air.extract_bits.u.i16(i16, i32, i32)\n", "i16",
              "call i16 @air.extract_bits.u.i16(i16 -32768, i32 15, i32 1)", 1);
   CHECK_FOLD("declare i32 @air.insert_bits.u.i32(i32, i32, i32, i32)\n", "i32",
              "call i32 @air.insert_bits.u.i32(i32 65535, i32 0, i32 4, i32 8)", 0xf00f);
   CHECK_FOLD("declare i32 @air.insert_bits.u.i32(i32, i32, i32, i32)\n", "i32",
              "call i32 @air.insert_bits.u.i32(i32 4660, i32 255, i32 4, i32 0)", 4660);
   CHECK_FOLD("declare i32 @air.insert_bits.s.i32(i32, i32, i32, i32)\n", "i32",
              "call i32 @air.insert_bits.s.i32(i32 1, i32 -559038737, i32 0, i32 32)", 0xdeadbeefu);
}

/* sincos and frexp store their second result through a thread pointer. */
static void
second_results_store_through_thread_pointers(void)
{
   uint64_t result;
   assert(fold_second("declare float @air.fast_sincos.f32(float, ptr)\n", "float", "float",
                      "call float @air.fast_sincos.f32(float 0.0, ptr %p)", &result) == f32(1.0f));
   assert(result == 0);
   assert(fold_second("declare half @air.sincos.f16(half, ptr)\n", "half", "half",
                      "call half @air.sincos.f16(half 0xH0000, ptr %p)", &result) == 0x3c00);
   assert(result == 0);
   assert(fold_second("declare float @___metal_frexp_float_pthreadint32(float, ptr)\n", "i32",
                      "float", "call float @___metal_frexp_float_pthreadint32(float 12.0, ptr %p)",
                      &result) == 4);
   assert(result == f32(0.75f));
   /* Subnormals normalize. */
   assert(fold_second("declare half @___metal_frexp_half_pthreadint32(half, ptr)\n", "i32", "half",
                      "call half @___metal_frexp_half_pthreadint32(half 0xH0001, ptr %p)",
                      &result) == (uint32_t)-23);
   assert(result == 0x3800);
   assert(fold_second("declare float @___metal_frexp_float_pthreadint32(float, ptr)\n", "i32",
                      "float", "call float @___metal_frexp_float_pthreadint32(float 0.0, ptr %p)",
                      &result) == 0);
   assert(result == 0);
}

/* Formats pack their first component lowest, rounding to even; NaN packs as
 * zero and sRGB converts color but not alpha. */
static void
packing_follows_metal(void)
{
   CHECK_FOLD("declare i32 @air.pack.unorm4x8.v4f32(<4 x float>)\n", "i32",
              "call i32 @air.pack.unorm4x8.v4f32(<4 x float> <float 1.0, float 0.0, float 0.5,"
              " float 0x7FF8000000000000>)", 0x008000ffu);
   CHECK_FOLD("declare i32 @air.pack.snorm4x8.v4f32(<4 x float>)\n", "i32",
              "call i32 @air.pack.snorm4x8.v4f32(<4 x float> <float -1.0, float 2.0, float 0.0,"
              " float -0.5>)", 0xc0007f81u);
   CHECK_FOLD("declare i32 @air.pack.unorm2x16.v2f16(<2 x half>)\n", "i32",
              "call i32 @air.pack.unorm2x16.v2f16(<2 x half> <half 0xH3C00, half 0xH0000>)", 0xffff);
   CHECK_FOLD("declare i16 @air.pack.unorm.rgb565.v3f32(<3 x float>)\n", "i16",
              "call i16 @air.pack.unorm.rgb565.v3f32(<3 x float> <float 1.0, float 0.0, float 1.0>)",
              0xf81f);
   CHECK_FOLD("declare i32 @air.pack.unorm.rgb10a2.v4f32(<4 x float>)\n", "i32",
              "call i32 @air.pack.unorm.rgb10a2.v4f32(<4 x float> <float 1.0, float 0.0, float 0.0,"
              " float 1.0>)", 0xc00003ffu);
   CHECK_FOLD("declare i32 @air.pack.unorm4x8.srgb.v4f32(<4 x float>)\n", "i32",
              "call i32 @air.pack.unorm4x8.srgb.v4f32(<4 x float> <float 0.0, float 0.0, float 0.0,"
              " float 0.5>)", 0x80000000u);
   const char *unorm = "declare <4 x float> @air.unpack.unorm4x8.v4f32(i32)\n";
   assert(fold_lane(unorm, "<4 x float>", "float",
                    "call <4 x float> @air.unpack.unorm4x8.v4f32(i32 -2130771968)", 2) == f32(1.0f));
   assert(fold_lane(unorm, "<4 x float>", "float",
                    "call <4 x float> @air.unpack.unorm4x8.v4f32(i32 -2130771968)", 3) ==
          f32(128.0f / 255.0f));
   const char *snorm = "declare <4 x float> @air.unpack.snorm4x8.v4f32(i32)\n";
   assert(fold_lane(snorm, "<4 x float>", "float",
                    "call <4 x float> @air.unpack.snorm4x8.v4f32(i32 128)", 0) == f32(-1.0f));
   assert(fold_lane(snorm, "<4 x float>", "float",
                    "call <4 x float> @air.unpack.snorm4x8.v4f32(i32 127)", 0) == f32(1.0f));
   assert(fold_lane("declare <3 x float> @air.unpack.unorm.rgb565.v3f32(i16)\n", "<3 x float>",
                    "float", "call <3 x float> @air.unpack.unorm.rgb565.v3f32(i16 31)", 0) ==
          f32(1.0f));
   assert(fold_lane("declare <4 x float> @air.unpack.unorm4x8.srgb.v4f32(i32)\n", "<4 x float>",
                    "float", "call <4 x float> @air.unpack.unorm4x8.srgb.v4f32(i32 -16777216)", 3) ==
          f32(1.0f));
   assert(fold_lane("declare <2 x half> @air.unpack.unorm2x16.v2f16(i32)\n", "<2 x half>", "half",
                    "call <2 x half> @air.unpack.unorm2x16.v2f16(i32 65535)", 0) == 0x3c00);
}

static void
bools_reduce(void)
{
   const char *declarations = "declare i1 @air.all.v4i1(<4 x i1>)\ndeclare i1 @air.any.v4i1(<4 x i1>)\n";
   assert(fold_body(declarations,
                    "%v = call i1 @air.all.v4i1(<4 x i1> <i1 true, i1 true, i1 false, i1 true>)\n"
                    "%r = zext i1 %v to i32\n", "i32") == 0);
   assert(fold_body(declarations,
                    "%v = call i1 @air.any.v4i1(<4 x i1> <i1 false, i1 false, i1 true, i1 false>)\n"
                    "%r = zext i1 %v to i32\n", "i32") == 1);
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
   /* A bool converts as zero or one; anything nonzero is true. */
   CHECK_FOLD("declare float @air.convert.f.f32.u.i1(i1)\n", "float",
              "call float @air.convert.f.f32.u.i1(i1 true)", f32(1.0f));
   CHECK_FOLD("declare i32 @air.convert.s.i32.u.i1(i1)\n", "i32",
              "call i32 @air.convert.s.i32.u.i1(i1 true)", 1);
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
      {"declare float @air.sincos.f32(float, ptr)\n", "float",
       "call float @air.sincos.f32(float 1.0, ptr null)", STELA_AIR_INSTRUCTION},
      /* ldexp takes an exponent per lane. */
      {"declare <2 x float> @air.ldexp.v2f32(<2 x float>, i32)\n", "<2 x float>",
       "call <2 x float> @air.ldexp.v2f32(<2 x float> zeroinitializer, i32 1)", STELA_AIR_TYPE},
      /* Packing types match their format. */
      {"declare i32 @air.pack.unorm2x16.v4f32(<4 x float>)\n", "i32",
       "call i32 @air.pack.unorm2x16.v4f32(<4 x float> zeroinitializer)", STELA_AIR_TYPE},
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

/* Every kind of function lowers, and compiles with NAK, on loaded values the
 * compiler cannot fold: %a, %b and %c of the operand type. */
static void
functions_compile(void)
{
   static const struct {
      const char *declaration, *operand, *result, *expression;
   } functions[] = {
      {"declare float @air.fast_sin.f32(float)\n", "float", "float", "call float @air.fast_sin.f32(float %a)"},
      {"declare float @air.fast_tanh.f32(float)\n", "float", "float", "call float @air.fast_tanh.f32(float %a)"},
      {"declare float @air.fast_acosh.f32(float)\n", "float", "float", "call float @air.fast_acosh.f32(float %a)"},
      {"declare float @air.fast_exp10.f32(float)\n", "float", "float", "call float @air.fast_exp10.f32(float %a)"},
      {"declare float @air.fast_cospi.f32(float)\n", "float", "float", "call float @air.fast_cospi.f32(float %a)"},
      {"declare float @air.fast_atan2.f32(float, float)\n", "float", "float",
       "call float @air.fast_atan2.f32(float %a, float %b)"},
      {"declare float @air.fast_pow.f32(float, float)\n", "float", "float",
       "call float @air.fast_pow.f32(float %a, float %b)"},
      {"declare float @air.fast_fmod.f32(float, float)\n", "float", "float",
       "call float @air.fast_fmod.f32(float %a, float %b)"},
      {"declare float @air.fract.f32(float)\n", "float", "float", "call float @air.fract.f32(float %a)"},
      {"declare float @air.round.f32(float)\n", "float", "float", "call float @air.round.f32(float %a)"},
      {"declare float @air.rint.f32(float)\n", "float", "float", "call float @air.rint.f32(float %a)"},
      {"declare float @air.fdim.f32(float, float)\n", "float", "float",
       "call float @air.fdim.f32(float %a, float %b)"},
      {"declare float @air.fmedian3.f32(float, float, float)\n", "float", "float",
       "call float @air.fmedian3.f32(float %a, float %b, float %c)"},
      {"declare float @air.mix.f32(float, float, float)\n", "float", "float",
       "call float @air.mix.f32(float %a, float %b, float %c)"},
      {"declare float @llvm.fma.f32(float, float, float)\n", "float", "float",
       "call float @llvm.fma.f32(float %a, float %b, float %c)"},
      {"", "float", "float", "frem fast float %a, %b"},
      {"", "float", "float", "fdiv fast float %a, %b"},
      {"declare half @air.sin.f16(half)\n", "half", "half", "call half @air.sin.f16(half %a)"},
      {"declare half @air.sqrt.f16(half)\n", "half", "half", "call half @air.sqrt.f16(half %a)"},
      {"declare half @air.fma.f16(half, half, half)\n", "half", "half",
       "call half @air.fma.f16(half %a, half %b, half %c)"},
      {"", "half", "half", "fdiv fast half %a, %b"},
      {"declare float @air.dot.v3f32(<3 x float>, <3 x float>)\n", "<3 x float>", "float",
       "call float @air.dot.v3f32(<3 x float> %a, <3 x float> %b)"},
      {"declare <3 x float> @air.cross.v3f32(<3 x float>, <3 x float>)\n", "<3 x float>", "<3 x float>",
       "call <3 x float> @air.cross.v3f32(<3 x float> %a, <3 x float> %b)"},
      {"declare <3 x float> @air.fast_normalize.v3f32(<3 x float>)\n", "<3 x float>", "<3 x float>",
       "call <3 x float> @air.fast_normalize.v3f32(<3 x float> %a)"},
      {"declare float @air.fast_distance.v4f32(<4 x float>, <4 x float>)\n", "<4 x float>", "float",
       "call float @air.fast_distance.v4f32(<4 x float> %a, <4 x float> %b)"},
      {"declare i32 @air.clz.i32(i32, i1)\n", "i32", "i32", "call i32 @air.clz.i32(i32 %a, i1 false)"},
      {"declare i64 @air.ctz.i64(i64, i1)\n", "i64", "i64", "call i64 @air.ctz.i64(i64 %a, i1 false)"},
      {"declare i16 @air.popcount.i16(i16)\n", "i16", "i16", "call i16 @air.popcount.i16(i16 %a)"},
      {"declare i8 @air.reverse_bits.i8(i8)\n", "i8", "i8", "call i8 @air.reverse_bits.i8(i8 %a)"},
      {"declare i64 @air.mul_hi.u.i64(i64, i64)\n", "i64", "i64",
       "call i64 @air.mul_hi.u.i64(i64 %a, i64 %b)"},
      {"declare i16 @air.add_sat.s.i16(i16, i16)\n", "i16", "i16",
       "call i16 @air.add_sat.s.i16(i16 %a, i16 %b)"},
      {"declare i8 @air.sub_sat.u.i8(i8, i8)\n", "i8", "i8", "call i8 @air.sub_sat.u.i8(i8 %a, i8 %b)"},
      {"declare i32 @air.clamp.u.i32(i32, i32, i32)\n", "i32", "i32",
       "call i32 @air.clamp.u.i32(i32 %a, i32 %b, i32 %c)"},
      {"declare half @air.convert.f.f16.s.i32(i32)\n", "i32", "half",
       "call half @air.convert.f.f16.s.i32(i32 %a)"},
      {"", "half", "i16", "fptosi half %a to i16"},
      {"", "float", "i64", "fptoui float %a to i64"},
      {"", "i64", "float", "uitofp i64 %a to float"},
      {"", "<2 x half>", "<2 x float>", "fpext <2 x half> %a to <2 x float>"},
      {"declare <4 x float> @air.sign.v4f32(<4 x float>)\n", "<4 x float>", "<4 x float>",
       "call <4 x float> @air.sign.v4f32(<4 x float> %a)"},
      {"declare half @air.nextafter.f16(half, half)\n", "half", "half",
       "call half @air.nextafter.f16(half %a, half %b)"},
      {"declare <2 x float> @air.ldexp.v2f32(<2 x float>, <2 x i32>)\n", "<2 x float>", "<2 x float>",
       "call <2 x float> @air.ldexp.v2f32(<2 x float> %a, <2 x i32> <i32 3, i32 -3>)"},
      {"declare float @air.fast_sincos.f32(float, ptr)\n", "float", "float",
       "call float @air.fast_sincos.f32(float %a, ptr %p)"},
      {"declare <3 x float> @___metal_frexp_v3float_pthreadv3int32(<3 x float>, ptr)\n",
       "<3 x float>", "<3 x float>",
       "call <3 x float> @___metal_frexp_v3float_pthreadv3int32(<3 x float> %a, ptr %p)"},
      {"declare <2 x i32> @___metal_ilogb_v2half(<2 x half>, i32)\n", "<2 x half>", "<2 x i32>",
       "call <2 x i32> @___metal_ilogb_v2half(<2 x half> %a, i32 0)"},
      {"declare <2 x i64> @air.mad_sat.s.v2i64(<2 x i64>, <2 x i64>, <2 x i64>)\n", "<2 x i64>",
       "<2 x i64>", "call <2 x i64> @air.mad_sat.s.v2i64(<2 x i64> %a, <2 x i64> %b, <2 x i64> %c)"},
      {"declare <4 x i8> @air.rhadd.u.v4i8(<4 x i8>, <4 x i8>)\n", "<4 x i8>", "<4 x i8>",
       "call <4 x i8> @air.rhadd.u.v4i8(<4 x i8> %a, <4 x i8> %b)"},
      {"declare <4 x i16> @air.extract_bits.s.v4i16(<4 x i16>, i32, i32)\n", "<4 x i16>", "<4 x i16>",
       "call <4 x i16> @air.extract_bits.s.v4i16(<4 x i16> %a, i32 3, i32 7)"},
      {"declare i64 @air.insert_bits.u.i64(i64, i64, i32, i32)\n", "i64", "i64",
       "call i64 @air.insert_bits.u.i64(i64 %a, i64 %b, i32 40, i32 9)"},
      {"declare <2 x i64> @air.rotate.v2i64(<2 x i64>, <2 x i64>)\n", "<2 x i64>", "<2 x i64>",
       "call <2 x i64> @air.rotate.v2i64(<2 x i64> %a, <2 x i64> %b)"},
      {"declare i32 @air.pack.unorm4x8.srgb.v4f32(<4 x float>)\n", "<4 x float>", "i32",
       "call i32 @air.pack.unorm4x8.srgb.v4f32(<4 x float> %a)"},
      {"declare <4 x half> @air.unpack.snorm4x8.v4f16(i32)\n", "i32", "<4 x half>",
       "call <4 x half> @air.unpack.snorm4x8.v4f16(i32 %a)"},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(functions); i++) {
      const char *t = functions[i].operand;
      char body[1024];
      snprintf(body, sizeof(body),
               "%%p = alloca <4 x i32>, align 16\n"
               "%%a = load %s, ptr addrspace(1) %%out, align 16\n"
               "%%pb = getelementptr i8, ptr addrspace(1) %%out, i64 16\n"
               "%%b = load %s, ptr addrspace(1) %%pb, align 16\n"
               "%%pc = getelementptr i8, ptr addrspace(1) %%out, i64 32\n"
               "%%c = load %s, ptr addrspace(1) %%pc, align 16\n"
               "%%r = %s\nstore %s %%r, ptr addrspace(1) %%out, align 16\nret void\n",
               t, t, t, functions[i].expression, functions[i].result);
      struct stela_air_error error = {0};
      nir_shader *shader = translate(functions[i].declaration, body, &nir_options,
                                     stela_metal_bind_buffer, &error);
      if (!shader)
         fprintf(stderr, "%s: %u %s\n", functions[i].expression, error.kind, error.detail);
      assert(shader);
      ralloc_free(shader);
#ifdef STELA_AIR_TEST_NAK
      stela_air_test_nak(nak_translate, &(struct fixture){functions[i].declaration, body});
#endif
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
                    .binding_data = &primary, .fp_profile = STELA_AIR_FP_METAL},
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
   second_results_store_through_thread_pointers();
   packing_follows_metal();
   bools_reduce();
   conversions_follow_their_names();
   refuses_misnamed_and_misplaced_functions();
   half_declares_its_float_controls();
   functions_compile();
   fragments_take_derivatives_and_discard();
   glsl_type_singleton_decref();
   puts("air math: ok");
   return 0;
}
