/* SPDX-License-Identifier: MIT */
/* Atomics, barriers, fences and SIMD-group functions. Original LLVM IR
 * fixtures in the forms air_to_nir.c and air_simd.c document; no Apple
 * output. */
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

static const char *metadata =
   "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

/* Threadgroup storage the fixtures may use. */
static const char *shared = "@s = internal addrspace(3) global [64 x i32] undef, align 4\n";

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};

static nir_shader *
translate(const char *declarations, const char *body, const nir_shader_compiler_options *options,
          stela_air_bind_buffer bind, struct stela_air_error *error)
{
   char definition[4096], all[4096];
   snprintf(definition, sizeof(definition), "define void @kernel(ptr addrspace(1) %%out) {\n%s}\n", body);
   snprintf(all, sizeof(all), "%s%s", shared, declarations);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, all, definition, metadata);
   const struct stela_air_options o = {
      .workgroup_size = {64, 1, 1}, .max_instructions = 10000, .max_threadgroup_bytes = 256,
      .bind_buffer = bind, .binding_data = &primary,
      .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41,
   };
   *error = (struct stela_air_error){0};
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", body, error->kind, error->detail);
   return shader;
}

static nir_shader *
kernel(const char *declarations, const char *body, struct stela_air_error *error)
{
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

static nir_shader *
lowered(const char *declarations, const char *body)
{
   struct stela_air_error error;
   nir_shader *shader = kernel(declarations, body, &error);
   assert(shader && error.kind == STELA_AIR_OK);
#ifdef STELA_AIR_TEST_NAK
   stela_air_test_nak(nak_translate, &(struct fixture){declarations, body});
#endif
   return shader;
}

static void
refused(const char *declarations, const char *body, enum stela_air_error_kind kind)
{
   struct stela_air_error error;
   nir_shader *shader = kernel(declarations, body, &error);
   if (shader || error.kind != kind)
      fprintf(stderr, "%s: wanted %u, got %u %s\n", body, kind, error.kind, error.detail);
   assert(!shader && error.kind == kind);
}

static unsigned
count(nir_shader *shader, nir_intrinsic_op op)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block)
            n += instr->type == nir_instr_type_intrinsic && nir_instr_as_intrinsic(instr)->intrinsic == op;
      }
   }
   return n;
}

/* The atomic operations of the shader's atomic intrinsics, in order. */
static unsigned
atomics(nir_shader *shader, nir_atomic_op *ops, unsigned capacity)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            if (nir_intrinsic_has_atomic_op(intr)) {
               assert(n < capacity);
               ops[n++] = nir_intrinsic_atomic_op(intr);
            }
         }
      }
   }
   return n;
}

static void
expect_atomics(const char *declarations, const char *body, const nir_atomic_op *expected, unsigned n)
{
   nir_shader *shader = lowered(declarations, body);
   nir_atomic_op ops[16];
   unsigned seen = atomics(shader, ops, ARRAY_SIZE(ops));
   assert(seen == n && !memcmp(ops, expected, n * sizeof(*ops)));
   ralloc_free(shader);
}

static void
llvm_atomics_are_relaxed_device_and_threadgroup_atomics(void)
{
   const nir_atomic_op device[] = {
      nir_atomic_op_iadd, nir_atomic_op_iadd, nir_atomic_op_xchg, nir_atomic_op_imin,
      nir_atomic_op_umax, nir_atomic_op_ixor, nir_atomic_op_fadd, nir_atomic_op_cmpxchg,
   };
   expect_atomics("",
      "%a = atomicrmw add ptr addrspace(1) %out, i32 1 monotonic, align 4\n"
      "%b = atomicrmw sub ptr addrspace(1) %out, i32 %a monotonic, align 4\n"
      "%c = atomicrmw xchg ptr addrspace(1) %out, i32 %b monotonic, align 4\n"
      "%d = atomicrmw min ptr addrspace(1) %out, i32 %c monotonic, align 4\n"
      "%e = atomicrmw umax ptr addrspace(1) %out, i32 %d monotonic, align 4\n"
      "%f = atomicrmw volatile xor ptr addrspace(1) %out, i32 %e monotonic, align 4\n"
      "%g = atomicrmw fsub ptr addrspace(1) %out, float 1.0 monotonic, align 4\n"
      "%h = cmpxchg weak ptr addrspace(1) %out, i32 %f, i32 7 monotonic monotonic, align 4\n"
      "%old = extractvalue { i32, i1 } %h, 0\n%exchanged = extractvalue { i32, i1 } %h, 1\n"
      "%r = select i1 %exchanged, i32 %old, i32 0\n"
      "store atomic i32 %r, ptr addrspace(1) %out monotonic, align 4\n"
      "%l = load atomic i32, ptr addrspace(1) %out unordered, align 4\nret void\n",
      device, ARRAY_SIZE(device));
   const nir_atomic_op threadgroup[] = {nir_atomic_op_iadd, nir_atomic_op_cmpxchg};
   expect_atomics("",
      "%p = getelementptr [64 x i32], ptr addrspace(3) @s, i64 0, i64 3\n"
      "%a = atomicrmw add ptr addrspace(3) %p, i32 1 monotonic, align 4\n"
      "%h = cmpxchg ptr addrspace(3) %p, i32 %a, i32 0 monotonic monotonic, align 4\n"
      "%old = extractvalue { i32, i1 } %h, 0\n"
      "store i32 %old, ptr addrspace(1) %out, align 4\nret void\n",
      threadgroup, ARRAY_SIZE(threadgroup));
   /* Relaxed atomic loads and stores are coherent single accesses. The other
    * loads read the binding tables. */
   nir_shader *shader = lowered("",
      "%l = load atomic i32, ptr addrspace(1) %out monotonic, align 4\n"
      "store atomic i32 %l, ptr addrspace(1) %out monotonic, align 4\nret void\n");
   unsigned flagged[2] = {0};
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            switch (intr->intrinsic) {
            case nir_intrinsic_load_global: case nir_intrinsic_load_ssbo:
               flagged[0] += (nir_intrinsic_access(intr) & (ACCESS_ATOMIC | ACCESS_COHERENT)) ==
                             (ACCESS_ATOMIC | ACCESS_COHERENT);
               break;
            case nir_intrinsic_store_global: case nir_intrinsic_store_ssbo:
               flagged[1] += (nir_intrinsic_access(intr) & (ACCESS_ATOMIC | ACCESS_COHERENT)) ==
                             (ACCESS_ATOMIC | ACCESS_COHERENT);
               break;
            default:
               break;
            }
         }
      }
   }
   assert(flagged[0] == 1 && flagged[1] == 1);
   ralloc_free(shader);
}

static void
air_atomics_follow_their_names(void)
{
   const nir_atomic_op expected[] = {
      nir_atomic_op_iadd, nir_atomic_op_imax, nir_atomic_op_umin, nir_atomic_op_xchg,
      nir_atomic_op_fadd, nir_atomic_op_iand,
   };
   expect_atomics(
      "declare i32 @air.atomic.global.add.u.i32(ptr addrspace(1), i32, i32, i32, i1)\n"
      "declare i32 @air.atomic.global.max.s.i32(ptr addrspace(1), i32, i32, i32, i1)\n"
      "declare i32 @air.atomic.global.min.u.i32(ptr addrspace(1), i32, i32, i32, i1)\n"
      "declare i32 @air.atomic.global.xchg.i32(ptr addrspace(1), i32, i32, i32, i1)\n"
      "declare float @air.atomic.global.sub.f.f32(ptr addrspace(1), float, i32, i32, i1)\n"
      "declare i32 @air.atomic.local.and.u.i32(ptr addrspace(3), i32, i32, i32, i1)\n",
      "%a = call i32 @air.atomic.global.add.u.i32(ptr addrspace(1) %out, i32 1, i32 0, i32 3, i1 true)\n"
      "%b = call i32 @air.atomic.global.max.s.i32(ptr addrspace(1) %out, i32 %a, i32 0, i32 3, i1 true)\n"
      "%c = call i32 @air.atomic.global.min.u.i32(ptr addrspace(1) %out, i32 %b, i32 0, i32 2, i1 false)\n"
      "%d = call i32 @air.atomic.global.xchg.i32(ptr addrspace(1) %out, i32 %c, i32 0, i32 3, i1 true)\n"
      "%e = call float @air.atomic.global.sub.f.f32(ptr addrspace(1) %out, float 2.0, i32 0, i32 3, i1 true)\n"
      "%p = getelementptr [64 x i32], ptr addrspace(3) @s, i64 0, i64 1\n"
      "%f = call i32 @air.atomic.local.and.u.i32(ptr addrspace(3) %p, i32 %d, i32 0, i32 1, i1 true)\n"
      "store i32 %f, ptr addrspace(1) %out, align 4\nret void\n",
      expected, ARRAY_SIZE(expected));
}

static void
refuses_unqualified_atomics(void)
{
   /* Metal's atomics are relaxed. */
   refused("", "%a = atomicrmw add ptr addrspace(1) %out, i32 1 seq_cst, align 4\nret void\n",
           STELA_AIR_MEMORY);
   refused("", "%h = cmpxchg ptr addrspace(1) %out, i32 0, i32 1 acq_rel monotonic, align 4\nret void\n",
           STELA_AIR_MEMORY);
   refused("", "%l = load atomic i32, ptr addrspace(1) %out acquire, align 4\nret void\n", STELA_AIR_MEMORY);
   refused("", "%a = atomicrmw nand ptr addrspace(1) %out, i32 1 monotonic, align 4\nret void\n",
           STELA_AIR_INSTRUCTION);
   refused("", "%a = atomicrmw fmax ptr addrspace(1) %out, float 1.0 monotonic, align 4\nret void\n",
           STELA_AIR_INSTRUCTION);
   refused("", "%a = atomicrmw add ptr addrspace(1) %out, i16 1 monotonic, align 2\nret void\n",
           STELA_AIR_TYPE);
   /* An AIR atomic's name spells its memory, operation and type. */
   refused("declare i32 @air.atomic.local.add.u.i32(ptr addrspace(1), i32, i32, i32, i1)\n",
           "%a = call i32 @air.atomic.local.add.u.i32(ptr addrspace(1) %out, i32 1, i32 0, i32 1, i1 true)\nret void\n",
           STELA_AIR_INSTRUCTION);
   refused("declare float @air.atomic.global.max.f.f32(ptr addrspace(1), float, i32, i32, i1)\n",
           "%a = call float @air.atomic.global.max.f.f32(ptr addrspace(1) %out, float 1.0, i32 0, i32 3, i1 true)\nret void\n",
           STELA_AIR_INSTRUCTION);
   refused("declare i32 @air.atomic.global.add.u.i32(ptr addrspace(1), i32, i32, i32, i1)\n",
           "%a = call i32 @air.atomic.global.add.u.i32(ptr addrspace(1) %out, i32 1, i32 5, i32 3, i1 true)\nret void\n",
           STELA_AIR_MEMORY);
}

static void
check_barrier(const char *declaration, const char *call, mesa_scope execution, mesa_scope memory,
              nir_variable_mode modes)
{
   char body[256];
   snprintf(body, sizeof(body), "%s\nret void\n", call);
   nir_shader *shader = lowered(declaration, body);
   unsigned barriers = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic ||
                nir_instr_as_intrinsic(instr)->intrinsic != nir_intrinsic_barrier)
               continue;
            nir_intrinsic_instr *barrier = nir_instr_as_intrinsic(instr);
            assert(nir_intrinsic_execution_scope(barrier) == execution &&
                   nir_intrinsic_memory_scope(barrier) == memory &&
                   nir_intrinsic_memory_modes(barrier) == modes &&
                   nir_intrinsic_memory_semantics(barrier) == (modes ? NIR_MEMORY_ACQ_REL : 0));
            barriers++;
         }
      }
   }
   assert(barriers == (execution != SCOPE_NONE || modes));
   ralloc_free(shader);
}

static void
barriers_and_fences_follow_their_flags(void)
{
   const char *threadgroup = "declare void @air.wg.barrier(i32, i32, i32) convergent\n";
   const nir_variable_mode device = nir_var_mem_ssbo | nir_var_mem_global;
   check_barrier(threadgroup, "call void @air.wg.barrier(i32 2, i32 5, i32 1) convergent",
                 SCOPE_WORKGROUP, SCOPE_WORKGROUP, nir_var_mem_shared);
   check_barrier(threadgroup, "call void @air.wg.barrier(i32 7, i32 5, i32 1) convergent",
                 SCOPE_WORKGROUP, SCOPE_WORKGROUP, device | nir_var_mem_shared | nir_var_image);
   check_barrier(threadgroup, "call void @air.wg.barrier(i32 0, i32 5, i32 1) convergent",
                 SCOPE_WORKGROUP, SCOPE_NONE, 0);
   check_barrier("declare void @air.wg.barrier(i32, i32) convergent\n",
                 "call void @air.wg.barrier(i32 1, i32 1) convergent",
                 SCOPE_WORKGROUP, SCOPE_WORKGROUP, device);
   check_barrier("declare void @air.simdgroup.barrier(i32, i32) convergent\n",
                 "call void @air.simdgroup.barrier(i32 2, i32 1) convergent",
                 SCOPE_SUBGROUP, SCOPE_WORKGROUP, nir_var_mem_shared);
   const char *fence = "declare void @air.atomic.fence(i32, i32, i32)\n";
   check_barrier(fence, "call void @air.atomic.fence(i32 1, i32 5, i32 2)", SCOPE_NONE, SCOPE_DEVICE,
                 device);
   check_barrier(fence, "call void @air.atomic.fence(i32 4, i32 5, i32 4)", SCOPE_NONE, SCOPE_SUBGROUP,
                 nir_var_image);
   /* A relaxed fence orders nothing. */
   check_barrier(fence, "call void @air.atomic.fence(i32 3, i32 0, i32 1)", SCOPE_NONE, SCOPE_NONE, 0);
   const char *refusals[][2] = {
      {threadgroup, "call void @air.wg.barrier(i32 8, i32 5, i32 1) convergent"},
      {threadgroup, "call void @air.wg.barrier(i32 2, i32 0, i32 1) convergent"},
      {threadgroup, "call void @air.wg.barrier(i32 2, i32 5, i32 2) convergent"},
      {"declare void @air.wg.barrier(i32, i32, i32)\n", "call void @air.wg.barrier(i32 2, i32 5, i32 1)"},
      {fence, "call void @air.atomic.fence(i32 1, i32 2, i32 2)"},
      {fence, "call void @air.atomic.fence(i32 1, i32 5, i32 0)"},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(refusals); i++) {
      char body[256];
      snprintf(body, sizeof(body), "%s\nret void\n", refusals[i][1]);
      refused(refusals[i][0], body, STELA_AIR_INSTRUCTION);
   }
}

static void
simd_functions_lower_to_subgroup_operations(void)
{
   nir_shader *shader = lowered(
      "declare i32 @air.simd_shuffle.u.i32(i32, i16)\n"
      "declare float @air.simd_shuffle_down.f.f32(float, i16)\n"
      "declare <2 x half> @air.quad_shuffle_xor.f.v2f16(<2 x half>, i16)\n"
      "declare i64 @air.simd_broadcast.u.i64(i64, i16)\n"
      "declare i32 @air.simd_sum.s.i32(i32)\n"
      "declare i16 @air.simd_max.s.i16(i16)\n"
      "declare float @air.quad_sum.f.f32(float)\n"
      "declare i32 @air.simd_prefix_exclusive_sum.u.i32(i32)\n"
      "declare i32 @air.quad_prefix_inclusive_product.u.i32(i32)\n"
      "declare i1 @air.simd_all(i1)\n"
      "declare i64 @air.simd_ballot(i1)\n"
      "declare i1 @air.quad_is_first()\n",
      "%a = call i32 @air.simd_shuffle.u.i32(i32 1, i16 3)\n"
      "%f = bitcast i32 %a to float\n"
      "%b = call float @air.simd_shuffle_down.f.f32(float %f, i16 1)\n"
      "%h = call <2 x half> @air.quad_shuffle_xor.f.v2f16(<2 x half> <half 0xH3C00, half 0xH4000>, i16 1)\n"
      "%w = call i64 @air.simd_broadcast.u.i64(i64 5, i16 0)\n"
      "%s = call i32 @air.simd_sum.s.i32(i32 %a)\n"
      "%m = call i16 @air.simd_max.s.i16(i16 -3)\n"
      "%q = call float @air.quad_sum.f.f32(float %b)\n"
      "%e = call i32 @air.simd_prefix_exclusive_sum.u.i32(i32 %s)\n"
      "%p = call i32 @air.quad_prefix_inclusive_product.u.i32(i32 %e)\n"
      "%v = icmp eq i32 %p, 0\n"
      "%all = call i1 @air.simd_all(i1 %v)\n"
      "%ballot = call i64 @air.simd_ballot(i1 %all)\n"
      "%first = call i1 @air.quad_is_first()\n"
      "%hb = bitcast <2 x half> %h to i32\n"
      "%wt = trunc i64 %w to i32\n%bt = trunc i64 %ballot to i32\n"
      "%me = sext i16 %m to i32\n%qb = bitcast float %q to i32\n"
      "%x0 = xor i32 %hb, %wt\n%x1 = xor i32 %x0, %bt\n%x2 = xor i32 %x1, %me\n"
      "%x3 = xor i32 %x2, %qb\n%fz = zext i1 %first to i32\n%x4 = xor i32 %x3, %fz\n"
      "store i32 %x4, ptr addrspace(1) %out, align 4\nret void\n");
   /* Data moves through 32-bit shuffles: one each for the shuffles, two for
    * the 64-bit broadcast and four for the quad scan. */
   assert(count(shader, nir_intrinsic_shuffle) == 9);
   assert(count(shader, nir_intrinsic_reduce) == 3);
   assert(count(shader, nir_intrinsic_exclusive_scan) == 1);
   assert(count(shader, nir_intrinsic_vote_all) == 1);
   assert(count(shader, nir_intrinsic_ballot) == 2);
   ralloc_free(shader);
   const char *refusals[][2] = {
      /* The lane is an i16. */
      {"declare i32 @air.simd_shuffle.u.i32(i32, i32)\n",
       "%a = call i32 @air.simd_shuffle.u.i32(i32 1, i32 3)\nret void\n"},
      /* Bitwise functions take integers. */
      {"declare float @air.simd_and.f.f32(float)\n",
       "%a = call float @air.simd_and.f.f32(float 1.0)\nret void\n"},
      {"declare i16 @air.simd_ballot(i1)\n", "%a = call i16 @air.simd_ballot(i1 true)\nret void\n"},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(refusals); i++)
      refused(refusals[i][0], refusals[i][1], STELA_AIR_TYPE);
   refused("declare i32 @air.simd_shuffle.f.i32(i32, i16)\n",
           "%a = call i32 @air.simd_shuffle.f.i32(i32 1, i16 3)\nret void\n", STELA_AIR_INSTRUCTION);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   llvm_atomics_are_relaxed_device_and_threadgroup_atomics();
   air_atomics_follow_their_names();
   refuses_unqualified_atomics();
   barriers_and_fences_follow_their_flags();
   simd_functions_lower_to_subgroup_operations();
   glsl_type_singleton_decref();
   puts("air sync: ok");
   return 0;
}
