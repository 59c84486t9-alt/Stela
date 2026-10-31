/* SPDX-License-Identifier: MIT */
/* Atomics, barriers, fences, SIMD-group functions and SIMD-group matrices.
 * Original LLVM IR fixtures in the forms air_to_nir.c, air_simd.c and
 * air_matrix.c document; no Apple output. */
#include "../metal_abi.h"
#include "compiler/air_to_nir.h"
#include "air_test_fixture.h"
#include "util/half_float.h"
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
      .workgroup_size = {64, 1, 1}, .max_instructions = 10000, .max_threadgroup_bytes = 256, .max_private_bytes = 64,
      .bind_buffer = bind, .binding_data = &primary,
      .fp_profile = STELA_AIR_FP_METAL,
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

/* The fixed address NAK's compiles and the SIMD-group runs bind the buffer
 * at; NAK takes lowered push constants. */
#define BUFFER 0x100000

static nir_def *
fixed_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   return nir_imm_int64(b, BUFFER); /* Fixture only. */
}

#ifdef STELA_AIR_TEST_NAK

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
      "declare float @air.atomic.global.sub.f32(ptr addrspace(1), float, i32, i32, i1)\n"
      "declare i32 @air.atomic.local.and.u.i32(ptr addrspace(3), i32, i32, i32, i1)\n",
      "%a = call i32 @air.atomic.global.add.u.i32(ptr addrspace(1) %out, i32 1, i32 0, i32 3, i1 true)\n"
      "%b = call i32 @air.atomic.global.max.s.i32(ptr addrspace(1) %out, i32 %a, i32 0, i32 3, i1 true)\n"
      "%c = call i32 @air.atomic.global.min.u.i32(ptr addrspace(1) %out, i32 %b, i32 0, i32 2, i1 false)\n"
      "%d = call i32 @air.atomic.global.xchg.i32(ptr addrspace(1) %out, i32 %c, i32 0, i32 3, i1 true)\n"
      "%e = call float @air.atomic.global.sub.f32(ptr addrspace(1) %out, float 2.0, i32 0, i32 3, i1 true)\n"
      "%p = getelementptr [64 x i32], ptr addrspace(3) @s, i64 0, i64 1\n"
      "%f = call i32 @air.atomic.local.and.u.i32(ptr addrspace(3) %p, i32 %d, i32 0, i32 1, i1 true)\n"
      "store i32 %f, ptr addrspace(1) %out, align 4\nret void\n",
      expected, ARRAY_SIZE(expected));
   /* Loads and stores are coherent accesses; a compare-exchange compares
    * and receives through its thread pointer; 64-bit min and max return
    * nothing. */
   const nir_atomic_op forms[] = {nir_atomic_op_cmpxchg, nir_atomic_op_umax};
   expect_atomics(
      "declare i32 @air.atomic.global.load.i32(ptr addrspace(1), i32, i32, i1)\n"
      "declare void @air.atomic.global.store.i32(ptr addrspace(1), i32, i32, i32, i1)\n"
      "declare i32 @air.atomic.global.cmpxchg.weak.i32(ptr addrspace(1), ptr, i32, i32, i32, i32, i1)\n"
      "declare void @air.atomic.global.max.u.i64(ptr addrspace(1), i64, i32, i32, i1)\n",
      "%x = alloca i32, align 4\n"
      "%l = call i32 @air.atomic.global.load.i32(ptr addrspace(1) %out, i32 0, i32 2, i1 true)\n"
      "store i32 %l, ptr %x, align 4\n"
      "%o = call i32 @air.atomic.global.cmpxchg.weak.i32(ptr addrspace(1) %out, ptr %x, i32 7,"
      " i32 0, i32 0, i32 2, i1 true)\n"
      "%e = load i32, ptr %x, align 4\n%s = add i32 %o, %e\n"
      "call void @air.atomic.global.store.i32(ptr addrspace(1) %out, i32 %s, i32 0, i32 2, i1 true)\n"
      "%wide = zext i32 %s to i64\n"
      "call void @air.atomic.global.max.u.i64(ptr addrspace(1) %out, i64 %wide, i32 0, i32 2, i1 true)\n"
      "ret void\n",
      forms, ARRAY_SIZE(forms));
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
   refused("declare float @air.atomic.global.max.f32(ptr addrspace(1), float, i32, i32, i1)\n",
           "%a = call float @air.atomic.global.max.f32(ptr addrspace(1) %out, float 1.0, i32 0, i32 3, i1 true)\nret void\n",
           STELA_AIR_INSTRUCTION);
   /* A compare-exchange's expected value is the thread's. */
   refused("declare i32 @air.atomic.global.cmpxchg.weak.i32(ptr addrspace(1), ptr addrspace(1), i32, i32, i32, i32, i1)\n",
           "%a = call i32 @air.atomic.global.cmpxchg.weak.i32(ptr addrspace(1) %out, ptr addrspace(1) %out,"
           " i32 1, i32 0, i32 0, i32 2, i1 true)\nret void\n",
           STELA_AIR_MEMORY);
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
   const char *simdgroup = "declare void @air.simdgroup.barrier(i32, i32) convergent\n";
   check_barrier(simdgroup, "call void @air.simdgroup.barrier(i32 2, i32 4) convergent",
                 SCOPE_SUBGROUP, SCOPE_SUBGROUP, nir_var_mem_shared);
   check_barrier(simdgroup, "call void @air.simdgroup.barrier(i32 0, i32 4) convergent",
                 SCOPE_SUBGROUP, SCOPE_NONE, 0);
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
      {simdgroup, "call void @air.simdgroup.barrier(i32 2, i32 2) convergent"},
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
      "declare float @air.simd_shuffle_down.f32(float, i16)\n"
      "declare <2 x half> @air.quad_shuffle_xor.v2f16(<2 x half>, i16)\n"
      "declare i64 @air.simd_broadcast.u.i64(i64, i16)\n"
      "declare i32 @air.simd_sum.s.i32(i32)\n"
      "declare i16 @air.simd_max.s.i16(i16)\n"
      "declare float @air.quad_sum.f32(float)\n"
      "declare i32 @air.simd_prefix_exclusive_sum.u.i32(i32)\n"
      "declare i32 @air.quad_prefix_inclusive_product.u.i32(i32)\n"
      "declare i1 @air.simd_all(i1)\n"
      "declare i64 @air.simd_ballot.i64(i1)\n"
      "declare i16 @air.quad_ballot(i1)\n"
      "declare i64 @air.simd_active_threads_mask.i64()\n"
      "declare i16 @air.quad_active_threads_mask()\n"
      "declare i1 @air.simd_is_helper_thread()\n"
      "declare i1 @air.quad_is_first()\n"
      "declare float @air.simd_shuffle_and_fill_down.f32(float, float, i16, i16)\n"
      "declare i32 @air.quad_shuffle_and_fill_up.u.i32(i32, i32, i16, i16)\n"
      "declare i16 @air.get_simdgroup_size.i16()\n",
      "%a = call i32 @air.simd_shuffle.u.i32(i32 1, i16 3)\n"
      "%f = bitcast i32 %a to float\n"
      "%b = call float @air.simd_shuffle_down.f32(float %f, i16 1)\n"
      "%h = call <2 x half> @air.quad_shuffle_xor.v2f16(<2 x half> <half 0xH3C00, half 0xH4000>, i16 1)\n"
      "%w = call i64 @air.simd_broadcast.u.i64(i64 5, i16 0)\n"
      "%s = call i32 @air.simd_sum.s.i32(i32 %a)\n"
      "%m = call i16 @air.simd_max.s.i16(i16 -3)\n"
      "%q = call float @air.quad_sum.f32(float %b)\n"
      "%e = call i32 @air.simd_prefix_exclusive_sum.u.i32(i32 %s)\n"
      "%p = call i32 @air.quad_prefix_inclusive_product.u.i32(i32 %e)\n"
      "%v = icmp eq i32 %p, 0\n"
      "%all = call i1 @air.simd_all(i1 %v)\n"
      "%ballot = call i64 @air.simd_ballot.i64(i1 %all)\n"
      "%quad_ballot = call i16 @air.quad_ballot(i1 %all)\n"
      "%active = call i64 @air.simd_active_threads_mask.i64()\n"
      "%quad_active = call i16 @air.quad_active_threads_mask()\n"
      "%helper = call i1 @air.simd_is_helper_thread()\n"
      "%first = call i1 @air.quad_is_first()\n"
      "%hb = bitcast <2 x half> %h to i32\n"
      "%wt = trunc i64 %w to i32\n%bt = trunc i64 %ballot to i32\n"
      "%me = sext i16 %m to i32\n%qb = bitcast float %q to i32\n"
      "%x0 = xor i32 %hb, %wt\n%x1 = xor i32 %x0, %bt\n%x2 = xor i32 %x1, %me\n"
      "%x3 = xor i32 %x2, %qb\n%fz = zext i1 %first to i32\n%x4 = xor i32 %x3, %fz\n"
      "%lanes = call i16 @air.get_simdgroup_size.i16()\n"
      "%fd = call float @air.simd_shuffle_and_fill_down.f32(float %f, float %q, i16 2, i16 %lanes)\n"
      "%fu = call i32 @air.quad_shuffle_and_fill_up.u.i32(i32 %x4, i32 %a, i16 1, i16 4)\n"
      "%fb = bitcast float %fd to i32\n%x5 = xor i32 %fu, %fb\n"
      "store i32 %x5, ptr addrspace(1) %out, align 4\nret void\n");
   /* Data moves through 32-bit shuffles: one each for the shuffles, two for
    * the 64-bit broadcast, four for the quad scan and two, of the value and
    * of the fill, for each shuffle and fill. */
   assert(count(shader, nir_intrinsic_shuffle) == 13);
   assert(count(shader, nir_intrinsic_reduce) == 3);
   assert(count(shader, nir_intrinsic_exclusive_scan) == 1);
   assert(count(shader, nir_intrinsic_vote_all) == 1);
   assert(count(shader, nir_intrinsic_ballot) == 5);
   ralloc_free(shader);
   const char *refusals[][2] = {
      /* The lane is an i16. */
      {"declare i32 @air.simd_shuffle.u.i32(i32, i32)\n",
       "%a = call i32 @air.simd_shuffle.u.i32(i32 1, i32 3)\nret void\n"},
      /* Bitwise functions take integers. */
      {"declare float @air.simd_and.f32(float)\n",
       "%a = call float @air.simd_and.f32(float 1.0)\nret void\n"},
      {"declare i32 @air.quad_ballot(i1)\n", "%a = call i32 @air.quad_ballot(i1 true)\nret void\n"},
      {"declare i16 @air.simd_ballot.i16(i1)\n",
       "%a = call i16 @air.simd_ballot.i16(i1 true)\nret void\n"},
      /* A fill's delta and modulo are i16s. */
      {"declare float @air.simd_shuffle_and_fill_up.f32(float, float, i16, i32)\n",
       "%a = call float @air.simd_shuffle_and_fill_up.f32(float 1.0, float 2.0, i16 1, i32 4)\n"
       "ret void\n"},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(refusals); i++)
      refused(refusals[i][0], refusals[i][1], STELA_AIR_TYPE);
   /* Integers carry their sign. */
   refused("declare i32 @air.simd_shuffle.i32(i32, i16)\n",
           "%a = call i32 @air.simd_shuffle.i32(i32 1, i16 3)\nret void\n", STELA_AIR_INSTRUCTION);
}

enum { SIMD_LANES = 32, MAX_SHUFFLES = 128 };

/* Rewrites a lane's uses of `def` with the `bits` constant `value`; whether
 * it had any. */
static bool
fold_use(nir_def *def, uint64_t value)
{
   if (nir_def_is_unused(def))
      return false;
   nir_builder b = nir_builder_at(nir_after_instr(nir_def_instr(def)));
   nir_def_rewrite_uses(def, nir_imm_intN_t(&b, value, def->bit_size));
   return true;
}

/* A lane's shuffle as witnesses constant folding leaves alone: its data and
 * source lane stored to scratch, and its result loaded from scratch. */
struct shuffle {
   nir_intrinsic_instr *data, *source, *result;
};

/* Runs `body` on one SIMD-group of 32 lanes over `memory`, the buffer at
 * BUFFER: each lane is a clone given its index, whose global loads read
 * `memory` and whose shuffles read the other lanes' values, folded until
 * every one is known. Each lane's stores then write `memory`. */
static void
run_simdgroup(const char *declarations, const char *body, uint8_t *memory, size_t size)
{
   struct stela_air_error error;
   nir_shader *shader = translate(declarations, body, &nir_options, fixed_buffer, &error);
   assert(shader);
#ifdef STELA_AIR_TEST_NAK
   stela_air_test_nak(nak_translate, &(struct fixture){declarations, body});
#endif
   nir_shader *lanes[SIMD_LANES];
   static struct shuffle shuffles[SIMD_LANES][MAX_SHUFFLES];
   unsigned count = 0;
   for (unsigned l = 0; l < SIMD_LANES; l++) {
      lanes[l] = nir_shader_clone(NULL, shader);
      count = 0;
      nir_foreach_function_impl(impl, lanes[l]) {
         nir_builder b = nir_builder_create(impl);
         nir_foreach_block(block, impl) {
            nir_foreach_instr_safe(instr, block) {
               if (instr->type != nir_instr_type_intrinsic)
                  continue;
               nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
               if (intrinsic->intrinsic == nir_intrinsic_load_subgroup_invocation) {
                  fold_use(&intrinsic->def, l);
               } else if (intrinsic->intrinsic == nir_intrinsic_shuffle) {
                  assert(count < MAX_SHUFFLES && intrinsic->def.bit_size == 32 &&
                         intrinsic->def.num_components == 1);
                  b.cursor = nir_before_instr(instr);
                  struct shuffle *s = &shuffles[l][count];
                  nir_def *offset = nir_imm_int(&b, 8 * count++);
                  s->data = nir_store_scratch(&b, intrinsic->src[0].ssa, offset, .align_mul = 4);
                  s->source = nir_store_scratch(&b, intrinsic->src[1].ssa, nir_iadd_imm(&b, offset, 4),
                                                .align_mul = 4);
                  nir_def *result = nir_load_scratch(&b, 1, 32, offset, .align_mul = 4);
                  s->result = nir_instr_as_intrinsic(nir_def_instr(result));
                  nir_def_replace(&intrinsic->def, result);
               }
            }
         }
      }
   }
   ralloc_free(shader);
   for (bool progress = true; progress;) {
      progress = false;
      for (unsigned l = 0; l < SIMD_LANES; l++) {
         while (nir_opt_constant_folding(lanes[l]) | nir_opt_dead_cf(lanes[l]))
            ;
         nir_foreach_function_impl(impl, lanes[l]) {
            nir_foreach_block(block, impl) {
               nir_foreach_instr(instr, block) {
                  if (instr->type != nir_instr_type_intrinsic)
                     continue;
                  nir_intrinsic_instr *load = nir_instr_as_intrinsic(instr);
                  if (load->intrinsic != nir_intrinsic_load_global || !nir_src_is_const(load->src[0]))
                     continue;
                  uint64_t offset = nir_src_as_uint(load->src[0]) - BUFFER, value = 0;
                  assert(load->def.num_components == 1 && offset + load->def.bit_size / 8 <= size);
                  memcpy(&value, memory + offset, load->def.bit_size / 8);
                  progress |= fold_use(&load->def, value);
               }
            }
         }
      }
      for (unsigned l = 0; l < SIMD_LANES; l++) {
         for (unsigned k = 0; k < count; k++) {
            const struct shuffle *s = &shuffles[l][k];
            if (!nir_src_is_const(s->source->src[0]))
               continue;
            unsigned source = nir_src_as_uint(s->source->src[0]);
            assert(source < SIMD_LANES);
            nir_src *data = &shuffles[source][k].data->src[0];
            if (nir_src_is_const(*data))
               progress |= fold_use(&s->result->def, nir_src_as_uint(*data));
         }
      }
   }
   for (unsigned l = 0; l < SIMD_LANES; l++) {
      nir_foreach_function_impl(impl, lanes[l]) {
         nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
               if (instr->type != nir_instr_type_intrinsic)
                  continue;
               nir_intrinsic_instr *store = nir_instr_as_intrinsic(instr);
               if (store->intrinsic != nir_intrinsic_store_global)
                  continue;
               if (!nir_src_is_const(store->src[0]) || !nir_src_is_const(store->src[1]))
                  nir_print_shader(lanes[l], stderr);
               assert(nir_src_is_const(store->src[0]) && nir_src_is_const(store->src[1]));
               uint64_t value = nir_src_as_uint(store->src[0]);
               uint64_t offset = nir_src_as_uint(store->src[1]) - BUFFER;
               unsigned bytes = store->src[0].ssa->bit_size / 8;
               assert(store->src[0].ssa->num_components == 1 && offset + bytes <= size);
               memcpy(memory + offset, &value, bytes);
            }
         }
      }
      ralloc_free(lanes[l]);
   }
}

static float
float_at(const uint8_t *memory, size_t index)
{
   float value;
   memcpy(&value, memory + 4 * index, sizeof(value));
   return value;
}

static void
put_float(uint8_t *memory, size_t index, float value)
{
   memcpy(memory + 4 * index, &value, sizeof(value));
}

#define MATRIX_DECLARATIONS                                                                        \
   "declare <64 x float> @air.simdgroup_matrix_8x8_load.v64f32.p1f32(ptr addrspace(1), i64,"      \
   " <2 x i64>, i1)\n"                                                                             \
   "declare void @air.simdgroup_matrix_8x8_store.v64f32.p1f32(<64 x float>, ptr addrspace(1),"    \
   " i64, <2 x i64>, i1)\n"                                                                        \
   "declare <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float)\n"               \
   "declare <64 x float> @air.simdgroup_matrix_8x8_init_diag.v64f32.f32(float)\n"                 \
   "declare <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"                           \
   ".v64f32.v64f32.v64f32.v64f32(<64 x float>, <64 x float>, <64 x float>)\n"

/* a * b + 0.5, row-major at stride 8, against the same product on the
 * CPU. */
static void
matrix_products_follow_rows_and_columns(void)
{
   uint8_t memory[1024] = {0};
   for (unsigned i = 0; i < 64; i++) {
      put_float(memory, i, (float)(i % 11) - 3.0f);
      put_float(memory, 64 + i, (float)(i % 7) * 0.5f);
   }
   run_simdgroup(MATRIX_DECLARATIONS,
                 "%a = call <64 x float> @air.simdgroup_matrix_8x8_load.v64f32.p1f32(ptr addrspace(1)"
                 " %out, i64 8, <2 x i64> zeroinitializer, i1 false)\n"
                 "%pb = getelementptr float, ptr addrspace(1) %out, i64 64\n"
                 "%b = call <64 x float> @air.simdgroup_matrix_8x8_load.v64f32.p1f32(ptr addrspace(1)"
                 " %pb, i64 8, <2 x i64> zeroinitializer, i1 false)\n"
                 "%c = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float 0.5)\n"
                 "%d = call <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"
                 ".v64f32.v64f32.v64f32.v64f32(<64 x float> %a, <64 x float> %b, <64 x float> %c)\n"
                 "%pd = getelementptr float, ptr addrspace(1) %out, i64 128\n"
                 "call void @air.simdgroup_matrix_8x8_store.v64f32.p1f32(<64 x float> %d,"
                 " ptr addrspace(1) %pd, i64 8, <2 x i64> zeroinitializer, i1 false)\n"
                 "ret void\n",
                 memory, sizeof(memory));
   for (unsigned r = 0; r < 8; r++) {
      for (unsigned c = 0; c < 8; c++) {
         float sum = 0.5f;
         for (unsigned k = 0; k < 8; k++)
            sum += float_at(memory, 8 * r + k) * float_at(memory, 64 + 8 * k + c);
         assert(float_at(memory, 128 + 8 * r + c) == sum);
      }
   }
}

/* Loads and stores place the matrix at their origin's column x and row y in
 * rows of their stride, transposed when asked; a diagonal is the identity
 * scaled. */
static void
matrix_memory_takes_origins_strides_and_transposes(void)
{
   uint8_t memory[2048] = {0};
   for (unsigned i = 0; i < 160; i++)
      put_float(memory, i, (float)i);
   run_simdgroup(MATRIX_DECLARATIONS,
                 "%b = call <64 x float> @air.simdgroup_matrix_8x8_load.v64f32.p1f32(ptr addrspace(1)"
                 " %out, i64 16, <2 x i64> <i64 1, i64 2>, i1 true)\n"
                 "%i = call <64 x float> @air.simdgroup_matrix_8x8_init_diag.v64f32.f32(float 1.0)\n"
                 "%d = call <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"
                 ".v64f32.v64f32.v64f32.v64f32(<64 x float> %i, <64 x float> %b,"
                 " <64 x float> zeroinitializer)\n"
                 "%pd = getelementptr float, ptr addrspace(1) %out, i64 192\n"
                 "call void @air.simdgroup_matrix_8x8_store.v64f32.p1f32(<64 x float> %d,"
                 " ptr addrspace(1) %pd, i64 12, <2 x i64> <i64 3, i64 1>, i1 true)\n"
                 "%t = call <64 x float> @air.simdgroup_matrix_8x8_init_diag.v64f32.f32(float 3.0)\n"
                 "%pt = getelementptr float, ptr addrspace(1) %out, i64 320\n"
                 "call void @air.simdgroup_matrix_8x8_store.v64f32.p1f32(<64 x float> %t,"
                 " ptr addrspace(1) %pt, i64 8, <2 x i64> zeroinitializer, i1 false)\n"
                 "ret void\n",
                 memory, sizeof(memory));
   for (unsigned r = 0; r < 8; r++) {
      for (unsigned c = 0; c < 8; c++) {
         /* Element (r, c) loads from row 2 + c, column 1 + r and stores to
          * row 1 + c, column 3 + r. */
         assert(float_at(memory, 192 + (1 + c) * 12 + 3 + r) == (float)((2 + c) * 16 + 1 + r));
         assert(float_at(memory, 320 + 8 * r + c) == (r == c ? 3.0f : 0.0f));
      }
   }
}

/* Half and bfloat products accumulate in single precision; a half result
 * rounds once; a thread's elements 0 and 1 are its storage's. */
static void
matrix_elements_and_narrow_types(void)
{
   uint8_t memory[2048] = {0};
   for (unsigned i = 0; i < 64; i++) {
      uint16_t half = _mesa_float_to_half((float)(i % 5) - 2.0f);
      float wide = (float)(i % 3) + 1.0f;
      uint32_t bits;
      memcpy(&bits, &wide, sizeof(bits));
      uint16_t bfloat = bits >> 16;
      memcpy(memory + 2 * i, &half, 2);
      memcpy(memory + 128 + 2 * i, &bfloat, 2);
   }
   run_simdgroup(
      "declare <64 x half> @air.simdgroup_matrix_8x8_load.v64f16.p1f16(ptr addrspace(1), i64,"
      " <2 x i64>, i1)\n"
      "declare <64 x bfloat> @air.simdgroup_matrix_8x8_load.v64bf16.p1bf16(ptr addrspace(1), i64,"
      " <2 x i64>, i1)\n"
      "declare <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"
      ".v64f32.v64f16.v64f16.v64f32(<64 x half>, <64 x half>, <64 x float>)\n"
      "declare <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"
      ".v64f32.v64bf16.v64bf16.v64f32(<64 x bfloat>, <64 x bfloat>, <64 x float>)\n"
      "declare <64 x half> @air.simdgroup_matrix_8x8_init_diag.v64f16.f16(half)\n"
      "declare <64 x half> @air.simdgroup_matrix_8x8_multiply_accumulate"
      ".v64f16.v64f16.v64f16.v64f16(<64 x half>, <64 x half>, <64 x half>)\n"
      "declare void @air.simdgroup_matrix_8x8_store.v64f16.p1f16(<64 x half>, ptr addrspace(1),"
      " i64, <2 x i64>, i1)\n"
      "declare void @air.simdgroup_matrix_8x8_store.v64f32.p1f32(<64 x float>, ptr addrspace(1),"
      " i64, <2 x i64>, i1)\n",
      "%a = call <64 x half> @air.simdgroup_matrix_8x8_load.v64f16.p1f16(ptr addrspace(1) %out,"
      " i64 8, <2 x i64> zeroinitializer, i1 false)\n"
      "%pb = getelementptr i8, ptr addrspace(1) %out, i64 128\n"
      "%b = call <64 x bfloat> @air.simdgroup_matrix_8x8_load.v64bf16.p1bf16(ptr addrspace(1) %pb,"
      " i64 8, <2 x i64> zeroinitializer, i1 false)\n"
      "%aa = call <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"
      ".v64f32.v64f16.v64f16.v64f32(<64 x half> %a, <64 x half> %a, <64 x float> zeroinitializer)\n"
      "%d = call <64 x float> @air.simdgroup_matrix_8x8_multiply_accumulate"
      ".v64f32.v64bf16.v64bf16.v64f32(<64 x bfloat> %b, <64 x bfloat> %b, <64 x float> %aa)\n"
      "%e = extractelement <64 x float> %d, i64 1\n"
      "%f = insertelement <64 x float> %d, float %e, i64 0\n"
      "%pd = getelementptr i8, ptr addrspace(1) %out, i64 512\n"
      "call void @air.simdgroup_matrix_8x8_store.v64f32.p1f32(<64 x float> %f, ptr addrspace(1) %pd,"
      " i64 8, <2 x i64> zeroinitializer, i1 false)\n"
      "%i = call <64 x half> @air.simdgroup_matrix_8x8_init_diag.v64f16.f16(half 0xH3C00)\n"
      "%h = call <64 x half> @air.simdgroup_matrix_8x8_multiply_accumulate"
      ".v64f16.v64f16.v64f16.v64f16(<64 x half> %a, <64 x half> %i, <64 x half> zeroinitializer)\n"
      "%ph = getelementptr i8, ptr addrspace(1) %out, i64 1024\n"
      "call void @air.simdgroup_matrix_8x8_store.v64f16.p1f16(<64 x half> %h, ptr addrspace(1) %ph,"
      " i64 8, <2 x i64> zeroinitializer, i1 false)\n"
      "ret void\n",
      memory, sizeof(memory));
   for (unsigned r = 0; r < 8; r++) {
      for (unsigned c = 0; c < 8; c++) {
         float sum = 0.0f;
         for (unsigned k = 0; k < 8; k++) {
            float a = (float)((8 * r + k) % 5) - 2.0f, x = (float)((8 * k + c) % 5) - 2.0f;
            float b = (float)((8 * r + k) % 3) + 1.0f, y = (float)((8 * k + c) % 3) + 1.0f;
            sum += a * x + b * y;
         }
         /* Each even column took its odd neighbour's element. */
         float expected = sum;
         if (!(c & 1)) {
            expected = 0.0f;
            for (unsigned k = 0; k < 8; k++) {
               float a = (float)((8 * r + k) % 5) - 2.0f, x = (float)((8 * k + c + 1) % 5) - 2.0f;
               float b = (float)((8 * r + k) % 3) + 1.0f, y = (float)((8 * k + c + 1) % 3) + 1.0f;
               expected += a * x + b * y;
            }
         }
         assert(float_at(memory, 128 + 8 * r + c) == expected);
         uint16_t half;
         memcpy(&half, memory + 1024 + 2 * (8 * r + c), 2);
         assert(half == _mesa_float_to_half((float)((8 * r + c) % 5) - 2.0f));
      }
   }
}

static void
refuses_misused_matrices(void)
{
   const char *refusals[][3] = {
      /* A thread holds two elements. */
      {MATRIX_DECLARATIONS,
       "%m = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float 1.0)\n"
       "%e = extractelement <64 x float> %m, i64 2\nret void\n", "instruction"},
      {MATRIX_DECLARATIONS,
       "%m = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float 1.0)\n"
       "%e = shufflevector <64 x float> %m, <64 x float> poison, <2 x i32> <i32 0, i32 64>\n"
       "ret void\n", "instruction"},
      /* Matrices are stored to device or threadgroup memory. */
      {"declare void @air.simdgroup_matrix_8x8_store.v64f32.p2f32(<64 x float>, ptr addrspace(2),"
       " i64, <2 x i64>, i1)\n",
       "call void @air.simdgroup_matrix_8x8_store.v64f32.p2f32(<64 x float> zeroinitializer,"
       " ptr addrspace(2) null, i64 8, <2 x i64> zeroinitializer, i1 false)\nret void\n", "type"},
      /* A fill is of the matrix's element. */
      {"declare <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(half)\n",
       "%m = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(half 0xH3C00)\n"
       "ret void\n", "type"},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(refusals); i++)
      refused(refusals[i][0], refusals[i][1],
              refusals[i][2][0] == 'i' ? STELA_AIR_INSTRUCTION : STELA_AIR_TYPE);
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
   matrix_products_follow_rows_and_columns();
   matrix_memory_takes_origins_strides_and_transposes();
   matrix_elements_and_narrow_types();
   refuses_misused_matrices();
   glsl_type_singleton_decref();
   puts("air sync: ok");
   return 0;
}
