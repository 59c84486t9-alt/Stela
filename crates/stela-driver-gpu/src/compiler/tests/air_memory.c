/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Thread memory (allocas), LLVM's memory intrinsics, constant data
 * (initialized constant globals) and constant buffers. Original LLVM IR
 * fixtures; no Apple output. */
#include "../metal_abi.h"
#include "compiler/air_to_nir.h"
#include "air_test_fixture.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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

/* A kernel's argument list, its device buffer `out` (!40) and the versions. */
#define KERNEL_ARGUMENTS(list) \
   "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{" list "}\n" \
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\"," \
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\"," \
   " i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n" \
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n" \
   "!air.compile_options = !{!23, !24, !25}\n" \
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n" \
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n" \
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n" \
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n"

static const char *metadata = KERNEL_ARGUMENTS("!40");

static const char *intrinsics =
   "declare void @llvm.lifetime.start.p0(i64, ptr)\n"
   "declare void @llvm.lifetime.end.p0(i64, ptr)\n"
   "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n"
   "declare void @llvm.memset.p1.i64(ptr addrspace(1), i8, i64, i1)\n"
   "declare void @llvm.memcpy.p0.p2.i64(ptr, ptr addrspace(2), i64, i1)\n"
   "declare void @llvm.memcpy.p1.p0.i64(ptr addrspace(1), ptr, i64, i1)\n"
   "declare void @llvm.memcpy.p2.p0.i64(ptr addrspace(2), ptr, i64, i1)\n"
   "declare void @llvm.memmove.p1.p1.i64(ptr addrspace(1), ptr addrspace(1), i64, i1)\n";

static const char *table =
   "@table = internal addrspace(2) constant [4 x float] "
   "[float 1.0, float 2.0, float 3.0, float 4.0], align 4\n";

struct limits {
   unsigned private_bytes, constant_bytes;
};

static const struct limits defaults = {.private_bytes = 1024, .constant_bytes = 65536};

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};

static nir_shader *
translate_kernel(const char *declarations, const char *definition, const char *kernel_metadata,
                 const nir_shader_compiler_options *options, stela_air_bind_buffer bind,
                 const struct limits *limits, struct stela_air_error *error)
{
   LLVMMemoryBufferRef input =
      stela_air_test_custom_bitcode(module, declarations, definition, kernel_metadata);
   const struct stela_air_options o = {
      .workgroup_size = {1, 1, 1}, .max_instructions = 10000,
      .bind_buffer = bind, .binding_data = &primary,
      .fp_profile = STELA_AIR_FP_METAL,
      .max_private_bytes = limits->private_bytes, .max_constant_bytes = limits->constant_bytes,
   };
   *error = (struct stela_air_error){0};
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static nir_shader *
translate(const char *globals, const char *body, const nir_shader_compiler_options *options,
          stela_air_bind_buffer bind, const struct limits *limits, struct stela_air_error *error)
{
   char definition[16384], declarations[4096];
   snprintf(definition, sizeof(definition), "define void @kernel(ptr addrspace(1) %%out) {\n%s}\n", body);
   snprintf(declarations, sizeof(declarations), "%s%s", globals, intrinsics);
   return translate_kernel(declarations, definition, metadata, options, bind, limits, error);
}

#ifdef STELA_AIR_TEST_NAK
/* NAK takes lowered push constants, so its compiles bind a fixed address. */
static nir_def *
fixed_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   return nir_imm_int64(b, 0x100000); /* Compile fixture only. */
}

struct fixture {
   const char *globals, *body;
};

static nir_shader *
nak_translate(const nir_shader_compiler_options *options, void *data)
{
   const struct fixture *fixture = data;
   struct stela_air_error error;
   nir_shader *shader = translate(fixture->globals, fixture->body, options, fixed_buffer, &defaults, &error);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", fixture->body, error.kind, error.detail);
   return shader;
}
#endif

static nir_shader *
lowered(const char *globals, const char *body)
{
   struct stela_air_error error;
   nir_shader *shader = translate(globals, body, &nir_options, stela_metal_bind_buffer, &defaults, &error);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", body, error.kind, error.detail);
   assert(shader);
   return shader;
}

/* Thread-memory fixtures also compile with NAK. NVK, not NAK, lowers
 * load_constant into its shader-data constant buffer. */
static nir_shader *
compiled(const char *globals, const char *body)
{
#ifdef STELA_AIR_TEST_NAK
   stela_air_test_nak(nak_translate, &(struct fixture){globals, body});
#endif
   return lowered(globals, body);
}

static void
refused(const char *globals, const char *body, const struct limits *limits,
        enum stela_air_error_kind kind)
{
   struct stela_air_error error;
   nir_shader *shader = translate(globals, body, &nir_options, stela_metal_bind_buffer, limits, &error);
   if (shader || error.kind != kind)
      fprintf(stderr, "%s: wanted %u, got %u %s\n", body, kind, error.kind, error.detail);
   assert(!shader && error.kind == kind && error.detail[0]);
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

/* The intrinsics `op` of the shader, in order. */
static unsigned
intrinsics_of(nir_shader *shader, nir_intrinsic_op op, nir_intrinsic_instr **found, unsigned capacity)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic && nir_instr_as_intrinsic(instr)->intrinsic == op) {
               assert(n < capacity);
               found[n++] = nir_instr_as_intrinsic(instr);
            }
         }
      }
   }
   return n;
}

/* An entry-block alloca becomes scratch of its aligned size, indexed
 * dynamically, with no variable left for the backend to lay out again. */
static void
thread_memory_lowers_to_scratch(void)
{
   nir_shader *shader = compiled("",
      "%a = alloca [4 x i32], align 4\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%p = getelementptr [4 x i32], ptr %a, i32 0, i32 %i\n"
      "store i32 7, ptr %p, align 4\n"
      "%q = getelementptr [4 x i32], ptr %a, i32 0, i32 1\n"
      "%v = load i32, ptr %q, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   assert(shader->scratch_size == 16);
   assert(count(shader, nir_intrinsic_store_scratch) == 1 && count(shader, nir_intrinsic_load_scratch) == 1);
   assert(exec_list_is_empty(&nir_shader_get_entrypoint(shader)->locals));
   ralloc_free(shader);

   /* Allocations keep their alignment; a pointer PHI keeps its allocation. */
   shader = compiled("",
      "entry:\n%a = alloca i32, align 4\n%b = alloca <4 x float>, align 16\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n%c = icmp eq i32 %i, 0\n"
      "br i1 %c, label %then, label %join\n"
      "then:\n%h = getelementptr i8, ptr %b, i64 4\nbr label %join\n"
      "join:\n%p = phi ptr [%b, %entry], [%h, %then]\n"
      "store i32 1, ptr %a, align 4\nstore i32 2, ptr %p, align 4\n"
      "%v = load i32, ptr %p, align 4\nstore i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   assert(shader->scratch_size == 20 || shader->scratch_size == 32);
   ralloc_free(shader);

   refused("", "br label %b\nb:\n%a = alloca i32, align 4\nstore i32 1, ptr %a, align 4\nret void\n",
           &defaults, STELA_AIR_MEMORY);
   refused("", "%n = load i32, ptr addrspace(1) %out, align 4\n%a = alloca i32, i32 %n, align 4\n"
           "store i32 1, ptr %a, align 4\nret void\n", &defaults, STELA_AIR_MEMORY);
   refused("", "%a = alloca i32, align 4\n%o = atomicrmw add ptr %a, i32 1 monotonic, align 4\nret void\n",
           &defaults, STELA_AIR_MEMORY);
   refused("", "%a = alloca i32, align 4\n%v = load atomic i32, ptr %a monotonic, align 4\n"
           "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n", &defaults, STELA_AIR_MEMORY);
   const char *five = "%a = alloca [5 x i32], align 4\nstore i32 1, ptr %a, align 4\nret void\n";
   refused("", five, &(struct limits){.private_bytes = 16}, STELA_AIR_LIMIT);
   refused("", five, &(struct limits){0}, STELA_AIR_LIMIT);
}

#define MATRIX_GLOBALS                                                                             \
   "%m = type { <64 x float> }\n"                                                                  \
   "declare <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float)\n"

/* An allocation of SIMD-group matrices, each loaded and stored whole, keeps
 * only the thread elements: 8 of each 256-byte matrix, at a 32nd of its
 * offset. 4096 bytes of matrices fit a 1024-byte limit as 128. */
static void
matrix_thread_memory_keeps_thread_elements(void)
{
   const char *body =
      "%a = alloca [4 x [4 x %m]], align 256\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%c = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float 2.0)\n"
      "call void @llvm.lifetime.start.p0(i64 4096, ptr %a)\n"
      "%p = getelementptr [4 x [4 x %m]], ptr %a, i64 0, i32 %i, i32 1, i32 0\n"
      "store <64 x float> %c, ptr %p, align 256\n"
      "%q = getelementptr [4 x [4 x %m]], ptr %a, i64 0, i64 2, i64 3\n"
      "%v = load <64 x float>, ptr %q, align 256\n"
      "%e = extractelement <64 x float> %v, i32 1\n"
      "store float %e, ptr addrspace(1) %out, align 4\n"
      "call void @llvm.lifetime.end.p0(i64 4096, ptr %a)\nret void\n";
   nir_shader *shader = compiled(MATRIX_GLOBALS, body);
   assert(shader->scratch_size == 128);
   nir_opt_constant_folding(shader);
   nir_intrinsic_instr *loads[1];
   assert(intrinsics_of(shader, nir_intrinsic_load_scratch, loads, 1) == 1);
   /* Matrix (2, 3) at byte (4 * 2 + 3) * 256, kept at 88. */
   assert(nir_src_is_const(loads[0]->src[0]) && nir_src_as_uint(loads[0]->src[0]) == 88);
   assert(loads[0]->def.num_components == 2 && loads[0]->def.bit_size == 32);
   assert(count(shader, nir_intrinsic_store_scratch) == 1);
   ralloc_free(shader);

   /* A float inside a matrix, or a matrix at half its size, keeps the
    * whole layout, which passes the limit. */
   refused(MATRIX_GLOBALS,
           "%a = alloca [4 x [4 x %m]], align 256\n"
           "%c = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float 2.0)\n"
           "store <64 x float> %c, ptr %a, align 256\n"
           "%f = getelementptr [4 x [4 x %m]], ptr %a, i64 0, i64 0, i64 0, i32 0, i64 3\n"
           "%e = load float, ptr %f, align 4\n"
           "store float %e, ptr addrspace(1) %out, align 4\nret void\n",
           &defaults, STELA_AIR_LIMIT);
   refused(MATRIX_GLOBALS,
           "%a = alloca [4 x [4 x %m]], align 256\n"
           "%c = call <64 x float> @air.simdgroup_matrix_8x8_init_filled.v64f32.f32(float 2.0)\n"
           "%h = getelementptr i8, ptr %a, i64 128\n"
           "store <64 x float> %c, ptr %h, align 128\nret void\n",
           &defaults, STELA_AIR_LIMIT);
}

/* A null pointer stands in for a device buffer's address, which is never
 * zero: a PHI or select joins them and equality compares them. An offset into
 * an allocation may be zero, so it never joins null. */
static void
null_joins_device_addresses(void)
{
   nir_shader *shader = compiled("",
      "entry:\n%i = load i32, ptr addrspace(1) %out, align 4\n%c = icmp eq i32 %i, 0\n"
      "br i1 %c, label %then, label %join\n"
      "then:\n%h = getelementptr i32, ptr addrspace(1) %out, i64 1\nbr label %join\n"
      "join:\n%p = phi ptr addrspace(1) [null, %entry], [%h, %then]\n"
      "%q = select i1 %c, ptr addrspace(1) null, ptr addrspace(1) %p\n"
      "%z = icmp eq ptr addrspace(1) %q, null\nbr i1 %z, label %done, label %use\n"
      "use:\n%v = load i32, ptr addrspace(1) %q, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nbr label %done\n"
      "done:\nret void\n");
   assert(count(shader, nir_intrinsic_store_global) == 1);
   ralloc_free(shader);

   /* Null and an allocation choose: the store reaches the allocation only
    * where it is chosen. */
   shader = compiled("",
      "entry:\n%a = alloca i32, align 4\n%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%c = icmp eq i32 %i, 0\nbr i1 %c, label %then, label %join\n"
      "then:\nbr label %join\n"
      "join:\n%p = phi ptr [null, %entry], [%a, %then]\n"
      "store i32 1, ptr %p, align 4\n%v = load i32, ptr %a, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   assert(count(shader, nir_intrinsic_store_scratch) == 1);
   ralloc_free(shader);
   shader = compiled("",
      "%a = alloca i32, align 4\n%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%c = icmp eq i32 %i, 0\n%p = select i1 %c, ptr null, ptr %a\n"
      "store i32 1, ptr %p, align 4\n%v = load i32, ptr %a, align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   assert(count(shader, nir_intrinsic_store_scratch) == 1);
   ralloc_free(shader);
}

/* Constant folding writes a constant offset off a null pointer, a buffer a
 * function constant left out, as an integer cast to a pointer: an access
 * through it reaches no memory, as through null. */
static void
folded_offsets_off_null_reach_no_memory(void)
{
   nir_shader *shader = compiled("",
      "%v = load i32, ptr addrspace(1) inttoptr (i64 16 to ptr addrspace(1)), align 4\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   /* The only load is the buffer's address; the store writes zero. */
   assert(count(shader, nir_intrinsic_store_global) == 1);
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (intrinsic->intrinsic == nir_intrinsic_load_global)
               assert(intrinsic->def.bit_size == 64);
            if (intrinsic->intrinsic == nir_intrinsic_store_global)
               assert(nir_src_is_const(intrinsic->src[0]) && !nir_src_as_uint(intrinsic->src[0]));
         }
      }
   }
   ralloc_free(shader);
}

/* A pointer array in thread memory read at a run-time index: the load
 * chooses among the slots' pointers, which keep their buffer, and the array
 * leaves memory. A store at a run-time index has no such choice. */
static void
pointer_slots_load_by_choice(void)
{
   const char *slots =
      "%a = alloca [2 x ptr addrspace(1)], align 8\n"
      "%s0 = getelementptr inbounds [2 x ptr addrspace(1)], ptr %a, i64 0, i64 0\n"
      "store ptr addrspace(1) %out, ptr %s0, align 8\n"
      "%s1 = getelementptr inbounds [2 x ptr addrspace(1)], ptr %a, i64 0, i64 1\n"
      "%o4 = getelementptr inbounds i32, ptr addrspace(1) %out, i64 4\n"
      "store ptr addrspace(1) %o4, ptr %s1, align 8\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n%j = and i32 %i, 1\n"
      "%k = zext i32 %j to i64\n"
      "%d = getelementptr inbounds [2 x ptr addrspace(1)], ptr %a, i64 0, i64 %k\n";
   char body[2048];
   snprintf(body, sizeof(body), "%s%s", slots,
            "%p = load ptr addrspace(1), ptr %d, align 8\n"
            "store i32 7, ptr addrspace(1) %p, align 4\nret void\n");
   nir_shader *shader = compiled("", body);
   assert(count(shader, nir_intrinsic_store_global) == 1);
   assert(!count(shader, nir_intrinsic_load_scratch) && !count(shader, nir_intrinsic_store_scratch));
   ralloc_free(shader);
   snprintf(body, sizeof(body), "%s%s", slots,
            "store ptr addrspace(1) %out, ptr %d, align 8\n"
            "%p = load ptr addrspace(1), ptr %s1, align 8\n"
            "store i32 7, ptr addrspace(1) %p, align 4\nret void\n");
   refused("", body, &defaults, STELA_AIR_TYPE);
}

/* A pointer chosen among `roots` allocations by a loaded index, through
 * which a value is read and stored. */
static char *
chosen_among(unsigned roots)
{
   char *body = malloc(roots * 160 + 256);
   assert(body);
   char *at = body;
   at += sprintf(at, "%%i = load i32, ptr addrspace(1) %%out, align 4\n");
   for (unsigned k = 0; k < roots; k++)
      at += sprintf(at, "%%a%u = alloca i32, align 4\nstore i32 %u, ptr %%a%u, align 4\n", k, k, k);
   at += sprintf(at, "%%p0 = getelementptr i32, ptr %%a0, i64 0\n");
   for (unsigned k = 1; k < roots; k++)
      at += sprintf(at, "%%c%u = icmp eq i32 %%i, %u\n%%p%u = select i1 %%c%u, ptr %%a%u, ptr %%p%u\n",
                    k, k, k, k, k, k - 1);
   sprintf(at, "%%v = load i32, ptr %%p%u, align 4\nstore i32 %%v, ptr addrspace(1) %%out, align 4\n"
               "ret void\n", roots - 1);
   return body;
}

/* A pointer chooses among as many roots as a function binds buffers, and
 * null: here allocations, each a guarded access. */
static void
pointers_choose_among_every_binding(void)
{
   char *body = chosen_among(13);
   nir_shader *shader = compiled("", body);
   assert(count(shader, nir_intrinsic_store_global) == 1);
   ralloc_free(shader);
   free(body);
   body = chosen_among(33);
   refused("", body, &defaults, STELA_AIR_LIMIT);
   free(body);
}

/* Generic pointers, cast from device and thread memory: a choice between
 * them reaches the chosen root, and the space queries ask which it is. */
static void
generic_pointers_choose_their_memory(void)
{
   const char *declarations =
      "declare i1 @air.is_device_pointer(ptr addrspace(8))\n"
      "declare i1 @air.is_threadgroup_pointer(ptr addrspace(8))\n"
      "declare i1 @air.is_thread_pointer(ptr addrspace(8))\n";
   nir_shader *shader = compiled(declarations,
      "%a = alloca [2 x i32], align 4\n"
      "store i32 11, ptr %a, align 4\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n%c = icmp eq i32 %i, 0\n"
      "%d = getelementptr i32, ptr addrspace(1) %out, i64 4\n"
      "%gd = addrspacecast ptr addrspace(1) %d to ptr addrspace(8)\n"
      "%ga = addrspacecast ptr %a to ptr addrspace(8)\n"
      "%p = select i1 %c, ptr addrspace(8) %gd, ptr addrspace(8) %ga\n"
      "%q = getelementptr i32, ptr addrspace(8) %p, i64 1\n"
      "store i32 33, ptr addrspace(8) %q, align 4\n"
      "%r = getelementptr i32, ptr addrspace(8) %ga, i64 1\n"
      "%v = load i32, ptr addrspace(8) %r, align 4\n"
      "%device = call i1 @air.is_device_pointer(ptr addrspace(8) %p)\n"
      "%group = call i1 @air.is_threadgroup_pointer(ptr addrspace(8) %ga)\n"
      "%thread = call i1 @air.is_thread_pointer(ptr addrspace(8) %p)\n"
      "%dv = zext i1 %device to i32\n%gv = zext i1 %group to i32\n%tv = zext i1 %thread to i32\n"
      "%w = add i32 %v, %dv\n%y = add i32 %w, %gv\n%x = add i32 %y, %tv\n"
      "%back = addrspacecast ptr addrspace(8) %gd to ptr addrspace(1)\n"
      "store i32 %x, ptr addrspace(1) %back, align 4\nret void\n");
   /* The choice's store is a global store or a scratch store; the load of
    * the allocation is thread memory alone. */
   assert(count(shader, nir_intrinsic_store_global) == 2);
   assert(count(shader, nir_intrinsic_store_scratch) == 2);
   assert(count(shader, nir_intrinsic_load_scratch) == 1);
   ralloc_free(shader);
   refused(declarations,
      "%a = alloca i32, align 4\n%g = addrspacecast ptr %a to ptr addrspace(8)\n"
      "%o = atomicrmw add ptr addrspace(8) %g, i32 1 monotonic, align 4\nret void\n",
      &defaults, STELA_AIR_MEMORY);
   refused(declarations,
      "%g = addrspacecast ptr addrspace(1) %out to ptr addrspace(8)\n"
      "%c = addrspacecast ptr addrspace(8) %g to ptr addrspace(2)\n"
      "%v = load i32, ptr addrspace(2) %c, align 4\nret void\n", &defaults, STELA_AIR_MEMORY);
}

/* memset, memcpy and memmove of constant lengths, in the largest chunks the
 * alignment allows; lifetime markers lower to nothing. */
static void
memory_intrinsics_lower_to_chunks(void)
{
   nir_shader *shader = compiled("",
      "%a = alloca [16 x i32], align 16\n"
      "call void @llvm.lifetime.start.p0(i64 64, ptr %a)\n"
      "call void @llvm.memset.p0.i64(ptr align 16 %a, i8 0, i64 64, i1 false)\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%p = getelementptr [16 x i32], ptr %a, i32 0, i32 %i\n"
      "store i32 5, ptr %p, align 4\n"
      "call void @llvm.memcpy.p1.p0.i64(ptr addrspace(1) align 4 %out, ptr align 16 %a, i64 64, i1 false)\n"
      "call void @llvm.lifetime.end.p0(i64 64, ptr %a)\nret void\n");
   nir_intrinsic_instr *stores[8];
   assert(intrinsics_of(shader, nir_intrinsic_store_scratch, stores, ARRAY_SIZE(stores)) == 5);
   for (unsigned i = 0; i < 4; i++)
      assert(stores[i]->src[0].ssa->num_components == 4 && stores[i]->src[0].ssa->bit_size == 32);
   assert(count(shader, nir_intrinsic_load_scratch) == 16 && count(shader, nir_intrinsic_store_global) == 16);
   ralloc_free(shader);

   /* An odd length steps down through narrower chunks. */
   shader = compiled("",
      "%a = alloca [2 x i32], align 8\n"
      "%b = load i8, ptr addrspace(1) %out, align 4\n"
      "call void @llvm.memset.p0.i64(ptr align 8 %a, i8 %b, i64 7, i1 false)\n"
      "%v = load i32, ptr %a, align 8\nstore i32 %v, ptr addrspace(1) %out, align 4\nret void\n");
   assert(intrinsics_of(shader, nir_intrinsic_store_scratch, stores, ARRAY_SIZE(stores)) == 3);
   assert(stores[0]->src[0].ssa->bit_size == 32 && stores[1]->src[0].ssa->bit_size == 16 &&
          stores[2]->src[0].ssa->bit_size == 8);
   ralloc_free(shader);

   /* An overlapping move loads every chunk before storing any. */
   shader = compiled("",
      "%s = getelementptr i8, ptr addrspace(1) %out, i64 4\n"
      "call void @llvm.memmove.p1.p1.i64(ptr addrspace(1) align 4 %out, ptr addrspace(1) align 4 %s, "
      "i64 8, i1 false)\nret void\n");
   /* The binding table's loads come first. */
   nir_intrinsic_instr *loads[8], *global[2];
   unsigned n = intrinsics_of(shader, nir_intrinsic_load_global, loads, ARRAY_SIZE(loads));
   assert(n >= 2 && intrinsics_of(shader, nir_intrinsic_store_global, global, ARRAY_SIZE(global)) == 2);
   assert(global[0]->src[0].ssa == &loads[n - 2]->def && global[1]->src[0].ssa == &loads[n - 1]->def);
   ralloc_free(shader);

   refused("", "%n = load i64, ptr addrspace(1) %out, align 8\n"
           "call void @llvm.memset.p1.i64(ptr addrspace(1) align 4 %out, i8 0, i64 %n, i1 false)\nret void\n",
           &defaults, STELA_AIR_MEMORY);
   refused("", "call void @llvm.memset.p1.i64(ptr addrspace(1) align 4 %out, i8 0, i64 8, i1 true)\nret void\n",
           &defaults, STELA_AIR_MEMORY);
   refused("", "call void @llvm.memset.p1.i64(ptr addrspace(1) %out, i8 0, i64 2048, i1 false)\nret void\n",
           &defaults, STELA_AIR_LIMIT);
}

/* A buffer is aligned only as its declared type is: a vector access through
 * `out`, a uint pointer, claims 4-byte alignment whatever LLVM claims, as
 * Apple GPUs accept such accesses at element alignment. */
static void
buffer_accesses_claim_their_declared_alignment(void)
{
   nir_shader *shader = compiled("",
      "%v = load <4 x i32>, ptr addrspace(1) %out, align 16\n"
      "%p = getelementptr i8, ptr addrspace(1) %out, i64 16\n"
      "store <4 x i32> %v, ptr addrspace(1) %p, align 16\nret void\n");
   nir_intrinsic_instr *loads[8], *stores[1];
   unsigned n = intrinsics_of(shader, nir_intrinsic_load_global, loads, ARRAY_SIZE(loads));
   assert(n && intrinsics_of(shader, nir_intrinsic_store_global, stores, ARRAY_SIZE(stores)) == 1);
   assert(loads[n - 1]->def.num_components == 4 && nir_intrinsic_align_mul(loads[n - 1]) == 4);
   assert(nir_intrinsic_align_mul(stores[0]) == 4);
   ralloc_free(shader);
}

/* Initialized constant globals become the shader's constant data, laid out in
 * first-use order, and load_constant at their base with their range. */
static void
constant_data_lowers_to_load_constant(void)
{
   char globals[512];
   snprintf(globals, sizeof(globals), "%s%s", table,
            "@bytes = private unnamed_addr addrspace(2) constant {i8, i16, <2 x half>} "
            "{i8 1, i16 515, <2 x half> <half 1.0, half 2.0>}, align 4\n");
   nir_shader *shader = lowered(globals,
      "%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%p = getelementptr [4 x float], ptr addrspace(2) @table, i32 0, i32 %i\n"
      "%f = load float, ptr addrspace(2) %p, align 4\n"
      "store float %f, ptr addrspace(1) %out, align 4\n"
      "%h = getelementptr {i8, i16, <2 x half>}, ptr addrspace(2) @bytes, i32 0, i32 2\n"
      "%v = load <2 x half>, ptr addrspace(2) %h, align 4\n"
      "store <2 x half> %v, ptr addrspace(1) %out, align 4\nret void\n");
   static const uint8_t expected[24] = {
      0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x80, 0x40,
      0x01, 0x00, 0x03, 0x02, 0x00, 0x3c, 0x00, 0x40,
   };
   assert(shader->constant_data_size == sizeof(expected) &&
          !memcmp(shader->constant_data, expected, sizeof(expected)));
   nir_intrinsic_instr *loads[2];
   assert(intrinsics_of(shader, nir_intrinsic_load_constant, loads, ARRAY_SIZE(loads)) == 2);
   assert(nir_intrinsic_base(loads[0]) == 0 && nir_intrinsic_range(loads[0]) == 16);
   assert(nir_intrinsic_base(loads[1]) == 16 && nir_intrinsic_range(loads[1]) == 8);
   assert(loads[1]->def.num_components == 2 && loads[1]->def.bit_size == 16);
   ralloc_free(shader);

   /* A copy initializes thread memory from constant data. */
   shader = lowered(table,
      "%a = alloca [4 x float], align 4\n"
      "call void @llvm.memcpy.p0.p2.i64(ptr align 4 %a, ptr addrspace(2) align 4 @table, i64 16, i1 false)\n"
      "%v = load float, ptr %a, align 4\nstore float %v, ptr addrspace(1) %out, align 4\nret void\n");
   assert(count(shader, nir_intrinsic_load_constant) == 4 && count(shader, nir_intrinsic_store_scratch) == 4);
   ralloc_free(shader);

   const char *use = "%f = load float, ptr addrspace(2) @table, align 4\n"
                     "store float %f, ptr addrspace(1) %out, align 4\nret void\n";
   refused(table, use, &(struct limits){.constant_bytes = 8}, STELA_AIR_LIMIT);
   refused(table, "store float 1.0, ptr addrspace(2) @table, align 4\nret void\n", &defaults, STELA_AIR_MEMORY);
   refused(table, "%o = atomicrmw xchg ptr addrspace(2) @table, float 1.0 monotonic, align 4\nret void\n",
           &defaults, STELA_AIR_MEMORY);
   refused(table, "%a = alloca float, align 4\n"
           "call void @llvm.memcpy.p2.p0.i64(ptr addrspace(2) align 4 @table, ptr align 4 %a, i64 4, i1 false)\n"
           "ret void\n", &defaults, STELA_AIR_MEMORY);
   const char *invalid[] = {
      "@table = internal addrspace(2) global [4 x float] zeroinitializer, align 4\n",
      "@table = external addrspace(2) constant [4 x float], align 4\n",
      "@table = internal addrspace(1) constant [4 x float] zeroinitializer, align 4\n",
   };
   /* Every global is validated, used or not. */
   for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++)
      refused(invalid[i], "ret void\n", &defaults, STELA_AIR_TARGET);
   refused("@table = internal addrspace(2) constant [4 x ptr] zeroinitializer, align 8\n",
           "ret void\n", &defaults, STELA_AIR_TYPE);
   refused("@x = internal addrspace(2) constant i32 1, align 4\n"
           "@table = internal addrspace(2) constant i64 ptrtoint (ptr addrspace(2) @x to i64), align 8\n",
           use, &defaults, STELA_AIR_TYPE);
}

/* A constant buffer `scale` (!41) with `access`. */
#define SCALE_ARGUMENT(access) \
   "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"" access "\"," \
   " !\"air.address_space\", i32 2, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\"," \
   " i32 4, !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"scale\"}\n"

/* A kernel's constant buffer is a read-only root, beside its device buffer. */
static void
kernels_read_constant_buffers(void)
{
   static const char *kernel_metadata = KERNEL_ARGUMENTS("!40, !41") SCALE_ARGUMENT("air.read");
   const struct {
      const char *body;
      enum stela_air_error_kind kind;
   } cases[] = {
      {"%s = load float, ptr addrspace(2) %scale, align 4\n"
       "%p = getelementptr float, ptr addrspace(2) %scale, i64 1\n"
       "%t = load float, ptr addrspace(2) %p, align 4\n%r = fadd fast float %s, %t\n"
       "store float %r, ptr addrspace(1) %out, align 4\nret void\n", STELA_AIR_OK},
      {"store float 1.0, ptr addrspace(2) %scale, align 4\nret void\n", STELA_AIR_MEMORY},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      char definition[1024];
      snprintf(definition, sizeof(definition),
               "define void @kernel(ptr addrspace(1) %%out, ptr addrspace(2) %%scale) {\n%s}\n",
               cases[i].body);
      struct stela_air_error error;
      nir_shader *shader = translate_kernel("", definition, kernel_metadata, &nir_options,
                                            stela_metal_bind_buffer, &defaults, &error);
      if (error.kind != cases[i].kind)
         fprintf(stderr, "%s: %u %s\n", cases[i].body, error.kind, error.detail);
      assert(error.kind == cases[i].kind && !shader == (cases[i].kind != STELA_AIR_OK));
      ralloc_free(shader);
   }
   /* Constant buffers are read-only. */
   static const char *writable = KERNEL_ARGUMENTS("!40, !41") SCALE_ARGUMENT("air.read_write");
   struct stela_air_error error;
   assert(!translate_kernel("", "define void @kernel(ptr addrspace(1) %out, ptr addrspace(2) %scale) {\n"
                            "ret void\n}\n", writable, &nir_options, stela_metal_bind_buffer, &defaults, &error) &&
          error.kind == STELA_AIR_ARGUMENT);
}

/* A rasterization rate map decoder maps a coordinate by its layer's scale
 * and offset in the map's parameter data, a constant buffer of no stated
 * size. */
static void
rate_map_decoders_read_their_parameters(void)
{
   static const char *kernel_metadata = KERNEL_ARGUMENTS("!40, !42")
      "!42 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read\","
      " !\"air.address_space\", i32 2, !\"air.arg_type_name\","
      " !\"metal::rasterization_rate_map_data\", !\"air.arg_name\", !\"data\"}\n";
   static const char *declarations =
      "declare <2 x float> @air.map_screen_to_physical_coordinates.v2f32.p2i8.i32(<2 x float>, ptr addrspace(2), i32)\n"
      "declare <2 x float> @air.map_physical_to_screen_coordinates.v2f32.p2i8.i32(<2 x float>, ptr addrspace(2), i32)\n";
   static const char *definition =
      "define void @kernel(ptr addrspace(1) %out, ptr addrspace(2) %data) {\n"
      "%l = load i32, ptr addrspace(1) %out, align 4\n"
      "%p = call <2 x float> @air.map_screen_to_physical_coordinates.v2f32.p2i8.i32("
      "<2 x float> <float 3.0, float 5.0>, ptr addrspace(2) %data, i32 %l)\n"
      "%s = call <2 x float> @air.map_physical_to_screen_coordinates.v2f32.p2i8.i32("
      "<2 x float> %p, ptr addrspace(2) %data, i32 %l)\n"
      "store <2 x float> %s, ptr addrspace(1) %out, align 4\nret void\n}\n";
   struct stela_air_error error;
   nir_shader *shader = translate_kernel(declarations, definition, kernel_metadata, &nir_options,
                                         stela_metal_bind_buffer, &defaults, &error);
   if (!shader)
      fprintf(stderr, "rate map decoder: %u %s\n", error.kind, error.detail);
   assert(shader);
   unsigned vectors = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                nir_intrinsic_infos[nir_instr_as_intrinsic(instr)->intrinsic].has_dest &&
                nir_instr_as_intrinsic(instr)->def.num_components == 4)
               vectors++;
         }
      }
   }
   assert(vectors == 2);
   ralloc_free(shader);
}

/* The access of the shader's one 32-bit scalar load_global (the bindings'
 * tables load 64-bit addresses), or ~0 without exactly one. */
static unsigned
word_load_access(nir_shader *shader)
{
   nir_intrinsic_instr *loads[16], *word = NULL;
   unsigned n = intrinsics_of(shader, nir_intrinsic_load_global, loads, ARRAY_SIZE(loads));
   for (unsigned i = 0; i < n; i++) {
      if (loads[i]->def.bit_size == 32 && loads[i]->def.num_components == 1) {
         if (word)
            return ~0u;
         word = loads[i];
      }
   }
   return word ? nir_intrinsic_access(word) : ~0u;
}

/* A device buffer the kernel only reads, which Apple's compiler says no
 * other pointer reaches, is read-only while the kernel writes another; one
 * it may alias stays an ordinary load. */
static void
unaliased_read_buffers_load_read_only(void)
{
   static const char *kernel_metadata = KERNEL_ARGUMENTS("!40, !41")
      "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read\","
      " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
      " i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"in\"}\n";
   const char *attributes[] = {"\"air-buffer-no-alias\" ", ""};
   for (unsigned i = 0; i < ARRAY_SIZE(attributes); i++) {
      char definition[1024];
      snprintf(definition, sizeof(definition),
               "define void @kernel(ptr addrspace(1) %%out, ptr addrspace(1) %s%%in) {\n"
               "%%p = getelementptr i32, ptr addrspace(1) %%in, i64 1\n"
               "%%v = load i32, ptr addrspace(1) %%p, align 4\n"
               "store i32 %%v, ptr addrspace(1) %%out, align 4\nret void\n}\n",
               attributes[i]);
      struct stela_air_error error;
      nir_shader *shader = translate_kernel("", definition, kernel_metadata, &nir_options,
                                            stela_metal_bind_buffer, &defaults, &error);
      if (!shader)
         fprintf(stderr, "read buffer: %u %s\n", error.kind, error.detail);
      assert(shader);
      unsigned access = word_load_access(shader);
      const unsigned read_only = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER;
      assert(access != ~0u && (access & read_only) == (i == 0 ? read_only : 0));
      ralloc_free(shader);
   }
}

/* A struct or array crosses memory leaf by leaf at its layout offsets; an
 * undefined leaf stores nothing. */
static void
aggregates_load_and_store_by_leaf(void)
{
   nir_shader *shader = compiled("",
      "%a = alloca { i32, float, [2 x i16] }, align 4\n"
      "%i = load i32, ptr addrspace(1) %out, align 4\n"
      "%s = insertvalue { i32, float, [2 x i16] } undef, i32 %i, 0\n"
      "%t = insertvalue { i32, float, [2 x i16] } %s, float 2.0, 1\n"
      "store { i32, float, [2 x i16] } %t, ptr %a, align 4\n"
      "%l = load { i32, float, [2 x i16] }, ptr %a, align 4\n"
      "%v = extractvalue { i32, float, [2 x i16] } %l, 2, 1\n"
      "%w = zext i16 %v to i32\n"
      "store i32 %w, ptr addrspace(1) %out, align 4\nret void\n");
   assert(shader->scratch_size == 12);
   ralloc_free(shader);

   /* A constant aggregate stores each of its leaves. */
   shader = compiled("", "store [2 x i32] [i32 1, i32 2], ptr addrspace(1) %out, align 4\nret void\n");
   assert(count(shader, nir_intrinsic_store_global) + count(shader, nir_intrinsic_store_ssbo) == 2);
   ralloc_free(shader);

   refused("", "%a = alloca { i1 }, align 4\nstore { i1 } { i1 true }, ptr %a, align 4\nret void\n",
           &defaults, STELA_AIR_MEMORY);
}

/* A pointer left in a stack slot keeps its provenance through promotion. */
static void
stack_pointers_keep_their_origin(void)
{
   nir_shader *shader = compiled("",
      "%s = alloca ptr addrspace(1), align 8\n"
      "store ptr addrspace(1) %out, ptr %s, align 8\n"
      "%p = load ptr addrspace(1), ptr %s, align 8\n"
      "store i32 5, ptr addrspace(1) %p, align 4\nret void\n");
   assert(shader->scratch_size == 0);
   assert(count(shader, nir_intrinsic_store_global) + count(shader, nir_intrinsic_store_ssbo) == 1);
   ralloc_free(shader);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   thread_memory_lowers_to_scratch();
   matrix_thread_memory_keeps_thread_elements();
   memory_intrinsics_lower_to_chunks();
   null_joins_device_addresses();
   folded_offsets_off_null_reach_no_memory();
   pointer_slots_load_by_choice();
   pointers_choose_among_every_binding();
   generic_pointers_choose_their_memory();
   buffer_accesses_claim_their_declared_alignment();
   constant_data_lowers_to_load_constant();
   kernels_read_constant_buffers();
   rate_map_decoders_read_their_parameters();
   aggregates_load_and_store_by_leaf();
   stack_pointers_keep_their_origin();
   unaliased_read_buffers_load_read_only();
   glsl_type_singleton_decref();
   puts("air memory: ok");
   return 0;
}
