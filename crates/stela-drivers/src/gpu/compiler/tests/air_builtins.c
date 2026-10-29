/* SPDX-License-Identifier: MIT */
/* AIR builtin inputs over the Metal ABI's device values. Original LLVM IR
 * fixtures in the argument forms air_metadata.c documents; no Apple output. */
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

/* The descriptor of builtin argument index, of the given type. */
#define BUILTIN(node, index, name, type)                                                           \
   "!" #node " = !{i32 " #index ", !\"air." name "\", !\"air.arg_type_name\", !\"" type          \
   "\", !\"air.arg_name\", !\"" name "\"}\n"

static const char *kernel_body =
   "define void @kernel(<3 x i32> %grid_position, <2 x i16> %local, i32 %group, <3 x i32> %size,"
   " <3 x i32> %dispatch, <3 x i32> %groups, <3 x i32> %threads, i32 %index, i32 %simdgroup,"
   " i32 %simdgroups, i32 %dispatch_simdgroups, i32 %quadgroup, i32 %quadgroups,"
   " i32 %dispatch_quadgroups, i16 %lane, i32 %width, i32 %execution, i32 %quad_lane) {\n"
   "ret void\n}\n";

static const char *kernel_metadata =
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n"
   "!4 = !{!40, !41, !42, !43, !44, !45, !46, !47, !48, !49, !50, !51, !52, !53, !54, !55, !56,"
   " !57}\n"
   BUILTIN(40, 0, "thread_position_in_grid", "uint3")
   BUILTIN(41, 1, "thread_position_in_threadgroup", "ushort2")
   BUILTIN(42, 2, "threadgroup_position_in_grid", "uint")
   BUILTIN(43, 3, "threads_per_threadgroup", "uint3")
   BUILTIN(44, 4, "dispatch_threads_per_threadgroup", "uint3")
   BUILTIN(45, 5, "threadgroups_per_grid", "uint3")
   BUILTIN(46, 6, "threads_per_grid", "uint3")
   BUILTIN(47, 7, "thread_index_in_threadgroup", "uint")
   BUILTIN(48, 8, "simdgroup_index_in_threadgroup", "uint")
   BUILTIN(49, 9, "simdgroups_per_threadgroup", "uint")
   BUILTIN(50, 10, "dispatch_simdgroups_per_threadgroup", "uint")
   BUILTIN(51, 11, "quadgroup_index_in_threadgroup", "uint")
   BUILTIN(52, 12, "quadgroups_per_threadgroup", "uint")
   BUILTIN(53, 13, "dispatch_quadgroups_per_threadgroup", "uint")
   BUILTIN(54, 14, "thread_index_in_simdgroup", "ushort")
   BUILTIN(55, 15, "threads_per_simdgroup", "uint")
   BUILTIN(56, 16, "thread_execution_width", "uint")
   BUILTIN(57, 17, "thread_index_in_quadgroup", "uint");

static const char *vertex_body =
   "define <4 x float> @vertex(i32 %vertex, i32 %instance, i32 %base_vertex, i32 %base_instance,"
   " i32 %view) {\n"
   "ret <4 x float> zeroinitializer\n}\n";

static const char *vertex_metadata =
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @vertex, !3, !4}\n"
   "!3 = !{!5}\n!5 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"position\"}\n"
   "!4 = !{!40, !41, !42, !43, !44}\n"
   BUILTIN(40, 0, "vertex_id", "uint")
   BUILTIN(41, 1, "instance_id", "uint")
   BUILTIN(42, 2, "base_vertex", "uint")
   BUILTIN(43, 3, "base_instance", "uint")
   BUILTIN(44, 4, "amplification_id", "uint");

static const char *fragment_body =
   "define <4 x float> @fragment(i1 %front, i32 %sample, i32 %mask, i32 %primitive, i32 %layer,"
   " i32 %viewport, i32 %lane, <2 x float> %point) {\n"
   "ret <4 x float> zeroinitializer\n}\n";

static const char *fragment_metadata =
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @fragment, !3, !4}\n"
   "!3 = !{!5}\n!5 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\"}\n"
   "!4 = !{!40, !41, !42, !43, !44, !45, !46, !47}\n"
   BUILTIN(40, 0, "front_facing", "bool")
   BUILTIN(41, 1, "sample_id", "uint")
   BUILTIN(42, 2, "sample_mask_in", "uint")
   BUILTIN(43, 3, "primitive_id", "uint")
   BUILTIN(44, 4, "render_target_array_index", "uint")
   BUILTIN(45, 5, "viewport_array_index", "uint")
   BUILTIN(46, 6, "thread_index_in_simdgroup", "uint")
   BUILTIN(47, 7, "point_coord", "float2");

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};
static struct stela_metal_stage fragment = {.table = STELA_METAL_TABLE_FRAGMENT};

static struct stela_air_options
options(struct stela_metal_stage *stage, bool compute, bool device)
{
   return (struct stela_air_options){
      .workgroup_size = {compute ? 8u : 0u, compute ? 4u : 0u, compute ? 2u : 0u},
      .max_instructions = 10000, .bind_buffer = stela_metal_bind_buffer, .binding_data = stage,
      .fp_profile = STELA_AIR_FP_METAL,
      .load_device_value = device ? stela_metal_load_device_value : NULL,
   };
}

static char *
metadata(const char *entry)
{
   size_t bytes = strlen(entry) + strlen(versions) + 1;
   char *text = malloc(bytes);
   assert(text);
   snprintf(text, bytes, "%s%s", entry, versions);
   return text;
}

static nir_shader *
translate(const char *body, const char *entry_metadata, const char *entry, int stage,
          bool device, struct stela_air_error *error)
{
   char *md = metadata(entry_metadata);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, md, "");
   free(md);
   nir_shader *shader;
   if (stage) {
      struct stela_air_stage_options o = {
         .stage = (enum stela_air_stage)stage, .max_varying_slots = 16,
         .resources = options(stage == STELA_AIR_FRAGMENT ? &fragment : &primary, false, device),
      };
      shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input), entry,
                                      &nir_options, &o, error);
   } else {
      const struct stela_air_options o = options(&primary, true, device);
      shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input), entry,
                                &nir_options, &o, error);
   }
   LLVMDisposeMemoryBuffer(input);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", entry, error->kind, error->detail);
   return shader;
}

struct census {
   unsigned intrinsics[nir_num_intrinsics];
   unsigned grid_loads, amplification_loads, narrowed;
};

static struct census
count(nir_shader *shader)
{
   struct census census = {0};
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_alu &&
                nir_instr_as_alu(instr)->op == nir_op_u2u16)
               census.narrowed++;
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            census.intrinsics[intrinsic->intrinsic]++;
            if (intrinsic->intrinsic == nir_intrinsic_load_push_constant) {
               unsigned base = (unsigned)nir_intrinsic_base(intrinsic);
               census.grid_loads += base == STELA_METAL_PUSH_GRID;
               census.amplification_loads += base == STELA_METAL_PUSH_AMPLIFICATION;
            }
         }
      }
   }
   return census;
}

static bool
reads_input(nir_shader *shader, gl_varying_slot slot)
{
   nir_foreach_variable_with_modes(var, shader, nir_var_shader_in) {
      if (var->data.location == (int)slot)
         return var->data.interpolation == INTERP_MODE_FLAT;
   }
   return false;
}

static void
kernel_builtins_read_the_dispatch(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(kernel_body, kernel_metadata, "kernel", 0, true, &error);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "builtin kernel");
   struct census census = count(shader);
   assert(census.intrinsics[nir_intrinsic_load_workgroup_id]);
   assert(census.intrinsics[nir_intrinsic_load_local_invocation_id]);
   assert(census.intrinsics[nir_intrinsic_load_num_workgroups]);
   assert(census.intrinsics[nir_intrinsic_load_local_invocation_index]);
   assert(census.intrinsics[nir_intrinsic_load_subgroup_id]);
   assert(census.intrinsics[nir_intrinsic_load_num_subgroups]);
   assert(census.intrinsics[nir_intrinsic_load_subgroup_size]);
   assert(census.intrinsics[nir_intrinsic_load_subgroup_invocation]);
   /* The guard, threads_per_grid and both dispatch-size reads. */
   assert(census.grid_loads == 5);
   /* ushort2 and ushort forms. */
   assert(census.narrowed == 2);
   ralloc_free(shader);
}

static void
kernels_without_device_values_run_whole_threadgroups(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(
      "define void @kernel(<3 x i32> %position) {\nret void\n}\n",
      "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!40}\n"
      BUILTIN(40, 0, "thread_position_in_grid", "uint3"),
      "kernel", 0, false, &error);
   assert(shader && error.kind == STELA_AIR_OK);
   struct census census = count(shader);
   assert(!census.intrinsics[nir_intrinsic_load_push_constant]);
   ralloc_free(shader);

   /* Device-supplied builtins need the device. */
   shader = translate(
      "define void @kernel(<3 x i32> %size) {\nret void\n}\n",
      "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!40}\n"
      BUILTIN(40, 0, "dispatch_threads_per_threadgroup", "uint3"),
      "kernel", 0, false, &error);
   assert(!shader && error.kind == STELA_AIR_ARGUMENT);
}

static void
vertex_builtins_include_the_bases(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(vertex_body, vertex_metadata, "vertex", STELA_AIR_VERTEX, true,
                                  &error);
   assert(shader && error.kind == STELA_AIR_OK);
   struct census census = count(shader);
   assert(census.intrinsics[nir_intrinsic_load_vertex_id] == 1);
   assert(census.intrinsics[nir_intrinsic_load_instance_id] == 1);
   assert(census.intrinsics[nir_intrinsic_load_base_vertex] == 1);
   /* instance_id adds it, and base_instance reads it. */
   assert(census.intrinsics[nir_intrinsic_load_base_instance] == 2);
   assert(census.amplification_loads == 1);
   ralloc_free(shader);
}

static void
fragment_builtins_read_the_rasterizer(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(fragment_body, fragment_metadata, "fragment", STELA_AIR_FRAGMENT,
                                  false, &error);
   assert(shader && error.kind == STELA_AIR_OK);
   struct census census = count(shader);
   assert(census.intrinsics[nir_intrinsic_load_front_face] == 1);
   assert(census.intrinsics[nir_intrinsic_load_sample_id] == 1);
   assert(census.intrinsics[nir_intrinsic_load_sample_mask_in] == 1);
   assert(census.intrinsics[nir_intrinsic_load_subgroup_invocation] == 1);
   assert(census.intrinsics[nir_intrinsic_load_point_coord] == 1);
   assert(reads_input(shader, VARYING_SLOT_PRIMITIVE_ID));
   assert(reads_input(shader, VARYING_SLOT_LAYER));
   assert(reads_input(shader, VARYING_SLOT_VIEWPORT));
   ralloc_free(shader);
}

static void
refuses_misplaced_and_malformed_builtins(void)
{
   const struct {
      const char *body, *descriptors;
   } kernels[] = {
      /* A vertex builtin in a kernel. */
      {"define void @kernel(i32 %v) {\nret void\n}\n", BUILTIN(40, 0, "vertex_id", "uint")},
      /* Too many lanes. */
      {"define void @kernel(<4 x i32> %p) {\nret void\n}\n",
       BUILTIN(40, 0, "thread_position_in_grid", "uint4")},
      /* A scalar builtin as a vector. */
      {"define void @kernel(<2 x i32> %i) {\nret void\n}\n",
       BUILTIN(40, 0, "thread_index_in_threadgroup", "uint2")},
      /* Not an integer. */
      {"define void @kernel(float %i) {\nret void\n}\n",
       BUILTIN(40, 0, "thread_index_in_threadgroup", "float")},
      /* An unknown builtin. */
      {"define void @kernel(i32 %i) {\nret void\n}\n",
       BUILTIN(40, 0, "thread_position_in_universe", "uint")},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(kernels); i++) {
      char md[512];
      snprintf(md, sizeof(md), "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n"
                               "!4 = !{!40}\n%s", kernels[i].descriptors);
      struct stela_air_error error = {0};
      assert(!translate(kernels[i].body, md, "kernel", 0, true, &error));
      assert(error.kind == STELA_AIR_ARGUMENT);
   }
   struct stela_air_error error = {0};
   assert(!translate("define void @kernel(i32 %a, i32 %b) {\nret void\n}\n",
                     "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
                     BUILTIN(40, 0, "thread_index_in_threadgroup", "uint")
                     BUILTIN(41, 1, "thread_index_in_threadgroup", "uint"),
                     "kernel", 0, true, &error));
   assert(error.kind == STELA_AIR_METADATA);
}

static bool
reflect_max_threads(const struct stela_air_inspection *info, const struct stela_air_entry *entry,
                    void *data)
{
   (void)info;
   *(unsigned *)data = entry->max_threads;
   return true;
}

/* air.max_work_group_size bounds the workgroup a kernel compiles for, and
 * inspection reflects it. */
static void
kernels_bound_their_workgroups(void)
{
   const char *body = "define void @kernel(i32 %i) {\nret void\n}\n";
   for (unsigned limit = 32; limit <= 64; limit += 32) {
      char md[512];
      snprintf(md, sizeof(md), "!air.kernel = !{!2}\n!2 = !{ptr @kernel, !3, !4, !5}\n!3 = !{}\n"
               "!4 = !{!40}\n!5 = !{!\"air.max_work_group_size\", i32 %u}\n%s", limit,
               BUILTIN(40, 0, "thread_index_in_threadgroup", "uint"));
      struct stela_air_error error = {0};
      /* The workgroup is 64 threads. */
      nir_shader *shader = translate(body, md, "kernel", 0, true, &error);
      assert(limit < 64 ? !shader && error.kind == STELA_AIR_LIMIT : shader != NULL);
      ralloc_free(shader);

      char *text = metadata(md);
      LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, text, "");
      free(text);
      unsigned reflected = 0;
      assert(stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), 1,
                               reflect_max_threads, &reflected, &error));
      assert(reflected == limit);
      LLVMDisposeMemoryBuffer(input);
   }
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   kernel_builtins_read_the_dispatch();
   kernels_without_device_values_run_whole_threadgroups();
   vertex_builtins_include_the_bases();
   fragment_builtins_read_the_rasterizer();
   refuses_misplaced_and_malformed_builtins();
   kernels_bound_their_workgroups();
   glsl_type_singleton_decref();
   puts("air builtins: ok");
   return 0;
}
