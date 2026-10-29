/* SPDX-License-Identifier: MIT */
/* Object and mesh functions, and the fragment inputs of mesh primitive data.
 * Original LLVM IR fixtures in the object and mesh forms DXMT emits; no
 * Apple output. */
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
   "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
   "declare void @air.set_threadgroups_per_grid_mesh_properties(ptr addrspace(3), <3 x i32>)\n"
   "declare void @air.set_position_mesh(ptr addrspace(7), i32, <4 x float>)\n"
   "declare void @air.set_clip_distance_mesh(ptr addrspace(7), i32, i32, float)\n"
   "declare void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7), i32, i32, <2 x float>)\n"
   "declare void @air.set_vertex_data_mesh.v4f32(ptr addrspace(7), i32, i32, <4 x float>)\n"
   "declare void @air.set_primitive_data_mesh.v4f32(ptr addrspace(7), i32, i32, <4 x float>)\n"
   "declare void @air.set_render_target_array_index_mesh.i32(ptr addrspace(7), i32, i32)\n"
   "declare void @air.set_primitive_id_mesh(ptr addrspace(7), i32, i32)\n"
   "declare void @air.set_index_mesh(ptr addrspace(7), i32, i8)\n"
   "declare void @air.set_primitive_count_mesh(ptr addrspace(7), i32)\n";

static const char *versions =
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

/* Each thread records its index in the payload; thread 0 launches two mesh
 * threadgroups. */
static const char *object =
   "define void @object(ptr addrspace(6) %payload, ptr addrspace(3) %grid, i32 %tid) {\n"
   "%i = zext i32 %tid to i64\n"
   "%p = getelementptr i32, ptr addrspace(6) %payload, i64 %i\n"
   "store i32 %tid, ptr addrspace(6) %p, align 4\n"
   "%first = icmp eq i32 %tid, 0\n"
   "br i1 %first, label %launch, label %done\n"
   "launch:\n"
   "call void @air.set_threadgroups_per_grid_mesh_properties(ptr addrspace(3) %grid,"
   " <3 x i32> <i32 2, i32 1, i32 1>)\n"
   "br label %done\n"
   "done:\nret void\n}\n"
   "!air.object = !{!2}\n"
   "!2 = !{ptr @object, !3, !4, !5, !6}\n!3 = !{}\n"
   "!5 = !{!\"air.max_work_group_size\", i32 32}\n!6 = !{!\"air.max_mesh_work_groups\", i32 8}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.payload\", !\"air.arg_type_size\", i32 128, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mtl_payload\"}\n"
   "!41 = !{i32 1, !\"air.mesh_grid_properties\", !\"air.arg_type_name\", !\"mesh_grid_properties\","
   " !\"air.arg_name\", !\"grid\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

#define MESH(body) \
   "define void @mesh(ptr addrspace(7) %m, ptr addrspace(6) %payload, i32 %tid) {\n" body \
   "ret void\n}\n"

/* Each thread sets a vertex and a triangle from the payload. */
static const char *mesh_body = MESH(
   "%s = load i32, ptr addrspace(6) %payload, align 4\n"
   "%f = uitofp i32 %s to float\n"
   "%pos = insertelement <4 x float> <float 0.0, float 0.0, float 0.0, float 1.0>, float %f, i64 0\n"
   "call void @air.set_position_mesh(ptr addrspace(7) %m, i32 %tid, <4 x float> %pos)\n"
   "call void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7) %m, i32 0, i32 %tid,"
   " <2 x float> <float 0.5, float 0.25>)\n"
   "call void @air.set_clip_distance_mesh(ptr addrspace(7) %m, i32 1, i32 %tid, float %f)\n"
   "call void @air.set_primitive_data_mesh.v4f32(ptr addrspace(7) %m, i32 0, i32 %tid, <4 x float> %pos)\n"
   "call void @air.set_render_target_array_index_mesh.i32(ptr addrspace(7) %m, i32 %tid, i32 %s)\n"
   "call void @air.set_primitive_id_mesh(ptr addrspace(7) %m, i32 %tid, i32 %tid)\n"
   "%v = trunc i32 %tid to i8\n"
   "call void @air.set_index_mesh(ptr addrspace(7) %m, i32 %tid, i8 %v)\n"
   "call void @air.set_primitive_count_mesh(ptr addrspace(7) %m, i32 %s)\n");

static const char *mesh_metadata =
   "!air.mesh = !{!2}\n"
   "!2 = !{ptr @mesh, !3, !4, !5}\n!3 = !{}\n!5 = !{!\"air.max_work_group_size\", i32 32}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.mesh\", !50, !\"air.arg_type_name\", !\"mesh<>\", !\"air.arg_name\", !\"mtl_mesh\"}\n"
   "!50 = !{!\"air.mesh_type_info\", !51, !52, i32 64, i32 32, !\"air.triangle\"}\n"
   "!51 = !{!60, !61, !62}\n"
   "!60 = !{!\"air.position\", !\"air.invariant\", !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"position\"}\n"
   "!61 = !{!\"air.mesh_vertex_data\", i32 0, !\"user(color)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!62 = !{!\"air.clip_distance\", !\"air.clip_distance_array_size\", i32 2,"
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"clip\"}\n"
   "!52 = !{!63, !64, !65}\n"
   "!63 = !{!\"air.mesh_primitive_data\", i32 0, !\"user(normal)\", !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"normal\"}\n"
   "!64 = !{!\"air.render_target_array_index\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"layer\"}\n"
   "!65 = !{!\"air.primitive_id\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"id\"}\n"
   "!41 = !{i32 1, !\"air.payload\", !\"air.arg_type_size\", i32 128, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mtl_payload\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

/* A fragment function reading the primitive data, which it asks to have
 * interpolated. */
static const char *fragment =
   "define <4 x float> @fragment(<4 x float> %normal) {\nret <4 x float> %normal\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @fragment, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.fragment_input\", !\"user(normal)\", !\"air.center\", !\"air.perspective\","
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"normal\"}\n";

static const struct stela_air_varying_slot varyings[] = {
   {"user(color)", 11, STELA_AIR_FLOAT, 2, 0, false},
   {"user(normal)", 12, STELA_AIR_FLOAT, 4, 1, true},
};

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};

static struct stela_air_stage_options
options(enum stela_air_stage stage)
{
   bool compute = stage == STELA_AIR_OBJECT || stage == STELA_AIR_MESH;
   return (struct stela_air_stage_options){
      .stage = stage, .max_varying_slots = 16, .varyings = varyings,
      .varying_count = ARRAY_SIZE(varyings),
      .max_payload_bytes = 16384, .max_mesh_vertices = 256, .max_mesh_primitives = 256,
      .resources = {
         .workgroup_size = {compute ? 32u : 0u, compute ? 1u : 0u, compute ? 1u : 0u},
         .max_threadgroup_bytes = compute ? 1024u : 0u,
         .max_instructions = 10000, .bind_buffer = stela_metal_bind_buffer, .binding_data = &primary,
         .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41,
         .load_device_value = stela_metal_load_device_value,
      },
   };
}

static nir_shader *
translate(const char *body, const char *metadata, const char *entry,
          const struct stela_air_stage_options *o, struct stela_air_error *error)
{
   char *text = ralloc_asprintf(NULL, "%s%s", metadata, versions);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, text, "");
   ralloc_free(text);
   *error = (struct stela_air_error){0};
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               entry, &nir_options, o, error);
   LLVMDisposeMemoryBuffer(input);
   if (!shader && error->kind == STELA_AIR_OK)
      error->kind = STELA_AIR_INPUT;
   return shader;
}

/* Splits a fixture into its code and its metadata. */
static nir_shader *
translate_fixture(const char *fixture, const char *entry, const struct stela_air_stage_options *o,
                  struct stela_air_error *error)
{
   const char *metadata = strstr(fixture, "!air.");
   char *body = ralloc_strndup(NULL, fixture, metadata - fixture);
   nir_shader *shader = translate(body, metadata, entry, o, error);
   ralloc_free(body);
   return shader;
}

static nir_shader *
mesh(const char *body, const char *metadata, const struct stela_air_stage_options *o,
     struct stela_air_error *error)
{
   return translate(body, metadata, "mesh", o, error);
}

static void
refused(nir_shader *shader, const struct stela_air_error *error, enum stela_air_error_kind kind)
{
   if (shader || error->kind != kind)
      fprintf(stderr, "expected refusal %u, got %u %s\n", kind, error->kind, error->detail);
   assert(!shader && error->kind == kind);
}

/* Replaces the one occurrence of from in text; the result is static. */
static const char *
replaced(const char *text, const char *from, const char *to)
{
   static char buffer[16384];
   const char *at = strstr(text, from);
   assert(at && !strstr(at + 1, from));
   int written = snprintf(buffer, sizeof(buffer), "%.*s%s%s", (int)(at - text), text, to,
                          at + strlen(from));
   assert(written > 0 && (size_t)written < sizeof(buffer));
   return buffer;
}

static unsigned
intrinsics(nir_shader *shader, nir_intrinsic_op op)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            n += instr->type == nir_instr_type_intrinsic &&
                 nir_instr_as_intrinsic(instr)->intrinsic == op;
         }
      }
   }
   return n;
}

static nir_intrinsic_instr *
intrinsic(nir_shader *shader, nir_intrinsic_op op)
{
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                nir_instr_as_intrinsic(instr)->intrinsic == op)
               return nir_instr_as_intrinsic(instr);
         }
      }
   }
   return NULL;
}

static nir_variable *
output(nir_shader *shader, int location)
{
   nir_foreach_variable_with_modes(var, shader, nir_var_shader_out) {
      if (var->data.location == location)
         return var;
   }
   return NULL;
}

static void
objects_launch_mesh_grids(void)
{
   struct stela_air_stage_options o = options(STELA_AIR_OBJECT);
   struct stela_air_error error;
   nir_shader *shader = translate_fixture(object, "object", &o, &error);
   if (!shader)
      fprintf(stderr, "object: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "object function");
   assert(shader->info.stage == MESA_SHADER_TASK);
   assert(shader->info.task_payload_size == 128);
   assert(intrinsics(shader, nir_intrinsic_store_task_payload) == 1);
   /* One launch at the end, carrying the payload; the grid is set by one
    * thread, so it goes through threadgroup memory. */
   nir_intrinsic_instr *launch = intrinsic(shader, nir_intrinsic_launch_mesh_workgroups);
   assert(intrinsics(shader, nir_intrinsic_launch_mesh_workgroups) == 1);
   assert(nir_intrinsic_range(launch) == 128);
   assert(intrinsics(shader, nir_intrinsic_store_shared) == 6);
   assert(intrinsics(shader, nir_intrinsic_load_shared) == 3);
   assert(intrinsics(shader, nir_intrinsic_barrier) == 2);
   /* Unless it bounds the threads drawMeshThreads launches, no device
    * values are read. */
   assert(!intrinsics(shader, nir_intrinsic_load_push_constant));
   ralloc_free(shader);

   o.launched_by_grid = true;
   shader = translate_fixture(object, "object", &o, &error);
   if (!shader)
      fprintf(stderr, "grid-launched object: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "grid-launched object function");
   assert(intrinsics(shader, nir_intrinsic_load_push_constant));
   assert(intrinsics(shader, nir_intrinsic_launch_mesh_workgroups) == 1);
   ralloc_free(shader);
}

static void
meshes_output_primitives(void)
{
   struct stela_air_stage_options o = options(STELA_AIR_MESH);
   struct stela_air_error error;
   nir_shader *shader = mesh(mesh_body, mesh_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "mesh: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "mesh function");
   assert(shader->info.stage == MESA_SHADER_MESH);
   assert(shader->info.mesh.max_vertices_out == 64 && shader->info.mesh.max_primitives_out == 32);
   assert(shader->info.mesh.primitive_type == MESA_PRIM_TRIANGLES);
   assert(intrinsics(shader, nir_intrinsic_load_task_payload) == 1);

   /* Vertex outputs have one element per vertex, primitive outputs one per
    * primitive. */
   nir_variable *position = output(shader, VARYING_SLOT_POS);
   assert(position && glsl_get_length(position->type) == 64 && position->data.invariant);
   assert(!position->data.per_primitive);
   nir_variable *color = output(shader, VARYING_SLOT_VAR0);
   assert(color && glsl_get_length(color->type) == 64 && !color->data.per_primitive);
   nir_variable *clip = output(shader, VARYING_SLOT_CLIP_DIST0);
   assert(clip && clip->data.compact && glsl_get_length(clip->type) == 64);
   assert(glsl_get_length(glsl_get_array_element(clip->type)) == 2);
   nir_variable *normal = output(shader, VARYING_SLOT_VAR0 + 1);
   assert(normal && glsl_get_length(normal->type) == 32 && normal->data.per_primitive);
   nir_variable *layer = output(shader, VARYING_SLOT_LAYER);
   assert(layer && layer->data.per_primitive);
   nir_variable *id = output(shader, VARYING_SLOT_PRIMITIVE_ID);
   assert(id && id->data.per_primitive);
   nir_variable *indices = output(shader, VARYING_SLOT_PRIMITIVE_INDICES);
   assert(indices && indices->data.per_primitive && glsl_get_length(indices->type) == 32);
   assert(glsl_get_vector_elements(glsl_get_array_element(indices->type)) == 3);

   /* Six setters, and the index's three corners. */
   assert(intrinsics(shader, nir_intrinsic_store_deref) == 9);
   assert(intrinsics(shader, nir_intrinsic_set_vertex_and_primitive_count) == 1);
   ralloc_free(shader);
}

static void
fragments_read_primitive_data_flat(void)
{
   struct stela_air_stage_options o = options(STELA_AIR_FRAGMENT);
   struct stela_air_error error;
   nir_shader *shader = translate_fixture(fragment, "fragment", &o, &error);
   if (!shader)
      fprintf(stderr, "fragment: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_foreach_variable_with_modes(var, shader, nir_var_shader_in) {
      assert(var->data.location == VARYING_SLOT_VAR0 + 1);
      assert(var->data.per_primitive && var->data.interpolation == INTERP_MODE_FLAT);
   }
   ralloc_free(shader);
}

static void
mesh_misuse_is_refused(void)
{
   struct stela_air_stage_options o = options(STELA_AIR_MESH);
   struct stela_air_error error;
   /* Data the mesh lacks, a value of another type and a dynamic data index. */
   refused(mesh(MESH("call void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7) %m, i32 1, i32 0,"
                     " <2 x float> zeroinitializer)\n"), mesh_metadata, &o, &error),
           &error, STELA_AIR_INSTRUCTION);
   refused(mesh(MESH("call void @air.set_vertex_data_mesh.v4f32(ptr addrspace(7) %m, i32 0, i32 0,"
                     " <4 x float> zeroinitializer)\n"), mesh_metadata, &o, &error),
           &error, STELA_AIR_TYPE);
   refused(mesh(MESH("call void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7) %m, i32 %tid, i32 0,"
                     " <2 x float> zeroinitializer)\n"), mesh_metadata, &o, &error),
           &error, STELA_AIR_INSTRUCTION);
   /* Vertex data is not primitive data. */
   refused(mesh(MESH("call void @air.set_primitive_data_mesh.v4f32(ptr addrspace(7) %m, i32 1, i32 0,"
                     " <4 x float> zeroinitializer)\n"), mesh_metadata, &o, &error),
           &error, STELA_AIR_INSTRUCTION);

   /* Capacities, payloads and threadgroups beyond the target's or the
    * function's limits. */
   o.max_mesh_vertices = 32;
   refused(mesh(mesh_body, mesh_metadata, &o, &error), &error, STELA_AIR_LIMIT);
   o = options(STELA_AIR_MESH);
   o.max_payload_bytes = 64;
   refused(mesh(mesh_body, mesh_metadata, &o, &error), &error, STELA_AIR_LIMIT);
   o = options(STELA_AIR_MESH);
   o.resources.workgroup_size[0] = 64;
   refused(mesh(mesh_body, mesh_metadata, &o, &error), &error, STELA_AIR_LIMIT);
   /* Compute-like functions need their workgroup; render ones are never
    * launched by a grid. */
   o = options(STELA_AIR_MESH);
   o.resources.workgroup_size[0] = 0;
   refused(mesh(mesh_body, mesh_metadata, &o, &error), &error, STELA_AIR_INPUT);
   o = options(STELA_AIR_FRAGMENT);
   o.launched_by_grid = true;
   refused(translate_fixture(fragment, "fragment", &o, &error), &error, STELA_AIR_INPUT);
}

static void
invalid_meshes_are_refused(void)
{
   struct stela_air_stage_options o = options(STELA_AIR_MESH);
   struct stela_air_error error;
   /* Two positions, a topology Metal lacks and duplicate data indices. */
   refused(mesh(mesh_body, replaced(mesh_metadata, "!51 = !{!60, !61, !62}", "!51 = !{!60, !61, !62, !60}"),
                &o, &error), &error, STELA_AIR_METADATA);
   refused(mesh(mesh_body, replaced(mesh_metadata, "!\"air.triangle\"", "!\"air.quad\""), &o, &error),
           &error, STELA_AIR_ARGUMENT);
   refused(mesh(mesh_body, replaced(mesh_metadata, "i32 0, !\"user(normal)\"", "i32 0, !\"user(color)\""),
                &o, &error), &error, STELA_AIR_METADATA);
   /* A payload without its size. */
   refused(mesh(mesh_body, replaced(mesh_metadata, "!\"air.arg_type_size\", i32 128, ", ""), &o, &error),
           &error, STELA_AIR_ARGUMENT);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   objects_launch_mesh_grids();
   meshes_output_primitives();
   fragments_read_primitive_data_flat();
   mesh_misuse_is_refused();
   invalid_meshes_are_refused();
   glsl_type_singleton_decref();
   puts("air mesh: ok");
   return 0;
}
