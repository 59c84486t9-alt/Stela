/* SPDX-License-Identifier: MIT */
/* The Metal device's compiler service: reflection and compilation of
 * kernels, linked vertex and fragment functions, and object and mesh
 * functions. Original LLVM IR fixtures, one AIR module per function as
 * libraries hold them; no Apple output. */
#include "../metal_compiler.h"
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

#define IDENT "Apple metal version 32023.922 (metalfe-32023.922.4)"

static const char *versions =
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"" IDENT "\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

/* Each thread stores its index to a static and a dynamic threadgroup array
 * and copies it out after a barrier. */
static const char *kernel =
   "@scratch = internal addrspace(3) global [16 x i32] undef, align 16\n"
   "declare void @air.wg.barrier(i32, i32) convergent\n"
   "define void @kernel(ptr addrspace(1) %data, ptr addrspace(3) %shared, i32 %tid) {\n"
   "%i = zext i32 %tid to i64\n"
   "%p = getelementptr i32, ptr addrspace(3) %shared, i64 %i\n"
   "store i32 %tid, ptr addrspace(3) %p, align 4\n"
   "store i32 %tid, ptr addrspace(3) @scratch, align 16\n"
   "call void @air.wg.barrier(i32 2, i32 1) convergent\n"
   "%v = load i32, ptr addrspace(3) %p, align 4\n"
   "%q = getelementptr i32, ptr addrspace(1) %data, i64 %i\n"
   "store i32 %v, ptr addrspace(1) %q, align 4\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @kernel, !3, !4, !5}\n!3 = !{}\n!5 = !{!\"air.max_work_group_size\", i32 64}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 2, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"shared\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

#define VERTEX_RESULT "<{ <4 x float>, <2 x float> }>"

static const char *vertex =
   "define " VERTEX_RESULT " @vertex(<4 x float> %p) {\n"
   "%uv = shufflevector <4 x float> %p, <4 x float> %p, <2 x i32> <i32 0, i32 1>\n"
   "%a0 = insertvalue " VERTEX_RESULT " undef, <4 x float> %p, 0\n"
   "%a1 = insertvalue " VERTEX_RESULT " %a0, <2 x float> %uv, 1\n"
   "ret " VERTEX_RESULT " %a1\n}\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @vertex, !3, !4}\n!3 = !{!30, !31}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!31 = !{!\"air.vertex_output\", !\"user(uv)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.vertex_input\", !\"air.location_index\", i32 3, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"p\"}\n";

/* Discards fragments left of the origin. */
static const char *fragment =
   "declare void @air.discard_fragment()\n"
   "define <4 x float> @fragment(<2 x float> %uv) {\n"
   "%x = extractelement <2 x float> %uv, i64 0\n"
   "%left = fcmp olt float %x, 0.0\n"
   "br i1 %left, label %discard, label %shade\n"
   "discard:\ncall void @air.discard_fragment()\nbr label %shade\n"
   "shade:\n%c = shufflevector <2 x float> %uv, <2 x float> %uv, <4 x i32> <i32 0, i32 1, i32 0, i32 1>\n"
   "ret <4 x float> %c\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @fragment, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.render_target\", i32 1, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.fragment_input\", !\"user(uv)\", !\"air.center\", !\"air.perspective\","
   " !\"air.arg_type_name\", !\"float2\", !\"air.arg_name\", !\"uv\"}\n";

static const char *object =
   "declare void @air.set_threadgroups_per_grid_mesh_properties(ptr addrspace(3), <3 x i32>)\n"
   "define void @object(ptr addrspace(6) %payload, ptr addrspace(3) %grid) {\n"
   "store i32 7, ptr addrspace(6) %payload, align 4\n"
   "call void @air.set_threadgroups_per_grid_mesh_properties(ptr addrspace(3) %grid,"
   " <3 x i32> <i32 1, i32 1, i32 1>)\n"
   "ret void\n}\n"
   "!air.object = !{!2}\n"
   "!2 = !{ptr @object, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.payload\", !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mtl_payload\"}\n"
   "!41 = !{i32 1, !\"air.mesh_grid_properties\", !\"air.arg_type_name\", !\"mesh_grid_properties\","
   " !\"air.arg_name\", !\"grid\"}\n";

static const char *mesh =
   "declare void @air.set_position_mesh(ptr addrspace(7), i32, <4 x float>)\n"
   "declare void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7), i32, i32, <2 x float>)\n"
   "declare void @air.set_primitive_count_mesh(ptr addrspace(7), i32)\n"
   "define void @mesh(ptr addrspace(7) %m, ptr addrspace(6) %payload, i32 %tid) {\n"
   "%s = load i32, ptr addrspace(6) %payload, align 4\n"
   "call void @air.set_position_mesh(ptr addrspace(7) %m, i32 %tid, <4 x float> zeroinitializer)\n"
   "call void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7) %m, i32 0, i32 %tid,"
   " <2 x float> zeroinitializer)\n"
   "call void @air.set_primitive_count_mesh(ptr addrspace(7) %m, i32 %s)\n"
   "ret void\n}\n"
   "!air.mesh = !{!2}\n"
   "!2 = !{ptr @mesh, !3, !4}\n!3 = !{}\n!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.mesh\", !50, !\"air.arg_type_name\", !\"mesh<>\", !\"air.arg_name\", !\"mtl_mesh\"}\n"
   "!50 = !{!\"air.mesh_type_info\", !51, !52, i32 3, i32 1, !\"air.triangle\"}\n"
   "!51 = !{!60, !61}\n!52 = !{}\n"
   "!60 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!61 = !{!\"air.mesh_vertex_data\", i32 0, !\"user(uv)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\"}\n"
   "!41 = !{i32 1, !\"air.payload\", !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mtl_payload\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

static const struct stela_metal_target target = {
   .nir = &nir_options, .max_instructions = 10000, .max_threadgroup_bytes = 32768,
   .max_private_bytes = 4096, .max_constant_bytes = 65536, .max_varying_slots = 16,
   .max_payload_bytes = 16384, .max_mesh_vertices = 256, .max_mesh_primitives = 256,
};

/* A fixture's bitcode: its code and metadata, then the versions. */
static LLVMMemoryBufferRef
bitcode(const char *fixture)
{
   const char *metadata = strstr(fixture, "\n!air.") + 1;
   char *body = ralloc_strndup(NULL, fixture, metadata - fixture);
   char *tail = ralloc_asprintf(body, "%s%s", metadata, versions);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, tail, "");
   ralloc_free(body);
   return input;
}

static bool
reflect(const char *fixture, const char *entry, struct stela_metal_reflection *reflection,
        struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(fixture);
   bool reflected = stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), entry,
                                        reflection, error);
   if (!reflected)
      fprintf(stderr, "%s: %u %s\n", entry, error->kind, error->detail);
   LLVMDisposeMemoryBuffer(input);
   return reflected;
}

static nir_shader *
compile(const char *fixture, const char *entry, const struct stela_metal_specialization *specialization,
        struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(fixture);
   nir_shader *shader = stela_metal_compile(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                            entry, &target, specialization, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static const char *
name(const struct stela_metal_reflection *reflection, uint32_t offset, uint32_t bytes)
{
   static char text[STELA_METAL_NAME_BYTES + 1];
   memcpy(text, reflection->names + offset, bytes);
   text[bytes] = 0;
   return text;
}

static void
kernels_reflect_and_compile_their_threadgroup_memory(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(kernel, "kernel", &reflection, &error));
   assert(reflection.stage == STELA_METAL_KERNEL && reflection.max_total_threads == 64);
   assert(reflection.buffer_count == 1 && reflection.buffers[0].index == 2);
   assert(reflection.buffers[0].access == (STELA_METAL_ACCESS_READ | STELA_METAL_ACCESS_WRITE));
   assert(reflection.threadgroup_count == 1 && reflection.threadgroup[0].index == 0 &&
          reflection.threadgroup[0].bytes == 4);
   assert(reflection.threadgroup_bytes == 64);
   assert(!strcmp(name(&reflection, reflection.ident, reflection.ident_bytes), IDENT));

   const struct stela_metal_threadgroup_length lengths[] = {{0, 256}};
   struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .threadgroup_length_count = 1, .threadgroup_lengths = lengths,
   };
   nir_shader *shader = compile(kernel, "kernel", &specialization, &error);
   if (!shader)
      fprintf(stderr, "kernel: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_COMPUTE);
   assert(shader->info.shared_size >= 256 + 64);
   stela_metal_release(shader);

   /* Each threadgroup buffer needs its dispatch's length. */
   specialization.threadgroup_length_count = 0;
   assert(!compile(kernel, "kernel", &specialization, &error) && error.kind != STELA_AIR_OK);
}

static nir_variable *
varying(nir_shader *shader, nir_variable_mode mode, int location)
{
   nir_foreach_variable_with_modes(var, shader, mode) {
      if (var->data.location == location)
         return var;
   }
   return NULL;
}

static void
render_stages_compile_at_their_linked_locations(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(vertex, "vertex", &reflection, &error));
   assert(reflection.stage == STELA_METAL_VERTEX && reflection.varying_count == 1);
   assert(reflection.attribute_count == 1 && reflection.attributes[0].index == 3 &&
          reflection.attributes[0].components == 4);
   const struct stela_metal_varying *uv = &reflection.varyings[0];
   assert(!strcmp(name(&reflection, uv->identifier, uv->identifier_bytes), "user(uv)"));
   assert(uv->primitive == STELA_AIR_FLOAT && uv->components == 2 && !uv->per_primitive);

   assert(reflect(fragment, "fragment", &reflection, &error));
   assert(reflection.stage == STELA_METAL_FRAGMENT && reflection.discards);
   assert(reflection.varying_count == 1 && reflection.color_output_count == 1);
   assert(reflection.color_outputs[0].index == 1 && !reflection.color_outputs[0].dual_source);

   /* user(uv) is the second linked varying. */
   const struct stela_metal_linked_varying linked[] = {
      {"user(color)", 11, 0}, {"user(uv)", 8, 0},
   };
   const struct stela_metal_specialization specialization = {.varyings = linked, .varying_count = 2};
   nir_shader *shaders[2] = {
      compile(vertex, "vertex", &specialization, &error),
      compile(fragment, "fragment", &specialization, &error),
   };
   assert(shaders[0] && shaders[1]);
   assert(varying(shaders[0], nir_var_shader_out, VARYING_SLOT_VAR0 + 1));
   assert(varying(shaders[1], nir_var_shader_in, VARYING_SLOT_VAR0 + 1));
   for (unsigned i = 0; i < 2; i++)
      stela_metal_release(shaders[i]);

   /* A varying the pipeline did not link is refused. */
   const struct stela_metal_specialization unlinked = {.varyings = linked, .varying_count = 1};
   assert(!compile(fragment, "fragment", &unlinked, &error) && error.kind == STELA_AIR_ARGUMENT);
   /* As are entries no AIR list names. */
   assert(!reflect(vertex, "missing", &reflection, &error) && error.kind == STELA_AIR_ARGUMENT);
}

static void
mesh_stages_compile_with_their_launch(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(object, "object", &reflection, &error));
   assert(reflection.stage == STELA_METAL_OBJECT && !reflection.buffer_count);
   assert(reflect(mesh, "mesh", &reflection, &error));
   assert(reflection.stage == STELA_METAL_MESH && reflection.varying_count == 1);

   const struct stela_metal_specialization launch = {
      .workgroup_size = {32, 1, 1}, .launched_by_grid = 1,
   };
   nir_shader *shader = compile(object, "object", &launch, &error);
   if (!shader)
      fprintf(stderr, "object: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_TASK);
   stela_metal_release(shader);

   const struct stela_metal_linked_varying linked[] = {{"user(uv)", 8, 0}};
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {32, 1, 1}, .varyings = linked, .varying_count = 1,
   };
   shader = compile(mesh, "mesh", &specialization, &error);
   if (!shader)
      fprintf(stderr, "mesh: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_MESH);
   assert(varying(shader, nir_var_shader_out, VARYING_SLOT_VAR0));
   stela_metal_release(shader);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   kernels_reflect_and_compile_their_threadgroup_memory();
   render_stages_compile_at_their_linked_locations();
   mesh_stages_compile_with_their_launch();
   glsl_type_singleton_decref();
   puts("metal compiler: ok");
   return 0;
}
