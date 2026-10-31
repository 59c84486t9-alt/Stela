/* SPDX-License-Identifier: MIT */
/* Stage-in the functions fetch themselves: post-tessellation vertex
 * functions' control points and per-patch attributes, and kernels'.
 * Original LLVM IR fixtures in the forms air_metadata.c documents; no Apple
 * output. */
#include "compiler/air_to_nir.h"
#include "air_test_fixture.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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

#define RESULT "<{ <4 x float>, <4 x float>, <2 x float>, i32 }>"
#define POINT "{ <4 x float>, <2 x float> }"

/* A quad patch's function: a control point the patch ID selects gives the
 * position, the patch its color, and another control point the texture
 * coordinates it offsets by the position in the patch. */
static const char *quad =
   "define " RESULT " @patch(ptr %points, <4 x float> %color, <2 x float> %at, i32 %id,"
   " i32 %instance) {\n"
   "%index = and i32 %id, 3\n"
   "%p = call " POINT " @control_point(i32 %index, ptr %points)\n"
   "%position = extractvalue " POINT " %p, 0\n"
   "%q = call " POINT " @control_point(i32 1, ptr %points)\n"
   "%uv = extractvalue " POINT " %q, 1\n"
   "%offset = fadd <2 x float> %uv, %at\n"
   "%points_in_patch = call i32 @air.get_num_patch_control_points()\n"
   "%sum = add i32 %id, %instance\n"
   "%ids = add i32 %sum, %points_in_patch\n"
   "%r0 = insertvalue " RESULT " undef, <4 x float> %position, 0\n"
   "%r1 = insertvalue " RESULT " %r0, <4 x float> %color, 1\n"
   "%r2 = insertvalue " RESULT " %r1, <2 x float> %offset, 2\n"
   "%r3 = insertvalue " RESULT " %r2, i32 %ids, 3\n"
   "ret " RESULT " %r3\n}\n"
   "declare " POINT " @control_point(i32, ptr) section \"air.externally_defined\"\n"
   "declare i32 @air.get_num_patch_control_points()\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @patch, !3, !4, !5}\n"
   "!3 = !{!30, !31, !32, !33}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!31 = !{!\"air.vertex_output\", !\"user(color)\", !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!32 = !{!\"air.vertex_output\", !\"user(uv)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\"}\n"
   "!33 = !{!\"air.vertex_output\", !\"user(id)\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"id\"}\n"
   "!4 = !{!40, !41, !42, !43, !44}\n"
   "!40 = !{i32 0, !\"air.patch_control_point_input\", !45, !46, !47}\n"
   "!45 = !{!\"air.patch_control_point_function\", ptr @control_point}\n"
   "!46 = !{!\"air.location_index\", i32 0, i32 1, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"position\"}\n"
   "!47 = !{!\"air.location_index\", i32 1, i32 1, !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\"}\n"
   "!41 = !{i32 1, !\"air.patch_input\", !\"air.location_index\", i32 2, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"color\"}\n"
   "!42 = !{i32 2, !\"air.position_in_patch\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"at\"}\n"
   "!43 = !{i32 3, !\"air.patch_id\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"id\"}\n"
   "!44 = !{i32 4, !\"air.instance_id\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"instance\"}\n"
   "!5 = !{!\"air.patch\", !\"quad\", !\"air.patch_control_point\", i32 4}\n";

static const struct stela_air_varying_slot varyings[] = {
   {"user(color)", 11, STELA_AIR_FLOAT, 4, 0},
   {"user(uv)", 8, STELA_AIR_FLOAT, 2, 1},
   {"user(id)", 8, STELA_AIR_UINT, 1, 2},
};

/* The fetches a translation asks for, in order. */
static struct fetch {
   unsigned location;
   bool point, integer;
} fetches[8];
static unsigned fetch_count;
static nir_def *patch_ids;

static nir_def *
load_device_value(nir_builder *b, enum stela_air_device_value value, void *data)
{
   (void)data;
   assert(value == STELA_AIR_PATCH_IDS);
   patch_ids = nir_load_push_constant(b, 3, 32, nir_imm_int(b, 0), .base = 0, .range = 12);
   return patch_ids;
}

/* Patch functions fetch at their patch IDs, kernels at a position. */
static nir_def *
fetch_attribute(nir_builder *b, unsigned location, nir_def *at, nir_def *point, bool integer,
                void *data)
{
   (void)data;
   assert(at->num_components == 3 && (!patch_ids || at == patch_ids));
   assert(fetch_count < ARRAY_SIZE(fetches));
   fetches[fetch_count++] = (struct fetch){location, point != NULL, integer};
   nir_def *address = nir_imm_int64(b, 16 * location);
   return nir_load_global(b, 4, 32, address, .access = ACCESS_NON_WRITEABLE, .align_mul = 16);
}

static char *
change(const char *source, const char *old, const char *replacement)
{
   const char *at = strstr(source, old);
   assert(at);
   size_t first = (size_t)(at - source);
   char *result = malloc(strlen(source) - strlen(old) + strlen(replacement) + 1);
   assert(result);
   memcpy(result, source, first);
   strcpy(result + first, replacement);
   strcpy(result + first + strlen(replacement), at + strlen(old));
   return result;
}

static LLVMMemoryBufferRef
bitcode(const char *text)
{
   const char *metadata = strstr(text, "!air.");
   char *body = strndup(text, (size_t)(metadata - text));
   assert(body);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, metadata, versions);
   free(body);
   return input;
}

static nir_shader *
translate(const char *text, bool fetch, struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(text);
   struct stela_air_stage_options o = {
      .stage = STELA_AIR_VERTEX, .max_varying_slots = 16, .varyings = varyings,
      .varying_count = ARRAY_SIZE(varyings),
      .resources = {
         .max_instructions = 10000, .max_constant_bytes = 65536,
         .fp_profile = STELA_AIR_FP_METAL,
         .load_device_value = load_device_value, .fetch_attribute = fetch ? fetch_attribute : NULL,
      },
   };
   fetch_count = 0;
   patch_ids = NULL;
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               "patch", &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static bool
capture(const struct stela_air_inspection *info, const struct stela_air_stage_entry *entry, void *data)
{
   (void)info;
   const struct stela_air_stage_io *in = entry->inputs;
   assert(entry->patch == STELA_AIR_PATCH_QUAD && entry->patch_control_points == 4);
   assert(entry->input_count == 5 && entry->output_count == 4);
   assert(in[0].semantic == STELA_AIR_CONTROL_POINTS && in[0].member_count == 2);
   assert(in[0].members[0].location == 0 && in[0].members[0].components == 4);
   assert(in[0].members[1].location == 1 && in[0].members[1].primitive == STELA_AIR_FLOAT &&
          in[0].members[1].components == 2 && !in[0].members[1].unused);
   assert(in[1].semantic == STELA_AIR_VERTEX_INPUT && in[1].location == 2 && in[1].components == 4);
   assert(in[2].semantic == STELA_AIR_POSITION_IN_PATCH && in[2].components == 2);
   assert(in[3].semantic == STELA_AIR_STAGE_BUILTIN && in[3].builtin == STELA_AIR_PATCH_ID);
   assert(in[4].semantic == STELA_AIR_STAGE_BUILTIN && in[4].builtin == STELA_AIR_INSTANCE_ID);
   *(bool *)data = true;
   return true;
}

static void
patch_metadata_reflects_control_points_and_patch_inputs(void)
{
   LLVMMemoryBufferRef input = bitcode(quad);
   struct stela_air_error error = {0};
   bool seen = false;
   bool inspected = stela_air_inspect_stage(LLVMGetBufferStart(input), LLVMGetBufferSize(input), NULL,
                                            "patch", STELA_AIR_VERTEX, capture, &seen, &error);
   if (!inspected)
      fprintf(stderr, "inspection: %u %s\n", error.kind, error.detail);
   assert(inspected && seen);
   LLVMDisposeMemoryBuffer(input);
}

/* A patch that declares no control points leaves its size to the draw. */
static void
uncounted_patches_refuse_their_size(void)
{
   const char *count = ", !\"air.patch_control_point\", i32 4";
   const char *at = strstr(quad, count);
   assert(at);
   char *text = malloc(strlen(quad) + 1);
   assert(text);
   memcpy(text, quad, (size_t)(at - quad));
   strcpy(text + (at - quad), at + strlen(count));
   struct stela_air_error error = {0};
   assert(!translate(text, true, &error));
   if (error.kind != STELA_AIR_INSTRUCTION)
      fprintf(stderr, "uncounted patch: %u %s\n", error.kind, error.detail);
   assert(error.kind == STELA_AIR_INSTRUCTION && strstr(error.detail, "no control points"));
   free(text);
}

static unsigned
intrinsics(nir_shader *shader, nir_intrinsic_op op)
{
   unsigned count = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            count += instr->type == nir_instr_type_intrinsic &&
                     nir_instr_as_intrinsic(instr)->intrinsic == op;
         }
      }
   }
   return count;
}

static void
patch_functions_become_evaluation_shaders(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(quad, true, &error);
   if (!shader)
      fprintf(stderr, "patch: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_TESS_EVAL);
   assert(shader->info.tess._primitive_mode == TESS_PRIMITIVE_QUADS);
   assert(intrinsics(shader, nir_intrinsic_load_tess_coord) == 1);
   /* The patch's color, then both members of each control point read. */
   const struct fetch expected[] = {
      {2, false, false}, {0, true, false}, {1, true, false}, {0, true, false}, {1, true, false},
   };
   assert(fetch_count == ARRAY_SIZE(expected));
   for (unsigned i = 0; i < fetch_count; i++) {
      assert(fetches[i].location == expected[i].location && fetches[i].point == expected[i].point &&
             fetches[i].integer == expected[i].integer);
   }
   ralloc_free(shader);
}

static void
refuse(const char *text, bool fetch, enum stela_air_error_kind kind)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(text, fetch, &error);
   if (shader || error.kind != kind)
      fprintf(stderr, "expected refusal %u: %u %s\n", kind, error.kind, error.detail);
   assert(!shader && error.kind == kind);
}

static void
patch_functions_refuse_what_they_cannot_read(void)
{
   /* No stage-in fetch. */
   refuse(quad, false, STELA_AIR_ARGUMENT);
   /* Triangles are at a float3. */
   char *text = change(quad, "!\"quad\"", "!\"triangle\"");
   refuse(text, true, STELA_AIR_ARGUMENT);
   free(text);
   /* Patch functions run per tessellated vertex, without vertex IDs. */
   text = change(quad, "air.instance_id", "air.vertex_id");
   refuse(text, true, STELA_AIR_ARGUMENT);
   free(text);
   /* Every attribute has its own location. */
   text = change(quad, "i32 2, i32 1,", "i32 1, i32 1,");
   refuse(text, true, STELA_AIR_ARGUMENT);
   free(text);
   /* Only patch functions take control points. */
   text = change(quad, ", !5}\n", "}\n");
   refuse(text, true, STELA_AIR_ARGUMENT);
   free(text);
}

/* A kernel storing the stage-in value at its thread position; it never
 * reads its index. */
static const char *kernel =
   "define void @kernel(<4 x float> %value, <2 x i32> %index, ptr addrspace(1) %out, i32 %gid) {\n"
   "%slot = zext i32 %gid to i64\n"
   "%at = getelementptr <4 x float>, ptr addrspace(1) %out, i64 %slot\n"
   "store <4 x float> %value, ptr addrspace(1) %at, align 16\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n"
   "!4 = !{!40, !41, !42, !43}\n"
   "!40 = !{i32 0, !\"air.stage_in\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"value\"}\n"
   "!41 = !{i32 1, !\"air.stage_in\", !\"air.location_index\", i32 1, i32 1,"
   " !\"air.arg_type_name\", !\"uint2\", !\"air.arg_name\", !\"index\"}\n"
   "!42 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"out\"}\n"
   "!43 = !{i32 3, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"gid\"}\n";

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   (void)buffer;
   (void)data;
   return nir_load_push_constant(b, 1, 64, nir_imm_int(b, 0), .base = 16, .range = 8);
}

static nir_shader *
translate_kernel(const char *text, struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(text);
   const struct stela_air_options o = {
      .max_instructions = 10000, .workgroup_size = {64, 1, 1}, .bind_buffer = bind_buffer,
      .fp_profile = STELA_AIR_FP_METAL, .fetch_attribute = fetch_attribute,
   };
   fetch_count = 0;
   patch_ids = NULL;
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static bool
reflect_kernel(const struct stela_air_inspection *info, const struct stela_air_entry *entry,
               void *data)
{
   (void)info;
   const struct stela_air_argument_info *arguments = entry->arguments;
   assert(entry->argument_count == 4);
   assert(arguments[0].kind == 5 && arguments[0].location == 0 &&
          arguments[0].primitive == STELA_AIR_FLOAT && arguments[0].type_components == 4);
   assert(arguments[1].kind == 5 && arguments[1].location == 1 &&
          arguments[1].primitive == STELA_AIR_UINT && !arguments[1].used);
   *(bool *)data = true;
   return true;
}

static void
kernels_fetch_their_stage_in_at_their_position(void)
{
   LLVMMemoryBufferRef input = bitcode(kernel);
   struct stela_air_error error = {0};
   bool seen = false;
   assert(stela_air_inspect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), NULL, 8, reflect_kernel,
                            &seen, &error) && seen);
   LLVMDisposeMemoryBuffer(input);

   nir_shader *shader = translate_kernel(kernel, &error);
   if (!shader)
      fprintf(stderr, "kernel: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_COMPUTE);
   /* Only the attribute it reads. */
   assert(fetch_count == 1 && fetches[0].location == 0 && !fetches[0].point &&
          !fetches[0].integer);
   ralloc_free(shader);

   /* Attributes have their own locations. */
   char *text = change(kernel, "i32 1, i32 1, !\"air.arg_type_name\", !\"uint2\"",
                       "i32 0, i32 1, !\"air.arg_type_name\", !\"uint2\"");
   assert(!translate_kernel(text, &error) && error.kind == STELA_AIR_ARGUMENT);
   free(text);
}

int
main(void)
{
   patch_metadata_reflects_control_points_and_patch_inputs();
   patch_functions_become_evaluation_shaders();
   patch_functions_refuse_what_they_cannot_read();
   uncounted_patches_refuse_their_size();
   kernels_fetch_their_stage_in_at_their_position();
   printf("AIR stage-in tests passed\n");
   return 0;
}
