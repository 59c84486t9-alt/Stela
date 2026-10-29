/* SPDX-License-Identifier: MIT */
/* AIR render stage inputs and outputs. Original LLVM IR fixtures in the
 * argument and output forms air_metadata.c documents; no Apple output. */
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

#define VERTEX_RESULT "<{ <4 x float>, <2 x float>, i32, float, i32, i32 }>"

/* Stage-in attributes become a position, two varyings, a point size and the
 * layer and viewport. */
static const char *vertex =
   "define " VERTEX_RESULT " @vertex(<4 x float> %p, <2 x i32> %ids, i16 %narrow) {\n"
   "%c = shufflevector <4 x float> %p, <4 x float> %p, <2 x i32> <i32 0, i32 1>\n"
   "%id = extractelement <2 x i32> %ids, i32 1\n"
   "%layer = extractelement <2 x i32> %ids, i32 0\n"
   "%a0 = insertvalue " VERTEX_RESULT " undef, <4 x float> %p, 0\n"
   "%a1 = insertvalue " VERTEX_RESULT " %a0, <2 x float> %c, 1\n"
   "%a2 = insertvalue " VERTEX_RESULT " %a1, i32 %id, 2\n"
   "%a3 = insertvalue " VERTEX_RESULT " %a2, float 2.0, 3\n"
   "%a4 = insertvalue " VERTEX_RESULT " %a3, i32 %layer, 4\n"
   "%a5 = insertvalue " VERTEX_RESULT " %a4, i32 %id, 5\n"
   "ret " VERTEX_RESULT " %a5\n}\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @vertex, !3, !4}\n"
   "!3 = !{!30, !31, !32, !33, !34, !35}\n"
   "!30 = !{!\"air.position\", !\"air.invariant\", !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"position\"}\n"
   "!31 = !{!\"air.vertex_output\", !\"user(color)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!32 = !{!\"air.vertex_output\", !\"user(id)\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"id\"}\n"
   "!33 = !{!\"air.point_size\", !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"size\"}\n"
   "!34 = !{!\"air.render_target_array_index\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"layer\"}\n"
   "!35 = !{!\"air.viewport_array_index\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"viewport\"}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.vertex_input\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"p\"}\n"
   "!41 = !{i32 1, !\"air.vertex_input\", !\"air.location_index\", i32 3, i32 1,"
   " !\"air.arg_type_name\", !\"uint2\", !\"air.arg_name\", !\"ids\"}\n"
   "!42 = !{i32 2, !\"air.vertex_input\", !\"air.location_index\", i32 5, i32 1,"
   " !\"air.arg_type_name\", !\"short\", !\"air.arg_name\", !\"narrow\"}\n";

/* A vertex function writing only its position, for amplification. */
static const char *position_only =
   "define <4 x float> @vertex(<4 x float> %p) {\nret <4 x float> %p\n}\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @vertex, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.vertex_input\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"p\"}\n";

#define FRAGMENT_RESULT "<{ <4 x float>, <4 x i32>, float, i32, i32 }>"

/* Centroid, flat and sample inputs become two render targets, depth, a
 * sample mask and a stencil reference. */
static const char *fragment =
   "define " FRAGMENT_RESULT " @fragment(<2 x float> %color, i32 %id, float %s) {\n"
   "%c = shufflevector <2 x float> %color, <2 x float> %color, <4 x i32> <i32 0, i32 1, i32 0, i32 1>\n"
   "%u = insertelement <4 x i32> zeroinitializer, i32 %id, i32 0\n"
   "%a0 = insertvalue " FRAGMENT_RESULT " undef, <4 x float> %c, 0\n"
   "%a1 = insertvalue " FRAGMENT_RESULT " %a0, <4 x i32> %u, 1\n"
   "%a2 = insertvalue " FRAGMENT_RESULT " %a1, float %s, 2\n"
   "%a3 = insertvalue " FRAGMENT_RESULT " %a2, i32 %id, 3\n"
   "%a4 = insertvalue " FRAGMENT_RESULT " %a3, i32 7, 4\n"
   "ret " FRAGMENT_RESULT " %a4\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @fragment, !3, !4}\n"
   "!3 = !{!30, !31, !32, !33, !34}\n"
   "!30 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!31 = !{!\"air.render_target\", i32 1, i32 0, !\"air.arg_type_name\", !\"uint4\","
   " !\"air.arg_name\", !\"ids\"}\n"
   "!32 = !{!\"air.depth\", !\"air.depth_qualifier\", !\"air.greater\", !\"air.arg_type_name\","
   " !\"float\", !\"air.arg_name\", !\"depth\"}\n"
   "!33 = !{!\"air.sample_mask\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mask\"}\n"
   "!34 = !{!\"air.stencil\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"stencil\"}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.fragment_input\", !\"user(color)\", !\"air.centroid\", !\"air.perspective\","
   " !\"air.arg_type_name\", !\"float2\", !\"air.arg_name\", !\"color\"}\n"
   "!41 = !{i32 1, !\"air.fragment_input\", !\"user(id)\", !\"air.flat\","
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"id\"}\n"
   "!42 = !{i32 2, !\"air.fragment_input\", !\"user(s)\", !\"air.sample\", !\"air.no_perspective\","
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"s\"}\n";

static const struct stela_air_varying_slot varyings[] = {
   {"user(color)", 11, STELA_AIR_FLOAT, 2, 0},
   {"user(id)", 8, STELA_AIR_UINT, 1, 1},
   {"user(s)", 7, STELA_AIR_FLOAT, 1, 2},
};

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};

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

static nir_shader *
translate(const char *text, enum stela_air_stage stage, bool amplified,
          struct stela_air_error *error)
{
   size_t bytes = strlen(text) + strlen(versions) + 1;
   char *source = malloc(bytes);
   assert(source);
   const char *entry = strstr(text, "!air.");
   snprintf(source, bytes, "%.*s", (int)(entry - text), text);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, source, entry, versions);
   free(source);
   struct stela_air_stage_options o = {
      .stage = stage, .max_varying_slots = 16, .varyings = varyings,
      .varying_count = ARRAY_SIZE(varyings), .amplified = amplified,
      .resources = {
         .max_instructions = 10000, .bind_buffer = stela_metal_bind_buffer, .binding_data = &primary,
         .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41,
         .load_device_value = stela_metal_load_device_value, .max_constant_bytes = 65536,
      },
   };
   const char *name = stage == STELA_AIR_VERTEX ? "vertex" : "fragment";
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               name, &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static nir_variable *
variable(nir_shader *shader, nir_variable_mode mode, int location, unsigned index)
{
   nir_foreach_variable_with_modes(var, shader, mode) {
      if (var->data.location == location && var->data.index == index)
         return var;
   }
   return NULL;
}

static bool
typed(const nir_variable *var, enum glsl_base_type base, unsigned components)
{
   return var && glsl_get_base_type(var->type) == base &&
          glsl_get_vector_elements(var->type) == components;
}

static unsigned
view_mapping_loads(nir_shader *shader)
{
   unsigned loads = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_load_push_constant &&
                nir_intrinsic_base(nir_instr_as_intrinsic(instr)) == STELA_METAL_PUSH_VIEW_MAPPING)
               loads++;
         }
      }
   }
   return loads;
}

static void
vertex_functions_fetch_attributes_and_write_builtins(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(vertex, STELA_AIR_VERTEX, false, &error);
   if (!shader)
      fprintf(stderr, "vertex: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   assert(typed(variable(shader, nir_var_shader_in, VERT_ATTRIB_GENERIC0, 0), GLSL_TYPE_FLOAT, 4));
   assert(typed(variable(shader, nir_var_shader_in, VERT_ATTRIB_GENERIC0 + 3, 0), GLSL_TYPE_UINT, 2));
   /* Narrow attributes arrive in 32-bit lanes. */
   assert(typed(variable(shader, nir_var_shader_in, VERT_ATTRIB_GENERIC0 + 5, 0), GLSL_TYPE_INT, 1));
   nir_variable *position = variable(shader, nir_var_shader_out, VARYING_SLOT_POS, 0);
   assert(typed(position, GLSL_TYPE_FLOAT, 4) && position->data.invariant);
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_VAR0, 0), GLSL_TYPE_FLOAT, 2));
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_VAR1, 0), GLSL_TYPE_UINT, 1));
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_PSIZ, 0), GLSL_TYPE_FLOAT, 1));
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_LAYER, 0), GLSL_TYPE_INT, 1));
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_VIEWPORT, 0), GLSL_TYPE_INT, 1));
   assert(!view_mapping_loads(shader));
   ralloc_free(shader);

   /* Amplified, the layer and viewport take the view's offsets. */
   shader = translate(vertex, STELA_AIR_VERTEX, true, &error);
   assert(shader && view_mapping_loads(shader) == 1);
   ralloc_free(shader);
   shader = translate(position_only, STELA_AIR_VERTEX, true, &error);
   assert(shader && view_mapping_loads(shader) == 1);
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_LAYER, 0), GLSL_TYPE_INT, 1));
   assert(typed(variable(shader, nir_var_shader_out, VARYING_SLOT_VIEWPORT, 0), GLSL_TYPE_INT, 1));
   ralloc_free(shader);
}

/* position_only with a buffer `v` in `space` and its body. */
static char *
with_buffer(unsigned space, const char *body)
{
   char definition[1024], argument[512];
   snprintf(definition, sizeof(definition),
            "define <4 x float> @vertex(<4 x float> %%p, ptr addrspace(%u) %%v) {\n%s}\n", space, body);
   snprintf(argument, sizeof(argument),
            "!4 = !{!40, !41}\n"
            "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
            " !\"air.address_space\", i32 %u, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
            " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"v\"}\n", space);
   char *signature = change(position_only, "define <4 x float> @vertex(<4 x float> %p) {\nret <4 x float> %p\n}\n",
                            definition);
   char *text = change(signature, "!4 = !{!40}\n", argument);
   free(signature);
   return text;
}

/* A vertex function reads and writes a device buffer. */
static void
vertex_functions_access_device_buffers(void)
{
   char *text = with_buffer(1, "%l = load <4 x float>, ptr addrspace(1) %v, align 16\n"
                               "%w = getelementptr <4 x float>, ptr addrspace(1) %v, i64 1\n"
                               "store <4 x float> %p, ptr addrspace(1) %w, align 16\nret <4 x float> %l\n");
   struct stela_air_error error = {0};
   nir_shader *shader = translate(text, STELA_AIR_VERTEX, false, &error);
   if (!shader)
      fprintf(stderr, "device buffer: %u %s\n", error.kind, error.detail);
   assert(shader);
   ralloc_free(shader);
   free(text);

   /* Render functions have no threadgroup buffers. */
   text = with_buffer(3, "ret <4 x float> %p\n");
   assert(!translate(text, STELA_AIR_VERTEX, false, &error) && error.kind == STELA_AIR_ARGUMENT);
   free(text);
}

/* A vertex function reads constant data, as a table of positions. */
static void
vertex_functions_read_constant_data(void)
{
   char *table = change(position_only, "define <4 x float> @vertex(<4 x float> %p) {\nret <4 x float> %p\n}\n",
      "@positions = internal addrspace(2) constant [3 x <4 x float>] [<4 x float> zeroinitializer,"
      " <4 x float> <float 1.0, float 0.0, float 0.0, float 1.0>,"
      " <4 x float> <float 0.0, float 1.0, float 0.0, float 1.0>], align 16\n"
      "define <4 x float> @vertex(<4 x float> %p) {\n"
      "%x = extractelement <4 x float> %p, i32 0\n%i = fptoui float %x to i32\n"
      "%e = getelementptr [3 x <4 x float>], ptr addrspace(2) @positions, i32 0, i32 %i\n"
      "%v = load <4 x float>, ptr addrspace(2) %e, align 16\nret <4 x float> %v\n}\n");
   struct stela_air_error error = {0};
   nir_shader *shader = translate(table, STELA_AIR_VERTEX, false, &error);
   if (!shader)
      fprintf(stderr, "constant data: %u %s\n", error.kind, error.detail);
   assert(shader && shader->constant_data_size == 48);
   ralloc_free(shader);
   free(table);

   /* Render functions have no threadgroup memory. */
   char *shared = change(position_only, "define", "@s = internal addrspace(3) global i32 undef, align 4\ndefine");
   assert(!translate(shared, STELA_AIR_VERTEX, false, &error) && error.kind == STELA_AIR_TARGET);
   free(shared);
}

static void
fragment_functions_interpolate_and_write_targets(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = translate(fragment, STELA_AIR_FRAGMENT, false, &error);
   if (!shader)
      fprintf(stderr, "fragment: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_variable *color = variable(shader, nir_var_shader_in, VARYING_SLOT_VAR0, 0);
   assert(typed(color, GLSL_TYPE_FLOAT, 2) && color->data.interpolation == INTERP_MODE_SMOOTH &&
          color->data.centroid && !color->data.sample);
   nir_variable *id = variable(shader, nir_var_shader_in, VARYING_SLOT_VAR1, 0);
   assert(typed(id, GLSL_TYPE_UINT, 1) && id->data.interpolation == INTERP_MODE_FLAT);
   nir_variable *s = variable(shader, nir_var_shader_in, VARYING_SLOT_VAR2, 0);
   assert(typed(s, GLSL_TYPE_FLOAT, 1) && s->data.interpolation == INTERP_MODE_NOPERSPECTIVE &&
          s->data.sample);
   assert(typed(variable(shader, nir_var_shader_out, FRAG_RESULT_DATA0, 0), GLSL_TYPE_FLOAT, 4));
   assert(typed(variable(shader, nir_var_shader_out, FRAG_RESULT_DATA1, 0), GLSL_TYPE_UINT, 4));
   assert(typed(variable(shader, nir_var_shader_out, FRAG_RESULT_DEPTH, 0), GLSL_TYPE_FLOAT, 1));
   assert(shader->info.fs.depth_layout == FRAG_DEPTH_LAYOUT_GREATER);
   assert(typed(variable(shader, nir_var_shader_out, FRAG_RESULT_SAMPLE_MASK, 0), GLSL_TYPE_INT, 1));
   assert(typed(variable(shader, nir_var_shader_out, FRAG_RESULT_STENCIL, 0), GLSL_TYPE_INT, 1));
   ralloc_free(shader);

   /* Dual-source blending: index 1 of attachment 0. */
   char *dual = change(fragment, "!\"air.render_target\", i32 1, i32 0", "!\"air.render_target\", i32 0, i32 1");
   shader = translate(dual, STELA_AIR_FRAGMENT, false, &error);
   free(dual);
   assert(shader && variable(shader, nir_var_shader_out, FRAG_RESULT_DATA0, 1));
   ralloc_free(shader);
}

static void
refuses_unrepresentable_render_io(void)
{
   const struct {
      const char *text, *old, *replacement;
      enum stela_air_stage stage;
      enum stela_air_error_kind kind;
   } cases[] = {
      /* Integer varyings are flat. */
      {fragment, "!\"user(id)\", !\"air.flat\"", "!\"user(id)\", !\"air.center\", !\"air.perspective\"",
       STELA_AIR_FRAGMENT, STELA_AIR_ARGUMENT},
      /* Flat inputs have no sampling location. */
      {fragment, "!\"user(id)\", !\"air.flat\"", "!\"user(id)\", !\"air.center\", !\"air.flat\"",
       STELA_AIR_FRAGMENT, STELA_AIR_ARGUMENT},
      /* Interpolated inputs need one. */
      {fragment, "!\"air.centroid\", !\"air.perspective\"", "!\"air.perspective\"",
       STELA_AIR_FRAGMENT, STELA_AIR_ARGUMENT},
      /* Eight color attachments. */
      {fragment, "!\"air.render_target\", i32 1, i32 0", "!\"air.render_target\", i32 8, i32 0",
       STELA_AIR_FRAGMENT, STELA_AIR_ARGUMENT},
      /* Dual-source blending writes only attachment 0. */
      {fragment, "!\"air.render_target\", i32 1, i32 0", "!\"air.render_target\", i32 1, i32 1",
       STELA_AIR_FRAGMENT, STELA_AIR_ARGUMENT},
      {fragment, "!\"air.render_target\", i32 1, i32 0", "!\"air.render_target\", i32 0, i32 0",
       STELA_AIR_FRAGMENT, STELA_AIR_METADATA},
      {fragment, "!\"air.greater\"", "!\"air.sideways\"", STELA_AIR_FRAGMENT, STELA_AIR_METADATA},
      {fragment, "!\"air.stencil\", !\"air.arg_type_name\", !\"uint\"",
       "!\"air.stencil\", !\"air.arg_type_name\", !\"float\"", STELA_AIR_FRAGMENT, STELA_AIR_TYPE},
      {vertex, "!\"air.point_size\", !\"air.arg_type_name\", !\"float\"",
       "!\"air.point_size\", !\"air.arg_type_name\", !\"uint\"", STELA_AIR_VERTEX, STELA_AIR_TYPE},
      {vertex, "!\"air.viewport_array_index\"", "!\"air.clip_distance\"", STELA_AIR_VERTEX,
       STELA_AIR_ARGUMENT},
      {vertex, "!\"air.viewport_array_index\"", "!\"air.render_target_array_index\"",
       STELA_AIR_VERTEX, STELA_AIR_METADATA},
      /* Attributes are unique and below Metal's 31. */
      {vertex, "i32 5, i32 1", "i32 3, i32 1", STELA_AIR_VERTEX, STELA_AIR_ARGUMENT},
      {vertex, "i32 5, i32 1", "i32 31, i32 1", STELA_AIR_VERTEX, STELA_AIR_ARGUMENT},
      {vertex, "i32 5, i32 1", "i32 5, i32 2", STELA_AIR_VERTEX, STELA_AIR_ARGUMENT},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      char *text = change(cases[i].text, cases[i].old, cases[i].replacement);
      struct stela_air_error error = {0};
      nir_shader *shader = translate(text, cases[i].stage, false, &error);
      if (shader || error.kind != cases[i].kind)
         fprintf(stderr, "case %u: %u %s\n", i, error.kind, error.detail);
      assert(!shader && error.kind == cases[i].kind);
      free(text);
   }
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   vertex_functions_fetch_attributes_and_write_builtins();
   vertex_functions_read_constant_data();
   vertex_functions_access_device_buffers();
   fragment_functions_interpolate_and_write_targets();
   refuses_unrepresentable_render_io();
   glsl_type_singleton_decref();
   puts("air render io: ok");
   return 0;
}
