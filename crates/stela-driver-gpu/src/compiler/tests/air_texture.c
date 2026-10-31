/* SPDX-License-Identifier: MIT */
/* AIR texture functions over the Metal ABI's heap binds. Original LLVM IR
 * fixtures in the AIR call shapes air_texture.c documents; no Apple output. */
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
   "declare { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2),"
   " <2 x float>, i1, <2 x i32>, i1, float, float, i32)\n"
   "declare { float, i8 } @air.sample_compare_depth_2d.f32(ptr addrspace(1), ptr addrspace(2), i32,"
   " <2 x float>, float, i1, <2 x i32>, i1, float, float, i32)\n"
   "declare { <4 x float>, i8 } @air.gather_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2),"
   " <2 x float>, i1, <2 x i32>, i32, i32)\n"
   "declare { <4 x i32>, i8 } @air.read_texture_2d_array.u.v4i32(ptr addrspace(1), <2 x i32>, i32,"
   " i32, i32)\n"
   "declare { <4 x float>, i8 } @air.read_texture_2d.v4f32(ptr addrspace(1), <2 x i32>, i32, i32)\n"
   "declare void @air.write_texture_2d.v4f32(ptr addrspace(1), <2 x i32>, <4 x float>, i32, i32)\n"
   "declare i32 @air.get_width_texture_2d(ptr addrspace(1), i32)\n"
   "declare i32 @air.get_array_size_texture_2d_array(ptr addrspace(1))\n"
   "declare i32 @air.get_num_mip_levels_texture_2d_array(ptr addrspace(1))\n";

/* A kernel that samples src at a level with an offset, writes the texel to
 * dst, reads a uint array texture and stores its size queries. */
static const char *kernel_body =
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
   "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> <i32 1, i32 -1>,"
   " i1 true, float 2.0, float 0.0, i32 0)\n"
   "%t = extractvalue { <4 x float>, i8 } %s, 0\n"
   "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %dst, <2 x i32> <i32 3, i32 4>,"
   " <4 x float> %t, i32 0, i32 2)\n"
   "%r = call { <4 x i32>, i8 } @air.read_texture_2d_array.u.v4i32(ptr addrspace(1) %layers,"
   " <2 x i32> <i32 5, i32 6>, i32 2, i32 0, i32 3)\n"
   "%texel = extractvalue { <4 x i32>, i8 } %r, 0\n"
   "%w = call i32 @air.get_width_texture_2d(ptr addrspace(1) %src, i32 1)\n"
   "%n = call i32 @air.get_array_size_texture_2d_array(ptr addrspace(1) %layers)\n"
   "%sum = add i32 %w, %n\n"
   "store i32 %sum, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

/* kernel_body storing whether its sample or read missed a resident texel. */
static const char *sparse_body =
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
   "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> <i32 1, i32 -1>,"
   " i1 true, float 2.0, float 0.0, i32 0)\n"
   "%sampled = extractvalue { <4 x float>, i8 } %s, 1\n"
   "%r = call { <4 x i32>, i8 } @air.read_texture_2d_array.u.v4i32(ptr addrspace(1) %layers,"
   " <2 x i32> <i32 5, i32 6>, i32 2, i32 0, i32 3)\n"
   "%read = extractvalue { <4 x i32>, i8 } %r, 1\n"
   "%missed = or i8 %sampled, %read\n"
   "%bit = and i8 %missed, 1\n"
   "%wide = zext i8 %bit to i32\n"
   "store i32 %wide, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

static const char *kernel_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7, !8, !9, !10}\n"
   "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!6 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 2, i32 1, !\"air.sample\","
   " !\"air.arg_type_name\", !\"texture2d<float, sample>\", !\"air.arg_name\", !\"src\"}\n"
   "!7 = !{i32 2, !\"air.sampler\", !\"air.location_index\", i32 1, i32 1,"
   " !\"air.arg_type_name\", !\"sampler\", !\"air.arg_name\", !\"smp\"}\n"
   "!8 = !{i32 3, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.write\","
   " !\"air.arg_type_name\", !\"texture2d<float, write>\", !\"air.arg_name\", !\"dst\"}\n"
   "!9 = !{i32 4, !\"air.texture\", !\"air.location_index\", i32 7, i32 1, !\"air.read_write\","
   " !\"air.arg_type_name\", !\"texture2d_array<uint, read_write>\", !\"air.arg_name\", !\"layers\"}\n"
   "!10 = !{i32 5, !\"air.buffer\", !\"air.location_index\", i32 3, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* Texture and sampler array arguments as Apple's compiler passes them: by
 * value, each element loaded through a GEP of the handles, some wrapped in
 * Metal's texture2d and sampler structures. The kernel samples inputs[which]
 * with samplers[which & 1], adds inputs[2].read(gid) and writes the sum to
 * outputs[which & 1]. */
static const char *array_body =
   "define void @kernel(ptr byval([4 x ptr addrspace(1)]) %inputs,"
   " ptr byval([2 x ptr addrspace(1)]) %outputs, ptr byval([2 x ptr addrspace(2)]) %samplers,"
   " ptr addrspace(2) %which, <2 x i32> %gid) {\n"
   "%w = load i32, ptr addrspace(2) %which, align 4\n"
   "%i = zext i32 %w to i64\n"
   "%odd = and i32 %w, 1\n"
   "%j = zext i32 %odd to i64\n"
   "%sp = getelementptr inbounds [2 x { ptr addrspace(2) }], ptr %samplers, i64 0, i64 %j, i32 0\n"
   "%s = load ptr addrspace(2), ptr %sp, align 8\n"
   "%ip = getelementptr inbounds [4 x { ptr addrspace(1) }], ptr %inputs, i64 0, i64 %i, i32 0\n"
   "%in = load ptr addrspace(1), ptr %ip, align 8\n"
   "%sampled = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %in,"
   " ptr addrspace(2) %s, <2 x float> <float 0.5, float 0.5>, i1 true, <2 x i32> zeroinitializer,"
   " i1 false, float 0.0, float 0.0, i32 0)\n"
   "%texel = extractvalue { <4 x float>, i8 } %sampled, 0\n"
   "%cp = getelementptr inbounds [4 x ptr addrspace(1)], ptr %inputs, i64 0, i64 2\n"
   "%c = load ptr addrspace(1), ptr %cp, align 8\n"
   "%r = call { <4 x float>, i8 } @air.read_texture_2d.v4f32(ptr addrspace(1) %c, <2 x i32> %gid,"
   " i32 0, i32 0)\n"
   "%read = extractvalue { <4 x float>, i8 } %r, 0\n"
   "%sum = fadd <4 x float> %texel, %read\n"
   "%op = getelementptr inbounds [2 x { ptr addrspace(1) }], ptr %outputs, i64 0, i64 %j, i32 0\n"
   "%out = load ptr addrspace(1), ptr %op, align 8\n"
   "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %out, <2 x i32> %gid, <4 x float> %sum,"
   " i32 0, i32 2)\n"
   "ret void\n}\n";

static const char *array_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7, !8, !9}\n"
   "!5 = !{i32 0, !\"air.texture\", !\"air.location_index\", i32 0, i32 4, !\"air.sample\","
   " !\"air.arg_type_name\", !\"array<texture2d<float, sample>, 4>\", !\"air.arg_name\", !\"inputs\"}\n"
   "!6 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 4, i32 2, !\"air.write\","
   " !\"air.arg_type_name\", !\"array<texture2d<float, write>, 2>\", !\"air.arg_name\", !\"outputs\"}\n"
   "!7 = !{i32 2, !\"air.sampler\", !\"air.location_index\", i32 0, i32 2,"
   " !\"air.arg_type_name\", !\"array<sampler, 2>\", !\"air.arg_name\", !\"samplers\"}\n"
   "!8 = !{i32 3, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read\","
   " !\"air.address_space\", i32 2, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"which\"}\n"
   "!9 = !{i32 4, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint2\","
   " !\"air.arg_name\", !\"gid\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* A fragment function that samples with implicit derivatives, compares
 * against a depth texture and gathers. */
static const char *fragment_body =
   "define <4 x float> @fragment(<4 x float> %position, ptr addrspace(1) %color,"
   " ptr addrspace(2) %smp, ptr addrspace(1) %depth) {\n"
   "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %color,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.5>, i1 true, <2 x i32> zeroinitializer,"
   " i1 false, float 0.0, float 0.0, i32 0)\n"
   "%c = extractvalue { <4 x float>, i8 } %s, 0\n"
   "%d = call { float, i8 } @air.sample_compare_depth_2d.f32(ptr addrspace(1) %depth,"
   " ptr addrspace(2) %smp, i32 1, <2 x float> <float 0.5, float 0.5>, float 0.75, i1 true,"
   " <2 x i32> zeroinitializer, i1 false, float 0.0, float 0.0, i32 0)\n"
   "%g = call { <4 x float>, i8 } @air.gather_texture_2d.v4f32(ptr addrspace(1) %color,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.5>, i1 true, <2 x i32> zeroinitializer,"
   " i32 2, i32 0)\n"
   "%gc = extractvalue { <4 x float>, i8 } %g, 0\n"
   "%v = fadd <4 x float> %c, %gc\n"
   "ret <4 x float> %v\n}\n";

static const char *fragment_metadata =
   "!air.fragment = !{!10}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!10 = !{ptr @fragment, !11, !13}\n!11 = !{!12}\n"
   "!12 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\"}\n"
   "!13 = !{!14, !15, !16, !17}\n"
   "!14 = !{i32 0, !\"air.position\", !\"air.center\", !\"air.no_perspective\","
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\", !\"air.arg_unused\"}\n"
   "!15 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.sample\","
   " !\"air.arg_type_name\", !\"texture2d<float, sample>\", !\"air.arg_name\", !\"color\"}\n"
   "!16 = !{i32 2, !\"air.sampler\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"sampler\", !\"air.arg_name\", !\"smp\"}\n"
   "!17 = !{i32 3, !\"air.texture\", !\"air.location_index\", i32 1, i32 1, !\"air.sample\","
   " !\"air.arg_type_name\", !\"depth2d<float, sample>\", !\"air.arg_name\", !\"depth\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

static LLVMMemoryBufferRef
bitcode(const char *body, const char *metadata)
{
   return stela_air_test_custom_bitcode(module, body, metadata, "");
}

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};
static struct stela_metal_stage fragment = {.table = STELA_METAL_TABLE_FRAGMENT};

static struct stela_air_options
options(struct stela_metal_stage *stage, bool compute)
{
   return (struct stela_air_options){
      .workgroup_size = {compute ? 64u : 0u, compute ? 1u : 0u, compute ? 1u : 0u},
      .max_instructions = 10000, .bind_buffer = stela_metal_bind_buffer, .binding_data = stage,
      .bind_texture = stela_metal_bind_texture, .bind_sampler = stela_metal_bind_sampler,
      .bind_texture_id = stela_metal_bind_texture_id, .bind_sampler_id = stela_metal_bind_sampler_id,
      .resource_id = stela_metal_resource_id, .texture_levels = stela_metal_texture_levels,
      .texture_null = stela_metal_texture_null,
      .max_private_bytes = 64,
   };
}

static nir_shader *
kernel_with(const char *body, const char *metadata, const struct stela_air_options *o,
            struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(body, metadata);
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", &nir_options, o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static nir_shader *
kernel(const char *body, const char *metadata, struct stela_air_error *error)
{
   const struct stela_air_options o = options(&primary, true);
   return kernel_with(body, metadata, &o, error);
}

struct census {
   unsigned tex[64];
   nir_tex_instr *first[64];
   nir_intrinsic_instr *store, *load;
};

static struct census
count(nir_shader *shader)
{
   struct census census = {0};
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_tex) {
               nir_tex_instr *tex = nir_instr_as_tex(instr);
               assert(tex->op < ARRAY_SIZE(census.tex));
               if (!census.tex[tex->op]++)
                  census.first[tex->op] = tex;
            } else if (instr->type == nir_instr_type_intrinsic) {
               nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
               if (intrinsic->intrinsic == nir_intrinsic_image_deref_store)
                  census.store = intrinsic;
               if (intrinsic->intrinsic == nir_intrinsic_image_deref_load)
                  census.load = intrinsic;
            }
         }
      }
   }
   return census;
}

static nir_variable *
source_variable(nir_tex_instr *tex, nir_tex_src_type type)
{
   int index = nir_tex_instr_src_index(tex, type);
   assert(index >= 0);
   return nir_deref_instr_get_variable(nir_def_as_deref(tex->src[index].src.ssa));
}

static void
kernels_sample_write_read_and_query(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(kernel_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "kernel: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "texture kernel");
   struct census census = count(shader);

   /* No implicit derivatives in a kernel: the level is explicit. */
   assert(census.tex[nir_texop_txl] == 1 && !census.tex[nir_texop_tex]);
   nir_tex_instr *sample = census.first[nir_texop_txl];
   assert(sample->sampler_dim == GLSL_SAMPLER_DIM_2D && !sample->is_array);
   assert(sample->dest_type == nir_type_float32 && sample->coord_components == 2);
   /* Nothing reads its residency. */
   assert(!sample->is_sparse && sample->def.num_components == 4);
   assert(nir_tex_instr_src_index(sample, nir_tex_src_offset) >= 0);
   assert(nir_tex_instr_src_index(sample, nir_tex_src_lod) >= 0);
   nir_variable *images = source_variable(sample, nir_tex_src_texture_deref);
   assert(images->data.binding == STELA_METAL_HEAP_SAMPLED_IMAGES);
   assert(source_variable(sample, nir_tex_src_sampler_deref)->data.binding ==
          STELA_METAL_HEAP_SAMPLERS);

   assert(census.store && census.load);
   assert(nir_intrinsic_image_dim(census.store) == GLSL_SAMPLER_DIM_2D);
   assert(nir_intrinsic_src_type(census.store) == nir_type_float32);
   assert(nir_deref_instr_get_variable(nir_src_as_deref(census.store->src[0]))->data.binding ==
          STELA_METAL_HEAP_STORAGE_IMAGES);
   /* The array texture's layer is the coordinate's third component. */
   assert(nir_intrinsic_image_array(census.load) && nir_intrinsic_dest_type(census.load) == nir_type_uint32);
   nir_scalar layer = nir_scalar_chase_movs(nir_get_scalar(census.load->src[1].ssa, 2));
   assert(nir_scalar_is_const(layer) && nir_scalar_as_uint(layer) == 2);

   /* get_width of a sampled texture is txs at the level; get_array_size of
    * a storage texture is its image size. */
   assert(census.tex[nir_texop_txs] == 1);
   assert(nir_tex_instr_src_index(census.first[nir_texop_txs], nir_tex_src_lod) >= 0);
   ralloc_free(shader);
}

static void
fragments_sample_with_derivatives_compare_and_gather(void)
{
   LLVMMemoryBufferRef input = bitcode(fragment_body, fragment_metadata);
   struct stela_air_stage_options o = {
      .stage = STELA_AIR_FRAGMENT, .resources = options(&fragment, false), .max_varying_slots = 16,
   };
   o.resources.fp_profile = STELA_AIR_FP_METAL;
   struct stela_air_error error = {0};
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               "fragment", &nir_options, &o, &error);
   if (!shader)
      fprintf(stderr, "fragment: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "texture fragment");
   struct census census = count(shader);
   /* Implicit derivatives, and the shadow compare with its reference. */
   assert(census.tex[nir_texop_tex] == 2 && census.tex[nir_texop_tg4] == 1);
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_tex)
               continue;
            nir_tex_instr *tex = nir_instr_as_tex(instr);
            bool shadow = nir_tex_instr_src_index(tex, nir_tex_src_comparator) >= 0;
            assert(shadow == tex->is_shadow);
            if (shadow)
               assert(tex->def.num_components == 1);
            if (tex->op == nir_texop_tg4)
               assert(tex->component == 2 && tex->def.num_components == 4);
            assert(nir_tex_instr_src_index(tex, nir_tex_src_lod) < 0);
            assert(nir_tex_instr_src_index(tex, nir_tex_src_bias) < 0);
         }
      }
   }
   ralloc_free(shader);
   LLVMDisposeMemoryBuffer(input);
}

/* Replaces the first occurrence of from in text; the result is static. */
static const char *
replace(const char *text, const char *from, const char *to)
{
   static char buffer[8192];
   const char *at = strstr(text, from);
   assert(at && strlen(text) - strlen(from) + strlen(to) < sizeof(buffer));
   snprintf(buffer, sizeof(buffer), "%.*s%s%s", (int)(at - text), text, to, at + strlen(from));
   return buffer;
}

static void
refuse(const char *body, const char *metadata, enum stela_air_error_kind kind, const char *detail)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(body, metadata, &error);
   if (shader || error.kind != kind || !strstr(error.detail, detail))
      fprintf(stderr, "expected %u \"%s\", got %u \"%s\"\n", kind, detail, error.kind, error.detail);
   assert(!shader && error.kind == kind && strstr(error.detail, detail));
}

/* The resource ID a sampled texture call's source indexes the heap with. */
static nir_alu_instr *
sampled_id(nir_tex_instr *tex, nir_tex_src_type type)
{
   int source = nir_tex_instr_src_index(tex, type);
   assert(source >= 0);
   nir_deref_instr *deref = nir_def_as_deref(tex->src[source].src.ssa);
   nir_alu_instr *half = nir_def_as_alu(deref->arr.index.ssa);
   assert(half->op == nir_op_unpack_64_2x32_split_x);
   return nir_def_as_alu(half->src[0].src.ssa);
}

/* Each element a texture or sampler array access names is the resource its
 * slot's ID identifies. */
static void
array_arguments_bind_their_elements(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(array_body, array_metadata, &error);
   if (!shader)
      fprintf(stderr, "arrays: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "texture array kernel");
   struct census census = count(shader);
   nir_tex_instr *sample = census.first[nir_texop_txl];
   assert(sample && census.tex[nir_texop_txf] == 1 && census.store);
   /* Elements past an array select the null descriptors. */
   assert(sampled_id(sample, nir_tex_src_texture_deref)->op == nir_op_bcsel);
   assert(sampled_id(sample, nir_tex_src_sampler_deref)->op == nir_op_bcsel);
   assert(sampled_id(census.first[nir_texop_txf], nir_tex_src_texture_deref)->op == nir_op_bcsel);
   ralloc_free(shader);

   /* A target without resource IDs refuses them. */
   struct stela_air_options o = options(&primary, true);
   o.resource_id = NULL;
   assert(!kernel_with(array_body, array_metadata, &o, &error) && error.kind == STELA_AIR_ARGUMENT &&
          strstr(error.detail, "array"));
}

/* Reads of a cube and of a cube array texture with read access. */
static const char *cube_body =
   "declare { <4 x float>, i8 } @air.read_texture_cube.v4f32(ptr addrspace(1), <2 x i32>, i32,"
   " i32, i32)\n"
   "declare { <4 x float>, i8 } @air.read_texture_cube_array.v4f32(ptr addrspace(1), <2 x i32>,"
   " i32, i32, i32, i32)\n"
   "define void @kernel(i32 %tid, ptr addrspace(1) %cube, ptr addrspace(1) %cubes,"
   " ptr addrspace(1) %out) {\n"
   "%r = call { <4 x float>, i8 } @air.read_texture_cube.v4f32(ptr addrspace(1) %cube,"
   " <2 x i32> <i32 1, i32 2>, i32 3, i32 0, i32 1)\n"
   "%a = call { <4 x float>, i8 } @air.read_texture_cube_array.v4f32(ptr addrspace(1) %cubes,"
   " <2 x i32> <i32 1, i32 2>, i32 3, i32 2, i32 0, i32 1)\n"
   "%x = extractvalue { <4 x float>, i8 } %r, 0\n"
   "%y = extractvalue { <4 x float>, i8 } %a, 0\n"
   "%s = fadd <4 x float> %x, %y\n"
   "%e = extractelement <4 x float> %s, i32 0\n"
   "store float %e, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

static const char *cube_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7, !8}\n"
   "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!6 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.read\","
   " !\"air.arg_type_name\", !\"texturecube<float, read>\", !\"air.arg_name\", !\"cube\"}\n"
   "!7 = !{i32 2, !\"air.texture\", !\"air.location_index\", i32 1, i32 1, !\"air.read\","
   " !\"air.arg_type_name\", !\"texturecube_array<float, read>\", !\"air.arg_name\", !\"cubes\"}\n"
   "!8 = !{i32 3, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"out\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* Texel fetches take no cube: a cube's texels are its faces' layers. */
static void
cube_reads_fetch_their_faces(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(cube_body, cube_metadata, &error);
   if (!shader)
      fprintf(stderr, "cube reads: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "cube read kernel");
   assert(count(shader).tex[nir_texop_txf] == 2);
   nir_opt_constant_folding(shader);
   unsigned layers[] = {3, 3 + 6 * 2}, n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_tex)
               continue;
            nir_tex_instr *fetch = nir_instr_as_tex(instr);
            assert(fetch->sampler_dim == GLSL_SAMPLER_DIM_2D && fetch->is_array &&
                   fetch->coord_components == 3);
            nir_variable *faces = source_variable(fetch, nir_tex_src_texture_deref);
            assert(faces->data.binding == STELA_METAL_HEAP_SAMPLED_IMAGES &&
                   glsl_get_sampler_dim(glsl_without_array(faces->type)) == GLSL_SAMPLER_DIM_2D);
            nir_scalar layer = nir_scalar_resolved(fetch->src[nir_tex_instr_src_index(
                                                      fetch, nir_tex_src_coord)].src.ssa, 2);
            assert(nir_scalar_is_const(layer) && nir_scalar_as_uint(layer) == layers[n++]);
         }
      }
   }
   ralloc_free(shader);
}

/* kernel_body sampling with a constexpr sampler of Metal's default state,
 * as Apple's compiler emits one. */
static const char *constexpr_global =
   "@__air_sampler_state = internal addrspace(2) constant [2 x i64]"
   " [i64 34901797601017929, i64 0], align 8\n";
static const char *constexpr_metadata =
   "!air.sampler_states = !{!30}\n"
   "!30 = !{!\"air.sampler_state\", ptr addrspace(2) @__air_sampler_state}\n";

static const char *
join(const char *first, const char *second)
{
   static char buffer[2][8192];
   static unsigned next;
   char *joined = buffer[next++ & 1];
   assert(strlen(first) + strlen(second) < sizeof(buffer[0]));
   snprintf(joined, sizeof(buffer[0]), "%s%s", first, second);
   return joined;
}

/* A constexpr sampler is the sampler the options give its state. */
static void
constexpr_samplers_bind_their_samplers(void)
{
   char body[8192];
   snprintf(body, sizeof(body), "%s%s", constexpr_global,
            replace(kernel_body, "ptr addrspace(2) %smp, <2", "ptr addrspace(2) @__air_sampler_state, <2"));
   const char *metadata = join(kernel_metadata, constexpr_metadata);
   const uint64_t state = 34901797601017929ull, id = 0x0000000700000005ull;

   LLVMMemoryBufferRef input = bitcode(body, metadata);
   uint64_t states[AIR_MAX_SAMPLER_STATES];
   unsigned listed;
   struct stela_air_error error = {0};
   assert(stela_air_sampler_states(LLVMGetBufferStart(input), LLVMGetBufferSize(input), states,
                                   &listed, &error) &&
          listed == 1 && states[0] == state);
   LLVMDisposeMemoryBuffer(input);

   struct stela_air_options o = options(&primary, true);
   o.constexpr_samplers = &(struct stela_air_constexpr_sampler){state, id};
   o.constexpr_sampler_count = 1;
   nir_shader *shader = kernel_with(body, metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "constexpr: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "constexpr sampler kernel");
   nir_tex_instr *sample = count(shader).first[nir_texop_txl];
   int source = nir_tex_instr_src_index(sample, nir_tex_src_sampler_deref);
   nir_alu_instr *half = nir_def_as_alu(nir_def_as_deref(sample->src[source].src.ssa)->arr.index.ssa);
   assert(half->op == nir_op_unpack_64_2x32_split_x && nir_src_is_const(half->src[0].src) &&
          nir_src_as_uint(half->src[0].src) == id);
   ralloc_free(shader);

   /* A state the options give no sampler. */
   refuse(body, metadata, STELA_AIR_ARGUMENT, "has no sampler");
   /* A state whose second word is not zero. */
   refuse(replace(body, "i64 0], align 8", "i64 1], align 8"), metadata, STELA_AIR_METADATA,
          "constexpr sampler");
   /* A sampler state listed twice. */
   refuse(body, replace(metadata, "!{!30}", "!{!30, !30}"), STELA_AIR_METADATA,
          "duplicate constexpr sampler");
}

/* A storage texture's level selects its descriptor, which an access whose
 * level varies between threads indexes non-uniformly. */
static void
storage_levels_select_their_descriptor(void)
{
   const char *levels[] = {"i32 1", "i32 %tid"};
   for (unsigned i = 0; i < ARRAY_SIZE(levels); i++) {
      char to[64];
      snprintf(to, sizeof(to), "<4 x float> %%t, %s, i32 2", levels[i]);
      struct stela_air_error error = {0};
      nir_shader *shader = kernel(replace(kernel_body, "<4 x float> %t, i32 0, i32 2", to),
                                  kernel_metadata, &error);
      if (!shader)
         fprintf(stderr, "level %s: %u %s\n", levels[i], error.kind, error.detail);
      assert(shader);
      nir_intrinsic_instr *store = count(shader).store;
      nir_deref_instr *deref = nir_src_as_deref(store->src[0]);
      assert(nir_def_as_alu(deref->arr.index.ssa)->op == nir_op_bcsel);
      assert(!(nir_intrinsic_access(store) & ACCESS_NON_UNIFORM) == !i);
      ralloc_free(shader);
   }

   /* A storage texture's level count is the count its ID carries. */
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(replace(kernel_body, "@air.get_array_size_texture_2d_array",
                                       "@air.get_num_mip_levels_texture_2d_array"),
                               kernel_metadata, &error);
   assert(shader);
   bool counted = false;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            nir_alu_instr *alu = instr->type == nir_instr_type_alu ? nir_instr_as_alu(instr) : NULL;
            counted |= alu && alu->op == nir_op_ushr && nir_src_is_const(alu->src[1].src) &&
                       nir_src_as_uint(alu->src[1].src) == STELA_METAL_LEVEL_SHIFT;
         }
      }
   }
   assert(counted);
   ralloc_free(shader);
}

/* Sparse samples and reads report whether their texels are resident. */
static void
sparse_texels_report_their_residency(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(sparse_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "sparse: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "sparse texture kernel");
   struct census census = count(shader);
   nir_tex_instr *sample = census.first[nir_texop_txl];
   assert(sample && sample->is_sparse && sample->def.num_components == 5);
   unsigned loads = 0, residencies = 0;
   nir_foreach_block(block, nir_shader_get_entrypoint(shader)) {
      nir_foreach_instr(instr, block) {
         if (instr->type != nir_instr_type_intrinsic)
            continue;
         nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
         if (intrinsic->intrinsic == nir_intrinsic_image_deref_sparse_load) {
            assert(intrinsic->def.num_components == 5);
            loads++;
         }
         residencies += intrinsic->intrinsic == nir_intrinsic_is_sparse_texels_resident;
      }
   }
   assert(loads == 1 && !census.load && residencies == 2);
   ralloc_free(shader);
}

static void
unsupported_texture_uses_are_refused(void)
{
   /* Sampling the write-only texture. */
   refuse(replace(kernel_body, "@air.sample_texture_2d.v4f32(ptr addrspace(1) %src",
                  "@air.sample_texture_2d.v4f32(ptr addrspace(1) %dst"),
          kernel_metadata, STELA_AIR_INSTRUCTION, "sample access");
   /* A function whose texture type disagrees with the argument's. */
   refuse(replace(kernel_body, "@air.get_width_texture_2d(ptr addrspace(1) %src",
                  "@air.get_width_texture_2d(ptr addrspace(1) %layers"),
          kernel_metadata, STELA_AIR_INSTRUCTION, "unsupported texture function");
   /* A texture with an array's locations. */
   refuse(kernel_body,
          replace(kernel_metadata, "i32 2, i32 1, !\"air.sample\"", "i32 2, i32 4, !\"air.sample\""),
          STELA_AIR_ARGUMENT, "texture or sampler 1");
   /* An array whose type name disagrees with its locations. */
   refuse(array_body, replace(array_metadata, "array<sampler, 2>", "array<sampler, 3>"),
          STELA_AIR_ARGUMENT, "texture or sampler 2");
   /* Arrays overlapping in their locations. */
   refuse(array_body,
          replace(array_metadata, "i32 4, i32 2, !\"air.write\"", "i32 3, i32 2, !\"air.write\""),
          STELA_AIR_METADATA, "duplicate");
   /* An array's handles read as data. */
   refuse(replace(array_body, "ret void", "%raw = load i64, ptr %cp, align 8\nret void"),
          array_metadata, STELA_AIR_MEMORY, "by element");
   /* A load between an array's handles. */
   refuse(replace(array_body, "i64 0, i64 2\n", "i64 0, i64 2\n%mid = getelementptr i8, ptr %cp, i64 4\n"
                  "%m = load ptr addrspace(1), ptr %mid, align 4\n"),
          array_metadata, STELA_AIR_MEMORY, "names no handle");
   /* An unknown texture type. */
   refuse(kernel_body,
          replace(kernel_metadata, "texture2d<float, sample>", "texture4d<float, sample>"),
          STELA_AIR_ARGUMENT, "texture type");
}

/* Fetch operations on a uint 2D and an int 2D array texture, and a
 * compare-exchange through thread memory. */
static const char *atomic_body =
   "declare <4 x i32> @air.atomic_fetch_add_explicit_texture_2d.u.v4i32(ptr addrspace(1), <2 x i32>,"
   " <4 x i32>, i32, i32)\n"
   "declare <4 x i32> @air.atomic_fetch_sub_explicit_texture_2d.u.v4i32(ptr addrspace(1), <2 x i32>,"
   " <4 x i32>, i32, i32)\n"
   "declare <4 x i32> @air.atomic_fetch_min_explicit_texture_2d_array.s.v4i32(ptr addrspace(1),"
   " <2 x i32>, i32, <4 x i32>, i32, i32)\n"
   "declare i1 @air.atomic_compare_exchange_weak_explicit_texture_2d.u.v4i32(ptr addrspace(1),"
   " <2 x i32>, ptr, <4 x i32>, i32, i32, i32)\n"
   "declare <4 x i32> @air.atomic_load_explicit_texture_2d.u.v4i32(ptr addrspace(1), <2 x i32>,"
   " i32, i32)\n"
   "declare void @air.atomic_store_explicit_texture_2d.u.v4i32(ptr addrspace(1), <4 x i32>,"
   " <2 x i32>, i32, i32)\n"
   "declare i1 @air.is_null_texture_2d(ptr addrspace(1))\n"
   "define void @kernel(ptr addrspace(1) %t, ptr addrspace(1) %a, ptr addrspace(1) %out) {\n"
   "%e = alloca <4 x i32>, align 16\n"
   "%add = call <4 x i32> @air.atomic_fetch_add_explicit_texture_2d.u.v4i32(ptr addrspace(1) %t,"
   " <2 x i32> <i32 1, i32 2>, <4 x i32> <i32 5, i32 0, i32 0, i32 0>, i32 0, i32 3)\n"
   "%sub = call <4 x i32> @air.atomic_fetch_sub_explicit_texture_2d.u.v4i32(ptr addrspace(1) %t,"
   " <2 x i32> <i32 1, i32 2>, <4 x i32> <i32 2, i32 0, i32 0, i32 0>, i32 0, i32 3)\n"
   "%min = call <4 x i32> @air.atomic_fetch_min_explicit_texture_2d_array.s.v4i32(ptr addrspace(1) %a,"
   " <2 x i32> <i32 3, i32 4>, i32 1, <4 x i32> <i32 -7, i32 0, i32 0, i32 0>, i32 0, i32 3)\n"
   "store <4 x i32> <i32 7, i32 0, i32 0, i32 0>, ptr %e, align 16\n"
   "%ok = call i1 @air.atomic_compare_exchange_weak_explicit_texture_2d.u.v4i32(ptr addrspace(1) %t,"
   " <2 x i32> <i32 1, i32 2>, ptr %e, <4 x i32> <i32 9, i32 0, i32 0, i32 0>, i32 0, i32 0, i32 3)\n"
   "%load = call <4 x i32> @air.atomic_load_explicit_texture_2d.u.v4i32(ptr addrspace(1) %t,"
   " <2 x i32> <i32 1, i32 2>, i32 0, i32 3)\n"
   "call void @air.atomic_store_explicit_texture_2d.u.v4i32(ptr addrspace(1) %t,"
   " <4 x i32> <i32 3, i32 0, i32 0, i32 0>, <2 x i32> <i32 1, i32 2>, i32 0, i32 3)\n"
   "%null = call i1 @air.is_null_texture_2d(ptr addrspace(1) %t)\n"
   "%x = extractelement <4 x i32> %add, i32 0\n"
   "%y = extractelement <4 x i32> %min, i32 0\n"
   "%l = extractelement <4 x i32> %load, i32 0\n"
   "%s = add i32 %x, %y\n"
   "%w = zext i1 %ok to i32\n"
   "%n = zext i1 %null to i32\n"
   "%m = add i32 %l, %n\n"
   "%q = add i32 %s, %w\n"
   "%r = add i32 %q, %m\n"
   "store i32 %r, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

static const char *atomic_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7}\n"
   "!5 = !{i32 0, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.arg_type_name\", !\"texture2d<uint, read_write>\", !\"air.arg_name\", !\"t\"}\n"
   "!6 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 1, i32 1, !\"air.read_write\","
   " !\"air.arg_type_name\", !\"texture2d_array<int, read_write>\", !\"air.arg_name\", !\"a\"}\n"
   "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* The image atomics of a shader, in order. */
static unsigned
image_atomics(nir_shader *shader, nir_intrinsic_instr **found, unsigned capacity)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (intrinsic->intrinsic == nir_intrinsic_image_deref_atomic ||
                intrinsic->intrinsic == nir_intrinsic_image_deref_atomic_swap) {
               assert(n < capacity);
               found[n++] = intrinsic;
            }
         }
      }
   }
   return n;
}

static void
kernels_take_texture_atomics(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(atomic_body, atomic_metadata, &error);
   if (!shader)
      fprintf(stderr, "texture atomics: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_intrinsic_instr *atomics[6];
   assert(image_atomics(shader, atomics, ARRAY_SIZE(atomics)) == 6);
   const nir_atomic_op ops[] = {nir_atomic_op_iadd, nir_atomic_op_iadd, nir_atomic_op_imin,
                                nir_atomic_op_cmpxchg, nir_atomic_op_iadd, nir_atomic_op_xchg};
   const enum pipe_format formats[] = {PIPE_FORMAT_R32_UINT, PIPE_FORMAT_R32_UINT,
                                       PIPE_FORMAT_R32_SINT, PIPE_FORMAT_R32_UINT,
                                       PIPE_FORMAT_R32_UINT, PIPE_FORMAT_R32_UINT};
   for (unsigned i = 0; i < ARRAY_SIZE(atomics); i++) {
      assert(nir_intrinsic_atomic_op(atomics[i]) == ops[i]);
      assert(nir_intrinsic_format(atomics[i]) == formats[i]);
   }
   /* Subtraction adds the negated operand. */
   assert(nir_def_as_alu(atomics[1]->src[3].ssa)->op == nir_op_ineg);
   assert(nir_intrinsic_image_dim(atomics[2]) == GLSL_SAMPLER_DIM_2D && nir_intrinsic_image_array(atomics[2]));
   assert(atomics[3]->intrinsic == nir_intrinsic_image_deref_atomic_swap);
   ralloc_free(shader);

   /* Only read-write 32-bit integer textures take atomics, with relaxed order. */
   refuse(atomic_body, replace(atomic_metadata, "i32 0, i32 1, !\"air.read_write\"",
                               "i32 0, i32 1, !\"air.read\""), STELA_AIR_INSTRUCTION, "texture atomics");
   refuse(atomic_body, replace(atomic_metadata, "texture2d<uint, read_write>", "texture2d<float, read_write>"),
          STELA_AIR_INSTRUCTION, "texture atomics");
   refuse(replace(atomic_body, "<4 x i32> <i32 5, i32 0, i32 0, i32 0>, i32 0, i32 3",
                  "<4 x i32> <i32 5, i32 0, i32 0, i32 0>, i32 5, i32 3"),
          atomic_metadata, STELA_AIR_INSTRUCTION, "atomic order");
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   kernels_sample_write_read_and_query();
   fragments_sample_with_derivatives_compare_and_gather();
   storage_levels_select_their_descriptor();
   sparse_texels_report_their_residency();
   array_arguments_bind_their_elements();
   constexpr_samplers_bind_their_samplers();
   cube_reads_fetch_their_faces();
   unsupported_texture_uses_are_refused();
   kernels_take_texture_atomics();
   glsl_type_singleton_decref();
   puts("AIR textures: sample/level/offset, write, read_write array read, size queries, "
        "implicit-derivative fragment sampling, depth compare, gather, storage levels, arrays, atomics, "
        "constexpr samplers, cube reads and refusals passed");
   return 0;
}
