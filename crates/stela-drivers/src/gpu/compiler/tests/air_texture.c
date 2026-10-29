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
   "declare void @air.write_texture_2d.v4f32(ptr addrspace(1), <2 x i32>, <4 x float>, i32, i32)\n"
   "declare i32 @air.get_width_texture_2d(ptr addrspace(1), i32)\n"
   "declare i32 @air.get_array_size_texture_2d_array(ptr addrspace(1))\n";

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
      .max_private_bytes = 64,
   };
}

static nir_shader *
kernel(const char *body, const char *metadata, struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(body, metadata);
   const struct stela_air_options o = options(&primary, true);
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
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
   o.resources.fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
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

static void
unsupported_texture_uses_are_refused(void)
{
   /* Residency feedback of a sparse texture. */
   refuse(replace(kernel_body, "%t = extractvalue { <4 x float>, i8 } %s, 0",
                  "%t = extractvalue { <4 x float>, i8 } %s, 0\n"
                  "%resident = extractvalue { <4 x float>, i8 } %s, 1"),
          kernel_metadata, STELA_AIR_INSTRUCTION, "residency");
   /* Sampling the write-only texture. */
   refuse(replace(kernel_body, "@air.sample_texture_2d.v4f32(ptr addrspace(1) %src",
                  "@air.sample_texture_2d.v4f32(ptr addrspace(1) %dst"),
          kernel_metadata, STELA_AIR_INSTRUCTION, "sample access");
   /* A function whose texture type disagrees with the argument's. */
   refuse(replace(kernel_body, "@air.get_width_texture_2d(ptr addrspace(1) %src",
                  "@air.get_width_texture_2d(ptr addrspace(1) %layers"),
          kernel_metadata, STELA_AIR_INSTRUCTION, "unsupported texture function");
   /* Writing a storage texture level other than 0. */
   refuse(replace(kernel_body, "<4 x float> %t, i32 0, i32 2", "<4 x float> %t, i32 1, i32 2"),
          kernel_metadata, STELA_AIR_INSTRUCTION, "level other than");
   /* Texture arrays. */
   refuse(kernel_body,
          replace(kernel_metadata, "i32 2, i32 1, !\"air.sample\"", "i32 2, i32 4, !\"air.sample\""),
          STELA_AIR_ARGUMENT, "arrays");
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
   "%x = extractelement <4 x i32> %add, i32 0\n"
   "%y = extractelement <4 x i32> %min, i32 0\n"
   "%s = add i32 %x, %y\n"
   "%w = zext i1 %ok to i32\n"
   "%r = add i32 %s, %w\n"
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
   nir_intrinsic_instr *atomics[4];
   assert(image_atomics(shader, atomics, ARRAY_SIZE(atomics)) == 4);
   const nir_atomic_op ops[] = {nir_atomic_op_iadd, nir_atomic_op_iadd, nir_atomic_op_imin,
                                nir_atomic_op_cmpxchg};
   const enum pipe_format formats[] = {PIPE_FORMAT_R32_UINT, PIPE_FORMAT_R32_UINT,
                                       PIPE_FORMAT_R32_SINT, PIPE_FORMAT_R32_UINT};
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
   (void)stela_air_test_store_body;
   glsl_type_singleton_init_or_ref();
   kernels_sample_write_read_and_query();
   fragments_sample_with_derivatives_compare_and_gather();
   unsupported_texture_uses_are_refused();
   kernels_take_texture_atomics();
   glsl_type_singleton_decref();
   puts("AIR textures: sample/level/offset, write, read_write array read, size queries, "
        "implicit-derivative fragment sampling, depth compare, gather, atomics and refusals passed");
   return 0;
}
