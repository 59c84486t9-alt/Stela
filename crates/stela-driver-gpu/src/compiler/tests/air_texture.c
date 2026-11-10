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
   "declare { float, i8 } @air.sample_compare_depth_2d_grad.f32(ptr addrspace(1), ptr addrspace(2),"
   " i32, <2 x float>, float, <2 x float>, <2 x float>, float, i1, <2 x i32>, i32)\n"
   "declare { float, i8 } @air.sample_compare_depth_2d.f32(ptr addrspace(1), ptr addrspace(2), i32,"
   " <2 x float>, float, i1, <2 x i32>, i1, float, float, i32)\n"
   "declare { <4 x float>, i8 } @air.gather_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2),"
   " <2 x float>, i1, <2 x i32>, i32, i32)\n"
   "declare { <4 x float>, i8 } @air.gather_compare_depth_2d.f32(ptr addrspace(1), ptr addrspace(2),"
   " i32, <2 x float>, float, i1, <2 x i32>, i32)\n"
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

/* kernel_body sampling and sizing the null texture a constant chose. */
static const char *null_body =
   "declare ptr addrspace(1) @air.get_null_texture_2d()\n"
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
   "%none = call ptr addrspace(1) @air.get_null_texture_2d()\n"
   "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %none,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> <i32 1, i32 -1>,"
   " i1 true, float 2.0, float 0.0, i32 0)\n"
   "%t = extractvalue { <4 x float>, i8 } %s, 0\n"
   "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %dst, <2 x i32> <i32 3, i32 4>,"
   " <4 x float> %t, i32 0, i32 2)\n"
   "%w = call i32 @air.get_width_texture_2d(ptr addrspace(1) %none, i32 1)\n"
   "store i32 %w, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

/* kernel_body joining two samples, of which it reads only the texels. */
static const char *joined_body =
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
   "%first = icmp eq i32 %tid, 0\n"
   "br i1 %first, label %a, label %b\n"
   "a:\n"
   "%x = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> <i32 1, i32 -1>,"
   " i1 true, float 2.0, float 0.0, i32 0)\n"
   "br label %join\n"
   "b:\n"
   "%y = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.25, float 0.5>, i1 true, <2 x i32> <i32 1, i32 -1>,"
   " i1 true, float 2.0, float 0.0, i32 0)\n"
   "br label %join\n"
   "join:\n"
   "%s = phi { <4 x float>, i8 } [ %x, %a ], [ %y, %b ]\n"
   "%t = extractvalue { <4 x float>, i8 } %s, 0\n"
   "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %dst, <2 x i32> <i32 3, i32 4>,"
   " <4 x float> %t, i32 0, i32 2)\n"
   "store i32 0, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

/* kernel_body reading and writing with 16 bit positions and levels. */
static const char *short_body =
   "declare { <4 x float>, i8 } @air.read_texture_2d.i16.v4f32(ptr addrspace(1), <2 x i16>, i16,"
   " i32)\n"
   "declare void @air.write_texture_2d.i16.v4f32(ptr addrspace(1), <2 x i16>, <4 x float>, i16,"
   " i32)\n"
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
   "%r = call { <4 x float>, i8 } @air.read_texture_2d.i16.v4f32(ptr addrspace(1) %src,"
   " <2 x i16> <i16 5, i16 6>, i16 0, i32 0)\n"
   "%t = extractvalue { <4 x float>, i8 } %r, 0\n"
   "call void @air.write_texture_2d.i16.v4f32(ptr addrspace(1) %dst, <2 x i16> <i16 3, i16 4>,"
   " <4 x float> %t, i16 0, i32 2)\n"
   "store i32 0, ptr addrspace(1) %out, align 4\n"
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
   "%grad = call { float, i8 } @air.sample_compare_depth_2d_grad.f32(ptr addrspace(1) %depth,"
   " ptr addrspace(2) %smp, i32 1, <2 x float> <float 0.5, float 0.5>, float 0.75,"
   " <2 x float> <float 1.0, float 0.0>, <2 x float> <float 0.0, float 1.0>, float 0.0, i1 true,"
   " <2 x i32> zeroinitializer, i32 0)\n"
   "%g = call { <4 x float>, i8 } @air.gather_texture_2d.v4f32(ptr addrspace(1) %color,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.5>, i1 true, <2 x i32> zeroinitializer,"
   " i32 2, i32 0)\n"
   "%gc = extractvalue { <4 x float>, i8 } %g, 0\n"
   "%dg = call { <4 x float>, i8 } @air.gather_compare_depth_2d.f32(ptr addrspace(1) %depth,"
   " ptr addrspace(2) %smp, i32 1, <2 x float> <float 0.5, float 0.5>, float 0.75, i1 true,"
   " <2 x i32> zeroinitializer, i32 0)\n"
   "%dgc = extractvalue { <4 x float>, i8 } %dg, 0\n"
   "%gs = fadd <4 x float> %gc, %dgc\n"
   "%v = fadd <4 x float> %c, %gs\n"
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

/* Every sampler compares with Never. */
static nir_def *
always_never(nir_builder *b, const struct stela_air_sampler *sampler, nir_def *id, void *data)
{
   return nir_imm_true(b);
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
   assert(census.tex[nir_texop_tex] == 2 && census.tex[nir_texop_tg4] == 2);
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_tex)
               continue;
            nir_tex_instr *tex = nir_instr_as_tex(instr);
            bool shadow = nir_tex_instr_src_index(tex, nir_tex_src_comparator) >= 0;
            assert(shadow == tex->is_shadow);
            /* A comparison is one value; a compare gather is four. */
            if (shadow)
               assert(tex->def.num_components == (tex->op == nir_texop_tg4 ? 4 : 1));
            if (tex->op == nir_texop_tg4)
               assert((shadow || tex->component == 2) && tex->def.num_components == 4);
            assert(nir_tex_instr_src_index(tex, nir_tex_src_lod) < 0);
            assert(nir_tex_instr_src_index(tex, nir_tex_src_bias) < 0);
         }
      }
   }
   ralloc_free(shader);

   /* A Never sampler fails each compared channel: the two comparisons'
    * one and the compare gather's four. */
   o.resources.sampler_never = always_never;
   shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input), "fragment",
                                   &nir_options, &o, &error);
   assert(shader);
   unsigned failed = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_alu || nir_instr_as_alu(instr)->op != nir_op_bcsel)
               continue;
            nir_alu_instr *select = nir_instr_as_alu(instr);
            failed += nir_src_is_const(select->src[0].src) && nir_src_as_bool(select->src[0].src) &&
                      nir_src_is_const(select->src[1].src) && nir_src_as_float(select->src[1].src) == 0.0;
         }
      }
   }
   assert(failed == 6);
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

   /* Before Metal 3.2 the state is one word with its top bit set. */
   char older[8192];
   snprintf(older, sizeof(older), "%s%s",
            "@__air_sampler_state = internal addrspace(2) constant i64 -9188470239253757879, align 8\n",
            replace(kernel_body, "ptr addrspace(2) %smp, <2", "ptr addrspace(2) @__air_sampler_state, <2"));
   shader = kernel_with(older, metadata, &o, &error);
   assert(shader);
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

/* A block of 1 by 2 texels into thread memory, the last stored. */
static const char *block_body =
   "declare void @air.block_read_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2), <2 x i32>,"
   " <2 x i32>, i32, i32, ptr, ptr, <2 x i32>)\n"
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
   "%block = alloca [2 x <4 x float>], align 16\n"
   "call void @air.block_read_texture_2d.v4f32(ptr addrspace(1) %src, ptr addrspace(2) %smp,"
   " <2 x i32> <i32 1, i32 2>, <2 x i32> <i32 0, i32 1>, i32 1, i32 0, ptr %block, ptr null,"
   " <2 x i32> <i32 1, i32 2>)\n"
   "%last = getelementptr [2 x <4 x float>], ptr %block, i64 0, i64 1\n"
   "%v = load <4 x float>, ptr %last, align 16\n"
   "%x = extractelement <4 x float> %v, i64 0\n%i = fptoui float %x to i32\n"
   "store i32 %i, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n";

/* Each texel of a block is a fetch at its place in the block. */
static void
block_reads_fetch_each_texel(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(block_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "block: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "block read kernel");
   struct census census = count(shader);
   assert(census.tex[nir_texop_txf] == 2);
   /* Each fetch is of level 1. */
   nir_tex_instr *first = census.first[nir_texop_txf];
   assert(nir_tex_instr_src_index(first, nir_tex_src_lod) >= 0);
   ralloc_free(shader);
   /* A residency destination receives each texel's residency from a sparse
    * fetch. */
   char *destined = strdup(replace(block_body, "ptr %block, ptr null", "ptr %block, ptr %residency"));
   const char *resident = replace(
      destined, "%block = alloca [2 x <4 x float>], align 16\n",
      "%block = alloca [2 x <4 x float>], align 16\n%residency = alloca [2 x i8], align 1\n");
   free(destined);
   shader = kernel(resident, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "resident block: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "resident block read kernel");
   unsigned sparse = 0, residencies = 0;
   nir_foreach_block(block, nir_shader_get_entrypoint(shader)) {
      nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_tex)
            sparse += nir_instr_as_tex(instr)->is_sparse;
         residencies += instr->type == nir_instr_type_intrinsic &&
                        nir_instr_as_intrinsic(instr)->intrinsic ==
                           nir_intrinsic_is_sparse_texels_resident;
      }
   }
   assert(sparse == 2 && residencies == 2);
   ralloc_free(shader);
}

/* A kernel's explicit imageblock of 8-byte elements, its texture and its
 * threads' positions in their threadgroup. */
static const char *imageblock_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7}\n"
   "!5 = !{i32 0, !\"air.imageblock\", !\"explicit\", !\"air.imageblock_data_size\", i32 8,"
   " !\"air.arg_type_align_size\", i32 8, !\"air.arg_type_name\","
   " !\"imageblock<Pixel, layout_explicit>\", !\"air.arg_name\", !\"block\"}\n"
   "!6 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.write\","
   " !\"air.arg_type_name\", !\"texture2d<half, write>\", !\"air.arg_name\", !\"out\"}\n"
   "!7 = !{i32 2, !\"air.thread_position_in_threadgroup\", !\"air.arg_type_name\", !\"ushort2\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* As Core Animation's downsample kernels do: each thread stores its pixel,
 * and after a barrier one writes a region of the block's half4 member. */
static const char *imageblock_body =
   "%block_t = type { ptr addrspace(4) }\n"
   "declare ptr addrspace(4) @air.imageblock_data(<2 x i16>, i32, i16)\n"
   "declare i16 @air.get_imageblock_width()\n"
   "declare void @air.wg.barrier(i32, i32, i32) convergent\n"
   "declare void @air.write_imageblock_slice_to_texture_2d.i16.v4f16(ptr addrspace(1),"
   " ptr addrspace(4), i1, <2 x i16>, <2 x i16>, <2 x i16>, i16, i1, i32)\n"
   "define void @kernel(%block_t %block, ptr addrspace(1) %out, <2 x i16> %tid) {\n"
   "%p = call ptr addrspace(4) @air.imageblock_data(<2 x i16> %tid, i32 0, i16 0)\n"
   "%w = call i16 @air.get_imageblock_width()\n"
   "%x = extractelement <2 x i16> %tid, i64 0\n"
   "%sum = add i16 %x, %w\n"
   "%h = uitofp i16 %sum to half\n"
   "%v = insertelement <4 x half> zeroinitializer, half %h, i64 0\n"
   "store <4 x half> %v, ptr addrspace(4) %p, align 8\n"
   "call void @air.wg.barrier(i32 8, i32 5, i32 1) convergent\n"
   "%first = call ptr addrspace(4) @air.imageblock_data(<2 x i16> zeroinitializer, i32 0, i16 0)\n"
   "call void @air.write_imageblock_slice_to_texture_2d.i16.v4f16(ptr addrspace(1) %out,"
   " ptr addrspace(4) %first, i1 true, <2 x i16> zeroinitializer, <2 x i16> <i16 3, i16 2>,"
   " <2 x i16> <i16 1, i16 1>, i16 0, i1 false, i32 2)\n"
   "ret void\n}\n";

/* The imageblock is threadgroup memory of the encoder's dimensions'
 * elements, and the slice write a loop of image stores. Without dimensions
 * it is 0 x 0, as on Apple GPUs, over an element for each thread of a
 * threadgroup's first row. */
static void
imageblocks_live_in_threadgroup_memory(void)
{
   struct stela_air_error error = {0};
   struct stela_air_options o = options(&primary, true);
   o.workgroup_size[0] = 4, o.workgroup_size[1] = 4;
   o.max_threadgroup_bytes = 32768;
   o.imageblock_size[0] = 8, o.imageblock_size[1] = 2;
   nir_shader *shader = kernel_with(imageblock_body, imageblock_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "imageblock: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "imageblock kernel");
   assert(shader->info.shared_size == 8 * 2 * 8);
   assert(count(shader).store);
   bool looped = false;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         for (nir_cf_node *node = block->cf_node.parent; node; node = node->parent)
            looped |= node->type == nir_cf_node_loop;
      }
   }
   assert(looped);
   ralloc_free(shader);
   /* Only the block's origin starts a slice. */
   const char *offset = replace(imageblock_body, "i1 true, <2 x i16> zeroinitializer",
                                "i1 true, <2 x i16> <i16 1, i16 0>");
   assert(!kernel_with(offset, imageblock_metadata, &o, &error));
   /* Unsized, in a kernel of a fixed and of a dynamic threadgroup shape. */
   o.imageblock_size[0] = 0, o.imageblock_size[1] = 0;
   shader = kernel_with(imageblock_body, imageblock_metadata, &o, &error);
   assert(shader);
   nir_validate_shader(shader, "unsized imageblock");
   assert(shader->info.shared_size == 4 * 8);
   ralloc_free(shader);
   o.dynamic_shape = true;
   o.load_device_value = stela_metal_load_device_value;
   o.workgroup_size[0] = 64, o.workgroup_size[1] = 1;
   shader = kernel_with(imageblock_body, imageblock_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "dynamic imageblock: %u %s\n", error.kind, error.detail);
   assert(shader);
   assert(shader->info.shared_size == 64 * 8);
   ralloc_free(shader);
}

/* A tile function's implicit imageblock, its threadgroup buffer and its
 * threads' positions in their tile. */
static const char *tile_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7}\n"
   "!5 = !{i32 0, !\"air.imageblock\", !\"implicit\", !\"air.arg_type_align_size\", i32 8,"
   " !\"air.arg_type_name\", !\"imageblock<Color, layout_implicit>\", !\"air.arg_name\", !\"block\"}\n"
   "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"shared\"}\n"
   "!7 = !{i32 2, !\"air.thread_position_in_threadgroup\", !\"air.arg_type_name\", !\"ushort2\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* Each thread reads its pixel's color, writes it back with the tile's
 * width in green, and counts into the tile's threadgroup memory. */
static const char *tile_body =
   "%block_t = type { ptr addrspace(4) }\n"
   "declare <4 x half> @air.load.implicit_imageblock.v4f16(i32, <2 x i16>, i32, i16)\n"
   "declare void @air.store.implicit_imageblock.v4f16(<4 x half>, i32, <2 x i16>, i32, i16)\n"
   "declare void @air.store.implicit_imageblock.mask.v4f16(<4 x half>, i32, <2 x i16>, i16)\n"
   "declare i16 @air.get_imageblock_width()\n"
   "declare i16 @air.get_imageblock_num_colors(<2 x i16>)\n"
   "define void @kernel(%block_t %block, ptr addrspace(3) %shared, <2 x i16> %tid) {\n"
   "%v = call <4 x half> @air.load.implicit_imageblock.v4f16(i32 0, <2 x i16> %tid, i32 0, i16 0)\n"
   "%w = call i16 @air.get_imageblock_width()\n"
   "%colors = call i16 @air.get_imageblock_num_colors(<2 x i16> %tid)\n"
   "%sum = add i16 %w, %colors\n"
   "%h = uitofp i16 %sum to half\n"
   "%g = insertelement <4 x half> %v, half %h, i64 1\n"
   "call void @air.store.implicit_imageblock.v4f16(<4 x half> %g, i32 0, <2 x i16> %tid, i32 0, i16 0)\n"
   "call void @air.store.implicit_imageblock.mask.v4f16(<4 x half> %v, i32 0, <2 x i16> %tid, i16 1)\n"
   "%old = load i32, ptr addrspace(3) %shared, align 4\n"
   "%new = add i32 %old, 1\n"
   "store i32 %new, ptr addrspace(3) %shared, align 4\n"
   "ret void\n}\n";

static unsigned
intrinsics(nir_shader *shader, nir_intrinsic_op op)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block)
            n += instr->type == nir_instr_type_intrinsic &&
                 nir_instr_as_intrinsic(instr)->intrinsic == op;
      }
   }
   return n;
}

/* A tile function's imageblock is its pass's attachments' texels at its
 * tile's pixels, and its threadgroup memory is copied in from the tile's
 * persistent memory before it runs and out after. */
static void
tile_functions_access_their_attachments(void)
{
   struct stela_air_error error = {0};
   struct stela_air_options o = options(&primary, true);
   struct stela_air_tile tile = {.formats = {PIPE_FORMAT_R16G16B16A16_FLOAT}, .samples = 1};
   o.dynamic_shape = true;
   o.load_device_value = stela_metal_load_device_value;
   o.bind_attachment = stela_metal_bind_attachment;
   o.max_threadgroup_bytes = 32768;
   o.dynamic_threadgroup_bytes = 1024;
   o.threadgroup_offset = stela_metal_threadgroup_offset;
   o.tile = &tile;
   nir_shader *shader = kernel_with(tile_body, tile_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "tile: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "tile function");
   struct census census = count(shader);
   assert(census.load && census.store);
   assert(nir_intrinsic_image_dim(census.store) == GLSL_SAMPLER_DIM_2D);
   /* The persistent memory's copies in and out. */
   assert(intrinsics(shader, nir_intrinsic_load_global) >= 1);
   assert(intrinsics(shader, nir_intrinsic_store_global) >= 1);
   ralloc_free(shader);
   /* A multisampled pass's pixels have a color per sample unless all agree. */
   tile.samples = 4;
   shader = kernel_with(tile_body, tile_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "multisampled tile: %u %s\n", error.kind, error.detail);
   assert(shader);
   assert(nir_intrinsic_image_dim(count(shader).store) == GLSL_SAMPLER_DIM_MS);
   ralloc_free(shader);
   tile.samples = 3;
   assert(!kernel_with(tile_body, tile_metadata, &o, &error));
   tile.samples = 1;
   /* A color without an attachment, a tile function whose dispatches do
    * not shape it, and an implicit imageblock outside one are refused. */
   tile.formats[0] = PIPE_FORMAT_NONE;
   assert(!kernel_with(tile_body, tile_metadata, &o, &error));
   tile.formats[0] = PIPE_FORMAT_R16G16B16A16_FLOAT;
   o.dynamic_shape = false;
   o.dynamic_threadgroup_bytes = 0;
   assert(!kernel_with(tile_body, tile_metadata, &o, &error));
   o.tile = NULL;
   assert(!kernel_with(tile_body, tile_metadata, &o, &error));
   /* An integer color of a float attachment is refused. */
   o.tile = &tile;
   o.dynamic_shape = true;
   o.dynamic_threadgroup_bytes = 1024;
   static const char *integer =
      "%block_t = type { ptr addrspace(4) }\n"
      "declare <4 x i16> @air.load.implicit_imageblock.v4i16(i32, <2 x i16>, i32, i16)\n"
      "define void @kernel(%block_t %block, ptr addrspace(3) %shared, <2 x i16> %tid) {\n"
      "%v = call <4 x i16> @air.load.implicit_imageblock.v4i16(i32 0, <2 x i16> %tid, i32 0, i16 0)\n"
      "%x = extractelement <4 x i16> %v, i64 0\n"
      "%w = zext i16 %x to i32\n"
      "store i32 %w, ptr addrspace(3) %shared, align 4\n"
      "ret void\n}\n";
   assert(!kernel_with(integer, tile_metadata, &o, &error));
}

/* A tile function's explicit imageblock: each color of its pixel doubled,
 * then the first color's coverage. */
static const char *tile_explicit_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7}\n"
   "!5 = !{i32 0, !\"air.imageblock\", !\"explicit\", !\"air.imageblock_data_size\", i32 32,"
   " !\"air.arg_type_align_size\", i32 16, !\"air.arg_type_name\","
   " !\"imageblock<Data, layout_explicit>\", !\"air.arg_name\", !\"block\"}\n"
   "!6 = !{i32 1, !\"air.thread_position_in_threadgroup\", !\"air.arg_type_name\", !\"ushort2\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"out\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

static const char *tile_explicit_body =
   "%block_t = type { ptr addrspace(4) }\n"
   "declare ptr addrspace(4) @air.imageblock_data(<2 x i16>, i32, i16)\n"
   "declare i16 @air.get_imageblock_num_colors(<2 x i16>)\n"
   "declare i16 @air.get_color_coverage_mask(<2 x i16>, i16)\n"
   "define void @kernel(%block_t %block, <2 x i16> %tid, ptr addrspace(1) %out) {\n"
   "%n = call i16 @air.get_imageblock_num_colors(<2 x i16> %tid)\n"
   "%none = icmp eq i16 %n, 0\n"
   "br i1 %none, label %done, label %loop\n"
   "loop:\n"
   "%i = phi i16 [ 0, %0 ], [ %next, %loop ]\n"
   "%p = call ptr addrspace(4) @air.imageblock_data(<2 x i16> %tid, i32 1, i16 %i)\n"
   "%v = load <4 x float>, ptr addrspace(4) %p, align 16\n"
   "%w = fmul <4 x float> %v, <float 2.0, float 2.0, float 2.0, float 2.0>\n"
   "store <4 x float> %w, ptr addrspace(4) %p, align 16\n"
   "%next = add i16 %i, 1\n"
   "%end = icmp eq i16 %next, %n\n"
   "br i1 %end, label %done, label %loop\n"
   "done:\n"
   "%m = call i16 @air.get_color_coverage_mask(<2 x i16> %tid, i16 0)\n"
   "%f = uitofp i16 %m to float\n"
   "%s = insertelement <4 x float> zeroinitializer, float %f, i64 0\n"
   "store <4 x float> %s, ptr addrspace(1) %out, align 16\n"
   "ret void\n}\n";

/* A tile function's explicit imageblock is its pass's imageblock data at
 * its tile's pixels, each sample a color. */
static void
tile_functions_access_imageblock_data(void)
{
   struct stela_air_error error = {0};
   struct stela_air_options o = options(&primary, true);
   struct stela_air_tile tile = {.samples = 4};
   o.dynamic_shape = true;
   o.load_device_value = stela_metal_load_device_value;
   o.bind_attachment = stela_metal_bind_attachment;
   o.tile = &tile;
   nir_shader *shader = kernel_with(tile_explicit_body, tile_explicit_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "tile explicit: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "tile explicit imageblock");
   /* The pass's data and the output, through global memory alone. */
   assert(intrinsics(shader, nir_intrinsic_load_global) >= 2);
   assert(intrinsics(shader, nir_intrinsic_store_global) >= 2);
   assert(!intrinsics(shader, nir_intrinsic_load_shared));
   ralloc_free(shader);
   /* Pointers from separate calls join in a PHI, as optimized loops do. */
   static const char *joined =
      "%block_t = type { ptr addrspace(4) }\n"
      "declare ptr addrspace(4) @air.imageblock_data(<2 x i16>, i32, i16)\n"
      "define void @kernel(%block_t %block, <2 x i16> %tid, ptr addrspace(1) %out) {\n"
      "%x = extractelement <2 x i16> %tid, i64 0\n"
      "%odd = trunc i16 %x to i1\n"
      "br i1 %odd, label %a, label %b\n"
      "a:\n"
      "%pa = call ptr addrspace(4) @air.imageblock_data(<2 x i16> %tid, i32 0, i16 0)\n"
      "br label %j\n"
      "b:\n"
      "%pb = call ptr addrspace(4) @air.imageblock_data(<2 x i16> zeroinitializer, i32 0, i16 0)\n"
      "%pc = getelementptr inbounds i8, ptr addrspace(4) %pb, i64 16\n"
      "br label %j\n"
      "j:\n"
      "%p = phi ptr addrspace(4) [ %pa, %a ], [ %pc, %b ]\n"
      "%v = load <4 x float>, ptr addrspace(4) %p, align 16\n"
      "store <4 x float> %v, ptr addrspace(1) %out, align 16\n"
      "ret void\n}\n";
   shader = kernel_with(joined, tile_explicit_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "joined tile imageblock pointers: %u %s\n", error.kind, error.detail);
   assert(shader);
   ralloc_free(shader);
   /* Outside a tile function, data of a later color is refused, and a
    * kernel's imageblock pointers join as a tile function's do. */
   o.tile = NULL;
   o.dynamic_shape = false;
   assert(!kernel_with(tile_explicit_body, tile_explicit_metadata, &o, &error));
   o.workgroup_size[0] = 8;
   o.workgroup_size[1] = 8;
   o.workgroup_size[2] = 1;
   o.max_threadgroup_bytes = 32768;
   shader = kernel_with(joined, tile_explicit_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "joined kernel imageblock pointers: %u %s\n", error.kind, error.detail);
   assert(shader);
   assert(intrinsics(shader, nir_intrinsic_load_shared) >= 1);
   ralloc_free(shader);
}

/* A null texture has no descriptor to bind, and reads zero. */
static void
null_textures_bind_nothing(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(null_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "null: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "null texture kernel");
   assert(!count(shader).first[nir_texop_txl]);
   ralloc_free(shader);
   /* A null depth texture is one too. */
   static const char *depth =
      "declare ptr addrspace(1) @air.get_null_depth_2d()\n"
      "declare i1 @air.is_null_depth_2d(ptr addrspace(1))\n"
      "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
      " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
      "%none = call ptr addrspace(1) @air.get_null_depth_2d()\n"
      "%null = call i1 @air.is_null_depth_2d(ptr addrspace(1) %none)\n"
      "%bit = zext i1 %null to i32\n"
      "store i32 %bit, ptr addrspace(1) %out, align 4\n"
      "ret void\n}\n";
   shader = kernel(depth, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "null depth: %u %s\n", error.kind, error.detail);
   assert(shader);
   ralloc_free(shader);
}

/* Textures chosen at run time between a bound one and a null one, through a
 * PHI and a select: each call on the bound texture runs only where it was
 * chosen, and is_null_texture reports the choice. */
static void
textures_choose_null_at_run_time(void)
{
   static const char *chosen =
      "declare ptr addrspace(1) @air.get_null_texture_2d()\n"
      "declare i1 @air.is_null_texture_2d(ptr addrspace(1))\n"
      "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
      " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
      "%use = icmp ne i32 %tid, 0\n"
      "br i1 %use, label %join, label %none\n"
      "none:\n"
      "%null = call ptr addrspace(1) @air.get_null_texture_2d()\n"
      "br label %join\n"
      "join:\n"
      "%t = phi ptr addrspace(1) [ %null, %none ], [ %src, %0 ]\n"
      "%n = call ptr addrspace(1) @air.get_null_texture_2d()\n"
      "%d = select i1 %use, ptr addrspace(1) %dst, ptr addrspace(1) %n\n"
      "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %t,"
      " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> zeroinitializer,"
      " i1 false, float 0.0, float 0.0, i32 0)\n"
      "%texel = extractvalue { <4 x float>, i8 } %s, 0\n"
      "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %d, <2 x i32> <i32 3, i32 4>,"
      " <4 x float> %texel, i32 0, i32 2)\n"
      "%is = call i1 @air.is_null_texture_2d(ptr addrspace(1) %t)\n"
      "%w = call i32 @air.get_width_texture_2d(ptr addrspace(1) %t, i32 0)\n"
      "%bit = zext i1 %is to i32\n"
      "%v = add i32 %w, %bit\n"
      "store i32 %v, ptr addrspace(1) %out, align 4\n"
      "ret void\n}\n";
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(chosen, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "chosen: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "chosen null texture kernel");
   assert(count(shader).first[nir_texop_txl]);
   ralloc_free(shader);
   /* Two different bound textures are no choice a null one makes. */
   static const char *distinct =
      "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
      " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
      "%use = icmp ne i32 %tid, 0\n"
      "%t = select i1 %use, ptr addrspace(1) %src, ptr addrspace(1) %dst\n"
      "%w = call i32 @air.get_width_texture_2d(ptr addrspace(1) %t, i32 0)\n"
      "store i32 %w, ptr addrspace(1) %out, align 4\n"
      "ret void\n}\n";
   assert(!kernel(distinct, kernel_metadata, &error));
}

/* Two samples join through a PHI of their results, without their residency. */
static void
samples_join_through_phis(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(joined_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "joined: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "joined samples kernel");
   nir_tex_instr *sample = count(shader).first[nir_texop_txl];
   assert(sample && !sample->is_sparse && sample->def.num_components == 4);
   ralloc_free(shader);
}

/* 16 bit positions and levels widen to the 32 bits every image op takes. */
static void
short_indices_widen_their_positions(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(short_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "short: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_validate_shader(shader, "short index kernel");
   struct census census = count(shader);
   assert(census.first[nir_texop_txf] || census.load);
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

/* fetch_max at ushort positions (.i16), as MetalFX's motion vector splats
 * call it, on the uint 2D and int 2D array textures of atomic_metadata. */
static const char *short_atomic_body =
   "declare <4 x i32> @air.atomic_fetch_max_explicit_texture_2d.i16.u.v4i32(ptr addrspace(1),"
   " <2 x i16>, <2 x i16>, <4 x i32>, i32, i32)\n"
   "declare <4 x i32> @air.atomic_fetch_max_explicit_texture_2d_array.i16.s.v4i32(ptr addrspace(1),"
   " <2 x i16>, i16, <2 x i16>, <4 x i32>, i32, i32)\n"
   "define void @kernel(ptr addrspace(1) %t, ptr addrspace(1) %a, ptr addrspace(1) %out) {\n"
   "%u = call <4 x i32> @air.atomic_fetch_max_explicit_texture_2d.i16.u.v4i32(ptr addrspace(1) %t,"
   " <2 x i16> <i16 -1, i16 2>, <2 x i16> zeroinitializer, <4 x i32> <i32 5, i32 0, i32 0, i32 0>,"
   " i32 0, i32 3)\n"
   "%s = call <4 x i32> @air.atomic_fetch_max_explicit_texture_2d_array.i16.s.v4i32(ptr addrspace(1) %a,"
   " <2 x i16> <i16 3, i16 4>, i16 1, <2 x i16> <i16 1, i16 -1>,"
   " <4 x i32> <i32 -7, i32 0, i32 0, i32 0>, i32 0, i32 3)\n"
   "%x = extractelement <4 x i32> %u, i32 0\n%y = extractelement <4 x i32> %s, i32 0\n"
   "%r = add i32 %x, %y\nstore i32 %r, ptr addrspace(1) %out, align 4\nret void\n}\n";

/* Positions zero-extend from 16 bits, offsets sign-extend, and the texel
 * stays 32 bits. */
static void
kernels_take_short_position_texture_atomics(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = kernel(short_atomic_body, atomic_metadata, &error);
   if (!shader)
      fprintf(stderr, "short texture atomics: %u %s\n", error.kind, error.detail);
   assert(shader);
   nir_opt_constant_folding(shader);
   nir_intrinsic_instr *atomics[2];
   assert(image_atomics(shader, atomics, ARRAY_SIZE(atomics)) == 2);
   assert(nir_intrinsic_atomic_op(atomics[0]) == nir_atomic_op_umax &&
          nir_intrinsic_format(atomics[0]) == PIPE_FORMAT_R32_UINT);
   assert(nir_intrinsic_atomic_op(atomics[1]) == nir_atomic_op_imax &&
          nir_intrinsic_format(atomics[1]) == PIPE_FORMAT_R32_SINT &&
          nir_intrinsic_image_array(atomics[1]));
   const uint32_t coords[2][3] = {{65535, 2, 0}, {4, 3, 1}};
   for (unsigned i = 0; i < 2; i++) {
      assert(atomics[i]->src[1].ssa->bit_size == 32 && atomics[i]->src[3].ssa->bit_size == 32);
      for (unsigned c = 0; c < 3; c++) {
         nir_scalar coord = nir_scalar_resolved(atomics[i]->src[1].ssa, c);
         assert(nir_scalar_is_const(coord) && nir_scalar_as_uint(coord) == coords[i][c]);
      }
   }
   nir_scalar data = nir_scalar_resolved(atomics[1]->src[3].ssa, 0);
   assert(nir_scalar_is_const(data) && nir_scalar_as_int(data) == -7);
   ralloc_free(shader);
}

#define SPELLED(calls) \
   "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp," \
   " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n" calls \
   "%u = fptoui float %x to i32\nstore i32 %u, ptr addrspace(1) %out, align 4\nret void\n}\n"

static const char *metal4_declarations =
   "declare ptr addrspace(2) @air.get_read_sampler()\n"
   "declare { <4 x float>, i8 } @air.read_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2),"
   " <2 x i32>, <2 x i32>, i32, i32)\n"
   "declare <4 x i32> @air.atomic_fetch_add_explicit_texture_2d.u.v4i32(ptr addrspace(1), <2 x i32>,"
   " <2 x i32>, <4 x i32>, i32, i32)\n";

/* Metal 4 reads through a placeholder sampler, at an offset. */
static const char *metal4_read = SPELLED(
   "%none = call ptr addrspace(2) @air.get_read_sampler()\n"
   "%s = call { <4 x float>, i8 } @air.read_texture_2d.v4f32(ptr addrspace(1) %src,"
   " ptr addrspace(2) %none, <2 x i32> <i32 1, i32 2>, <2 x i32> zeroinitializer, i32 0, i32 0)\n"
   "%t = extractvalue { <4 x float>, i8 } %s, 0\n"
   "%x = extractelement <4 x float> %t, i64 0\n");

static const char *metal4_atomic =
   "define void @kernel(ptr addrspace(1) %t, ptr addrspace(1) %a, ptr addrspace(1) %out) {\n"
   "%add = call <4 x i32> @air.atomic_fetch_add_explicit_texture_2d.u.v4i32(ptr addrspace(1) %t,"
   " <2 x i32> <i32 1, i32 2>, <2 x i32> zeroinitializer, <4 x i32> <i32 5, i32 0, i32 0, i32 0>,"
   " i32 0, i32 3)\nret void\n}\n";

static const char *metal1_declarations =
   "declare <4 x float> @air.sample_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2), <2 x float>,"
   " i1, <2 x i32>, i1, float)\n"
   "declare void @air.write_texture_2d.v4f32(ptr addrspace(1), <2 x i32>, <4 x float>, i32)\n";

/* Metal 1 has no access operands or minimum level of detail, and returns
 * bare texels. */
static const char *metal1_calls = SPELLED(
   "%s = call <4 x float> @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> zeroinitializer,"
   " i1 true, float 1.0)\n"
   "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %dst, <2 x i32> <i32 3, i32 4>,"
   " <4 x float> %s, i32 0)\n"
   "%x = extractelement <4 x float> %s, i64 0\n");

static nir_shader *
spelled(const char *triple, const char *declarations, const char *body, const char *metadata,
        struct stela_air_error *error)
{
   char prefix[1024];
   snprintf(prefix, sizeof(prefix),
            "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
            "target triple = \"%s\"\n%s", triple, declarations);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(prefix, body, metadata, "");
   const struct stela_air_options o = options(&primary, true);
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   if (!shader)
      fprintf(stderr, "%s: %u %s\n", triple, error->kind, error->detail);
   return shader;
}

static const char *lod_declaration =
   "declare float @air.calculate_clamped_lod_texture_2d(ptr addrspace(1), ptr addrspace(2),"
   " <2 x float>, i32)\n";

static const char *kernel_lod = SPELLED(
   "%x = call float @air.calculate_clamped_lod_texture_2d(ptr addrspace(1) %src,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i32 0)\n");

static void
kernels_calculate_levels_over_their_quadgroups(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = spelled("air64_v29-apple-macosx27.2.0", lod_declaration, kernel_lod,
                                kernel_metadata, &error);
   assert(shader && count(shader).tex[nir_texop_lod] == 1);
   assert(shader->info.derivative_group == DERIVATIVE_GROUP_LINEAR);
   assert(nir_shader_supports_implicit_lod(shader));
   ralloc_free(shader);
}

static void
every_metal_version_spells_its_calls(void)
{
   struct stela_air_error error = {0};
   nir_shader *shader = spelled("air64_v29-apple-macosx27.2.0", metal4_declarations, metal4_read,
                                kernel_metadata, &error);
   assert(shader && count(shader).tex[nir_texop_txf] == 1);
   ralloc_free(shader);

   /* Libraries built for iOS run here unchanged. */
   shader = spelled("air64_v29-apple-ios27.2.0", metal4_declarations, metal4_read, kernel_metadata,
                    &error);
   assert(shader);
   ralloc_free(shader);

   /* An offset moves the texel read, as Apple7 GPUs read. */
   shader = spelled("air64_v29-apple-macosx27.2.0", metal4_declarations,
                    replace(metal4_read, "<2 x i32> zeroinitializer", "<2 x i32> <i32 1, i32 -1>"),
                    kernel_metadata, &error);
   assert(shader);
   /* (1, 2) + (1, -1) once folded. */
   nir_opt_constant_folding(shader);
   nir_opt_copy_prop(shader);
   nir_tex_instr *fetch = count(shader).first[nir_texop_txf];
   nir_src *coord = &fetch->src[nir_tex_instr_src_index(fetch, nir_tex_src_coord)].src;
   assert(nir_src_is_const(*coord) && nir_src_comp_as_uint(*coord, 0) == 2 &&
          nir_src_comp_as_uint(*coord, 1) == 1);
   ralloc_free(shader);
   /* Through a sampler, the read clamps to the level's edge. */
   shader = spelled("air64_v29-apple-macosx27.2.0", metal4_declarations,
                    replace(metal4_read, "ptr addrspace(2) %none, <2 x i32>",
                            "ptr addrspace(2) %smp, <2 x i32>"),
                    kernel_metadata, &error);
   assert(shader && count(shader).tex[nir_texop_txs] == 1 && count(shader).tex[nir_texop_txf] == 1);
   ralloc_free(shader);

   shader = spelled("air64_v29-apple-macosx27.2.0", metal4_declarations, metal4_atomic,
                    atomic_metadata, &error);
   nir_intrinsic_instr *atomics[1];
   assert(shader && image_atomics(shader, atomics, 1) == 1);
   ralloc_free(shader);

   shader = spelled("air64_v111-apple-macosx10.12.0", metal1_declarations, metal1_calls,
                    replace(kernel_metadata, "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1",
                            "!20 = !{i32 1, i32 11, i32 0}\n!21 = !{!\"Metal\", i32 1, i32 2"),
                    &error);
   assert(shader);
   struct census census = count(shader);
   assert(census.tex[nir_texop_txl] == 1 && census.store);
   ralloc_free(shader);

   /* Linking older libraries drops the version from the triple. */
   shader = spelled("air64-apple-macosx10.12.0", metal1_declarations, metal1_calls,
                    replace(kernel_metadata, "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1",
                            "!20 = !{i32 1, i32 11, i32 0}\n!21 = !{!\"Metal\", i32 1, i32 2"),
                    &error);
   assert(shader);
   ralloc_free(shader);

   /* The triple otherwise carries the version. */
   assert(!spelled("air64_v29-apple-macosx10.12.0", metal1_declarations, metal1_calls,
                   replace(kernel_metadata, "!20 = !{i32 2, i32 9, i32 0}", "!20 = !{i32 1, i32 11, i32 0}"),
                   &error));
   assert(error.kind == STELA_AIR_TARGET);
}

/* A fragment function that stops shading some pixels, then differentiates
 * a value it reads from a constant buffer and samples with a bias at a
 * coordinate made from it: the read and the derivative leave the branch,
 * and the sample takes the gradients taken there, scaled by 2^bias. */
static const char *divergent_body =
   "declare float @air.dfdx.f32(float)\n"
   "define <4 x float> @fragment(<4 x float> %position, ptr addrspace(1) %color,"
   " ptr addrspace(2) %smp, ptr addrspace(2) %k) {\n"
   "entry:\n"
   "%x = extractelement <4 x float> %position, i64 0\n"
   "%skip = fcmp olt float %x, 4.0\n"
   "br i1 %skip, label %out, label %shade\n"
   "shade:\n"
   "%kp = getelementptr inbounds i8, ptr addrspace(2) %k, i64 4\n"
   "%s = load float, ptr addrspace(2) %kp, align 4\n"
   "%w = fmul float %x, %s\n"
   "%d = call float @air.dfdx.f32(float %w)\n"
   "%uv0 = insertelement <2 x float> undef, float %w, i64 0\n"
   "%uv = insertelement <2 x float> %uv0, float %x, i64 1\n"
   "%t = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %color,"
   " ptr addrspace(2) %smp, <2 x float> %uv, i1 true, <2 x i32> zeroinitializer,"
   " i1 false, float 1.0, float 0.0, i32 0)\n"
   "%c = extractvalue { <4 x float>, i8 } %t, 0\n"
   "%r = insertelement <4 x float> %c, float %d, i64 3\n"
   "br label %out\n"
   "out:\n"
   "%v = phi <4 x float> [ zeroinitializer, %entry ], [ %r, %shade ]\n"
   "ret <4 x float> %v\n}\n";

static const char *divergent_metadata =
   "!air.fragment = !{!10}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!10 = !{ptr @fragment, !11, !13}\n!11 = !{!12}\n"
   "!12 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\"}\n"
   "!13 = !{!14, !15, !16, !17}\n"
   "!14 = !{i32 0, !\"air.position\", !\"air.center\", !\"air.no_perspective\","
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!15 = !{i32 1, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.sample\","
   " !\"air.arg_type_name\", !\"texture2d<float, sample>\", !\"air.arg_name\", !\"color\"}\n"
   "!16 = !{i32 2, !\"air.sampler\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"sampler\", !\"air.arg_name\", !\"smp\"}\n"
   "!17 = !{i32 3, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read\","
   " !\"air.address_space\", i32 2, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"k\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

/* Whether an instruction lies outside every branch. */
static bool
unconditional(const nir_instr *instr)
{
   return instr->block->cf_node.parent->type == nir_cf_node_function;
}

static void
divergent_derivatives_take_the_whole_quad(void)
{
   LLVMMemoryBufferRef input = bitcode(divergent_body, divergent_metadata);
   struct stela_air_stage_options o = {
      .stage = STELA_AIR_FRAGMENT, .resources = options(&fragment, false), .max_varying_slots = 16,
   };
   o.resources.fp_profile = STELA_AIR_FP_METAL;
   struct stela_air_error error = {0};
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               "fragment", &nir_options, &o, &error);
   LLVMDisposeMemoryBuffer(input);
   if (!shader)
      fprintf(stderr, "divergent: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "divergent fragment");
   struct census census = count(shader);
   assert(census.tex[nir_texop_txd] == 1 && !census.tex[nir_texop_tex] &&
          !census.tex[nir_texop_txb]);
   nir_tex_instr *txd = census.first[nir_texop_txd];
   assert(!unconditional(&txd->instr));
   assert(nir_tex_instr_src_index(txd, nir_tex_src_bias) < 0);
   unsigned ddx = 0, ddy = 0, speculated = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            switch (intrinsic->intrinsic) {
            case nir_intrinsic_ddx:
               assert(unconditional(instr));
               ddx++;
               break;
            case nir_intrinsic_ddy:
               assert(unconditional(instr));
               ddy++;
               break;
            case nir_intrinsic_load_global:
               /* The constant buffer's field; the argument tables' fields
                * are also speculatable, and free to reorder. */
               if ((nir_intrinsic_access(intrinsic) & (ACCESS_CAN_SPECULATE | ACCESS_CAN_REORDER)) ==
                   ACCESS_CAN_SPECULATE) {
                  assert(unconditional(instr));
                  speculated++;
               }
               break;
            default:
               break;
            }
         }
      }
   }
   /* dfdx(w), and the coordinate's two gradients. */
   assert(ddx == 2 && ddy == 1 && speculated == 1);
   /* The gradients the sample takes are scaled by its bias. */
   for (unsigned i = 0; i < 2; i++) {
      nir_def *gradient = nir_get_tex_src(txd, i ? nir_tex_src_ddy : nir_tex_src_ddx);
      assert(gradient && nir_def_instr(gradient)->type == nir_instr_type_alu &&
             nir_instr_as_alu(nir_def_instr(gradient))->op == nir_op_fmul);
   }
   ralloc_free(shader);
}

/* The divergent fragment's metadata with `body`. */
static nir_shader *
fragment_of(const char *body)
{
   LLVMMemoryBufferRef input = bitcode(body, divergent_metadata);
   struct stela_air_stage_options o = {
      .stage = STELA_AIR_FRAGMENT, .resources = options(&fragment, false), .max_varying_slots = 16,
   };
   o.resources.fp_profile = STELA_AIR_FP_METAL;
   struct stela_air_error error = {0};
   nir_shader *shader = stela_air_stage_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                               "fragment", &nir_options, &o, &error);
   LLVMDisposeMemoryBuffer(input);
   if (!shader)
      fprintf(stderr, "branched: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "branched fragment");
   return shader;
}

/* The divergent fragment with its branch on `skip` computed as `branch`. */
static nir_shader *
branched_fragment(const char *branch)
{
   char body[4096];
   snprintf(body, sizeof(body), "%s",
            replace(divergent_body, "%skip = fcmp olt float %x, 4.0\n", branch));
   return fragment_of(body);
}

/* The number of derivatives taken outside every branch, and inside one. */
static void
derivative_places(nir_shader *shader, unsigned *outside, unsigned *inside)
{
   *outside = *inside = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_intrinsic &&
                (nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_ddx ||
                 nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_ddy))
               (*(unconditional(instr) ? outside : inside))++;
         }
      }
   }
}

/* A branch on a value every invocation shares keeps a quad's lanes
 * together, so its derivative and implicit-derivative sample stay in it;
 * a branch on a value read at a per-pixel index does not. */
static void
uniform_branches_keep_their_derivatives(void)
{
   nir_shader *shader = branched_fragment("%k0 = load float, ptr addrspace(2) %k, align 4\n"
                                          "%skip = fcmp olt float %k0, 4.0\n");
   struct census census = count(shader);
   assert(!census.tex[nir_texop_txd] && census.tex[nir_texop_txb] == 1);
   assert(!unconditional(&census.first[nir_texop_txb]->instr));
   unsigned outside, inside;
   derivative_places(shader, &outside, &inside);
   assert(!outside && inside == 1);
   ralloc_free(shader);

   shader = branched_fragment("%i = fptoui float %x to i64\n"
                              "%i3 = and i64 %i, 3\n"
                              "%ki = getelementptr inbounds float, ptr addrspace(2) %k, i64 %i3\n"
                              "%k0 = load float, ptr addrspace(2) %ki, align 4\n"
                              "%skip = fcmp olt float %k0, 4.0\n");
   census = count(shader);
   assert(census.tex[nir_texop_txd] == 1 && !census.tex[nir_texop_txb]);
   derivative_places(shader, &outside, &inside);
   assert(outside == 3 && !inside);
   ralloc_free(shader);
}

/* A read the branch guards, of a read-only buffer Apple's compiler marks
 * unaliased, at a per-pixel index the skipped pixels would take out of its
 * bounds: it may fault, so it stays in the branch, and so do the derivative
 * of the value it reads and the sample at a coordinate made from it. */
static void
guarded_reads_keep_their_derivatives(void)
{
   char body[4096];
   snprintf(body, sizeof(body), "%s",
            replace(divergent_body, "ptr addrspace(2) %k)",
                    "ptr addrspace(2) \"air-buffer-no-alias\" %k)"));
   char indexed[4096];
   snprintf(indexed, sizeof(indexed), "%s",
            replace(body, "%kp = getelementptr inbounds i8, ptr addrspace(2) %k, i64 4\n",
                    "%i = fptoui float %x to i64\n%j = sub i64 %i, 4\n"
                    "%kp = getelementptr inbounds float, ptr addrspace(2) %k, i64 %j\n"));
   nir_shader *shader = fragment_of(indexed);
   struct census census = count(shader);
   assert(!census.tex[nir_texop_txd] && census.tex[nir_texop_txb] == 1);
   assert(!unconditional(&census.first[nir_texop_txb]->instr));
   unsigned outside, inside, guarded = 0;
   derivative_places(shader, &outside, &inside);
   assert(!outside && inside == 1);
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic ||
                nir_instr_as_intrinsic(instr)->intrinsic != nir_intrinsic_load_global)
               continue;
            nir_intrinsic_instr *load = nir_instr_as_intrinsic(instr);
            /* The argument table's address field is in bounds anywhere. */
            if (nir_intrinsic_access(load) & ACCESS_CAN_SPECULATE)
               continue;
            assert(nir_intrinsic_access(load) & ACCESS_CAN_REORDER);
            assert(!unconditional(instr));
            guarded++;
         }
      }
   }
   assert(guarded == 1);
   ralloc_free(shader);
}

/* A frozen texel and residency pair, as Apple's compiler freezes a read
 * whose lanes it uses before checking them, keeps the read's four lanes and
 * its residency. */
static void
frozen_texture_reads_keep_their_lanes(void)
{
   static const char *body =
      "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
      " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
      "%r = call { <4 x float>, i8 } @air.read_texture_2d.v4f32(ptr addrspace(1) %src,"
      " <2 x i32> <i32 5, i32 6>, i32 0, i32 0)\n"
      "%f = freeze { <4 x float>, i8 } %r\n"
      "%t = extractvalue { <4 x float>, i8 } %f, 0\n"
      "%k = extractvalue { <4 x float>, i8 } %f, 1\n"
      "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %dst, <2 x i32> <i32 3, i32 4>,"
      " <4 x float> %t, i32 0, i32 2)\n"
      "%w = zext i8 %k to i32\n"
      "store i32 %w, ptr addrspace(1) %out, align 4\n"
      "ret void\n}\n";
   struct stela_air_options o = options(&primary, true);
   struct stela_air_error error = {0};
   nir_shader *shader = kernel_with(body, kernel_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "frozen read: %s\n", error.detail);
   assert(shader);
   assert(count(shader).tex[nir_texop_txf] == 1);
   ralloc_free(shader);
}

/* Two samples of one texture that may have two planes: each branches to
 * its planes, and both convert them with the texture's one conversion,
 * computed ahead of the first branch, rather than each in its branch. */
static void
two_plane_samples_share_their_conversion(void)
{
   static const char *body =
      "define void @kernel(i32 %tid, ptr addrspace(1) %src, ptr addrspace(2) %smp,"
      " ptr addrspace(1) %dst, ptr addrspace(1) %layers, ptr addrspace(1) %out) {\n"
      "%a = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
      " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> zeroinitializer,"
      " i1 false, float 0.0, float 0.0, i32 0)\n"
      "%b = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %src,"
      " ptr addrspace(2) %smp, <2 x float> <float 0.25, float 0.5>, i1 true, <2 x i32> zeroinitializer,"
      " i1 false, float 0.0, float 0.0, i32 0)\n"
      "%ta = extractvalue { <4 x float>, i8 } %a, 0\n"
      "%tb = extractvalue { <4 x float>, i8 } %b, 0\n"
      "%t = fadd <4 x float> %ta, %tb\n"
      "call void @air.write_texture_2d.v4f32(ptr addrspace(1) %dst, <2 x i32> <i32 3, i32 4>,"
      " <4 x float> %t, i32 0, i32 2)\n"
      "ret void\n}\n";
   struct stela_air_options o = options(&primary, true);
   o.texture_planes = stela_metal_texture_planes;
   o.dynamic_planes = true;
   struct stela_air_error error = {0};
   nir_shader *shader = kernel_with(body, kernel_metadata, &o, &error);
   if (!shader)
      fprintf(stderr, "two-plane samples: %s\n", error.detail);
   assert(shader);
   nir_opt_cse(shader);
   nir_opt_dce(shader);
   /* Each sample takes a texel of each plane, or one of its only plane, at
    * the base level outside fragment functions. */
   assert(count(shader).tex[nir_texop_txl] == 6);
   unsigned video = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_alu || nir_instr_as_alu(instr)->op != nir_op_iand)
               continue;
            nir_alu_instr *alu = nir_instr_as_alu(instr);
            for (unsigned i = 0; i < 2; i++)
               video += nir_src_is_const(alu->src[i].src) &&
                        nir_src_comp_as_uint(alu->src[i].src, alu->src[i].swizzle[0]) ==
                           STELA_AIR_PLANES_VIDEO;
         }
      }
   }
   assert(video == 1);
   ralloc_free(shader);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   kernels_sample_write_read_and_query();
   fragments_sample_with_derivatives_compare_and_gather();
   storage_levels_select_their_descriptor();
   sparse_texels_report_their_residency();
   null_textures_bind_nothing();
   textures_choose_null_at_run_time();
   block_reads_fetch_each_texel();
   imageblocks_live_in_threadgroup_memory();
   tile_functions_access_their_attachments();
   tile_functions_access_imageblock_data();
   samples_join_through_phis();
   short_indices_widen_their_positions();
   array_arguments_bind_their_elements();
   constexpr_samplers_bind_their_samplers();
   cube_reads_fetch_their_faces();
   unsupported_texture_uses_are_refused();
   kernels_take_texture_atomics();
   kernels_take_short_position_texture_atomics();
   every_metal_version_spells_its_calls();
   kernels_calculate_levels_over_their_quadgroups();
   divergent_derivatives_take_the_whole_quad();
   uniform_branches_keep_their_derivatives();
   guarded_reads_keep_their_derivatives();
   two_plane_samples_share_their_conversion();
   frozen_texture_reads_keep_their_lanes();
   glsl_type_singleton_decref();
   puts("AIR textures: sample/level/offset, write, read_write array read, size queries, "
        "implicit-derivative fragment sampling, depth compare, gather, storage levels, arrays, atomics, "
        "constexpr samplers, cube reads, null textures, imageblocks, tile functions, joined samples, "
        "whole-quad derivatives in branches, derivatives kept in uniform branches and with guarded reads, and refusals passed");
   return 0;
}
