/* SPDX-License-Identifier: MIT */
/* Argument buffers: device and constant addresses, texture and sampler
 * resource IDs, inline constants and nested argument buffers, over the
 * Metal ABI's heap binds. Original LLVM IR fixtures in the argument buffer
 * reflection DXMT emits; no Apple output. */
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

/* Args is { texture2d<float, sample> tex; sampler smp; device float *data;
 * float scale; texture2d<float, read> layers[4]; constant Inner *inner; },
 * Inner is { device uint *counts; }. */
static const char *module =
   "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
   "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
   "%struct.Inner = type { ptr addrspace(1) }\n"
   "%struct.Args = type { ptr addrspace(1), ptr addrspace(2), ptr addrspace(1), float,"
   " [4 x ptr addrspace(1)], ptr addrspace(2) }\n"
   "%struct.Material = type { ptr addrspace(1), ptr addrspace(2) }\n"
   "declare { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2),"
   " <2 x float>, i1, <2 x i32>, i1, float, float, i32)\n"
   "declare i32 @air.get_width_texture_2d(ptr addrspace(1), i32)\n";

#define KERNEL(body) \
   "define void @kernel(i32 %tid, ptr addrspace(2) %args, ptr addrspace(1) %out) {\n" body "}\n"

static const char *kernel_body = KERNEL(
   "%tp = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 0\n"
   "%tex = load ptr addrspace(1), ptr addrspace(2) %tp, align 8\n"
   "%sp = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 1\n"
   "%smp = load ptr addrspace(2), ptr addrspace(2) %sp, align 8\n"
   "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %tex,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.25>, i1 true, <2 x i32> <i32 1, i32 -1>,"
   " i1 true, float 2.0, float 0.0, i32 0)\n"
   "%t = extractvalue { <4 x float>, i8 } %s, 0\n"
   "%x = extractelement <4 x float> %t, i64 0\n"
   "%scp = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 3\n"
   "%scale = load float, ptr addrspace(2) %scp, align 4\n"
   "%idx = zext i32 %tid to i64\n"
   "%lp = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 4, i64 %idx\n"
   "%layer = load ptr addrspace(1), ptr addrspace(2) %lp, align 8\n"
   "%w = call i32 @air.get_width_texture_2d(ptr addrspace(1) %layer, i32 0)\n"
   "%dp = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 2\n"
   "%data = load ptr addrspace(1), ptr addrspace(2) %dp, align 8\n"
   "%e = getelementptr float, ptr addrspace(1) %data, i64 %idx\n"
   "store float %x, ptr addrspace(1) %e, align 4\n"
   "%f = getelementptr float, ptr addrspace(1) %data, i64 1\n"
   "store float %scale, ptr addrspace(1) %f, align 4\n"
   "%ip = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 5\n"
   "%inner = load ptr addrspace(2), ptr addrspace(2) %ip, align 8\n"
   "%cp = getelementptr inbounds %struct.Inner, ptr addrspace(2) %inner, i64 0, i32 0\n"
   "%counts = load ptr addrspace(1), ptr addrspace(2) %cp, align 8\n"
   "store i32 %w, ptr addrspace(1) %counts, align 4\n"
   "ret void\n");

static const char *kernel_metadata =
   "!air.kernel = !{!2}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n"
   "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7}\n"
   "!5 = !{i32 0, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!6 = !{i32 1, !\"air.indirect_buffer\", !\"air.buffer_size\", i32 72, !\"air.location_index\","
   " i32 0, i32 1, !\"air.read\", !\"air.address_space\", i32 2, !\"air.struct_type_info\", !30,"
   " !\"air.arg_type_size\", i32 72, !\"air.arg_type_align_size\", i32 8, !\"air.arg_type_name\","
   " !\"Args\", !\"air.arg_name\", !\"args\"}\n"
   "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n"
   "!30 = !{i32 0, i32 8, i32 0, !\"texture2d<float, sample>\", !\"tex\", !\"air.indirect_argument\", !31,"
   " i32 8, i32 8, i32 0, !\"sampler\", !\"smp\", !\"air.indirect_argument\", !32,"
   " i32 16, i32 8, i32 0, !\"float*\", !\"data\", !\"air.indirect_argument\", !33,"
   " i32 24, i32 4, i32 0, !\"float\", !\"scale\", !\"air.indirect_argument\", !34,"
   " i32 32, i32 32, i32 4, !\"texture2d<float, read>\", !\"layers\", !\"air.indirect_argument\", !35,"
   " i32 64, i32 8, i32 0, !\"Inner\", !\"inner\", !\"air.indirect_argument\", !36}\n"
   "!31 = !{i32 0, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.sample\","
   " !\"air.arg_type_name\", !\"texture2d<float, sample>\", !\"air.arg_name\", !\"tex\"}\n"
   "!32 = !{i32 1, !\"air.sampler\", !\"air.location_index\", i32 1, i32 1,"
   " !\"air.arg_type_name\", !\"sampler\", !\"air.arg_name\", !\"smp\"}\n"
   "!33 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 2, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"data\"}\n"
   "!34 = !{i32 3, !\"air.indirect_constant\", !\"air.location_index\", i32 3, i32 1,"
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"scale\"}\n"
   "!35 = !{i32 4, !\"air.texture\", !\"air.location_index\", i32 4, i32 4, !\"air.read\","
   " !\"air.arg_type_name\", !\"texture2d<float, read>\", !\"air.arg_name\", !\"layers\"}\n"
   "!36 = !{i32 5, !\"air.indirect_buffer\", !\"air.buffer_size\", i32 8, !\"air.location_index\","
   " i32 8, i32 1, !\"air.read\", !\"air.address_space\", i32 2, !\"air.struct_type_info\", !37,"
   " !\"air.arg_type_size\", i32 8, !\"air.arg_type_align_size\", i32 8, !\"air.arg_type_name\","
   " !\"Inner\", !\"air.arg_name\", !\"inner\"}\n"
   "!37 = !{i32 0, i32 8, i32 0, !\"uint*\", !\"counts\", !\"air.indirect_argument\", !38}\n"
   "!38 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"counts\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n";

/* A fragment function that samples a material's texture with its sampler. */
static const char *fragment_body =
   "define <4 x float> @fragment(<4 x float> %position, ptr addrspace(2) %material) {\n"
   "%tp = getelementptr inbounds %struct.Material, ptr addrspace(2) %material, i64 0, i32 0\n"
   "%tex = load ptr addrspace(1), ptr addrspace(2) %tp, align 8\n"
   "%sp = getelementptr inbounds %struct.Material, ptr addrspace(2) %material, i64 0, i32 1\n"
   "%smp = load ptr addrspace(2), ptr addrspace(2) %sp, align 8\n"
   "%s = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %tex,"
   " ptr addrspace(2) %smp, <2 x float> <float 0.5, float 0.5>, i1 true, <2 x i32> zeroinitializer,"
   " i1 false, float 0.0, float 0.0, i32 0)\n"
   "%c = extractvalue { <4 x float>, i8 } %s, 0\n"
   "ret <4 x float> %c\n}\n";

static const char *fragment_metadata =
   "!air.fragment = !{!10}\n"
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!10 = !{ptr @fragment, !11, !13}\n!11 = !{!12}\n"
   "!12 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\"}\n"
   "!13 = !{!14, !15}\n"
   "!14 = !{i32 0, !\"air.position\", !\"air.center\", !\"air.no_perspective\","
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\", !\"air.arg_unused\"}\n"
   "!15 = !{i32 1, !\"air.indirect_buffer\", !\"air.buffer_size\", i32 16, !\"air.location_index\","
   " i32 0, i32 1, !\"air.read\", !\"air.address_space\", i32 2, !\"air.struct_type_info\", !16,"
   " !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 8, !\"air.arg_type_name\","
   " !\"Material\", !\"air.arg_name\", !\"material\"}\n"
   "!16 = !{i32 0, i32 8, i32 0, !\"texture2d<float, sample>\", !\"tex\", !\"air.indirect_argument\", !17,"
   " i32 8, i32 8, i32 0, !\"sampler\", !\"smp\", !\"air.indirect_argument\", !18}\n"
   "!17 = !{i32 0, !\"air.texture\", !\"air.location_index\", i32 0, i32 1, !\"air.sample\","
   " !\"air.arg_type_name\", !\"texture2d<float, sample>\", !\"air.arg_name\", !\"tex\"}\n"
   "!18 = !{i32 1, !\"air.sampler\", !\"air.location_index\", i32 1, i32 1,"
   " !\"air.arg_type_name\", !\"sampler\", !\"air.arg_name\", !\"smp\"}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};
static struct stela_metal_stage fragment = {.table = STELA_METAL_TABLE_FRAGMENT};

static struct stela_air_options
options(struct stela_metal_stage *stage, bool compute)
{
   return (struct stela_air_options){
      .workgroup_size = {compute ? 64u : 0u, compute ? 1u : 0u, compute ? 1u : 0u},
      .max_instructions = 10000, .bind_buffer = stela_metal_bind_buffer, .binding_data = stage,
      .bind_texture = stela_metal_bind_texture, .bind_sampler = stela_metal_bind_sampler,
      .bind_texture_id = stela_metal_bind_texture_id,
      .bind_sampler_id = stela_metal_bind_sampler_id,
   };
}

static nir_shader *
kernel_with(const char *body, const char *metadata, const struct stela_air_options *o,
            struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, metadata, "");
   *error = (struct stela_air_error){0};
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

static void
refused(const char *body, const char *metadata, enum stela_air_error_kind kind)
{
   struct stela_air_error error;
   nir_shader *shader = kernel(body, metadata, &error);
   if (shader || error.kind != kind)
      fprintf(stderr, "expected refusal %u, got %u %s\n", kind, error.kind, error.detail);
   assert(!shader && error.kind == kind);
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
intrinsics(nir_shader *shader, nir_intrinsic_op op, unsigned bit_size)
{
   unsigned n = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            n += intrinsic->intrinsic == op &&
                 (!bit_size || (nir_intrinsic_infos[op].has_dest ? intrinsic->def.bit_size :
                                intrinsic->src[0].ssa->bit_size) == bit_size);
         }
      }
   }
   return n;
}

static nir_tex_instr *
texture_instruction(nir_shader *shader, nir_texop op)
{
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_tex && nir_instr_as_tex(instr)->op == op)
               return nir_instr_as_tex(instr);
         }
      }
   }
   return NULL;
}

/* The load of the resource ID a texture instruction's heap element names. */
static nir_intrinsic_instr *
resource_id(nir_tex_instr *tex, nir_tex_src_type type)
{
   int index = nir_tex_instr_src_index(tex, type);
   assert(index >= 0);
   nir_deref_instr *element = nir_def_as_deref(tex->src[index].src.ssa);
   assert(element->deref_type == nir_deref_type_array);
   nir_alu_instr *half = nir_def_as_alu(element->arr.index.ssa);
   assert(half->op == nir_op_unpack_64_2x32_split_x);
   nir_intrinsic_instr *load = nir_def_as_intrinsic(half->src[0].src.ssa);
   assert(load->intrinsic == nir_intrinsic_load_global);
   return load;
}

static void
kernels_read_argument_buffers(void)
{
   struct stela_air_error error;
   nir_shader *shader = kernel(kernel_body, kernel_metadata, &error);
   if (!shader)
      fprintf(stderr, "kernel: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   nir_validate_shader(shader, "argument buffer kernel");

   /* Only the two arguments' addresses come from the argument table. */
   assert(intrinsics(shader, nir_intrinsic_load_push_constant, 0) == 2);
   /* Those, then tex, smp, layers[tid], data, inner and counts, and scale. */
   assert(intrinsics(shader, nir_intrinsic_load_global, 64) == 8);
   assert(intrinsics(shader, nir_intrinsic_load_global, 32) == 1);
   assert(intrinsics(shader, nir_intrinsic_store_global, 0) == 3);

   /* The sample's texture and sampler IDs are loaded from args. */
   nir_tex_instr *sample = texture_instruction(shader, nir_texop_txl);
   assert(sample);
   nir_intrinsic_instr *texture = resource_id(sample, nir_tex_src_texture_deref);
   nir_intrinsic_instr *sampler = resource_id(sample, nir_tex_src_sampler_deref);
   assert(texture != sampler && texture->src[0].ssa != sampler->src[0].ssa);
   /* layers[tid]'s ID is loaded at a dynamic offset. */
   nir_tex_instr *size = texture_instruction(shader, nir_texop_txs);
   assert(size);
   assert(!nir_src_is_const(resource_id(size, nir_tex_src_texture_deref)->src[0]));
   ralloc_free(shader);
}

static void
fragments_sample_argument_buffers(void)
{
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, fragment_body,
                                                             fragment_metadata, "");
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
   nir_validate_shader(shader, "argument buffer fragment");
   nir_tex_instr *sample = texture_instruction(shader, nir_texop_tex);
   assert(sample);
   resource_id(sample, nir_tex_src_texture_deref);
   resource_id(sample, nir_tex_src_sampler_deref);
   ralloc_free(shader);
   LLVMDisposeMemoryBuffer(input);
}

static void
argument_buffer_misuse_is_refused(void)
{
   /* An address load from inline data, and an ID loaded as an address. */
   refused(KERNEL("%p = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 3\n"
                  "%q = load ptr addrspace(1), ptr addrspace(2) %p, align 8\n"
                  "store i32 0, ptr addrspace(1) %q, align 4\nret void\n"),
           kernel_metadata, STELA_AIR_TYPE);
   refused(KERNEL("%q = load ptr addrspace(2), ptr addrspace(2) %args, align 8\n"
                  "store i32 0, ptr addrspace(1) %out, align 4\nret void\n"),
           kernel_metadata, STELA_AIR_TYPE);
   /* Dynamic indices step only through an array field's elements. */
   refused(KERNEL("%i = zext i32 %tid to i64\n"
                  "%p = getelementptr i8, ptr addrspace(2) %args, i64 %i\n"
                  "%q = load ptr addrspace(1), ptr addrspace(2) %p, align 8\n"
                  "store i32 0, ptr addrspace(1) %q, align 4\nret void\n"),
           kernel_metadata, STELA_AIR_MEMORY);
   /* Plain buffers hold no addresses. */
   refused(KERNEL("%q = load ptr addrspace(1), ptr addrspace(1) %out, align 8\n"
                  "store i32 0, ptr addrspace(1) %q, align 4\nret void\n"),
           kernel_metadata, STELA_AIR_MEMORY);
   /* A loaded address does not cross a PHI. */
   refused(KERNEL("%dp = getelementptr inbounds %struct.Args, ptr addrspace(2) %args, i64 0, i32 2\n"
                  "%data = load ptr addrspace(1), ptr addrspace(2) %dp, align 8\n"
                  "%c = icmp eq i32 %tid, 0\nbr i1 %c, label %a, label %b\n"
                  "a:\n%g = getelementptr float, ptr addrspace(1) %data, i64 1\nbr label %b\n"
                  "b:\n%p = phi ptr addrspace(1) [ %data, %0 ], [ %g, %a ]\n"
                  "store float 0.0, ptr addrspace(1) %p, align 4\nret void\n"),
           kernel_metadata, STELA_AIR_MEMORY);

   /* Loaded IDs need their bind callbacks; SSBO bindings have no addresses. */
   struct stela_air_options o = options(&primary, true);
   o.bind_texture_id = NULL;
   struct stela_air_error error;
   assert(!kernel_with(kernel_body, kernel_metadata, &o, &error) &&
          error.kind == STELA_AIR_INSTRUCTION);
}

static bool
ssbo_slot(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   *slot = buffer->index;
   return true;
}

static void
invalid_argument_buffers_are_refused(void)
{
   struct stela_air_options o = options(&primary, true);
   o.bind_buffer = NULL;
   o.bind_ssbo = ssbo_slot;
   o.ssbo_count = 2;
   struct stela_air_error error;
   assert(!kernel_with(kernel_body, kernel_metadata, &o, &error) &&
          error.kind == STELA_AIR_ARGUMENT);

   /* Overlapping fields, an array whose bytes are not its IDs, and counts
    * that disagree. */
   refused(kernel_body, replaced(kernel_metadata, "i32 8, i32 8, i32 0, !\"sampler\"",
                                 "i32 4, i32 8, i32 0, !\"sampler\""), STELA_AIR_TYPE);
   refused(kernel_body, replaced(kernel_metadata, "i32 32, i32 32, i32 4",
                                 "i32 32, i32 24, i32 4"), STELA_AIR_TYPE);
   refused(kernel_body, replaced(kernel_metadata, "i32 32, i32 32, i32 4",
                                 "i32 32, i32 32, i32 2"), STELA_AIR_METADATA);
   /* Unknown kinds, a size the reflection contradicts and a writable
    * constant address. */
   refused(kernel_body, replaced(kernel_metadata, "!\"air.indirect_constant\"",
                                 "!\"air.imageblock\""), STELA_AIR_ARGUMENT);
   refused(kernel_body, replaced(kernel_metadata, "!\"air.arg_type_size\", i32 72",
                                 "!\"air.arg_type_size\", i32 64"), STELA_AIR_ARGUMENT);
   refused(kernel_body, replaced(kernel_metadata,
                                 "!\"air.read\", !\"air.address_space\", i32 2, !\"air.struct_type_info\", !37",
                                 "!\"air.read_write\", !\"air.address_space\", i32 2,"
                                 " !\"air.struct_type_info\", !37"),
           STELA_AIR_ARGUMENT);
}

int
main(void)
{
   (void)stela_air_test_store_body;
   glsl_type_singleton_init_or_ref();
   kernels_read_argument_buffers();
   fragments_sample_argument_buffers();
   argument_buffer_misuse_is_refused();
   invalid_argument_buffers_are_refused();
   glsl_type_singleton_decref();
   puts("air argument buffer: ok");
   return 0;
}
