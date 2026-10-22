/* SPDX-License-Identifier: MIT */
/* Offline original AIR -> shared NIR -> original vendor compiler -> PM4.
 * Topology/VM and packet addresses below are immutable CPU models. No physical
 * device, allocation, residency, upload, execution or completion is claimed.
 */
#include "air_to_nir.h"
#include "stela/tests/air_test_fixture.h"
#include "air_probe_input.h"
#include "stela/tests/targets/amd.h"
#include "../hosted/compute.h"
#include "../hosted/llvm_compute.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/nir/ac_nir.h"
#include "amd/common/sid.h"
#include "amd/compiler/aco_interface.h"
#include "util/ralloc.h"
#if STELA_AMD_TEST_LLVM
#include "../hosted/llvm_float.h"
#include "amd/llvm/ac_llvm_build.h"
#include "amd/llvm/ac_nir_to_llvm.h"
#include "amd/llvm/ac_shader_abi.h"
#include <llvm-c/Analysis.h>
#include <llvm-c/Disassembler.h>
#include <llvm-c/Object.h>
#endif

#define CHECK(x) do { if (!(x)) { \
   fprintf(stderr, "%s:%u: %s\n", __func__, __LINE__, #x); exit(1); \
} } while (0)

static struct radeon_info
model(enum radeon_family family, bool graphics)
{
   struct radeon_info info = {
      .family = family, .gfx_level = ac_get_gfx_level(family), .has_graphics = graphics,
      .num_cu = 8, .num_se = 2, .max_se = 2, .spi_cu_en = UINT32_MAX,
      .max_good_cu_per_sa = 4, .max_sa_per_se = 1,
      .virtual_address_max = UINT64_C(0x800000000000),
      .virtual_address_alignment = 4096, .tcc_cache_line_size = 128,
   };
   ac_fill_compiler_info(&info, NULL, false);
   info.instr_prefetch_distance = info.gfx_level >= GFX11 ? 4 : 0;
   return info;
}

static void
test_finalizer(const struct radeon_info *info)
{
   const unsigned grain = ac_shader_get_lds_alloc_granularity(info->gfx_level);
   const unsigned limit = info->compiler_info.lds_size_per_workgroup;
   const unsigned sizes[] = {0, 1, grain - 1, grain, grain + 1, limit};
   nir_shader shader = {.info = {.stage = MESA_SHADER_COMPUTE}};
   for (unsigned i = 0; i < ARRAY_SIZE(sizes); i++) {
      shader.info.shared_size = sizes[i];
      struct ac_shader_config config;
      memset(&config, 0xa5, sizeof(config));
      config.lds_size = 0;
      struct ac_shader_config expected = config;
      /* Compute LDS is exactly the shader's shared size. */
      expected.lds_size = sizes[i];
      CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
            STELA_AMD_LLVM_COMPUTE_OK);
      CHECK(!memcmp(&expected, &config, sizeof(config)));
      CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
            STELA_AMD_LLVM_COMPUTE_OK);
      CHECK(!memcmp(&expected, &config, sizeof(config)));
   }
   struct ac_shader_config config = {.lds_size = 7}, preserved = config;
   shader.info.shared_size = 8;
   CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
         STELA_AMD_LLVM_COMPUTE_CONFIG_MISMATCH);
   CHECK(!memcmp(&preserved, &config, sizeof(config)));
   config.lds_size = 0;
   preserved = config;
   const unsigned bad[] = {limit + 1, UINT32_MAX};
   for (unsigned i = 0; i < ARRAY_SIZE(bad); i++) {
      shader.info.shared_size = bad[i];
      CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
            STELA_AMD_LLVM_COMPUTE_UNSUPPORTED);
      CHECK(!memcmp(&preserved, &config, sizeof(config)));
   }
   struct ac_compiler_info malformed = info->compiler_info;
   malformed.lds_size_per_workgroup = UINT32_MAX;
   const unsigned bad_encoding[] = {UINT32_MAX, UINT32_C(0x40000000)};
   for (unsigned i = 0; i < ARRAY_SIZE(bad_encoding); i++) {
      shader.info.shared_size = bad_encoding[i];
      CHECK(stela_amd_llvm_finalize_compute_lds(&malformed, &shader, &config) ==
            STELA_AMD_LLVM_COMPUTE_UNSUPPORTED);
      CHECK(!memcmp(&preserved, &config, sizeof(config)));
   }
   shader.info.shared_size = 128;
   shader.info.cs.has_variable_shared_mem = true;
   CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
         STELA_AMD_LLVM_COMPUTE_UNSUPPORTED);
   CHECK(!memcmp(&preserved, &config, sizeof(config)));
   shader.info.cs.has_variable_shared_mem = false;
   shader.info.workgroup_size_variable = true;
   CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
         STELA_AMD_LLVM_COMPUTE_UNSUPPORTED);
   CHECK(!memcmp(&preserved, &config, sizeof(config)));
   shader.info.workgroup_size_variable = false;
   shader.info.stage = MESA_SHADER_VERTEX;
   CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, &config) ==
         STELA_AMD_LLVM_COMPUTE_UNSUPPORTED);
   CHECK(!memcmp(&preserved, &config, sizeof(config)));
   CHECK(stela_amd_llvm_finalize_compute_lds(NULL, &shader, &config) ==
         STELA_AMD_LLVM_COMPUTE_INVALID);
   CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, NULL, &config) ==
         STELA_AMD_LLVM_COMPUTE_INVALID);
   CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, &shader, NULL) ==
         STELA_AMD_LLVM_COMPUTE_INVALID);
   CHECK(!memcmp(&preserved, &config, sizeof(config)));
}

struct fixture {
   LLVMMemoryBufferRef input;
   const char *name, *entry;
   unsigned workgroup, shared_bytes, shared_index;
   bool dynamic;
   enum { FIXED, ALLOCATION_GRAIN, TARGET_LIMIT } specialization;
   char hash[BLAKE3_HEX_LEN];
};

struct binding {
   struct ac_shader_args args;
   struct ac_arg buffer;
   const struct fixture *fixture;
   unsigned buffers, shared;
};

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   struct binding *binding = data;
   CHECK(buffer->index == 7 && buffer->address_space == 1 &&
         buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 &&
         buffer->type_alignment == 4);
   binding->buffers++;
   return nir_pack_64_2x32(b, ac_nir_load_arg(b, &binding->args, binding->buffer));
}

static bool
bind_threadgroup(const struct stela_air_buffer *buffer,
                   struct stela_air_threadgroup_view *view, void *data)
{
   struct binding *binding = data;
   CHECK(binding->fixture->dynamic && buffer->index == binding->fixture->shared_index &&
         buffer->address_space == 3 && buffer->access == STELA_AIR_READ_WRITE &&
         buffer->type_size == 4 && buffer->type_alignment == 4);
   binding->shared++;
   *view = (struct stela_air_threadgroup_view) {
      .size = binding->fixture->shared_bytes, .alignment = 4,
      .available_access = STELA_AIR_READ_WRITE,
   };
   return true;
}

static void
compute_args(struct binding *binding, const struct radeon_info *info)
{
   ac_add_arg(&binding->args, AC_ARG_SGPR, 2, AC_ARG_VALUE, &binding->buffer);
   for (unsigned axis = 0; axis < 3; axis++) {
      if (info->gfx_level >= GFX12)
         binding->args.workgroup_ids[axis].used = true;
      else
         ac_add_arg(&binding->args, AC_ARG_SGPR, 1, AC_ARG_VALUE,
                    &binding->args.workgroup_ids[axis]);
   }
   if (info->gfx_level < GFX11)
      ac_add_arg(&binding->args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &binding->args.scratch_offset);
   if (info->compiler_info.local_invocation_ids_packed) {
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE,
                 &binding->args.local_invocation_ids_packed);
   } else {
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_x);
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_y);
      ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_z);
   }
}

struct compiled {
   struct ac_shader_config config;
   unsigned executable_bytes, code_bytes, parsed_lds;
   unsigned shared_reads, shared_writes, barriers, waits;
   bool binary_disassembled;
   char hash[BLAKE3_HEX_LEN];
};

static void
observe_assembly(struct compiled *result, const char *text)
{
   result->shared_reads += strstr(text, "ds_read") != NULL || strstr(text, "ds_load") != NULL;
   result->shared_writes += strstr(text, "ds_write") != NULL || strstr(text, "ds_store") != NULL;
   result->barriers += strstr(text, "s_barrier") != NULL;
   result->waits += strstr(text, "s_wait") != NULL;
}

static void
capture(void **private, const struct ac_shader_config *config,
         const char *ir, unsigned ir_size, const char *assembly, unsigned assembly_size,
         struct amd_stats *stats, uint32_t exec_size, const uint32_t *code, uint32_t code_dw,
         const struct aco_symbol *symbols, unsigned num_symbols,
         const struct ac_shader_debug_info *debug_info, unsigned debug_count)
{
   (void)ir; (void)ir_size; (void)stats; (void)symbols; (void)debug_info; (void)debug_count;
   struct compiled *result = *private;
   CHECK(config && code && code_dw && code_dw <= UINT32_MAX / 4 && exec_size &&
         exec_size <= code_dw * 4 && !num_symbols && assembly && assembly_size);
   result->config = *config;
   result->parsed_lds = config->lds_size;
   result->executable_bytes = exec_size;
   result->code_bytes = code_dw * 4;
   stela_digest(code, exec_size, result->hash);
   char *text = malloc((size_t)assembly_size + 1);
   CHECK(text);
   memcpy(text, assembly, assembly_size);
   text[assembly_size] = 0;
   result->binary_disassembled = !strstr(text, "falling back to print_program");
   fputs(text, stdout);
   for (char *line = text; line && *line;) {
      char *next = strchr(line, '\n');
      if (next)
         *next++ = 0;
      observe_assembly(result, line);
      line = next;
   }
   free(text);
}

#if STELA_AMD_TEST_LLVM
static void
compile_llvm(nir_shader *shader, const struct ac_shader_args *args,
              const struct radeon_info *info, unsigned workgroup, struct compiled *result)
{
   struct ac_llvm_compiler compiler;
   CHECK(ac_init_llvm_compiler(&compiler, info->family, AC_TM_CHECK_IR));
   struct ac_llvm_context llvm = {0};
   ac_llvm_context_init(&llvm, &compiler, &info->compiler_info, AC_FLOAT_MODE_DEFAULT,
                        64, false, false);
   struct ac_shader_abi abi = {0};
   struct ac_llvm_pointer main = ac_build_main(args, &llvm, AC_LLVM_AMDGPU_CS,
                                               "stela_shared", llvm.voidt, llvm.module);
   ac_llvm_set_workgroup_size(main.value, workgroup);
   ac_llvm_set_target_features(main.value, &llvm, false);
   CHECK(stela_amd_llvm_apply_float_controls(llvm.context, main.value, shader) ==
         STELA_AMD_LLVM_FLOAT_OK);
   CHECK(ac_nir_translate(&llvm, &abi, args, shader));
   LLVMBuildRetVoid(llvm.builder);
   CHECK(!LLVMVerifyModule(llvm.module, LLVMReturnStatusAction, NULL));
   CHECK(ac_llvm_optimize_module(compiler.meo, llvm.module));
   CHECK(!LLVMVerifyModule(llvm.module, LLVMReturnStatusAction, NULL));
   char *elf = NULL;
   size_t elf_size = 0;
   compiler.beo = ac_create_backend_optimizer(compiler.tm);
   CHECK(ac_compile_module_to_elf(compiler.beo, llvm.module, &elf, &elf_size));
   CHECK(elf && elf_size >= 64 && !memcmp(elf, "\177ELF\2\1\1", 7));
   CHECK((unsigned char)elf[18] == 224 && !elf[19]);
   LLVMMemoryBufferRef memory = LLVMCreateMemoryBufferWithMemoryRangeCopy(elf, elf_size, "shared-elf");
   LLVMBinaryRef binary = LLVMCreateBinary(memory, NULL, NULL);
   CHECK(binary && LLVMBinaryGetType(binary) == LLVMBinaryTypeELF64L);
   LLVMSectionIteratorRef section = LLVMObjectFileCopySectionIterator(binary);
   bool config_found = false;
   for (; section && !LLVMObjectFileIsSectionIteratorAtEnd(binary, section); LLVMMoveToNextSection(section)) {
      LLVMRelocationIteratorRef reloc = LLVMGetRelocations(section);
      CHECK(!reloc || LLVMIsRelocationIteratorAtEnd(section, reloc));
      if (reloc)
         LLVMDisposeRelocationIterator(reloc);
      const char *name = LLVMGetSectionName(section);
      const char *data = LLVMGetSectionContents(section);
      const uint64_t size = LLVMGetSectionSize(section);
      if (name && !strcmp(name, ".text")) {
         CHECK(!result->executable_bytes && data && size && size <= UINT32_MAX && size <= elf_size);
         result->code_bytes = result->executable_bytes = size;
         stela_digest(data, size, result->hash);
         LLVMDisasmContextRef disasm = LLVMCreateDisasmCPU(LLVMGetTarget(llvm.module),
            ac_get_llvm_processor_name(info->family), NULL, 0, NULL, NULL);
         CHECK(disasm);
         for (size_t offset = 0; offset < size;) {
            char text[512];
            size_t bytes = LLVMDisasmInstruction(disasm, (uint8_t *)data + offset,
               size - offset, offset, text, sizeof(text));
            CHECK(bytes && bytes <= size - offset);
            printf("AMD LLVM +0x%zx: %s\n", offset, text);
            observe_assembly(result, text);
            offset += bytes;
         }
         LLVMDisasmDispose(disasm);
         result->binary_disassembled = true;
      } else if (name && !strcmp(name, ".AMDGPU.config")) {
         CHECK(!config_found && data && size && size <= elf_size && size % 8 == 0 &&
               (uintptr_t)data % _Alignof(uint32_t) == 0);
         ac_parse_llvm_binary_config(data, size, 64, &info->compiler_info, &result->config);
         result->parsed_lds = result->config.lds_size;
         CHECK(!result->parsed_lds); /* Original parser leaves frontend LDS allocation empty. */
         CHECK(stela_amd_llvm_restore_float_controls(shader, &result->config) ==
               STELA_AMD_LLVM_FLOAT_OK);
         struct ac_shader_config expected = result->config;
         expected.lds_size = shader->info.shared_size;
         CHECK(stela_amd_llvm_finalize_compute_lds(&info->compiler_info, shader, &result->config) ==
               STELA_AMD_LLVM_COMPUTE_OK);
         CHECK(!memcmp(&expected, &result->config, sizeof(expected)));
         config_found = true;
      }
   }
   CHECK(config_found && result->executable_bytes);
   if (section)
      LLVMDisposeSectionIterator(section);
   LLVMDisposeBinary(binary);
   LLVMDisposeMemoryBuffer(memory);
   free(elf);
   ac_llvm_context_dispose(&llvm);
   LLVMDisposeModule(llvm.module);
   LLVMContextDispose(llvm.context);
   ac_destroy_llvm_compiler(&compiler);
}
#endif

static uint32_t
register_word(const uint32_t *words, unsigned count, unsigned reg)
{
   for (unsigned cursor = 0; cursor < count;) {
      const unsigned header = words[cursor], length = ((header >> 16) & 0x3fff) + 2;
      CHECK(header >> 30 == 3 && length <= count - cursor &&
            ((header >> 8) & 255) == PKT3_SET_SH_REG && length >= 3);
      const unsigned start = 0xb000 + 4 * words[cursor + 1];
      for (unsigned i = 2; i < length; i++) {
         if (start + 4 * (i - 2) == reg)
            return words[cursor + i];
      }
      cursor += length;
   }
   CHECK(false);
   return 0;
}

static void
compile_target(const struct fixture *fixture, const char *target, enum radeon_family family,
                unsigned wave, bool llvm_backend)
{
   struct radeon_info info = model(family, stela_amd_has_graphics(family));
   struct fixture specialized = *fixture;
   if (fixture->specialization == ALLOCATION_GRAIN)
      specialized.shared_bytes = ac_shader_get_lds_alloc_granularity(info.gfx_level);
   else if (fixture->specialization == TARGET_LIMIT)
      specialized.shared_bytes = info.compiler_info.lds_size_per_workgroup;
   fixture = &specialized;
   if (!llvm_backend && !aco_is_gpu_supported(&info)) {
      record_held(target, stela_amd_aco_refusal(family));
      return;
   }
   test_finalizer(&info);
   nir_shader_compiler_options nir_options;
   ac_nir_set_options(&info.compiler_info, llvm_backend, &nir_options);
   struct binding binding = {.fixture = fixture};
   compute_args(&binding, &info);
   const struct stela_air_options options = {
      .workgroup_size = {fixture->workgroup, 1, 1}, .max_instructions = 256,
      .bind_buffer = bind_buffer, .binding_data = &binding,
      .bind_threadgroup = bind_threadgroup,
      .max_threadgroup_bytes = info.compiler_info.lds_size_per_workgroup,
   };
   struct stela_air_error error;
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(fixture->input),
      LLVMGetBufferSize(fixture->input), fixture->entry, &nir_options, &options, &error);
   if (!shader)
      fprintf(stderr, "%s %s refused %u: %s\n", ac_get_family_name(family), fixture->entry,
              error.kind, error.detail);
   CHECK(shader && error.kind == STELA_AIR_OK && binding.buffers == 1 &&
         binding.shared == fixture->dynamic && shader->info.shared_size == fixture->shared_bytes &&
         !shader->info.cs.has_variable_shared_mem);
   unsigned shared_loads = 0, shared_stores = 0, barriers = 0, global_stores = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            shared_loads += intr->intrinsic == nir_intrinsic_load_shared;
            shared_stores += intr->intrinsic == nir_intrinsic_store_shared;
            if (intr->intrinsic == nir_intrinsic_store_global) {
               CHECK(!nir_src_is_const(intr->src[1]));
               global_stores++;
            }
            if (intr->intrinsic == nir_intrinsic_barrier) {
               CHECK(nir_intrinsic_execution_scope(intr) == SCOPE_WORKGROUP &&
                     nir_intrinsic_memory_scope(intr) == SCOPE_WORKGROUP &&
                     nir_intrinsic_memory_modes(intr) == nir_var_mem_shared &&
                     nir_intrinsic_memory_semantics(intr) == NIR_MEMORY_ACQ_REL);
               barriers++;
            }
         }
      }
   }
   CHECK(global_stores);
   CHECK(fixture->shared_bytes ? shared_loads && shared_stores && barriers :
                                !shared_loads && !shared_stores && !barriers);
   const ac_nir_lower_intrinsics_to_args_options arg_options = {
      .gfx_level = info.gfx_level, .hw_stage = AC_HW_COMPUTE_SHADER,
      .wave_size = wave, .workgroup_size = fixture->workgroup, .use_llvm = llvm_backend,
   };
   ac_nir_lower_intrinsics_to_args(shader, &binding.args, &arg_options);
   ac_nir_lower_global_access(shader, info.gfx_level);
   nir_lower_int64(shader);
   bool progress;
   do {
      progress = nir_opt_constant_folding(shader);
      progress |= nir_opt_copy_prop(shader);
      progress |= nir_opt_algebraic(shader);
      progress |= nir_opt_dce(shader);
   } while (progress);
   nir_lower_alu_width(shader, ac_nir_opt_vectorize_cb, &info.gfx_level);
   nir_lower_load_const_to_scalar(shader);
   nir_opt_copy_prop(shader);
   nir_opt_dce(shader);
   nir_shader_gather_info(shader, nir_shader_get_entrypoint(shader));
   nir_validate_shader(shader, "AIR shared actual AMD compiler input");
   struct compiled compiled = {0};
   if (llvm_backend) {
#if STELA_AMD_TEST_LLVM
      CHECK(wave == 64);
      compile_llvm(shader, &binding.args, &info, fixture->workgroup, &compiled);
#else
      CHECK(false);
#endif
   } else {
      const struct aco_compiler_options compiler_options = {
         .compiler_info = &info.compiler_info, .family = family,
         .gfx_level = info.gfx_level, .record_asm = true,
      };
      const struct aco_shader_info shader_info = {
         .hw_stage = AC_HW_COMPUTE_SHADER, .wave_size = wave,
         .workgroup_size = fixture->workgroup, .lds_size = shader->info.shared_size,
      };
      void *private = &compiled;
      aco_compile_shader(&compiler_options, &shader_info, 1, &shader, &binding.args, capture, &private);
   }
   CHECK(fixture->shared_bytes ? compiled.shared_reads && compiled.shared_writes && compiled.waits :
                                !compiled.shared_reads && !compiled.shared_writes && !compiled.barriers);
   /* Original compilers may remove a collective instruction for one wave;
    * a multi-wave workgroup must retain actual hardware synchronization. */
   CHECK(!fixture->shared_bytes || fixture->workgroup <= wave || compiled.barriers);
   CHECK(compiled.config.lds_size == fixture->shared_bytes);
   const struct stela_amd_compute_binary binary = {
      .shader = shader, .args = &binding.args, .config = &compiled.config,
      .family = family, .gfx_level = info.gfx_level, .wave_size = wave,
      .executable_bytes = compiled.executable_bytes, .code_bytes = compiled.code_bytes,
   };
   /* CPU packet model only. Shader address still comes from real SGPR inputs. */
   const struct stela_amd_buffer_view code = {
      .allocation_va = 0x10000000, .allocation_bytes = 4096, .range = 4096,
      .required_alignment = 256,
   };
   const struct stela_amd_compute_binding resource = {
      .argument = binding.buffer, .view = {
         .allocation_va = 0x20000000, .allocation_bytes = 4096, .range = 4096,
         .required_alignment = 4,
      },
   };
   struct stela_amd_compute_pipeline pipeline;
   CHECK(stela_amd_build_compute_pipeline(&info, &binary, &code, &resource, 1, &pipeline) ==
         STELA_AMD_COMPUTE_OK);
   const unsigned encoded = ac_shader_encode_lds_size(fixture->shared_bytes,
      info.gfx_level, MESA_SHADER_COMPUTE);
   CHECK(G_00B84C_LDS_SIZE(pipeline.rsrc2) == encoded &&
         G_00B84C_USER_SGPR(pipeline.rsrc2) == 2 && !G_00B84C_SCRATCH_EN(pipeline.rsrc2) &&
         G_00B84C_TGID_X_EN(pipeline.rsrc2) && G_00B84C_TGID_Y_EN(pipeline.rsrc2) &&
         G_00B84C_TGID_Z_EN(pipeline.rsrc2) && G_00B84C_TIDIG_COMP_CNT(pipeline.rsrc2) == 2);
   const struct stela_amd_compute_pipeline preserved = pipeline;
   struct ac_shader_config incompatible = compiled.config;
   incompatible.lds_size = fixture->shared_bytes ? 0 : 1;
   struct stela_amd_compute_binary wrong_lds = binary;
   wrong_lds.config = &incompatible;
   CHECK(stela_amd_build_compute_pipeline(&info, &wrong_lds, &code, &resource, 1, &pipeline) ==
         STELA_AMD_COMPUTE_UNSUPPORTED);
   CHECK(!memcmp(&preserved, &pipeline, sizeof(pipeline)));
   uint32_t words[256], count;
   CHECK(stela_amd_compute_pipeline(&info, &pipeline, words, ARRAY_SIZE(words), &count) ==
         STELA_AMD_COMMAND_OK);
   CHECK(register_word(words, count, R_00B84C_COMPUTE_PGM_RSRC2) == pipeline.rsrc2);
   record_compiled(target, compiled.executable_bytes);
   record_object("facts");
   record_str("backend", llvm_backend ? "llvm" : "aco");
   record_str("input_blake3", fixture->hash);
   record_str("code_blake3", compiled.hash);
   record_uint("workgroup", fixture->workgroup);
   record_uint("shared_bytes", fixture->shared_bytes);
   if (fixture->dynamic)
      record_uint("metal_as3_index", fixture->shared_index);
   record_uint("parsed_lds_bytes", compiled.parsed_lds);
   record_uint("final_lds_bytes", compiled.config.lds_size);
   record_uint("raw_rsrc2", compiled.config.rsrc2);
   record_uint("pm4_rsrc2", pipeline.rsrc2);
   record_uint("encoded_lds_blocks", encoded);
   record_uint("lds_allocation_grain", ac_shader_get_lds_alloc_granularity(info.gfx_level));
   record_uint("nir_shared_loads", shared_loads);
   record_uint("nir_shared_stores", shared_stores);
   record_uint("nir_barriers", barriers);
   record_str("instruction_view", compiled.binary_disassembled ? "binary-disassembly" :
                                                                 "original-aco-hardware-ir");
   record_uint("instruction_shared_reads", compiled.shared_reads);
   record_uint("instruction_shared_writes", compiled.shared_writes);
   record_uint("instruction_barriers", compiled.barriers);
   record_uint("instruction_waits", compiled.waits);
   record_end();
   ralloc_free(shader);
}

int
main(int argc, char **argv)
{
   if (argc != 4) {
      fprintf(stderr, "usage: %s actual-shared.bc static-workgroup64.bc dynamic-workgroup64.bc\n", argv[0]);
      return 1;
   }
   /* The legacy receipt wrapper remains exercised by the existing raw probes. */
   (void)input_receipt;
#if STELA_AMD_TEST_LLVM
   ac_init_llvm_once();
#endif
   glsl_type_singleton_init_or_ref();
   struct fixture fixtures[] = {
      {.name = "original-static", .entry = "stela_threadgroup_static", .workgroup = 32,
       .shared_bytes = 128},
      {.name = "original-dynamic", .entry = "stela_threadgroup_dynamic", .workgroup = 32,
       .shared_bytes = 128, .dynamic = true, .shared_index = 3},
      {.name = "static-wg64", .entry = "kernel", .workgroup = 64, .shared_bytes = 256},
      {.name = "dynamic-wg64", .entry = "kernel", .workgroup = 64, .shared_bytes = 256,
       .dynamic = true, .shared_index = 7},
      /* Original no-shared AIR fixture. */
      {.name = "no-shared", .entry = "kernel", .workgroup = 32},
      {.name = "dynamic-grain", .entry = "kernel", .workgroup = 64, .dynamic = true,
       .shared_index = 7, .specialization = ALLOCATION_GRAIN},
      {.name = "dynamic-limit", .entry = "kernel", .workgroup = 64, .dynamic = true,
       .shared_index = 7, .specialization = TARGET_LIMIT},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(fixtures); i++) {
      struct fixture *fixture = &fixtures[i];
      fixture->input = i == 4 ? stela_air_test_bitcode(stela_air_test_store_body, "") :
         read_raw_input(argv[i < 2 ? 1 : i == 2 ? 2 : 3]);
      CHECK(fixture->input);
      const unsigned workgroup[3] = {fixture->workgroup, 1, 1};
      CHECK(input_receipt_options(fixture->input, fixture->entry, i != 4,
                                   fixture->hash, workgroup, 256));
      /* ACO compiles every family it supports; the retained LLVM backend
       * compiles the families ACO holds, at wave64. The first pass records
       * expectations. */
      for (unsigned pass = 0; pass < 2; pass++) {
         for (unsigned j = 0; j < ARRAY_SIZE(stela_amd_targets); j++) {
            const enum radeon_family family = stela_amd_targets[j];
            const bool llvm = stela_amd_aco_hold(family);
            const char *hold = llvm ? stela_amd_llvm_hold(family) : NULL;
            const unsigned min_wave = llvm ? 64 : stela_amd_min_wave(family);
            for (unsigned wave = 64; wave >= min_wave; wave /= 2) {
               char name[32], target[64];
               stela_amd_target_name(name, family, wave);
               snprintf(target, sizeof(target), "%s/%s", fixture->name, name);
               if (!pass)
                  record_expect(target, hold);
               else if (hold)
                  record_held(target, hold);
               else
                  compile_target(fixture, target, family, wave, llvm);
            }
         }
      }
      LLVMDisposeMemoryBuffer(fixture->input);
   }
   glsl_type_singleton_decref();
   return 0;
}
