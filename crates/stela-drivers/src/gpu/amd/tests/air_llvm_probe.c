/* SPDX-License-Identifier: MIT */
/* Offline AIR -> shared NIR -> retained Mesa AMD LLVM compiler.
 * The shader ABI is explicit; no device initialization/execution is claimed.
 */
#include "air_to_nir.h"
#include "air_test_fixture.h"
#include "probe_report.h"
#include "amd/llvm/ac_llvm_build.h"
#include "amd/llvm/ac_nir_to_llvm.h"
#include "amd/llvm/ac_shader_abi.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_shader_args.h"
#include "amd/common/nir/ac_nir.h"
#include "amd/common/sid.h"
#include "../stela/llvm_float.h"
#include "util/mesa-blake3.h"
#include "util/ralloc.h"
#include <llvm-c/Analysis.h>
#include <llvm-c/Disassembler.h>
#include <llvm-c/Object.h>
#include "air_probe_input.h"

#define CHECK(condition) do { if (!(condition)) { \
   fprintf(stderr, "%s:%u: %s\n", __func__, __LINE__, #condition); exit(1); \
} } while (0)

struct binding {
   struct ac_shader_args args;
   struct ac_arg buffer;
   unsigned count;
   unsigned argument;
};

static nir_def *
bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
   struct binding *binding = data;
   CHECK(buffer->index == 7 && buffer->address_space == 1);
   CHECK(buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 &&
         buffer->type_alignment == 4);
   binding->count++;
   binding->argument = buffer->argument;
   return nir_pack_64_2x32(b, ac_nir_load_arg(b, &binding->args, binding->buffer));
}

static void
compute_args(struct binding *binding)
{
   /* An integer SGPR pair avoids ac_build_main's descriptor-pointer-specific
    * dereferenceable(UINT64_MAX) attributes on a bounded Metal buffer view. */
   ac_add_arg(&binding->args, AC_ARG_SGPR, 2, AC_ARG_VALUE, &binding->buffer);
   for (unsigned axis = 0; axis < 3; axis++)
      ac_add_arg(&binding->args, AC_ARG_SGPR, 1, AC_ARG_VALUE,
                 &binding->args.workgroup_ids[axis]);
   ac_add_arg(&binding->args, AC_ARG_SGPR, 1, AC_ARG_VALUE, &binding->args.scratch_offset);
   ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_x);
   ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_y);
   ac_add_arg(&binding->args, AC_ARG_VGPR, 1, AC_ARG_VALUE, &binding->args.local_invocation_id_z);
}

static bool
verify_module(LLVMModuleRef module)
{
   char *error = NULL;
   bool ok = !LLVMVerifyModule(module, LLVMReturnStatusAction, &error);
   if (!ok)
      fprintf(stderr, "LLVM module refused: %s\n", error ? error : "(no diagnostic)");
   LLVMDisposeMessage(error);
   return ok;
}

static void
hash_bytes(const void *data, size_t size, char text[BLAKE3_HEX_LEN])
{
   blake3_hash hash;
   _mesa_blake3_compute(data, size, hash);
   _mesa_blake3_format(text, hash);
}

static bool
inspect_binary(const char *elf, size_t size, const char *target,
                const char *processor, const char *input_hash, const char *entry,
                unsigned argument, const struct ac_compiler_info *info,
                const char *triple, const nir_shader *shader)
{
   /* Validate the emitted container independently of target-machine creation.
    * e_machine=224 is the ELF AMDGPU identifier, not an instruction encoding. */
   CHECK(size >= 64 && !memcmp(elf, "\177ELF\2\1\1", 7));
   const unsigned char *bytes = (const unsigned char *)elf;
   CHECK((bytes[18] | bytes[19] << 8) == 224);
   unsigned flags = bytes[48] | (unsigned)bytes[49] << 8 |
                    (unsigned)bytes[50] << 16 | (unsigned)bytes[51] << 24;
   LLVMMemoryBufferRef memory = LLVMCreateMemoryBufferWithMemoryRangeCopy(elf, size, "amd-llvm-elf");
   char *error = NULL;
   LLVMBinaryRef binary = LLVMCreateBinary(memory, NULL, &error);
   if (!binary) {
      fprintf(stderr, "emitted object refused: %s\n", error ? error : "(no diagnostic)");
      LLVMDisposeMessage(error);
      LLVMDisposeMemoryBuffer(memory);
      return false;
   }
   CHECK(LLVMBinaryGetType(binary) == LLVMBinaryTypeELF64L);
   LLVMSectionIteratorRef section = LLVMObjectFileCopySectionIterator(binary);
   size_t text_size = 0;
   bool config_found = false;
   struct ac_shader_config config = {0};
   char code_hash[BLAKE3_HEX_LEN] = {0}, elf_hash[BLAKE3_HEX_LEN];
   while (section && !LLVMObjectFileIsSectionIteratorAtEnd(binary, section)) {
      LLVMRelocationIteratorRef relocation = LLVMGetRelocations(section);
      CHECK(!relocation || LLVMIsRelocationIteratorAtEnd(section, relocation));
      if (relocation)
         LLVMDisposeRelocationIterator(relocation);
      const char *name = LLVMGetSectionName(section);
      if (name && !strcmp(name, ".text")) {
         CHECK(!text_size);
         text_size = LLVMGetSectionSize(section);
         CHECK(text_size && text_size <= size);
         const char *contents = LLVMGetSectionContents(section);
         CHECK(contents);
         hash_bytes(contents, text_size, code_hash);
         LLVMDisasmContextRef disasm =
            LLVMCreateDisasmCPU(triple, processor, NULL, 0, NULL, NULL);
         CHECK(disasm);
         size_t offset = 0;
         while (offset < text_size) {
            char instruction[512];
            size_t consumed = LLVMDisasmInstruction(
               disasm, (uint8_t *)contents + offset, text_size - offset, offset,
               instruction, sizeof(instruction));
            CHECK(consumed && consumed <= text_size - offset);
            printf("AMD LLVM %s +0x%zx: %s\n", target, offset, instruction);
            offset += consumed;
         }
         LLVMDisasmDispose(disasm);
      } else if (name && !strcmp(name, ".AMDGPU.config")) {
         const char *contents = LLVMGetSectionContents(section);
         uint64_t config_size = LLVMGetSectionSize(section);
         /* The original pure config parser consumes aligned register/value
          * word pairs. Validate those preconditions before passing the actual
          * emitted section; retain its generation-specific interpretation. */
         CHECK(!config_found && contents && config_size && config_size <= size &&
               config_size % 8 == 0 && (uintptr_t)contents % _Alignof(uint32_t) == 0);
         ac_parse_llvm_binary_config(contents, config_size, 64, info, &config);
         config_found = true;
      }
      LLVMMoveToNextSection(section);
   }
   CHECK(text_size && config_found && config.num_sgprs && config.num_vgprs);
   const unsigned parsed_float_mode = config.float_mode;
   CHECK(stela_amd_llvm_restore_float_controls(shader, &config) == STELA_AMD_LLVM_FLOAT_OK);
   if (section)
      LLVMDisposeSectionIterator(section);
   hash_bytes(elf, size, elf_hash);
   probe_compiled("air-amd-llvm", target, text_size);
   printf("STELA_AIR_BINARY {\"backend\":\"amd-llvm\",\"entry\":");
   json_string(entry);
   printf(",\"target\":\"%s\","
          "\"processor\":\"%s\",\"wave_size\":64,\"workgroup_size\":[32,1,1],"
          "\"input_blake3\":\"%s\",\"elf_bytes\":%zu,\"elf_blake3\":\"%s\","
          "\"code_bytes\":%zu,\"code_blake3\":\"%s\",\"elf_machine\":224,"
          "\"elf_flags\":%u,\"buffer_argument\":%u,\"metal_buffer_index\":7,"
          "\"buffer_abi\":\"device_va_integer_user_sgpr0_1\","
          "\"calling_convention\":\"amdgpu_cs\",\"llvm_ir_verified\":true,"
          "\"dispatch_config_finalized\":false,"
          "\"config_parser\":\"ac_parse_llvm_binary_config\",\"sgprs\":%u,\"vgprs\":%u,"
          "\"scratch_bytes_per_wave\":%u,\"spilled_sgprs\":%u,\"spilled_vgprs\":%u,"
          "\"rsrc1\":%u,\"rsrc2\":%u,\"rsrc3\":%u,\"float_mode\":%u,"
          "\"nir_float_controls\":%u,\"raw_float_mode\":%u,\"parsed_float_mode\":%u,"
          "\"float_controls_finalizer\":\"stela_amd_llvm_restore_float_controls\"}\n",
          target, processor, input_hash, size, elf_hash, text_size, code_hash, flags, argument,
          config.num_sgprs, config.num_vgprs, config.scratch_bytes_per_wave,
          config.spilled_sgprs, config.spilled_vgprs, config.rsrc1, config.rsrc2,
          config.rsrc3, config.float_mode, shader->info.float_controls_execution_mode,
          G_00B848_FLOAT_MODE(config.rsrc1), parsed_float_mode);
   LLVMDisposeBinary(binary);
   LLVMDisposeMemoryBuffer(memory);
   return true;
}

static bool
compile_target(LLVMMemoryBufferRef input, const char *entry, const char *input_hash,
                enum radeon_family family, bool file)
{
   char target[64];
   snprintf(target, sizeof(target), "%s.wave64", ac_get_family_name(family));
   const char *processor = ac_get_llvm_processor_name(family);
   if (!*processor) {
      probe_unsupported("air-amd-llvm", target, "retained-llvm-processor-name-unavailable");
      return true;
   }
   struct radeon_info gpu = {.gfx_level = ac_get_gfx_level(family), .family = family};
   ac_fill_compiler_info(&gpu, NULL, false);
   struct ac_llvm_compiler compiler;
   if (!ac_init_llvm_compiler(&compiler, family, AC_TM_CHECK_IR)) {
      fprintf(stderr, "%s: retained LLVM target initialization refused\n", target);
      return false;
   }
   char *actual_cpu = LLVMGetTargetMachineCPU(compiler.tm);
   CHECK(actual_cpu && !strcmp(actual_cpu, processor));
   LLVMDisposeMessage(actual_cpu);
   nir_shader_compiler_options nir_options;
   ac_nir_set_options(&gpu.compiler_info, true, &nir_options);
   struct binding binding = {0};
   compute_args(&binding);
   const struct stela_air_options air_options = {
      .workgroup_size = {32, 1, 1}, .max_instructions = 100,
      .bind_buffer = bind_buffer, .binding_data = &binding,
   };
   struct stela_air_error error;
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                        entry, &nir_options, &air_options, &error);
   if (!shader) {
      fprintf(stderr, "%s AIR refused: %u %s\n", target, error.kind, error.detail);
      ac_destroy_llvm_compiler(&compiler);
      return false;
   }
   CHECK(binding.count == 1 && error.kind == STELA_AIR_OK);
   unsigned loads = 0, stores = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (intrinsic->intrinsic == nir_intrinsic_load_global) {
               CHECK(!nir_src_is_const(intrinsic->src[0]));
               loads++;
            } else if (intrinsic->intrinsic == nir_intrinsic_store_global) {
               CHECK(!nir_src_is_const(intrinsic->src[1]));
               if (!file)
                  CHECK(!nir_src_is_const(intrinsic->src[0]));
               stores++;
            }
         }
      }
   }
   CHECK(file ? loads + stores > 0 : loads == 1 && stores == 1);
   printf("STELA_AIR_MEMORY {\"backend\":\"amd-llvm\",\"input_blake3\":\"%s\","
          "\"target\":\"%s\",\"global_loads\":%u,\"global_stores\":%u}\n",
          input_hash, target, loads, stores);
   const ac_nir_lower_intrinsics_to_args_options args_options = {
      .gfx_level = gpu.gfx_level, .hw_stage = AC_HW_COMPUTE_SHADER,
      .wave_size = 64, .workgroup_size = 32,
   };
   ac_nir_lower_intrinsics_to_args(shader, &binding.args, &args_options);
   ac_nir_lower_global_access(shader, gpu.gfx_level);
   nir_lower_int64(shader);
   bool progress;
   do {
      progress = nir_opt_constant_folding(shader);
      progress |= nir_opt_copy_prop(shader);
      progress |= nir_opt_algebraic(shader);
      progress |= nir_opt_dce(shader);
   } while (progress);
   nir_lower_alu_width(shader, ac_nir_opt_vectorize_cb, &gpu.gfx_level);
   nir_lower_load_const_to_scalar(shader);
   nir_opt_copy_prop(shader);
   nir_opt_dce(shader);
   nir_shader_gather_info(shader, nir_shader_get_entrypoint(shader));
   nir_validate_shader(shader, "AIR to AMD LLVM compute ABI");

   struct ac_llvm_context llvm = {0};
   ac_llvm_context_init(&llvm, &compiler, &gpu.compiler_info, AC_FLOAT_MODE_DEFAULT,
                        64, false, false);
   struct ac_shader_abi abi = {0}; /* Global64 fixture needs no descriptor callbacks. */
   struct ac_llvm_pointer main = ac_build_main(&binding.args, &llvm, AC_LLVM_AMDGPU_CS,
                                               "stela_compute", llvm.voidt, llvm.module);
   ac_llvm_set_workgroup_size(main.value, 32);
   ac_llvm_set_target_features(main.value, &llvm, false);
   enum stela_amd_llvm_float_status fp_status =
      stela_amd_llvm_apply_float_controls(llvm.context, main.value, shader);
   bool ok = fp_status == STELA_AMD_LLVM_FLOAT_OK &&
             ac_nir_translate(&llvm, &abi, &binding.args, shader);
   if (fp_status != STELA_AMD_LLVM_FLOAT_OK)
      fprintf(stderr, "%s NIR float controls refused: %u\n", target, fp_status);
   if (ok) {
      LLVMBuildRetVoid(llvm.builder);
      ok = verify_module(llvm.module) && ac_llvm_optimize_module(compiler.meo, llvm.module) &&
           verify_module(llvm.module);
   }
   char *elf = NULL;
   size_t elf_size = 0;
   if (ok) {
      compiler.beo = ac_create_backend_optimizer(compiler.tm);
      ok = ac_compile_module_to_elf(compiler.beo, llvm.module, &elf, &elf_size) &&
           inspect_binary(elf, elf_size, target, processor, input_hash, entry,
                           binding.argument, &gpu.compiler_info, LLVMGetTarget(llvm.module), shader);
   }
   free(elf);
   ralloc_free(shader);
   ac_llvm_context_dispose(&llvm);
   LLVMDisposeModule(llvm.module);
   LLVMContextDispose(llvm.context);
   ac_destroy_llvm_compiler(&compiler);
   return ok;
}

int
main(int argc, char **argv)
{
   const char *entry = "kernel";
   bool file = false;
   LLVMMemoryBufferRef input;
   if (argc == 1) {
      input = stela_air_test_bitcode(stela_air_test_store_body, "");
   } else if (argc == 5 && !strcmp(argv[1], "--input") && !strcmp(argv[3], "--entry") &&
              *argv[4] && strlen(argv[4]) <= 256) {
      input = read_raw_input(argv[2]);
      entry = argv[4];
      file = true;
      if (!input)
         return 1;
   } else {
      fprintf(stderr, "usage: %s [--input raw.bc --entry kernel_name]\n", argv[0]);
      return 1;
   }
   char input_hash[BLAKE3_HEX_LEN];
   if (!input_receipt(input, entry, file, input_hash)) {
      LLVMDisposeMemoryBuffer(input);
      return 1;
   }
   ac_init_llvm_once();
   glsl_type_singleton_init_or_ref();
   bool ok = true;
   const enum radeon_family targets[] = {CHIP_MI100, CHIP_MI200, CHIP_GFX940, CHIP_GFX1210};
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++)
      ok &= compile_target(input, entry, input_hash, targets[i], file);
   LLVMDisposeMemoryBuffer(input);
   glsl_type_singleton_decref();
   return !ok;
}
