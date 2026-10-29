/* SPDX-License-Identifier: MIT */
/* CPU-only LLVM attribute/config contract fixtures; no GPU initialization. */
#include "../hosted/llvm_float.h"
#include "amd/common/ac_binary.h"
#include "amd/common/sid.h"
#include "compiler/nir/nir.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
   LLVMContextRef context = LLVMContextCreate();
   LLVMModuleRef module = LLVMModuleCreateWithNameInContext("float-control-contract", context);
   LLVMTypeRef type = LLVMFunctionType(LLVMVoidTypeInContext(context), NULL, 0, false);
   LLVMValueRef function = LLVMAddFunction(module, "kernel", type);
   unsigned kind = LLVMGetEnumAttributeKindForName("denormal_fpenv", 14);
   assert(kind);
   LLVMAttributeRef ieee = LLVMCreateDenormalFPEnvAttribute(context,
      LLVMDenormalModeKindIEEE, LLVMDenormalModeKindIEEE,
      LLVMDenormalModeKindIEEE, LLVMDenormalModeKindIEEE);
   LLVMAttributeRef ftz = LLVMCreateDenormalFPEnvAttribute(context,
      LLVMDenormalModeKindIEEE, LLVMDenormalModeKindIEEE,
      LLVMDenormalModeKindPreserveSign, LLVMDenormalModeKindPreserveSign);
   nir_shader shader = {0};
   const unsigned preserve = FLOAT_CONTROLS_DENORM_PRESERVE_FP32 |
                              FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32;
   const unsigned flush = FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 |
                           FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32;
   for (unsigned controls = 0; controls < 4096; controls++) {
      LLVMAddAttributeAtIndex(function, LLVMAttributeFunctionIndex, ftz);
      shader.info.float_controls_execution_mode = controls;
      bool supported = !controls || controls == preserve || controls == flush;
      assert(stela_amd_llvm_apply_float_controls(context, function, &shader) ==
             (supported ? STELA_AMD_LLVM_FLOAT_OK : STELA_AMD_LLVM_FLOAT_UNSUPPORTED));
      assert(LLVMGetEnumAttributeAtIndex(function, LLVMAttributeFunctionIndex, kind) ==
             (controls == preserve ? ieee : ftz));
   }
   for (unsigned controls = 0; controls < 2; controls++) {
      shader.info.float_controls_execution_mode = controls ? preserve : flush;
      for (unsigned raw = 0; raw < 256; raw++) {
         struct ac_shader_config config = {.num_sgprs = 16, .float_mode = 0xa5,
            .rsrc1 = S_00B848_FLOAT_MODE(raw)};
         const struct ac_shader_config before = config;
         unsigned expected = V_00B028_FP_16_64_DENORMS |
                              (controls ? V_00B028_FP_32_DENORMS : 0);
         bool match = raw == expected;
         assert(stela_amd_llvm_restore_float_controls(&shader, &config) ==
                (match ? STELA_AMD_LLVM_FLOAT_OK : STELA_AMD_LLVM_FLOAT_CONFIG_MISMATCH));
         if (match) {
            struct ac_shader_config after = before;
            after.float_mode = raw;
            assert(!memcmp(&config, &after, sizeof(config)));
         } else {
            assert(!memcmp(&config, &before, sizeof(config)));
         }
      }
   }
   shader.info.float_controls_execution_mode = preserve;
   assert(stela_amd_llvm_apply_float_controls(NULL, function, &shader) == STELA_AMD_LLVM_FLOAT_INVALID);
   assert(stela_amd_llvm_apply_float_controls(context, NULL, &shader) == STELA_AMD_LLVM_FLOAT_INVALID);
   assert(stela_amd_llvm_apply_float_controls(context, function, NULL) == STELA_AMD_LLVM_FLOAT_INVALID);
   LLVMContextRef other = LLVMContextCreate();
   assert(stela_amd_llvm_apply_float_controls(other, function, &shader) == STELA_AMD_LLVM_FLOAT_INVALID);
   LLVMContextDispose(other);
   LLVMDisposeModule(module);
   LLVMContextDispose(context);
   puts("AMD LLVM float controls: 4096 attribute modes + 512 raw config cases passed; CPU fixtures only");
   return 0;
}
