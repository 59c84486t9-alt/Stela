/* SPDX-License-Identifier: MIT */
#include "llvm_float.h"
#include "compiler/nir/nir.h"
#include "amd/common/ac_binary.h"
#include "amd/common/sid.h"

static bool
supported_controls(unsigned controls)
{
   return !controls || controls == (FLOAT_CONTROLS_DENORM_PRESERVE_FP32 |
                                    FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32) ||
          controls == (FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 |
                       FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32);
}

enum stela_amd_llvm_float_status
stela_amd_llvm_apply_float_controls(LLVMContextRef context, LLVMValueRef function,
                                    const struct nir_shader *shader)
{
   if (!context || !function || !shader || !LLVMIsAFunction(function) ||
       LLVMGetTypeContext(LLVMTypeOf(function)) != context)
      return STELA_AMD_LLVM_FLOAT_INVALID;
   unsigned major, minor, patch;
   LLVMGetVersion(&major, &minor, &patch);
   if (major != 23)
      return STELA_AMD_LLVM_FLOAT_UNSUPPORTED;
   const unsigned controls = shader->info.float_controls_execution_mode;
   if (!controls)
      return STELA_AMD_LLVM_FLOAT_OK;
   const unsigned ieee = FLOAT_CONTROLS_DENORM_PRESERVE_FP32 |
                         FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32;
   if (!supported_controls(controls))
      return STELA_AMD_LLVM_FLOAT_UNSUPPORTED;
   const LLVMDenormalModeKind fp32 = controls == ieee ? LLVMDenormalModeKindIEEE :
                                                     LLVMDenormalModeKindPreserveSign;
   /* Reuse the original backend's LLVM23 attribute mechanism. Keep its IEEE
    * FP16/64 environment; only the explicitly declared FP32 behavior changes.
    * LLVM replaces the existing attribute of this kind rather than appending
    * contradictory target-dependent strings. The original AMDGPU backend then
    * emits its actual .AMDGPU.config from this function environment.
    */
   LLVMAttributeRef attribute = LLVMCreateDenormalFPEnvAttribute(context,
      LLVMDenormalModeKindIEEE, LLVMDenormalModeKindIEEE, fp32, fp32);
   LLVMAddAttributeAtIndex(function, LLVMAttributeFunctionIndex, attribute);
   return STELA_AMD_LLVM_FLOAT_OK;
}

enum stela_amd_llvm_float_status
stela_amd_llvm_restore_float_controls(const struct nir_shader *shader,
                                      struct ac_shader_config *config)
{
   if (!shader || !config)
      return STELA_AMD_LLVM_FLOAT_INVALID;
   const unsigned controls = shader->info.float_controls_execution_mode;
   if (!supported_controls(controls))
      return STELA_AMD_LLVM_FLOAT_UNSUPPORTED;
   if (!controls)
      return STELA_AMD_LLVM_FLOAT_OK;
   const unsigned raw = G_00B848_FLOAT_MODE(config->rsrc1);
   const unsigned expected = V_00B028_FP_16_64_DENORMS |
      (controls & FLOAT_CONTROLS_DENORM_PRESERVE_FP32 ? V_00B028_FP_32_DENORMS : 0);
   if (raw != expected)
      return STELA_AMD_LLVM_FLOAT_CONFIG_MISMATCH;
   config->float_mode = raw;
   return STELA_AMD_LLVM_FLOAT_OK;
}
