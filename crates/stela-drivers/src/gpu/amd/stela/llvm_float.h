/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_LLVM_FLOAT_H
#define STELA_AMD_LLVM_FLOAT_H

#include <llvm-c/Core.h>

struct nir_shader;
struct ac_shader_config;
enum stela_amd_llvm_float_status {
   STELA_AMD_LLVM_FLOAT_OK,
   STELA_AMD_LLVM_FLOAT_INVALID,
   STELA_AMD_LLVM_FLOAT_UNSUPPORTED,
   STELA_AMD_LLVM_FLOAT_CONFIG_MISMATCH,
};

/* Bind actual shared-NIR FP32 controls to the original AMD LLVM function after
 * ac_build_main and before translation/optimization. The original builder must
 * use AC_FLOAT_MODE_DEFAULT, retaining signed zeros and avoiding nsz/arcp flags.
 * The caller retains that actual shader and matching LLVM function/context.
 * Mode zero leaves the retained backend's unspecified defaults unchanged.
 * Explicit FP32 RTE+IEEE or RTE+signed FTZ are supported; other width/rounding
 * contracts are refused before changing attributes. This neither fabricates
 * compiler resource registers nor qualifies floating-point hardware execution.
 */
enum stela_amd_llvm_float_status
stela_amd_llvm_apply_float_controls(LLVMContextRef context, LLVMValueRef function,
                                    const struct nir_shader *shader);

/* The original config parser retains raw rsrc1 but applies a historical
 * RadeonSI FTZ32 policy to config.float_mode. For an explicitly supported NIR
 * environment, validate every emitted raw float-mode bit (RTE and IEEE16/64,
 * plus declared IEEE/FTZ32), then retain that exact compiler field instead.
 * No flags are guessed, no other config field changes, and errors are atomic.
 * Mode zero leaves the original parser's unspecified policy unchanged.
 */
enum stela_amd_llvm_float_status
stela_amd_llvm_restore_float_controls(const struct nir_shader *shader,
                                      struct ac_shader_config *config);

#endif
