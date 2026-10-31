/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_TEST_NAK_H
#define STELA_AIR_TEST_NAK_H
/* Compiles frontend fixtures with the NVIDIA backend, for every target. */
#include "compiler/nir/nir.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include "targets/nvidia.h"
#include <assert.h>

/* A fixture's shader, translated with a backend's NIR options. */
typedef nir_shader *(*stela_air_test_translate)(const nir_shader_compiler_options *options,
                                                void *fixture);

static inline void
stela_air_test_nak(stela_air_test_translate translate, void *fixture)
{
   for (unsigned i = 0; i < ARRAY_SIZE(stela_nvidia_sms); i++) {
      const struct nv_device_info device = {.sm = stela_nvidia_sms[i], .max_warps_per_mp = 32};
      struct nak_compiler *compiler = nak_compiler_create(&device);
      assert(compiler);
      nir_shader *shader = translate(nak_nir_options(compiler), fixture);
      assert(shader);
      nak_preprocess_nir(shader, compiler);
      struct nak_shader_bin *bin = nak_compile_shader(shader, false, compiler, 0, NULL, false);
      assert(bin && bin->code_size && bin->info.sm == stela_nvidia_sms[i]);
      nak_shader_bin_destroy(bin);
      ralloc_free(shader);
      nak_compiler_destroy(compiler);
   }
}
#endif
