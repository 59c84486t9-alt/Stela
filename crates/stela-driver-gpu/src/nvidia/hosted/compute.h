/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_COMPUTE_H
#define STELA_NVIDIA_COMPUTE_H

#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"

/* Descriptor/packet encoding only. The native GPU driver must create and bind
 * the real compute channel/context, map/upload executable code and QMD/constant
 * buffers, establish residency/coherence/cache ordering, configure shared/local
 * windows, submit on the correct queue and report completion/faults. These
 * packets are not a complete initialization or submission stream.
 */
enum stela_nvidia_compute_error {
   STELA_NVIDIA_COMPUTE_OK,
   STELA_NVIDIA_COMPUTE_INPUT,
   STELA_NVIDIA_COMPUTE_DEVICE,
   STELA_NVIDIA_COMPUTE_SHADER,
   STELA_NVIDIA_COMPUTE_GEOMETRY,
   STELA_NVIDIA_COMPUTE_SHARED_MEMORY,
   STELA_NVIDIA_COMPUTE_SCRATCH_UNSUPPORTED,
   STELA_NVIDIA_COMPUTE_ADDRESS,
   STELA_NVIDIA_COMPUTE_CONSTANT_BUFFER,
};

struct stela_nvidia_compute_dispatch {
   /* Real executable GPU VA, total shared memory, group counts and cbufs.
    * cbuf indices/layout must match the compiler/frontend binding ABI. */
   struct nak_qmd_info qmd;
   uint64_t qmd_addr; /* GPU upload VA, aligned to NAK_QMD_ALIGN_B. */
   unsigned va_bits; /* Actual usable unsigned GPU VM width from the backend. */
};

#define STELA_NVIDIA_COMPUTE_MAX_PUSH_DW 4
struct stela_nvidia_compute_encoded {
   uint32_t qmd[NAK_MAX_QMD_DWORDS];
   uint32_t qmd_size_B;
   uint32_t push[STELA_NVIDIA_COMPUTE_MAX_PUSH_DW];
   uint32_t push_dw;
};

/* Uses original NAK QMD encoding and generated NVK/NVIDIA command helpers.
 * Device geometry/capabilities must come from the physical driver. No synthetic
 * device identity or allocation is created here. Rejects unbacked shader scratch
 * and unsupported targets before calling the original assert-bearing encoder.
 * All outputs remain unchanged on failure; error may be NULL.
 */
bool stela_nvidia_compute_encode(const struct nv_device_info *dev,
                             const struct nak_shader_bin *shader,
                             const struct stela_nvidia_compute_dispatch *dispatch,
                             struct stela_nvidia_compute_encoded *encoded,
                             enum stela_nvidia_compute_error *error);
#endif
