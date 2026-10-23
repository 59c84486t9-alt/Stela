/* SPDX-License-Identifier: MIT */
#ifndef STELA_TARGETS_INTEL_H
#define STELA_TARGETS_INTEL_H
/* Intel compile targets and holds for every Stela compiler probe: every
 * platform Mesa's device table names, from Gen7. As in Mesa, ELK compiles
 * through Gen8 and BRW from Gen9. They are CPU compiler models, never devices.
 */
#include "intel/dev/intel_device_info.h"
#include <stdio.h>
#include <stdlib.h>

#define STELA_INTEL_FIRST_VER 7

/* Gen35 compilation and dispatch are not qualified; the hosted producers
 * refuse it before compiling (hosted/air_compile.c, compute.c, air_graphics.c).
 */
#define STELA_HOLD_INTEL_GEN35 "intel-gen35-dispatch-qualification"
/* Refusals by design, which pass. FP32 denorm preservation starts at Gen8
 * (hosted/fp_controls.h).
 */
#define STELA_REFUSAL_INTEL_GEN7_FP32_PRESERVE "fp32-preserve-requires-gen8"
/* Gen7.0 ELK lowers byte or misaligned shared access to byte-scattered
 * messages, which the owned compiler refuses.
 */
#define STELA_REFUSAL_INTEL_GEN7_BYTE_SHARED "gen7-byte-scattered-shared"

/* The platform hold every Intel probe applies, or NULL. */
static inline const char *
stela_intel_hold(const struct intel_device_info *device)
{
   return device->ver == 35 ? STELA_HOLD_INTEL_GEN35 : NULL;
}

static inline bool
stela_intel_elk(const struct intel_device_info *device)
{
   return device->ver < 9;
}

/* Name and device of Mesa's next named platform from Gen7, or NULL. */
static inline const char *
stela_intel_next_target(unsigned *cursor, struct intel_device_info *device)
{
   for (const char *name; (name = intel_platform_name_by_index((*cursor)++));) {
      const int pci = intel_device_name_to_pci_device_id(name);
      if (pci < 0 || !intel_get_device_info_for_build(pci, device)) {
         fprintf(stderr, "Mesa names platform %s without device info\n", name);
         exit(1);
      }
      if (device->ver >= STELA_INTEL_FIRST_VER)
         return name;
   }
   return NULL;
}

#define STELA_INTEL_FOREACH_TARGET(name, device)                            \
   for (unsigned stela_cursor_ = 0;                                         \
        ((name) = stela_intel_next_target(&stela_cursor_, &(device)));)

#endif
