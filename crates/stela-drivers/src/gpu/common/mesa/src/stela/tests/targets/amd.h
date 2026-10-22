/* SPDX-License-Identifier: MIT */
#ifndef STELA_TARGETS_AMD_H
#define STELA_TARGETS_AMD_H
/* AMD compile targets and holds for every Stela compiler probe: one family per
 * graphics generation Stela qualifies, then the compute-only CDNA families.
 * They are CPU compiler models, never devices. A probe of the upstream
 * compiler alone covers every family in Mesa's table from GFX6 instead.
 */
#include "amd/common/amd_family.h"
#include <stdbool.h>
#include <stdio.h>

static const enum radeon_family stela_amd_targets[] = {
   CHIP_TAHITI, CHIP_BONAIRE, CHIP_CARRIZO, CHIP_RAVEN, CHIP_NAVI10,
   CHIP_REMBRANDT, CHIP_NAVI31, CHIP_STRIX1, CHIP_GFX1170, CHIP_GFX1201,
   CHIP_GFX1210, CHIP_MI100, CHIP_MI200, CHIP_GFX940,
};

#define STELA_AMD_FIRST_FAMILY CHIP_TAHITI

/* Original ACO refuses compute-only CDNA and generations it does not know
 * (aco_is_gpu_supported); Stela compiles those families with the retained
 * LLVM backend instead.
 */
#define STELA_HOLD_AMD_ACO_CDNA "aco-excludes-cdna"
#define STELA_HOLD_AMD_ACO_GENERATION "aco-unsupported-generation"
/* A probe outcome for an ACO refusal this manifest does not list. */
#define STELA_HOLD_AMD_ACO_UNLISTED "aco-refusal-not-in-manifest"

static inline bool
stela_amd_has_graphics(enum radeon_family family)
{
   return family != CHIP_MI100 && family != CHIP_MI200 && family != CHIP_GFX940;
}

/* The ACO hold of a family, or NULL. */
static inline const char *
stela_amd_aco_hold(enum radeon_family family)
{
   if (!stela_amd_has_graphics(family))
      return STELA_HOLD_AMD_ACO_CDNA;
   return family == CHIP_GFX1210 ? STELA_HOLD_AMD_ACO_GENERATION : NULL;
}

/* The retained LLVM backend names no processor for GFX1210
 * (ac_get_llvm_processor_name).
 */
#define STELA_HOLD_AMD_LLVM_PROCESSOR "retained-llvm-processor-name-unavailable"

/* The LLVM hold of a family ACO holds, or NULL. */
static inline const char *
stela_amd_llvm_hold(enum radeon_family family)
{
   return family == CHIP_GFX1210 ? STELA_HOLD_AMD_LLVM_PROCESSOR : NULL;
}

/* Whether the retained LLVM backend compiles a family: one ACO holds. */
static inline bool
stela_amd_llvm_compiles(enum radeon_family family)
{
   return stela_amd_aco_hold(family) && !stela_amd_llvm_hold(family);
}

/* Every family runs wave64; wave32 starts at GFX10. Iterate with
 * for (wave = 64; wave >= stela_amd_min_wave(family); wave /= 2).
 */
static inline unsigned
stela_amd_min_wave(enum radeon_family family)
{
   return ac_get_gfx_level(family) >= GFX10 ? 32 : 64;
}

/* The outcome of a family ACO refused; compared with its expected hold. */
static inline const char *
stela_amd_aco_refusal(enum radeon_family family)
{
   const char *hold = stela_amd_aco_hold(family);
   return hold ? hold : STELA_HOLD_AMD_ACO_UNLISTED;
}

static inline void
stela_amd_target_name(char name[32], enum radeon_family family, unsigned wave)
{
   snprintf(name, 32, "%s.wave%u", ac_get_family_name(family), wave);
}

#endif
