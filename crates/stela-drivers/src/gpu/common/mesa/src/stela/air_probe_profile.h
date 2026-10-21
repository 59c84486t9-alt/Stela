/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_PROBE_PROFILE_H
#define STELA_AIR_PROBE_PROFILE_H

#include "air_to_nir.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Offline probe option, never inferred from a shader's self-reported metadata.
 * The production input owner supplies the independently qualified provenance.
 * Keep this trailing option separate from each probe's bounded raw-file reader.
 */
static inline const char *
stela_air_probe_profile_name(enum stela_air_fp_profile profile)
{
   switch (profile) {
   case STELA_AIR_FP_IEEE_DEFAULT:
      return "ieee";
   case STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41:
      return "apple-32023.922-air2.9-msl4.1";
   default:
      return NULL;
   }
}

static inline bool
stela_air_probe_profile(int *argc, char **argv, enum stela_air_fp_profile *profile)
{
   *profile = STELA_AIR_FP_IEEE_DEFAULT;
   if (*argc >= 3 && !strcmp(argv[*argc - 2], "--fp-profile")) {
      /* Require a real input, rather than applying a compiler profile to the
       * built-in LLVM fixture. The input reader checks the remaining arguments.
       */
      if (*argc <= 3)
         return false;
      const char *name = argv[*argc - 1];
      if (!strcmp(name, "ieee"))
         *profile = STELA_AIR_FP_IEEE_DEFAULT;
      else if (!strcmp(name, "apple-32023.922-air2.9-msl4.1"))
         *profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
      else
         return false;
      *argc -= 2;
   }
   return true;
}

static inline void
stela_air_probe_profile_receipt(enum stela_air_fp_profile profile)
{
   printf("STELA_AIR_PROFILE {\"name\":\"%s\",\"kind\":%u}\n",
          stela_air_probe_profile_name(profile), (unsigned)profile);
}

#endif
