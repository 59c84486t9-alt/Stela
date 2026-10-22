/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_PAGE_GEOMETRY_H
#define STELA_NVIDIA_PAGE_GEOMETRY_H
#include "os-interface.h"

/* Private publisher of the Rust actual-PageSource owner. Original RM data
 * symbols remain unavailable/zero until that owner queries and binds genuine
 * native geometry before all C callers. Never call this instead of install().
 * Initial publication excludes every original reader; values never change.
 * All validation precedes writes; repeats match exactly or preserve old facts.
 */
/* Current native producer admits base-only profiles; broader valid geometry
 * returns NV_ERR_NOT_SUPPORTED without changing any original data symbol. */
NV_STATUS stela_nvidia_set_page_geometry(NvU64, NvU64, NvU64, NvU8);
_Static_assert(sizeof(os_page_size) == 8 && sizeof(os_max_page_size) == 8 &&
               sizeof(os_page_mask) == 8 && sizeof(os_page_shift) == 1,
               "original native RM page globals ABI");
#endif
