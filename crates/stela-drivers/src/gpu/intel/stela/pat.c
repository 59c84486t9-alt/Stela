/* SPDX-License-Identifier: MIT */
#include "pat.h"
#include "../xe/xe_scalar_types.h"
#include "../xe/xe_gt_type.h"
#include "../xe/xe_force_wake_domain_types.h"
#include "../xe/regs/xe_reg_defs.h"
#include "pat_compile_defs.h"
#include <drm/intel/pick.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
struct diagnostics { bool warning, missing; };
#define XE_PAT_SELECT_WARN(context, condition) (((struct diagnostics *)(context))->warning |= !!(condition))
#define XE_PAT_SELECT_MISSING(context, version) ((void)(version), ((struct diagnostics *)(context))->missing = true)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#include "../xe/xe_pat_select.h"
#pragma clang diagnostic pop
struct program {
 const struct stela_intel_activation_io *io;
 void *context;
 struct stela_intel_pat_result *result;
};
static void write32(void *context, struct xe_reg reg, uint32_t value)
{
 struct program *program = context;
 program->io->write32(program->context, reg.addr, value);
 program->result->writes++;
}
#define XE_PAT_PROGRAM_WRITE(context, reg, value) write32(context, reg, value)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#include "../xe/xe_pat_program.h"
#pragma clang diagnostic pop
int stela_intel_pat_program(const struct stela_intel_activation_io *io, void *context,
 const struct stela_intel_activation_facts *facts, struct stela_intel_pat_result *out)
{
 if (!io || !io->write32 || !io->check_context || !facts || !out) return -22;
 if (!facts->platform || facts->platform > INT32_MAX) return -22;
 if (facts->gt_type != XE_GT_TYPE_MAIN || !facts->graphics_verx100 ||
     facts->discrete > 1 || facts->has_llc > 1 ||
     !(facts->initialized & XE_FW_GT) || !(facts->awake & XE_FW_GT)) return -95;
 int status = io->check_context(context);
 if (status) return status;
 struct xe_pat_selection selection = {0};
 struct diagnostics diagnostics = {0};
 if (!xe_pat_select(&selection, (enum xe_platform)facts->platform,
                    facts->graphics_verx100, facts->discrete != 0,
                    facts->has_llc != 0, &diagnostics)) return -95;
 /* Profile identity is actual original programmer policy, not table equality:
  * DG2 uses the same entries but requires its real multicast MCR operations. */
 if (selection.profile != XE_PAT_PROFILE_XELP || diagnostics.warning || diagnostics.missing ||
     selection.n_entries != 4 || selection.pat_ats || selection.pat_primary_pta ||
     selection.pat_media_pta) return -95;
 for (int i = 0; i < selection.n_entries; i++) {
  uint32_t offset = (uint32_t)_PAT_INDEX(i);
  if (offset % 4 || offset > SZ_4M - 4) return -34;
 }
 struct stela_intel_pat_result result = {
  .n_entries = (uint32_t)selection.n_entries,
  .cache_none = selection.idx[XE_CACHE_NONE], .cache_wt = selection.idx[XE_CACHE_WT],
  .cache_wb = selection.idx[XE_CACHE_WB],
  .cache_none_compression = selection.idx[XE_CACHE_NONE_COMPRESSION],
  .cache_wb_compression = selection.idx[XE_CACHE_WB_COMPRESSION],
 };
 for (int i = 0; i < selection.n_entries; i++) result.entries[i] = selection.table[i].value;
 struct program program = {io, context, &result};
 /* Whole original direct loop; no fallible operation/allocation after effects. */
 xe_pat_program_direct(&program, selection.table, selection.n_entries,
                       selection.pat_ats, selection.pat_primary_pta);
 *out = result;
 return 0;
}
