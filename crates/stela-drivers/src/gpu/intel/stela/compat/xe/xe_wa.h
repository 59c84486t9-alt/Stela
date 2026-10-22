/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_WA_H
#define STELA_XE_WA_H
#include <generated/xe_wa_oob.h>
#include "xe_assert.h"
/* Out-of-band workaround queries are services of the adapter's GT, which
 * answers them from the generated rule identifiers.
 */
static bool stela_xe_gt_wa(const struct xe_gt *gt, unsigned int id);
#define XE_GT_WA(gt__, id__) stela_xe_gt_wa(gt__, XE_WA_OOB_ ## id__)
#endif
