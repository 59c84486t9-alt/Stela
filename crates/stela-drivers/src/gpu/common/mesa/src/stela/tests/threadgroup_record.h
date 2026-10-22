/* SPDX-License-Identifier: MIT */
#ifndef STELA_THREADGROUP_RECORD_H
#define STELA_THREADGROUP_RECORD_H
/* Threadgroup facts of an owned compile result, in an open record. */
#include "../../../../../metal/compiler/threadgroup.h"
#include "probe_report.h"

/* An owned compiler refuses dynamic threadgroup lengths without a dispatch
 * specialization request.
 */
#define STELA_REFUSAL_DYNAMIC_THREADGROUP "dynamic-threadgroup-specialization-unavailable"

/* The backend's total shared bytes, then each specialized row as
 * "argument:index:bytes:alignment" in AIR metadata order.
 */
static inline void
record_threadgroup(const struct stela_metal_threadgroup_specialization *threadgroup,
                   unsigned total_shared)
{
   record_uint("total_shared", total_shared);
   record_array("threadgroup_rows");
   for (unsigned r = 0; r < threadgroup->count; r++) {
      const struct stela_metal_threadgroup_binding *row = &threadgroup->bindings[r];
      char text[64];
      snprintf(text, sizeof(text), "%u:%u:%llu:%u", row->buffer.argument, row->buffer.index,
               (unsigned long long)row->bytes, row->alignment);
      record_item(text);
   }
   record_close();
}

#endif
