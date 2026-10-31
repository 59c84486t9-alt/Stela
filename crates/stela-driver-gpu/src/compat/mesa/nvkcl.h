/* SPDX-License-Identifier: MIT */
/* NVK's two internal compute kernels. Mesa compiles them from OpenCL C with
 * LLVM at build time into `nvkcl.h`; `nvkcl.c` builds the same programs in NIR
 * so the boot image needs neither (`src/nouveau/vulkan/cl/`). */
#ifndef STELA_MESA_NVKCL_H
#define STELA_MESA_NVKCL_H
#include "nir.h"

void nvk_copy_queries(nir_builder *b, nir_def *pool_addr, nir_def *available_stride,
		      nir_def *reports_start, nir_def *report_count, nir_def *query_stride,
		      nir_def *first_query, nir_def *query_count, nir_def *dst_addr,
		      nir_def *dst_stride, nir_def *flags);
void nvk_copy_indirect(nir_builder *b, nir_def *in, nir_def *in_stride, nir_def *out,
		       nir_def *count);
#endif
