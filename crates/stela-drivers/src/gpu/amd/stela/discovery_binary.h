/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef STELA_AMD_DISCOVERY_BINARY_H
#define STELA_AMD_DISCOVERY_BINARY_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/stddef.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif
#include "../include/discovery.h"

enum amdgpu_discovery_binary_status {
   AMDGPU_DISCOVERY_BINARY_OK,
   AMDGPU_DISCOVERY_BINARY_INVALID,
   AMDGPU_DISCOVERY_BINARY_BOUNDS,
   AMDGPU_DISCOVERY_BINARY_VERSION,
   AMDGPU_DISCOVERY_BINARY_CHECKSUM,
};

/* Original additive checksum algorithm. Every byte must be readable; size is
 * bounded by INT_MAX. The full validator establishes its own stronger u16 span.
 */
uint16_t amdgpu_discovery_calculate_checksum(const uint8_t *data, uint32_t size);

/* Directory geometry from the original fixed/v2-counted header. A bounded
 * prefix is sufficient; available_bytes is the actual acquired region size.
 * This neither reads an entry nor validates a table/checksum. Failure leaves
 * the output unchanged. Live acquisition must retain its real reset owner. */
struct amdgpu_discovery_directory {
   size_t binary_bytes, directory_bytes, entry_offset;
};
enum amdgpu_discovery_binary_status
amdgpu_discovery_binary_directory(const uint8_t *prefix, size_t prefix_bytes,
                                  size_t available_bytes, uint16_t id,
                                  struct amdgpu_discovery_directory *output);

/* Checked original directory selection only, not full binary validation.
 * The returned original format pointer borrows the actual snapshot's lifetime;
 * NULL means malformed directory, missing table or unsupported binary version.
 */
const struct table_info *
amdgpu_discovery_binary_table(const uint8_t *binary, size_t bytes, uint16_t id);

/* Validate a real readable immutable acquisition snapshot before original
 * driver consumers run. No allocation, register/memory acquisition, device
 * mutation, capability inference or hardware activation occurs here.
 *
 * Caller owns the actual TMR/firmware snapshot and excludes concurrent mutation
 * throughout validation and handoff. Original reg-base initialization then
 * intentionally mutates its private copy (endian/address conversion and VCN
 * revision masking); the preflight does not authorize revalidation of that
 * modified copy or concurrent untrusted access. Actual firmware/TMR ownership,
 * device binding, VRAM/ACPI acquisition and original consumer lifecycle remain
 * required. Optional NPS integrity policy remains lazy in the original caller.
 */
enum amdgpu_discovery_binary_status
amdgpu_discovery_binary_validate(const uint8_t *binary, size_t bytes);

#endif
