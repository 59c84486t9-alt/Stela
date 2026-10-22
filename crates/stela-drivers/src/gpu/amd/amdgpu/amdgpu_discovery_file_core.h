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

#ifndef AMDGPU_DISCOVERY_FILE_CORE_H
#define AMDGPU_DISCOVERY_FILE_CORE_H
#include "../stela/discovery_binary.h"

enum amdgpu_discovery_file_status {
 AMDGPU_DISCOVERY_FILE_OK,
 AMDGPU_DISCOVERY_FILE_TOO_LARGE,
 AMDGPU_DISCOVERY_FILE_TOO_SMALL,
 AMDGPU_DISCOVERY_FILE_INVALID,
};
/* Actual preferred-file span before copy into the zeroed TMR-sized allocation.
 * The original caller keeps request/log/copy/release and outer source policy.
 * Readable immutable actual file bytes are required. No pointer retained. */
static inline enum amdgpu_discovery_file_status
amdgpu_discovery_file_validate(const uint8_t *data, size_t bytes, uint32_t capacity)
{
 if (bytes > capacity)
  return AMDGPU_DISCOVERY_FILE_TOO_LARGE;
 /* Ensure the firmware is at least large enough to contain the
  * binary header fields.
  */
 if (bytes < offsetof(struct binary_header, binary_size) +
             sizeof(((struct binary_header *)0)->binary_size))
  return AMDGPU_DISCOVERY_FILE_TOO_SMALL;
 /* A short file must not borrow zero-filled TMR padding as firmware data. */
 if (amdgpu_discovery_binary_validate(data, bytes) != AMDGPU_DISCOVERY_BINARY_OK)
  return AMDGPU_DISCOVERY_FILE_INVALID;
 return AMDGPU_DISCOVERY_FILE_OK;
}
#endif
