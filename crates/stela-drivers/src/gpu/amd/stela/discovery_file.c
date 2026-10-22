/* SPDX-License-Identifier: MIT */
#include "discovery_file.h"
#include "../amdgpu/amdgpu_discovery_file_core.h"
int stela_amd_discovery_file_validate(const uint8_t *data, size_t bytes, uint32_t capacity)
{
 return amdgpu_discovery_file_validate(data, bytes, capacity);
}
size_t stela_amd_discovery_file_minimum(void)
{
 return offsetof(struct binary_header, binary_size) +
        sizeof(((struct binary_header *)0)->binary_size);
}
