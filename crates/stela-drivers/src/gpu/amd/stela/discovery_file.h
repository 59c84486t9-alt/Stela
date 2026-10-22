/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_DISCOVERY_FILE_H
#define STELA_AMD_DISCOVERY_FILE_H
#include <stddef.h>
#include <stdint.h>
/* Same status values as original shared bounded-file policy. Actual immutable
 * readable file allocation only; capacity is the real queried TMR extent.
 * No acquisition/admission/copy/allocator; no pointer retained or bytes changed. */
size_t stela_amd_discovery_file_minimum(void);
int stela_amd_discovery_file_validate(const uint8_t *data, size_t bytes, uint32_t capacity);
#endif
