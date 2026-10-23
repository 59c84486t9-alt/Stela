/* SPDX-License-Identifier: MIT */
/* Separate CPU-only process: link the actual production stela_nvlink_memory.c
 * against this bounded denial provider, never into the driver. Real-success
 * heap ownership is exercised by the Rust tests through the actual C hooks.
 */
#include <stddef.h>
#include "nvlink_os.h"
#include "memory.h"

static NvU64 observed_size;
static NvU32 allocations;
static NvU32 frees;
static NvU32 denied_status;
static void *observed_free;

NvU32 stela_nvidia_alloc(NvU64 size, void **out)
{
    allocations++;
    observed_size = size;
    *out = NULL;
    return denied_status;
}

void stela_nvidia_free(void *pointer)
{
    frees++;
    observed_free = pointer;
}

int main(void)
{
    const NvU64 sizes[] = {0, 1, 4096, ((NvU64)1 << 32) + 17, ~(NvU64)0};
    const NvU32 statuses[] = {
        STELA_NVIDIA_ALLOC_INVALID_SIZE,
        STELA_NVIDIA_ALLOC_OUT_OF_MEMORY,
    };
    NvU32 i, j;
    for (i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
        denied_status = statuses[i];
        for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
            NvU32 before = allocations;
            if (nvlink_malloc(sizes[j]) != NULL ||
                allocations != before + 1 || observed_size != sizes[j] ||
                frees != 0)
                return 1;
        }
    }
    nvlink_free(NULL);
    if (frees != 1 || observed_free != NULL || allocations != 10)
        return 2;
    return 0;
}
