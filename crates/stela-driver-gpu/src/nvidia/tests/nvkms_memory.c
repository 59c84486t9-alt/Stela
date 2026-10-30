/* SPDX-License-Identifier: MIT */
/* Separate CPU process. Keep the original private prefix/realloc algorithm,
 * observing only its sized free call. The production backend is a separately
 * compiled real stela_nvkms_memory.c; only its common-heap/zero callees are
 * renamed to the bounded observation/denial seams below. These definitions
 * never enter a production archive. The existing lut_heap.rs supplies the
 * actual shared Heap and metadata adapter, with no alternate heap algorithm.
 */
#include "nvidia-modeset-os-interface.h"
void stela_nvkms_observed_free(void *pointer, size_t size);
#define nvkms_free stela_nvkms_observed_free
#include "nvkms-utils.c"
#undef nvkms_free
#include "stela_memory.h"

void stela_nvkms_test_heap_initialize(void);
size_t stela_nvkms_test_heap_live(void);
NvU32 stela_nvkms_model_alloc(NvU64 bytes, void **out);
void stela_nvkms_model_free(void *pointer);
void *stela_nvkms_model_zero(void *pointer, NvU8 value, size_t bytes);

/* Two simultaneously live allocations cover the original realloc transition.
 * This is fixture ownership accounting, never a production allocation registry.
 */
static struct {
    void *pointer;
    NvU64 bytes;
} live[2];
static NvU32 deny_status;
static NvU64 last_request;
static unsigned int allocation_calls, free_calls, zero_calls;
static unsigned int sized_frees, null_frees, errors;

static int live_index(void *pointer)
{
    unsigned int i;
    for (i = 0; i < 2; i++) {
        if (live[i].pointer == pointer)
            return (int)i;
    }
    return -1;
}

NvU32 stela_nvkms_model_alloc(NvU64 bytes, void **out)
{
    NvU32 status;
    unsigned int i;
    allocation_calls++;
    last_request = bytes;
    *out = NULL;
    if (deny_status != 0)
        return deny_status;
    status = stela_nvidia_alloc(bytes, out);
    if (status != STELA_NVIDIA_ALLOC_SUCCESS)
        return status;
    for (i = 0; i < 2; i++) {
        if (live[i].pointer == NULL) {
            live[i].pointer = *out;
            live[i].bytes = bytes;
            return status;
        }
    }
    errors++;
    stela_nvidia_free(*out);
    *out = NULL;
    return STELA_NVIDIA_ALLOC_OUT_OF_MEMORY;
}

void stela_nvkms_model_free(void *pointer)
{
    int i;
    if (pointer == NULL) {
        null_frees++;
        stela_nvidia_free(NULL);
        return;
    }
    i = live_index(pointer);
    if (i < 0) {
        errors++;
        return;
    }
    live[i].pointer = NULL;
    live[i].bytes = 0;
    free_calls++;
    stela_nvidia_free(pointer);
}

void *stela_nvkms_model_zero(void *pointer, NvU8 value, size_t bytes)
{
    int i = live_index(pointer);
    if (i < 0 || value != 0 || live[i].bytes != bytes) {
        errors++;
        return pointer;
    }
    zero_calls++;
    return nvkms_memset(pointer, value, bytes);
}

void stela_nvkms_observed_free(void *pointer, size_t size)
{
    int i = live_index(pointer);
    if (i < 0 || live[i].bytes != size)
        errors++;
    sized_frees++;
    nvkms_free(pointer, size);
}

static NvU8 pattern(size_t index)
{
    return (NvU8)(0x63 ^ (index * 13));
}

static int bytes_match(const NvU8 *pointer, size_t bytes)
{
    size_t i;
    for (i = 0; i < bytes; i++) {
        if (pointer[i] != pattern(i))
            return 0;
    }
    return 1;
}

int main(void)
{
    const size_t sizes[] = {0, 1, 15, 16, 17, 4096, 4097, 65537};
    const NvBool zero_flags[] = {0, 1, 2, 255};
    const NvU32 statuses[] = {
        STELA_NVIDIA_ALLOC_INVALID_SIZE, STELA_NVIDIA_ALLOC_OUT_OF_MEMORY,
    };
    unsigned int i, j, before_alloc, before_free, before_zero;
    size_t k, before_live;
    NvU8 *p, *q;

    stela_nvkms_test_heap_initialize();
    if (stela_nvkms_test_heap_live() != 0)
        return 1;
    for (i = 0; i < sizeof(zero_flags) / sizeof(zero_flags[0]); i++) {
        for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
            before_zero = zero_calls;
            p = nvkms_alloc(sizes[j], zero_flags[i]);
            if (p == NULL || ((NvUPtr)p & 15) != 0 ||
                zero_calls != before_zero + (zero_flags[i] != 0) ||
                last_request != sizes[j])
                return 2;
            for (k = 0; k < sizes[j]; k++) {
                if (zero_flags[i] != 0 && p[k] != 0)
                    return 3;
                p[k] = pattern(k);
            }
            if (!bytes_match(p, sizes[j]))
                return 4;
            nvkms_free(p, sizes[j]);
        }
    }
    for (i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
        deny_status = statuses[i];
        for (j = 0; j < sizeof(zero_flags) / sizeof(zero_flags[0]); j++) {
            before_zero = zero_calls;
            before_free = free_calls;
            before_alloc = allocation_calls;
            p = nvkms_alloc(((NvU64)1 << 32) + 17, zero_flags[j]);
            if (p != NULL || last_request != ((NvU64)1 << 32) + 17 ||
                zero_calls != before_zero || free_calls != before_free ||
                allocation_calls != before_alloc + 1)
                return 5;
        }
    }
    deny_status = 0;
    before_zero = zero_calls;
    p = nvInternalAlloc(63, TRUE);
    if (p == NULL || sizeof(nvkms_memory_info_t) != 8 ||
        offsetof(nvkms_memory_info_t, data) != 8 ||
        ((NvUPtr)p & 15) != 8 || last_request != 71 ||
        zero_calls != before_zero + 1)
        return 6;
    for (k = 0; k < 63; k++) {
        if (p[k] != 0)
            return 7;
        p[k] = pattern(k);
    }
    before_live = stela_nvkms_test_heap_live();
    before_free = free_calls;
    before_zero = zero_calls;
    deny_status = STELA_NVIDIA_ALLOC_OUT_OF_MEMORY;
    q = nvInternalRealloc(p, 101);
    if (q != NULL || !bytes_match(p, 63) || free_calls != before_free ||
        zero_calls != before_zero || last_request != 109 ||
        stela_nvkms_test_heap_live() != before_live)
        return 8;
    deny_status = 0;
    before_alloc = allocation_calls;
    q = nvInternalRealloc(p, ~(size_t)0);
    if (q != NULL || allocation_calls != before_alloc ||
        free_calls != before_free || !bytes_match(p, 63))
        return 9;
    q = nvInternalRealloc(p, ((NvU64)1 << 63) - 1);
    if (q != NULL || free_calls != before_free || !bytes_match(p, 63) ||
        stela_nvkms_test_heap_live() != before_live)
        return 10;
    q = nvInternalRealloc(p, 101);
    if (q == NULL || !bytes_match(q, 63) || free_calls != before_free + 1 ||
        zero_calls != before_zero)
        return 11;
    for (k = 63; k < 101; k++)
        q[k] = pattern(k);
    p = nvInternalRealloc(q, 17);
    if (p == NULL || !bytes_match(p, 17) || free_calls != before_free + 2)
        return 12;
    q = nvInternalRealloc(p, 0);
    if (q != NULL || free_calls != before_free + 3)
        return 13;
    p = nvInternalRealloc(NULL, 0);
    if (p == NULL || last_request != 8)
        return 14;
    nvInternalFree(p);
    nvInternalFree(NULL);
    nvkms_free(NULL, ~(size_t)0);
    if (errors != 0 || live[0].pointer != NULL || live[1].pointer != NULL ||
        null_frees != 1 || sized_frees != 4 ||
        stela_nvkms_test_heap_live() != 0)
        return 15;
    return 0;
}
