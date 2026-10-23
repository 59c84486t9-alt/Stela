/* SPDX-License-Identifier: MIT */
/* Separate CPU-only fixture. Include the unchanged original allocation unit
 * so its private prefix is real, never a reconstructed vendor record. Link
 * unchanged nvkms-lut.c for the actual upload loop, with dead-code removal.
 * The two metadata hook definitions below exist only in this test process.
 */
#include "nvkms-utils.c"
#include "nvkms-lut.h"
#include "memory.h"

void stela_nvkms_test_heap_initialize(void);
size_t stela_nvkms_test_heap_live(void);

static void *allocation;
static size_t allocation_bytes;
static unsigned int allocated, freed, invalid_free;

void *nvkms_alloc(size_t size, NvBool zero)
{
    void *p = NULL;
    if (stela_nvidia_alloc(size, &p) != STELA_NVIDIA_ALLOC_SUCCESS)
        return NULL;
    allocation = p;
    allocation_bytes = size;
    allocated++;
    if (zero)
        nvkms_memset(p, 0, size);
    return p;
}

void nvkms_free(void *p, size_t size)
{
    if (p != allocation || size != allocation_bytes)
        invalid_free++;
    stela_nvidia_free(p);
    freed++;
}

static NvU16 value_at(unsigned int output, size_t entry, size_t channel)
{
    return (NvU16)((output ? 0x9000 : 0x1000) +
                  entry * (channel * 2 + 3) + channel * 0x111);
}

/* An independent byte-coordinate expectation, including both rounded slots.
 * This does not replay the original dword upload algorithm or use a round trip.
 */
static NvU8 expected_at(size_t byte)
{
    const size_t array_bytes = 8232;
    const unsigned int output = byte >= 8448;
    const size_t local = output ? byte - 8448 : byte;
    NvU16 value;
    if (local >= array_bytes)
        return 0;
    value = value_at(output, local / 8, (local % 8) / 2);
    return (NvU8)(value >> ((local % 2) * 8));
}

int main(void)
{
    static _Alignas(16) NvU8 destination[16896 + 32];
    NVSurfaceEvoRec surface = {0};
    NVDispEvoRec display = {0};
    NVEvoLutDataRec *p;
    size_t i;
    const size_t entries = NV_LUT_VSS_HEADER_SIZE + NV_NUM_EVO_LUT_ENTRIES;

    stela_nvkms_test_heap_initialize();
    if (stela_nvkms_test_heap_live() != 0)
        return 1;
    p = nvInternalAlloc(sizeof(*p), TRUE);
    if (p == NULL || sizeof(nvkms_memory_info_t) != 8 ||
        offsetof(nvkms_memory_info_t, data) != 8 ||
        (NvU8 *)p - (NvU8 *)allocation != 8 ||
        allocation_bytes != sizeof(*p) + 8 ||
        ((NvUPtr)p & 15) != 8 || ((NvUPtr)p & 255) == 0 ||
        ((NvUPtr)p & 3) != 0)
        return 2;
    for (i = 0; i < sizeof(*p); i++) {
        if (((const NvU8 *)p)[i] != 0)
            return 3;
    }
    for (i = 0; i < entries; i++) {
        p->base[i].Red = value_at(0, i, 0);
        p->base[i].Green = value_at(0, i, 1);
        p->base[i].Blue = value_at(0, i, 2);
        p->base[i].Unused = value_at(0, i, 3);
        p->output[i].Red = value_at(1, i, 0);
        p->output[i].Green = value_at(1, i, 1);
        p->output[i].Blue = value_at(1, i, 2);
        p->output[i].Unused = value_at(1, i, 3);
    }
    nvkms_memset(destination, 0xa5, sizeof(destination));
    surface.cpuAddress[0] = destination + 16;
    surface.planes[0].rmObjectSizeInBytes = sizeof(*p);
    display.displayOwner = 0;
    nvUploadDataToLutSurfaceEvo(&surface, p, &display);
    for (i = 0; i < sizeof(*p); i++) {
        if (((const NvU8 *)p)[i] != expected_at(i) ||
            destination[16 + i] != expected_at(i))
            return 4;
    }
    for (i = 0; i < 16; i++) {
        if (destination[i] != 0xa5 || destination[16 + sizeof(*p) + i] != 0xa5)
            return 5;
    }
    nvInternalFree(p);
    if (allocated != 1 || freed != 1 || invalid_free != 0 ||
        stela_nvkms_test_heap_live() != 0)
        return 6;
    return 0;
}
