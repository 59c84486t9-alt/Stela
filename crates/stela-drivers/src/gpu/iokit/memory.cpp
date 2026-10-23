/* SPDX-License-Identifier: MIT */
#include "memory.h"
#include <IOKit/IOLib.h>
#include <libkern/libkern.h>

static_assert(sizeof(size_t) == sizeof(vm_size_t), "IOKit allocation size ABI");
static_assert(sizeof(size_t) == sizeof(vm_offset_t), "IOKit alignment ABI");

extern "C" void *stela_gpu_iokit_allocate_zeroed(size_t bytes, size_t alignment)
{
    if (!bytes || !alignment || (alignment & (alignment - 1)))
        return nullptr;
    void *pointer = IOMallocAligned(bytes, alignment);
    if (pointer)
        bzero(pointer, bytes);
    return pointer;
}

extern "C" void stela_gpu_iokit_free(void *pointer, size_t bytes)
{
    IOFreeAligned(pointer, bytes);
}
