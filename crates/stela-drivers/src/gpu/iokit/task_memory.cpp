/* SPDX-License-Identifier: MIT */
#include "task_memory.h"
#include <IOKit/IOLib.h>
#include <kern/task.h>
#include <kern/task_ref.h>
#include <stdint.h>

namespace stela::gpu {

TaskMemory::~TaskMemory()
{
    /* Automatically completing here could unwire pages still used by hardware.
     * Even releasing the last descriptor reference can complete it inside XNU.
     * A still-prepared owner is a kernel caller lifetime bug, never permission
     * to manufacture quiescence. Keep this check active in release builds.
     */
    if (memory_ || task_)
        panic("Stela GPU task memory destroyed before quiescent completion");
}

IOReturn TaskMemory::prepare(task_t owning_task, mach_vm_address_t address,
                            mach_vm_size_t length, IODirection direction)
{
    if (memory_)
        return kIOReturnBusy;
    if (!owning_task || owning_task == kernel_task || !length ||
        address > UINT64_MAX - length ||
        (direction != kIODirectionIn && direction != kIODirectionOut &&
         direction != kIODirectionOutIn))
        return kIOReturnBadArgument;

    task_reference(owning_task);
    OSSharedPtr<IOMemoryDescriptor> memory(
        IOMemoryDescriptor::withAddressRange(address, length,
            direction | kIOMemoryMapperNone, owning_task), OSNoRetain);
    if (!memory) {
        task_deallocate(owning_task);
        return kIOReturnNoMemory;
    }
    IOReturn status = memory->prepare();
    if (status != kIOReturnSuccess) {
        memory.reset();
        task_deallocate(owning_task);
        return status;
    }
    task_ = owning_task;
    memory_.reset(memory.detach(), OSNoRetain);
    return kIOReturnSuccess;
}

IOReturn TaskMemory::finish_after_quiescence(bool transfer_failed)
{
    if (!memory_)
        return kIOReturnNotReady;
    IOReturn status = memory_->complete(transfer_failed ?
        kIODirectionCompleteWithError : kIODirectionNone);
    if (status != kIOReturnSuccess)
        return status;
    memory_.reset();
    task_deallocate(task_);
    task_ = nullptr;
    return kIOReturnSuccess;
}

} // namespace stela::gpu
