/* SPDX-License-Identifier: MIT */
#pragma once
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSSharedPtr.h>

namespace stela::gpu {

/* ARM macOS kernel ownership only; never an IPC/native-backend representation.
 * Embed in the real task-owned frontend resource. Calls and destruction must be
 * serialized by that resource's existing IOKit lifecycle. The caller supplies
 * the actual IOUserClient owning task, never a task/address received on the wire.
 *
 * The frontend MUST retain this owner until every backend mapping/lease is
 * genuinely quiescent, including task death, failure and service removal.
 * Prepared memory is not a native DMA grant, residency, coherency or permission
 * to submit work. No physical/DMA/GPU address is produced here.
 */
class TaskMemory final {
public:
    TaskMemory() = default;
    ~TaskMemory();
    TaskMemory(const TaskMemory &) = delete;
    TaskMemory &operator=(const TaskMemory &) = delete;
    TaskMemory(TaskMemory &&) = delete;
    TaskMemory &operator=(TaskMemory &&) = delete;

    /* May sleep. Only In, Out and OutIn are accepted; direction is relative to
     * described memory, following IOKit. No arbitrary IOMemory option bits.
     * Invalid input/busy ownership causes no task/descriptor mutation. Allocation
     * or prepare failure releases the original references, without complete().
     */
    IOReturn prepare(task_t owning_task, mach_vm_address_t address,
                     mach_vm_size_t length, IODirection direction);

    /* Borrowed ARM-kernel object, valid only while this owner remains prepared.
     * Do not release, re-prepare, complete, reinitialize or export this pointer.
     * Mapping/grant validation and its asynchronous lifetime belong to the real
     * transport owner; they must end before finish_after_quiescence().
     */
    IOMemoryDescriptor *prepared_descriptor() const { return memory_.get(); }

    /* Call ONLY after actual backend access/mappings are quiescent and required
     * cache/reservation/code visibility is complete. transfer_failed selects the
     * original IOKit completion-error flag, not a synthetic GPU completion.
     * Failure retains both references unchanged for the caller's quarantine and
     * recovery; it must not destroy this owner or report completed teardown.
     * Success releases the descriptor before the task. Empty => NotReady.
     */
    IOReturn finish_after_quiescence(bool transfer_failed = false);

private:
    OSSharedPtr<IOMemoryDescriptor> memory_;
    task_t task_ = nullptr;
};

} // namespace stela::gpu
