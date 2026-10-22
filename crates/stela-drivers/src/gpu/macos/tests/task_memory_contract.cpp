/* SPDX-License-Identifier: MIT */
/* Compile the real owner below against deliberately narrow service mocks.
 * These check caller ownership/error handling, not IOKit implementation, kernel
 * class layout, ABI, page wiring, task death or hardware quiescence. The normal
 * Makefile targets separately compile against the unmodified Apple SDK.
 * No mock is compiled into a driver component.
 */
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <cstdlib>
#include <type_traits>
#include <sys/wait.h>
#include <unistd.h>

// Suppress SDK declarations only in this test translation unit.
#define _IOMEMORYDESCRIPTOR_H
#define XNU_LIBKERN_LIBKERN_CXX_OS_SHARED_PTR_H
#define __IOKIT_IOLIB_H
#define _KERN_TASK_H_
#define _KERN_TASK_REF_H_

using IOReturn = int32_t;
using IODirection = uint32_t;
using IOOptionBits = uint32_t;
using mach_vm_address_t = uint64_t;
using mach_vm_size_t = uint64_t;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnNoMemory = static_cast<IOReturn>(0xe00002bdu);
constexpr IOReturn kIOReturnBadArgument = static_cast<IOReturn>(0xe00002c2u);
constexpr IOReturn kIOReturnBusy = static_cast<IOReturn>(0xe00002d5u);
constexpr IOReturn kIOReturnNotReady = static_cast<IOReturn>(0xe00002d8u);
constexpr IOReturn injected_error = -12345;
constexpr IODirection kIODirectionNone = 0;
constexpr IODirection kIODirectionIn = 1;
constexpr IODirection kIODirectionOut = 2;
constexpr IODirection kIODirectionOutIn = 3;
constexpr IODirection kIODirectionCompleteWithError = 0x40;
constexpr IOOptionBits kIOMemoryMapperNone = 0x800;
struct task { unsigned references = 1; } user, kernel;
using task_t = task *;
task_t kernel_task = &kernel;

enum Event { ReferenceTask, Factory, Prepare, Complete, ReleaseMemory, ReleaseTask };
static Event events[32];
static unsigned event_count, complete_calls, releases;
static IOReturn prepare_status, complete_status;
static bool factory_failure;
static IODirection last_complete_direction;
static void record(Event event)
{
    assert(event_count < 32);
    events[event_count++] = event;
}
static void task_reference(task_t owner)
{
    assert(owner == &user && owner->references == 1);
    ++owner->references;
    record(ReferenceTask);
}
static void task_deallocate(task_t owner)
{
    assert(owner == &user && owner->references == 2);
    --owner->references;
    record(ReleaseTask);
}
struct IOMemoryDescriptor {
    unsigned references = 0;
    bool prepared = false;
    static IOMemoryDescriptor *withAddressRange(mach_vm_address_t,
        mach_vm_size_t, IOOptionBits, task_t);
    IOReturn prepare(IODirection direction = kIODirectionNone)
    {
        assert(references == 1 && !prepared && direction == kIODirectionNone);
        assert(user.references == 2);
        record(Prepare);
        prepared = prepare_status == kIOReturnSuccess;
        return prepare_status;
    }
    IOReturn complete(IODirection direction = kIODirectionNone)
    {
        assert(references == 1 && prepared && user.references == 2);
        ++complete_calls;
        last_complete_direction = direction;
        record(Complete);
        if (complete_status == kIOReturnSuccess)
            prepared = false;
        return complete_status;
    }
    void release()
    {
        // A release while prepared could unwire pages inside original XNU.
        assert(references == 1 && !prepared && user.references == 2);
        --references;
        ++releases;
        record(ReleaseMemory);
    }
} descriptor;
IOMemoryDescriptor *IOMemoryDescriptor::withAddressRange(mach_vm_address_t,
    mach_vm_size_t length, IOOptionBits options, task_t owner)
{
    assert(owner == &user && owner->references == 2 && length != 0);
    assert((options & ~kIODirectionOutIn) == kIOMemoryMapperNone);
    assert(descriptor.references == 0);
    record(Factory);
    if (factory_failure)
        return nullptr;
    descriptor.references = 1;
    return &descriptor;
}
struct NoRetain {};
constexpr NoRetain OSNoRetain{};
template<class T> class OSSharedPtr {
public:
    OSSharedPtr() = default;
    OSSharedPtr(T *pointer, NoRetain) : pointer_(pointer) {}
    ~OSSharedPtr() { reset(); }
    OSSharedPtr(const OSSharedPtr &) = delete;
    OSSharedPtr &operator=(const OSSharedPtr &) = delete;
    explicit operator bool() const { return pointer_ != nullptr; }
    T *get() const { return pointer_; }
    T *operator->() const { return pointer_; }
    T *detach() { T *result = pointer_; pointer_ = nullptr; return result; }
    void reset()
    {
        if (pointer_)
            pointer_->release();
        pointer_ = nullptr;
    }
    void reset(T *pointer, NoRetain) { reset(); pointer_ = pointer; }
private:
    T *pointer_ = nullptr;
};
[[noreturn]] static void panic(const char *, ...)
{
    // The child must refuse destruction before either completion or release.
    _Exit(complete_calls == 0 && releases == 0 && user.references == 2 ? 86 : 87);
}

#include "../task_memory.cpp"
using stela::gpu::TaskMemory;
static_assert(!std::is_copy_constructible_v<TaskMemory>);
static_assert(!std::is_move_constructible_v<TaskMemory>);
static void reset()
{
    assert(user.references == 1 && kernel.references == 1);
    assert(descriptor.references == 0 && !descriptor.prepared);
    event_count = complete_calls = releases = 0;
    factory_failure = false;
    prepare_status = complete_status = kIOReturnSuccess;
    last_complete_direction = 0;
}
template<size_t N> static void expect(const Event (&expected)[N])
{
    assert(event_count == N);
    for (unsigned i = 0; i < N; ++i)
        assert(events[i] == expected[i]);
}
int main()
{
    reset();
    {
        TaskMemory owner;
        assert(!owner.prepared_descriptor());
        assert(owner.finish_after_quiescence() == kIOReturnNotReady);
        assert(owner.prepare(nullptr, 0x1000, 4096, kIODirectionIn) == kIOReturnBadArgument);
        assert(owner.prepare(kernel_task, 0x1000, 4096, kIODirectionIn) == kIOReturnBadArgument);
        assert(owner.prepare(&user, 0x1000, 0, kIODirectionIn) == kIOReturnBadArgument);
        assert(owner.prepare(&user, UINT64_MAX, 1, kIODirectionIn) == kIOReturnBadArgument);
        assert(owner.prepare(&user, 1, UINT64_MAX, kIODirectionIn) == kIOReturnBadArgument);
        for (IODirection direction : {0u, 4u, 0x40u, 0x800u, UINT32_MAX})
            assert(owner.prepare(&user, 0x1000, 4096, direction) == kIOReturnBadArgument);
        assert(event_count == 0);
    }
    for (IODirection direction : {kIODirectionIn, kIODirectionOut, kIODirectionOutIn}) {
        reset();
        TaskMemory owner;
        assert(owner.prepare(&user, UINT64_MAX - 1, 1, direction) == kIOReturnSuccess);
        assert(owner.prepared_descriptor() == &descriptor);
        assert(owner.prepare(nullptr, 0, 0, 0) == kIOReturnBusy);
        assert(event_count == 3 && user.references == 2);
        assert(owner.finish_after_quiescence() == kIOReturnSuccess);
        assert(!owner.prepared_descriptor() && last_complete_direction == kIODirectionNone);
        assert(owner.finish_after_quiescence() == kIOReturnNotReady);
        expect({ReferenceTask, Factory, Prepare, Complete, ReleaseMemory, ReleaseTask});
    }
    reset();
    {
        factory_failure = true;
        TaskMemory owner;
        assert(owner.prepare(&user, 0x1000, 4096, kIODirectionOut) == kIOReturnNoMemory);
        assert(!owner.prepared_descriptor());
        expect({ReferenceTask, Factory, ReleaseTask});
    }
    reset();
    {
        prepare_status = injected_error;
        TaskMemory owner;
        assert(owner.prepare(&user, 0x1000, 4096, kIODirectionOut) == injected_error);
        assert(!owner.prepared_descriptor() && complete_calls == 0);
        expect({ReferenceTask, Factory, Prepare, ReleaseMemory, ReleaseTask});
    }
    reset();
    {
        TaskMemory owner;
        assert(owner.prepare(&user, 0, 4096, kIODirectionIn) == kIOReturnSuccess);
        complete_status = injected_error;
        assert(owner.finish_after_quiescence() == injected_error);
        assert(owner.prepared_descriptor() == &descriptor && descriptor.prepared);
        assert(user.references == 2 && releases == 0);
        assert(owner.prepare(&user, 0x1000, 4096, kIODirectionOut) == kIOReturnBusy);
        complete_status = kIOReturnSuccess;
        assert(owner.finish_after_quiescence(true) == kIOReturnSuccess);
        assert(last_complete_direction == kIODirectionCompleteWithError);
        expect({ReferenceTask, Factory, Prepare, Complete, Complete, ReleaseMemory, ReleaseTask});
        // A finished embedded owner can be reused without retaining stale refs.
        assert(owner.prepare(&user, 0x1000, 4096, kIODirectionOut) == kIOReturnSuccess);
        assert(owner.finish_after_quiescence() == kIOReturnSuccess);
    }
    reset();
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        { TaskMemory owner;
          assert(owner.prepare(&user, 0x1000, 4096, kIODirectionOut) == kIOReturnSuccess); }
        _Exit(88);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 86);
    std::puts("task memory ownership/error contracts passed (service mocks; no kernel/device execution)");
}
