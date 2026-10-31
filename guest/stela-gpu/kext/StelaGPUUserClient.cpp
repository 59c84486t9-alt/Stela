#include "StelaGPU.h"

#include <IOKit/IOKitKeys.h>
#include <IOKit/IOLib.h>
#include <StelaGPU/Interface.h>

OSDefineMetaClassAndStructors(StelaGPUUserClient, IOUserClient);

/* By selector. */
const IOExternalMethodDispatch StelaGPUUserClient::methods[kStelaGPUSelectorCount] = {
	{
		.function = &StelaGPUUserClient::notifyCompletion,
		.checkScalarInputCount = 1,
		.checkStructureInputSize = 0,
		.checkScalarOutputCount = 0,
		.checkStructureOutputSize = 0,
	},
	{
		.function = &StelaGPUUserClient::importMemory,
		.checkScalarInputCount = 2,
		.checkStructureInputSize = 0,
		.checkScalarOutputCount = 1,
		.checkStructureOutputSize = 0,
	},
};

/*
 * IOKit's default locking serializes close and mapping against every
 * external method, which then run concurrently with each other.
 */
bool
StelaGPUUserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties)
{
	if (type != kStelaGPUUserClientType
	    || !IOUserClient::initWithTask(owningTask, securityID, type, properties)) {
		return false;
	}
	setProperty(kIOUserClientDefaultLockingKey, kOSBooleanTrue);
	setProperty(kIOUserClientDefaultLockingSetPropertiesKey, kOSBooleanTrue);
	setProperty(kIOUserClientDefaultLockingSingleThreadExternalMethodKey, kOSBooleanFalse);
	lock = IOLockAlloc();
	return lock != nullptr;
}

bool
StelaGPUUserClient::start(IOService *provider)
{
	gpu = OSDynamicCast(StelaGPU, provider);
	if (!gpu || !IOUserClient::start(provider)) {
		gpu = nullptr;
		return false;
	}
	// Closing the gate can follow the provider's stop.
	gpu->retain();
	gate = gpu->openGate();
	if (gate == 0) {
		IOLog("StelaGPU: every gate connection is open\n");
		IOUserClient::stop(provider);
		return false;
	}
	gateMemory = gpu->copyGateMemory(gate);
	if (!gateMemory) {
		gpu->closeGate(gate);
		gate = 0;
		IOUserClient::stop(provider);
		return false;
	}
	return true;
}

void
StelaGPUUserClient::stop(IOService *provider)
{
	disarm();
	IOUserClient::stop(provider);
}

void
StelaGPUUserClient::free()
{
	OSSafeReleaseNULL(gateMemory);
	OSSafeReleaseNULL(gpu);
	if (lock) {
		IOLockFree(lock);
		lock = nullptr;
	}
	IOUserClient::free();
}

/*
 * The task's last mapping of the gate page goes before the connection
 * closes, so no task ever reaches a gate page reopened for another. IOKit
 * holds the client's lock, so no mapping is being made meanwhile.
 */
IOReturn
StelaGPUUserClient::clientClose()
{
	disarm();
	if (gate != 0) {
		while (IOMemoryMap *map = removeMappingForDescriptor(gateMemory)) {
			map->unmap();
			map->release();
		}
		gpu->closeGate(gate);
		gate = 0;
	}
	terminate();
	return kIOReturnSuccess;
}

IOReturn
StelaGPUUserClient::clientMemoryForType(UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory)
{
	if (type != kStelaGPUGateMemory) {
		return kIOReturnBadArgument;
	}
	if (gate == 0) {
		return kIOReturnNotOpen;
	}
	// The gate's registers are device memory the task stores to.
	*options = (*options & kIOMapAnywhere) | kIOMapInhibitCache;
	gateMemory->retain();
	*memory = gateMemory;
	return kIOReturnSuccess;
}

IOReturn
StelaGPUUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
    IOExternalMethodDispatch *, OSObject *, void *)
{
	if (selector >= kStelaGPUSelectorCount) {
		return kIOReturnBadArgument;
	}
	// IOUserClient takes the dispatch it checks the call against as mutable.
	IOExternalMethodDispatch dispatch = methods[selector];
	return IOUserClient::externalMethod(selector, arguments, &dispatch, this, nullptr);
}

/*
 * Arms the client's one notification. On success the client owns the
 * reference's send right until it delivers or disarms it.
 */
IOReturn
StelaGPUUserClient::notifyCompletion(OSObject *target, void *, IOExternalMethodArguments *arguments)
{
	auto self = static_cast<StelaGPUUserClient *>(target);
	if (!arguments->asyncWakePort) {
		return kIOReturnBadArgument;
	}
	IOLockLock(self->lock);
	if (self->armed) {
		releaseAsyncReference64(self->armedReference);
	}
	bcopy(arguments->asyncReference, self->armedReference, sizeof(OSAsyncReference64));
	self->armed = true;
	self->armedSeen = arguments->scalarInput[0];
	// The count is read after arming, so a completion in between is never missed.
	self->deliver(self->gpu->completions());
	IOLockUnlock(self->lock);
	return kIOReturnSuccess;
}

/* Runs on the calling thread, whose task the memory is. */
IOReturn
StelaGPUUserClient::importMemory(OSObject *target, void *, IOExternalMethodArguments *arguments)
{
	auto self = static_cast<StelaGPUUserClient *>(target);
	if (self->gate == 0) {
		return kIOReturnNotOpen;
	}
	uint64_t handle = self->gpu->importMemory(self->gate, current_task(), arguments->scalarInput[0],
	    arguments->scalarInput[1]);
	if (handle == 0) {
		return kIOReturnNoMemory;
	}
	arguments->scalarOutput[0] = handle;
	return kIOReturnSuccess;
}

void
StelaGPUUserClient::notify(uint64_t now)
{
	IOLockLock(lock);
	deliver(now);
	IOLockUnlock(lock);
}

void
StelaGPUUserClient::deliver(uint64_t now)
{
	if (!armed || now == armedSeen) {
		return;
	}
	io_user_reference_t count = now;
	sendAsyncResult64(armedReference, kIOReturnSuccess, &count, 1);
	releaseAsyncReference64(armedReference);
	armed = false;
}

void
StelaGPUUserClient::disarm()
{
	IOLockLock(lock);
	if (armed) {
		releaseAsyncReference64(armedReference);
		armed = false;
	}
	IOLockUnlock(lock);
}
