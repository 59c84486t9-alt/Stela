/*
 * StelaGPU: the accelerator Metal discovers, over Stela's call gate at
 * /arm-io/stela-gpu<n> (stela_contracts::gate::window).
 *
 * The kext opens and closes one gate connection per user client and maps
 * its gate page into the client's task, which then calls the native GPU
 * service with no kernel crossing. The gate's interrupt reports completed
 * GPU work; the kext counts it and notifies each client that asked.
 *
 * What a CPU reaches of a GPU's memory is the task's own: the kext wires the
 * pages and names them to the gate, whose control page only the kernel maps,
 * and they stay wired until the GPU no longer reaches them.
 */
#pragma once

#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>

#include "IOAccelerator.h"

class StelaGPU : public IOAccelerator {
	OSDeclareDefaultStructors(StelaGPU);

public:
	bool start(IOService *provider) override;
	void stop(IOService *provider) override;
	void free() override;

	/* Opens a gate connection, answering its gate page, 0 when none is free. */
	uint64_t openGate();
	/* Closes the connection of gate page `page`. */
	void closeGate(uint64_t page);
	/* The memory of gate page `page`, retained. */
	IODeviceMemory *copyGateMemory(uint64_t page);
	/* How many completion interrupts the gate has raised. */
	uint64_t completions() const;
	/*
	 * Wires `length` bytes of the task at `address` and gives them to the
	 * connection of gate page `page`, answering the handle, 0 on failure.
	 */
	uint64_t importMemory(uint64_t page, task_t task, mach_vm_address_t address, mach_vm_size_t length);

private:
	/* Unwires what the gate says the GPU no longer reaches. */
	void retireMemory();
	/* Maps the gate's control page and takes its interrupt. */
	bool attachGate(IOService *provider);
	static void interruptOccurred(OSObject *owner, IOInterruptEventSource *source, int count);
	uint64_t read(uint64_t reg) const;
	void write(uint64_t reg, uint64_t value);

	IODeviceMemory *window = nullptr;
	IOMemoryMap *control = nullptr;
	IOWorkLoop *workLoop = nullptr;
	IOInterruptEventSource *interrupt = nullptr;
	/* Serializes the control page's open and close sequences. */
	IOLock *lock = nullptr;
	uint64_t completionCount = 0;
};

class StelaGPUUserClient : public IOUserClient {
	OSDeclareDefaultStructors(StelaGPUUserClient);

public:
	bool initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties) override;
	bool start(IOService *provider) override;
	void stop(IOService *provider) override;
	void free() override;
	IOReturn clientClose() override;
	IOReturn clientMemoryForType(UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) override;
	IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
	    IOExternalMethodDispatch *dispatch, OSObject *target, void *reference) override;

	/* Sends the armed notification if the completion count is past it. */
	void notify(uint64_t now);

private:
	static const IOExternalMethodDispatch methods[];
	static IOReturn notifyCompletion(OSObject *target, void *reference, IOExternalMethodArguments *arguments);
	static IOReturn importMemory(OSObject *target, void *reference, IOExternalMethodArguments *arguments);
	/* With `lock` held: sends and releases the armed notification once `now` passes it. */
	void deliver(uint64_t now);
	/* Releases the armed notification unsent. */
	void disarm();

	StelaGPU *gpu = nullptr;
	/* The connection's gate page, 0 once closed. */
	uint64_t gate = 0;
	IODeviceMemory *gateMemory = nullptr;
	/* Guards the armed notification against the interrupt's delivery. */
	IOLock *lock = nullptr;
	bool armed = false;
	uint64_t armedSeen = 0;
	OSAsyncReference64 armedReference = {};
};
