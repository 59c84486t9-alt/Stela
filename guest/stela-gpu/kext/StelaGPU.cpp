#include "StelaGPU.h"

#include <IOKit/IOLib.h>
#include <stela/gate.h>

OSDefineMetaClassAndStructors(StelaGPU, IOAccelerator);

bool
StelaGPU::start(IOService *provider)
{
	if (!IOAccelerator::start(provider)) {
		return false;
	}
	if (!attachGate(provider)) {
		stop(provider);
		return false;
	}
	/*
	 * AppleCLPC reads this from every accelerator it finds and panics without
	 * it. In milliwatts of the SoC's package budget, which this device spends
	 * none of.
	 */
	setProperty("GetGPUMaxPower", 0ULL, 32);
	registerService();
	return true;
}

bool
StelaGPU::attachGate(IOService *provider)
{
	window = provider->getDeviceMemoryWithIndex(0);
	if (!window || window->getLength() != STELA_GATE_BYTES) {
		IOLog("StelaGPU: the gate window is not %llu bytes\n", STELA_GATE_BYTES);
		window = nullptr;
		return false;
	}
	window->retain();
	IODeviceMemory *page = IODeviceMemory::withSubRange(window, 0, STELA_GATE_PAGE);
	if (page) {
		control = page->map(kIOMapInhibitCache);
		page->release();
	}
	if (!control) {
		IOLog("StelaGPU: cannot map the gate's control page\n");
		return false;
	}
	if (read(STELA_GATE_COUNT) != STELA_GATE_CONNECTIONS) {
		IOLog("StelaGPU: the gate has %llu connections, not %llu\n",
		    read(STELA_GATE_COUNT), STELA_GATE_CONNECTIONS);
		return false;
	}
	lock = IOLockAlloc();
	workLoop = IOWorkLoop::workLoop();
	if (!lock || !workLoop) {
		return false;
	}
	interrupt = IOInterruptEventSource::interruptEventSource(this, &StelaGPU::interruptOccurred, provider, 0);
	if (!interrupt || workLoop->addEventSource(interrupt) != kIOReturnSuccess) {
		IOLog("StelaGPU: cannot take the gate's interrupt\n");
		OSSafeReleaseNULL(interrupt);
		return false;
	}
	interrupt->enable();
	return true;
}

void
StelaGPU::stop(IOService *provider)
{
	if (lock) {
		IOLockLock(lock);
		stopping = true;
		IOLockUnlock(lock);
		// Only the host's retirement tokens permit unwiring imported pages.
		retireMemory();
		IOLockLock(lock);
		if (imports != 0 && !retainedForDma) {
			retainedForDma = true;
			retain();
			IOLog("StelaGPU: stopped with %llu wired imports; retaining the provider until native DMA retirement is available\n", imports);
		}
		IOLockUnlock(lock);
	}
	if (interrupt) {
		interrupt->disable();
		workLoop->removeEventSource(interrupt);
		OSSafeReleaseNULL(interrupt);
	}
	IOAccelerator::stop(provider);
}

void
StelaGPU::free()
{
	OSSafeReleaseNULL(interrupt);
	OSSafeReleaseNULL(workLoop);
	OSSafeReleaseNULL(control);
	OSSafeReleaseNULL(window);
	if (lock) {
		IOLockFree(lock);
		lock = nullptr;
	}
	IOAccelerator::free();
}

uint64_t
StelaGPU::openGate()
{
	IOLockLock(lock);
	if (stopping) {
		IOLockUnlock(lock);
		return 0;
	}
	write(STELA_GATE_OPEN, 1);
	uint64_t page = read(STELA_GATE_OPENED);
	IOLockUnlock(lock);
	return page;
}

void
StelaGPU::closeGate(uint64_t page)
{
	IOLockLock(lock);
	write(STELA_GATE_CLOSE, page);
	IOLockUnlock(lock);
}

IODeviceMemory *
StelaGPU::copyGateMemory(uint64_t page)
{
	return IODeviceMemory::withSubRange(window, page * STELA_GATE_PAGE, STELA_GATE_PAGE);
}

/*
 * The prepared descriptor of imported memory stands for its token: only the
 * gate sees a token, and it answers only those the kext gave it.
 */
uint64_t
StelaGPU::importMemory(uint64_t page, task_t task, mach_vm_address_t address, mach_vm_size_t length)
{
	IOMemoryDescriptor *memory = IOMemoryDescriptor::withAddressRange(address, length, kIODirectionOutIn, task);
	if (!memory) {
		return 0;
	}
	if (memory->prepare() != kIOReturnSuccess) {
		memory->release();
		return 0;
	}
	IOLockLock(lock);
	if (stopping || imports == ~uint64_t(0)) {
		IOLockUnlock(lock);
		memory->complete();
		memory->release();
		return 0;
	}
	for (IOByteCount offset = 0; offset < length;) {
		IOByteCount bytes = 0;
		addr64_t physical = memory->getPhysicalSegment(offset, &bytes, kIOMemoryMapperNone);
		write(STELA_GATE_IMPORT_ADDRESS, physical);
		write(STELA_GATE_IMPORT_BYTES, bytes);
		offset += bytes;
	}
	write(STELA_GATE_IMPORT_TOKEN, reinterpret_cast<uint64_t>(memory));
	write(STELA_GATE_IMPORT, page);
	uint64_t handle = read(STELA_GATE_IMPORTED);
	if (handle != 0) {
		imports++;
	}
	IOLockUnlock(lock);
	if (handle == 0) {
		memory->complete();
		memory->release();
	}
	return handle;
}

void
StelaGPU::retireMemory()
{
	for (;;) {
		IOLockLock(lock);
		write(STELA_GATE_RETIRE, 1);
		uint64_t token = read(STELA_GATE_RETIRED);
		if (token != 0) {
			// The host answers only tokens of successful imports, once each.
			assert(imports != 0);
			imports--;
		}
		IOLockUnlock(lock);
		if (token == 0) {
			return;
		}
		auto memory = reinterpret_cast<IOMemoryDescriptor *>(token);
		memory->complete();
		memory->release();
	}
}

uint64_t
StelaGPU::completions() const
{
	return __atomic_load_n(&completionCount, __ATOMIC_ACQUIRE);
}

/*
 * The gate holds its level interrupt until acknowledged. Acknowledging
 * before counting means work completing after the count raises it again.
 */
void
StelaGPU::interruptOccurred(OSObject *owner, IOInterruptEventSource *, int)
{
	auto gpu = static_cast<StelaGPU *>(owner);
	gpu->write(STELA_GATE_ACK, 1);
	gpu->retireMemory();
	uint64_t now = __atomic_add_fetch(&gpu->completionCount, 1, __ATOMIC_ACQ_REL);
	gpu->applyToClients([](IOService *client, void *context) {
		if (auto user = OSDynamicCast(StelaGPUUserClient, client)) {
			user->notify(*static_cast<uint64_t *>(context));
		}
	}, &now);
}

uint64_t
StelaGPU::read(uint64_t reg) const
{
	return *reinterpret_cast<volatile uint64_t *>(control->getVirtualAddress() + reg);
}

void
StelaGPU::write(uint64_t reg, uint64_t value)
{
	*reinterpret_cast<volatile uint64_t *>(control->getVirtualAddress() + reg) = value;
}
