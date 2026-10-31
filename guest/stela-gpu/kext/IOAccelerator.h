/*
 * IOGraphicsFamily's accelerator base class (com.apple.iokit.IOGraphicsFamily),
 * whose services Metal's device discovery matches. It adds neither virtual
 * methods nor members to IOService: its MetaClass registers IOService's size.
 */
#pragma once

#include <IOKit/IOService.h>

class IOAccelerator : public IOService {
	OSDeclareDefaultStructors(IOAccelerator);
};

static_assert(sizeof(IOAccelerator) == 0x88, "the kernel's IOService and IOAccelerator are 0x88 bytes");
