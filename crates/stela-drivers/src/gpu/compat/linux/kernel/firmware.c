// SPDX-License-Identifier: MIT
/* Linux's firmware loader over the running owner's images, which stay valid
 * until the owner exits; Linux code releases what it requests before then.
 * An owner without images has none to find. */
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/slab.h>
#include <stela/linux.h>

static int load(const struct firmware **out, const char *name, struct device *device, bool warn)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	const u8 *data = NULL;
	size_t size = 0;
	*out = NULL;
	int status = owner->services->firmware ?
		owner->services->firmware(owner->context, name, &data, &size) : -ENOENT;
	if (status) {
		if (warn)
			dev_warn(device, "Direct firmware load for %s failed with error %d\n", name,
				 status);
		return status;
	}
	struct firmware *fw = kzalloc_obj(*fw);
	if (!fw)
		return -ENOMEM;
	fw->size = size;
	fw->data = data;
	*out = fw;
	return 0;
}

int request_firmware(const struct firmware **fw, const char *name, struct device *device)
{
	return load(fw, name, device, true);
}

int firmware_request_nowarn(const struct firmware **fw, const char *name, struct device *device)
{
	return load(fw, name, device, false);
}

int request_firmware_direct(const struct firmware **fw, const char *name, struct device *device)
{
	return load(fw, name, device, false);
}

void release_firmware(const struct firmware *fw)
{
	kfree(fw);
}
