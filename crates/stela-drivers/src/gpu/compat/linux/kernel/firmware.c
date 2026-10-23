// SPDX-License-Identifier: MIT
/* Linux's firmware loader over the running owner's images, which stay valid
 * until the owner exits; Linux code releases what it requests before then.
 * An owner without images has none to find. */
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/slab.h>
#include <stela/linux.h>

#ifdef STELA_LINUX_FIRMWARE_TEST
static bool fail_metadata_allocation;
#endif

static struct firmware *metadata(void)
{
#ifdef STELA_LINUX_FIRMWARE_TEST
	/* Bounded fault injection, with no production allocator replacement. */
	if (fail_metadata_allocation)
		return NULL;
#endif
	return kzalloc_obj(struct firmware);
}

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
	struct firmware *fw = metadata();
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

#ifdef STELA_LINUX_FIRMWARE_TEST
#include <linux/array_size.h>
#include <linux/printk.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <stela/test.h>

/* Synthetic bytes qualify request ownership only, never a GPU firmware input. */
static const u8 payload[] = {0x51, 0x92, 0x03, 0xe4};
static const char request_name[] = "vendor/exact-image.bin";

struct fixture {
	unsigned int requests, messages;
	int status, level;
	char message[160];
};

static int image(void *context, const char *name, const u8 **data, size_t *size)
{
	struct fixture *fixture = context;
	assert(!strcmp(name, request_name));
	assert(!*data && !*size);
	fixture->requests++;
	if (fixture->status)
		return fixture->status;
	*data = payload;
	*size = sizeof(payload);
	return 0;
}

static void message(void *context, int level, const char *text)
{
	struct fixture *fixture = context;
	fixture->messages++;
	fixture->level = level;
	assert(strlen(text) < sizeof(fixture->message));
	memcpy(fixture->message, text, strlen(text) + 1);
}

static void outside_owner(void)
{
	const struct firmware *firmware;
	(void)firmware_request_nowarn(&firmware, request_name, NULL);
}

int main(void)
{
	assert(stela_test_traps(outside_owner));
	const struct firmware *firmware = (const struct firmware *)1;
	stela_linux_enter(&stela_linux_bare);
	assert(firmware_request_nowarn(&firmware, request_name, NULL) == -ENOENT);
	assert(!firmware);
	release_firmware(NULL);
	stela_linux_exit();

	struct fixture fixture = {};
	const struct stela_linux_services services = {.firmware = image, .log = message};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	int (*const requests[])(const struct firmware **, const char *, struct device *) = {
		request_firmware, firmware_request_nowarn, request_firmware_direct,
	};
	const struct firmware *wrappers[ARRAY_SIZE(requests)];
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		wrappers[i] = (const struct firmware *)1;
		assert(!requests[i](&wrappers[i], request_name, NULL));
		assert(wrappers[i] && wrappers[i]->data == payload);
		assert(wrappers[i]->size == sizeof(payload) && !wrappers[i]->priv);
		for (size_t j = 0; j < i; j++)
			assert(wrappers[i] != wrappers[j]);
	}
	assert(fixture.requests == ARRAY_SIZE(requests) && !fixture.messages);
	for (size_t i = 0; i < ARRAY_SIZE(wrappers); i++)
		release_firmware(wrappers[i]);
	const u8 expected[] = {0x51, 0x92, 0x03, 0xe4};
	assert(!memcmp(payload, expected, sizeof(payload)));

	const int errors[] = {-ENOENT, -EBADMSG, -EINVAL, -EIO, -ENOMEM};
	for (size_t i = 0; i < ARRAY_SIZE(errors); i++) {
		fixture.status = errors[i];
		for (size_t j = 0; j < ARRAY_SIZE(requests); j++) {
			unsigned int before = fixture.messages;
			firmware = (const struct firmware *)1;
			assert(requests[j](&firmware, request_name, NULL) == errors[i]);
			assert(!firmware);
			assert(fixture.messages == before + (j == 0 ? 1U : 0U));
			if (!j) {
				assert(fixture.level == LOGLEVEL_WARNING);
				assert(strstr(fixture.message, request_name));
				char expected_status[24];
				snprintf(expected_status, sizeof(expected_status), "error %d\n", errors[i]);
				assert(strstr(fixture.message, expected_status));
			}
		}
	}
	fixture.status = 0;
	fail_metadata_allocation = true;
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		unsigned int before = fixture.messages;
		firmware = (const struct firmware *)1;
		assert(requests[i](&firmware, request_name, NULL) == -ENOMEM);
		assert(!firmware && fixture.messages == before);
	}
	fail_metadata_allocation = false;
	assert(!firmware_request_nowarn(&firmware, request_name, NULL));
	assert(firmware && firmware->data == payload && firmware->size == sizeof(payload));
	release_firmware(firmware);
	stela_linux_exit();
	printf("Linux firmware: exact request/errors, metadata ownership and failure unwind passed\n");
	return 0;
}
#endif
