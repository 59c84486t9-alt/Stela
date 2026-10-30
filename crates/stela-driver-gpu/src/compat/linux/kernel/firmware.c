// SPDX-License-Identifier: MIT
/* Linux firmware requests own a snapshot of the provider's bytes through
 * release_firmware, independently of the execution owner that requested it. */
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <stela/linux.h>

/* Keep the exact heap layout private: public firmware metadata is immutable to
 * consumers, and freeing does not need either that size or a borrowed owner.
 * The first member permits converting a public handle back to its allocation. */
struct snapshot {
	struct firmware firmware;
	size_t allocation_bytes;
};

#ifdef STELA_LINUX_FIRMWARE_TEST
#include <stela/test.h>
static bool fail_snapshot_allocation;
static size_t live_snapshots, allocated_bytes, released_bytes, allocation_calls;
#endif

static struct snapshot *allocate_snapshot(size_t bytes)
{
#ifdef STELA_LINUX_FIRMWARE_TEST
	/* Bounded failure at the sole acquisition; no production allocator swap. */
	if (fail_snapshot_allocation)
		return NULL;
	allocation_calls++;
#endif
	struct snapshot *snapshot = stela_linux_heap_alloc(bytes, __alignof__(struct snapshot));
#ifdef STELA_LINUX_FIRMWARE_TEST
	if (snapshot) {
		live_snapshots++;
		allocated_bytes += bytes;
	}
#endif
	return snapshot;
}

static int load(const struct firmware **out, const char *name, struct device *device, bool warn)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!name || !*name)
		return -EINVAL;
	/* request_firmware is sleepable. Refuse before the provider, which may
	 * itself block, instead of relying on an allocator's later check. */
	if (!stela_linux_quiescent()) {
		stela_linux_unsupported("firmware request context");
		return -EOPNOTSUPP;
	}
	const u8 *data = NULL;
	size_t size = 0;
	int status = owner->services->firmware ?
		owner->services->firmware(owner->context, name, &data, &size) : -ENOENT;
	/* A provider must return within its original entered execution context.
	 * Check before reading/copying its result or using its diagnostic sink. */
	if (stela_linux_owner() != owner || !stela_linux_quiescent())
		__builtin_trap();
	if (status) {
		if (warn)
			dev_warn(device, "Direct firmware load for %s failed with error %d\n", name,
				 status);
		return status;
	}
	/* The original assign_fw rejects empty images. Invalid successful shape
	 * is separate from a provider error and emits no direct-load warning. */
	if (!size)
		return -ENOENT;
	if (!data)
		return -EBADMSG;
	size_t maximum = (size_t)SSIZE_MAX & ~((size_t)__alignof__(struct snapshot) - 1);
	if (size > maximum - sizeof(struct snapshot) ||
	    (unsigned long)data > ULONG_MAX - size)
		return -EOVERFLOW;
	/* The provider guarantees this complete source window readable and stable
	 * through the copy; integer range checks alone cannot prove a mapping. */
	size_t bytes = sizeof(struct snapshot) + size;
	struct snapshot *snapshot = allocate_snapshot(bytes);
	if (!snapshot)
		return -ENOMEM;
	snapshot->allocation_bytes = bytes;
	snapshot->firmware.size = size;
	u8 *payload = (u8 *)(snapshot + 1);
	snapshot->firmware.data = payload;
	memcpy(payload, data, size);
	*out = &snapshot->firmware;
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
	if (!fw)
		return;
	const struct snapshot *snapshot = (const struct snapshot *)fw;
#ifdef STELA_LINUX_FIRMWARE_TEST
	assert(live_snapshots);
	live_snapshots--;
	released_bytes += snapshot->allocation_bytes;
#endif
	stela_linux_heap_free((void *)snapshot, snapshot->allocation_bytes,
			      __alignof__(struct snapshot));
}

#ifdef STELA_LINUX_FIRMWARE_TEST
#include <linux/array_size.h>
#include <linux/bottom_half.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sprintf.h>

/* Synthetic bytes qualify ownership only, never a GPU firmware input. */
static const char request_name[] = "vendor/exact-image.bin";
static int (*const requests[])(const struct firmware **, const char *, struct device *) = {
	request_firmware, firmware_request_nowarn, request_firmware_direct,
};

struct fixture {
	const u8 *data;
	size_t size;
	unsigned int requests, messages, refusals;
	int status, level, callback_action;
	char message[160];
};

static int image(void *context, const char *name, const u8 **data, size_t *size)
{
	struct fixture *fixture = context;
	assert(!strcmp(name, request_name));
	assert(!*data && !*size);
	fixture->requests++;
	*data = fixture->data;
	*size = fixture->size;
	if (fixture->callback_action == 1)
		preempt_disable();
	if (fixture->callback_action == 2) {
		stela_linux_exit();
		stela_linux_enter(&stela_linux_bare);
	}
	return fixture->status;
}

static void message(void *context, int level, const char *text)
{
	struct fixture *fixture = context;
	fixture->messages++;
	fixture->level = level;
	assert(strlen(text) < sizeof(fixture->message));
	memcpy(fixture->message, text, strlen(text) + 1);
}

static void unsupported(void *context, const char *operation)
{
	struct fixture *fixture = context;
	assert(!strcmp(operation, "firmware request context"));
	fixture->refusals++;
}

static const struct stela_linux_services services = {
	.firmware = image, .log = message, .unsupported = unsupported,
};

static u8 pattern(size_t index, unsigned int salt)
{
	return (u8)(index * 37 + salt);
}

static void fill(u8 *data, size_t size, unsigned int salt)
{
	for (size_t i = 0; i < size; i++)
		data[i] = pattern(i, salt);
}

static void check(const struct firmware *firmware, size_t size, unsigned int salt)
{
	assert(firmware && firmware->size == size && !firmware->priv);
	assert(!((unsigned long)firmware->data & (__alignof__(struct snapshot) - 1)));
	for (size_t i = 0; i < size; i++)
		assert(firmware->data[i] == pattern(i, salt));
}

static void independent_lifetime(void)
{
	const size_t size = 257;
	u8 *backing = calloc(size + 2, 1);
	struct fixture *fixture = calloc(1, sizeof(*fixture));
	assert(backing && fixture);
	/* A deliberately unaligned source also has tight one-byte guards. */
	backing[0] = 0x7c;
	backing[size + 1] = 0xc7;
	fixture->data = backing + 1;
	fixture->size = size;
	const struct stela_linux_owner owner = {.services = &services, .context = fixture};
	const struct firmware *wrappers[ARRAY_SIZE(requests)];
	stela_linux_enter(&owner);
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		fill(backing + 1, size, (unsigned int)i);
		wrappers[i] = (const struct firmware *)1;
		assert(!requests[i](&wrappers[i], request_name, NULL));
		assert(wrappers[i]->data != fixture->data);
		for (size_t j = 0; j <= i; j++) {
			check(wrappers[j], size, (unsigned int)j);
			if (j != i)
				assert(wrappers[i] != wrappers[j] &&
				       wrappers[i]->data != wrappers[j]->data);
		}
	}
	assert(fixture->requests == ARRAY_SIZE(requests) && !fixture->messages);
	assert(backing[0] == 0x7c && backing[size + 1] == 0xc7);
	stela_linux_exit();
	/* Destroy the actual context and bytes, not just a logical owner flag. */
	memset(backing, 0xd3, size + 2);
	memset(fixture, 0xa5, sizeof(*fixture));
	free(backing);
	free(fixture);
	for (size_t i = 0; i < ARRAY_SIZE(wrappers); i++)
		check(wrappers[i], size, (unsigned int)i);
	struct fixture second = {};
	const struct stela_linux_owner next = {.services = &services, .context = &second};
	stela_linux_enter(&next);
	for (size_t i = 0; i < ARRAY_SIZE(wrappers); i++)
		release_firmware(wrappers[i]);
	assert(!second.requests && !second.messages && !live_snapshots);
	stela_linux_exit();
}

static void large_snapshot(void)
{
	/* Exercise the real path beyond the raw allocator's 4 MiB upper bound. */
	const size_t size = KMALLOC_MAX_SIZE + PAGE_SIZE + 1;
	u8 *backing = calloc(size, 1);
	assert(backing);
	fill(backing, size, 19);
	struct fixture fixture = {.data = backing, .size = size};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	const struct firmware *firmware;
	stela_linux_enter(&owner);
	assert(!firmware_request_nowarn(&firmware, request_name, NULL));
	stela_linux_exit();
	memset(backing, 0xd3, size);
	free(backing);
	check(firmware, size, 19);
	/* Matching free needs no per-entry owner or provider context. */
	release_firmware(firmware);
	assert(!live_snapshots);
}

static void errors_and_shapes(void)
{
	struct fixture fixture = {.data = (const u8 *)SIZE_MAX, .size = SIZE_MAX};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	const int errors[] = {-ENOENT, -EBADMSG, -EINVAL, -EIO, -ENOMEM};
	for (size_t i = 0; i < ARRAY_SIZE(errors); i++) {
		fixture.status = errors[i];
		for (size_t j = 0; j < ARRAY_SIZE(requests); j++) {
			unsigned int before = fixture.messages;
			size_t calls = allocation_calls;
			const struct firmware *firmware = (const struct firmware *)1;
			assert(requests[j](&firmware, request_name, NULL) == errors[i]);
			assert(!firmware && allocation_calls == calls && !live_snapshots);
			assert(fixture.messages == before + (j == 0 ? 1U : 0U));
			if (!j) {
				char expected[160];
				snprintf(expected, sizeof(expected),
					 "Direct firmware load for %s failed with error %d\n",
					 request_name, errors[i]);
				assert(fixture.level == LOGLEVEL_WARNING);
				/* dev_printk prefixes the NULL device name in the message. */
				assert(strstr(fixture.message, expected));
			}
		}
	}
	fixture.status = 0;
	const struct {
		const u8 *data;
		size_t size;
		int status;
	} shapes[] = {
		{NULL, 0, -ENOENT}, {(const u8 *)1, 0, -ENOENT},
		{NULL, 4, -EBADMSG}, {(const u8 *)1, SIZE_MAX, -EOVERFLOW},
		{(const u8 *)1, (size_t)SSIZE_MAX, -EOVERFLOW},
		{(const u8 *)(SIZE_MAX - 1), 4, -EOVERFLOW},
	};
	for (size_t i = 0; i < ARRAY_SIZE(shapes); i++) {
		fixture.data = shapes[i].data;
		fixture.size = shapes[i].size;
		for (size_t j = 0; j < ARRAY_SIZE(requests); j++) {
			unsigned int before = fixture.messages;
			size_t calls = allocation_calls;
			const struct firmware *firmware = (const struct firmware *)1;
			assert(requests[j](&firmware, request_name, NULL) == shapes[i].status);
			assert(!firmware && !live_snapshots && allocation_calls == calls);
			assert(fixture.messages == before);
		}
	}
	/* Invalid public inputs never reach the unsafe provider. */
	unsigned int before = fixture.requests;
	for (size_t j = 0; j < ARRAY_SIZE(requests); j++) {
		const struct firmware *firmware = (const struct firmware *)1;
		assert(requests[j](NULL, request_name, NULL) == -EINVAL);
		assert(requests[j](&firmware, NULL, NULL) == -EINVAL && !firmware);
		firmware = (const struct firmware *)1;
		assert(requests[j](&firmware, "", NULL) == -EINVAL && !firmware);
	}
	assert(fixture.requests == before);
	stela_linux_exit();
}

static void allocation_failure(void)
{
	u8 backing[31];
	fill(backing, sizeof(backing), 43);
	struct fixture fixture = {.data = backing, .size = sizeof(backing)};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	/* Keep a real live result across each failed independent acquisition. */
	const struct firmware *retained;
	assert(!request_firmware(&retained, request_name, NULL));
	size_t calls = allocation_calls, bytes = allocated_bytes;
	fail_snapshot_allocation = true;
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		const struct firmware *firmware = (const struct firmware *)1;
		unsigned int before = fixture.messages;
		assert(requests[i](&firmware, request_name, NULL) == -ENOMEM);
		assert(!firmware && live_snapshots == 1 && allocation_calls == calls);
		assert(allocated_bytes == bytes && fixture.messages == before);
		check(retained, sizeof(backing), 43);
	}
	fail_snapshot_allocation = false;
	release_firmware(retained);
	const struct firmware *recovered;
	assert(!request_firmware(&recovered, request_name, NULL));
	check(recovered, sizeof(backing), 43);
	release_firmware(recovered);
	assert(!live_snapshots);
	stela_linux_exit();
}

static void nonquiescent_refusal(void)
{
	const u8 backing[] = {1, 2, 3};
	struct fixture fixture = {.data = backing, .size = sizeof(backing)};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	for (unsigned int context = 0; context < 4; context++) {
		unsigned long flags = 0;
		switch (context) {
		case 0: preempt_disable(); break;
		case 1: rcu_read_lock(); break;
		case 2: local_bh_disable(); break;
		case 3: flags = arch_local_irq_save(); break;
		}
		for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
			const struct firmware *firmware = (const struct firmware *)1;
			size_t calls = allocation_calls;
			unsigned int before = fixture.refusals;
			assert(requests[i](&firmware, request_name, NULL) == -EOPNOTSUPP);
			assert(!firmware && allocation_calls == calls);
			assert(!fixture.requests && !fixture.messages && !live_snapshots);
			assert(fixture.refusals == before + 1);
		}
		switch (context) {
		case 0: preempt_enable(); break;
		case 1: rcu_read_unlock(); break;
		case 2: local_bh_enable(); break;
		case 3: arch_local_irq_restore(flags); break;
		}
	}
	assert(stela_linux_quiescent());
	stela_linux_exit();
}

static size_t selected_request;
static unsigned int selected_context;
static int selected_action;

static void outside_owner(void)
{
	const struct firmware *firmware;
	(void)requests[selected_request](&firmware, request_name, NULL);
}

static void strict_refusal(void)
{
	stela_linux_enter(&stela_linux_bare);
	switch (selected_context) {
	case 0: preempt_disable(); break;
	case 1: rcu_read_lock(); break;
	case 2: local_bh_disable(); break;
	case 3: (void)arch_local_irq_save(); break;
	}
	const struct firmware *firmware;
	(void)requests[selected_request](&firmware, request_name, NULL);
}

static void changed_callback_context(void)
{
	/* An unchecked result would return overflow, not SIGILL. Check both
	 * success and error paths before either data copy or diagnostics. */
	struct fixture fixture = {
		.data = (const u8 *)(SIZE_MAX - 1), .size = 4,
		.callback_action = selected_action > 2 ? selected_action - 2 : selected_action,
		.status = selected_action > 2 ? -EIO : 0,
	};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	stela_linux_enter(&owner);
	const struct firmware *firmware;
	(void)requests[selected_request](&firmware, request_name, NULL);
}

int main(void)
{
	release_firmware(NULL);
	for (selected_request = 0; selected_request < ARRAY_SIZE(requests); selected_request++) {
		assert(stela_test_traps(outside_owner));
		for (selected_context = 0; selected_context < 4; selected_context++)
			assert(stela_test_traps(strict_refusal));
		for (selected_action = 1; selected_action <= 4; selected_action++)
			assert(stela_test_traps(changed_callback_context));
	}
	stela_linux_enter(&stela_linux_bare);
	const struct firmware *firmware = (const struct firmware *)1;
	assert(firmware_request_nowarn(&firmware, request_name, NULL) == -ENOENT);
	assert(!firmware);
	release_firmware(NULL);
	stela_linux_exit();
	independent_lifetime();
	large_snapshot();
	errors_and_shapes();
	allocation_failure();
	nonquiescent_refusal();
	assert(!live_snapshots && allocated_bytes == released_bytes);
	printf("Linux firmware: owned snapshots, cross-owner lifetime, large payloads, errors, failure and context passed\n");
	return 0;
}
#endif
