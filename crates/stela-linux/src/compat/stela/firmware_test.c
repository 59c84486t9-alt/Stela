// SPDX-License-Identifier: MIT
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

static const struct stela_linux_owner canonical_owner;
static struct fixture *current_fixture;

struct fixture {
	struct device device;
	unsigned int device_releases, authority_releases;
	const u8 *data;
	size_t size;
	unsigned int requests, messages, refusals;
	int status, level, callback_action;
	char message[160];
};

/* C-only boundary model. The production strong symbol is Rust's immutable
 * exact-target Catalog lookup; this model never constructs a native grant. */
int stela_linux_firmware_image(const void *authority, const char *name,
                              const u8 **data, size_t *size)
{
	struct fixture *fixture = (struct fixture *)authority;
	assert(!strcmp(name, request_name));
	assert(!*data && !*size);
	fixture->requests++;
	*data = fixture->data;
	*size = fixture->size;
	if (fixture->callback_action == 1)
		preempt_disable();
	if (fixture->callback_action == 2) {
		stela_linux_exit();
		stela_linux_enter(&canonical_owner);
	}
	return fixture->status;
}

static void message(void *context, int level, const char *text)
{
	struct fixture *fixture = current_fixture;
	(void)context;
	assert(fixture);
	fixture->messages++;
	fixture->level = level;
	assert(strlen(text) < sizeof(fixture->message));
	memcpy(fixture->message, text, strlen(text) + 1);
}

static void unsupported(void *context, const char *operation)
{
	struct fixture *fixture = current_fixture;
	(void)context;
	if (!fixture)
		__builtin_trap();
	assert(!strcmp(operation, "firmware request context"));
	fixture->refusals++;
}

static const struct stela_linux_services services = {
	.log = message, .unsupported = unsupported,
};

static const struct stela_linux_owner canonical_owner = {.services = &services};
static void device_released(struct device *device)
{
	container_of(device, struct fixture, device)->device_releases++;
}
static void authority_released(void *authority)
{
	((struct fixture *)authority)->authority_releases++;
}
static void fixture_bind(struct fixture *fixture)
{
	fixture->device.release = device_released;
	device_initialize(&fixture->device);
	assert(!stela_linux_device_bind(&fixture->device, fixture, authority_released));
}
static void fixture_unbind(struct fixture *fixture)
{
	stela_linux_device_close(&fixture->device);
	put_device(&fixture->device);
	assert(fixture->device_releases == 1 && fixture->authority_releases == 1);
}
static void fixture_enter(struct fixture *fixture)
{
	current_fixture = fixture;
	stela_linux_enter(&canonical_owner);
	fixture_bind(fixture);
}
static void fixture_exit(struct fixture *fixture)
{
	fixture_unbind(fixture);
	stela_linux_exit();
	current_fixture = NULL;
}

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
	const struct firmware *wrappers[ARRAY_SIZE(requests)];
	fixture_enter(fixture);
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		fill(backing + 1, size, (unsigned int)i);
		wrappers[i] = (const struct firmware *)1;
		assert(!requests[i](&wrappers[i], request_name, &fixture->device));
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
	fixture_exit(fixture);
	/* Destroy the actual context and bytes, not just a logical owner flag. */
	memset(backing, 0xd3, size + 2);
	memset(fixture, 0xa5, sizeof(*fixture));
	free(backing);
	free(fixture);
	for (size_t i = 0; i < ARRAY_SIZE(wrappers); i++)
		check(wrappers[i], size, (unsigned int)i);
	struct fixture second = {};
	fixture_enter(&second);
	for (size_t i = 0; i < ARRAY_SIZE(wrappers); i++)
		release_firmware(wrappers[i]);
	assert(!second.requests && !second.messages && !live_snapshots);
	fixture_exit(&second);
}

static void large_snapshot(void)
{
	/* Exercise the real path beyond the raw allocator's 4 MiB upper bound. */
	const size_t size = KMALLOC_MAX_SIZE + PAGE_SIZE + 1;
	u8 *backing = calloc(size, 1);
	assert(backing);
	fill(backing, size, 19);
	struct fixture fixture = {.data = backing, .size = size};
	const struct firmware *firmware;
	fixture_enter(&fixture);
	assert(!firmware_request_nowarn(&firmware, request_name, &fixture.device));
	fixture_exit(&fixture);
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
	fixture_enter(&fixture);
	const int errors[] = {-ENOENT, -EBADMSG, -EINVAL, -EIO, -ENOMEM};
	for (size_t i = 0; i < ARRAY_SIZE(errors); i++) {
		fixture.status = errors[i];
		for (size_t j = 0; j < ARRAY_SIZE(requests); j++) {
			unsigned int before = fixture.messages;
			size_t calls = allocation_calls;
			const struct firmware *firmware = (const struct firmware *)1;
			assert(requests[j](&firmware, request_name, &fixture.device) == errors[i]);
			assert(!firmware && allocation_calls == calls && !live_snapshots);
			assert(fixture.messages == before + (j == 0 ? 1U : 0U));
			if (!j) {
				char expected[160];
				snprintf(expected, sizeof(expected),
					 "Direct firmware load for %s failed with error %d\n",
					 request_name, errors[i]);
				assert(fixture.level == LOGLEVEL_WARNING);
				/* Device diagnostics may add the original device prefix. */
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
			assert(requests[j](&firmware, request_name, &fixture.device) == shapes[i].status);
			assert(!firmware && !live_snapshots && allocation_calls == calls);
			assert(fixture.messages == before);
		}
	}
	/* Invalid public inputs never reach the unsafe provider. */
	unsigned int before = fixture.requests;
	for (size_t j = 0; j < ARRAY_SIZE(requests); j++) {
		const struct firmware *firmware = (const struct firmware *)1;
		assert(requests[j](NULL, request_name, &fixture.device) == -EINVAL);
		assert(requests[j](&firmware, NULL, NULL) == -EINVAL && !firmware);
		firmware = (const struct firmware *)1;
		assert(requests[j](&firmware, "", NULL) == -EINVAL && !firmware);
	}
	assert(fixture.requests == before);
	fixture_exit(&fixture);
}

static void allocation_failure(void)
{
	u8 backing[31];
	fill(backing, sizeof(backing), 43);
	struct fixture fixture = {.data = backing, .size = sizeof(backing)};
	fixture_enter(&fixture);
	/* Keep a real live result across each failed independent acquisition. */
	const struct firmware *retained;
	assert(!request_firmware(&retained, request_name, &fixture.device));
	size_t calls = allocation_calls, bytes = allocated_bytes;
	fail_snapshot_allocation = true;
	for (size_t i = 0; i < ARRAY_SIZE(requests); i++) {
		const struct firmware *firmware = (const struct firmware *)1;
		unsigned int before = fixture.messages;
		assert(requests[i](&firmware, request_name, &fixture.device) == -ENOMEM);
		assert(!firmware && live_snapshots == 1 && allocation_calls == calls);
		assert(allocated_bytes == bytes && fixture.messages == before);
		check(retained, sizeof(backing), 43);
	}
	fail_snapshot_allocation = false;
	release_firmware(retained);
	const struct firmware *recovered;
	assert(!request_firmware(&recovered, request_name, &fixture.device));
	check(recovered, sizeof(backing), 43);
	release_firmware(recovered);
	assert(!live_snapshots);
	fixture_exit(&fixture);
}

static void nonquiescent_refusal(void)
{
	const u8 backing[] = {1, 2, 3};
	struct fixture fixture = {.data = backing, .size = sizeof(backing)};
	fixture_enter(&fixture);
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
			assert(requests[i](&firmware, request_name, &fixture.device) == -EOPNOTSUPP);
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
	fixture_exit(&fixture);
}

struct child_fixture {
	struct device device;
	unsigned int releases;
};
static void child_released(struct device *device)
{
	container_of(device, struct child_fixture, device)->releases++;
}
static void exact_routes_and_late_parent(void)
{
	u8 first_bytes[] = {1, 2, 3}, second_bytes[] = {9, 8, 7};
	struct fixture first = {.data = first_bytes, .size = sizeof(first_bytes)};
	struct fixture second = {.data = second_bytes, .size = sizeof(second_bytes)};
	struct child_fixture child = {};
	struct child_fixture unknown = {};
	fixture_enter(&first);
	unknown.device.release = child_released;
	device_initialize(&unknown.device);
	fixture_bind(&second);
	child.device.release = child_released;
	device_initialize(&child.device);
	/* Match original device/faux ordering: parent can be supplied after
	 * initialize; add must use that actual retained registered parent. */
	child.device.parent = &first.device;
	assert(!dev_set_name(&child.device, "unrelated-visible-name"));
	assert(!device_add(&child.device));
	const struct firmware *a = NULL, *b = NULL, *refused = NULL;
	assert(!firmware_request_nowarn(&a, request_name, &child.device));
	assert(!firmware_request_nowarn(&b, request_name, &second.device));
	assert(first.requests == 1 && second.requests == 1);
	assert(!memcmp(a->data, first_bytes, sizeof(first_bytes)));
	assert(!memcmp(b->data, second_bytes, sizeof(second_bytes)));
	assert(a != b && a->data != b->data);
	/* Unknown/NULL/closed originals cannot borrow some current radio route. */
	assert(firmware_request_nowarn(&refused, request_name, &unknown.device) == -ENODEV && !refused);
	assert(firmware_request_nowarn(&refused, request_name, NULL) == -ENODEV && !refused);
	stela_linux_device_close(&first.device);
	assert(firmware_request_nowarn(&refused, request_name, &child.device) == -ENODEV && !refused);
	assert(first.requests == 1 && second.requests == 1);
	device_del(&child.device);
	put_device(&child.device);
	assert(child.releases == 1);
	put_device(&unknown.device);
	assert(unknown.releases == 1);
	fixture_unbind(&second);
	fixture_exit(&first);
	/* Both real source registrations are gone; independent copies remain. */
	assert(!memcmp(a->data, first_bytes, sizeof(first_bytes)));
	assert(!memcmp(b->data, second_bytes, sizeof(second_bytes)));
	release_firmware(a);
	release_firmware(b);
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
	stela_linux_enter(&canonical_owner);
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
	fixture_enter(&fixture);
	const struct firmware *firmware;
	(void)requests[selected_request](&firmware, request_name, &fixture.device);
}

int main(void)
{
	assert(!stela_linux_kernel_claim(&canonical_owner));
	assert(!stela_linux_kernel_environment(&canonical_owner));
	assert(!stela_linux_kernel_ready(&canonical_owner));
	release_firmware(NULL);
	for (selected_request = 0; selected_request < ARRAY_SIZE(requests); selected_request++) {
		assert(stela_test_traps(outside_owner));
		for (selected_context = 0; selected_context < 4; selected_context++)
			assert(stela_test_traps(strict_refusal));
		for (selected_action = 1; selected_action <= 4; selected_action++)
			assert(stela_test_traps(changed_callback_context));
	}
	stela_linux_enter(&canonical_owner);
	const struct firmware *firmware = (const struct firmware *)1;
	assert(firmware_request_nowarn(&firmware, request_name, NULL) == -ENODEV);
	assert(!firmware);
	release_firmware(NULL);
	stela_linux_exit();
	exact_routes_and_late_parent();
	independent_lifetime();
	large_snapshot();
	errors_and_shapes();
	allocation_failure();
	nonquiescent_refusal();
	assert(!live_snapshots && allocated_bytes == released_bytes);
	printf("Linux firmware: owned snapshots, exact authority, owner-independent lifetime, large payloads, errors, failure and context passed\n");
	return 0;
}
