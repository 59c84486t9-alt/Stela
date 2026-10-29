// SPDX-License-Identifier: GPL-2.0
/* Hosted lifecycle fixtures for unchanged pinned Linux kobject/uevent.
 * Synthetic image/namespace facts qualify no native image, task or GPU. */
#include <linux/bug.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/kobject.h>
#include <linux/ns_common.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/test.h>

/* Only these exact static bytes may be borrowed in this finite executable.
 * No range registration or native image/permission authority is inferred. */
static const char borrowed_name[] = "borrowed-name";
static const char renamed_name[] = "renamed";
static bool fixture_registered;
bool stela_linux_is_rodata(const void *pointer)
{
	if (!fixture_registered)
		__builtin_trap();
	unsigned long address = (unsigned long)pointer;
	const struct { const char *base; size_t size; } names[] = {
		{borrowed_name, sizeof(borrowed_name)}, {renamed_name, sizeof(renamed_name)},
	};
	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		unsigned long base = (unsigned long)names[i].base;
		if (address >= base && address - base < names[i].size)
			return true;
	}
	return false;
}

bool stela_linux_heap_try_available(void) { return false; }
void *stela_linux_heap_try_alloc(size_t size, size_t align)
{
	(void)size; (void)align;
	__builtin_trap();
}

/* Observe the original real environment after all original mutations, while
 * its actual heap block is live. Rebase copied pointers before freeing it. */
static const struct kobj_uevent_env *pending_environment;
static struct kobj_uevent_env captured_environment;
static unsigned int captured_environments;
static void capture_environment(void)
{
	const struct kobj_uevent_env *env = pending_environment;
	assert(env && env->envp_idx >= 0 && env->envp_idx <= UEVENT_NUM_ENVP);
	assert(env->buflen >= 0 && env->buflen <= UEVENT_BUFFER_SIZE);
	memcpy(&captured_environment, env, sizeof(*env));
	for (int i = 0; i < env->envp_idx; i++) {
		assert(env->envp[i] >= env->buf && env->envp[i] < env->buf + env->buflen);
		size_t offset = (size_t)(env->envp[i] - env->buf);
		captured_environment.envp[i] = captured_environment.buf + offset;
	}
	for (size_t i = 0; i < ARRAY_SIZE(captured_environment.argv); i++)
		captured_environment.argv[i] = NULL;
	pending_environment = NULL;
	captured_environments++;
}

struct heap_record {
	void *pointer;
	size_t size;
	size_t align;
};

static struct heap_record heap_records[128];
static size_t heap_fail_after = SIZE_MAX;
static size_t heap_live;
static size_t heap_released;
static unsigned int warnings;

void *stela_linux_heap_alloc(size_t size, size_t align)
{
	if (!heap_fail_after)
		return NULL;
	if (heap_fail_after != SIZE_MAX)
		heap_fail_after--;
	struct heap_record *record = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(heap_records); i++) {
		if (!heap_records[i].pointer) {
			record = heap_records + i;
			break;
		}
	}
	if (!record)
		return NULL;
	size_t actual_align = max_t(size_t, align, sizeof(void *));
	assert(actual_align && !(actual_align & (actual_align - 1)));
	assert(size && size <= SIZE_MAX - actual_align + 1);
	void *pointer = aligned_alloc(actual_align, (size + actual_align - 1) & ~(actual_align - 1));
	if (!pointer)
		return NULL;
	memset(pointer, 0, size);
	*record = (struct heap_record){.pointer = pointer, .size = size, .align = align};
	heap_live++;
	return pointer;
}

void stela_linux_heap_free(void *pointer, size_t size, size_t align)
{
	for (size_t i = 0; i < ARRAY_SIZE(heap_records); i++) {
		struct heap_record *record = heap_records + i;
		if (record->pointer != pointer)
			continue;
		assert(record->size == size && record->align == align && heap_live);
		if (pending_environment) {
			unsigned long base = (unsigned long)pointer;
			unsigned long address = (unsigned long)pending_environment;
			if (address >= base && size >= sizeof(*pending_environment) &&
				address - base <= size - sizeof(*pending_environment))
				capture_environment();
		}
		memset(pointer, 0xd3, size);
		free(pointer);
		*record = (struct heap_record){0};
		heap_live--;
		heap_released++;
		return;
	}
	assert(false);
}

__noreturn void stela_test_fail(const char *file, int line, const char *condition)
{
	printf("%s:%d: assertion failed: %s\n", file, line, condition);
	__builtin_trap();
}

static void warning(void *context, const char *file, int line, const char *condition)
{
	(void)context;
	assert(file && line > 0 && condition);
	warnings++;
}

static_assert(!IS_ENABLED(CONFIG_SYSFS));
static_assert(!IS_ENABLED(CONFIG_KERNFS));
static_assert(!IS_ENABLED(CONFIG_NET));
static_assert(!IS_ENABLED(CONFIG_UEVENT_HELPER));
static_assert(!IS_ENABLED(CONFIG_DEBUG_KOBJECT_RELEASE));
static_assert(!IS_ENABLED(CONFIG_MULTIUSER));

#define OBJECT_GUARD 0x73656c61U

struct fixture_object {
	struct kobject object;
	u32 guard;
	unsigned int id;
};

struct fixture_set {
	struct kset set;
	u32 guard;
};

static unsigned int released_ids[128];
static size_t released_count;
static unsigned int visibility_calls;
static struct fixture_object *protected_parent;

static void release_object(struct kobject *object)
{
	struct fixture_object *fixture = container_of(object, struct fixture_object, object);
	assert(fixture->guard == OBJECT_GUARD && !kref_read(&object->kref));
	assert(!object->state_in_sysfs && list_empty(&object->entry));
	assert(released_count < ARRAY_SIZE(released_ids));
	if (fixture->id == 2) {
		assert(!strcmp(kobject_name(object), "child!node-2"));
		assert(protected_parent && protected_parent->guard == OBJECT_GUARD);
		assert(kref_read(&protected_parent->object.kref) == 1);
	}
	released_ids[released_count++] = fixture->id;
	fixture->guard = 0;
	kfree(fixture);
}

static void release_set(struct kobject *object)
{
	struct fixture_set *fixture = container_of(to_kset(object), struct fixture_set, set);
	assert(fixture->guard == OBJECT_GUARD && !kref_read(&object->kref));
	assert(list_empty(&fixture->set.list) && !object->state_in_sysfs);
	assert(!strcmp(kobject_name(object), "set-3"));
	assert(released_count < ARRAY_SIZE(released_ids));
	released_ids[released_count++] = 3;
	fixture->guard = 0;
	kfree(fixture);
}

static umode_t visible(struct kobject *object, struct attribute *attribute, int index)
{
	(void)object;
	(void)attribute;
	(void)index;
	visibility_calls++;
	return 0444;
}

static ssize_t attribute_show(struct kobject *object, struct kobj_attribute *attribute, char *buffer)
{
	(void)attribute;
	struct fixture_object *fixture = container_of(object, struct fixture_object, object);
	return scnprintf(buffer, PAGE_SIZE, "%u\n", fixture->id);
}

static ssize_t attribute_store(struct kobject *object, struct kobj_attribute *attribute,
			       const char *buffer, size_t count)
{
	(void)attribute;
	struct fixture_object *fixture = container_of(object, struct fixture_object, object);
	if (count != 1 || buffer[0] < '0' || buffer[0] > '9')
		return -EINVAL;
	fixture->id = (unsigned int)(buffer[0] - '0');
	return (ssize_t)count;
}

static struct kobj_attribute value_attribute = {
	.attr = {.name = "value", .mode = 0644}, .show = attribute_show, .store = attribute_store,
};
static struct attribute *attributes[] = {&value_attribute.attr, NULL};
static const struct attribute_group group = {.attrs = attributes, .is_visible = visible};
static const struct attribute_group *groups[] = {&group, NULL};
static const struct kobj_type object_type = {
	.release = release_object, .sysfs_ops = &kobj_sysfs_ops, .default_groups = groups,
};
static const struct kobj_type set_type = {.release = release_set, .sysfs_ops = &kobj_sysfs_ops};

static bool filter_accept = true;
static bool event_fail;
static bool event_no_name;
static unsigned int filter_calls;
static unsigned int event_calls;
static char last_action[32];
static char last_path[96];

static int event_filter(const struct kobject *object)
{
	assert(object->state_initialized);
	filter_calls++;
	return filter_accept;
}

static const char *event_name(const struct kobject *object)
{
	assert(object->state_initialized);
	return event_no_name ? NULL : "stela-test";
}

static int event_environment(const struct kobject *object, struct kobj_uevent_env *environment)
{
	assert(object->state_initialized && environment->envp_idx >= 3);
	assert(!strncmp(environment->envp[0], "ACTION=", 7));
	assert(!strncmp(environment->envp[1], "DEVPATH=", 8));
	assert(!strcmp(environment->envp[2], "SUBSYSTEM=stela-test"));
	snprintf(last_action, sizeof(last_action), "%s", environment->envp[0] + 7);
	snprintf(last_path, sizeof(last_path), "%s", environment->envp[1] + 8);
	event_calls++;
	assert(!pending_environment);
	pending_environment = environment;
	if (event_fail)
		return -EIO;
	return add_uevent_var(environment, "FIXTURE=%u", 1U);
}

static const struct kset_uevent_ops events = {
	.filter = event_filter, .name = event_name, .uevent = event_environment,
};

static struct fixture_set *new_set(void)
{
	struct fixture_set *fixture = kzalloc_obj(*fixture);
	assert(fixture);
	fixture->guard = OBJECT_GUARD;
	fixture->set.kobj.ktype = &set_type;
	fixture->set.uevent_ops = &events;
	assert(!kobject_set_name(&fixture->set.kobj, "set-%u", 3U));
	assert(!kset_register(&fixture->set));
	return fixture;
}

static struct fixture_object *new_object(unsigned int id, struct kobject *parent, struct kset *set,
					 const char *name)
{
	struct fixture_object *fixture = kzalloc_obj(*fixture);
	assert(fixture);
	fixture->guard = OBJECT_GUARD;
	fixture->id = id;
	fixture->object.kset = set;
	assert(!kobject_init_and_add(&fixture->object, &object_type, parent, "%s-%u", name, id));
	return fixture;
}

static void reference_and_release_order(void)
{
	size_t before = released_count;
	struct fixture_object *root = new_object(1, NULL, NULL, "root");
	struct fixture_set *set = new_set();
	struct fixture_object *child = new_object(2, &root->object, &set->set, "child/node");
	assert(!strcmp(kobject_name(&child->object), "child!node-2"));
	assert(kref_read(&root->object.kref) == 2 && kref_read(&set->set.kobj.kref) == 2);
	struct kobject *found = kset_find_obj(&set->set, "child!node-2");
	assert(found == &child->object && kref_read(&found->kref) == 2);
	kobject_put(found);
	assert(!kset_find_obj(&set->set, "missing"));
	char *path = kobject_get_path(&child->object, GFP_KERNEL);
	assert(path && !strcmp(path, "/root-1/child!node-2"));
	kfree(path);
	assert(child->object.state_in_sysfs && !child->object.sd && !visibility_calls);
	char output[PAGE_SIZE];
	assert(kobj_sysfs_ops.show(&child->object, &value_attribute.attr, output) == 2);
	assert(!strcmp(output, "2\n"));
	assert(kobj_sysfs_ops.store(&child->object, &value_attribute.attr, "8", 1) == 1);
	assert(child->id == 8);
	struct kobj_attribute absent = {.attr = {.name = "absent"}};
	assert(kobj_sysfs_ops.show(&child->object, &absent.attr, output) == -EIO);
	assert(kobj_sysfs_ops.store(&child->object, &absent.attr, "x", 1) == -EIO);
	child->id = 2;
	assert(kobject_get(&child->object) == &child->object);
	kobject_put(&root->object);
	kset_unregister(&set->set);
	assert(released_count == before && kref_read(&child->object.kref) == 2);
	assert(kref_read(&set->set.kobj.kref) == 1 && !set->set.kobj.state_in_sysfs);
	kobject_put(&child->object);
	assert(released_count == before);
	protected_parent = root;
	kobject_put(&child->object);
	protected_parent = NULL;
	assert(released_count == before + 3);
	assert(released_ids[before] == 3 && released_ids[before + 1] == 2 && released_ids[before + 2] == 1);
	assert(!heap_live);
}

static void allocation_and_name_rollback(void)
{
	struct fixture_object *root = new_object(10, NULL, NULL, "parent");
	struct fixture_set *set = new_set();
	size_t baseline = heap_live;
	for (size_t failure = 0; failure < 2; failure++) {
		char mutable_name[] = "dynamic";
		heap_fail_after = failure;
		assert(!kobject_create_and_add(mutable_name, &root->object));
		heap_fail_after = SIZE_MAX;
		assert(heap_live == baseline && kref_read(&root->object.kref) == 1);
	}
	struct fixture_object *failed = kzalloc_obj(*failed);
	assert(failed);
	failed->guard = OBJECT_GUARD;
	failed->id = 4;
	failed->object.kset = &set->set;
	heap_fail_after = 0;
	assert(kobject_init_and_add(&failed->object, &object_type, &root->object, "fail-%u", 4U) == -ENOMEM);
	heap_fail_after = SIZE_MAX;
	assert(failed->object.state_initialized && !failed->object.state_in_sysfs);
	assert(!failed->object.name && !failed->object.parent && list_empty(&set->set.list));
	assert(kref_read(&root->object.kref) == 1 && kref_read(&set->set.kobj.kref) == 1);
	kobject_put(&failed->object);
	assert(heap_live == baseline);
	struct fixture_object *named = kzalloc_obj(*named);
	assert(named);
	named->guard = OBJECT_GUARD;
	named->id = 5;
	kobject_init(&named->object, &object_type);
	assert(!kobject_set_name(&named->object, "old-%u", 5U));
	const char *old = kobject_name(&named->object);
	baseline = heap_live;
	heap_fail_after = 1; /* Format succeeds; slash-copy allocation fails. */
	assert(kobject_set_name(&named->object, "new/%u", 5U) == -ENOMEM);
	heap_fail_after = SIZE_MAX;
	assert(kobject_name(&named->object) == old && !strcmp(old, "old-5") && heap_live == baseline);
	assert(!kobject_set_name(&named->object, "new/%u", 5U));
	assert(!strcmp(kobject_name(&named->object), "new!5"));
	kobject_put(&named->object);
	kset_unregister(&set->set);
	kobject_put(&root->object);
	assert(!heap_live);
}

static void event_and_move_effects(void)
{
	struct fixture_set *set = new_set();
	struct fixture_object *left = new_object(11, NULL, NULL, "left");
	struct fixture_object *right = new_object(12, NULL, NULL, "right");
	struct fixture_object *child = new_object(13, &left->object, &set->set, "child");
	s64 sequence = atomic64_read(&uevent_seqnum);
	unsigned int calls = event_calls;
	child->object.uevent_suppress = true;
	assert(!kobject_uevent(&child->object, KOBJ_ADD));
	assert(event_calls == calls && atomic64_read(&uevent_seqnum) == sequence);
	child->object.uevent_suppress = false;
	filter_accept = false;
	assert(!kobject_uevent(&child->object, KOBJ_ADD) && event_calls == calls);
	filter_accept = true;
	event_fail = true;
	assert(kobject_uevent(&child->object, KOBJ_ADD) == -EIO);
	assert(!child->object.state_add_uevent_sent && atomic64_read(&uevent_seqnum) == sequence);
	event_fail = false;
	assert(!kobject_uevent(&child->object, KOBJ_ADD));
	assert(child->object.state_add_uevent_sent && atomic64_read(&uevent_seqnum) == sequence + 1);
	assert(!strcmp(last_action, "add") && !strcmp(last_path, "/left-11/child-13"));
	assert(!kobject_rename(&child->object, renamed_name));
	assert(!strcmp(kobject_name(&child->object), "renamed") && !strcmp(last_action, "move"));
	assert(!kobject_move(&child->object, &right->object));
	assert(child->object.parent == &right->object);
	assert(kref_read(&left->object.kref) == 1 && kref_read(&right->object.kref) == 2);
	assert(!strcmp(last_path, "/right-12/renamed"));
	kobject_put(&child->object); /* Real automatic REMOVE callback before release. */
	assert(!strcmp(last_action, "remove") && !strcmp(last_path, "/right-12/renamed"));
	kobject_put(&left->object);
	kobject_put(&right->object);
	kset_unregister(&set->set);
	assert(!heap_live);
}


static const char *environment_value(const char *key)
{
	size_t length = strlen(key);
	for (int i = 0; i < captured_environment.envp_idx; i++) {
		const char *entry = captured_environment.envp[i];
		if (!strncmp(entry, key, length) && entry[length] == '=')
			return entry + length + 1;
	}
	return NULL;
}

static void names_and_explicit_deletion(void)
{
	struct fixture_object *root = new_object(20, NULL, NULL, "parent");
	struct fixture_set *set = new_set();
	struct fixture_object *child = new_object(21, NULL, &set->set, "member");
	assert(child->object.parent == &set->set.kobj);
	assert(kref_read(&set->set.kobj.kref) == 3); /* parent and membership */
	assert(!list_empty(&set->set.list));
	kobject_del(&child->object);
	assert(!child->object.parent && !child->object.state_in_sysfs);
	assert(list_empty(&child->object.entry) && list_empty(&set->set.list));
	assert(kref_read(&child->object.kref) == 1 && kref_read(&set->set.kobj.kref) == 1);
	kobject_put(&child->object);

	/* Original !SYSFS does not enforce directory-name uniqueness. */
	struct fixture_object *a = new_object(22, &root->object, &set->set, "same");
	struct fixture_object *b = new_object(22, &root->object, &set->set, "same");
	struct kobject *found = kset_find_obj(&set->set, "same-22");
	assert(found == &a->object);
	kobject_put(found);
	kobject_put(&a->object);
	found = kset_find_obj(&set->set, "same-22");
	assert(found == &b->object);
	kobject_put(found);
	kobject_put(&b->object);

	struct fixture_object *named = kzalloc_obj(*named);
	assert(named);
	named->guard = OBJECT_GUARD;
	named->id = 23;
	kobject_init(&named->object, &object_type);
	assert(!kobject_get_path(&named->object, GFP_KERNEL));
	assert(!kobject_set_name(&named->object, "%s", borrowed_name));
	assert(kobject_name(&named->object) == borrowed_name);
	/* NULL format with existing name is the original explicit no-op. */
	const char *old = named->object.name;
	int (*set_name)(struct kobject *, const char *, ...) = kobject_set_name;
	int (*add)(struct kobject *, struct kobject *, const char *, ...) = kobject_add;
	assert(!set_name(&named->object, NULL) && named->object.name == old);
	assert(!add(&named->object, &root->object, NULL));
	assert(kref_read(&root->object.kref) == 2);
	kobject_put(&named->object); /* Actual borrowed-name free is suppressed. */
	assert(kref_read(&root->object.kref) == 1);
	assert(!kobject_get(NULL) && !kobject_get_unless_zero(NULL));
	kobject_put(NULL);
	kobject_del(NULL);
	kset_unregister(NULL);
	assert(kobject_add(NULL, NULL, "unused") == -EINVAL);
	assert(kset_register(NULL) == -EINVAL);
	struct kset no_type = {};
	assert(kset_register(&no_type) == -EINVAL);
	kset_unregister(&set->set);
	kobject_put(&root->object);
	assert(!heap_live);
}

static void event_environment_and_syntax(void)
{
	struct fixture_set *set = new_set();
	struct fixture_object *child = new_object(30, NULL, &set->set, "event");
	size_t baseline = heap_live;
	s64 initial_sequence = atomic64_read(&uevent_seqnum);
	unsigned int initial_calls = event_calls;
	event_no_name = true;
	assert(!kobject_uevent(&child->object, KOBJ_ADD));
	event_no_name = false;
	assert(heap_live == baseline && event_calls == initial_calls);
	assert(!child->object.state_add_uevent_sent && atomic64_read(&uevent_seqnum) == initial_sequence);
	char huge[UEVENT_BUFFER_SIZE + 1];
	memset(huge, 'x', sizeof(huge)); huge[UEVENT_BUFFER_SIZE] = '\0';
	char *too_large[] = {huge, NULL};
	assert(kobject_uevent_env(&child->object, KOBJ_ADD, too_large) == -ENOMEM);
	assert(heap_live == baseline && event_calls == initial_calls && !pending_environment);
	assert(!child->object.state_add_uevent_sent && atomic64_read(&uevent_seqnum) == initial_sequence);
	char *external[] = {"MODALIAS=first", "KEEP=one", "MODALIAS=last", "TAIL=end", NULL};
	unsigned int captures = captured_environments;
	s64 sequence = atomic64_read(&uevent_seqnum);
	assert(!kobject_uevent_env(&child->object, KOBJ_UNBIND, external));
	assert(captured_environments == captures + 1 && !pending_environment);
	assert(!environment_value("MODALIAS"));
	assert(!strcmp(environment_value("KEEP"), "one"));
	assert(!strcmp(environment_value("TAIL"), "end"));
	assert(!strcmp(environment_value("ACTION"), "unbind"));
	assert(!strcmp(environment_value("DEVPATH"), "/set-3/event-30"));
	assert(!strcmp(environment_value("SUBSYSTEM"), "stela-test"));
	assert(!strcmp(environment_value("FIXTURE"), "1"));
	char number[32];
	snprintf(number, sizeof(number), "%lld", (long long)(sequence + 1));
	assert(!strcmp(environment_value("SEQNUM"), number));
	assert(captured_environment.envp_idx == 7);
	size_t position = 0;
	for (int i = 0; i < captured_environment.envp_idx; i++) {
		assert(captured_environment.envp[i] == captured_environment.buf + position);
		position += strlen(captured_environment.envp[i]) + 1;
	}
	assert(position == (size_t)captured_environment.buflen);

	static const char *const actions[] = {
		"add", "remove", "change", "move", "online", "offline", "bind", "unbind",
	};
	for (size_t i = 0; i < ARRAY_SIZE(actions); i++) {
		char input[32];
		int length = snprintf(input, sizeof(input), "%s\n", actions[i]);
		assert(length > 0);
		sequence = atomic64_read(&uevent_seqnum);
		assert(!kobject_synth_uevent(&child->object, input, (size_t)length));
		assert(!strcmp(environment_value("ACTION"), actions[i]));
		assert(!strcmp(environment_value("SYNTH_UUID"), "0"));
		assert(atomic64_read(&uevent_seqnum) == sequence + 1);
	}
	static const char valid[] =
		"change 00112233-4455-6677-8899-aabbccddeeff KEY1=VALUE9 A=B";
	assert(!kobject_synth_uevent(&child->object, valid, sizeof(valid)));
	assert(!strcmp(environment_value("SYNTH_UUID"), "00112233-4455-6677-8899-aabbccddeeff"));
	assert(!strcmp(environment_value("SYNTH_ARG_KEY1"), "VALUE9"));
	assert(!strcmp(environment_value("SYNTH_ARG_A"), "B"));
	static const char *const invalid[] = {
		"", "ad", "nonsense", "change nope", "change 00112233-4455-6677-8899-aabbccddeeff ",
		"change 00112233-4455-6677-8899-aabbccddeeff A=",
		"change 00112233-4455-6677-8899-aabbccddeeff A_B=C",
		"change 00112233-4455-6677-8899-aabbccddeeff A=B-C",
	};
	for (size_t i = 0; i < ARRAY_SIZE(invalid); i++) {
		sequence = atomic64_read(&uevent_seqnum);
		captures = captured_environments;
		size_t baseline = heap_live;
		assert(kobject_synth_uevent(&child->object, invalid[i], strlen(invalid[i])) == -EINVAL);
		assert(atomic64_read(&uevent_seqnum) == sequence && captured_environments == captures);
		assert(!pending_environment && heap_live == baseline);
	}
	/* Full key and byte capacities exercise original bounded append errors.
	 * Truncated bytes may change on error; only logical index/length preserve. */
	struct kobj_uevent_env *env = kzalloc_obj(*env);
	assert(env);
	for (unsigned i = 0; i < UEVENT_NUM_ENVP; i++)
		assert(!add_uevent_var(env, "K%u=V", i));
	int used = env->buflen;
	unsigned int warned = warnings;
	assert(add_uevent_var(env, "OVER=V") == -ENOMEM);
	assert(env->envp_idx == UEVENT_NUM_ENVP && env->buflen == used && warnings == warned + 1);
	memset(env, 0, sizeof(*env));
	char full[UEVENT_BUFFER_SIZE + 1];
	memset(full, 'x', sizeof(full));
	full[UEVENT_BUFFER_SIZE] = '\0';
	warned = warnings;
	assert(add_uevent_var(env, "%s", full) == -ENOMEM);
	assert(!env->envp_idx && !env->buflen && warnings == warned + 1);
	full[UEVENT_BUFFER_SIZE - 1] = '\0';
	assert(!add_uevent_var(env, "%s", full));
	assert(env->envp_idx == 1 && env->buflen == UEVENT_BUFFER_SIZE);
	warned = warnings;
	assert(add_uevent_var(env, "%s", "") == -ENOMEM);
	assert(env->envp_idx == 1 && env->buflen == UEVENT_BUFFER_SIZE && warnings == warned + 1);
	kfree(env);
	kobject_put(&child->object);
	kset_unregister(&set->set);
	assert(!heap_live && !pending_environment);
}

static void allocation_failure_edges(void)
{
	for (size_t failure = 0; failure <= 5; failure++) {
		struct fixture_set *set = new_set();
		struct fixture_object *left = new_object(40, NULL, NULL, "left");
		struct fixture_object *right = new_object(41, NULL, NULL, "right");
		struct fixture_object *child = new_object(42, &left->object, &set->set, "child");
		const char *old_name = child->object.name;
		char new_name[] = "fresh-name";
		size_t baseline = heap_live;
		heap_fail_after = failure;
		int result = kobject_rename(&child->object, new_name);
		heap_fail_after = SIZE_MAX;
		if (failure < 3) {
			assert(result == -ENOMEM && child->object.name == old_name);
			assert(!strcmp(child->object.name, "child-42") && heap_live == baseline);
		} else {
			/* The original API ignores later uevent failure after rename. */
			assert(!result && !strcmp(child->object.name, new_name));
			assert(heap_live == baseline);
		}
		assert(kref_read(&child->object.kref) == 1 && child->object.parent == &left->object);
		assert(kref_read(&left->object.kref) == 2 && kref_read(&right->object.kref) == 1);
		kobject_put(&child->object);
		kobject_put(&left->object);
		kobject_put(&right->object);
		kset_unregister(&set->set);
		assert(!heap_live && !pending_environment);
	}
	for (size_t failure = 0; failure <= 4; failure++) {
		struct fixture_set *set = new_set();
		struct fixture_object *left = new_object(43, NULL, NULL, "left");
		struct fixture_object *right = new_object(44, NULL, NULL, "right");
		struct fixture_object *child = new_object(45, &left->object, &set->set, "child");
		size_t baseline = heap_live;
		heap_fail_after = failure;
		int result = kobject_move(&child->object, &right->object);
		heap_fail_after = SIZE_MAX;
		assert(heap_live == baseline && kref_read(&child->object.kref) == 1);
		if (failure < 2) {
			assert(result == -ENOMEM && child->object.parent == &left->object);
			assert(kref_read(&left->object.kref) == 2 && kref_read(&right->object.kref) == 1);
		} else {
			assert(!result && child->object.parent == &right->object);
			assert(kref_read(&left->object.kref) == 1 && kref_read(&right->object.kref) == 2);
		}
		kobject_put(&child->object);
		kobject_put(&left->object);
		kobject_put(&right->object);
		kset_unregister(&set->set);
		assert(!heap_live && !pending_environment);
	}
	struct fixture_set *set = new_set();
	struct fixture_object *child = new_object(46, NULL, &set->set, "child");
	for (size_t failure = 0; failure < 2; failure++) {
		size_t baseline = heap_live;
		s64 sequence = atomic64_read(&uevent_seqnum);
		heap_fail_after = failure;
		assert(kobject_uevent(&child->object, KOBJ_ADD) == (failure ? -ENOENT : -ENOMEM));
		heap_fail_after = SIZE_MAX;
		assert(heap_live == baseline && !child->object.state_add_uevent_sent);
		assert(atomic64_read(&uevent_seqnum) == sequence && !pending_environment);
	}
	char dynamic_name[] = "dynamic";
	struct kobject *dynamic = kobject_create_and_add(dynamic_name, &set->set.kobj);
	assert(dynamic && dynamic->parent == &set->set.kobj);
	kobject_put(dynamic);
	kobject_put(&child->object);
	kset_unregister(&set->set);
	assert(!heap_live);
}

static struct ns_common test_namespace;
static unsigned int namespace_grabs, namespace_drops;
static bool namespace_mount;
static bool may_mount(void) { return namespace_mount; }
static struct ns_common *grab_namespace(void)
{
	namespace_grabs++;
	return &test_namespace;
}
static const struct ns_common *initial_namespace(void) { return &test_namespace; }
static void drop_namespace(struct ns_common *ns)
{
	assert(ns == &test_namespace && namespace_grabs > namespace_drops);
	namespace_drops++;
}
static const struct kobj_ns_type_operations namespace_ops = {
	.type = KOBJ_NS_TYPE_NET, .current_may_mount = may_mount,
	.grab_current_ns = grab_namespace, .initial_ns = initial_namespace,
	.drop_ns = drop_namespace,
};
static const struct kobj_ns_type_operations *child_namespace(const struct kobject *object)
{
	assert(object);
	return &namespace_ops;
}
static const struct ns_common *object_namespace(const struct kobject *object)
{
	assert(object && object->parent);
	return &test_namespace;
}
static void ownership(const struct kobject *object, kuid_t *uid, kgid_t *gid)
{
	assert(object);
	*uid = KUIDT_INIT(41);
	*gid = KGIDT_INIT(42);
}
static const struct kobj_type namespace_type = {
	.release = release_object, .child_ns_type = child_namespace,
	.namespace = object_namespace, .get_ownership = ownership,
};

static const struct kobj_type ownership_type = {
	.release = release_object, .get_ownership = ownership,
};

static void namespace_and_ownership(void)
{
	assert(!kobj_ns_type_registered(KOBJ_NS_TYPE_NET));
	struct kobj_ns_type_operations invalid = namespace_ops;
	invalid.type = KOBJ_NS_TYPE_NONE;
	assert(kobj_ns_type_register(&invalid) == -EINVAL);
	invalid.type = KOBJ_NS_TYPES;
	assert(kobj_ns_type_register(&invalid) == -EINVAL);
	assert(!kobj_ns_type_register(&namespace_ops));
	assert(kobj_ns_type_register(&namespace_ops) == -EBUSY);
	assert(kobj_ns_type_registered(KOBJ_NS_TYPE_NET));
	assert(!kobj_ns_type_registered(KOBJ_NS_TYPE_NONE));
	namespace_mount = false;
	assert(!kobj_ns_current_may_mount(KOBJ_NS_TYPE_NET));
	namespace_mount = true;
	assert(kobj_ns_current_may_mount(KOBJ_NS_TYPE_NET));
	assert(kobj_ns_current_may_mount(KOBJ_NS_TYPE_NONE));
	assert(!kobj_ns_grab_current(KOBJ_NS_TYPE_NONE));
	struct ns_common *ns = kobj_ns_grab_current(KOBJ_NS_TYPE_NET);
	assert(ns == &test_namespace && namespace_grabs == 1);
	kobj_ns_drop(KOBJ_NS_TYPE_NET, ns);
	assert(namespace_drops == 1);
	kobj_ns_drop(KOBJ_NS_TYPE_NONE, ns);
	assert(namespace_drops == 1);

	struct fixture_object *root = kzalloc_obj(*root);
	struct fixture_object *child = kzalloc_obj(*child);
	assert(root && child);
	root->guard = child->guard = OBJECT_GUARD;
	root->id = 50; child->id = 51;
	assert(!kobject_init_and_add(&root->object, &namespace_type, NULL, "namespace-%u", root->id));
	assert(!kobject_init_and_add(&child->object, &namespace_type, &root->object, "namespace-%u", child->id));
	assert(kobj_child_ns_ops(&root->object) == &namespace_ops);
	assert(kobj_ns_ops(&child->object) == &namespace_ops);
	assert(kobject_namespace(&child->object) == &test_namespace);
	assert(!kobject_namespace(&root->object));
	kuid_t uid; kgid_t gid;
	kobject_get_ownership(&child->object, &uid, &gid);
	assert(uid.val == 41 && gid.val == 42);
	/* Original !MULTIUSER helpers expose root regardless of callback values;
	 * observing the stored callback output grants no native permissions. */
	assert(__kuid_val(uid) == 0 && __kgid_val(gid) == 0);
	/* Dynamic kset's original ktype has no namespace method. Its parent
	 * therefore supplies ownership but no child namespace requirement. */
	struct fixture_object *owning_root = kzalloc_obj(*owning_root);
	assert(owning_root);
	owning_root->guard = OBJECT_GUARD; owning_root->id = 52;
	assert(!kobject_init_and_add(&owning_root->object, &ownership_type, NULL,
								 "ownership-%u", owning_root->id));
	char dynamic[] = "owned-set";
	struct kset *set = kset_create_and_add(dynamic, NULL, &owning_root->object);
	assert(set);
	kobject_get_ownership(&set->kobj, &uid, &gid);
	assert(uid.val == 41 && gid.val == 42);
	/* Original !MULTIUSER helpers expose root regardless of callback values;
	 * observing the stored callback output grants no native permissions. */
	assert(__kuid_val(uid) == 0 && __kgid_val(gid) == 0);
	kset_unregister(set);
	kobject_put(&owning_root->object);
	kobject_put(&child->object);
	kobject_put(&root->object);
	assert(!heap_live);
}

int main(void)
{
	fixture_registered = true;
	const struct stela_linux_services services = {.warn = warning};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	reference_and_release_order();
	allocation_and_name_rollback();
	event_and_move_effects();
	names_and_explicit_deletion();
	event_environment_and_syntax();
	allocation_failure_edges();
	namespace_and_ownership();
	assert(!heap_live && heap_released && !visibility_calls && filter_calls);
	assert(!pending_environment && captured_environments && namespace_grabs == namespace_drops);
	stela_linux_exit();
	printf("Linux kobjects: original lifecycle, parent/kset/name/ref unwind, events and namespace callbacks passed\n");
	return 0;
}
