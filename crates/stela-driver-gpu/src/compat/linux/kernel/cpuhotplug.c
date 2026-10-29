// SPDX-License-Identifier: GPL-2.0
/* Serialized registration only, following Linux 7.2.12 kernel/cpu.c,
 * CPU control, (C) 2001, 2002, 2003, 2004 Rusty Russell.
 * Real CPU transition/callback invocation remains explicitly unavailable. */
#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/list.h>
#include <linux/cpuhotplug.h>
#include <linux/cpuhplock.h>
#include <linux/errno.h>
#include <stela/linux.h>

#if defined(CONFIG_SMP) || defined(CONFIG_HOTPLUG_CPU)
#error "CPUHP registry requires the serialized non-hotplug Linux profile"
#endif
static_assert(CONFIG_NR_CPUS == 1);

struct cpuhp_step {
	const char *name;
	union {
		int (*single)(unsigned int cpu);
		int (*multi)(unsigned int cpu, struct hlist_node *node);
	} startup;
	union {
		int (*single)(unsigned int cpu);
		int (*multi)(unsigned int cpu, struct hlist_node *node);
	} teardown;
	struct hlist_head list;
	bool cant_stop;
	bool multi_instance;
};

/* As in the original !SMP table, only the endpoints begin occupied. The
 * execution owner serializes every access; its exit is not CPU death.
 * Borrowed names, callback code and instance storage survive owner changes. */
static struct cpuhp_step steps[CPUHP_ONLINE + 1] = {
	[CPUHP_OFFLINE] = {.name = "offline"},
	[CPUHP_ONLINE] = {.name = "online"},
};

static void require_context(void)
{
	if (!stela_linux_quiescent())
		__builtin_trap();
}

static bool valid_state(enum cpuhp_state state)
{
	return state > CPUHP_OFFLINE && state < CPUHP_ONLINE;
}

static struct cpuhp_step *require_state(enum cpuhp_state state)
{
	if (!valid_state(state))
		__builtin_trap();
	return &steps[state];
}

static int refuse_invocation(void)
{
	stela_linux_unsupported("CPU hotplug callback invocation");
	return -EOPNOTSUPP;
}

/* Only a dynamic base in SETUP selects a free slot. Removal always addresses
 * the supplied slot, even when it equals a dynamic base. */
static int reserve_state(enum cpuhp_state first)
{
	enum cpuhp_state end = first == CPUHP_BP_PREPARE_DYN ?
		CPUHP_BP_PREPARE_DYN_END : CPUHP_AP_ONLINE_DYN_END;
	for (enum cpuhp_state state = first; state <= end; state++) {
		if (!steps[state].name)
			return state;
	}
	WARN(1, "No more dynamic states available for CPU hotplug\n");
	return -ENOSPC;
}

int __cpuhp_setup_state_cpuslocked(enum cpuhp_state state, const char *name, bool invoke,
				 int (*startup)(unsigned int cpu),
				 int (*teardown)(unsigned int cpu), bool multi_instance)
{
	require_context();
	if (!valid_state(state) || !name)
		return -EINVAL;
	/* Refuse before reservation or publication, even for NULL callbacks. */
	if (invoke)
		return refuse_invocation();
	bool dynamic = state == CPUHP_BP_PREPARE_DYN || state == CPUHP_AP_ONLINE_DYN;
	if (dynamic) {
		int selected = reserve_state(state);
		if (selected < 0)
			return selected;
		state = (enum cpuhp_state)selected;
	}
	struct cpuhp_step *step = &steps[state];
	if (step->name)
		return -EBUSY;
	step->startup.single = startup;
	step->teardown.single = teardown;
	step->name = name;
	step->multi_instance = multi_instance;
	INIT_HLIST_HEAD(&step->list);
	return dynamic ? state : 0;
}

int __cpuhp_setup_state(enum cpuhp_state state, const char *name, bool invoke,
			int (*startup)(unsigned int cpu), int (*teardown)(unsigned int cpu),
			bool multi_instance)
{
	/* The original !HOTPLUG_CPU cpus_read_lock/unlock are empty. */
	return __cpuhp_setup_state_cpuslocked(state, name, invoke, startup, teardown, multi_instance);
}

int __cpuhp_state_add_instance_cpuslocked(enum cpuhp_state state, struct hlist_node *node,
					bool invoke)
{
	require_context();
	struct cpuhp_step *step = require_state(state);
	if (!step->multi_instance)
		return -EINVAL;
	if (invoke)
		return refuse_invocation();
	if (!node)
		__builtin_trap();
	/* The public add API does not require node initialization: hlist_add_head
	 * overwrites both links. Detect our actual membership by identity without
	 * reading indeterminate incoming node bytes. The caller still owns valid
	 * unlinked storage; unrelated external-list membership is its precondition,
	 * not something that can be inferred from arbitrary old node bytes. */
	for (enum cpuhp_state registered = CPUHP_OFFLINE + 1; registered < CPUHP_ONLINE;
	     registered++) {
		for (struct hlist_node *member = steps[registered].list.first; member;
		     member = member->next) {
			if (member == node)
				__builtin_trap();
		}
	}
	hlist_add_head(node, &step->list);
	return 0;
}

int __cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node, bool invoke)
{
	return __cpuhp_state_add_instance_cpuslocked(state, node, invoke);
}

int __cpuhp_state_remove_instance(enum cpuhp_state state, struct hlist_node *node, bool invoke)
{
	require_context();
	struct cpuhp_step *step = require_state(state);
	if (!step->multi_instance)
		return -EINVAL;
	if (invoke)
		return refuse_invocation();
	if (!node)
		__builtin_trap();
	/* Find actual membership before dereferencing pprev. A foreign or already
	 * detached node cannot remove another state's node or an arbitrary pointer. */
	struct hlist_node **link = &step->list.first;
	while (*link && *link != node)
		link = &(*link)->next;
	if (!*link || node->pprev != link || (node->next && node->next->pprev != &node->next))
		__builtin_trap();
	hlist_del(node);
	return 0;
}

void __cpuhp_remove_state_cpuslocked(enum cpuhp_state state, bool invoke)
{
	require_context();
	struct cpuhp_step *step = require_state(state);
	if (invoke) {
		(void)refuse_invocation();
		/* Returning would let a caller unload still-registered callback code.
		 * The void API cannot return an unsupported errno. */
		__builtin_trap();
	}
	if (!hlist_empty(&step->list))
		__builtin_trap();
	step->startup.single = NULL;
	step->teardown.single = NULL;
	step->name = NULL;
	step->multi_instance = false;
	INIT_HLIST_HEAD(&step->list);
}

void __cpuhp_remove_state(enum cpuhp_state state, bool invoke)
{
	__cpuhp_remove_state_cpuslocked(state, invoke);
}

#ifdef STELA_LINUX_CPUHP_TEST
#include <linux/array_size.h>
#include <linux/bottom_half.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <stela/test.h>

static unsigned int callback_calls;
static unsigned int refusals;
static unsigned int warnings;
static struct cpuhp_step snapshot[ARRAY_SIZE(steps)];
static struct hlist_node *watched_node;
static struct hlist_node node_snapshot;

static int startup(unsigned int cpu)
{
	(void)cpu;
	callback_calls++;
	return 0;
}

static int teardown(unsigned int cpu)
{
	(void)cpu;
	callback_calls++;
	return 0;
}

static int multi_startup(unsigned int cpu, struct hlist_node *node)
{
	(void)node;
	return startup(cpu);
}

static int multi_teardown(unsigned int cpu, struct hlist_node *node)
{
	(void)node;
	return teardown(cpu);
}

static void take_snapshot(struct hlist_node *node)
{
	memcpy(snapshot, steps, sizeof(steps));
	watched_node = node;
	if (node)
		memcpy(&node_snapshot, node, sizeof(*node));
}

static void unchanged(void)
{
	assert(!memcmp(snapshot, steps, sizeof(steps)));
	if (watched_node)
		assert(!memcmp(&node_snapshot, watched_node, sizeof(node_snapshot)));
	assert(!callback_calls);
}

static void unsupported(void *context, const char *operation)
{
	assert(context == &refusals && !strcmp(operation, "CPU hotplug callback invocation"));
	/* This also checks void invocation removal immediately before its trap,
	 * in the child, rather than relying on fork's private-copy isolation. */
	unchanged();
	refusals++;
}

static void warn(void *context, const char *file, int line, const char *condition)
{
	assert(context == &refusals && strstr(file, "cpuhotplug.c") && line > 0);
	/* WARN with formatted text supplies an empty condition; WARN_ON instead
	 * supplies the stringized expression in this compatibility architecture. */
	assert(!strcmp(condition, ""));
	unchanged();
	warnings++;
}

static void empty_slot(enum cpuhp_state state)
{
	assert(!steps[state].name && !steps[state].startup.single && !steps[state].teardown.single);
	assert(!steps[state].multi_instance && !steps[state].cant_stop);
	assert(hlist_empty(&steps[state].list));
}

static void empty_registry(void)
{
	assert(!strcmp(steps[CPUHP_OFFLINE].name, "offline"));
	assert(!strcmp(steps[CPUHP_ONLINE].name, "online"));
	for (enum cpuhp_state state = CPUHP_OFFLINE + 1; state < CPUHP_ONLINE; state++)
		empty_slot(state);
	assert(!callback_calls);
}

static void fixed_states(void)
{
	const enum cpuhp_state invalid[] = {
		CPUHP_INVALID, CPUHP_OFFLINE, CPUHP_ONLINE, (enum cpuhp_state)(CPUHP_ONLINE + 1),
		(enum cpuhp_state)-17,
	};
	for (size_t i = 0; i < ARRAY_SIZE(invalid); i++) {
		take_snapshot(NULL);
		assert(cpuhp_setup_state_nocalls(invalid[i], "invalid", startup, teardown) == -EINVAL);
		unchanged();
		assert(cpuhp_setup_state_nocalls_cpuslocked(invalid[i], "invalid", NULL, NULL) == -EINVAL);
		unchanged();
	}
	/* Every admissible non-base state, including each dynamic END, is also
	 * a fixed request. A requested interior slot must not get reallocated. */
	for (enum cpuhp_state state = CPUHP_OFFLINE + 1; state < CPUHP_ONLINE; state++) {
		if (state == CPUHP_BP_PREPARE_DYN || state == CPUHP_AP_ONLINE_DYN)
			continue;
		char name[] = "borrowed";
		assert(!cpuhp_setup_state_nocalls(state, name, startup, teardown));
		assert(steps[state].name == name && steps[state].startup.single == startup);
		assert(steps[state].teardown.single == teardown && !steps[state].multi_instance);
		name[0] = 'B';
		assert(steps[state].name[0] == 'B');
		take_snapshot(NULL);
		assert(cpuhp_setup_state_nocalls(state, "duplicate", teardown, startup) == -EBUSY);
		unchanged();
		assert(cpuhp_setup_state_nocalls(state, NULL, NULL, NULL) == -EINVAL);
		unchanged();
		cpuhp_remove_state_nocalls(state);
		empty_slot(state);
		cpuhp_remove_state_nocalls_cpuslocked(state); /* Empty valid removal. */
		empty_slot(state);
		cpus_read_lock();
		assert(!cpuhp_setup_state_nocalls_cpuslocked(state, "", NULL, NULL));
		assert(steps[state].name && !steps[state].name[0]);
		cpuhp_remove_state_nocalls_cpuslocked(state);
		cpus_read_unlock();
		empty_slot(state);
	}
	for (size_t i = 0; i < 2; i++) {
		enum cpuhp_state base = i ? CPUHP_AP_ONLINE_DYN : CPUHP_BP_PREPARE_DYN;
		take_snapshot(NULL);
		assert(cpuhp_setup_state_nocalls(base, NULL, startup, teardown) == -EINVAL);
		unchanged();
	}
	empty_registry();
}

static void dynamic_range(enum cpuhp_state base, enum cpuhp_state end)
{
	for (enum cpuhp_state state = base; state <= end; state++) {
		int assigned = cpuhp_setup_state_nocalls(base, "dynamic", startup, teardown);
		assert(assigned == state && steps[state].startup.single == startup);
	}
	take_snapshot(NULL);
	assert(cpuhp_setup_state_nocalls(base, "full", NULL, NULL) == -ENOSPC);
	unchanged();
	assert(cpuhp_setup_state_nocalls_cpuslocked(base, "full", NULL, NULL) == -ENOSPC);
	unchanged();
	assert(cpuhp_setup_state_nocalls(end, "occupied-end", NULL, NULL) == -EBUSY);
	unchanged();
	/* The original dynamic-base removal bug would clear a free slot instead
	 * of this actual slot, leaving its borrowed callbacks installed. */
	struct cpuhp_step neighbor;
	memcpy(&neighbor, &steps[base + 1], sizeof(neighbor));
	cpuhp_remove_state_nocalls(base);
	empty_slot(base);
	assert(!memcmp(&neighbor, &steps[base + 1], sizeof(neighbor)));
	assert(cpuhp_setup_state_nocalls_cpuslocked(base, "base-reused", NULL, teardown) == base);
	assert(steps[base].teardown.single == teardown && !steps[base].startup.single);
	const enum cpuhp_state holes[] = {base, (enum cpuhp_state)(base + (end - base) / 2), end};
	for (size_t i = 0; i < ARRAY_SIZE(holes); i++)
		cpuhp_remove_state_nocalls_cpuslocked(holes[i]);
	for (size_t i = 0; i < ARRAY_SIZE(holes); i++)
		assert(cpuhp_setup_state_nocalls(base, "hole-reused", startup, teardown) == holes[i]);
	for (enum cpuhp_state state = base; state <= end; state++) {
		cpuhp_remove_state_nocalls(state);
		empty_slot(state);
	}
	empty_registry();
}

static void multi_instances(const struct stela_linux_owner *owner)
{
	struct hlist_node a, b, fresh, pattern;
	INIT_HLIST_NODE(&a);
	INIT_HLIST_NODE(&b);
	assert(!cpuhp_setup_state_multi(CPUHP_RADIX_DEAD, "multi", multi_startup, multi_teardown));
	struct cpuhp_step *step = &steps[CPUHP_RADIX_DEAD];
	assert(step->multi_instance && step->startup.multi == multi_startup);
	assert(step->teardown.multi == multi_teardown && hlist_empty(&step->list));
	/* No prior initialization is required by original hlist_add_head. These
	 * caller-owned detached node bytes must be overwritten before any read. */
	assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &fresh));
	assert(step->list.first == &fresh && !fresh.next && fresh.pprev == &step->list.first);
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &fresh));
	memset(&pattern, 0xa5, sizeof(pattern));
	assert(!cpuhp_state_add_instance_nocalls_cpuslocked(CPUHP_RADIX_DEAD, &pattern));
	assert(step->list.first == &pattern && !pattern.next && pattern.pprev == &step->list.first);
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &pattern));
	assert(hlist_empty(&step->list));
	assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &a));
	cpus_read_lock();
	assert(!cpuhp_state_add_instance_nocalls_cpuslocked(CPUHP_RADIX_DEAD, &b));
	cpus_read_unlock();
	assert(step->list.first == &b && b.next == &a && a.next == NULL);
	assert(b.pprev == &step->list.first && a.pprev == &b.next);
	/* The borrowed stack nodes are still live here, across two owners. */
	take_snapshot(&a);
	stela_linux_exit();
	stela_linux_enter(&stela_linux_bare);
	unchanged();
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &a));
	assert(a.next == LIST_POISON1 && a.pprev == LIST_POISON2);
	assert(step->list.first == &b && !b.next);
	assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &a)); /* Detached poison reuse. */
	assert(step->list.first == &a && a.next == &b && b.pprev == &a.next);
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &a));
	INIT_HLIST_NODE(&a);
	assert(!__cpuhp_state_add_instance_cpuslocked(CPUHP_RADIX_DEAD, &a, false));
	assert(!__cpuhp_state_remove_instance(CPUHP_RADIX_DEAD, &a, false));
	assert(!__cpuhp_state_remove_instance(CPUHP_RADIX_DEAD, &b, false));
	cpuhp_remove_multi_state(CPUHP_RADIX_DEAD);
	stela_linux_exit();
	stela_linux_enter(owner);
	empty_registry();
	take_snapshot(&a);
	/* Missing and single-instance states both return EINVAL without reading
	 * even a NULL node or claiming an invocation service. */
	assert(cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, NULL) == -EINVAL);
	assert(cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, NULL) == -EINVAL);
	unchanged();
	assert(!cpuhp_setup_state_nocalls(CPUHP_RADIX_DEAD, "single", startup, teardown));
	take_snapshot(&a);
	assert(cpuhp_state_add_instance(CPUHP_RADIX_DEAD, NULL) == -EINVAL);
	assert(cpuhp_state_remove_instance(CPUHP_RADIX_DEAD, NULL) == -EINVAL);
	unchanged();
	cpuhp_remove_state_nocalls(CPUHP_RADIX_DEAD);
	empty_registry();
}

static void invoking_errors(void)
{
	for (size_t i = 0; i < 2; i++) {
		enum cpuhp_state state = i ? CPUHP_AP_ONLINE_DYN : CPUHP_RADIX_DEAD;
		take_snapshot(NULL);
		unsigned int before = refusals;
		assert(cpuhp_setup_state(state, "invoke", startup, teardown) == -EOPNOTSUPP);
		unchanged();
		assert(cpuhp_setup_state_cpuslocked(state, "invoke", NULL, NULL) == -EOPNOTSUPP);
		unchanged();
		assert(__cpuhp_setup_state(state, "invoke", true, NULL, NULL, true) == -EOPNOTSUPP);
		unchanged();
		assert(refusals == before + 3);
	}
	struct hlist_node node;
	INIT_HLIST_NODE(&node);
	assert(!cpuhp_setup_state_multi(CPUHP_RADIX_DEAD, "multi", multi_startup, multi_teardown));
	take_snapshot(&node);
	assert(cpuhp_state_add_instance(CPUHP_RADIX_DEAD, &node) == -EOPNOTSUPP);
	unchanged();
	assert(__cpuhp_state_add_instance_cpuslocked(CPUHP_RADIX_DEAD, &node, true) == -EOPNOTSUPP);
	unchanged();
	assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &node));
	take_snapshot(&node);
	assert(cpuhp_state_remove_instance(CPUHP_RADIX_DEAD, &node) == -EOPNOTSUPP);
	unchanged();
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &node));
	cpuhp_remove_multi_state(CPUHP_RADIX_DEAD);
	/* Multi states with NULL callbacks still cannot turn invoke into success. */
	assert(!cpuhp_setup_state_multi(CPUHP_RADIX_DEAD, "null-multi", NULL, NULL));
	INIT_HLIST_NODE(&node);
	take_snapshot(&node);
	assert(cpuhp_state_add_instance(CPUHP_RADIX_DEAD, &node) == -EOPNOTSUPP);
	unchanged();
	assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &node));
	take_snapshot(&node);
	assert(cpuhp_state_remove_instance(CPUHP_RADIX_DEAD, &node) == -EOPNOTSUPP);
	unchanged();
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &node));
	cpuhp_remove_multi_state(CPUHP_RADIX_DEAD);
	empty_registry();
}

/* Context cases dispatch all seven real entries. No test-only production
 * bypass exists: these use the same owner/quiescence checks as drivers. */
static unsigned int selected_entry;
static unsigned int selected_context;
static struct hlist_node test_node;

static void entry(void)
{
	switch (selected_entry) {
	case 0: (void)__cpuhp_setup_state(CPUHP_RADIX_DEAD, "context", false, NULL, NULL, false); break;
	case 1: (void)__cpuhp_setup_state_cpuslocked(CPUHP_RADIX_DEAD, "context", false, NULL, NULL, false); break;
	case 2: (void)__cpuhp_state_add_instance(CPUHP_RADIX_DEAD, &test_node, false); break;
	case 3: (void)__cpuhp_state_add_instance_cpuslocked(CPUHP_RADIX_DEAD, &test_node, false); break;
	case 4: (void)__cpuhp_state_remove_instance(CPUHP_RADIX_DEAD, &test_node, false); break;
	case 5: __cpuhp_remove_state(CPUHP_RADIX_DEAD, false); break;
	case 6: __cpuhp_remove_state_cpuslocked(CPUHP_RADIX_DEAD, false); break;
	default: assert(false);
	}
}

static void outside_owner(void)
{
	stela_linux_exit();
	entry();
}

static void nonquiescent(void)
{
	switch (selected_context) {
	case 0: preempt_disable(); break;
	case 1: rcu_read_lock(); break;
	case 2: local_bh_disable(); break;
	case 3: (void)arch_local_irq_save(); break;
	default: assert(false);
	}
	entry();
}

static void invoke_remove(void)
{
	if (selected_entry)
		__cpuhp_remove_state_cpuslocked(CPUHP_RADIX_DEAD, true);
	else
		cpuhp_remove_state(CPUHP_RADIX_DEAD);
}

static void strict_invoke(void)
{
	stela_linux_exit();
	stela_linux_enter(&stela_linux_bare);
	(void)cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "strict", startup, teardown);
}

static unsigned int selected_violation;

static void invalid_membership(void)
{
	struct hlist_node detached;
	INIT_HLIST_NODE(&detached);
	switch (selected_violation) {
	case 0: (void)cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &test_node); break;
	case 1: (void)cpuhp_state_add_instance_nocalls_cpuslocked(CPUHP_RADIX_DEAD, &test_node); break;
	case 2: (void)cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, NULL); break;
	case 3: (void)cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, NULL); break;
	case 4: (void)cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &detached); break;
	case 5: (void)cpuhp_state_remove_instance_nocalls(CPUHP_PAGE_ALLOC, &test_node); break;
	case 6: cpuhp_remove_multi_state(CPUHP_RADIX_DEAD); break;
	case 7: cpuhp_remove_state_nocalls_cpuslocked(CPUHP_RADIX_DEAD); break;
	case 8: cpuhp_remove_state_nocalls(CPUHP_OFFLINE); break;
	case 9: cpuhp_remove_state_nocalls_cpuslocked(CPUHP_ONLINE); break;
	case 10: (void)cpuhp_state_add_instance_nocalls(CPUHP_INVALID, &detached); break;
	case 11: (void)cpuhp_state_add_instance_nocalls_cpuslocked(CPUHP_ONLINE, &detached); break;
	case 12: (void)cpuhp_state_remove_instance_nocalls(CPUHP_OFFLINE, &detached); break;
	case 13: (void)cpuhp_state_add_instance_nocalls(CPUHP_PAGE_ALLOC, &test_node); break;
	case 14:
		assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &test_node));
		(void)cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &test_node);
		break;
	case 15:
		test_node.pprev = &detached.next;
		(void)cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &test_node);
		break;
	case 16:
		assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &detached));
		test_node.pprev = &steps[CPUHP_PAGE_ALLOC].list.first;
		(void)cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &detached);
		break;
	default: assert(false);
	}
}

static void contract_traps(void)
{
	assert(!cpuhp_setup_state_multi(CPUHP_RADIX_DEAD, "traps", multi_startup, multi_teardown));
	assert(!cpuhp_setup_state_multi(CPUHP_PAGE_ALLOC, "other-state", NULL, NULL));
	INIT_HLIST_NODE(&test_node);
	assert(!cpuhp_state_add_instance_nocalls(CPUHP_RADIX_DEAD, &test_node));
	for (selected_entry = 0; selected_entry < 7; selected_entry++) {
		take_snapshot(&test_node);
		assert(stela_test_traps(outside_owner));
		unchanged();
		for (selected_context = 0; selected_context < 4; selected_context++) {
			assert(stela_test_traps(nonquiescent));
			unchanged();
		}
	}
	for (selected_violation = 0; selected_violation < 17; selected_violation++) {
		assert(stela_test_traps(invalid_membership));
		unchanged();
	}
	for (selected_entry = 0; selected_entry < 2; selected_entry++) {
		take_snapshot(&test_node);
		assert(stela_test_traps(invoke_remove));
		unchanged();
	}
	assert(stela_test_traps(strict_invoke));
	unchanged();
	assert(!cpuhp_state_remove_instance_nocalls(CPUHP_RADIX_DEAD, &test_node));
	cpuhp_remove_multi_state(CPUHP_RADIX_DEAD);
	cpuhp_remove_multi_state(CPUHP_PAGE_ALLOC);
	empty_registry();
	assert(!cpuhp_setup_state_nocalls(CPUHP_RADIX_DEAD, "null-single", NULL, NULL));
	/* A void invoking removal must fail closed even with no teardown code. */
	take_snapshot(NULL);
	assert(stela_test_traps(invoke_remove));
	unchanged();
	cpuhp_remove_state_nocalls(CPUHP_RADIX_DEAD);
	empty_registry();
}

int main(void)
{
	const struct stela_linux_services services = {.unsupported = unsupported, .warn = warn};
	const struct stela_linux_owner owner = {.services = &services, .context = &refusals};
	stela_linux_enter(&owner);
	empty_registry();
	fixed_states();
	dynamic_range(CPUHP_BP_PREPARE_DYN, CPUHP_BP_PREPARE_DYN_END);
	dynamic_range(CPUHP_AP_ONLINE_DYN, CPUHP_AP_ONLINE_DYN_END);
	assert(warnings == 4);
	multi_instances(&owner);
	invoking_errors();
	assert(refusals == 11);
	contract_traps();
	stela_linux_exit();
	printf("Linux CPUHP: real nocalls registry, dynamic slots, instances, lifetime and refusal passed\n");
	return 0;
}
#endif
