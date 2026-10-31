// SPDX-License-Identifier: MIT
/* The selected domain's fatal Linux API boundary. Reporting and a terminal
 * stop are real; SMP arbitration, notifiers, crash dumps and reboot are not
 * provided by this serialized execution environment. */
#include <linux/panic.h>
#include <linux/sprintf.h>
#include <stela/linux.h>

/* Stela's panics never return, so no console is ever left mid-oops. */
int oops_in_progress;

void vpanic(const char *fmt, va_list args)
{
	/* Same bounded message size as the selected printk adapter. Keep storage
	 * local so a logger's own formatting cannot overwrite the fatal report.
	 * This needs no allocation, quiescent point, task or scheduler service. */
	char message[1024];
	vscnprintf(message, sizeof(message), fmt, args);
	stela_linux_fatal(message);
}

void panic(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vpanic(fmt, args);
}

#ifdef STELA_LINUX_PANIC_TEST
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <stela/task.h>
#include <stela/test.h>

/* The existing hosted fatal witness verifies SIGILL after a logger returns.
 * An assertion failure, premature trap, normal return or missing report fails.
 * The signal handler reads only this sig_atomic_t-compatible int witness. */
int stela_taint_test_stops(void (*operation)(void), volatile int *witness, int expected);
static volatile int reported;
static struct stela_linux_lease expected_lease;
static const char *expected_message;
static int expected_preempt;
static bool long_report;

static void report(void *context, int level, const char *message)
{
	assert(context == &expected_lease && level == LOGLEVEL_EMERG);
	assert(stela_linux_lease_matches(&expected_lease));
	assert(preempt_count() == expected_preempt);
	assert(!reported);
	if (long_report) {
		assert(strlen(message) == 1023);
		for (unsigned int i = 0; i < 1023; i++)
			assert(message[i] == 'x');
	} else {
		assert(!strcmp(message, expected_message));
	}
	reported = 1;
}

static void formatted_panic(void)
{
	panic("failure %s %d %#llx %.3s", "selected", -17, 0x123456789abcdef0ULL, "bounded");
}

static void call_vpanic(const char *fmt, ...) __noreturn __printf(1, 2);
static void call_vpanic(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vpanic(fmt, args);
}

static void direct_vpanic(void)
{
	call_vpanic("va_list %u %s", 42U, "retained");
}

static void bounded_panic(void)
{
	char text[2048];
	memset(text, 'x', sizeof(text) - 1);
	text[sizeof(text) - 1] = '\0';
	panic("%s", text);
}

static void critical_panic(void)
{
	preempt_disable();
	raw_local_irq_disable();
	expected_preempt = 1;
	stela_linux_lease_snapshot(&expected_lease);
	panic("critical failure");
}

static void no_logger(void)
{
	stela_linux_exit();
	stela_linux_enter(&stela_linux_bare);
	panic("terminal without logger");
}

static void outside_owner(void)
{
	stela_linux_exit();
	panic("no admitted report owner");
}

int main(void)
{
	const struct stela_linux_services services = {.log = report};
	const struct stela_linux_owner owner = {.services = &services, .context = &expected_lease};
	stela_linux_enter(&owner);
	stela_linux_lease_snapshot(&expected_lease);
	expected_message = "failure selected -17 0x123456789abcdef0 bou";
	assert(stela_taint_test_stops(formatted_panic, &reported, 1));
	expected_message = "va_list 42 retained";
	assert(stela_taint_test_stops(direct_vpanic, &reported, 1));
	long_report = true;
	assert(stela_taint_test_stops(bounded_panic, &reported, 1));
	long_report = false;
	expected_message = "critical failure";
	assert(stela_taint_test_stops(critical_panic, &reported, 1));
	assert(stela_test_traps(no_logger));
	assert(stela_test_traps(outside_owner));
	assert(!reported && stela_linux_lease_matches(&expected_lease));
	stela_linux_exit();
	printf("Linux panic: formatted emergency reports, bounded storage and terminal failure passed\n");
	return 0;
}
#endif
