// SPDX-License-Identifier: MIT
/* Linux's kernel messages, each delivered formatted to the running owner's
 * log at its level. Messages longer than Linux's 1024-byte records are cut
 * as Linux cuts them. */
#include <linux/device.h>
#include <linux/printk.h>
#include <linux/sprintf.h>
#include <stela/linux.h>

/* The level a message's prefixes give, after which its text starts. */
static int level_of(const char **fmt)
{
	int level = MESSAGE_LOGLEVEL_DEFAULT;
	for (int kind; (kind = printk_get_level(*fmt)); *fmt += 2)
		if (kind >= '0' && kind <= '7')
			level = kind - '0';
	return level;
}

static int emit(int level, const char *fmt, va_list args)
{
	/* One context runs Linux code at a time. */
	static char message[1024];
	int length = vscnprintf(message, sizeof(message), fmt, args);
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (owner->services->log)
		owner->services->log(owner->context, level, message);
	return length;
}

static __printf(2, 3) void emitf(int level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	emit(level, fmt, args);
	va_end(args);
}

int vprintk(const char *fmt, va_list args)
{
	int level = level_of(&fmt);
	return emit(level, fmt, args);
}

int _printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int length = vprintk(fmt, args);
	va_end(args);
	return length;
}

const char *dev_driver_string(const struct device *dev)
{
	struct device_driver *driver = READ_ONCE(dev->driver);
	return driver ? driver->name : dev_bus_name(dev);
}

/* A device's messages carry its driver and name, as Linux's do. */
static void dev_vprintk(const char *level, const struct device *dev, const char *fmt,
			va_list args)
{
	va_list copy;
	va_copy(copy, args);
	struct va_format vaf = {.fmt = fmt, .va = &copy};
	int number = level_of(&level);
	if (dev)
		emitf(number, "%s %s: %pV", dev_driver_string(dev), dev_name(dev), &vaf);
	else
		emitf(number, "(NULL device *): %pV", &vaf);
	va_end(copy);
}

void _dev_printk(const char *level, const struct device *dev, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	dev_vprintk(level, dev, fmt, args);
	va_end(args);
}

#define DEV_PRINTK(name, level)							\
void name(const struct device *dev, const char *fmt, ...)			\
{										\
	va_list args;								\
	va_start(args, fmt);							\
	dev_vprintk(level, dev, fmt, args);					\
	va_end(args);								\
}

DEV_PRINTK(_dev_emerg, KERN_EMERG)
DEV_PRINTK(_dev_alert, KERN_ALERT)
DEV_PRINTK(_dev_crit, KERN_CRIT)
DEV_PRINTK(_dev_err, KERN_ERR)
DEV_PRINTK(_dev_warn, KERN_WARNING)
DEV_PRINTK(_dev_notice, KERN_NOTICE)
DEV_PRINTK(_dev_info, KERN_INFO)

/* A WARN's message, which precedes the WARN itself. */
void __warn_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

/* Only the current function's saved return address is compiler-defined here.
 * Reading a caller's frame chain needs a retained native stack and its bounds.
 * The diagnostic precedes the unsupported report, which an owner may stop at. */
static void dump_caller(const char *level, const void *caller)
{
	const char *prefix = level;
	int number = level_of(&prefix);
	emitf(number, "Call trace incomplete: caller %px; stack unwinding unavailable\n", caller);
	stela_linux_unsupported("native stack unwinding");
}

noinline void dump_stack_lvl(const char *log_lvl)
{
	dump_caller(log_lvl, __builtin_extract_return_addr(__builtin_return_address(0)));
}

noinline void dump_stack(void)
{
	dump_caller(KERN_DEFAULT, __builtin_extract_return_addr(__builtin_return_address(0)));
}

#ifdef STELA_LINUX_PRINTK_TEST
#include <linux/string.h>
#include <stela/test.h>

static unsigned int messages;
static unsigned int missing;
static int observed_level;
static char observed[256];

static void test_log(void *context, int level, const char *message)
{
	assert(context == &messages);
	messages++;
	observed_level = level;
	size_t length = strlen(message);
	assert(length < sizeof(observed));
	memcpy(observed, message, length + 1);
}

static void test_missing(void *context, const char *operation)
{
	assert(context == &messages && messages == missing + 1);
	assert(!strcmp(operation, "native stack unwinding"));
	assert(strstr(observed, "Call trace incomplete: caller ") == observed);
	assert(strstr(observed, "; stack unwinding unavailable\n"));
	missing++;
}

static void trapping_missing(void *context, const char *operation)
{
	test_missing(context, operation);
	__builtin_trap();
}

static void trapping_trace(void)
{
	const struct stela_linux_services services = {.log = test_log, .unsupported = trapping_missing};
	const struct stela_linux_owner owner = {.services = &services, .context = &messages};
	stela_linux_enter(&owner);
	dump_stack();
}

static void outside_owner(void)
{
	dump_stack();
}

int main(void)
{
	const struct stela_linux_services services = {.log = test_log, .unsupported = test_missing};
	const struct stela_linux_owner owner = {.services = &services, .context = &messages};
	stela_linux_enter(&owner);
	/* A known address checks the actual formatter and diagnostic ordering;
	 * the public entry points below capture a real, nonzero saved caller. */
	dump_caller(KERN_ERR, (const void *)0x1234UL);
	assert(observed_level == LOGLEVEL_ERR && strstr(observed, "0000000000001234;"));
	dump_stack_lvl(KERN_WARNING);
	assert(observed_level == LOGLEVEL_WARNING && !strstr(observed, "0000000000000000;"));
	dump_stack();
	assert(observed_level == MESSAGE_LOGLEVEL_DEFAULT && missing == 3);
	stela_linux_exit();
	assert(stela_test_traps(trapping_trace));
	assert(stela_test_traps(outside_owner));
	printf("Linux stack diagnostic: caller, severity, missing-unwinder policy passed\n");
	return 0;
}
#endif
