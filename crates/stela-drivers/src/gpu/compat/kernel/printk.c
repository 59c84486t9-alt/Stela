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
