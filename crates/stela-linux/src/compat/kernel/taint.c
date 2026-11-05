// SPDX-License-Identifier: GPL-2.0-only
/* Selected Linux taint service, derived from Linux kernel/panic.c and
 * lib/debug_locks.c at cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * Shared image state, serialized by the entered Linux owner. This is not the
 * Linux panic/reboot/SMP implementation. Taint-triggered fatal stops report to
 * that owner and trap; neither owner exit nor registry retirement resets state.
 */
#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/debug_locks.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/kstrtox.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <linux/string_choices.h>
#include <stela/linux.h>

static unsigned long tainted_mask =
	IS_ENABLED(CONFIG_RANDSTRUCT) ? (1UL << TAINT_RANDSTRUCT) : 0;
unsigned long panic_on_taint;
bool panic_on_taint_nousertaint;
/* __debug_locks_off in the original header exchanges this even !LOCKDEP. */
int debug_locks __read_mostly = 1;
int debug_locks_silent __read_mostly;

#define TAINT_FLAG(taint, _c_true, _c_false)				\
	[ TAINT_##taint ] = {						\
		.c_true = _c_true, .c_false = _c_false,			\
		.desc = #taint,						\
	}

/*
 * NOTE: if you modify the taint_flags or TAINT_FLAGS_COUNT,
 * please also modify tools/debugging/kernel-chktaint and
 * Documentation/admin-guide/tainted-kernels.rst, including its
 * small shell script that prints the TAINT_FLAGS_COUNT bits of
 * /proc/sys/kernel/tainted.
 *
 * Also, update INIT_TAINT_BUF_MAX below.
 */
const struct taint_flag taint_flags[TAINT_FLAGS_COUNT] = {
	TAINT_FLAG(PROPRIETARY_MODULE,		'P', 'G'),
	TAINT_FLAG(FORCED_MODULE,		'F', ' '),
	TAINT_FLAG(CPU_OUT_OF_SPEC,		'S', ' '),
	TAINT_FLAG(FORCED_RMMOD,		'R', ' '),
	TAINT_FLAG(MACHINE_CHECK,		'M', ' '),
	TAINT_FLAG(BAD_PAGE,			'B', ' '),
	TAINT_FLAG(USER,			'U', ' '),
	TAINT_FLAG(DIE,				'D', ' '),
	TAINT_FLAG(OVERRIDDEN_ACPI_TABLE,	'A', ' '),
	TAINT_FLAG(WARN,			'W', ' '),
	TAINT_FLAG(CRAP,			'C', ' '),
	TAINT_FLAG(FIRMWARE_WORKAROUND,		'I', ' '),
	TAINT_FLAG(OOT_MODULE,			'O', ' '),
	TAINT_FLAG(UNSIGNED_MODULE,		'E', ' '),
	TAINT_FLAG(SOFTLOCKUP,			'L', ' '),
	TAINT_FLAG(LIVEPATCH,			'K', ' '),
	TAINT_FLAG(AUX,				'X', ' '),
	TAINT_FLAG(RANDSTRUCT,			'T', ' '),
	TAINT_FLAG(TEST,			'N', ' '),
	TAINT_FLAG(FWCTL,			'J', ' '),
};

#undef TAINT_FLAG

/* All 20 verbose descriptions need 328 bytes including NUL. Keep the
 * original bootstrap bound permanently, without importing alloc_taint_buf. */
#define STELA_TAINT_BUFFER_SIZE 350
static_assert(sizeof("Tainted: ")
	+ sizeof("PROPRIETARY_MODULE") - 1 + 4
	+ sizeof("FORCED_MODULE") - 1 + 4
	+ sizeof("CPU_OUT_OF_SPEC") - 1 + 4
	+ sizeof("FORCED_RMMOD") - 1 + 4
	+ sizeof("MACHINE_CHECK") - 1 + 4
	+ sizeof("BAD_PAGE") - 1 + 4
	+ sizeof("USER") - 1 + 4
	+ sizeof("DIE") - 1 + 4
	+ sizeof("OVERRIDDEN_ACPI_TABLE") - 1 + 4
	+ sizeof("WARN") - 1 + 4
	+ sizeof("CRAP") - 1 + 4
	+ sizeof("FIRMWARE_WORKAROUND") - 1 + 4
	+ sizeof("OOT_MODULE") - 1 + 4
	+ sizeof("UNSIGNED_MODULE") - 1 + 4
	+ sizeof("SOFTLOCKUP") - 1 + 4
	+ sizeof("LIVEPATCH") - 1 + 4
	+ sizeof("AUX") - 1 + 4
	+ sizeof("RANDSTRUCT") - 1 + 4
	+ sizeof("TEST") - 1 + 4
	+ sizeof("FWCTL") - 1 + 4
	+ 2 * (TAINT_FLAGS_COUNT - 1) <= STELA_TAINT_BUFFER_SIZE);
static char taint_buffer[STELA_TAINT_BUFFER_SIZE];

static void valid_flag(unsigned flag)
{
	if (flag >= TAINT_FLAGS_COUNT)
		stela_linux_fatal("Linux taint flag out of range");
}

static const char *format_taint(bool verbose)
{
	(void)stela_linux_owner();
	static_assert(TAINT_FLAGS_COUNT == 20);
	if (!tainted_mask) {
		memcpy(taint_buffer, "Not tainted", sizeof("Not tainted"));
		return taint_buffer;
	}
	size_t used = (size_t)scnprintf(taint_buffer, sizeof(taint_buffer), "Tainted: ");
	const char *sep = "";
	for (unsigned i = 0; i < TAINT_FLAGS_COUNT; i++) {
		const struct taint_flag *t = &taint_flags[i];
		bool is_set = test_bit(i, &tainted_mask);
		char c = is_set ? t->c_true : t->c_false;
		if (verbose) {
			if (!is_set)
				continue;
			used += (size_t)scnprintf(taint_buffer + used, sizeof(taint_buffer) - used,
						 "%s[%c]=%s", sep, c, t->desc);
			sep = ", ";
		} else {
			taint_buffer[used++] = c;
			taint_buffer[used] = '\0';
		}
	}
	return taint_buffer;
}

const char *print_tainted(void)
{
	return format_taint(false);
}

const char *print_tainted_verbose(void)
{
	return format_taint(true);
}

int test_taint(unsigned flag)
{
	(void)stela_linux_owner();
	valid_flag(flag);
	return test_bit(flag, &tainted_mask);
}

unsigned long get_taint(void)
{
	(void)stela_linux_owner();
	return tainted_mask;
}

void add_taint(unsigned flag, enum lockdep_ok lockdep_ok)
{
	(void)stela_linux_owner();
	valid_flag(flag);
	if (lockdep_ok == LOCKDEP_NOW_UNRELIABLE && __debug_locks_off())
		pr_warn("Disabling lock debugging due to kernel taint\n");
	set_bit(flag, &tainted_mask);
	if (tainted_mask & panic_on_taint) {
		panic_on_taint = 0;
		stela_linux_fatal("panic_on_taint set ...");
	}
}

static int __init panic_on_taint_setup(char *s)
{
	char *taint_str;

	if (!s)
		return -EINVAL;

	taint_str = strsep(&s, ",");
	if (kstrtoul(taint_str, 16, &panic_on_taint))
		return -EINVAL;

	/* make sure panic_on_taint doesn't hold out-of-range TAINT flags */
	panic_on_taint &= TAINT_FLAGS_MAX;

	if (!panic_on_taint)
		return -EINVAL;

	if (s && !strcmp(s, "nousertaint"))
		panic_on_taint_nousertaint = true;

	pr_info("panic_on_taint: bitmask=0x%lx nousertaint_mode=%s\n",
		panic_on_taint, str_enabled_disabled(panic_on_taint_nousertaint));

	return 0;
}
early_param("panic_on_taint", panic_on_taint_setup);

#ifdef STELA_LINUX_TAINT_TEST
#include <stela/taint_test.h>
#endif
