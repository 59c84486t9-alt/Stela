/* SPDX-License-Identifier: GPL-2.0-only */
/* Exact retained kernel/panic.c source projections; only identifiers are
 * lexically renamed below. The bounded test-only seq-buffer adapters are
 * explicitly separate. No allocator, full panic, sysctl or parser reference
 * is implied by these selected source bodies. */
#define tainted_mask reference_mask
#define taint_flags reference_flags
#define print_tainted_seq reference_print_seq
#define _print_tainted reference_print
#define print_tainted reference_print_tainted
#define print_tainted_verbose reference_print_verbose
#define test_taint reference_test_taint
#define get_taint reference_get_taint
#define add_taint reference_add_taint
#define panic_on_taint reference_panic_on_taint
#define panic_on_taint_nousertaint reference_nousertaint
#define panic_on_taint_setup reference_setup
#define __debug_locks_off reference_locks_off
#define panic stela_linux_fatal
#define seq_buf reference_seq_buf
#define seq_buf_puts reference_puts
#define seq_buf_printf reference_printf
#define seq_buf_putc reference_putc
#define seq_buf_init reference_seq_init
#define seq_buf_str reference_seq_str
#define taint_buf reference_buf
#define taint_buf_size reference_size

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


static void print_tainted_seq(struct seq_buf *s, bool verbose)
{
	const char *sep = "";
	int i;

	if (!tainted_mask) {
		seq_buf_puts(s, "Not tainted");
		return;
	}

	seq_buf_printf(s, "Tainted: ");
	for (i = 0; i < TAINT_FLAGS_COUNT; i++) {
		const struct taint_flag *t = &taint_flags[i];
		bool is_set = test_bit(i, &tainted_mask);
		char c = is_set ? t->c_true : t->c_false;

		if (verbose) {
			if (is_set) {
				seq_buf_printf(s, "%s[%c]=%s", sep, c, t->desc);
				sep = ", ";
			}
		} else {
			seq_buf_putc(s, c);
		}
	}
}

static const char *_print_tainted(bool verbose)
{
	struct seq_buf s;

	BUILD_BUG_ON(ARRAY_SIZE(taint_flags) != TAINT_FLAGS_COUNT);

	seq_buf_init(&s, taint_buf, taint_buf_size);

	print_tainted_seq(&s, verbose);

	return seq_buf_str(&s);
}

const char *print_tainted(void)
{
	return _print_tainted(false);
}

const char *print_tainted_verbose(void)
{
	return _print_tainted(true);
}

int test_taint(unsigned flag)
{
	return test_bit(flag, &tainted_mask);
}

unsigned long get_taint(void)
{
	return tainted_mask;
}

void add_taint(unsigned flag, enum lockdep_ok lockdep_ok)
{
	if (lockdep_ok == LOCKDEP_NOW_UNRELIABLE && __debug_locks_off())
		pr_warn("Disabling lock debugging due to kernel taint\n");

	set_bit(flag, &tainted_mask);

	if (tainted_mask & panic_on_taint) {
		panic_on_taint = 0;
		panic("panic_on_taint set ...");
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
#undef tainted_mask
#undef taint_flags
#undef print_tainted_seq
#undef _print_tainted
#undef print_tainted
#undef print_tainted_verbose
#undef test_taint
#undef get_taint
#undef add_taint
#undef panic_on_taint
#undef panic_on_taint_nousertaint
#undef panic_on_taint_setup
#undef __debug_locks_off
#undef panic
#undef seq_buf
#undef seq_buf_puts
#undef seq_buf_printf
#undef seq_buf_putc
#undef seq_buf_init
#undef seq_buf_str
#undef taint_buf
#undef taint_buf_size
