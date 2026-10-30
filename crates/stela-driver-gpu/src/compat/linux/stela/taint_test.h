/* SPDX-License-Identifier: GPL-2.0-only */
/* Hosted inline fixtures. Direct state assignments below isolate cases only;
 * the production service deliberately exports no reset or restart API. */
#include <linux/array_size.h>
#include <stela/test.h>

struct reference_seq_buf {
	char *buffer;
	size_t size, len;
};

static void reference_seq_init(struct reference_seq_buf *s, char *buffer, unsigned int size)
{
	*s = (struct reference_seq_buf){.buffer = buffer, .size = size};
	assert(size);
	buffer[0] = '\0';
}

/* These adapters exercise exact original print_tainted_seq bodies over a
 * bounded buffer. They are not substitutions for a production seq_buf API. */
static int reference_printf(struct reference_seq_buf *s, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int n = vscnprintf(s->buffer + s->len, s->size - s->len, fmt, args);
	va_end(args);
	assert(n >= 0 && (size_t)n < s->size - s->len - 1);
	s->len += (size_t)n;
	return 0;
}

static int reference_puts(struct reference_seq_buf *s, const char *text)
{
	return reference_printf(s, "%s", text);
}

static int reference_putc(struct reference_seq_buf *s, unsigned char c)
{
	return reference_printf(s, "%c", c);
}

static const char *reference_seq_str(struct reference_seq_buf *s)
{
	assert(s->len < s->size);
	s->buffer[s->len] = '\0';
	return s->buffer;
}

static unsigned long reference_mask =
	IS_ENABLED(CONFIG_RANDSTRUCT) ? (1UL << TAINT_RANDSTRUCT) : 0;
static unsigned long reference_panic_on_taint;
static bool reference_nousertaint;
static int reference_debug_locks = 1;
static char reference_buf[350];
static size_t reference_size = sizeof(reference_buf);

static int reference_locks_off(void)
{
	return __atomic_exchange_n(&reference_debug_locks, 0, __ATOMIC_SEQ_CST);
}

#include <stela/taint_reference.h>

struct taint_event {
	int level;
	char message[160];
};

static struct taint_event taint_events[16];
static unsigned int taint_event_count, taint_warnings;
static unsigned int taint_context_a, taint_context_b;
static bool expected_fatal_reference;
static unsigned long expected_fatal_mask;
static volatile int fatal_witness;
/* Separate hosted signal/fork helper verifies the real trap AND that the
 * emergency callback saw the required state before it, and no code after it. */
int stela_taint_test_stops(void (*operation)(void), volatile int *witness, int expected);

static void taint_test_log(void *context, int level, const char *message)
{
	assert(context == &taint_context_a || context == &taint_context_b);
	if (level == LOGLEVEL_EMERG) {
		assert(!strcmp(message, "panic_on_taint set ..."));
		if (expected_fatal_reference) {
			assert(reference_mask == expected_fatal_mask);
			assert(reference_panic_on_taint == 0);
			assert(reference_debug_locks == 0);
		} else {
			assert(get_taint() == expected_fatal_mask);
			assert(panic_on_taint == 0);
			assert(debug_locks == 0);
		}
		fatal_witness = 1;
		return;
	}
	assert(taint_event_count < ARRAY_SIZE(taint_events));
	struct taint_event *event = &taint_events[taint_event_count++];
	event->level = level;
	assert(strlen(message) < sizeof(event->message));
	memcpy(event->message, message, strlen(message) + 1);
}

static void taint_test_warn(void *context, const char *file, int line, const char *condition)
{
	assert(context == &taint_context_a || context == &taint_context_b);
	assert(file && line > 0 && condition);
	/* The warning callback executes before add_taint, including the first
	 * actual header WARN_ON_ONCE below. */
	if (!taint_warnings)
		assert(!test_taint(TAINT_WARN));
	taint_warnings++;
}

static void same_event(unsigned int a, unsigned int b)
{
	assert(taint_events[a].level == taint_events[b].level);
	assert(!strcmp(taint_events[a].message, taint_events[b].message));
}

static void compare_formats(unsigned long mask)
{
	/* Test-only case isolation, never an admission or retirement operation. */
	tainted_mask = reference_mask = mask;
	assert(get_taint() == reference_get_taint());
	for (unsigned i = 0; i < TAINT_FLAGS_COUNT; i++)
		assert(test_taint(i) == reference_test_taint(i));
	assert(!strcmp(print_tainted(), reference_print_tainted()));
	assert(!strcmp(print_tainted_verbose(), reference_print_verbose()));
	assert(strlen(print_tainted_verbose()) < sizeof(taint_buffer));
}

static void formats_and_bits(void)
{
	static const char characters[] = "PFSRMBUDAWCIOELKXTNJ";
	static const char *const names[] = {
		"PROPRIETARY_MODULE", "FORCED_MODULE", "CPU_OUT_OF_SPEC", "FORCED_RMMOD",
		"MACHINE_CHECK", "BAD_PAGE", "USER", "DIE", "OVERRIDDEN_ACPI_TABLE", "WARN",
		"CRAP", "FIRMWARE_WORKAROUND", "OOT_MODULE", "UNSIGNED_MODULE", "SOFTLOCKUP",
		"LIVEPATCH", "AUX", "RANDSTRUCT", "TEST", "FWCTL",
	};
	assert(sizeof(characters) - 1 == TAINT_FLAGS_COUNT && ARRAY_SIZE(names) == TAINT_FLAGS_COUNT);
	compare_formats(0);
	assert(!strcmp(print_tainted(), "Not tainted"));
	for (unsigned i = 0; i < TAINT_FLAGS_COUNT; i++) {
		assert(taint_flags[i].c_true == characters[i]);
		assert(taint_flags[i].c_false == (i == 0 ? 'G' : ' '));
		assert(!strcmp(taint_flags[i].desc, names[i]));
		assert(taint_flags[i].c_true == reference_flags[i].c_true);
		assert(taint_flags[i].c_false == reference_flags[i].c_false);
		assert(!strcmp(taint_flags[i].desc, reference_flags[i].desc));
		compare_formats(1UL << i);
		const char *short_string = print_tainted();
		assert(strlen(short_string) == 9 + TAINT_FLAGS_COUNT);
		assert(short_string[9 + i] == characters[i]);
		const char *verbose = print_tainted_verbose();
		assert(!strncmp(verbose, "Tainted: [", 10) && !strstr(verbose, ", "));
		assert(strstr(verbose, names[i]));
		/* Both variants return the permanent same buffer; later calls
		 * overwrite the earlier bytes, including shortening/NUL. */
		assert(short_string == verbose);
	}
	/* Exercise every flag through each real add/test/get entry, including
	 * idempotent repeated addition, rather than only preloading format masks. */
	tainted_mask = reference_mask = 0;
	for (unsigned i = 0; i < TAINT_FLAGS_COUNT; i++) {
		add_taint(i, LOCKDEP_STILL_OK);
		reference_add_taint(i, LOCKDEP_STILL_OK);
		add_taint(i, LOCKDEP_STILL_OK);
		reference_add_taint(i, LOCKDEP_STILL_OK);
		assert(get_taint() == ((1UL << (i + 1)) - 1));
		assert(get_taint() == reference_get_taint());
		assert(test_taint(i) && reference_test_taint(i));
	}
	compare_formats(TAINT_FLAGS_MAX);
	assert(strlen(print_tainted_verbose()) + 1 == 328);
	assert(!strcmp(print_tainted(), "Tainted: PFSRMBUDAWCIOELKXTNJ"));
	compare_formats(0x55555);
	compare_formats(0xaaaaa);
	compare_formats((1UL << TAINT_PROPRIETARY_MODULE) | (1UL << TAINT_FWCTL));
}

static void lock_state(void)
{
	tainted_mask = reference_mask = 0;
	panic_on_taint = reference_panic_on_taint = 0;
	debug_locks = reference_debug_locks = 1;
	taint_event_count = 0;
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);
	reference_add_taint(TAINT_USER, LOCKDEP_STILL_OK);
	assert(debug_locks == 1 && reference_debug_locks == 1 && taint_event_count == 0);
	add_taint(TAINT_USER, LOCKDEP_NOW_UNRELIABLE);
	reference_add_taint(TAINT_USER, LOCKDEP_NOW_UNRELIABLE);
	assert(debug_locks == 0 && reference_debug_locks == 0 && taint_event_count == 2);
	same_event(0, 1);
	assert(taint_events[0].level == LOGLEVEL_WARNING);
	assert(!strcmp(taint_events[0].message, "Disabling lock debugging due to kernel taint\n"));
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	reference_add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	assert(taint_event_count == 2);
	assert(get_taint() == ((1UL << TAINT_USER) | (1UL << TAINT_DIE)));
	assert(get_taint() == reference_get_taint());
	/* add_taint's original warning is not gated by debug_locks_silent. */
	debug_locks = reference_debug_locks = 1;
	debug_locks_silent = 1;
	add_taint(TAINT_AUX, LOCKDEP_NOW_UNRELIABLE);
	reference_add_taint(TAINT_AUX, LOCKDEP_NOW_UNRELIABLE);
	assert(taint_event_count == 4);
	same_event(2, 3);
	debug_locks_silent = 0;
}

static void setup_case(const char *input, int expected_return,
		       unsigned long expected_mask, bool expected_nousertaint)
{
	char owned[80], original[80];
	char *a = NULL, *b = NULL;
	if (input) {
		assert(strlen(input) < sizeof(owned));
		memcpy(owned, input, strlen(input) + 1);
		memcpy(original, input, strlen(input) + 1);
		a = owned;
		b = original;
	}
	taint_event_count = 0;
	int actual = panic_on_taint_setup(a);
	unsigned int produced = taint_event_count;
	int reference = reference_setup(b);
	assert(actual == expected_return && reference == actual);
	assert(panic_on_taint == expected_mask && reference_panic_on_taint == expected_mask);
	assert(panic_on_taint_nousertaint == expected_nousertaint);
	assert(reference_nousertaint == expected_nousertaint);
	if (input)
		assert(!memcmp(owned, original, strlen(input) + 1));
	assert(taint_event_count == 2 * produced);
	if (!actual) {
		assert(produced == 1 && taint_events[0].level == LOGLEVEL_INFO);
		same_event(0, 1);
	} else {
		assert(!produced);
	}
}

static void panic_setup(void)
{
	panic_on_taint = reference_panic_on_taint = 0;
	panic_on_taint_nousertaint = reference_nousertaint = false;
	setup_case(NULL, -EINVAL, 0, false);
	setup_case("", -EINVAL, 0, false);
	setup_case("40", 0, 0x40, false);
	setup_case("bogus,nousertaint", -EINVAL, 0x40, false);
	setup_case("100000", -EINVAL, 0, false);
	setup_case("100040,nousertaint", 0, 0x40, true);
	setup_case("0x200", 0, 0x200, true);
	setup_case("+00040\n", 0, 0x40, true);
	setup_case("80,nousertaint,extra", 0, 0x80, true);
	setup_case("ffffffffffffffff", 0, TAINT_FLAGS_MAX, true);
	setup_case("10000000000000000", -EINVAL, TAINT_FLAGS_MAX, true);
	setup_case("0", -EINVAL, 0, true);
	/* Wrong or repeated suffixes are accepted but do not enable the flag. */
	panic_on_taint_nousertaint = reference_nousertaint = false;
	setup_case("40,nousertaint,extra", 0, 0x40, false);
	setup_case("40,NOUSER TAINT", 0, 0x40, false);
	setup_case("40,", 0, 0x40, false);
	setup_case("40,nousertaint", 0, 0x40, true);
	setup_case("80", 0, 0x80, true);
}

static void production_fatal(void)
{
	expected_fatal_reference = false;
	expected_fatal_mask = (1UL << TAINT_USER) | (1UL << TAINT_AUX);
	tainted_mask = 1UL << TAINT_AUX;
	panic_on_taint = 1UL << TAINT_USER;
	panic_on_taint_nousertaint = true;
	debug_locks = 1;
	fatal_witness = 0;
	add_taint(TAINT_USER, LOCKDEP_NOW_UNRELIABLE);
	fatal_witness = 2;
}

static void original_fatal(void)
{
	expected_fatal_reference = true;
	expected_fatal_mask = (1UL << TAINT_USER) | (1UL << TAINT_AUX);
	reference_mask = 1UL << TAINT_AUX;
	reference_panic_on_taint = 1UL << TAINT_USER;
	reference_nousertaint = true;
	reference_debug_locks = 1;
	fatal_witness = 0;
	reference_add_taint(TAINT_USER, LOCKDEP_NOW_UNRELIABLE);
	fatal_witness = 2;
}

static void fatal_without_logger(void)
{
	const struct stela_linux_owner bare = {.services = stela_linux_bare.services};
	stela_linux_exit();
	stela_linux_enter(&bare);
	stela_linux_fatal("test terminal stop without a logger");
}

static void bad_flag(void)
{
	add_taint(TAINT_FLAGS_COUNT, LOCKDEP_STILL_OK);
}

static void bad_test_flag(void)
{
	(void)test_taint(~0U);
}

static void outside_owner(void)
{
	stela_linux_exit();
	(void)get_taint();
}

static void warn_once_site(bool condition)
{
	(void)WARN_ON_ONCE(condition);
}

int main(void)
{
	const struct stela_linux_services services = {.log = taint_test_log, .warn = taint_test_warn};
	const struct stela_linux_owner a = {.services = &services, .context = &taint_context_a};
	const struct stela_linux_owner b = {.services = &services, .context = &taint_context_b};
	stela_linux_enter(&a);
	assert(get_taint() == (IS_ENABLED(CONFIG_RANDSTRUCT) ? (1UL << TAINT_RANDSTRUCT) : 0));
	assert(debug_locks == 1 && debug_locks_silent == 0);
	formats_and_bits();
	lock_state();
	unsigned long permanent = get_taint();
	stela_linux_exit();
	stela_linux_enter(&b);
	assert(get_taint() == permanent && debug_locks == 0);
	/* A different owner and repeated addition keep the same image state. */
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);
	assert(get_taint() == permanent);
	panic_setup();
	panic_on_taint = 0;
	tainted_mask = 0;
	taint_warnings = 0;
	warn_once_site(false);
	assert(!taint_warnings && !get_taint());
	warn_once_site(true);
	warn_once_site(true);
	assert(taint_warnings == 1 && get_taint() == (1UL << TAINT_WARN));
	stela_linux_exit();
	stela_linux_enter(&a);
	warn_once_site(true);
	assert(taint_warnings == 1 && get_taint() == (1UL << TAINT_WARN));
	stela_linux_warn(__FILE__, __LINE__, "exact taint flags", BUGFLAG_TAINT(TAINT_FWCTL));
	assert(taint_warnings == 2 && test_taint(TAINT_FWCTL));
	assert(stela_taint_test_stops(production_fatal, &fatal_witness, 1));
	assert(stela_taint_test_stops(original_fatal, &fatal_witness, 1));
	assert(stela_test_traps(fatal_without_logger));
	/* Validation errors are terminal, so their dedicated loggerless owner
	 * avoids the panic-specific emergency-state assertions above. */
	stela_linux_exit();
	stela_linux_enter(&stela_linux_bare);
	assert(stela_test_traps(bad_flag));
	assert(stela_test_traps(bad_test_flag));
	assert(stela_test_traps(outside_owner));
	stela_linux_exit();
	printf("Linux taint: original state/format/setup differential, owners, warnings and fatal ordering passed\n");
	return 0;
}
