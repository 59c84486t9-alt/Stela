/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included only by params.c's dedicated hosted parser fixture. The oracle
 * functions below are retained Linux source bytes, not another implementation. */
#include <stela/test.h>

char *source_next_arg(char *args, char **param, char **val);
#define dash2underscore source_dash2underscore
#define parameqn source_parameqn
#define parameq source_parameq
#define param_check_unsafe source_param_check_unsafe
#define parse_one source_parse_one
#define parse_args source_parse_args
#define next_arg source_next_arg
#include <stela/params-reference.h>
#undef next_arg
#undef parse_args
#undef parse_one
#undef param_check_unsafe
#undef parameq
#undef parameqn
#undef dash2underscore

#define TOKEN_BYTES 512
#define TRACE_ENTRIES 32
struct parser_call {
	const struct kernel_param *kp;
	bool null_value;
	bool tainted;
	char name[48];
	char value[80];
};
struct parser_capture {
	char bytes[TOKEN_BYTES];
	char diagnostics[2048];
	size_t diagnostic_length;
	struct parser_call calls[TRACE_ENTRIES];
	unsigned int count;
	unsigned int setters;
	unsigned int unknowns;
	unsigned int mutations;
	int result_kind;
	long result_value;
};
static struct parser_capture *active_capture;

static void parser_log(void *context, int level, const char *message)
{
	struct parser_capture *capture = context;
	assert(capture == active_capture);
	/* Retain both severity and complete formatted diagnostic bytes. */
	int added = scnprintf(capture->diagnostics + capture->diagnostic_length,
			      sizeof(capture->diagnostics) - capture->diagnostic_length,
			      "%d:%s", level, message);
	assert(added > 0 && capture->diagnostic_length + added < sizeof(capture->diagnostics) - 1);
	capture->diagnostic_length += added;
}

static struct parser_call *parser_trace(const struct kernel_param *kp, const char *name,
				       const char *value)
{
	assert(active_capture->count < TRACE_ENTRIES);
	struct parser_call *call = &active_capture->calls[active_capture->count++];
	call->kp = kp;
	call->null_value = !value;
	call->tainted = !!(get_taint() & (1UL << TAINT_USER));
	assert(strlen(name) < sizeof(call->name));
	strcpy(call->name, name);
	if (value) {
		assert(strlen(value) < sizeof(call->value));
		strcpy(call->value, value);
	}
	return call;
}

static int parser_set(const char *value, const struct kernel_param *kp)
{
	parser_trace(kp, kp->name, value);
	active_capture->setters++;
	/* A custom setter can mutate before returning an error. No rollback. */
	active_capture->mutations++;
	if (kp->flags & KERNEL_PARAM_FL_UNSAFE)
		assert(get_taint() & (1UL << TAINT_USER));
	if (!value)
		return 0;
	if (!strcmp(value, "bad"))
		return -EINVAL;
	if (!strcmp(value, "large"))
		return -ENOSPC;
	if (!strcmp(value, "range"))
		return -ERANGE;
	return 0;
}

static int parser_unknown(char *param, char *val, const char *doing, void *arg)
{
	assert(arg == active_capture && !strcmp(doing, "fixture"));
	parser_trace(NULL, param, val);
	active_capture->unknowns++;
	if (val && !strcmp(param, "repair"))
		param[strlen(param)] = '=';
	if (!strcmp(param, "consume"))
		return 0;
	if (!strcmp(param, "large"))
		return -ENOSPC;
	if (!strcmp(param, "range"))
		return -ERANGE;
	return -ENOENT;
}

static const struct kernel_param_ops parser_ops = {.set = parser_set};
static const struct kernel_param_ops noarg_ops = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG, .set = parser_set,
};
/* Shared exact addresses used by all three executions. A duplicate public
 * name tests original first-match filtering, including no setup fallback. */
static const struct kernel_param parser_parameters[] = {
	{.name = "x", .ops = &parser_ops, .level = -1},
	{.name = "has_dash", .ops = &parser_ops, .level = -1},
	{.name = "switch", .ops = &noarg_ops, .level = -1},
	{.name = "shadow", .ops = &parser_ops, .level = 5},
	{.name = "shadow", .ops = &parser_ops, .level = -1},
	{.name = "unsafe", .ops = &parser_ops, .level = -1, .flags = KERNEL_PARAM_FL_UNSAFE},
	{.name = "hardware", .ops = &parser_ops, .level = -1,
	 .flags = KERNEL_PARAM_FL_HWPARAM | KERNEL_PARAM_FL_UNSAFE},
};

static void parser_result(struct parser_capture *capture, char *result)
{
	unsigned long address = (unsigned long)result;
	unsigned long base = (unsigned long)capture->bytes;
	if (!result) {
		capture->result_kind = 0;
	} else if (address >= base && address < base + sizeof(capture->bytes)) {
		capture->result_kind = 1;
		capture->result_value = address - base;
	} else {
		capture->result_kind = 2;
		capture->result_value = (long)result;
	}
}

static void parser_run(struct parser_capture *capture, const char *command, unsigned int path,
		       s16 min, s16 max, bool with_unknown)
{
	memset(capture, 0, sizeof(*capture));
	memset(capture->bytes, 0x92, sizeof(capture->bytes));
	assert(strlen(command) < sizeof(capture->bytes));
	strcpy(capture->bytes, command);
	active_capture = capture;
	const struct stela_linux_services services = {.log = parser_log};
	const struct stela_linux_owner owner = {.services = &services, .context = capture};
	stela_linux_enter(&owner);
	parse_unknown_fn unknown = with_unknown ? parser_unknown : NULL;
	char *result;
	if (!path) {
		result = source_parse_args("fixture", capture->bytes, parser_parameters,
			ARRAY_SIZE(parser_parameters), min, max, capture, unknown);
	} else if (path == 1) {
		result = parse_args("fixture", capture->bytes, parser_parameters,
			ARRAY_SIZE(parser_parameters), min, max, capture, unknown);
	} else {
		const struct kernel_param *view[ARRAY_SIZE(parser_parameters)];
		for (size_t i = 0; i < ARRAY_SIZE(view); i++)
			view[i] = &parser_parameters[i];
		struct stela_linux_params_result parsed = stela_linux_parse_args_view(
			"fixture", capture->bytes, view, ARRAY_SIZE(view), min, max,
			capture, unknown, NULL);
		assert(!parsed.observer_error);
		result = parsed.result;
	}
	parser_result(capture, result);
	stela_linux_exit();
	active_capture = NULL;
}

/* Run before any canonical case seeds TAINT_USER: missing required values
 * and filtered levels must leave the real bit clear; a failing unsafe setter
 * must see both the original notice and the taint already committed. */
static void unsafe_dispatch_order(void)
{
	struct parser_capture capture = {0};
	active_capture = &capture;
	const struct stela_linux_services services = {.log = parser_log};
	const struct stela_linux_owner owner = {.services = &services, .context = &capture};
	const struct kernel_param *view[] = {&parser_parameters[5]};
	stela_linux_enter(&owner);
	assert(!(get_taint() & (1UL << TAINT_USER)));
	strcpy(capture.bytes, "unsafe");
	struct stela_linux_params_result parsed = stela_linux_parse_args_view(
		"fixture", capture.bytes, view, 1, -1, -1, NULL, NULL, NULL);
	assert(parsed.result == ERR_PTR(-EINVAL) && !parsed.observer_error);
	assert(!capture.setters && !(get_taint() & (1UL << TAINT_USER)));
	memset(&capture, 0, sizeof(capture));
	strcpy(capture.bytes, "unsafe=filtered");
	parsed = stela_linux_parse_args_view("fixture", capture.bytes, view, 1, 0, 7, NULL, NULL, NULL);
	assert(!parsed.result && !parsed.observer_error && !capture.setters);
	assert(!capture.diagnostic_length && !(get_taint() & (1UL << TAINT_USER)));
	memset(&capture, 0, sizeof(capture));
	strcpy(capture.bytes, "unsafe=bad");
	parsed = stela_linux_parse_args_view("fixture", capture.bytes, view, 1, -1, -1, NULL, NULL, NULL);
	assert(parsed.result == ERR_PTR(-EINVAL) && !parsed.observer_error);
	assert(capture.setters == 1 && capture.calls[0].tainted);
	assert(!strncmp(capture.diagnostics,
		"5:Setting dangerous option unsafe - tainting kernel\n",
		strlen("5:Setting dangerous option unsafe - tainting kernel\n")));
	assert(get_taint() & (1UL << TAINT_USER)); /* Failed set never rolls back. */
	stela_linux_exit();
	active_capture = NULL;
}

static void canonical_parser_differential(void)
{
	const struct {
		const char *command;
		s16 min, max;
		bool unknown;
		int error;
		unsigned int setters, unknowns;
		const char *tail;
	} cases[] = {
		{"", -1, -1, false, 0, 0, 0, NULL},
		{" \t\n\r\v\f", -1, -1, false, 0, 0, 0, NULL},
		{"x=one", -1, -1, false, 0, 1, 0, NULL},
		{"x=one x=two", -1, -1, false, 0, 2, 0, NULL},
		{"x", -1, -1, false, -EINVAL, 0, 0, NULL},
		{"x=", -1, -1, false, 0, 1, 0, NULL},
		{"switch", -1, -1, false, 0, 1, 0, NULL},
		{"switch= switch=false", -1, -1, false, 0, 2, 0, NULL},
		{"has-dash=a has_dash=b", -1, -1, false, 0, 2, 0, NULL},
		{"X=case", -1, -1, false, -ENOENT, 0, 0, NULL},
		{"x=\"two words\"", -1, -1, false, 0, 1, 0, NULL},
		{"\"x=two words\"", -1, -1, false, 0, 1, 0, NULL},
		{"x=\"unterminated space", -1, -1, false, 0, 1, 0, NULL},
		{"x=a=b=c", -1, -1, false, 0, 1, 0, NULL},
		{"x=\"\"", -1, -1, false, 0, 1, 0, NULL},
		{"\"switch\"", -1, -1, false, 0, 1, 0, NULL},
		{"=odd", -1, -1, true, -ENOENT, 0, 1, NULL},
		{"x=one,two", -1, -1, false, 0, 1, 0, NULL},
		{"shadow=value", -1, -1, true, 0, 0, 0, NULL},
		{"shadow", -1, -1, true, 0, 0, 0, NULL},
		{"shadow=value", 5, 5, false, 0, 1, 0, NULL},
		{"shadow=value x=ignored", -1, 5, false, 0, 2, 0, NULL},
		{"unknown=value", -1, -1, false, -ENOENT, 0, 0, NULL},
		{"repair=abc", -1, -1, true, -ENOENT, 0, 1, NULL},
		{"unknown=\"two words\"", -1, -1, true, -ENOENT, 0, 1, NULL},
		{"\"consume=two words\" consume", -1, -1, true, 0, 0, 2, NULL},
		{"x=bad x=valid", -1, -1, false, -EINVAL, 2, 0, NULL},
		{"x=bad x=large x=range x=valid", -1, -1, false, -ERANGE, 4, 0, NULL},
		{"range=q large=foo consume=ok", -1, -1, true, -ENOSPC, 0, 3, NULL},
		{"-- untouched=x tail", -1, -1, false, 0, 0, 0, "untouched=x tail"},
		{"x=one --  x=untouched", -1, -1, false, 0, 1, 0, "x=untouched"},
		{"x=bad -- x=untouched", -1, -1, false, -EINVAL, 1, 0, NULL},
		{"--=value x=one", -1, -1, true, -ENOENT, 1, 1, NULL},
		{"unsafe", -1, -1, false, -EINVAL, 0, 0, NULL},
		{"unsafe=bad x=valid", -1, -1, false, -EINVAL, 2, 0, NULL},
		{"hardware=value", -1, -1, false, 0, 1, 0, NULL},
		{"unsafe=ignored", 0, 7, false, 0, 0, 0, NULL},
	};
	/* TAINT_USER is monotonic. Seed the real shared state before canonical
	 * comparisons so the reference and both paths have identical inputs. */
	stela_linux_enter(&stela_linux_bare);
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);
	stela_linux_exit();
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct parser_capture oracle, actual;
		parser_run(&oracle, cases[i].command, 0, cases[i].min, cases[i].max, cases[i].unknown);
		assert(oracle.setters == cases[i].setters && oracle.unknowns == cases[i].unknowns);
		assert(oracle.mutations == oracle.setters);
		if (cases[i].error) {
			assert(oracle.result_kind == 2 && oracle.result_value == cases[i].error);
		} else if (cases[i].tail) {
			assert(oracle.result_kind == 1);
			assert(!strcmp(oracle.bytes + oracle.result_value, cases[i].tail));
		} else {
			assert(!oracle.result_kind);
		}
		for (unsigned int path = 1; path <= 2; path++) {
			parser_run(&actual, cases[i].command, path, cases[i].min, cases[i].max, cases[i].unknown);
			/* Every byte was initialized, including trace padding and token
			 * suffix poison. Equal counts alone cannot pass this oracle. */
			assert(!memcmp(&oracle, &actual, sizeof(oracle)));
		}
	}
	assert(parameq("hyphen-name", "hyphen_name"));
	assert(!parameq("hyphen", "hyphen_more"));
	assert(parameqn("hyphen-nameSUFFIX", "hyphen_name", 11));
	assert(!parameqn("hyphen-NAME", "hyphen_name", 11));
}

struct parser_observer_state {
	enum stela_linux_param_event fail_event;
	int failure;
	unsigned int before, after;
	int last_result;
};
static int parser_observe(void *context, enum stela_linux_param_event event,
			  const struct kernel_param *kp, char *param, char *val, int result)
{
	struct parser_observer_state *state = context;
	assert(param && val && !strcmp(val, "bad"));
	if (event == STELA_LINUX_PARAM_BEFORE_SET || event == STELA_LINUX_PARAM_AFTER_SET)
		assert(kp == &parser_parameters[0]);
	else
		assert(!kp);
	if (event == STELA_LINUX_PARAM_BEFORE_SET || event == STELA_LINUX_PARAM_BEFORE_UNKNOWN) {
		state->before++;
		assert(!result && !active_capture->count);
	} else {
		state->after++;
		state->last_result = result;
		assert(active_capture->count == 1);
	}
	return event == state->fail_event ? state->failure : 0;
}

static void observer_terminal_failures(void)
{
	for (unsigned int event = 0; event < 4; event++) {
		for (unsigned int positive = 0; positive < 2; positive++) {
			struct parser_capture capture = {0};
			active_capture = &capture;
			strcpy(capture.bytes, event < 2 ? "x=bad x=later" : "range=bad x=later");
			const struct stela_linux_services services = {.log = parser_log};
			const struct stela_linux_owner owner = {.services = &services, .context = &capture};
			stela_linux_enter(&owner);
			const struct kernel_param *view[] = {&parser_parameters[0]};
			struct parser_observer_state state = {.fail_event = event,
				.failure = positive ? 1 : -EOWNERDEAD};
			const struct stela_linux_param_observer observer = {
				.observe = parser_observe, .context = &state,
			};
			struct stela_linux_params_result parsed = stela_linux_parse_args_view(
				"fixture", capture.bytes, view, ARRAY_SIZE(view), -1, -1,
				&capture, parser_unknown, &observer);
			int expected = positive ? -EPROTO : -EOWNERDEAD;
			assert(parsed.observer_error == expected && parsed.result == ERR_PTR(expected));
			bool after = event == STELA_LINUX_PARAM_AFTER_SET || event == STELA_LINUX_PARAM_AFTER_UNKNOWN;
			assert(state.before == 1 && state.after == after);
			assert(capture.count == after && capture.mutations == (after && event < 2));
			if (after)
				assert(state.last_result == (event < 2 ? -EINVAL : -ERANGE));
			assert(strstr(capture.bytes + (event < 2 ? 6 : 10), "x=later"));
			assert(!capture.diagnostic_length); /* terminal before error logger */
			stela_linux_exit();
			active_capture = NULL;
		}
	}
}

static void explicit_dispatch_extensions(void)
{
	const struct kernel_param_ops readonly = {0};
	const struct kernel_param_ops future_ops = {.flags = 2, .set = parser_set};
	struct kernel_param parameter = {.name = "extension", .ops = &readonly, .level = -1};
	const struct kernel_param *view[] = {&parameter, &parser_parameters[0]};
	const struct kernel_param_ops *operations[] = {&readonly, &future_ops, &parser_ops};
	const int errors[] = {-EPERM, -EOPNOTSUPP, -EOPNOTSUPP};
	for (unsigned int i = 0; i < ARRAY_SIZE(operations); i++) {
		struct parser_capture capture = {0};
		active_capture = &capture;
		strcpy(capture.bytes, "extension=value x=later");
		parameter.ops = operations[i];
		parameter.flags = i == 2 ? 0x80 : 0;
		const struct stela_linux_services services = {.log = parser_log};
		const struct stela_linux_owner owner = {.services = &services, .context = &capture};
		stela_linux_enter(&owner);
		struct stela_linux_params_result parsed = stela_linux_parse_args_view(
			"fixture", capture.bytes, view, ARRAY_SIZE(view), -1, -1, NULL, NULL, NULL);
		assert(!parsed.observer_error && parsed.result == ERR_PTR(errors[i]));
		assert(capture.setters == 1 && capture.calls[0].kp == &parser_parameters[0]);
		stela_linux_exit();
		active_capture = NULL;
	}
}

int main(void)
{
	unsafe_dispatch_order();
	canonical_parser_differential();
	observer_terminal_failures();
	explicit_dispatch_extensions();
	printf("Linux parser: retained-source differential, exact descriptors and terminal observers passed\n");
	return 0;
}
