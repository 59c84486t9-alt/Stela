/* SPDX-License-Identifier: GPL-2.0-only */
/* Verbatim bounded projections: Linux kernel/params.c Copyright (C) 2001
 * Rusty Russell; lib/cmdline.c code/copyrights from init/main.c and
 * arch/i386/kernel/setup.c. See source-projection.json for exact ranges. */
static char dash2underscore(char c)
{
	if (c == '-')
		return '_';
	return c;
}

bool parameqn(const char *a, const char *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (dash2underscore(a[i]) != dash2underscore(b[i]))
			return false;
	}
	return true;
}

bool parameq(const char *a, const char *b)
{
	return parameqn(a, b, strlen(a)+1);
}

static bool param_check_unsafe(const struct kernel_param *kp)
{
	if (kp->flags & KERNEL_PARAM_FL_HWPARAM &&
	    security_locked_down(LOCKDOWN_MODULE_PARAMETERS))
		return false;

	if (kp->flags & KERNEL_PARAM_FL_UNSAFE) {
		pr_notice("Setting dangerous option %s - tainting kernel\n",
			  kp->name);
		add_taint(TAINT_USER, LOCKDEP_STILL_OK);
	}

	return true;
}

static int parse_one(char *param,
		     char *val,
		     const char *doing,
		     const struct kernel_param *params,
		     unsigned num_params,
		     s16 min_level,
		     s16 max_level,
		     void *arg, parse_unknown_fn handle_unknown)
{
	unsigned int i;
	int err;

	/* Find parameter */
	for (i = 0; i < num_params; i++) {
		if (parameq(param, params[i].name)) {
			if (params[i].level < min_level
			    || params[i].level > max_level)
				return 0;
			/* No one handled NULL, so do it here. */
			if (!val &&
			    !(params[i].ops->flags & KERNEL_PARAM_OPS_FL_NOARG))
				return -EINVAL;
			pr_debug("handling %s with %p\n", param,
				params[i].ops->set);
			kernel_param_lock(params[i].mod);
			if (param_check_unsafe(&params[i]))
				err = params[i].ops->set(val, &params[i]);
			else
				err = -EPERM;
			kernel_param_unlock(params[i].mod);
			return err;
		}
	}

	if (handle_unknown) {
		pr_debug("doing %s: %s='%s'\n", doing, param, val);
		return handle_unknown(param, val, doing, arg);
	}

	pr_debug("Unknown argument '%s'\n", param);
	return -ENOENT;
}

/* Args looks like "foo=bar,bar2 baz=fuz wiz". */
char *parse_args(const char *doing,
		 char *args,
		 const struct kernel_param *params,
		 unsigned int num,
		 s16 min_level,
		 s16 max_level,
		 void *arg, parse_unknown_fn unknown)
{
	char *param, *val, *err = NULL;

	/* Chew leading spaces */
	args = skip_spaces(args);

	if (*args)
		pr_debug("doing %s, parsing ARGS: '%s'\n", doing, args);

	while (*args) {
		int ret;
		int irq_was_disabled;

		args = next_arg(args, &param, &val);
		/* Stop at -- */
		if (!val && strcmp(param, "--") == 0)
			return err ?: args;
		irq_was_disabled = irqs_disabled();
		ret = parse_one(param, val, doing, params, num,
				min_level, max_level, arg, unknown);
		if (irq_was_disabled && !irqs_disabled())
			pr_warn("%s: option '%s' enabled irq's!\n",
				doing, param);

		switch (ret) {
		case 0:
			continue;
		case -ENOENT:
			pr_err("%s: Unknown parameter `%s'\n", doing, param);
			break;
		case -ENOSPC:
			pr_err("%s: `%s' too large for parameter `%s'\n",
			       doing, val ?: "", param);
			break;
		default:
			pr_err("%s: `%s' invalid for parameter `%s'\n",
			       doing, val ?: "", param);
			break;
		}

		err = ERR_PTR(ret);
	}

	return err;
}

/*
 * Parse a string to get a param value pair.
 * You can use " around spaces, but can't escape ".
 * Hyphens and underscores equivalent in parameter names.
 */
char *next_arg(char *args, char **param, char **val)
{
	unsigned int i, equals = 0;
	int in_quote = 0, quoted = 0;

	if (*args == '"') {
		args++;
		in_quote = 1;
		quoted = 1;
	}

	for (i = 0; args[i]; i++) {
		if (isspace(args[i]) && !in_quote)
			break;
		if (equals == 0) {
			if (args[i] == '=')
				equals = i;
		}
		if (args[i] == '"')
			in_quote = !in_quote;
	}

	*param = args;
	if (!equals)
		*val = NULL;
	else {
		args[equals] = '\0';
		*val = args + equals + 1;

		/* Don't include quotes in value. */
		if (**val == '"') {
			(*val)++;
			if (args[i-1] == '"')
				args[i-1] = '\0';
		}
	}
	if (quoted && i > 0 && args[i-1] == '"')
		args[i-1] = '\0';

	if (args[i]) {
		args[i] = '\0';
		args += i + 1;
	} else
		args += i;

	/* Chew up trailing spaces. */
	return skip_spaces(args);
}
