/* SPDX-License-Identifier: GPL-2.0-only */
/* Exact retained Linux init/main.c setup/repair/early bodies. Copyright (C)
 * 1991, 1992 Linus Torvalds. Macro names adapt only the isolated fixture's
 * table, function identity and diagnostic collection, never their semantics. */
#pragma GCC diagnostic push
/* Original source uses int strlen result; retain its bytes as the oracle. */
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define obsolete_checksetup reference_obsolete_checksetup
#define repair_env_string reference_repair_env_string
#define do_early_param reference_do_early_param
#define __setup_start reference_setup_start
#define __setup_end reference_setup_end
static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

static void __init repair_env_string(char *param, char *val)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
		} else
			BUG();
	}
}

static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if (p->early && parameq(param, p->str)) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}
#undef obsolete_checksetup
#undef repair_env_string
#undef do_early_param
#undef __setup_start
#undef __setup_end
#pragma GCC diagnostic pop
