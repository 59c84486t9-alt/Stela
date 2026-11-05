/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef STELA_PARAMS_H
#define STELA_PARAMS_H
#include <linux/moduleparam.h>

/* Each entry runs under the existing entered, serialized Linux owner.
 * The caller supplies owned writable token bytes with the lifetime of EVERY
 * consumer, including a custom setter retaining a value pointer. The registry
 * view uses a checked-quiescent owner and its observer enforces that boundary
 * before and after callbacks; no observer/context is retained. */
enum stela_linux_param_event {
	STELA_LINUX_PARAM_BEFORE_SET,
	STELA_LINUX_PARAM_AFTER_SET,
	STELA_LINUX_PARAM_BEFORE_UNKNOWN,
	STELA_LINUX_PARAM_AFTER_UNKNOWN,
};

struct stela_linux_param_observer {
	/* Borrowed for this parse call only. BEFORE result is zero. AFTER is
	 * delivered even after a setter/unknown error. A negative return is a
	 * terminal context failure: stop immediately without parsing another
	 * token, and keep all prior effects. A positive observer return is an
	 * observer contract violation reported as -EPROTO. Unknown has kp=NULL.
	 * BEFORE_SET precedes HWPARAM/UNSAFE/security/taint effects as well as
	 * the actual setter. No callback occurs for a filtered or rejected kp. */
	int (*observe)(void *context, enum stela_linux_param_event event,
		       const struct kernel_param *kp, char *param, char *val, int result);
	void *context;
};

struct stela_linux_params_result {
	/* Source parse_args convention: NULL, -- tail, or ERR_PTR(last error).
	 * On terminal observer failure this is ERR_PTR(observer_error). */
	char *result;
	int observer_error;
};

struct stela_linux_params_result stela_linux_parse_args_view(
	const char *doing, char *args, const struct kernel_param *const *params,
	unsigned int num, s16 min_level, s16 max_level, void *arg,
	parse_unknown_fn unknown, const struct stela_linux_param_observer *observer);
#endif
