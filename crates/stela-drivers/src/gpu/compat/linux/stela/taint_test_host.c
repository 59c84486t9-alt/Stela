/* SPDX-License-Identifier: MIT */
/* Host-only trap observer; compile outside the Linux header environment,
 * beside stela/test.c. Never part of a native image or Linux service. */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(__builtin_types_compatible_p(sig_atomic_t, int),
	       "hosted witness requires int sig_atomic_t");
static volatile sig_atomic_t *stop_witness;
static sig_atomic_t stop_expected;

static void stopped(int signal_number)
{
	(void)signal_number;
	_Exit(*stop_witness == stop_expected ? 86 : 89);
}

int stela_taint_test_stops(void (*operation)(void), volatile int *witness, int expected)
{
	pid_t child = fork();
	if (child < 0)
		abort();
	if (!child) {
		stop_witness = witness;
		stop_expected = expected;
		if (signal(SIGILL, stopped) == SIG_ERR)
			_Exit(87);
		operation();
		_Exit(88);
	}
	int status;
	while (waitpid(child, &status, 0) < 0)
		if (errno != EINTR)
			abort();
	return WIFEXITED(status) && WEXITSTATUS(status) == 86;
}
