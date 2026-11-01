/* SPDX-License-Identifier: MIT */
/* Hosted-only process isolation: permanent production singleton state is never
 * reset to run a second scenario. A signal/abnormal exit is a fixture failure. */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
int stela_test_registry_case(void (*run)(void))
{
 pid_t child = fork();
 if (child < 0) return 0;
 if (!child) { run(); _exit(0); }
 int status;
 while (waitpid(child,&status,0) < 0) if (errno != EINTR) return 0;
 return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
