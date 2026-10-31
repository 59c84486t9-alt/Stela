// SPDX-License-Identifier: MIT
/* Process identity, with the interfaces of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/pid.c and kernel/sys.c.
 * Linux code under Stela runs on the owner's tasks and clients are the
 * owner's, so no process exists here: tasks have no struct pid, and a
 * task's number is its own. */
#include <linux/pid.h>
#include <linux/sched.h>

/* The uid Linux reports for one a namespace cannot express. */
int overflowuid = 65534;

void put_pid(struct pid *pid)
{
	WARN_ON_ONCE(pid);
}

struct task_struct *pid_task(struct pid *pid, enum pid_type type)
{
	(void)type;
	WARN_ON_ONCE(pid);
	return NULL;
}

pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type, struct pid_namespace *ns)
{
	(void)type;
	(void)ns;
	return task->pid;
}
