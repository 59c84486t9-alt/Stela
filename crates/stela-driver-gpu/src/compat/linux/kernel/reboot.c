// SPDX-License-Identifier: MIT
/* Linux's orderly_poweroff, following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/reboot.c. Its callers hold
 * atomic contexts, so the request runs as work. Linux's work starts
 * /sbin/poweroff and forces the machine off if that fails; here the owner
 * shuts the machine down, and force tells it not to wait for clean exits. */
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <stela/linux.h>

static bool force_poweroff;

static void poweroff(struct work_struct *work)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	(void)work;
	if (owner->services->shutdown)
		owner->services->shutdown(owner->context, READ_ONCE(force_poweroff));
	else
		stela_linux_unsupported("orderly poweroff");
}
static DECLARE_WORK(poweroff_work, poweroff);

void orderly_poweroff(bool force)
{
	if (force)
		WRITE_ONCE(force_poweroff, true);
	schedule_work(&poweroff_work);
}
