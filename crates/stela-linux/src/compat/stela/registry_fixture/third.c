/* SPDX-License-Identifier: MIT */
#include "fixture.h"
#include <stela/registration.h>
static int duplicate(void) { stela_registry_fixture_event(30); return -5; }
static void leave(void) { stela_registry_fixture_event(31); }
static int count;
module_param(count, int, 0);
module_init(duplicate);
module_exit(leave);
/* A generic exit is metadata, never guessed as an init inverse. */
__exitcall(leave);
MODULE_INFO(description, "independent real Kbuild group");

const struct kernel_param *stela_fixture_third_count(void)
{
 return &__param_count;
}
