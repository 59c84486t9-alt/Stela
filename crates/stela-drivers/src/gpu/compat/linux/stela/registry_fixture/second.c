/* SPDX-License-Identifier: MIT */
#include "fixture.h"
#include <stela/registration.h>
static int duplicate(void) { stela_registry_fixture_event(20); return 0; }
static void leave(void) { stela_registry_fixture_event(21); }
static int count;
static int setup(char *value) { (void)value; stela_registry_fixture_event(22); return -1; }
static int early(char *value) { (void)value; stela_registry_fixture_event(23); return -22; }
module_param(count, int, 0644);
__setup("fixture=", setup);
early_param("fixture-early", early);
/* Explicit unique-id obsolete handler must remain a real NULL setup target. */
__setup_param("obsolete", obsolete_fixture, NULL, 0);
core_initcall_sync(duplicate);
core_initcall(duplicate);
device_initcall(duplicate);
__exitcall(leave);
MODULE_INFO(description, "second TU, same real Kbuild group as first");

const struct kernel_param *stela_fixture_second_count(void)
{
 return &__param_count;
}
