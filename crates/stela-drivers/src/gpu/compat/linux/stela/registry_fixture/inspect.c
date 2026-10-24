/* SPDX-License-Identifier: MIT */
#include "fixture.h"
#include <linux/string.h>
#include <linux/mod_devicetable.h>
#include <stela/test.h>
#include <stela/linux.h>
static unsigned int events[64], event_count;
void stela_registry_fixture_event(unsigned int value)
{
 assert(event_count < ARRAY_SIZE(events));
 events[event_count++] = value;
}
/* Link this with the ACTUAL generated fixture manifest and four original-
 * macro fixture objects. It inspects/executes exact retained targets, without
 * claiming registry phase/lifetime or hardware qualification. */
int main(void)
{
 const struct stela_linux_registry_image *image = &stela_linux_fixture_image;
 const struct stela_linux_init_record *module = NULL;
 const struct stela_linux_build_unit *first = NULL, *second = NULL;
 unsigned int normal = 0, sync = 0, early = 0, rootfs = 0, console = 0;
 unsigned int modules = 0, obsolete = 0;
 size_t i;
 assert(image->abi_version == STELA_LINUX_REGISTRY_ABI);
 assert(image->unit_count == 4 && image->group_count == 2);
 assert(image->parameter_count == 4 && image->setup_count == 5);
 assert(image->device_count == 1 && image->exit_count == 4);
 assert(image->info_count == 10);
 assert(image->init_count == 23);
 assert(!strcmp(image->groups[0]->module_name, "nouveau"));
 assert(!strcmp(image->groups[1]->module_name, "ch7006"));
 first = image->units[0]; second = image->units[1];
 assert(first != second && first->group == second->group);
 assert(image->units[2]->group != first->group);
 assert(image->parameters[0]->target == stela_fixture_first_count());
 assert(image->parameters[1]->target == stela_fixture_first_borrowed());
 assert(image->parameters[2]->target == stela_fixture_second_count());
 assert(image->parameters[3]->target == stela_fixture_third_count());
 assert(image->parameters[0]->target != image->parameters[2]->target);
 assert(!strcmp(image->parameters[0]->target->name, "nouveau.count"));
 assert(!strcmp(image->parameters[2]->target->name, "nouveau.count"));
 for (i = 0; i < image->init_count; i++) {
  const struct stela_linux_init_record *record = image->inits[i];
  assert(record->header.unit_ordinal == record->unit->ordinal);
  if (i && record->unit == image->inits[i - 1]->unit)
   assert(record->header.emission_sequence > image->inits[i - 1]->header.emission_sequence);
  if (record->header.kind == STELA_LINUX_REG_MODULE_INIT) {
   modules++; if (!module) module = record; continue;
  }
  if (record->header.level == STELA_LINUX_REG_EARLY_LEVEL) early++;
  else if (record->header.level == STELA_LINUX_REG_ROOTFS_LEVEL) rootfs++;
  else if (record->header.kind == STELA_LINUX_REG_CONSOLE) console++;
  else if (record->header.flags & STELA_LINUX_REG_SYNC) sync++;
  else normal++;
 }
 assert(modules == 2 && early == 1 && rootfs == 1 && console == 1);
 assert(normal == 10 && sync == 8);
 for (i = 0; i < image->setup_count; i++) {
  const struct stela_linux_setup_record *record = image->setups[i];
  if (!record->target) { assert(!strcmp(record->label, "obsolete")); obsolete++; }
 }
 assert(obsolete == 1);
 stela_linux_enter(&stela_linux_bare);
 assert(module && module->target() == 0);
 stela_linux_exit();
 assert(event_count == 1 && events[0] == 10);
 assert(image->devices[0]->size == 2 * sizeof(struct pci_device_id));
 return 0;
}
