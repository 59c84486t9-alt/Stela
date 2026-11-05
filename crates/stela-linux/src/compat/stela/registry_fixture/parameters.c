/* SPDX-License-Identifier: MIT */
#include <linux/module.h>
#include <linux/string.h>
#include <stela/registration.h>
/* Separate authored image: genuine original wrappers and private descriptors,
 * without changing the base 47-record capture fixture. */
static int plain, core_danger, count, danger, irq;
static bool enabled;
static char label[32];
static int custom_value;
static unsigned int custom_calls;
static const struct kernel_param *last_custom;
static int fixture_set(const char *value, const struct kernel_param *parameter)
{
 last_custom = parameter;
 custom_calls++;
 return param_set_int(value, parameter);
}
static const struct kernel_param_ops fixture_ops = {
 .set = fixture_set, .get = param_get_int,
};
core_param(core_plain, plain, int, 0600);
core_param_unsafe(core_danger, core_danger, int, 0);
module_param(enabled, bool, 0);
module_param_named(count_alias, count, int, 0644);
module_param_unsafe(danger, int, 0);
module_param_hw_named(irq_line, irq, int, irq, 0444);
module_param_string(label, label, sizeof(label), 0);
__core_param_cb(core_custom, &fixture_ops, &custom_value, 0);
module_param_cb(callback, &fixture_ops, &custom_value, 0);
module_param_cb_unsafe(danger_callback, &fixture_ops, &custom_value, 0);
core_param_cb(level_core, &fixture_ops, &custom_value, 0);
postcore_param_cb(level_postcore, &fixture_ops, &custom_value, 0);
arch_param_cb(level_arch, &fixture_ops, &custom_value, 0);
subsys_param_cb(level_subsys, &fixture_ops, &custom_value, 0);
fs_param_cb(level_fs, &fixture_ops, &custom_value, 0);
device_param_cb(level_device, &fixture_ops, &custom_value, 0);
late_param_cb(level_late, &fixture_ops, &custom_value, 0);

size_t stela_fixture_parameter_originals(const struct kernel_param *const **out)
{
 static const struct kernel_param *const originals[] = {
  &__param_core_plain, &__param_core_danger, &__param_enabled,
  &__param_count_alias, &__param_danger, &__param_irq_line, &__param_label,
  &__param_core_custom, &__param_callback, &__param_danger_callback,
  &__param_level_core, &__param_level_postcore, &__param_level_arch,
  &__param_level_subsys, &__param_level_fs, &__param_level_device,
  &__param_level_late,
 };
 *out = originals;
 return ARRAY_SIZE(originals);
}
bool stela_fixture_parameter_values_match(void)
{
 return plain == 11 && core_danger == 12 && enabled && count == 13 &&
  danger == 14 && irq == 15 && !strcmp(label, "fixture retained") &&
  custom_value == 37 && custom_calls == 10 && last_custom == &__param_level_late;
}
