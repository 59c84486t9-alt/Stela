/* SPDX-License-Identifier: MIT */
#include <linux/panic.h>
#include <stela/linux.h>
#include <stela/registry.h>
#include <stela/test.h>
extern const struct stela_linux_registry_image stela_linux_parameters_fixture_image;
size_t stela_fixture_parameter_originals(const struct kernel_param *const **out);
bool stela_fixture_parameter_values_match(void);
int main(void)
{
 const struct stela_linux_registry_image *image = &stela_linux_parameters_fixture_image;
 const struct kernel_param *const *originals;
 struct stela_linux_registry *registry = NULL;
 struct stela_linux_registry_report report;
 const char arguments[] =
  "core_plain=11 core_danger=12 fixture_params.enabled "
  "fixture_params.count_alias=13 fixture_params.danger=14 fixture_params.irq_line=15 "
  "fixture_params.label=\"fixture retained\" core_custom=20 fixture_params.callback=21 "
  "fixture_params.danger_callback=22 fixture_params.level_core=31 "
  "fixture_params.level_postcore=32 fixture_params.level_arch=33 "
  "fixture_params.level_subsys=34 fixture_params.level_fs=35 "
  "fixture_params.level_device=36 fixture_params.level_late=37";
 assert(image->parameter_count == 17 && image->info_count == 5);
 assert(image->init_count == 0 && image->setup_count == 0);
 assert(stela_fixture_parameter_originals(&originals) == image->parameter_count);
 for (size_t i = 0; i < image->parameter_count; i++) {
  const struct stela_linux_parameter_record *record = image->parameters[i];
  assert(record->target == originals[i]);
  assert(record->header.level == originals[i]->level);
 }
 assert(originals[1]->flags == KERNEL_PARAM_FL_UNSAFE);
 assert(originals[2]->ops->flags & KERNEL_PARAM_OPS_FL_NOARG);
 assert(originals[4]->flags == KERNEL_PARAM_FL_UNSAFE);
 assert(originals[5]->flags == KERNEL_PARAM_FL_HWPARAM);
 assert(originals[9]->flags == KERNEL_PARAM_FL_UNSAFE);
 for (size_t i = 10; i < 17; i++)
  assert(originals[i]->level == (s8)(i - 9));
 stela_linux_enter(&stela_linux_bare);
 assert(stela_linux_registry_begin(image, arguments, sizeof(arguments) - 1, &registry) == 0);
 assert(stela_linux_registry_early_parameters(registry, &report) == 0);
 assert(stela_linux_registry_initial_parameters(registry, NULL, &report) == 0);
 for (unsigned int stage = STELA_LINUX_STAGE_CONSOLE; stage < STELA_LINUX_STAGE_DONE; stage++)
  assert(stela_linux_registry_run_stage(registry, stage, &report) == 0);
 assert(stela_fixture_parameter_values_match());
 assert(get_taint() & (1UL << TAINT_USER));
 stela_linux_exit();
 /* No fabricated whole-domain retirement authority or reset between boots. */
 return 0;
}
