/* SPDX-License-Identifier: MIT */
#include <linux/err.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/registry.h>
#include <stela/test.h>
#include <video/cmdline.h>
#include <video/nomodeset.h>
extern const struct stela_linux_registry_image stela_linux_video_fixture_image;
static unsigned int nomodeset_warnings;
static void log_message(void *context, int level, const char *message)
{
 (void)context; (void)level;
 if (strstr(message, "Booted with the nomodeset parameter."))
  nomodeset_warnings++;
}
static const struct stela_linux_services services = { .log = log_message };
static const struct stela_linux_owner owner = { .services = &services };
/* Separate executable/process: original static video globals and the registry
 * singleton are intentionally never reset to fake another boot. The registry
 * retains storage because real video_setup keeps borrowed option pointers. */
int main(void)
{
 char input[] = "nomodeset-suffix video=1024x768 video=HDMI-A-1:1920x1080 video=DP-1:off video=HDMI-A-1:2560x1440";
 struct stela_linux_registry *registry = NULL;
 struct stela_linux_registry_report report;
 char *tail = (void *)1;
 const char *global, *named, *disabled;
 const struct stela_linux_registry_image *image = &stela_linux_video_fixture_image;
 assert(image->setup_count == 2 && image->parameter_count == 0);
 assert(image->init_count == 0 && image->exit_count == 0);
 stela_linux_enter(&owner);
 assert(!video_firmware_drivers_only());
 assert(video_get_options(NULL) == NULL);
 assert(stela_linux_registry_begin(image, input, sizeof(input) - 1, &registry) == 0);
 /* Mutate borrowed caller input BEFORE parsing: registry must use its own copy. */
 memset(input, 'X', sizeof(input) - 1);
 assert(stela_linux_registry_early_parameters(registry, &report) == 0);
 assert(stela_linux_registry_initial_parameters(registry, NULL, &report) == 0);
 assert(stela_linux_registry_parse_result(registry, 1, &tail) == 0 && tail == NULL);
 assert(video_firmware_drivers_only());
 assert(nomodeset_warnings == 1);
 global = video_get_options(NULL);
 named = video_get_options("HDMI-A-1");
 disabled = video_get_options("DP-1");
 assert(global && !strcmp(global, "1024x768"));
 assert(named && !strcmp(named, "2560x1440"));
 assert(disabled && !strcmp(disabled, "off"));
 assert(video_get_options("unconfigured") == global);
 stela_linux_exit();
 /* Original setup consumers outlive the borrowed execution owner. */
 stela_linux_enter(&stela_linux_bare);
 assert(video_firmware_drivers_only());
 assert(video_get_options(NULL) == global && !strcmp(global, "1024x768"));
 assert(video_get_options("HDMI-A-1") == named && !strcmp(named, "2560x1440"));
 assert(video_get_options("DP-1") == disabled && !strcmp(disabled, "off"));
 /* No whole-domain drain authority: keep genuine borrowed pointers pinned. */
 stela_linux_exit();
 return 0;
}
