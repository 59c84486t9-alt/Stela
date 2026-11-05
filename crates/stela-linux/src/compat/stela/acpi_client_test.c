// SPDX-License-Identifier: MIT
/* Compile/name isolation only. No portal, AML or native service is installed. */
#include <linux/acpi.h>
#include <linux/string.h>
#include <stela/test.h>
#define STRINGIFY_RAW(name) #name
#define STRINGIFY(name) STRINGIFY_RAW(name)

int main(void)
{
    assert(!strcmp(STRINGIFY(acpi_get_handle), "stela_linux_acpi_get_handle"));
    assert(!strcmp(STRINGIFY(acpi_evaluate_object), "stela_linux_acpi_evaluate_object"));
    assert(!strcmp(STRINGIFY(acpi_evaluate_dsm), "acpi_evaluate_dsm"));
    assert(!strcmp(STRINGIFY(acpi_check_dsm), "acpi_check_dsm"));
#ifndef CONFIG_ACPI
    /* The original disabled-client stubs still report their real configuration,
     * independently of the enabled boot interpreter linked in another archive. */
    assert(acpi_get_handle(NULL, NULL, NULL) == AE_NOT_CONFIGURED);
    assert(acpi_evaluate_object(NULL, NULL, NULL, NULL) == AE_NOT_CONFIGURED);
#endif
    printf("Linux ACPI clients retain distinct portal names; no service implied\n");
    return 0;
}
