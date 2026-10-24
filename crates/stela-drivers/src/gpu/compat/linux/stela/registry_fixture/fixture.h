/* SPDX-License-Identifier: MIT */
#ifndef STELA_REGISTRY_FIXTURE_H
#define STELA_REGISTRY_FIXTURE_H
#include <linux/module.h>
#include <stela/registry.h>
/* Authored controlled fixture effects; never substitutes for driver services. */
void stela_registry_fixture_event(unsigned int value);
extern const struct stela_linux_registry_image stela_linux_fixture_image;
const struct kernel_param *stela_fixture_first_count(void);
const struct kernel_param *stela_fixture_first_borrowed(void);
const struct kernel_param *stela_fixture_second_count(void);
const struct kernel_param *stela_fixture_third_count(void);
#endif
