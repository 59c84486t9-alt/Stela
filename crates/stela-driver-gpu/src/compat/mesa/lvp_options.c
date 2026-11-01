/* SPDX-License-Identifier: MIT */
/* The NIR options a device's shaders are built with, for the AIR compiler,
 * which reaches lavapipe by no route Vulkan offers. */
#include "lvp_private.h"

const struct nir_shader_compiler_options *stela_lvp_nir_options(VkPhysicalDevice physical)
{
	VK_FROM_HANDLE(lvp_physical_device, pdev, physical);
	return pdev->drv_options[MESA_SHADER_COMPUTE];
}
