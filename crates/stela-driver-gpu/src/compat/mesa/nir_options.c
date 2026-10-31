/* SPDX-License-Identifier: MIT */
/* The NIR options a device's shaders are built with, for the AIR compiler,
 * which reaches NVK by no route Vulkan offers. */
#include "nak.h"
#include "nvk_physical_device.h"

const struct nir_shader_compiler_options *stela_nvk_nir_options(VkPhysicalDevice physical)
{
	VK_FROM_HANDLE(nvk_physical_device, pdev, physical);
	return nak_nir_options(pdev->nak);
}
