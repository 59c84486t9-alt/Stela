// SPDX-License-Identifier: MIT
/* CUDA modules for VK_NVX_binary_import, which Metal has no use for. They are
 * ELF, and `stela.efi` carries no ELF reader, so a module fails to load. */
#include "nv_cubin.h"
#include "util/log.h"

bool nv_cubin_module_init(struct nv_cubin_module *module, const void *data, size_t size)
{
	(void)module;
	(void)data;
	(void)size;
	mesa_loge("unsupported: CUDA binaries (VK_NVX_binary_import)");
	return false;
}

void nv_cubin_module_fini(struct nv_cubin_module *module)
{
	(void)module;
}

const struct nv_cubin_function *nv_cubin_module_find_function(const struct nv_cubin_module *module,
							      const char *name)
{
	(void)module;
	(void)name;
	return NULL;
}

const struct nv_cubin_function_param_info *
nv_cubin_function_get_param_info(const struct nv_cubin_function *function, uint32_t ordinal)
{
	(void)function;
	(void)ordinal;
	return NULL;
}
