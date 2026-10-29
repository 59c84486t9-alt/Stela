/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include "os-interface.h"
#include "stela_pci.h"

/* Use the vendor's actual declarations and status definitions. Device discovery,
 * reset and removal are separate lifecycle work, not successful no-op hooks.
 */
#define PCI_CONFIG_BYTES 4096U

static NV_STATUS read_config(void *handle, NvU32 offset, NvU32 width, NvU32 *value)
{
    struct stela_nvidia_pci *pci = handle;
    if (pci == NULL)
        return NV_ERR_INVALID_POINTER;
    if (offset >= PCI_CONFIG_BYTES)
        return NV_ERR_NOT_SUPPORTED;
    if (!pci->read(pci->context, offset, width, value))
        return NV_ERR_INVALID_ARGUMENT;
    return NV_OK;
}

static NV_STATUS write_config(void *handle, NvU32 offset, NvU32 width, NvU32 value)
{
    struct stela_nvidia_pci *pci = handle;
    if (pci == NULL)
        return NV_ERR_INVALID_POINTER;
    if (offset >= PCI_CONFIG_BYTES)
        return NV_ERR_NOT_SUPPORTED;
    if (!pci->write(pci->context, offset, width, value))
        return NV_ERR_INVALID_ARGUMENT;
    return NV_OK;
}

/* Initialize failed reads to all ones: existing RM callers can ignore status.
 * Narrow writes stay narrow through the Rust ConfigSpace implementation.
 */
#define PCI_ACCESS(suffix, type, width, all_ones)                              \
NV_STATUS NV_API_CALL os_pci_read_##suffix(void *handle, NvU32 offset, type *out) \
{                                                                           \
    NvU32 value = all_ones;                                                  \
    NV_STATUS status;                                                       \
    if (out == NULL)                                                         \
        return NV_ERR_INVALID_POINTER;                                      \
    status = read_config(handle, offset, width, &value);                      \
    *out = (type)value;                                                      \
    return status;                                                          \
}                                                                           \
NV_STATUS NV_API_CALL os_pci_write_##suffix(void *handle, NvU32 offset, type value) \
{                                                                           \
    return write_config(handle, offset, width, value);                       \
}

PCI_ACCESS(byte, NvU8, 1U, 0xffU)
PCI_ACCESS(word, NvU16, 2U, 0xffffU)
PCI_ACCESS(dword, NvU32, 4U, 0xffffffffU)
