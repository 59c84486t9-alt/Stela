# SPDX-License-Identifier: MIT
# Stela's archive of NVIDIA's unchanged resource manager; see common.mk.
STELA_SRCS := $(addprefix ../../stela/,pci.c memory.c stela_ram_mapping.c stela_pages.c \
    stela_page_geometry.c stela_ordering.c stela_device.c stela_mmio.c stela_firmware.c \
    stela_primitives.c stela_nvlink_primitives.c stela_nvswitch_primitives.c \
    stela_nvlink_memory.c)
# Stela's runtime owns the standard memory symbols. gcc_helper.c aliases them
# to os_mem_*, which would recurse when the port's hooks call the runtime.
STELA_OBJS = $(filter-out $(OUTPUTDIR)/gcc_helper.o,$(OBJS))
STELA_ARCHIVE := $(OUTPUTDIR)/libnv-kernel.a
include ../../stela/build/common.mk
