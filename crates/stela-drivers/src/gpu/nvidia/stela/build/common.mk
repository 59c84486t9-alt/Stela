# SPDX-License-Identifier: MIT
# Shared by core.mk and modeset.mk, which `cargo xtask gpu nvidia` reads after
# NVIDIA's unchanged component Makefile, with STELA naming this port's
# directory. NVIDIA's own rules compile every object; these add Stela's port
# sources and archive the COFF objects for the UEFI link instead of NVIDIA's
# ELF partial link.
$(foreach src,$(STELA_SRCS),$(eval $(call DEFINE_OBJECT_RULE,TARGET,$(src))))
STELA_PORT_OBJS := $(call BUILD_OBJECT_LIST,$(STELA_SRCS))
$(STELA_PORT_OBJS): CFLAGS += -I $(STELA) -idirafter $(STELA)/compat -I $(OUTPUTDIR)
# The port names its firmware directory by version.mk's generated header.
$(STELA_PORT_OBJS): $(OUTPUTDIR)/version.h

# NVIDIA's object rules drop source directories, so refuse a Stela source whose
# object would replace one of NVIDIA's.
STELA_BASENAMES := $(notdir $(basename $(ALL_SRCS) $(STELA_SRCS)))
ifneq ($(words $(STELA_BASENAMES)),$(words $(sort $(STELA_BASENAMES))))
$(error duplicate NVIDIA object basenames: $(sort $(foreach name,$(STELA_BASENAMES),$(if $(word 2,$(filter $(name),$(STELA_BASENAMES))),$(name)))))
endif

.PHONY: stela-archive
stela-archive: $(STELA_ARCHIVE)
$(STELA_ARCHIVE): $(STELA_OBJS) $(STELA_PORT_OBJS)
	$(RM) $@
	$(AR) rcs $@ $^
