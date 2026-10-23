# SPDX-License-Identifier: MIT
# Stela's archive of NVIDIA's unchanged display core; see common.mk.
STELA_SRCS := $(addprefix $(STELA)/,stela_nvkms_primitives.c stela_nvkms_memory.c)
# NVIDIA embeds its compressed shaders with an ELF binary link. Stela embeds the
# same files into COFF objects with the symbols NVKMS reads.
STELA_SHADERS := $(SHADER_OBJS:.xz.o=.xz)
STELA_SHADER_OBJS := $(addsuffix .coff.o,$(STELA_SHADERS))
STELA_OBJS = $(filter-out $(SHADER_OBJS),$(OBJS)) $(STELA_SHADER_OBJS)
STELA_ARCHIVE := $(OUTPUTDIR)/libnv-modeset-kernel.a
include $(STELA)/build/common.mk

$(STELA_SHADER_OBJS): %.coff.o: %
	symbol=_binary_$(subst -,_,$(subst .,_,$(notdir $<))); \
	printf '.section .rdata,"dr"\n.globl %s_start\n%s_start:\n.incbin "%s"\n.globl %s_end\n%s_end:\n' \
	    $$symbol $$symbol $(abspath $<) $$symbol $$symbol > $@.S
	$(CC) $(EXTRA_CFLAGS) -c -x assembler $@.S -o $@
