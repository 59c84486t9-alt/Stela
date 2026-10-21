# SPDX-License-Identifier: GPL-2.0-only
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD ?= $(abspath $(SOURCE)/../../../../../..)/.stela/gpu/build/intel-native
TARGET ?= x86_64-unknown-windows
CC := clang
HOST_CC := clang
AR ?= llvm-ar

CFLAGS := --target=$(TARGET) -DSTELA_NATIVE -I$(SOURCE)/../xe -std=gnu11 -O2 \
          -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only \
          -Wall -Wextra -Werror -Wconversion -Wsign-conversion
HOST_CFLAGS := -DSTELA_NATIVE -I$(SOURCE)/../xe -std=gnu11 -O2 -g -Wall -Wextra -Werror \
               -Wconversion -Wsign-conversion
SANITIZE ?= -fsanitize=address,undefined
OBJECTS := $(BUILD)/xe_pt_walk.o $(BUILD)/pt_walk.o $(BUILD)/commands.o
HEADERS := $(wildcard $(SOURCE)/*.h $(SOURCE)/../xe/xe_pt_walk.h \
             $(SOURCE)/../xe/xe_ring_emit.h $(SOURCE)/../xe/instructions/*.h)
MESA_SOURCE ?= $(abspath $(SOURCE)/../../common/mesa)
MESA_BUILD ?=
PACKER_GENERATIONS := 120 125 200 300 350

.PHONY: all test test-packers
all: $(BUILD)/libstela-intel.a

$(BUILD):
	mkdir -p "$@"

$(BUILD)/xe_pt_walk.o: $(SOURCE)/../xe/xe_pt_walk.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/pt_walk.o: $(SOURCE)/pt_walk.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/commands.o: $(SOURCE)/commands.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/libstela-intel.a: $(OBJECTS)
	$(AR) rcs "$@" $(OBJECTS)

$(BUILD)/test-pt-walk: $(SOURCE)/tests/pt_walk.c $(SOURCE)/pt_walk.c \
                      $(SOURCE)/../xe/xe_pt_walk.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

$(BUILD)/test-commands: $(SOURCE)/tests/commands.c $(SOURCE)/commands.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

$(BUILD)/test-packers-%: $(SOURCE)/tests/commands_mesa.c $(SOURCE)/commands.c $(HEADERS) | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) -DSTELA_NATIVE -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/include -I$(MESA_SOURCE)/src/intel \
	    -I$(MESA_SOURCE)/src/intel/genxml -I$(MESA_BUILD)/src/intel \
	    -I$(SOURCE)/../xe $(filter %.c,$^) -lm -o "$@"

test-packers: $(addprefix $(BUILD)/test-packers-,$(PACKER_GENERATIONS))
	$(foreach generation,$(PACKER_GENERATIONS),"$(BUILD)/test-packers-$(generation)" &&) true

test: $(BUILD)/test-pt-walk $(BUILD)/test-commands
	"$(BUILD)/test-pt-walk"
	"$(BUILD)/test-commands"

-include $(OBJECTS:.o=.d)
