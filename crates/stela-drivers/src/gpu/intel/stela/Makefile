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
OBJECTS := $(BUILD)/xe_pt_walk.o $(BUILD)/pt_walk.o $(BUILD)/commands.o $(BUILD)/ct.o \
           $(BUILD)/i915_commands.o
HEADERS := $(wildcard $(SOURCE)/*.h $(SOURCE)/../xe/xe_pt_walk.h \
             $(SOURCE)/../xe/xe_ring_emit.h $(SOURCE)/../xe/instructions/*.h \
             $(SOURCE)/../xe/xe_guc_ct_message.h $(SOURCE)/../xe/abi/*.h \
             $(SOURCE)/../xe/regs/xe_guc_ct_regs.h $(SOURCE)/../i915/gt/intel_gpu_commands.h \
             $(SOURCE)/../i915/gt/intel_batch_emit.h)
MESA_SOURCE ?= $(abspath $(SOURCE)/../../common/mesa)
MESA_BUILD ?=
PYTHON ?= python3
DISPATCH_GENERATIONS := 70 75 80 90 110 120
DISPATCH_HEADERS := $(addprefix $(BUILD)/dispatch/gen,$(addsuffix _dispatch_pack.h,$(DISPATCH_GENERATIONS)))
DISPATCH_OBJECTS := $(addprefix $(BUILD)/dispatch-gen,$(addsuffix .o,$(DISPATCH_GENERATIONS)))
HOST_DISPATCH_OBJECTS := $(addprefix $(BUILD)/host-dispatch-gen,$(addsuffix .o,$(DISPATCH_GENERATIONS)))
OBJECTS += $(BUILD)/dispatch.o $(DISPATCH_OBJECTS)
PACKER_GENERATIONS := 120 125 200 300 350
I915_PACKER_GENERATIONS := 60 70 75 80 90 110

.PHONY: all test test-packers test-i915-packers
all: $(BUILD)/libstela-intel.a

$(BUILD):
	mkdir -p "$@"

$(BUILD)/xe_pt_walk.o: $(SOURCE)/../xe/xe_pt_walk.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/pt_walk.o: $(SOURCE)/pt_walk.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/commands.o: $(SOURCE)/commands.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/ct.o: $(SOURCE)/ct.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/i915_commands.o: $(SOURCE)/i915_commands.c | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/dispatch/gen%_dispatch_pack.h: $(MESA_SOURCE)/src/intel/genxml/gen%.xml \
    $(wildcard $(MESA_SOURCE)/src/intel/genxml/*.xml $(MESA_SOURCE)/src/intel/genxml/*.py) | $(BUILD)
	mkdir -p "$(BUILD)/dispatch"
	$(PYTHON) $(MESA_SOURCE)/src/intel/genxml/gen_pack_header.py "$<" \
	    --include-symbols GPGPU_WALKER,MEDIA_STATE_FLUSH --helpers-include genxml_native.h > "$@.tmp"
	mv "$@.tmp" "$@"

$(BUILD)/dispatch-gen%.o: $(SOURCE)/dispatch/gen%.c $(DISPATCH_HEADERS) $(SOURCE)/dispatch/pack.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SOURCE) -I$(BUILD)/dispatch -I$(MESA_SOURCE)/src \
	    -I$(MESA_SOURCE)/src/intel/genxml -MD -MP -c "$<" -o "$@"

$(BUILD)/dispatch.o: $(SOURCE)/dispatch.c $(SOURCE)/dispatch.h $(SOURCE)/dispatch_internal.h | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

.PHONY: dispatch
dispatch: $(BUILD)/dispatch.o $(DISPATCH_OBJECTS)

$(BUILD)/host-dispatch-gen%.o: $(SOURCE)/dispatch/gen%.c $(DISPATCH_HEADERS) $(SOURCE)/dispatch/pack.h
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE) -I$(BUILD)/dispatch \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/src/intel/genxml -MD -MP -c "$<" -o "$@"

$(BUILD)/test-dispatch: $(SOURCE)/tests/dispatch.c $(SOURCE)/dispatch.c \
    $(HOST_DISPATCH_OBJECTS) $(HEADERS) $(SOURCE)/dispatch_internal.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c %.o,$^) -o "$@"

$(BUILD)/test-dispatch-packers-%: $(SOURCE)/tests/dispatch_mesa.c $(SOURCE)/dispatch.c \
    $(HOST_DISPATCH_OBJECTS) $(HEADERS) $(SOURCE)/dispatch_internal.h | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) -DSTELA_NATIVE -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/include -I$(MESA_SOURCE)/src/intel \
	    -I$(MESA_SOURCE)/src/intel/genxml -I$(MESA_BUILD)/src/intel \
	    $(filter %.c %.o,$^) -lm -o "$@"

.PHONY: test-dispatch test-dispatch-packers
test-dispatch: $(BUILD)/test-dispatch
	"$(BUILD)/test-dispatch"

test-dispatch-packers: $(addprefix $(BUILD)/test-dispatch-packers-,$(DISPATCH_GENERATIONS))
	$(foreach generation,$(DISPATCH_GENERATIONS),"$(BUILD)/test-dispatch-packers-$(generation)" &&) true

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

$(BUILD)/test-i915-packers-%: $(SOURCE)/tests/i915_commands_mesa.c $(SOURCE)/i915_commands.c $(HEADERS) | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) -DSTELA_NATIVE -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/include -I$(MESA_SOURCE)/src/intel \
	    -I$(MESA_SOURCE)/src/intel/genxml -I$(MESA_BUILD)/src/intel \
	    $(filter %.c,$^) -lm -o "$@"

test-i915-packers: $(addprefix $(BUILD)/test-i915-packers-,$(I915_PACKER_GENERATIONS))
	$(foreach generation,$(I915_PACKER_GENERATIONS),"$(BUILD)/test-i915-packers-$(generation)" &&) true

$(BUILD)/test-ct: $(SOURCE)/tests/ct.c $(SOURCE)/ct.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

$(BUILD)/test-i915-commands: $(SOURCE)/tests/i915_commands.c $(SOURCE)/i915_commands.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

test: $(BUILD)/test-pt-walk $(BUILD)/test-commands $(BUILD)/test-ct $(BUILD)/test-i915-commands $(BUILD)/test-dispatch
	"$(BUILD)/test-pt-walk"
	"$(BUILD)/test-commands"
	"$(BUILD)/test-ct"
	"$(BUILD)/test-i915-commands"
	"$(BUILD)/test-dispatch"

-include $(OBJECTS:.o=.d)
-include $(HOST_DISPATCH_OBJECTS:.o=.d)
