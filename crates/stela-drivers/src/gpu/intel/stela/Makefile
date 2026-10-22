# SPDX-License-Identifier: GPL-2.0-only
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD ?= $(abspath $(SOURCE)/../../../../../..)/.stela/gpu/build/intel-native
# LP64 COFF with the UEFI Win64 C ABI, as build/native.rs compiles the port.
TARGET ?= x86_64-pc-cygwin
CC := clang
HOST_CC := clang
AR ?= llvm-ar

# Unchanged Linux sources build in Stela's shared Linux environment, with
# Kbuild's definition and forced includes, from system directories so upstream
# code keeps Linux's warning profile rather than Stela's. ../../compat's
# overlay.yaml puts each shadow in place of the upstream header it replaces,
# however a source names it. compat/ itself comes last and only adds the asm/
# and generated/ headers that Linux's arch tree and build supply.
LINUX := $(abspath $(SOURCE)/../../common/linux/include)
COMPAT := $(abspath $(SOURCE)/../../compat)
GENERATED := $(BUILD)/generated-include
LINUX_INCLUDES := -ivfsoverlay $(COMPAT)/overlay.yaml -D__KERNEL__ \
                  -include $(LINUX)/linux/kconfig.h -include $(LINUX)/linux/compiler_types.h \
                  -isystem $(GENERATED) -isystem $(SOURCE)/../xe -isystem $(SOURCE)/../i915 \
                  -isystem $(LINUX) -isystem $(LINUX)/uapi -isystem $(COMPAT)
COMPAT_HEADERS := $(COMPAT)/overlay.yaml $(shell find $(COMPAT) -name '*.h')
CFLAGS := --target=$(TARGET) $(LINUX_INCLUDES) -std=gnu11 -O2 \
          -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only \
          -Wall -Wextra -Werror -Wconversion -Wsign-conversion
HOST_CFLAGS := $(LINUX_INCLUDES) -std=gnu11 -O2 -g -Wall -Wextra -Werror \
               -Wconversion -Wsign-conversion
SANITIZE ?= -fsanitize=address,undefined
# Stela's adapters: each defines the services one unchanged Linux source uses
# and includes it, or is Stela's own code over Linux's unchanged headers.
ADAPTERS := pt_walk commands ct i915_commands activation firmware wopcm ggtt_probe pat guc_reset
OBJECTS := $(addprefix $(BUILD)/,$(addsuffix .o,$(ADAPTERS)))
HOST_ACTIVATION_OBJECTS := $(addprefix $(BUILD)/,$(addsuffix -host.o,activation wopcm firmware pat guc_reset))
HEADERS := $(wildcard $(SOURCE)/*.h $(SOURCE)/../xe/instructions/*.h $(SOURCE)/../xe/abi/*.h \
             $(SOURCE)/../i915/gt/intel_gpu_commands.h)
MESA_SOURCE ?= $(abspath $(SOURCE)/../../common/mesa)
MESA_BUILD ?=
PYTHON ?= python3
DISPATCH_GENERATIONS := 70 75 80 90 110 120
DISPATCH_HEADERS := $(addprefix $(BUILD)/dispatch/gen,$(addsuffix _dispatch_pack.h,$(DISPATCH_GENERATIONS)))
DISPATCH_OBJECTS := $(addprefix $(BUILD)/dispatch-gen,$(addsuffix .o,$(DISPATCH_GENERATIONS)))
HOST_DISPATCH_OBJECTS := $(addprefix $(BUILD)/host-dispatch-gen,$(addsuffix .o,$(DISPATCH_GENERATIONS)))
OBJECTS += $(BUILD)/dispatch.o $(DISPATCH_OBJECTS)
COMPUTE_GENERATIONS := 125 200 300 350
COMPUTE_XML_125 := gen125
COMPUTE_XML_200 := xe2
COMPUTE_XML_300 := xe3
COMPUTE_XML_350 := xe3p
COMPUTE_HEADERS := $(addprefix $(BUILD)/dispatch/gen,$(addsuffix _compute_pack.h,$(COMPUTE_GENERATIONS)))
COMPUTE_OBJECTS := $(addprefix $(BUILD)/compute-gen,$(addsuffix .o,$(COMPUTE_GENERATIONS)))
HOST_COMPUTE_OBJECTS := $(addprefix $(BUILD)/host-compute-gen,$(addsuffix .o,$(COMPUTE_GENERATIONS)))
.SECONDARY: $(COMPUTE_HEADERS)
OBJECTS += $(BUILD)/compute_dispatch.o $(COMPUTE_OBJECTS)
PACKER_GENERATIONS := 120 125 200 300 350
I915_PACKER_GENERATIONS := 60 70 75 80 90 110

.PHONY: all test test-packers test-i915-packers
all: $(BUILD)/libstela-intel.a

$(BUILD):
	mkdir -p "$@"

# Xe's workaround table, from Linux's unchanged generator and rules.
$(BUILD)/xe_gen_wa_oob: $(SOURCE)/../xe/xe_gen_wa_oob.c | $(BUILD)
	$(HOST_CC) -std=gnu11 -O2 -Wall -Wextra -Werror "$<" -o "$@"
$(GENERATED)/generated/xe_wa_oob.h: $(SOURCE)/../xe/xe_wa_oob.rules $(BUILD)/xe_gen_wa_oob
	mkdir -p "$(GENERATED)/generated"
	$(BUILD)/xe_gen_wa_oob "$<" "$(BUILD)/xe_wa_oob.c" "$@"

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

$(BUILD)/dispatch/gen%_compute_pack.h: $(wildcard $(MESA_SOURCE)/src/intel/genxml/*.xml $(MESA_SOURCE)/src/intel/genxml/*.py) | $(BUILD)
	mkdir -p "$(BUILD)/dispatch"
	$(PYTHON) $(MESA_SOURCE)/src/intel/genxml/gen_pack_header.py \
	    $(MESA_SOURCE)/src/intel/genxml/$(COMPUTE_XML_$*).xml \
	    --include-symbols COMPUTE_WALKER,COMPUTE_WALKER_BODY,INTERFACE_DESCRIPTOR_DATA,POSTSYNC_DATA,PREF_SLM_ALLOCATION_SIZE --helpers-include genxml_native.h > "$@.tmp"
	mv "$@.tmp" "$@"

$(BUILD)/compute-gen%.o: $(SOURCE)/dispatch/compute%.c $(COMPUTE_HEADERS) $(SOURCE)/dispatch/compute_pack.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SOURCE) -I$(BUILD)/dispatch -I$(MESA_SOURCE)/src \
	    -I$(MESA_SOURCE)/src/intel/genxml -MD -MP -c "$<" -o "$@"

$(BUILD)/compute_dispatch.o: $(SOURCE)/compute_dispatch.c $(SOURCE)/compute_dispatch.h $(SOURCE)/compute_dispatch_internal.h | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

$(BUILD)/host-compute-gen%.o: $(SOURCE)/dispatch/compute%.c $(COMPUTE_HEADERS) $(SOURCE)/dispatch/compute_pack.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE) -I$(BUILD)/dispatch \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/src/intel/genxml -MD -MP -c "$<" -o "$@"

.PHONY: compute-dispatch test-compute-dispatch test-compute-packers
compute-dispatch: $(BUILD)/compute_dispatch.o $(COMPUTE_OBJECTS)

$(BUILD)/test-compute-dispatch: $(SOURCE)/tests/compute_dispatch.c $(SOURCE)/compute_dispatch.c \
    $(HOST_COMPUTE_OBJECTS) $(HEADERS) $(SOURCE)/compute_dispatch_internal.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c %.o,$^) -o "$@"

test-compute-dispatch: $(BUILD)/test-compute-dispatch
	"$(BUILD)/test-compute-dispatch"

$(BUILD)/test-compute-packers-%: $(SOURCE)/tests/compute_dispatch_mesa.c $(SOURCE)/compute_dispatch.c \
    $(HOST_COMPUTE_OBJECTS) $(HEADERS) $(SOURCE)/compute_dispatch_internal.h | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) $(LINUX_INCLUDES) -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/include -I$(MESA_SOURCE)/src/intel \
	    -I$(MESA_SOURCE)/src/intel/genxml -I$(MESA_BUILD)/src/intel \
	    $(filter %.c %.o,$^) -lm -o "$@"

test-compute-packers: $(addprefix $(BUILD)/test-compute-packers-,$(COMPUTE_GENERATIONS))
	$(foreach generation,$(COMPUTE_GENERATIONS),"$(BUILD)/test-compute-packers-$(generation)" &&) true

$(BUILD)/host-dispatch-gen%.o: $(SOURCE)/dispatch/gen%.c $(DISPATCH_HEADERS) $(SOURCE)/dispatch/pack.h
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE) -I$(BUILD)/dispatch \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/src/intel/genxml -MD -MP -c "$<" -o "$@"

$(BUILD)/test-dispatch: $(SOURCE)/tests/dispatch.c $(SOURCE)/dispatch.c \
    $(HOST_DISPATCH_OBJECTS) $(HEADERS) $(SOURCE)/dispatch_internal.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c %.o,$^) -o "$@"

$(BUILD)/test-dispatch-packers-%: $(SOURCE)/tests/dispatch_mesa.c $(SOURCE)/dispatch.c \
    $(HOST_DISPATCH_OBJECTS) $(HEADERS) $(SOURCE)/dispatch_internal.h | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) $(LINUX_INCLUDES) -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
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

$(BUILD)/test-pt-walk: $(SOURCE)/tests/pt_walk.c $(SOURCE)/pt_walk.c $(HEADERS) $(COMPAT_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(SOURCE)/tests/pt_walk.c $(SOURCE)/pt_walk.c -o "$@"

$(BUILD)/test-commands: $(SOURCE)/tests/commands.c $(SOURCE)/commands.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

$(BUILD)/test-packers-%: $(SOURCE)/tests/commands_mesa.c $(SOURCE)/commands.c $(HEADERS) | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) $(LINUX_INCLUDES) -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/include -I$(MESA_SOURCE)/src/intel \
	    -I$(MESA_SOURCE)/src/intel/genxml -I$(MESA_BUILD)/src/intel \
	    -I$(SOURCE)/../xe $(filter %.c,$^) -lm -o "$@"

test-packers: $(addprefix $(BUILD)/test-packers-,$(PACKER_GENERATIONS))
	$(foreach generation,$(PACKER_GENERATIONS),"$(BUILD)/test-packers-$(generation)" &&) true

$(BUILD)/test-i915-packers-%: $(SOURCE)/tests/i915_commands_mesa.c $(SOURCE)/i915_commands.c $(HEADERS) | $(BUILD)
	test -n "$(MESA_BUILD)"
	$(HOST_CC) $(LINUX_INCLUDES) -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
	    -I$(MESA_SOURCE)/src -I$(MESA_SOURCE)/include -I$(MESA_SOURCE)/src/intel \
	    -I$(MESA_SOURCE)/src/intel/genxml -I$(MESA_BUILD)/src/intel \
	    $(filter %.c,$^) -lm -o "$@"

test-i915-packers: $(addprefix $(BUILD)/test-i915-packers-,$(I915_PACKER_GENERATIONS))
	$(foreach generation,$(I915_PACKER_GENERATIONS),"$(BUILD)/test-i915-packers-$(generation)" &&) true

$(BUILD)/test-ct: $(SOURCE)/tests/ct.c $(SOURCE)/ct.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

$(BUILD)/test-i915-commands: $(SOURCE)/tests/i915_commands.c $(SOURCE)/i915_commands.c $(HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) $(filter %.c,$^) -o "$@"

test: $(BUILD)/test-pt-walk $(BUILD)/test-commands $(BUILD)/test-ct $(BUILD)/test-i915-commands $(BUILD)/test-dispatch $(BUILD)/test-compute-dispatch
	"$(BUILD)/test-pt-walk"
	"$(BUILD)/test-commands"
	"$(BUILD)/test-ct"
	"$(BUILD)/test-i915-commands"
	"$(BUILD)/test-dispatch"
	"$(BUILD)/test-compute-dispatch"

-include $(OBJECTS:.o=.d)
-include $(HOST_DISPATCH_OBJECTS:.o=.d)
-include $(HOST_COMPUTE_OBJECTS:.o=.d)
-include $(HOST_ACTIVATION_OBJECTS:.o=.d) $(BUILD)/ggtt_probe-host.d

# Native and hosted adapter objects. The overlay hides shadows from -MD, so
# every adapter also depends on the Linux environment itself.
ADAPTER_INPUTS := $(COMPAT_HEADERS) $(GENERATED)/generated/xe_wa_oob.h
$(BUILD)/%-host.o: $(SOURCE)/%.c $(ADAPTER_INPUTS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -MD -MP -c "$<" -o "$@"
$(BUILD)/%.o: $(SOURCE)/%.c $(ADAPTER_INPUTS) | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"

.PHONY: activation firmware wopcm ggtt-probe pat guc-reset host-activation
activation firmware wopcm pat: %: $(BUILD)/%.o
ggtt-probe: $(BUILD)/ggtt_probe.o
guc-reset: $(BUILD)/guc_reset.o
host-activation: $(HOST_ACTIVATION_OBJECTS)

# Hosted tests over modelled registers and images; each includes its adapter
# or links the hosted adapters it calls.
XE_TESTS := activation firmware huc-firmware wopcm wopcm-owned ggtt-probe pat guc-reset
$(BUILD)/test-firmware: $(SOURCE)/tests/firmware.c $(SOURCE)/firmware.c $(ADAPTER_INPUTS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" -o "$@"
$(BUILD)/test-huc-firmware: $(SOURCE)/tests/huc_firmware.c $(SOURCE)/firmware.c $(ADAPTER_INPUTS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" -o "$@"
PAT_PEERS := $(filter-out $(BUILD)/pat-host.o,$(HOST_ACTIVATION_OBJECTS))
$(BUILD)/test-pat: $(SOURCE)/tests/pat.c $(SOURCE)/pat.c $(PAT_PEERS)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(PAT_PEERS) -lpthread -o "$@"
$(BUILD)/test-wopcm: $(SOURCE)/tests/wopcm.c $(SOURCE)/wopcm.c $(BUILD)/firmware-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(BUILD)/firmware-host.o -lpthread -o "$@"
ACTIVATION_PEERS := $(filter-out $(BUILD)/activation-host.o,$(HOST_ACTIVATION_OBJECTS))
$(BUILD)/test-activation: $(SOURCE)/tests/activation.c $(SOURCE)/activation.c $(ACTIVATION_PEERS)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(ACTIVATION_PEERS) -lpthread -o "$@"
$(BUILD)/test-wopcm-owned: $(SOURCE)/tests/wopcm_owned.c $(SOURCE)/activation.c $(ACTIVATION_PEERS)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(ACTIVATION_PEERS) -lpthread -o "$@"
$(BUILD)/test-ggtt-probe: $(SOURCE)/tests/ggtt_probe.c $(BUILD)/ggtt_probe-host.o $(HOST_ACTIVATION_OBJECTS)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(BUILD)/ggtt_probe-host.o \
	    $(HOST_ACTIVATION_OBJECTS) -lpthread -o "$@"
$(BUILD)/test-guc-reset: $(SOURCE)/tests/guc_reset.c $(HOST_ACTIVATION_OBJECTS)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(HOST_ACTIVATION_OBJECTS) -lpthread -o "$@"
.PHONY: $(addprefix test-,$(XE_TESTS))
$(addprefix test-,$(XE_TESTS)): test-%: $(BUILD)/test-%
	"$<"
