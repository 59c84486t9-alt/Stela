# SPDX-License-Identifier: MIT
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD ?= $(abspath $(SOURCE)/../../../../../..)/.stela/gpu/build/amd-native
# LP64 COFF with the UEFI Win64 C ABI, as build/native.rs compiles the port.
TARGET ?= x86_64-pc-cygwin
CC := clang
HOST_CC := clang

# Unchanged Linux sources build in Stela's shared Linux environment, as
# ../../intel/stela/Makefile describes, here with amdgpu's include trees.
AMD := $(abspath $(SOURCE)/..)
LINUX := $(abspath $(SOURCE)/../../common/linux/include)
COMPAT := $(abspath $(SOURCE)/../../compat)
LINUX_INCLUDES := -ivfsoverlay $(COMPAT)/overlay.yaml -D__KERNEL__ \
                  -include $(LINUX)/linux/kconfig.h -include $(LINUX)/linux/compiler_types.h \
                  -isystem $(AMD)/include/asic_reg -isystem $(AMD)/include \
                  -isystem $(AMD)/amdgpu -isystem $(AMD)/pm/inc \
                  -isystem $(AMD)/ras/ras_mgr -isystem $(AMD)/amdxcp \
                  -isystem $(LINUX) -isystem $(LINUX)/uapi -isystem $(COMPAT) \
                  -isystem $(LINUX)/../arch/x86/include/uapi
COMPAT_HEADERS := $(COMPAT)/overlay.yaml $(shell find $(COMPAT) -name '*.h')
WARNINGS := -Wall -Wextra -Werror -Wconversion -Wsign-conversion
CFLAGS := --target=$(TARGET) $(LINUX_INCLUDES) -std=gnu11 -O2 \
          -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only $(WARNINGS)
HOST_CFLAGS := $(LINUX_INCLUDES) -std=gnu11 -O2 -g $(WARNINGS)
SANITIZE ?= -fsanitize=address,undefined
# Stela's adapters: each defines the services one unchanged Linux source uses
# and includes it, or is Stela's own code over Linux's unchanged headers.
ADAPTERS := pci_match ip_discovery native_bar
TESTS := pci-match ip-discovery native-bar

.PHONY: all test check $(addprefix test-,$(TESTS))
all: $(addprefix $(BUILD)/,$(addsuffix .o,$(ADAPTERS)))

$(BUILD):
	mkdir -p "$@"

# Native and hosted objects. The overlay hides shadows from -MD, so every
# object also depends on the Linux environment itself.
$(BUILD)/%.o: $(SOURCE)/%.c $(COMPAT_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"
$(BUILD)/%-host.o: $(SOURCE)/%.c $(COMPAT_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -MD -MP -c "$<" -o "$@"
$(BUILD)/fixtures-host.o: $(SOURCE)/tests/fixtures.c $(COMPAT_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -MD -MP -c "$<" -o "$@"
-include $(wildcard $(BUILD)/*.d)

# Hosted tests over modelled registers, VRAM and firmware; each includes its
# adapter or links the hosted adapters it calls.
$(BUILD)/test-pci-match: $(SOURCE)/tests/pci_match.c $(SOURCE)/pci_match.c $(COMPAT_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" -o "$@"
$(BUILD)/test-ip-discovery: $(SOURCE)/tests/ip_discovery.c $(BUILD)/ip_discovery-host.o \
    $(BUILD)/pci_match-host.o $(BUILD)/fixtures-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(filter %.o,$^) -o "$@"
$(BUILD)/test-native-bar: $(SOURCE)/tests/native_bar.c $(BUILD)/native_bar-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(filter %.o,$^) -o "$@"
$(addprefix test-,$(TESTS)): test-%: $(BUILD)/test-%
	"$<"
test: $(addprefix test-,$(TESTS))

# Upstream code builds from system directories, where clang reports nothing,
# not even a call to a service no header declares. Check for those.
check: | $(BUILD)
	for adapter in $(ADAPTERS); do \
	  $(CC) $(CFLAGS) -Wsystem-headers -Wno-everything -Werror=implicit-function-declaration \
	    -Werror=implicit-int -fsyntax-only "$(SOURCE)/$$adapter.c" || exit 1; \
	done
