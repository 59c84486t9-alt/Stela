# SPDX-License-Identifier: MIT
# Compile a kernel component, not an installable kext. The eventual device
# service supplies lifecycle and module metadata and links this object.
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ARCH ?= arm64e
BUILD ?= $(abspath $(SOURCE)/../../../../..)/.stela/gpu/build/macos/$(ARCH)
SDKROOT ?= $(shell xcrun --sdk macosx --show-sdk-path)
HEADERS := $(SDKROOT)/System/Library/Frameworks/Kernel.framework/Headers
CC := $(shell xcrun --sdk macosx --find clang)
CXX := $(shell xcrun --sdk macosx --find clang++)
LD := $(shell xcrun --sdk macosx --find ld)

COMMON := -target $(ARCH)-apple-macos26.0 -isysroot $(SDKROOT) \
          -isystem $(HEADERS) -DKERNEL -mkernel -O2 \
          -fno-stack-protector -fno-stack-check -Wall -Wextra -Werror \
          -Werror=sign-conversion -Werror=shorten-64-to-32 \
          -Werror=conditional-uninitialized -Wno-unused-parameter
ifeq ($(ARCH),x86_64)
COMMON += -mno-sse -mno-sse2 -mno-mmx -msoft-float
else ifneq ($(filter $(ARCH),arm64 arm64e),)
COMMON += -mgeneral-regs-only
else
$(error unsupported kernel architecture $(ARCH))
endif

OBJECTS := $(BUILD)/memory.o
DEPENDS := $(OBJECTS:.o=.d)

.PHONY: all
all: $(BUILD)/gpu-memory.o

$(BUILD):
	mkdir -p "$@"

$(BUILD)/memory.o: $(SOURCE)/memory.cpp | $(BUILD)
	"$(CXX)" $(COMMON) -fapple-kext -fno-exceptions -fno-rtti \
	    -std=gnu++17 -MD -MP -c "$<" -o "$@"

$(BUILD)/gpu-memory.o: $(OBJECTS)
	"$(LD)" -r -arch $(ARCH) -o "$@" $(OBJECTS)

-include $(DEPENDS)
