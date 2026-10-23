# SPDX-License-Identifier: MIT
# User-space Metal library objects. No device/plugin registration or kernel code.
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ARCH ?= arm64
BUILD ?= $(abspath $(SOURCE)/../../../../../..)/target/gpu/metal/$(ARCH)
SDKROOT ?= $(shell xcrun --sdk macosx --show-sdk-path)
CC := $(shell xcrun --sdk macosx --find clang)

ifeq ($(filter $(ARCH),arm64 arm64e x86_64),)
$(error unsupported Metal object architecture $(ARCH))
endif
COMMON := -target $(ARCH)-apple-macos26.0 -isysroot $(SDKROOT) -O2 \
          -fobjc-arc -fblocks -Wall -Wextra -Werror

.PHONY: all
all: $(BUILD)/libstela-metal-library.dylib

$(BUILD):
	mkdir -p "$@"

$(BUILD)/library.o: $(SOURCE)/library.m | $(BUILD)
	"$(CC)" $(COMMON) -MD -MP -c "$<" -o "$@"

$(BUILD)/libstela-metal-library.dylib: $(BUILD)/library.o
	"$(CC)" $(COMMON) -dynamiclib "$<" -framework Foundation -framework Metal \
	    -Wl,-install_name,@rpath/libstela-metal-library.dylib -o "$@"

-include $(BUILD)/library.d
