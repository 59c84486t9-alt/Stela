# SPDX-License-Identifier: MIT
# Compile a kernel component, not an installable kext. The eventual device
# service supplies lifecycle and module metadata and links this object.
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ARCH ?= arm64e
BUILD ?= $(abspath $(SOURCE)/../../../../..)/target/gpu/macos/$(ARCH)
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

OBJECTS := $(BUILD)/memory.o $(BUILD)/task_memory.o
DEPENDS := $(OBJECTS:.o=.d) $(BUILD)/task-memory-contract.d

.PHONY: all contract-tests
all: $(BUILD)/gpu-memory.o $(BUILD)/task_memory.o

$(BUILD):
	mkdir -p "$@"

$(BUILD)/%.o: $(SOURCE)/%.cpp | $(BUILD)
	"$(CXX)" $(COMMON) -fapple-kext -fno-exceptions -fno-rtti \
	    -std=gnu++17 -MD -MP -c "$<" -o "$@"

$(BUILD)/gpu-memory.o: $(BUILD)/memory.o
	"$(LD)" -r -arch $(ARCH) -o "$@" "$<"

# Host-only ownership/error tests. No mocks enter the kernel component.
contract-tests: $(BUILD)/task-memory-contract
	"$<"

$(BUILD)/task-memory-contract: $(SOURCE)/tests/task_memory_contract.cpp $(SOURCE)/task_memory.cpp $(SOURCE)/task_memory.h | $(BUILD)
	"$(CXX)" -std=gnu++17 -isysroot "$(SDKROOT)" -idirafter "$(HEADERS)" \
	    -O2 -g -Wall -Wextra -Werror -Wconversion -fsanitize=address,undefined \
	    -fno-omit-frame-pointer -MD -MP "$<" -o "$@"

-include $(DEPENDS)
