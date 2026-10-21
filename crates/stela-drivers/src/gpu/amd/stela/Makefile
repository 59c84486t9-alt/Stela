# SPDX-License-Identifier: MIT
# These focused CPU tests require no Linux/Mesa build or physical GPU.
ifndef OUT_DIR
$(error Set OUT_DIR to an absolute ignored build directory)
endif
SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CFLAGS ?= -O2 -g
CLANG ?= clang
NM ?= nm
COMMON := -std=c11 -Wall -Wextra -Werror
VM_HEADERS := $(SOURCE)/vm_cpu.h $(SOURCE)/../amdgpu/amdgpu_vm_cpu_entries.h
TEST_INPUTS := $(SOURCE)/vm_cpu.c $(SOURCE)/../tests/vm_cpu_test.c
TEST_HEADERS := $(VM_HEADERS) $(SOURCE)/../amdgpu/amdgpu_gmc_pte.h \
  $(SOURCE)/../tests/vm_cpu_reference.h

.PHONY: test sanitize native uefi
.DEFAULT_GOAL := test

test: $(OUT_DIR)/vm_cpu_test
	"$<"

sanitize: $(OUT_DIR)/vm_cpu_sanitize
	ASAN_OPTIONS=detect_leaks=0 "$<"

native: $(OUT_DIR)/vm_cpu.o
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"

uefi: $(OUT_DIR)/vm_cpu_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"

$(OUT_DIR):
	mkdir -p "$@"

$(OUT_DIR)/vm_cpu_test: $(TEST_INPUTS) $(TEST_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(TEST_INPUTS) -o "$@"

$(OUT_DIR)/vm_cpu_sanitize: $(TEST_INPUTS) $(TEST_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -O1 -fsanitize=address,undefined $(TEST_INPUTS) -o "$@"

$(OUT_DIR)/vm_cpu.o: $(SOURCE)/vm_cpu.c $(VM_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -ffreestanding -fno-stack-protector \
	  -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

$(OUT_DIR)/vm_cpu_uefi.obj: $(SOURCE)/vm_cpu.c $(VM_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows $(COMMON) $(CFLAGS) -ffreestanding \
	  -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
