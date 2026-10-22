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

# Original BAR policy only: no PCI/MMIO access or native provider activation.
BAR_INCLUDE := -I$(SOURCE)/../../common/linux/include
BAR_HEADERS := $(SOURCE)/native_bar.h $(SOURCE)/../../common/linux/include/drm/amd_asic_type.h
BAR_INPUTS := $(SOURCE)/native_bar.c $(SOURCE)/../tests/native_bar_test.c
.PHONY: bar-test bar-sanitize bar-native bar-uefi
bar-test: $(OUT_DIR)/native_bar_test
	"$<"
bar-sanitize: $(OUT_DIR)/native_bar_sanitize
	ASAN_OPTIONS=detect_leaks=0 "$<"
bar-native: $(OUT_DIR)/native_bar.o
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
bar-uefi: $(OUT_DIR)/native_bar_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
$(OUT_DIR)/native_bar_test: $(BAR_INPUTS) $(BAR_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(BAR_INCLUDE) $(BAR_INPUTS) -o "$@"
$(OUT_DIR)/native_bar_sanitize: $(BAR_INPUTS) $(BAR_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(BAR_INCLUDE) -O1 -fsanitize=address,undefined $(BAR_INPUTS) -o "$@"
$(OUT_DIR)/native_bar.o: $(SOURCE)/native_bar.c $(BAR_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(BAR_INCLUDE) -ffreestanding -fno-stack-protector \
	  -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/native_bar_uefi.obj: $(SOURCE)/native_bar.c $(BAR_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows $(COMMON) $(CFLAGS) $(BAR_INCLUDE) -ffreestanding \
	  -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

# Same original MM-index loop; CPU-only traces and actual bounded native entry.
VRAM_MM_HEADERS := $(SOURCE)/vram_mm.h $(SOURCE)/../amdgpu/amdgpu_mm_access_core.h \
  $(SOURCE)/../include/asic_reg/bif/bif_4_1_d.h
VRAM_MM_TEST := $(SOURCE)/../tests/vram_mm.c
.PHONY: vram-mm-test vram-mm-sanitize vram-mm-native vram-mm-uefi
vram-mm-test: $(OUT_DIR)/vram_mm_test
	"$<"
vram-mm-sanitize: $(OUT_DIR)/vram_mm_sanitize
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$<"
vram-mm-native: $(OUT_DIR)/vram_mm.o
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
vram-mm-uefi: $(OUT_DIR)/vram_mm_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
$(OUT_DIR)/vram-mm-wrapper.inc: $(SOURCE)/../amdgpu/amdgpu_device.c | $(OUT_DIR)
	sed -n '/^static uint32_t amdgpu_mm_access_read32(/,/^size_t amdgpu_device_aper_access(/{ /^size_t amdgpu_device_aper_access(/d; p; }' "$<" > "$@"
	test -s "$@"
$(OUT_DIR)/vram-mm-instrumented.c: $(SOURCE)/vram_mm.c | $(OUT_DIR)
	printf '%s\n' '#include "vram_mm_test_io.h"' > "$@"
	sed -e 's/^stela_amd_vram_mm_read(/stela_amd_vram_mm_test_read(/' \
	  -e 's/uint32_t value = \*pointer;/uint32_t value = stela_amd_test_io_read(pointer);/' \
	  -e 's/\*pointer = value;/stela_amd_test_io_write(pointer, value);/' "$<" >> "$@"
$(OUT_DIR)/vram_mm_test: $(SOURCE)/vram_mm.c $(VRAM_MM_TEST) $(VRAM_MM_HEADERS) \
  $(SOURCE)/../tests/vram_mm_reference.h $(SOURCE)/../tests/vram_mm_test_io.h \
  $(OUT_DIR)/vram-mm-wrapper.inc $(OUT_DIR)/vram-mm-instrumented.c
	$(CC) $(COMMON) $(CFLAGS) -I$(OUT_DIR) -I$(SOURCE) -I$(SOURCE)/../tests \
	  $(SOURCE)/vram_mm.c $(OUT_DIR)/vram-mm-instrumented.c $(VRAM_MM_TEST) -o "$@"
$(OUT_DIR)/vram_mm_sanitize: $(SOURCE)/vram_mm.c $(VRAM_MM_TEST) $(VRAM_MM_HEADERS) \
  $(SOURCE)/../tests/vram_mm_reference.h $(SOURCE)/../tests/vram_mm_test_io.h \
  $(OUT_DIR)/vram-mm-wrapper.inc $(OUT_DIR)/vram-mm-instrumented.c
	$(CC) $(COMMON) $(CFLAGS) -I$(OUT_DIR) -I$(SOURCE) -I$(SOURCE)/../tests -O1 -fno-omit-frame-pointer \
	  -fsanitize=address,undefined $(SOURCE)/vram_mm.c $(OUT_DIR)/vram-mm-instrumented.c $(VRAM_MM_TEST) -o "$@"
$(OUT_DIR)/vram_mm.o: $(SOURCE)/vram_mm.c $(VRAM_MM_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -ffreestanding -fno-stack-protector \
	  -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/vram_mm_uefi.obj: $(SOURCE)/vram_mm.c $(VRAM_MM_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows-gnu $(COMMON) $(CFLAGS) -ffreestanding \
	  -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

# Actual original TMR query, with CPU-only test I/O instrumentation.
TMR_HEADERS := $(SOURCE)/discovery_tmr.h $(SOURCE)/vram_mm.h \
 $(SOURCE)/../include/asic_reg/bif/bif_4_1_d.h \
 $(SOURCE)/../amdgpu/amdgpu_discovery_tmr_core.h \
 $(SOURCE)/../amdgpu/amdgpu_discovery_tmr_limits.h \
 $(SOURCE)/../amdgpu/amdgpu_virt_bootstrap_core.h \
 $(SOURCE)/discovery_binary.h $(SOURCE)/../include/discovery.h \
 $(SOURCE)/../amdgpu/amdgpu_ip_limits.h \
 $(SOURCE)/../../common/linux/include/uapi/linux/stddef.h \
 $(SOURCE)/../../common/linux/include/drm/amd_asic_type.h
.PHONY: tmr-test tmr-sanitize tmr-native tmr-uefi
tmr-test: $(OUT_DIR)/discovery_tmr_test
	"$<"
tmr-sanitize: $(OUT_DIR)/discovery_tmr_sanitize
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$<"
tmr-native: $(OUT_DIR)/discovery_tmr.o
	$(NM) -u "$<" >"$<.undefined"
	test "$$(wc -l < "$<.undefined" | tr -d ' ')" = 1
	rg 'stela_amd_vram_mm_read' "$<.undefined"
tmr-uefi: $(OUT_DIR)/discovery_tmr_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test "$$(wc -l < "$<.undefined" | tr -d ' ')" = 1
	rg 'stela_amd_vram_mm_read' "$<.undefined"
$(OUT_DIR)/discovery-tmr-wrapper.inc: $(SOURCE)/../amdgpu/amdgpu_discovery.c | $(OUT_DIR)
	sed -n '/^static uint32_t amdgpu_discovery_tmr_read32(/,/^static int amdgpu_discovery_read_binary_from_sysmem/{ /^static int amdgpu_discovery_read_binary_from_sysmem/d; p; }' "$<" > "$@"
	test -s "$@"
$(OUT_DIR)/discovery-tmr-instrumented.c: $(SOURCE)/discovery_tmr.c | $(OUT_DIR)
	printf '%s\n' '#include "discovery_tmr_test_io.h"' > "$@"
	sed -e 's/^int stela_amd_discovery_tmr_query(/int stela_amd_discovery_tmr_test_query(/' \
	 -e 's/uint32_t value = \*pointer;/uint32_t value = stela_amd_tmr_test_read(pointer);/' "$<" >> "$@"
$(OUT_DIR)/tmr-vram-instrumented.c: $(SOURCE)/vram_mm.c | $(OUT_DIR)
	printf '%s\n' '#include "discovery_tmr_test_io.h"' > "$@"
	sed -e 's/uint32_t value = \*pointer;/uint32_t value = stela_amd_tmr_test_read(pointer);/' \
	 -e 's/\*pointer = value;/stela_amd_tmr_test_write(pointer, value);/' "$<" >> "$@"
TMR_TEST_INPUTS = $(SOURCE)/../tests/discovery_tmr.c \
 $(OUT_DIR)/discovery-tmr-instrumented.c $(OUT_DIR)/tmr-vram-instrumented.c
TMR_TEST_HEADERS := $(TMR_HEADERS) $(SOURCE)/../tests/discovery_tmr_reference.h \
 $(SOURCE)/../tests/discovery_tmr_virt_reference.h \
 $(SOURCE)/../tests/discovery_tmr_test_io.h
$(OUT_DIR)/discovery_tmr_test: $(TMR_TEST_INPUTS) $(TMR_TEST_HEADERS) $(OUT_DIR)/discovery-tmr-wrapper.inc
	$(CC) $(COMMON) $(CFLAGS) -I$(OUT_DIR) -I$(SOURCE) -I$(SOURCE)/../tests \
	 $(TMR_TEST_INPUTS) -o "$@"
$(OUT_DIR)/discovery_tmr_sanitize: $(TMR_TEST_INPUTS) $(TMR_TEST_HEADERS) $(OUT_DIR)/discovery-tmr-wrapper.inc
	$(CC) $(COMMON) $(CFLAGS) -I$(OUT_DIR) -I$(SOURCE) -I$(SOURCE)/../tests \
	 -O1 -fno-omit-frame-pointer -fsanitize=address,undefined $(TMR_TEST_INPUTS) -o "$@"
$(OUT_DIR)/discovery_tmr.o: $(SOURCE)/discovery_tmr.c $(TMR_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -ffreestanding -fno-stack-protector \
	 -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/discovery_tmr_uefi.obj: $(SOURCE)/discovery_tmr.c $(TMR_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows-gnu $(COMMON) $(CFLAGS) -ffreestanding \
	 -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

# Test-only same-process canonical RAM fixture objects; never linked in a driver.
.PHONY: tmr-ram-model
tmr-ram-model: $(OUT_DIR)/tmr-model.o $(OUT_DIR)/tmr-query-model.o \
 $(OUT_DIR)/tmr-vram-model.o $(OUT_DIR)/tmr-fixture.o $(OUT_DIR)/tmr-binary.o
$(OUT_DIR)/tmr-model.o: $(SOURCE)/../tests/discovery_tmr.c $(TMR_TEST_HEADERS) $(OUT_DIR)/discovery-tmr-wrapper.inc
	$(CC) $(COMMON) $(CFLAGS) -DSTELA_TMR_RUST_MODEL -I$(OUT_DIR) -c "$<" -o "$@"
$(OUT_DIR)/tmr-query-model.o: $(OUT_DIR)/discovery-tmr-instrumented.c $(TMR_HEADERS)
	$(CC) $(COMMON) $(CFLAGS) -I$(SOURCE) -I$(SOURCE)/../tests \
	 -Dstela_amd_discovery_tmr_test_query=stela_amd_discovery_tmr_query -c "$<" -o "$@"
$(OUT_DIR)/tmr-vram-model.o: $(OUT_DIR)/tmr-vram-instrumented.c $(VRAM_MM_HEADERS)
	$(CC) $(COMMON) $(CFLAGS) -I$(SOURCE) -I$(SOURCE)/../tests -c "$<" -o "$@"
$(OUT_DIR)/tmr-fixture.o: $(SOURCE)/../tests/discovery_tmr_fixture.c \
 $(SOURCE)/../tests/discovery_binary_test.c $(SOURCE)/../tests/discovery_reference.h $(TMR_HEADERS)
	$(CC) $(COMMON) $(CFLAGS) -c "$<" -o "$@"
$(OUT_DIR)/tmr-binary.o: $(SOURCE)/discovery_binary.c $(TMR_HEADERS) $(SOURCE)/../include/soc15_hw_ip.h | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -c "$<" -o "$@"

# Immutable discovery snapshots only; optional external files are CPU fixtures.
DISCOVERY_INPUTS ?=
DISCOVERY_HEADERS := $(SOURCE)/discovery_binary.h $(SOURCE)/../include/discovery.h \
  $(SOURCE)/../amdgpu/amdgpu_ip_limits.h $(SOURCE)/../include/soc15_hw_ip.h \
  $(SOURCE)/../../common/linux/include/uapi/linux/stddef.h
DISCOVERY_SOURCES := $(SOURCE)/discovery_binary.c $(SOURCE)/../tests/discovery_binary_test.c
DISCOVERY_TEST_HEADERS := $(DISCOVERY_HEADERS) $(SOURCE)/../tests/discovery_reference.h
.PHONY: discovery-test discovery-sanitize discovery-native discovery-uefi
discovery-test: $(OUT_DIR)/discovery_binary_test
	"$<" $(DISCOVERY_INPUTS)
discovery-sanitize: $(OUT_DIR)/discovery_binary_sanitize
	ASAN_OPTIONS=detect_leaks=0 "$<" $(DISCOVERY_INPUTS)
discovery-native: $(OUT_DIR)/discovery_binary.o
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
discovery-uefi: $(OUT_DIR)/discovery_binary_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
$(OUT_DIR)/discovery_binary_test: $(DISCOVERY_SOURCES) $(DISCOVERY_TEST_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -Wno-unused-function -fwrapv $(DISCOVERY_SOURCES) -o "$@"
$(OUT_DIR)/discovery_binary_sanitize: $(DISCOVERY_SOURCES) $(DISCOVERY_TEST_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -Wno-unused-function -fwrapv -O1 -fno-omit-frame-pointer \
	  -fsanitize=address,undefined $(DISCOVERY_SOURCES) -o "$@"
$(OUT_DIR)/discovery_binary.o: $(SOURCE)/discovery_binary.c $(DISCOVERY_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -ffreestanding -fno-stack-protector \
	  -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/discovery_binary_uefi.obj: $(SOURCE)/discovery_binary.c $(DISCOVERY_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows-gnu $(COMMON) $(CFLAGS) -ffreestanding \
	  -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

# Compile the actual retained live-read function, not a copied replacement.
# Only acquisition/OS context is a bounded CPU model in the test fixture.
.PHONY: discovery-refresh-test discovery-refresh-sanitize
discovery-refresh-test: $(OUT_DIR)/discovery_refresh_test
	"$<"
discovery-refresh-sanitize: $(OUT_DIR)/discovery_refresh_sanitize
	ASAN_OPTIONS=detect_leaks=0 "$<"
$(OUT_DIR)/discovery-refresh.inc: $(SOURCE)/../amdgpu/amdgpu_discovery.c | $(OUT_DIR)
	sed -n '/^static int amdgpu_discovery_refresh_nps_info(/,/^int amdgpu_discovery_get_nps_info(/{ /^int amdgpu_discovery_get_nps_info(/d; p; }' "$<" > "$@"
	test -s "$@"
$(OUT_DIR)/discovery_refresh_test: $(SOURCE)/../tests/discovery_refresh_test.c $(SOURCE)/discovery_binary.c $(DISCOVERY_HEADERS) $(OUT_DIR)/discovery-refresh.inc
	$(CC) $(COMMON) $(CFLAGS) -I$(OUT_DIR) $(SOURCE)/../tests/discovery_refresh_test.c $(SOURCE)/discovery_binary.c -o "$@"
$(OUT_DIR)/discovery_refresh_sanitize: $(SOURCE)/../tests/discovery_refresh_test.c $(SOURCE)/discovery_binary.c $(DISCOVERY_HEADERS) $(OUT_DIR)/discovery-refresh.inc
	$(CC) $(COMMON) $(CFLAGS) -I$(OUT_DIR) -O1 -fsanitize=address,undefined $(SOURCE)/../tests/discovery_refresh_test.c $(SOURCE)/discovery_binary.c -o "$@"

# Original PCI normal-table admission and source policy; no config/MMIO effects.
PCI_HEADERS := $(SOURCE)/pci_match.h $(SOURCE)/../amdgpu/amdgpu_pci_match_core.h \
 $(SOURCE)/../amdgpu/amdgpu_apu_flags_core.h $(SOURCE)/../amdgpu/amdgpu_discovery_source_core.h \
 $(SOURCE)/../include/amd_chip_flags.h \
 $(SOURCE)/../../common/linux/include/drm/amd_asic_type.h \
 $(SOURCE)/../../common/linux/include/linux/device-id/pci.h \
 $(SOURCE)/../../common/linux/include/linux/pci_ids.h
# Original table shorthand/ARRAY_SIZE conventions, as in the Linux consumer.
PCI_FLAGS := -Wno-missing-field-initializers -Wno-sign-compare
.PHONY: pci-test pci-sanitize pci-native pci-uefi
pci-test: $(OUT_DIR)/pci_match_test
	"$<"
pci-sanitize: $(OUT_DIR)/pci_match_sanitize
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$<"
pci-native: $(OUT_DIR)/pci_match.o
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
pci-uefi: $(OUT_DIR)/pci_match_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test ! -s "$<.undefined"
$(OUT_DIR)/pci-linux-wrappers.inc: $(SOURCE)/../amdgpu/amdgpu_drv.c $(SOURCE)/../amdgpu/amdgpu_device.c $(SOURCE)/../amdgpu/amdgpu_discovery.c | $(OUT_DIR)
	sed -n '/^static unsigned long amdgpu_fix_asic_type(/,/^static int amdgpu_pci_probe(/{ /^static int amdgpu_pci_probe(/d; p; }' "$(SOURCE)/../amdgpu/amdgpu_drv.c" > "$@"
	sed -n '/^static int amdgpu_device_init_apu_flags(/,/^\/\*\*/{ /^\/\*\*/d; p; }' "$(SOURCE)/../amdgpu/amdgpu_device.c" >> "$@"
	sed -n '/^static const char \*amdgpu_discovery_get_fw_name(/,/^static int amdgpu_discovery_get_table_info(/{ /^static int amdgpu_discovery_get_table_info(/d; p; }' "$(SOURCE)/../amdgpu/amdgpu_discovery.c" >> "$@"
	test -s "$@"
$(OUT_DIR)/pci_match_test: $(SOURCE)/../tests/pci_match.c $(SOURCE)/../tests/pci_reference.h $(SOURCE)/pci_match.c $(PCI_HEADERS) $(OUT_DIR)/pci-linux-wrappers.inc $(OUT_DIR)/pci-linux-paths.inc | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(PCI_FLAGS) -I$(OUT_DIR) "$<" -o "$@"
$(OUT_DIR)/pci_match_sanitize: $(SOURCE)/../tests/pci_match.c $(SOURCE)/../tests/pci_reference.h $(SOURCE)/pci_match.c $(PCI_HEADERS) $(OUT_DIR)/pci-linux-wrappers.inc $(OUT_DIR)/pci-linux-paths.inc | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(PCI_FLAGS) -I$(OUT_DIR) -O1 -fno-omit-frame-pointer -fsanitize=address,undefined "$<" -o "$@"
$(OUT_DIR)/pci_match.o: $(SOURCE)/pci_match.c $(PCI_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) $(PCI_FLAGS) -ffreestanding -fno-stack-protector \
	 -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/pci_match_uefi.obj: $(SOURCE)/pci_match.c $(PCI_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows-gnu $(COMMON) $(CFLAGS) $(PCI_FLAGS) -ffreestanding \
	 -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/pci-linux-paths.inc: $(SOURCE)/../amdgpu/amdgpu_device.c $(SOURCE)/../amdgpu/amdgpu_discovery.c | $(OUT_DIR)
	printf '%s\n' 'static int linux_initial_path(struct amdgpu_device *adev) {' 'int r;' > "$@"
	sed -n '/switch (amdgpu_initial_ip_path(/,/Check for IP version/{ /Check for IP version/d; p; }' "$(SOURCE)/../amdgpu/amdgpu_device.c" >> "$@"
	printf '%s\n' 'return 0;' '}' 'static int linux_discovery_path(struct amdgpu_device *adev) {' 'int r;' >> "$@"
	sed -n '/switch (amdgpu_discovery_static_asic(/,/amdgpu_discovery_init_soc_config(adev)/{ /amdgpu_discovery_init_soc_config(adev)/d; p; }' "$(SOURCE)/../amdgpu/amdgpu_discovery.c" >> "$@"
	printf '%s\n' 'return 0;' '}' >> "$@"

IP_HEADERS := $(SOURCE)/discovery_ip.h $(SOURCE)/discovery_binary.h \
 $(SOURCE)/../amdgpu/amdgpu_discovery_ip_core.h $(SOURCE)/../amdgpu/amdgpu_ip_types.h \
 $(SOURCE)/../amdgpu/amdgpu_ip_instance_limits.h $(SOURCE)/../amdgpu/amdgpu_ip_limits.h \
 $(SOURCE)/../include/discovery.h $(SOURCE)/../include/soc15_hw_ip.h
.PHONY: ip-test ip-sanitize ip-native ip-uefi
ip-test: $(OUT_DIR)/discovery_ip_test
	"$<" $(IP_INPUTS)
ip-sanitize: $(OUT_DIR)/discovery_ip_sanitize
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$<" $(IP_INPUTS)
ip-native: $(OUT_DIR)/discovery_ip.o
	$(NM) -u "$<" >"$<.undefined"
	test $$(wc -l <"$<.undefined") -eq 2
	rg 'amdgpu_discovery_binary_(table|validate)' "$<.undefined"
ip-uefi: $(OUT_DIR)/discovery_ip_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test $$(wc -l <"$<.undefined") -eq 2
	rg 'amdgpu_discovery_binary_(table|validate)' "$<.undefined"
$(OUT_DIR)/discovery-ip-linux.inc: $(SOURCE)/../amdgpu/amdgpu_discovery.c | $(OUT_DIR)
	sed -n '/^static void amdgpu_discovery_ip_debug(/,/^static uint32_t amdgpu_discovery_tmr_read32(/{ /^static uint32_t amdgpu_discovery_tmr_read32(/d; p; }' "$<" > "$@"
	sed -n '/^static int amdgpu_discovery_validate_ip(/,/^static void amdgpu_discovery_read_harvest_bit_per_ip(/{ /^static void amdgpu_discovery_read_harvest_bit_per_ip(/d; p; }' "$<" >> "$@"
	sed -n '/^static int amdgpu_discovery_reg_base_init(/,/^static void amdgpu_discovery_harvest_ip(/{ /^static void amdgpu_discovery_harvest_ip(/d; p; }' "$<" >> "$@"
IP_TEST_SOURCES := $(SOURCE)/discovery_ip.c $(SOURCE)/discovery_binary.c \
 $(SOURCE)/../tests/discovery_ip.c $(SOURCE)/../tests/discovery_ip_fixture.c
IP_TEST_DEPS := $(IP_HEADERS) $(SOURCE)/../tests/discovery_ip_reference.h \
 $(SOURCE)/../tests/discovery_binary_test.c $(SOURCE)/../tests/discovery_reference.h \
 $(OUT_DIR)/discovery-ip-linux.inc
$(OUT_DIR)/discovery_ip_test: $(IP_TEST_SOURCES) $(IP_TEST_DEPS)
	$(CC) $(COMMON) $(CFLAGS) -fwrapv -Wno-sign-compare -I$(OUT_DIR) $(IP_TEST_SOURCES) -o "$@"
$(OUT_DIR)/discovery_ip_sanitize: $(IP_TEST_SOURCES) $(IP_TEST_DEPS)
	$(CC) $(COMMON) $(CFLAGS) -O1 -fwrapv -fno-omit-frame-pointer -fsanitize=address,undefined -Wno-sign-compare -I$(OUT_DIR) $(IP_TEST_SOURCES) -o "$@"
$(OUT_DIR)/discovery_ip.o: $(SOURCE)/discovery_ip.c $(IP_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -fwrapv -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/discovery_ip_uefi.obj: $(SOURCE)/discovery_ip.c $(IP_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows-gnu $(COMMON) $(CFLAGS) -fwrapv -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

# Test-only independent frozen consumer for the canonical owned-source harness.
# Never linked into the production driver archive or used as a provider.
.PHONY: ip-ram-model
ip-ram-model: $(OUT_DIR)/ip-oracle.o $(OUT_DIR)/ip-fixture.o
$(OUT_DIR)/ip-oracle.o: $(IP_TEST_SOURCES) $(IP_TEST_DEPS)
	$(CC) $(COMMON) $(CFLAGS) -fwrapv -Wno-sign-compare -DSTELA_IP_RUST_MODEL \
	 -Dmain=stela_amd_ip_test_main -I$(OUT_DIR) -c "$(SOURCE)/../tests/discovery_ip.c" -o "$@"
$(OUT_DIR)/ip-fixture.o: $(SOURCE)/../tests/discovery_ip_fixture.c $(DISCOVERY_TEST_HEADERS) \
 $(SOURCE)/../tests/discovery_binary_test.c | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -c "$<" -o "$@"

FILE_HEADERS := $(SOURCE)/discovery_file.h $(SOURCE)/../amdgpu/amdgpu_discovery_file_core.h $(DISCOVERY_HEADERS)
FILE_SOURCES := $(SOURCE)/discovery_file.c $(SOURCE)/discovery_binary.c \
 $(SOURCE)/../tests/discovery_file.c $(SOURCE)/../tests/discovery_ip_fixture.c
FILE_TEST_DEPS := $(FILE_HEADERS) $(SOURCE)/../tests/discovery_file_reference.h \
 $(SOURCE)/../tests/discovery_binary_test.c $(SOURCE)/../tests/discovery_reference.h \
 $(OUT_DIR)/discovery-file-linux.inc
.PHONY: file-test file-sanitize file-native file-uefi
file-test: $(OUT_DIR)/discovery_file_test
	"$<" $(FILE_INPUTS)
file-sanitize: $(OUT_DIR)/discovery_file_sanitize
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$<" $(FILE_INPUTS)
file-native: $(OUT_DIR)/discovery_file.o
	$(NM) -u "$<" >"$<.undefined"
	test $$(wc -l <"$<.undefined") -eq 1
	rg 'amdgpu_discovery_binary_validate' "$<.undefined"
file-uefi: $(OUT_DIR)/discovery_file_uefi.obj
	$(NM) -u "$<" >"$<.undefined"
	test $$(wc -l <"$<.undefined") -eq 1
	rg 'amdgpu_discovery_binary_validate' "$<.undefined"
$(OUT_DIR)/discovery-file-linux.inc: $(SOURCE)/../amdgpu/amdgpu_discovery.c | $(OUT_DIR)
	sed -n '/^static int amdgpu_discovery_read_binary_from_file(/,/^static inline bool amdgpu_discovery_verify_checksum(/{ /^static inline bool amdgpu_discovery_verify_checksum(/d; p; }' "$<" > "$@"
$(OUT_DIR)/discovery_file_test: $(FILE_SOURCES) $(FILE_TEST_DEPS)
	$(CC) $(COMMON) $(CFLAGS) -fwrapv -I$(OUT_DIR) $(FILE_SOURCES) -o "$@"
$(OUT_DIR)/discovery_file_sanitize: $(FILE_SOURCES) $(FILE_TEST_DEPS)
	$(CC) $(COMMON) $(CFLAGS) -fwrapv -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -I$(OUT_DIR) $(FILE_SOURCES) -o "$@"
$(OUT_DIR)/discovery_file.o: $(SOURCE)/discovery_file.c $(FILE_HEADERS) | $(OUT_DIR)
	$(CC) $(COMMON) $(CFLAGS) -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"
$(OUT_DIR)/discovery_file_uefi.obj: $(SOURCE)/discovery_file.c $(FILE_HEADERS) | $(OUT_DIR)
	$(CLANG) --target=x86_64-unknown-windows-gnu $(COMMON) $(CFLAGS) -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only -c "$<" -o "$@"

.PHONY: file-ram-model
file-ram-model: $(OUT_DIR)/file-oracle.o
$(OUT_DIR)/file-oracle.o: $(FILE_SOURCES) $(FILE_TEST_DEPS)
	$(CC) $(COMMON) $(CFLAGS) -fwrapv -Dmain=stela_amd_file_test_main \
	 -I$(OUT_DIR) -c "$(SOURCE)/../tests/discovery_file.c" -o "$@"
