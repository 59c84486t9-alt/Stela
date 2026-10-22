# SPDX-License-Identifier: GPL-2.0-or-later
# Explicit external official input: never fetch an unpinned source during builds.
RBTREE_DONOR_SOURCE ?=
RBTREE_SOURCE_SHA := 3bc417b068cba5aff0c9b6a4400ee5b217bc366fe7b6daa66fab8948d16829c3
RBTREE_LINUX := $(SOURCE)/../../common/linux/include/linux
RBTREE_HEADERS := $(addprefix $(RBTREE_LINUX)/,rbtree_types.h rbtree.h rbtree_augmented.h container_of.h)
RBTREE_FLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter -I$(SOURCE)/tests
RBTREE_NATIVE_FLAGS := -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only
RBTREE_TYPES_BLOB := 3c7ae53e813976bd340e3c91c8833910ed1fda56
RBTREE_BLOB := 48acdc3889dd4e76a2313d822407a570c1b0fe90
RBTREE_AUGMENTED_BLOB := 6dbc5a1bf6a8ce04042df4c07167cc226d53a466
RBTREE_CONTAINER_BLOB := 1f6ebf27d962ff01831989cd7744d3cb12c3d37c
.PHONY: rbtree-source-check
rbtree-source-check:
	test -n "$(RBTREE_DONOR_SOURCE)" && test -f "$(RBTREE_DONOR_SOURCE)"
	test "$$(shasum -a 256 "$(RBTREE_DONOR_SOURCE)" | cut -d ' ' -f 1)" = "$(RBTREE_SOURCE_SHA)"
$(BUILD)/rbtree/donor/fixture.stamp: $(RBTREE_DONOR_SOURCE) $(SOURCE)/tests/rbtree.mk | rbtree-source-check
	mkdir -p "$(BUILD)/rbtree/donor"
	git -C "$(SOURCE)" show $(RBTREE_TYPES_BLOB) | sed '/^#include /d' > "$(BUILD)/rbtree/donor/rbtree_types.inc"
	git -C "$(SOURCE)" show $(RBTREE_BLOB) | sed '/^#include /d' > "$(BUILD)/rbtree/donor/rbtree.inc"
	git -C "$(SOURCE)" show $(RBTREE_AUGMENTED_BLOB) | sed '/^#include /d' > "$(BUILD)/rbtree/donor/rbtree_augmented.inc"
	git -C "$(SOURCE)" show $(RBTREE_CONTAINER_BLOB) | sed '/^#include /d' > "$(BUILD)/rbtree/donor/container_of.inc"
	sed '/^#include /d; /^EXPORT_SYMBOL/d' "$(RBTREE_DONOR_SOURCE)" > "$(BUILD)/rbtree/donor/rbtree-body.inc"
	touch "$@"
$(BUILD)/rbtree/current/fixture.stamp: $(BUILD)/rbtree/donor/fixture.stamp $(RBTREE_HEADERS)
	mkdir -p "$(BUILD)/rbtree/current"
	for h in rbtree_types rbtree rbtree_augmented container_of; do sed '/^#include /d' "$(RBTREE_LINUX)/$$h.h" > "$(BUILD)/rbtree/current/$$h.inc"; done
	cp "$(BUILD)/rbtree/donor/rbtree-body.inc" "$(BUILD)/rbtree/current/rbtree-body.inc"
	touch "$@"
RBTREE_TEST_INPUTS := $(SOURCE)/tests/rbtree.c $(SOURCE)/tests/rbtree_bind.h
$(BUILD)/rbtree/donor-test: $(RBTREE_TEST_INPUTS) $(BUILD)/rbtree/donor/fixture.stamp
	$(HOST_CC) $(RBTREE_FLAGS) $(SANITIZE) -I$(BUILD)/rbtree/donor "$<" -o "$@"
$(BUILD)/rbtree/linux-test: $(RBTREE_TEST_INPUTS) $(BUILD)/rbtree/current/fixture.stamp
	$(HOST_CC) $(RBTREE_FLAGS) $(SANITIZE) -I$(BUILD)/rbtree/current "$<" -o "$@"
$(BUILD)/rbtree/native-host-test: $(RBTREE_TEST_INPUTS) $(BUILD)/rbtree/current/fixture.stamp
	$(HOST_CC) $(RBTREE_FLAGS) $(SANITIZE) -DSTELA_NATIVE -I$(BUILD)/rbtree/current "$<" -o "$@"
.PHONY: test-rbtree rbtree-abi
# Compare shape/color checksums as well as independent invariants after each op.
test-rbtree: $(BUILD)/rbtree/donor-test $(BUILD)/rbtree/linux-test $(BUILD)/rbtree/native-host-test
	$(BUILD)/rbtree/donor-test > "$(BUILD)/rbtree/donor-test.log" 2> "$(BUILD)/rbtree/donor-addresses.log"
	$(BUILD)/rbtree/linux-test > "$(BUILD)/rbtree/linux-test.log" 2> "$(BUILD)/rbtree/linux-addresses.log"
	$(BUILD)/rbtree/native-host-test > "$(BUILD)/rbtree/native-host-test.log" 2> "$(BUILD)/rbtree/native-host-addresses.log"
	cmp "$(BUILD)/rbtree/donor-test.log" "$(BUILD)/rbtree/linux-test.log"
	cmp "$(BUILD)/rbtree/donor-test.log" "$(BUILD)/rbtree/native-host-test.log"
	cat "$(BUILD)/rbtree/native-host-test.log"
# Compile native COFF/ELF/Mach-O; this target does not execute COFF or ELF.
rbtree-abi: $(BUILD)/rbtree/current/fixture.stamp $(SOURCE)/tests/rbtree_abi.c $(SOURCE)/tests/rbtree_algorithm.c
	set -e; for t in x86_64-unknown-windows x86_64-unknown-linux-gnu x86_64-apple-darwin; do \
	    for unit in rbtree_abi rbtree_algorithm; do \
	        $(CC) --target=$$t $(RBTREE_FLAGS) $(RBTREE_NATIVE_FLAGS) -DSTELA_NATIVE -I$(BUILD)/rbtree/current -c "$(SOURCE)/tests/$$unit.c" -o "$(BUILD)/rbtree/$$t-$$unit.o"; \
	        $(CC) --target=$$t $(RBTREE_FLAGS) $(RBTREE_NATIVE_FLAGS) -DSTELA_NATIVE -I$(BUILD)/rbtree/current -S -emit-llvm "$(SOURCE)/tests/$$unit.c" -o "$(BUILD)/rbtree/$$t-$$unit.ll"; \
	    done; \
	done
	@if $(CC) --target=x86_64-unknown-windows $(RBTREE_FLAGS) $(RBTREE_NATIVE_FLAGS) -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -I$(BUILD)/rbtree/donor -c "$(SOURCE)/tests/rbtree_abi.c" -o "$(BUILD)/rbtree/broken-donor.o" > "$(BUILD)/rbtree/broken-donor.log" 2>&1; then echo "original LLP64 parent unexpectedly retained pointer width"; exit 1; fi
	rg 'parent must retain all pointer bits' "$(BUILD)/rbtree/broken-donor.log" >/dev/null
	set -e; for t in x86_64-unknown-linux-gnu x86_64-apple-darwin; do \
	    for unit in rbtree_abi rbtree_algorithm; do \
	        $(CC) --target=$$t $(RBTREE_FLAGS) $(RBTREE_NATIVE_FLAGS) -I$(BUILD)/rbtree/donor -S -emit-llvm "$(SOURCE)/tests/$$unit.c" -o "$(BUILD)/rbtree/$$t-$$unit-donor.ll"; \
	        $(CC) --target=$$t $(RBTREE_FLAGS) $(RBTREE_NATIVE_FLAGS) -I$(BUILD)/rbtree/current -S -emit-llvm "$(SOURCE)/tests/$$unit.c" -o "$(BUILD)/rbtree/$$t-$$unit-linux.ll"; \
	        cmp "$(BUILD)/rbtree/$$t-$$unit-donor.ll" "$(BUILD)/rbtree/$$t-$$unit-linux.ll"; \
	        cmp "$(BUILD)/rbtree/$$t-$$unit-donor.ll" "$(BUILD)/rbtree/$$t-$$unit.ll"; \
	    done; \
	done
