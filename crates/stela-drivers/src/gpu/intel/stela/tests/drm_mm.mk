# SPDX-License-Identifier: GPL-2.0-or-later
DRMMM_SOURCE := $(SOURCE)/../../common/linux/drivers/gpu/drm/drm_mm.c
DRMMM_TREE_SOURCE := $(SOURCE)/../../common/linux/lib/rbtree.c
DRMMM_FLAGS := -std=gnu23 -O2 -Wall -Wextra -Werror -Wno-unused-parameter -I$(SOURCE)/tests -D__DISABLE_EXPORTS
.PHONY: drm-mm-source-check
drm-mm-source-check:
	test "$$(shasum -a 256 "$(DRMMM_SOURCE)" | cut -d ' ' -f 1)" = 456a003da23d8d4b243d6ea2e59d69ddf593aef09d81c5b70015726fd666adbf
	test "$$(shasum -a 256 "$(DRMMM_TREE_SOURCE)" | cut -d ' ' -f 1)" = 3bc417b068cba5aff0c9b6a4400ee5b217bc366fe7b6daa66fab8948d16829c3
DRMMM_HEADERS := $(RBTREE_LINUX)/list.h $(RBTREE_LINUX)/types.h $(RBTREE_LINUX)/poison.h \
    $(RBTREE_LINUX)/limits.h \
    $(RBTREE_LINUX)/build_bug.h $(RBTREE_LINUX)/minmax.h $(RBTREE_LINUX)/math64.h \
    $(RBTREE_LINUX)/log2.h $(RBTREE_LINUX)/interval_tree_generic.h $(RBTREE_LINUX)/export.h \
    $(RBTREE_LINUX)/../asm-generic/bitops/generic-non-atomic.h $(RBTREE_LINUX)/../drm/drm_mm.h
$(BUILD)/drm-mm/fixture.stamp: $(BUILD)/rbtree/current/fixture.stamp $(DRMMM_SOURCE) $(DRMMM_TREE_SOURCE) $(DRMMM_HEADERS) $(SOURCE)/tests/drm_mm.mk | drm-mm-source-check
	mkdir -p "$(BUILD)/drm-mm"
	for h in list poison build_bug minmax interval_tree_generic export; do sed '/^#include /d' "$(RBTREE_LINUX)/$$h.h" > "$(BUILD)/drm-mm/$$h.inc"; done
	sed -n '/^struct list_head {/,/^};/p; /^struct hlist_head {/,/^};/p; /^struct hlist_node {/,/^};/p' "$(RBTREE_LINUX)/types.h" > "$(BUILD)/drm-mm/list_types.inc"
	sed '/^#include /d' "$(RBTREE_LINUX)/../asm-generic/bitops/generic-non-atomic.h" > "$(BUILD)/drm-mm/generic-non-atomic.inc"
	sed '/^#include /d' "$(RBTREE_LINUX)/../drm/drm_mm.h" > "$(BUILD)/drm-mm/drm_mm.inc"
	sed -n '/^static inline u64 div64_u64_rem(/,/^}/p' "$(RBTREE_LINUX)/math64.h" > "$(BUILD)/drm-mm/div64.inc"
	awk '/^static __always_inline __attribute__/ { signature = $$0 } /^bool is_power_of_2\(/ { print signature; active = 1 } active { print; if ($$0 == "}") exit }' "$(RBTREE_LINUX)/log2.h" > "$(BUILD)/drm-mm/power2.inc"
	test -s "$(BUILD)/drm-mm/power2.inc"
	sed -n '/^#define U64_MAX/p' "$(RBTREE_LINUX)/limits.h" > "$(BUILD)/drm-mm/limits.inc"
	sed '/^#include /d' "$(DRMMM_SOURCE)" > "$(BUILD)/drm-mm/drm-mm-body.inc"
	sed '/^#include /d' "$(DRMMM_TREE_SOURCE)" > "$(BUILD)/drm-mm/rbtree-body-full.inc"
	touch "$@"
.PHONY: drm-mm-abi
# Full original range+tree algorithm, test-bound only; no production-native claim.
drm-mm-abi: $(BUILD)/drm-mm/fixture.stamp
	set -e; for t in x86_64-unknown-windows x86_64-unknown-linux-gnu x86_64-apple-darwin; do \
	    $(CC) --target=$$t $(DRMMM_FLAGS) $(RBTREE_NATIVE_FLAGS) -DSTELA_NATIVE -I$(BUILD)/rbtree/current -I$(BUILD)/drm-mm -c "$(SOURCE)/tests/drm_mm_algorithm.c" -o "$(BUILD)/drm-mm/$$t.o"; \
	    $(CC) --target=$$t $(DRMMM_FLAGS) $(RBTREE_NATIVE_FLAGS) -DSTELA_NATIVE -I$(BUILD)/rbtree/current -I$(BUILD)/drm-mm -S -emit-llvm "$(SOURCE)/tests/drm_mm_algorithm.c" -o "$(BUILD)/drm-mm/$$t.ll"; \
	done
DRMMM_TEST_INPUTS := $(SOURCE)/tests/drm_mm.c $(SOURCE)/tests/drm_mm_bind.h $(SOURCE)/tests/drm_mm_algorithm.c
$(BUILD)/drm-mm/donor-test: $(DRMMM_TEST_INPUTS) $(BUILD)/drm-mm/fixture.stamp
	$(HOST_CC) $(DRMMM_FLAGS) $(SANITIZE) -I$(BUILD)/rbtree/donor -I$(BUILD)/drm-mm "$<" -o "$@"
$(BUILD)/drm-mm/linux-test: $(DRMMM_TEST_INPUTS) $(BUILD)/drm-mm/fixture.stamp
	$(HOST_CC) $(DRMMM_FLAGS) $(SANITIZE) -I$(BUILD)/rbtree/current -I$(BUILD)/drm-mm "$<" -o "$@"
$(BUILD)/drm-mm/native-host-test: $(DRMMM_TEST_INPUTS) $(BUILD)/drm-mm/fixture.stamp
	$(HOST_CC) $(DRMMM_FLAGS) $(SANITIZE) -DSTELA_NATIVE -I$(BUILD)/rbtree/current -I$(BUILD)/drm-mm "$<" -o "$@"
.PHONY: test-drm-mm
test-drm-mm: $(BUILD)/drm-mm/donor-test $(BUILD)/drm-mm/linux-test $(BUILD)/drm-mm/native-host-test
	$(BUILD)/drm-mm/donor-test > "$(BUILD)/drm-mm/donor-test.log" 2> "$(BUILD)/drm-mm/donor-addresses.log"
	$(BUILD)/drm-mm/linux-test > "$(BUILD)/drm-mm/linux-test.log" 2> "$(BUILD)/drm-mm/linux-addresses.log"
	$(BUILD)/drm-mm/native-host-test > "$(BUILD)/drm-mm/native-host-test.log" 2> "$(BUILD)/drm-mm/native-host-addresses.log"
	cmp "$(BUILD)/drm-mm/donor-test.log" "$(BUILD)/drm-mm/linux-test.log"
	cmp "$(BUILD)/drm-mm/donor-test.log" "$(BUILD)/drm-mm/native-host-test.log"
	cat "$(BUILD)/drm-mm/native-host-test.log"
.PHONY: drm-mm-linux-equivalence
drm-mm-linux-equivalence: $(BUILD)/drm-mm/fixture.stamp
	set -e; for t in x86_64-unknown-linux-gnu x86_64-apple-darwin; do \
	    for variant in donor current; do \
	        $(CC) --target=$$t $(DRMMM_FLAGS) $(RBTREE_NATIVE_FLAGS) -I$(BUILD)/rbtree/$$variant -I$(BUILD)/drm-mm -S -emit-llvm "$(SOURCE)/tests/drm_mm_algorithm.c" -o "$(BUILD)/drm-mm/$$t-$$variant.ll"; \
	    done; \
	    cmp "$(BUILD)/drm-mm/$$t-donor.ll" "$(BUILD)/drm-mm/$$t-current.ll"; \
	done
