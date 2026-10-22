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
OBJECTS += $(BUILD)/activation.o $(BUILD)/firmware.o $(BUILD)/wopcm.o $(BUILD)/ggtt_probe.o $(BUILD)/pat.o $(BUILD)/guc_reset.o
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

ACTIVATION_HEADERS := $(SOURCE)/activation.h $(wildcard $(SOURCE)/../xe/xe_*core.h \
    $(SOURCE)/../xe/xe_*types.h $(SOURCE)/../xe/xe_pci*.h $(SOURCE)/../xe/xe_mmio_poll.h \
    $(SOURCE)/../xe/xe_engine_ids.h $(SOURCE)/../xe/xe_force_wake_gt.h $(SOURCE)/wopcm.h $(SOURCE)/pat.h $(SOURCE)/guc_reset.h \
    $(SOURCE)/../xe/regs/*.h) $(SOURCE)/../../common/linux/include/drm/intel/pciids.h
$(BUILD)/activation.o: $(SOURCE)/activation.c $(ACTIVATION_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(SOURCE)/../../common/linux/include -MD -MP -c "$<" -o "$@"

.PHONY: activation test-activation test-activation-donor
activation: $(BUILD)/activation.o

$(BUILD)/activation-test: $(SOURCE)/tests/activation.c $(SOURCE)/activation.c $(ACTIVATION_HEADERS) $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE)/../../common/linux/include "$<" $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o -lpthread -o "$@"

test-activation: $(BUILD)/activation-test
	$(BUILD)/activation-test

# Immutable pre-extraction source object; override deliberately when updating
# retained driver source. This compiles actual donor loop fragments, not a
# handwritten oracle or a second shipping algorithm. No Linux runtime shim.
ACTIVATION_DONOR_BLOB ?= 197e2197bd0a300e4e83e5653b07eb861b39c6e2
$(BUILD)/activation-donor/donor-get.inc: | $(BUILD)
	mkdir -p "$(BUILD)/activation-donor"
	git -C "$(SOURCE)" show $(ACTIVATION_DONOR_BLOB) | \
	    sed -n '/^\tref_rqst = (domains == XE_FORCEWAKE_ALL)/,/^\tspin_unlock_irqrestore/{ /^\tspin_.*irq/d; p; }' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/activation-donor/donor-put.inc: | $(BUILD)
	mkdir -p "$(BUILD)/activation-donor"
	git -C "$(SOURCE)" show $(ACTIVATION_DONOR_BLOB) | \
	    sed -n '/^void xe_force_wake_put(/,/^const char \*xe_force_wake_domain_to_str/p' | \
	    sed -n '/^\tfor_each_fw_domain_masked(domain, fw_ref/,/^\tspin_unlock_irqrestore/{ /^\tspin_.*irq/d; p; }' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/activation-donor-reference.o: $(SOURCE)/tests/activation_donor.c $(SOURCE)/tests/activation_donor.h $(ACTIVATION_HEADERS) \
    $(BUILD)/activation-donor/donor-get.inc $(BUILD)/activation-donor/donor-put.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/activation-donor -c "$<" -o "$@"
$(BUILD)/activation-donor-test: $(SOURCE)/tests/activation.c $(SOURCE)/activation.c $(ACTIVATION_HEADERS) \
    $(BUILD)/activation-donor-reference.o $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o \
    $(BUILD)/activation-donor/donor-get.inc $(BUILD)/activation-donor/donor-put.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -DSTELA_DONOR_CHECK \
	    -I$(BUILD)/activation-donor -I$(SOURCE)/../../common/linux/include "$<" \
	    $(BUILD)/activation-donor-reference.o $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o -lpthread -o "$@"
test-activation-donor: $(BUILD)/activation-donor-test
	$(BUILD)/activation-donor-test

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
	$(HOST_CC) -DSTELA_NATIVE -DGFX_VERx10=$* -std=gnu11 -O2 -g $(SANITIZE) \
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

# Exact original GuC catalog/CSS algorithms; immutable metadata only, no upload.
FIRMWARE_HEADERS := $(SOURCE)/firmware.h $(SOURCE)/../xe/xe_scalar_types.h \
    $(SOURCE)/../xe/xe_platform_types.h $(SOURCE)/../xe/xe_gt_type.h $(SOURCE)/../xe/xe_huc_role.h \
    $(SOURCE)/../xe/xe_uc_fw_types.h $(SOURCE)/../xe/xe_uc_fw_catalog.h \
    $(SOURCE)/../xe/xe_uc_fw_css.h $(SOURCE)/../xe/xe_uc_fw_cpd.h $(SOURCE)/../xe/xe_uc_fw_version.h \
    $(SOURCE)/../xe/abi/uc_fw_abi.h
$(BUILD)/firmware.o: $(SOURCE)/firmware.c $(FIRMWARE_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -MD -MP -c "$<" -o "$@"
.PHONY: firmware test-firmware
firmware: $(BUILD)/firmware.o
FIRMWARE_DONOR_BLOB ?= 3f08a3b54062842f268da77f913aab57c3c09fb4
$(BUILD)/firmware-donor/donor-fw-defs.inc: | $(BUILD)
	mkdir -p "$(BUILD)/firmware-donor"
	git -C "$(SOURCE)" show $(FIRMWARE_DONOR_BLOB) | \
	    sed -n '/^struct uc_fw_entry {/,/^XE_GUC_FIRMWARE_DEFS(XE_UC_MODULE_FIRMWARE,/p' | \
	    sed '$$d' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/firmware-donor/donor-fw-select.inc: | $(BUILD)
	mkdir -p "$(BUILD)/firmware-donor"
	git -C "$(SOURCE)" show $(FIRMWARE_DONOR_BLOB) | \
	    sed -n '/^uc_fw_auto_select(/,/^}/p' | sed '1,2d;$$d' | \
	    sed '/^\tstruct xe_gt \*gt =/d; /^\tenum xe_platform p =/d; s/gt->info.type/gt_type/g' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/firmware-donor/donor-fw-css.inc: | $(BUILD)
	mkdir -p "$(BUILD)/firmware-donor"
	git -C "$(SOURCE)" show $(FIRMWARE_DONOR_BLOB) | \
	    sed -n '/^static int guc_read_css_info(/,/^static bool is_cpd_header(/p' | sed '$$d' | \
	    sed '/^\tstruct xe_gt \*gt =/d; /^\tstruct xe_device \*xe =/d' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/firmware-donor-reference.o: $(SOURCE)/tests/firmware_donor.c \
    $(SOURCE)/tests/firmware_donor.h $(FIRMWARE_HEADERS) \
    $(BUILD)/firmware-donor/donor-fw-defs.inc $(BUILD)/firmware-donor/donor-fw-select.inc \
    $(BUILD)/firmware-donor/donor-fw-css.inc $(BUILD)/firmware-donor/donor-fw-supported.inc \
    $(BUILD)/firmware-donor/donor-fw-default-status.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/firmware-donor -c "$<" -o "$@"
$(BUILD)/firmware-test: $(SOURCE)/tests/firmware.c $(SOURCE)/firmware.c \
    $(FIRMWARE_HEADERS) $(BUILD)/firmware-donor-reference.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(BUILD)/firmware-donor-reference.o -o "$@"
test-firmware: $(BUILD)/firmware-test
	$(BUILD)/firmware-test

WOPCM_HEADERS := $(SOURCE)/wopcm.h $(SOURCE)/activation.h $(SOURCE)/firmware.h \
    $(SOURCE)/../xe/xe_wopcm_core.h $(SOURCE)/../xe/xe_wopcm_size.h $(SOURCE)/../xe/xe_wopcm_types.h \
    $(SOURCE)/../xe/xe_huc_role.h $(SOURCE)/../xe/xe_mmio_verify.h \
    $(SOURCE)/../xe/regs/xe_guc_regs.h $(SOURCE)/../xe/xe_platform_types.h
$(BUILD)/wopcm.o: $(SOURCE)/wopcm.c $(WOPCM_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(SOURCE)/../../common/linux/include -MD -MP -c "$<" -o "$@"
$(BUILD)/wopcm-host.o: $(SOURCE)/wopcm.c $(WOPCM_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE)/../../common/linux/include -MD -MP -c "$<" -o "$@"
$(BUILD)/firmware-host.o: $(SOURCE)/firmware.c $(FIRMWARE_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -MD -MP -c "$<" -o "$@"
.PHONY: wopcm
wopcm: $(BUILD)/activation.o $(BUILD)/firmware.o $(BUILD)/wopcm.o

WOPCM_DONOR_BLOB ?= fe65ed246775d99973db5ac3552c40003cea9a55
WOPCM_VERIFY_DONOR_BLOB ?= 8b251c4811472a047e238a9448cbc9d96511cb40
WOPCM_HUC_DONOR_BLOB ?= 57afe21444b183f298a106e29f0e802d2ce343b3
$(BUILD)/wopcm-donor/donor-wopcm-constants.inc: | $(BUILD)
	mkdir -p "$(BUILD)/wopcm-donor"
	git -C "$(SOURCE)" show $(WOPCM_DONOR_BLOB) | \
	    sed -n '/^\/\* Default WOPCM size/,/^static inline struct xe_gt \*wopcm_to_gt/p' | \
	    sed '$$d' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/wopcm-donor/donor-wopcm-body.inc: | $(BUILD)
	mkdir -p "$(BUILD)/wopcm-donor"
	git -C "$(SOURCE)" show $(WOPCM_DONOR_BLOB) | \
	    sed -n '/^static u32 context_reserved_size/,/^ALLOW_ERROR_INJECTION/p' | sed '$$d' | \
	    sed 's/struct xe_device \*/struct stela_wopcm_model */g; s/struct xe_gt \*/struct stela_wopcm_model */g; s/xe->info.platform/xe->platform/g; s/\&gt->mmio/gt/g; s/xe_uc_fw_get_upload_size(\&gt->uc.guc.fw)/gt->guc_fw_size/g; s/xe_uc_fw_get_upload_size(\&gt->uc.huc.fw)/gt->huc_fw_size/g; s/xe_uc_fw_is_available(\&gt->uc.huc.fw)/stela_wopcm_huc(gt)/g' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/wopcm-donor/donor-verify.inc: | $(BUILD)
	mkdir -p "$(BUILD)/wopcm-donor"
	git -C "$(SOURCE)" show $(WOPCM_VERIFY_DONOR_BLOB) | \
	    sed -n '/^int xe_mmio_write32_and_verify(/,/^bool xe_mmio_in_range(/p' | sed '$$d' | \
	    sed 's/struct xe_mmio \*/struct stela_wopcm_model */g' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/wopcm-donor/donor-huc-role.inc: | $(BUILD)
	mkdir -p "$(BUILD)/wopcm-donor"
	git -C "$(SOURCE)" show $(WOPCM_HUC_DONOR_BLOB) | \
	    sed -n '/if (!xe_gt_is_media_type(gt) \&\& GRAPHICS_VERx100(xe) > 1255)/p' | \
	    sed 's/if (/return (/; s/) {/);/; s/xe_gt_is_media_type(gt)/media_gt/g; s/GRAPHICS_VERx100(xe)/graphics_verx100/g' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/wopcm-donor-reference.o: $(SOURCE)/tests/wopcm_donor.c $(SOURCE)/tests/wopcm_donor.h \
    $(WOPCM_HEADERS) $(BUILD)/wopcm-donor/donor-wopcm-constants.inc \
    $(BUILD)/wopcm-donor/donor-wopcm-body.inc $(BUILD)/wopcm-donor/donor-verify.inc \
    $(BUILD)/wopcm-donor/donor-huc-role.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE)/../../common/linux/include \
	    -I$(BUILD)/wopcm-donor -c "$<" -o "$@"
$(BUILD)/wopcm-test: $(SOURCE)/tests/wopcm.c $(SOURCE)/tests/wopcm_donor.h \
    $(WOPCM_HEADERS) $(BUILD)/wopcm-donor-reference.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE)/../../common/linux/include \
	    "$<" $(BUILD)/wopcm-donor-reference.o -lpthread -o "$@"
.PHONY: test-wopcm
test-wopcm: $(BUILD)/wopcm-test
	$(BUILD)/wopcm-test
$(BUILD)/activation-host.o: $(SOURCE)/activation.c $(ACTIVATION_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE)/../../common/linux/include -MD -MP -c "$<" -o "$@"
.PHONY: host-activation
host-activation: $(BUILD)/activation-host.o $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o
$(BUILD)/wopcm-owned-test: $(SOURCE)/tests/wopcm_owned.c $(SOURCE)/activation.c \
    $(ACTIVATION_HEADERS) $(WOPCM_HEADERS) $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(SOURCE)/../../common/linux/include \
	    "$<" $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o $(BUILD)/guc_reset-host.o -lpthread -o "$@"
.PHONY: test-wopcm-owned
test-wopcm-owned: $(BUILD)/wopcm-owned-test
	$(BUILD)/wopcm-owned-test
-include $(BUILD)/activation-host.d $(BUILD)/wopcm-host.d $(BUILD)/firmware-host.d

FIRMWARE_SUPPORTED_DONOR_BLOB ?= f2d3a3e7208bc1d0351c4f544b006889267d81e4
$(BUILD)/firmware-donor/donor-fw-supported.inc: | $(BUILD)
	mkdir -p "$(BUILD)/firmware-donor"
	git -C "$(SOURCE)" show $(FIRMWARE_SUPPORTED_DONOR_BLOB) | \
	    sed -n '/^static inline enum xe_uc_fw_status$$/,/^static inline bool xe_uc_fw_is_enabled(/p' | \
	    sed '$$d' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/firmware-donor/donor-fw-default-status.inc: | $(BUILD)
	mkdir -p "$(BUILD)/firmware-donor"
	git -C "$(SOURCE)" show $(FIRMWARE_DONOR_BLOB) | \
	    sed -n '/^static int uc_fw_request(/,/^static void uc_fw_release(/p' | \
	    sed -n '/^\txe_uc_fw_change_status(uc_fw, uc_fw->path ?$$/,/^\t\/\* an empty path means the firmware is disabled \*\//p' | \
	    sed '$$d' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"

# Same frozen original source as CSS/catalog, with only actual scalar context
# spellings and GSC security-output adapter changed; no fabricated Linux type.
$(BUILD)/firmware-donor/donor-fw-cpd.inc: | $(BUILD)
	mkdir -p "$(BUILD)/firmware-donor"
	git -C "$(SOURCE)" show $(FIRMWARE_DONOR_BLOB) | \
	    sed -n '/^static bool is_cpd_header(/,/^static int parse_gsc_layout(/p' | sed '$$d' | \
	    sed '/^	struct xe_gt \*gt =/d; /^	struct xe_device \*xe =/d; /struct xe_gsc \*gsc = container_of/d; s/xe->info.platform/active_platform/g; s/gsc->security_version/(*active_security)/g' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/huc-firmware-donor-reference.o: $(SOURCE)/tests/huc_firmware_donor.c \
    $(SOURCE)/tests/firmware_donor.h $(FIRMWARE_HEADERS) $(BUILD)/firmware-donor/donor-fw-cpd.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/firmware-donor -c "$<" -o "$@"
$(BUILD)/huc-firmware-test: $(SOURCE)/tests/huc_firmware.c $(SOURCE)/firmware.c \
    $(FIRMWARE_HEADERS) $(BUILD)/firmware-donor-reference.o $(BUILD)/huc-firmware-donor-reference.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) "$<" $(BUILD)/firmware-donor-reference.o $(BUILD)/huc-firmware-donor-reference.o -o "$@"
.PHONY: test-huc-firmware
test-huc-firmware: $(BUILD)/huc-firmware-test
	$(BUILD)/huc-firmware-test

GGTT_DEFS := $(BUILD)/ggtt/ggtt_probe_defs.h
GGTT_GMCH_SOURCE := $(SOURCE)/../../common/linux/include/drm/intel/i915_drm.h
GGTT_PAGE_SOURCE := $(SOURCE)/../xe/xe_bo.h
GGTT_SIZE_SOURCE := $(SOURCE)/../../common/linux/include/linux/sizes.h
GGTT_PROBE_HEADERS := $(SOURCE)/ggtt_probe.h $(SOURCE)/../xe/xe_ggtt_probe_core.h \
    $(SOURCE)/../xe/xe_wopcm_size.h $(SOURCE)/../xe/regs/xe_gtt_defs.h \
    $(SOURCE)/../xe/xe_scalar_types.h $(SOURCE)/../xe/xe_platform_types.h $(GGTT_DEFS)
$(GGTT_DEFS): $(GGTT_GMCH_SOURCE) $(GGTT_PAGE_SOURCE) $(GGTT_SIZE_SOURCE) | $(BUILD)
	mkdir -p "$(BUILD)/ggtt"
	sed -n '1,/^#ifndef _I915_DRM_H_/p' "$(GGTT_GMCH_SOURCE)" | sed '$$d' > "$@.tmp"
	sed -n '/^#define SNB_GMCH_CTRL[[:space:]]/p; /^#define   BDW_GMCH_GGMS_SHIFT[[:space:]]/p; /^#define   BDW_GMCH_GGMS_MASK[[:space:]]/p' "$(GGTT_GMCH_SOURCE)" >> "$@.tmp"
	sed -n '/^#define XE_PTE_SHIFT[[:space:]]/p; /^#define XE_PAGE_SIZE[[:space:]]/p; /^#define XE_PTE_MASK[[:space:]]/p' "$(GGTT_PAGE_SOURCE)" >> "$@.tmp"
	sed -n '/^#define SZ_1M[[:space:]]/p; /^#define SZ_8M[[:space:]]/p; /^#define SZ_2M[[:space:]]/p' "$(GGTT_SIZE_SOURCE)" >> "$@.tmp"
	test "$$(sed -n '/^#define /p' "$@.tmp" | wc -l | tr -d ' ')" = 9
	mv "$@.tmp" "$@"
$(BUILD)/ggtt_probe.o: $(SOURCE)/ggtt_probe.c $(GGTT_PROBE_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(BUILD)/ggtt -MD -MP -c "$<" -o "$@"
$(BUILD)/ggtt_probe-host.o: $(SOURCE)/ggtt_probe.c $(GGTT_PROBE_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/ggtt -MD -MP -c "$<" -o "$@"
.PHONY: ggtt-probe ggtt-probe-headers host-ggtt-probe
ggtt-probe-headers: $(GGTT_DEFS)
ggtt-probe: $(BUILD)/ggtt_probe.o
host-ggtt-probe: $(BUILD)/ggtt_probe-host.o
-include $(BUILD)/ggtt_probe.d $(BUILD)/ggtt_probe-host.d

# Frozen complete original Xe GGTT source. No fake Linux TU or MMIO provider:
# only unchanged scalar algorithms/assertions are compiled in the donor object.
GGTT_DONOR_BLOB ?= a351c578b17055b31d03f5cbf8ba06a71590c624
$(BUILD)/ggtt/donor-gsm-decode.inc: | $(BUILD)
	mkdir -p "$(BUILD)/ggtt"
	git -C "$(SOURCE)" show $(GGTT_DONOR_BLOB) | \
	    sed -n '/^static unsigned int probe_gsm_size(/,/^}/p' | \
	    sed -n '/^\tggms = /,/^\treturn /p' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/ggtt/donor-pf-range.inc: | $(BUILD)
	mkdir -p "$(BUILD)/ggtt"
	git -C "$(SOURCE)" show $(GGTT_DONOR_BLOB) | \
	    sed -n '/^\t\tggtt_start = wopcm;$$/,+1p' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/ggtt/donor-range-clamp.inc: | $(BUILD)
	mkdir -p "$(BUILD)/ggtt"
	git -C "$(SOURCE)" show $(GGTT_DONOR_BLOB) | \
	    sed -n '/^\tif (ggtt_size + ggtt_start > GUC_GGTT_TOP)$$/,+1p' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/ggtt/donor-pte-index.inc: | $(BUILD)
	mkdir -p "$(BUILD)/ggtt"
	git -C "$(SOURCE)" show $(GGTT_DONOR_BLOB) | \
	    sed -n '/^static u64 xe_ggtt_get_pte(/,/^}/p' | \
	    sed -n '/^\txe_tile_assert/,/^\treturn /p' | \
	    sed 's/xe_tile_assert(ggtt->tile, /assert(/g; s/ggtt->start/start/g; s/ggtt->size/size/g; s/readq(\&ggtt->gsm\[addr >> XE_PTE_SHIFT\])/addr >> XE_PTE_SHIFT/' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/ggtt-donor.o: $(SOURCE)/tests/ggtt_probe_donor.c $(SOURCE)/tests/ggtt_probe_donor.h \
    $(GGTT_PROBE_HEADERS) $(BUILD)/ggtt/donor-gsm-decode.inc $(BUILD)/ggtt/donor-pf-range.inc \
    $(BUILD)/ggtt/donor-range-clamp.inc $(BUILD)/ggtt/donor-pte-index.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/ggtt -c "$<" -o "$@"
$(BUILD)/ggtt-probe-test: $(SOURCE)/tests/ggtt_probe.c $(SOURCE)/tests/ggtt_probe_donor.h \
    $(GGTT_PROBE_HEADERS) $(BUILD)/ggtt-donor.o $(BUILD)/ggtt_probe-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/ggtt "$<" \
	    $(BUILD)/ggtt-donor.o $(BUILD)/ggtt_probe-host.o -o "$@"
.PHONY: test-ggtt-probe
test-ggtt-probe: $(BUILD)/ggtt-probe-test
	$(BUILD)/ggtt-probe-test

# Exact Linux compile-time definitions only. Active _Static_assert is retained;
# actual pick.h supplies address math, without compiler/percpu/runtime imports.
PAT_COMPILE_DEFS := $(BUILD)/pat/pat_compile_defs.h
PAT_COMPILER := $(SOURCE)/../../common/linux/include/linux/compiler.h
PAT_BUILD_BUG := $(SOURCE)/../../common/linux/include/linux/build_bug.h
$(PAT_COMPILE_DEFS): $(PAT_COMPILER) $(PAT_BUILD_BUG) | $(BUILD)
	mkdir -p "$(BUILD)/pat"
	sed -n '1p' "$(PAT_COMPILER)" > "$@.tmp"
	sed -n '/^#define __BUILD_BUG_ON_ZERO_MSG.*_Static_assert/p' "$(PAT_COMPILER)" >> "$@.tmp"
	awk '/^#define __is_constexpr\(/ { active = 1 } active { print; if ($$0 !~ /\\$$/) exit }' "$(PAT_COMPILER)" >> "$@.tmp"
	awk '/^#define BUILD_BUG_ON_ZERO\(/ { active = 1 } active { print; if ($$0 !~ /\\$$/) exit }' "$(PAT_BUILD_BUG)" >> "$@.tmp"
	test "$$(sed -n '/^#define /p' "$@.tmp" | wc -l | tr -d ' ')" = 3
	grep -Eq '_Static_assert' "$@.tmp"
	mv "$@.tmp" "$@"
PAT_HEADERS := $(SOURCE)/pat.h $(SOURCE)/activation.h $(SOURCE)/../xe/xe_pat.h \
    $(SOURCE)/../xe/xe_pat_tables.h $(SOURCE)/../xe/xe_pat_select.h \
    $(SOURCE)/../xe/xe_pat_program.h $(SOURCE)/../xe/xe_cache_level.h \
    $(SOURCE)/../xe/xe_gt_type.h $(PAT_COMPILE_DEFS) \
    $(SOURCE)/../../common/linux/include/drm/intel/pick.h
$(BUILD)/pat.o: $(SOURCE)/pat.c $(PAT_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(BUILD)/pat -I$(SOURCE)/../../common/linux/include -MD -MP -c "$<" -o "$@"
$(BUILD)/pat-host.o: $(SOURCE)/pat.c $(PAT_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/pat -I$(SOURCE)/../../common/linux/include -MD -MP -c "$<" -o "$@"
.PHONY: pat host-pat pat-headers
pat: $(BUILD)/pat.o
host-pat: $(BUILD)/pat-host.o
pat-headers: $(PAT_COMPILE_DEFS)
-include $(BUILD)/pat.d $(BUILD)/pat-host.d
PAT_DONOR_BLOB ?= fad5b5a5ed4a0ca256a98168e4beda1dab3f5bd5
$(BUILD)/pat/donor-pat-tables.inc: | $(BUILD)
	mkdir -p "$(BUILD)/pat"
	git -C "$(SOURCE)" show $(PAT_DONOR_BLOB) | sed -n '/^#define _PAT_ATS/,/^#define PAT_LABEL_LEN/{ /^#define PAT_LABEL_LEN/d; p; }' > "$@"
	git -C "$(SOURCE)" show $(PAT_DONOR_BLOB) | sed -n '/^static const struct xe_pat_table_entry xelp_pat_table\[\]/,/^u16 xe_pat_index_get_coh_mode/{ /^u16 xe_pat_index_get_coh_mode/d; p; }' >> "$@"
$(BUILD)/pat/donor-pat-select.inc: | $(BUILD)
	mkdir -p "$(BUILD)/pat"
	git -C "$(SOURCE)" show $(PAT_DONOR_BLOB) | sed -n '/^void xe_pat_init_early(/,/^void xe_pat_init(/{ /^void xe_pat_init(/d; p; }' > "$@"
$(BUILD)/pat/donor-pat-program.inc: | $(BUILD)
	mkdir -p "$(BUILD)/pat"
	git -C "$(SOURCE)" show $(PAT_DONOR_BLOB) | sed -n '/^static void program_pat(/,/^static void program_pat_mcr(/{ /^static void program_pat_mcr(/d; p; }' > "$@"
PAT_DONOR_HEADERS := $(SOURCE)/tests/pat_donor.h $(PAT_HEADERS) \
    $(BUILD)/pat/donor-pat-tables.inc $(BUILD)/pat/donor-pat-select.inc $(BUILD)/pat/donor-pat-program.inc $(BUILD)/pat/current-pat-wrapper.inc
$(BUILD)/pat-donor.o: $(SOURCE)/tests/pat_donor.c $(PAT_DONOR_HEADERS)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/pat -I$(SOURCE)/../../common/linux/include -c "$<" -o "$@"
$(BUILD)/pat-test: $(SOURCE)/tests/pat.c $(PAT_DONOR_HEADERS) $(BUILD)/pat-donor.o $(BUILD)/pat-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/pat -I$(SOURCE)/../../common/linux/include "$<" $(BUILD)/pat-donor.o $(BUILD)/pat-host.o -o "$@"
.PHONY: test-pat
test-pat: $(BUILD)/pat-test
	$(BUILD)/pat-test

$(BUILD)/pat/current-pat-wrapper.inc: $(SOURCE)/../xe/xe_pat.c | $(BUILD)
	mkdir -p "$(BUILD)/pat"
	sed -n '/^#define XE_PAT_SELECT_WARN(/,/^void xe_pat_init(/{ /^void xe_pat_init(/d; p; }' "$<" > "$@"

# Unmodified original OOB generator and complete output; select its actual reset
# entry for a compile-time exclusion proof, not a handwritten native WA table.
$(BUILD)/guc-reset/xe_gen_wa_oob: $(SOURCE)/../xe/xe_gen_wa_oob.c | $(BUILD)
	mkdir -p "$(BUILD)/guc-reset"
	$(HOST_CC) -std=gnu11 -O2 -Wall -Wextra -Werror "$<" -o "$@"
$(BUILD)/guc-reset/xe_wa_oob.c: $(SOURCE)/../xe/xe_wa_oob.rules $(BUILD)/guc-reset/xe_gen_wa_oob
	$(BUILD)/guc-reset/xe_gen_wa_oob "$<" "$(BUILD)/guc-reset/xe_wa_oob.c" "$(BUILD)/guc-reset/xe_wa_oob.h"
$(BUILD)/guc-reset/guc_reset_wa.inc: $(BUILD)/guc-reset/xe_wa_oob.c
	sed -n '/^{ XE_RTP_NAME("14025883347"),/,/) },/p' "$<" > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
GUC_RESET_HEADERS := $(SOURCE)/guc_reset.h $(SOURCE)/activation.h $(SOURCE)/../xe/xe_guc_reset_core.h \
    $(SOURCE)/../xe/xe_mmio_poll.h $(SOURCE)/../xe/xe_scalar_types.h $(SOURCE)/../xe/xe_gt_type.h \
    $(SOURCE)/../xe/xe_force_wake_domain_types.h $(SOURCE)/../xe/regs/xe_gt_regs.h \
    $(SOURCE)/../xe/regs/xe_guc_regs.h $(SOURCE)/../xe/abi/guc_errors_abi.h \
    $(BUILD)/guc-reset/guc_reset_wa.inc
$(BUILD)/guc_reset.o: $(SOURCE)/guc_reset.c $(GUC_RESET_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(BUILD)/guc-reset -MD -MP -c "$<" -o "$@"
$(BUILD)/guc_reset-host.o: $(SOURCE)/guc_reset.c $(GUC_RESET_HEADERS) | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/guc-reset -MD -MP -c "$<" -o "$@"
.PHONY: guc-reset host-guc-reset
guc-reset: $(BUILD)/guc_reset.o
host-guc-reset: $(BUILD)/guc_reset-host.o
-include $(BUILD)/guc_reset.d $(BUILD)/guc_reset-host.d

GUC_RESET_DONOR_BLOB ?= 4023700ff2a9678f6168d776b49c892adc8a58e5
$(BUILD)/guc-reset/guc-reset-donor.inc: | $(BUILD)
	mkdir -p "$(BUILD)/guc-reset"
	git -C "$(SOURCE)" show $(GUC_RESET_DONOR_BLOB) | sed -n '/^static void guc_prevent_fw_dma_failure_on_reset(/,/^static void guc_prepare_xfer(/{ /^static void guc_prepare_xfer(/d; p; }' > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
$(BUILD)/guc-reset/guc-reset-linux.inc: $(SOURCE)/../xe/xe_guc.c | $(BUILD)
	mkdir -p "$(BUILD)/guc-reset"
	sed -n '/^#define XE_GUC_RESET_CONTEXT /,/^static void guc_prepare_xfer(/{ /^static void guc_prepare_xfer(/d; p; }' "$<" > "$@.tmp"
	test -s "$@.tmp"
	mv "$@.tmp" "$@"
GUC_RESET_TEST_HEADERS := $(SOURCE)/tests/guc_reset_model.h $(SOURCE)/tests/guc_reset_bind.h $(GUC_RESET_HEADERS)
$(BUILD)/guc-reset-donor.o: $(SOURCE)/tests/guc_reset_donor.c $(GUC_RESET_TEST_HEADERS) $(BUILD)/guc-reset/guc-reset-donor.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/guc-reset -c "$<" -o "$@"
$(BUILD)/guc-reset-linux.o: $(SOURCE)/tests/guc_reset_linux.c $(GUC_RESET_TEST_HEADERS) $(BUILD)/guc-reset/guc-reset-linux.inc
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/guc-reset -c "$<" -o "$@"
$(BUILD)/guc-reset-test: $(SOURCE)/tests/guc_reset.c $(GUC_RESET_TEST_HEADERS) $(BUILD)/guc-reset-donor.o \
    $(BUILD)/guc-reset-linux.o $(BUILD)/guc_reset-host.o $(BUILD)/activation-host.o \
    $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o
	$(HOST_CC) $(HOST_CFLAGS) $(SANITIZE) -I$(BUILD)/guc-reset "$<" \
	    $(BUILD)/guc-reset-donor.o $(BUILD)/guc-reset-linux.o $(BUILD)/guc_reset-host.o \
	    $(BUILD)/activation-host.o $(BUILD)/wopcm-host.o $(BUILD)/firmware-host.o $(BUILD)/pat-host.o -o "$@"
.PHONY: test-guc-reset
test-guc-reset: $(BUILD)/guc-reset-test
	$(BUILD)/guc-reset-test

# Focused retained red-black tree pointer-width proof; no GPU activation.
include $(SOURCE)/tests/rbtree.mk
include $(SOURCE)/tests/drm_mm.mk
