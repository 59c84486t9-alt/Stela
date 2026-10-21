# SPDX-License-Identifier: MIT
# Use the exact hosted Mesa build produced by build/amd.rs, never a GPU device.
ifndef MESA_BUILD
$(error Set MESA_BUILD to the absolute mesa-amd-commands build directory)
endif
TEST_SOURCE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
MESA_SOURCE := $(abspath $(TEST_SOURCE)/../../common/mesa)
TEST_OUT ?= $(MESA_BUILD)/stela-rust-tests
RUSTC ?= rustc
CFLAGS ?= -O2 -g

.PHONY: test

test: $(TEST_OUT)/facade
	"$(TEST_OUT)/facade"

$(TEST_OUT):
	mkdir -p "$@"

$(TEST_OUT)/commands_fixture.o: $(TEST_SOURCE)/commands_fixture.c | $(TEST_OUT)
	$(CC) $(CFLAGS) -std=c11 -Wall -Wextra -Werror \
	  -I"$(MESA_SOURCE)/include" -I"$(MESA_SOURCE)/src" \
	  -I"$(MESA_BUILD)/src" -I"$(MESA_BUILD)/src/amd/common" -c "$<" -o "$@"

$(TEST_OUT)/facade: $(TEST_SOURCE)/facade.rs $(TEST_SOURCE)/../../amd.rs \
  $(TEST_OUT)/commands_fixture.o $(MESA_BUILD)/src/stela/libstela_amd_commands.a \
  $(MESA_BUILD)/src/amd/common/libamd_command_support.a
	$(RUSTC) $(RUSTFLAGS) --edition=2024 --test "$<" --crate-name stela_amd_facade -D warnings \
	  -L "native=$(MESA_BUILD)/src/stela" -L "native=$(MESA_BUILD)/src/amd/common" \
	  -l static=stela_amd_commands -l static=amd_command_support \
	  -C "link-arg=$(TEST_OUT)/commands_fixture.o" -o "$@"
