#!/usr/bin/env python3
"""Compare actual pinned Linux router/adapter bitfields and route/version helpers.

Usage: thunderbolt_topology_oracle.py HASH_PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Generated C, binaries and traces remain ignored. This is a layout/helper oracle,
not a Linux device model, capability executor or connection-manager oracle.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
    "tb.h": "eb885b01adee9ec24cf5cdc4c3aecf5ecd7dc6b5a84c9f300c42af6f9c41db7c",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)

def structure(name):
    match = re.search(r"(?:struct|enum) " + name + r" \{.*?\n\}(?: __packed)?;", texts["tb_regs.h"], re.S)
    assert match, name
    return match.group()

def function(name):
    text = texts["tb.h"]
    match = re.search(r"^static inline[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]

prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define __packed __attribute__((packed))
#define USB4_VERSION_MAJOR_MASK 0xe0U
#define FIELD_GET(mask,value) (((value)&(mask)) >> __builtin_ctz(mask))
'''
main = r'''
static u32 random_word(u32 *state) { u32 x=*state; x^=x<<13; x^=x>>17; x^=x<<5; return *state=x; }
int main(void) {
    u32 state=0x19bd32aa;
    for(unsigned n=0;n<4096;n++) {
        u32 raw[13]; for(unsigned i=0;i<13;i++) raw[i]=random_word(&state);
        struct tb_switch sw; struct tb_regs_port_header port;
        memcpy(&sw.config,raw,20); memcpy(&port,raw+5,32);
        printf("H"); for(unsigned i=0;i<13;i++) printf(" %u",raw[i]);
        printf(" %u %u %u %u %u %u %u %llu %u %u",sw.config.vendor_id,sw.config.device_id,sw.config.first_cap_offset,sw.config.upstream_port_number,sw.config.max_port_number,sw.config.depth,sw.config.revision,(unsigned long long)tb_route(&sw),sw.config.enabled,usb4_switch_version(&sw));
        printf(" %u %u %u %u %u %u %u\n",port.type,port.first_cap_offset,port.port_number,port.max_in_hop_id,port.max_out_hop_id,port.nfc_credits&0x3ff,(port.nfc_credits>>20)&0x3ff);
    }
    return 0;
}
'''
unit = out / "linux-thunderbolt-topology.c"
unit.write_text(prelude + "\n".join(structure(name) for name in ["tb_regs_switch_header", "tb_port_type", "tb_regs_port_header"]) + "\nstruct tb_switch { struct tb_regs_switch_header config; };\n" + function("tb_route") + function("usb4_switch_version") + main)
exe = out / "linux-thunderbolt-topology"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
trace = out / "trace.txt"
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
