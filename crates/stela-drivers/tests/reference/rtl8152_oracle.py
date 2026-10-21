#!/usr/bin/env python3
"""Execute unchanged pinned Linux OCP helpers; keep generated C/trace ignored.

Usage: python3 rtl8152_oracle.py R8152_C R8152_H OUTPUT_DIRECTORY
Then STELA_RTL8152_ORACLE=absolute/trace.txt cargo test -p stela-drivers \
    unchanged_linux_ocp -- --ignored
The generated translation unit retains the donor GPL/copyright header. Neither
source files nor generated executables are redistributed by this script.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, header, out = map(Path, sys.argv[1:])
assert hashlib.sha256(source.read_bytes()).hexdigest() == "9d766f203c7fdabe6449e8dd2b9e5dd4fccfa20a62aa5dbf00d64c0c475c5a9f"
text = source.read_text()
# Header is checked separately from the file it complements.
assert hashlib.sha256(header.read_bytes()).hexdigest() == "2d171ccd1779082dfcb4e2663e0127844acd1d67b0358ef1ed2eadb6510f06e0"
out.mkdir(parents=True, exist_ok=True)


def function(name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at = match.end()
    depth = 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


names = ["generic_ocp_read", "generic_ocp_write", "ocp_read_dword", "ocp_write_dword", "ocp_read_word", "ocp_write_word", "ocp_read_byte", "ocp_write_byte", "ocp_reg_read", "ocp_reg_write"]
defines = "\n".join(line for line in header.read_text().splitlines() if line.startswith("#define ") or line.startswith("#define\t"))
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
// Copyright (c) 2020 Realtek Semiconductor Corp. All rights reserved.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint32_t __le32;
#define __le32_to_cpu(x) (x)
#define __cpu_to_le32(x) (x)
#define RTL8152_INACCESSIBLE 0
#define PLA_OCP_GPHY_BASE 0xe86c
#define test_bit(bit, flags) 0
struct r8152 { int flags; u16 ocp_base; };
static u8 bytes[2][65536];
static void rtl_set_unplug(struct r8152 *tp) { (void)tp; }
static int request(u8 direction, u16 address, u16 index, u16 size, void *data) {
    printf("%02x05%02x%02x%02x%02x%02x%02x:", direction, address & 255, address >> 8,
           index & 255, index >> 8, size & 255, size >> 8);
    if (direction == 0x40) for (int i=0; i<size; i++) printf("%02x", ((u8 *)data)[i]);
    puts("");
    int bank = !!(index & 0x100);
    for (int i=0; i<size; i++) {
        if (direction == 0xc0) ((u8 *)data)[i] = bytes[bank][address+i];
        else if (index & (1 << (i % 4))) bytes[bank][address+i] = ((u8 *)data)[i];
    }
    return size;
}
static int get_registers(struct r8152 *tp, u16 a, u16 i, u16 s, void *d) { (void)tp; return request(0xc0,a,i,s,d); }
static int set_registers(struct r8152 *tp, u16 a, u16 i, u16 s, void *d) { (void)tp; return request(0x40,a,i,s,d); }
'''
main = r'''
int main(void) {
    struct r8152 tp = {0};
    for (int bank=0; bank<2; bank++) for (int a=0; a<65536; a++) bytes[bank][a] = (a*13 + bank*71) ^ (a >> 8);
    for (int bank=0; bank<2; bank++) {
        for (int a=0xc000; a<0xc020; a++) { ocp_write_byte(&tp,bank*0x100,a,a*7); ocp_read_byte(&tp,bank*0x100,a); }
        for (int a=0xe000; a<0xe020; a+=2) { ocp_write_word(&tp,bank*0x100,a,a*11); ocp_read_word(&tp,bank*0x100,a); }
        for (int a=0xd000; a<0xd020; a+=4) { ocp_write_dword(&tp,bank*0x100,a,a*0x1234); ocp_read_dword(&tp,bank*0x100,a); }
    }
    for (int a=0x2010; a<0xf000; a+=0x102) { ocp_reg_write(&tp,a,a*7); ocp_reg_read(&tp,a); }
    return 0;
}
'''
# Function bodies are inserted byte-for-byte, never rewritten to match Rust.
unit = out / "linux-ocp.c"
unit.write_text(prelude + "\n" + defines + "\n" + "\n".join(function(n) for n in names) + main)
exe = out / "linux-ocp"
subprocess.run(["cc", "-std=gnu11", "-O2", str(unit), "-o", str(exe)], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True)
print(out / "trace.txt")
