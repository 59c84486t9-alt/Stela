#!/usr/bin/env python3
"""Execute unchanged Linux hop deactivation with deterministic register/clock stubs.

Usage: thunderbolt_hop_oracle.py PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Generated C/binary/trace stay ignored. This compares hop register effects, not
hardware timing, tunnel allocation, topology metadata or endpoint DMA teardown.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
    "path.c": "06454cb34668f0d0de261de82e9ecd0e91fa04ce8ad24e7e4e0a99fbbf230aa0",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)
text = texts["path.c"]
match = re.search(r"^static int __tb_path_deactivate_hop\([^;{}]*?\)\n\{", text, re.M)
assert match
at, depth = match.end(), 1
while depth:
    depth += (text[at] == "{") - (text[at] == "}")
    at += 1
body = text[match.start():at]
structure = re.search(r"struct tb_regs_hop \{.*?\n\} __packed;", texts["tb_regs.h"], re.S).group()
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#define TB_CFG_HOPS 0
'''
stubs = r'''
struct tb_switch { bool usb4; };
struct tb_port { struct tb_switch *sw; bool lane; unsigned reads,writes; struct tb_regs_hop hop; u32 log[2][2]; };
static ktime_t now;
static ktime_t ktime_get(void) { return now; }
static ktime_t ktime_add_ms(ktime_t time,unsigned ms) { return time+ms; }
static bool ktime_before(ktime_t a,ktime_t b) { return a<b; }
static void usleep_range(unsigned a,unsigned b) { (void)a;(void)b; now++; }
static bool tb_port_is_null(const struct tb_port *p) { return p->lane; }
static bool tb_switch_is_usb4(const struct tb_switch *sw) { return sw->usb4; }
static int tb_port_read(struct tb_port *p,void *out,int space,int offset,int words) {
    if(space!=0 || offset!=16 || words!=2) return -EINVAL;
    if(p->reads++>=2) p->hop.pending=0;
    memcpy(out,&p->hop,8); return 0;
}
static int tb_port_write(struct tb_port *p,const void *in,int space,int offset,int words) {
    if(space!=0 || offset!=16 || words!=2 || p->writes>=2) return -EINVAL;
    memcpy(p->log[p->writes++],in,8);memcpy(&p->hop,in,8);return 0;
}
static u32 random_word(u32 *state) {u32 x=*state;x^=x<<13;x^=x>>17;x^=x<<5;return *state=x;}
'''
main = r'''
int main(void) {
    u32 state=0x14ab27cd;
    for(unsigned usb4=0;usb4<2;usb4++) for(unsigned lane=0;lane<2;lane++) for(unsigned clear=0;clear<2;clear++) for(unsigned n=0;n<1024;n++) {
        u32 raw[2]={random_word(&state)|0x80000000U,random_word(&state)|0x10000000U};
        struct tb_switch sw={.usb4=usb4};struct tb_port p={.sw=&sw,.lane=lane};memcpy(&p.hop,raw,8);now=0;
        if(__tb_path_deactivate_hop(&p,8,clear)) return 2;
        u32 final[2];memcpy(final,&p.hop,8);
        printf("H %u %u %u %u %u %u %u %u %u %u %u %u\n",usb4,lane,clear,raw[0],raw[1],final[0],final[1],p.writes,p.log[0][0],p.log[0][1],p.log[1][0],p.log[1][1]);
    }
    return 0;
}
'''
unit = out / "linux-thunderbolt-hop.c"
unit.write_text(prelude + structure + stubs + body + main)
exe = out / "linux-thunderbolt-hop"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
trace = out / "trace.txt"
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
