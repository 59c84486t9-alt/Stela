#!/usr/bin/env python3
"""Run unchanged Linux TB control TX, header and hotplug ACK helpers.

Usage: thunderbolt_config_oracle.py HASH_PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Generated source/binary/trace stay ignored. Requires an x86 host with SSE4.2;
CRC32C uses host hardware rather than reproducing the Rust software algorithm.
Kernel allocation/ring/logging are capture stubs. This covers actual encoded
control frames, not physical NHI operation or connection management.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
hashes = {
    "ctl.c": "82454a95f67942bbe6a3990cb9f3f54a4e5d8229020f4c95d4277f2ae1aee808",
    "ctl.h": "eb6155d43113ff27744a7f4f91e984fbfe5227bd073f466e122cc4315b8e33dd",
    "tb_msgs.h": "553b546d7945f268c08659863813e897bf12e7ebd89b6da9fb9805fcc067b602",
    "include_linux_thunderbolt.h": "77314f7a9762cbd0296024a1cfe7a1fc54c9ef2568db0229ad614758e1cd22eb",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)


def function(filename, name):
    text = texts[filename]
    match = re.search(r"^(?:static |int )[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2017-2018 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <nmmintrin.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __be32;
#define __packed __attribute__((packed))
#define WARN_ON(v) do { if(v) abort(); } while(0)
#define TB_FRAME_SIZE 256
#define tb_ctl_WARN(...) ((void)0)
#define tb_ctl_dbg(...) ((void)0)
#define trace_tb_tx(...) ((void)0)
static u32 cpu_to_be32(u32 v) { return __builtin_bswap32(v); }
static u32 crc32c(u32 crc, const void *data, size_t bytes) {
    const u8 *p=data; while(bytes--) crc=_mm_crc32_u8(crc,*p++); return crc;
}
static void cpu_to_be32_array(void *out, const void *in, size_t n) {
    while(n--) { u32 v; memcpy(&v,in,4); v=cpu_to_be32(v); memcpy(out,&v,4); in+=4; out+=4; }
}
'''
msgs = texts["tb_msgs.h"]
msgs = msgs[msgs.index("enum tb_cfg_space {"):msgs.index("/* ICM messages */")]
pkgtypes = re.search(r"enum tb_cfg_pkg_type \{.*?\n\};", texts["include_linux_thunderbolt.h"], re.S).group()
stubs = r'''
struct tb_ring {};
struct ring_frame {
    unsigned size,sof,eof;
    void (*callback)(struct tb_ring *,struct ring_frame *,bool);
};
struct tb_ctl { struct tb_ring *tx; int index; };
struct ctl_pkg { struct tb_ctl *ctl; void *buffer; struct ring_frame frame; };
static struct ctl_pkg capture;
static struct ctl_pkg *tb_ctl_pkg_alloc(struct tb_ctl *ctl) {
    static unsigned char buffer[256]; memset(&capture,0,sizeof(capture));
    memset(buffer,0,sizeof(buffer)); capture.ctl=ctl; capture.buffer=buffer; return &capture;
}
static void tb_ctl_pkg_free(struct ctl_pkg *p) { (void)p; }
static void tb_ctl_tx_callback(struct tb_ring *r,struct ring_frame *f,bool c) { (void)r;(void)f;(void)c; }
static int tb_ring_tx(struct tb_ring *r, struct ring_frame *f) { (void)r;(void)f; return 0; }
static void print_frame(void) {
    printf(" %u %u %u ",capture.frame.eof,capture.frame.sof,capture.frame.size);
    for(unsigned j=0;j<capture.frame.size;j++) printf("%02x",((u8*)capture.buffer)[j]);
    puts("");
}
'''
main = r'''
int main(void) {
    u64 routes[]={0,1,0x010203040506ULL,0xffffffffULL,0x100000000ULL,0x3fffffffffffffULL,0x3fffff00000000ULL};
    unsigned ports[]={0,1,31,63}, counts[]={1,2,7,31,59,60};
    struct tb_ctl ctl={0};
    for(unsigned r=0;r<7;r++) for(unsigned s=0;s<4;s++) for(unsigned p=0;p<4;p++)
    for(unsigned seq=0;seq<4;seq++) for(unsigned n=0;n<6;n++) for(unsigned w=0;w<2;w++) {
        unsigned count=counts[n],offset=(r*701+s*109+ports[p]*31+seq*3)% (8193-count);
        struct cfg_write_pkg packet={.header=tb_cfg_make_header(routes[r]),.addr={.offset=offset,.length=count,.port=ports[p],.space=s,.seq=seq}};
        for(unsigned j=0;j<count;j++) packet.data[j]=0x10203040U ^ (j*0x01010101U) ^ (r<<28) ^ (ports[p]<<16) ^ (seq<<8) ^ s;
        printf("C %llu %u %u %u %u %u %u",(unsigned long long)routes[r],s,ports[p],offset,count,seq,w);
        if(tb_ctl_tx(&ctl,&packet,w ? 12+count*4 : 12,w?TB_CFG_PKG_WRITE:TB_CFG_PKG_READ)) abort();
        print_frame();
    }
    for(unsigned r=0;r<7;r++) for(unsigned p=0;p<4;p++) for(unsigned u=0;u<2;u++) {
        printf("P %llu %u %u",(unsigned long long)routes[r],ports[p],u);
        if(tb_cfg_ack_plug(&ctl,routes[r],ports[p],u)) abort();
        print_frame();
    }
    return 0;
}
'''
unit = out / "linux-thunderbolt-config.c"
unit.write_text(prelude + pkgtypes + msgs + stubs + "\n" + "\n".join([
    function("ctl.h", "tb_cfg_get_route"), function("ctl.h", "tb_cfg_make_header"),
    function("ctl.c", "tb_crc"), function("ctl.c", "tb_ctl_tx"), function("ctl.c", "tb_cfg_ack_plug"),
]) + main)
exe = out / "linux-thunderbolt-config"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-msse4.2", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
trace = out / "trace.txt"
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
