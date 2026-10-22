#!/usr/bin/env python3
"""Pinned unchanged Linux two-hop USB3 path activation with real hop bitfields.

Usage: thunderbolt_path_oracle.py PINNED_SOURCE_DIRECTORY FRESH_OUTPUT_DIRECTORY
Captures native fixture reservations, not a production topology/permission,
HopID/credit allocator, bandwidth provider or complete USB3 tunnel.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
hashes = {
    "path.c": "06454cb34668f0d0de261de82e9ecd0e91fa04ce8ad24e7e4e0a99fbbf230aa0",
    "tunnel.c": "34f0171ebc71508a8aa0b932c913c5a055a4f0deb7fc181234f4712fc6d2d96d",
    "switch.c": "cb3e11c220daa808183d072415e1904ea1b5bcf44ad37bb9db869e36a4b65c66",
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
    "tb.h": "eb885b01adee9ec24cf5cdc4c3aecf5ecd7dc6b5a84c9f300c42af6f9c41db7c",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
trace = out / "trace.txt"
if trace.exists():
    raise SystemExit("refusing to replace historical trace; select fresh output")
out.mkdir(parents=True, exist_ok=True)


def function(filename, name):
    match = re.search(r"^(?:static )?(?:inline )?(?:void|int|bool)\s+" + name + r"\([^;{}]*?\)\n\{", texts[filename], re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (texts[filename][at] == "{") - (texts[filename][at] == "}")
        at += 1
    return texts[filename][match.start():at]


def declaration(filename, name, packed=False):
    return re.search(re.escape(name) + r" \{.*?\n\}" + (r" __packed;" if packed else ";"), texts[filename], re.S).group()


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#ifndef __counted_by
#define __counted_by(x)
#endif
#define TB_CFG_HOPS 0
#define TB_CFG_PORT 1
#define ADP_CS_4 4
#define ADP_CS_4_NFC_BUFFERS_MASK 1023U
#define TB_USB3_PRIORITY 3
#define TB_USB3_WEIGHT 2
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define tb_port_dbg(...) ((void)0)
#define tb_port_warn(...) ((void)0)
#define tb_WARN(...) ((void)0)
#define tb_dbg(...) ((void)0)
#define tb_warn(...) ((void)0)
#define tb_path_for_each_hop(path,hop) for((hop)=(path)->hops;(hop)<&(path)->hops[(path)->path_length];(hop)++)
struct tb;struct tb_port;
'''
stubs = r'''
struct tb_switch {bool credit_allocation,is_unplugged;unsigned max_usb3_credits;};
struct tb_port {struct tb_switch *sw;unsigned port,side;bool lane,bonded,disabled;unsigned reads;struct {u32 nfc_credits;}config;struct tb_regs_hop hop;};
static ktime_t now;
static unsigned nw;
static struct {unsigned side,port,offset;u32 raw[2];}writes[8];
static bool tb_port_is_null(const struct tb_port*p){return p->lane;}
static bool tb_switch_is_usb4(const struct tb_switch*sw){(void)sw;return true;}
static uint64_t tb_route(const struct tb_switch*sw){(void)sw;return 0;}
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static int tb_port_clear_counter(struct tb_port*p,int n){(void)p;(void)n;abort();}
static int tb_port_read(struct tb_port*p,void*out,int space,int offset,int words){
 if(space!=TB_CFG_HOPS||words!=2||(offset!=16&&offset!=62))abort();
 if(p->disabled&&++p->reads>=2)p->hop.pending=0;
 memcpy(out,&p->hop,8);return 0;
}
static int tb_port_write(struct tb_port*p,const void*in,int space,int offset,int words){
 if(space!=TB_CFG_HOPS||words!=2||nw>=8)abort();
 writes[nw].side=p->side;writes[nw].port=p->port;writes[nw].offset=offset;memcpy(writes[nw++].raw,in,8);
 memcpy(&p->hop,in,8);if(!p->hop.enable){p->disabled=true;p->reads=0;}return 0;
}
'''
main = r'''
int main(void){
 for(unsigned direction=0;direction<2;direction++)for(unsigned mode=0;mode<2;mode++)for(unsigned stale=0;stale<2;stale++)for(unsigned seed=0;seed<64;seed++){
  struct tb_switch sw[2]={{.credit_allocation=mode,.max_usb3_credits=17+seed%31},{.credit_allocation=mode,.max_usb3_credits=17+seed%31}};
  struct tb_port in[2]={{.sw=&sw[0],.port=direction?4:6,.side=0,.bonded=true},{.sw=&sw[1],.port=direction?2:1,.side=1,.lane=true,.bonded=true}};
  struct tb_port out[2]={{.sw=&sw[0],.port=direction?1:2,.side=0,.lane=true,.bonded=true},{.sw=&sw[1],.port=direction?6:4,.side=1,.bonded=true}};
  u32 initial[2][2];
  for(unsigned i=0;i<2;i++){initial[i][0]=((0x12345678U^(seed*0x104001U)^(i*0x13579U))&~0x80000000U)|(stale?0x80000000U:0);initial[i][1]=(0xabcdef12U^(seed*0x104101U)^(i*0x13579U))|(stale?0x10000000U:0);memcpy(&in[i].hop,initial[i],8);}
  struct tb_path *path=calloc(1,sizeof(*path)+2*sizeof(path->hops[0]));if(!path)abort();path->path_length=2;
  for(unsigned i=0;i<2;i++)path->hops[i]=(struct tb_path_hop){.in_port=&in[i],.out_port=&out[i],.in_hop_index=i?31:8,.in_counter_index=-1,.next_hop_index=i?8:31};
  tb_usb3_init_path(path);now=0;nw=0;if(tb_path_activate(path)||!path->activated)abort();
  printf("P %u %u %u %u",direction,mode,stale,seed);for(unsigned i=0;i<2;i++)printf(" %u %u",initial[i][0],initial[i][1]);
  printf(" %u",nw);for(unsigned i=0;i<nw;i++)printf(" %u %u %u %u %u",writes[i].side,writes[i].port,writes[i].offset,writes[i].raw[0],writes[i].raw[1]);
  u32 final[2];for(unsigned i=0;i<2;i++){memcpy(final,&in[i].hop,8);printf(" %u %u",final[0],final[1]);}puts("");free(path);
 }
}
'''
functions = [
    ("tb.h", "tb_port_use_credit_allocation"),
    ("switch.c", "tb_port_add_nfc_credits"),
    ("path.c", "tb_dump_hop"),
    ("path.c", "__tb_path_deallocate_nfc"),
    ("path.c", "__tb_path_deactivate_hop"),
    ("path.c", "__tb_path_deactivate_hops"),
    ("path.c", "tb_path_activate"),
    ("tunnel.c", "tb_usb3_init_credits"),
    ("tunnel.c", "tb_usb3_init_path"),
]
unit = out / "linux-thunderbolt-path.c"
unit.write_text("\n".join([
    prelude, declaration("tb_regs.h", "struct tb_regs_hop", True),
    declaration("tb.h", "struct tb_path_hop"), declaration("tb.h", "enum tb_path_port"),
    re.search(r"struct tb_path \{.*?\n\};", texts["tb.h"], re.S).group(), stubs,
    *[function(file, name) for file, name in functions], main,
]))
exe = out / "linux-thunderbolt-path"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{len(functions)} unchanged helpers; {trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
