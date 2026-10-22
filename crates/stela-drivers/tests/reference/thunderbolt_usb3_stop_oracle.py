#!/usr/bin/env python3
"""Unchanged Linux root USB3 activation→optional release-unused→normal endpoint/path stop.

Usage: thunderbolt_usb3_stop_oracle.py PINNED_SOURCE_DIRECTORY FRESH_OUTPUT
Protected native topology/allocations/permission and event delivery are captures.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
    "usb4.c": "bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5",
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
    text = texts[filename]
    match = re.search(r"^(?:static )?(?:inline )?(?:int|void|bool|u32|unsigned int)\s+" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


def declaration(filename, name, packed=False):
    return re.search(re.escape(name) + r" \{.*?\n\}" + (r" __packed;" if packed else ";"), texts[filename], re.S).group()


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#ifndef __counted_by
#define __counted_by(x)
#endif
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define TB_CFG_HOPS 0
#define TB_CFG_PORT 1
#define USB4_PORT_DELAY 50
#define ADP_CS_4 4
#define ADP_CS_4_NFC_BUFFERS_MASK 1023U
#define MEGA 1000000UL
#define DIV_ROUND_CLOSEST(n,d) (((n)+(d)/2)/(d))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define max(a,b) ((a)>(b)?(a):(b))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define WARN_ON(x) ((x)?(abort(),1):0)
#define tb_port_dbg(...) ((void)0)
#define tb_port_warn(...) ((void)0)
#define tb_WARN(...) ((void)0)
#define tb_dbg(...) ((void)0)
#define tb_warn(...) ((void)0)
#define tb_tunnel_dbg(...) ((void)0)
#define tb_tunnel_warn(...) ((void)0)
#define TB_USB3_PRIORITY 3
#define TB_USB3_WEIGHT 2
#define TB_TUNNEL_ACTIVATING 1
#define TB_TUNNEL_ACTIVE 2
#define TB_TUNNEL_INACTIVE 0
#define TB_TUNNEL_ACTIVATED 1
#define TB_TUNNEL_DEACTIVATED 0
#define tb_path_for_each_hop(path,hop) for((hop)=(path)->hops;(hop)<&(path)->hops[(path)->path_length];(hop)++)
struct tb;struct tb_port;
'''
macros = "\n".join(line for line in texts["tb_regs.h"].splitlines() if line.startswith("#define ADP_USB3_CS_"))
stubs = r'''
struct tb_switch {unsigned route;bool credit_allocation,is_unplugged;unsigned max_usb3_credits;};
struct tb_port {struct tb_switch *sw;unsigned port,cap_adap;bool lane,bonded,disabled;unsigned reads;struct {u32 nfc_credits;}config;struct tb_regs_hop hop;u32 regs[4];bool transition,target;unsigned polls;};
struct tb_tunnel {struct tb*tb;unsigned type;int state,npaths,allocated_up,allocated_down;struct tb_port *src_port,*dst_port;struct tb_path *paths[2];int(*pre_activate)(struct tb_tunnel*);int(*activate)(struct tb_tunnel*,bool);void(*post_deactivate)(struct tb_tunnel*);};
static ktime_t now;static unsigned nw,events;static bool clear_valid;
static struct{unsigned route,port,space,offset,count;u32 words[2];}writes[32];
static bool tb_port_is_null(const struct tb_port*p){return p->lane;}
static bool tb_port_is_usb3_down(const struct tb_port*p){return !p->lane&&!p->sw->route;}
static bool tb_port_is_usb3_up(const struct tb_port*p){return !p->lane&&p->sw->route;}
static bool tb_switch_is_usb4(const struct tb_switch*sw){(void)sw;return true;}
static unsigned tb_route(const struct tb_switch*sw){return sw->route;}
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void fsleep(unsigned us){(void)us;now++;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static int tb_port_clear_counter(struct tb_port*p,int n){(void)p;(void)n;abort();}
static void tb_tunnel_event(struct tb*t,unsigned event,unsigned type,struct tb_port*s,struct tb_port*d){(void)t;(void)type;(void)s;(void)d;if(event!=(events==0?TB_TUNNEL_ACTIVATED:TB_TUNNEL_DEACTIVATED))abort();events++;}
static int tb_port_read(struct tb_port*p,void*out,int space,int offset,int words){
 if(space==TB_CFG_HOPS){if(words!=2||(offset!=16&&offset!=62))abort();if(p->disabled&&++p->reads>=2)p->hop.pending=0;memcpy(out,&p->hop,8);return 0;}
 if(space!=TB_CFG_PORT||words!=1||offset<0x50||offset>0x53)abort();unsigned i=offset-p->cap_adap;
 if(i==1&&p->transition&&++p->polls>=2){p->regs[1]=(p->regs[1]&~ADP_USB3_CS_1_HCA)|(p->target?ADP_USB3_CS_1_HCA:0);p->transition=false;}*(u32*)out=p->regs[i];return 0;
}
static int tb_port_write(struct tb_port*p,const void*in,int space,int offset,int words){
 if(nw>=32||words<1||words>2)abort();writes[nw].route=p->sw->route;writes[nw].port=p->port;writes[nw].space=space;writes[nw].offset=offset;writes[nw].count=words;memcpy(writes[nw++].words,in,words*4);
 if(space==TB_CFG_HOPS){if(words!=2)abort();memcpy(&p->hop,in,8);p->disabled=!p->hop.enable;if(p->disabled)p->reads=0;return 0;}
 if(space!=TB_CFG_PORT||words!=1||offset<0x50||offset>0x53)abort();u32 value=*(const u32*)in;unsigned i=offset-p->cap_adap;
 if(i==2&&((p->regs[2]^value)&ADP_USB3_CS_2_CMR)){p->transition=true;p->target=value&ADP_USB3_CS_2_CMR;p->polls=0;}p->regs[i]=(i==0&&clear_valid)?value&~ADP_USB3_CS_0_V:value;return 0;
}
'''
main = r'''
int main(void){
 static const int requests[]={0,1,1023,8191,10000,16384,18000,20000};
 for(unsigned mode=0;mode<2;mode++)for(unsigned release=0;release<2;release++)for(unsigned seed=0;seed<32;seed++){
  struct tb_switch sw[2]={{.route=0,.credit_allocation=mode,.max_usb3_credits=17+seed%15},{.route=2,.credit_allocation=mode,.max_usb3_credits=17+seed%15}};
  struct tb_port ports[4]={{.sw=&sw[0],.port=6,.cap_adap=0x50,.bonded=true},{.sw=&sw[0],.port=2,.lane=true,.bonded=true},{.sw=&sw[1],.port=1,.lane=true,.bonded=true},{.sw=&sw[1],.port=4,.cap_adap=0x50,.bonded=true}};
  struct tb_path*paths[2];
  for(unsigned d=0;d<2;d++){paths[d]=calloc(1,sizeof(*paths[d])+2*sizeof(paths[d]->hops[0]));if(!paths[d])abort();paths[d]->path_length=2;
   for(unsigned i=0;i<2;i++){struct tb_port*in=&ports[d?(i?1:3):(i?2:0)];struct tb_port*out=&ports[d?(i?0:2):(i?3:1)];unsigned s=seed+d;unsigned stale=1;u32 raw[2]={((0x12345678U^(s*0x104001U)^(i*0x13579U))&~0x80000000U)|(stale?0x80000000U:0),(0xabcdef12U^(s*0x104101U)^(i*0x13579U))|(stale?0x10000000U:0)};memcpy(&in->hop,raw,8);paths[d]->hops[i]=(struct tb_path_hop){.in_port=in,.out_port=out,.in_hop_index=i?31:8,.next_hop_index=i?8:31,.in_counter_index=-1};}tb_usb3_init_path(paths[d]);
  }
  ports[0].regs[1]=(seed%256)|(((seed*3)%256)<<12);ports[0].regs[2]=(0x12345678U^(seed*0x10201U))&~ADP_USB3_CS_2_CMR;ports[0].regs[3]=(seed%4)|0x30000000U;
  struct tb_tunnel t={.npaths=2,.allocated_up=requests[seed%8],.allocated_down=requests[(seed/8)%8],.src_port=&ports[0],.dst_port=&ports[3],.paths={paths[0],paths[1]},.pre_activate=tb_usb3_pre_activate,.activate=tb_usb3_activate};
  nw=0;now=0;events=0;clear_valid=seed&1;if(tb_tunnel_activate(&t)||t.state!=TB_TUNNEL_ACTIVE||events!=1)abort();
  if(release){ports[0].regs[1]=(seed&1?1023:0)|((seed%3==0?1023:255)<<12);if(tb_usb3_release_unused_bandwidth(&t))abort();}
  for(unsigned d=0;d<2;d++)for(unsigned i=0;i<2;i++)paths[d]->hops[i].in_port->hop.pending=1;
  tb_tunnel_deactivate(&t);if(t.state!=TB_TUNNEL_INACTIVE||events!=2)abort();
  printf("S %u %u %u %u",mode,release,seed,nw);for(unsigned i=0;i<nw;i++){printf(" %u %u %u %u %u",writes[i].route,writes[i].port,writes[i].space,writes[i].offset,writes[i].count);for(unsigned j=0;j<writes[i].count;j++)printf(" %u",writes[i].words[j]);}printf(" %u %u %u %u",ports[0].regs[0],ports[3].regs[0],t.allocated_up,t.allocated_down);for(unsigned d=0;d<2;d++)for(unsigned i=0;i<2;i++){u32 raw[2];memcpy(raw,&paths[d]->hops[i].in_port->hop,8);printf(" %u %u",raw[0],raw[1]);}printf("\n");free(paths[0]);free(paths[1]);
 }
}
'''
functions = [
    *[("usb4.c", name) for name in ["usb4_port_wait_for_bit", "usb4_usb3_port_cm_request", "usb4_usb3_port_set_cm_request", "usb4_usb3_port_clear_cm_request", "usb3_bw_to_mbps", "mbps_to_usb3_bw", "usb4_usb3_port_read_consumed_bandwidth", "usb4_usb3_port_write_allocated_bandwidth", "usb4_usb3_port_allocate_bandwidth", "usb4_usb3_port_release_bandwidth"]],
    ("tb.h", "tb_port_use_credit_allocation"), ("switch.c", "tb_port_add_nfc_credits"),
    *[("path.c", name) for name in ["tb_dump_hop", "__tb_path_deallocate_nfc", "__tb_path_deactivate_hop", "__tb_path_deactivate_hops", "tb_path_activate", "tb_path_deactivate"]],
    ("tunnel.c", "tb_usb3_init_credits"), ("tunnel.c", "tb_usb3_init_path"),
    ("switch.c", "tb_usb3_port_enable"), ("tunnel.c", "tb_usb3_pre_activate"), ("tunnel.c", "tb_usb3_release_unused_bandwidth"),
    *[("tunnel.c", name) for name in ["tb_usb3_activate", "tb_tunnel_set_active", "tb_tunnel_deactivate", "tb_tunnel_activate"]],
]
unit = out / "linux-usb3-stop.c"
unit.write_text("\n".join([
    prelude, macros, declaration("tb_regs.h", "struct tb_regs_hop", True),
    declaration("tb.h", "struct tb_path_hop"), declaration("tb.h", "enum tb_path_port"),
    re.search(r"struct tb_path \{.*?\n\};", texts["tb.h"], re.S).group(), stubs,
    *[function(file, name) for file, name in functions], main,
]))
exe = out / "linux-usb3-stop"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{len(functions)} unchanged helpers; {trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
