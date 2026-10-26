#!/usr/bin/env python3
"""Unchanged Linux adjacent USB4v1 PCIe activation and normal stop transcript.

Usage: thunderbolt_pcie_oracle.py PINNED_THUNDERBOLT_DIRECTORY FRESH_OUTPUT
Protected topology, native policy/allocation and register effects are captures;
this executes no Linux PM, physical device or production authorization service.
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
    "tunnel.c": "386d7e4a12a71e7da48d064cb9f4d14c235e7e1ebb10b01a1e0f11ab76e565e6",
    "switch.c": "981a0e577906feba9a00d4df0546cfeea4de06a8a15e439a686e4c1dc77b6f71",
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
    "tb.h": "00cde540109b1d8ad0c0664745f5faa5e87f9e40a2c7ece93e373cc323fc6a94",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
trace = out / "trace.txt"
assert not trace.exists(), "preserve historical trace; choose a fresh output directory"
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#define __counted_by(x)
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(mask,val) (((val)&(mask))>>__builtin_ctz(mask))
#define TB_CFG_HOPS 0
#define TB_CFG_PORT 1
#define ADP_CS_4 4
#define ADP_CS_4_NFC_BUFFERS_MASK 1023U
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define min_not_zero(a,b) (!(a)?(b):!(b)?(a):min(a,b))
#define tb_port_dbg(...) ((void)0)
#define tb_port_warn(...) ((void)0)
#define tb_WARN(...) ((void)0)
#define tb_dbg(...) ((void)0)
#define tb_warn(...) ((void)0)
#define tb_tunnel_dbg(...) ((void)0)
#define tb_tunnel_warn(...) ((void)0)
#define tb_path_for_each_hop(path,hop) for((hop)=(path)->hops;(hop)<&(path)->hops[(path)->path_length];(hop)++)
#define TB_TUNNEL_ACTIVATING 1
#define TB_TUNNEL_ACTIVE 2
#define TB_TUNNEL_INACTIVE 0
#define TB_TUNNEL_ACTIVATED 1
#define TB_TUNNEL_DEACTIVATED 0
struct tb;struct tb_port;
'''
macros = "\n".join(line for line in texts["tb_regs.h"].splitlines()
                   if line.startswith(("#define ADP_PCIE_CS_", "#define USB4_VERSION_MAJOR_MASK")))
macros += "\n" + "\n".join(line for line in texts["tunnel.c"].splitlines()
                            if line.startswith(("#define TB_PCI_", "#define TB_MIN_PCIE_CREDITS", "#define TB_MIN_DMA_CREDITS")))
stubs = r'''
struct tb_switch {unsigned route;bool credit_allocation,is_unplugged;unsigned max_pcie_credits,max_usb3_credits,max_dma_credits,min_dp_aux_credits,min_dp_main_credits;struct{u32 thunderbolt_version;}config;struct tb_port *upstream;};
struct tb_port {struct tb_switch *sw;unsigned port,cap_adap,total_credits,ctl_credits;bool lane,bonded,disabled;unsigned reads;struct{u32 nfc_credits;}config;struct tb_regs_hop hop;u32 cs0;};
struct tb_tunnel {struct tb*tb;unsigned type;int state,npaths;struct tb_port *src_port,*dst_port;struct tb_path *paths[2];int(*pre_activate)(struct tb_tunnel*);int(*activate)(struct tb_tunnel*,bool);void(*post_deactivate)(struct tb_tunnel*);};
static unsigned dma_credits=14;
static bool tb_acpi_may_tunnel_usb3(void){return false;}
static bool tb_acpi_may_tunnel_pcie(void){return true;}
static bool tb_acpi_is_xdomain_allowed(void){return false;}
static bool tb_acpi_may_tunnel_dp(void){return false;}
static bool tb_port_is_null(const struct tb_port*p){return p->lane;}
static bool tb_port_is_pcie_down(const struct tb_port*p){return !p->lane&&!p->sw->route;}
static bool tb_port_is_pcie_up(const struct tb_port*p){return !p->lane&&p->sw->route;}
static struct tb_port *tb_upstream_port(const struct tb_switch *sw){return sw->upstream;}
static unsigned tb_port_get_link_generation(struct tb_port*p){(void)p;abort();}
static int usb4_pci_port_set_ext_encapsulation(struct tb_port*p,bool enable){(void)p;(void)enable;abort();}
static unsigned tb_route(const struct tb_switch*sw){return sw->route;}
static ktime_t now;static unsigned nw,events;
static struct{unsigned route,port,space,offset,count;u32 words[2];}writes[32];
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void fsleep(unsigned us){(void)us;now++;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static int tb_port_clear_counter(struct tb_port*p,int n){(void)p;(void)n;abort();}
static void tb_tunnel_event(struct tb*t,unsigned event,unsigned type,struct tb_port*s,struct tb_port*d){(void)t;(void)type;(void)s;(void)d;if(event!=(events==0?TB_TUNNEL_ACTIVATED:TB_TUNNEL_DEACTIVATED))abort();events++;}
static int tb_port_read(struct tb_port*p,void*out,int space,int offset,int words){
 if(space==TB_CFG_HOPS){if(words!=2||(offset!=16&&offset!=60&&offset!=62))abort();if(p->disabled&&++p->reads>=2)p->hop.pending=0;memcpy(out,&p->hop,8);return 0;}
 if(space!=TB_CFG_PORT||words!=1||offset!=0x50)abort();memcpy(out,&p->cs0,4);return 0;
}
static int tb_port_write(struct tb_port*p,const void*in,int space,int offset,int words){
 if(nw>=32||words<1||words>2)abort();writes[nw].route=p->sw->route;writes[nw].port=p->port;writes[nw].space=space;writes[nw].offset=offset;writes[nw].count=words;memcpy(writes[nw++].words,in,words*4);
 if(space==TB_CFG_HOPS){if(words!=2)abort();memcpy(&p->hop,in,8);p->disabled=!p->hop.enable;if(p->disabled)p->reads=0;return 0;}
 if(space!=TB_CFG_PORT||words!=1||offset!=0x50)abort();memcpy(&p->cs0,in,4);return 0;
}
'''
main = r'''
int main(void){
 for(unsigned mode=0;mode<2;mode++)for(unsigned stale=0;stale<2;stale++)for(unsigned seed=0;seed<32;seed++){
  struct tb_switch sw[2]={{.route=0,.credit_allocation=mode,.max_pcie_credits=6+seed%26,.config={.thunderbolt_version=32}},{.route=2,.credit_allocation=mode,.max_pcie_credits=6+seed%26,.config={.thunderbolt_version=32}}};
  struct tb_port ports[4]={{.sw=&sw[0],.port=6,.cap_adap=0x50,.bonded=true},{.sw=&sw[0],.port=2,.lane=true,.bonded=true,.total_credits=100,.ctl_credits=8},{.sw=&sw[1],.port=1,.lane=true,.bonded=true,.total_credits=100,.ctl_credits=8},{.sw=&sw[1],.port=4,.cap_adap=0x50,.bonded=true}};
  sw[0].upstream=&ports[1];sw[1].upstream=&ports[2];
  struct tb_path*paths[2];u32 initial[8];
  for(unsigned d=0;d<2;d++){paths[d]=calloc(1,sizeof(*paths[d])+2*sizeof(paths[d]->hops[0]));if(!paths[d])abort();paths[d]->path_length=2;
   for(unsigned i=0;i<2;i++){struct tb_port*in=&ports[d?(i?1:3):(i?2:0)];struct tb_port*out=&ports[d?(i?0:2):(i?3:1)];unsigned s=seed+d*2;u32 raw[2]={((0x12345678U^(s*0x104001U)^(i*0x13579U))&~0x80000000U)|(stale?0x80000000U:0),(0xabcdef12U^(s*0x104101U)^(i*0x13579U))|(stale?0x10000000U:0)};memcpy(initial+d*4+i*2,raw,8);memcpy(&in->hop,raw,8);paths[d]->hops[i]=(struct tb_path_hop){.in_port=in,.out_port=out,.in_hop_index=i?(d?31:30):8,.next_hop_index=i?8:(d?31:30),.in_counter_index=-1};}if(tb_pci_init_path(paths[d]))abort();
  }
  struct tb_tunnel t={.npaths=2,.src_port=&ports[0],.dst_port=&ports[3],.paths={paths[0],paths[1]},.pre_activate=tb_pci_pre_activate,.activate=tb_pci_activate};
  nw=0;now=0;events=0;if(tb_tunnel_activate(&t)||t.state!=TB_TUNNEL_ACTIVE||events!=1)abort();tb_tunnel_deactivate(&t);if(t.state!=TB_TUNNEL_INACTIVE||events!=2)abort();
  printf("C %u %u %u",mode,stale,seed);for(unsigned i=0;i<8;i++)printf(" %u",initial[i]);printf(" %u",nw);
  for(unsigned i=0;i<nw;i++){printf(" %u %u %u %u %u",writes[i].route,writes[i].port,writes[i].space,writes[i].offset,writes[i].count);for(unsigned j=0;j<writes[i].count;j++)printf(" %u",writes[i].words[j]);}
  printf(" %u %u",ports[0].cs0,ports[3].cs0);for(unsigned d=0;d<2;d++)for(unsigned i=0;i<2;i++){u32 final[2];memcpy(final,&paths[d]->hops[i].in_port->hop,8);printf(" %u %u",final[0],final[1]);}puts("");free(paths[0]);free(paths[1]);
 }
}
'''
functions = [
    *[("tb.h", name) for name in ["usb4_switch_version", "tb_switch_is_usb4", "tb_port_use_credit_allocation"]],
    ("switch.c", "tb_port_add_nfc_credits"),
    *[("path.c", name) for name in ["tb_dump_hop", "__tb_path_deallocate_nfc", "__tb_path_deactivate_hop", "__tb_path_deactivate_hops", "tb_path_activate", "tb_path_deactivate"]],
    ("usb4.c", "usb4_pci_port_ltssm_state"), ("switch.c", "tb_pci_port_enable"),
    *[("tunnel.c", name) for name in ["tb_usable_credits", "tb_available_credits", "tb_pci_port_ltssm_state_detect", "tb_pci_pre_activate", "tb_pci_set_ext_encapsulation", "tb_pci_activate", "tb_pci_init_credits", "tb_pci_init_path", "tb_tunnel_set_active", "tb_tunnel_deactivate", "tb_tunnel_activate"]],
]
unit = out / "linux-pcie-tunnel.c"
unit.write_text("\n".join([
    prelude, macros, declaration("tb_regs.h", "struct tb_regs_hop", True),
    declaration("tb_regs.h", "enum tb_pcie_ltssm_state"),
    declaration("tb.h", "struct tb_path_hop"), declaration("tb.h", "enum tb_path_port"),
    declaration("tb.h", "struct tb_path"), stubs,
    *[function(file, name) for file, name in functions], main,
]))
exe = out / "linux-pcie-tunnel"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True, timeout=60)
with trace.open("xb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True, timeout=60)
print(f"{len(functions)} unchanged helpers; {trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
