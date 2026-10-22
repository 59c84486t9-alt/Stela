#!/usr/bin/env python3
"""Execute unchanged Linux full USB4 router setup/write sequence.

Usage: thunderbolt_router_oracle.py PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Actual source structures, enum/setup/CV/readiness and per-port hotplug helpers
run with explicit policy, inventory, register and clock capture stubs. No native
ownership, Linux runtime, link training or physical qualification is supplied.
Generated C/executable/trace remain ignored. Existing traces are never replaced.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
 "switch.c":"cb3e11c220daa808183d072415e1904ea1b5bcf44ad37bb9db869e36a4b65c66",
 "usb4.c":"bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5",
 "tb_regs.h":"44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
 "tb.h":"eb885b01adee9ec24cf5cdc4c3aecf5ecd7dc6b5a84c9f300c42af6f9c41db7c",
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
trace=out/"trace.txt"
if trace.exists():raise SystemExit("refusing to replace immutable trace; select a fresh output directory")
out.mkdir(parents=True,exist_ok=True)
def function(filename,name):
 text=texts[filename]
 match=re.search(r"^(?:static )?(?:inline )?(?:int|bool|unsigned int)\s+"+name+r"\([^;{}]*?\)\n\{",text,re.M)
 assert match,name
 at,depth=match.end(),1
 while depth:
  depth+=(text[at]=="{")-(text[at]=="}");at+=1
 return text[match.start():at]
def declaration(prefix,suffix=r";"):
 return re.search(re.escape(prefix)+r" \{.*?\n\}"+suffix,texts["tb_regs.h"],re.S).group()
macros="\n".join(line for line in texts["tb_regs.h"].splitlines() if line.startswith(("#define ROUTER_CS_","#define PORT_CS_18","#define ADP_CS_5","#define USB4_VERSION_MAJOR_MASK")))
prelude=r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define tb_dbg(...) ((void)0)
#define tb_sw_dbg(...) ((void)0)
#define tb_sw_warn(...) ((void)0)
#define str_yes_no(x) ((x)?"yes":"no")
#define TB_CFG_PORT 1
#define TB_CFG_SWITCH 2
#define PCI_VENDOR_ID_INTEL 0x8086
'''
stubs=r'''
struct tb {int unused;};
struct tb_switch;
struct tb_port {struct tb_switch *sw;unsigned port,cap_usb4;struct tb_regs_port_header config;u32 hotplug;};
struct tb_switch {struct tb *tb;struct tb_switch *parent;struct tb_regs_switch_header config;struct tb_port ports[6];u32 regs[8];u64 route;unsigned downport,cap_plug_events,mask,ready_reads,config_reads;bool link_usb4,setup_written,valid_written;};
static ktime_t now;
static struct {unsigned port,space,offset,count;u32 data[4];} writes[16];
static unsigned nw;
static struct tb_switch *active;
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static u64 tb_route(const struct tb_switch *sw){return sw->route;}
static unsigned tb_route_length(u64 route){unsigned n=0;while(route){n++;route>>=8;}return n;}
static struct tb_switch *tb_switch_parent(struct tb_switch *sw){return sw->parent;}
static struct tb_port *tb_switch_downstream_port(struct tb_switch *sw){return &sw->parent->ports[sw->downport];}
static bool tb_switch_is_icm(struct tb_switch *sw){(void)sw;return false;}
static struct tb_port *tb_switch_find_port(struct tb_switch *sw,enum tb_port_type type){for(unsigned i=1;i<=sw->config.max_port_number;i++)if(sw->ports[i].config.type==type)return &sw->ports[i];return NULL;}
static bool tb_acpi_may_tunnel_usb3(void){return active->mask&1;}
static bool tb_acpi_may_tunnel_pcie(void){return active->mask&2;}
#define tb_switch_for_each_port(sw,p) for((p)=&(sw)->ports[1];(p)<=&(sw)->ports[(sw)->config.max_port_number];(p)++)
static int tb_sw_read(struct tb_switch *sw,void *out,int space,unsigned offset,unsigned count){
 if(space!=2||offset+count>8)abort();
 if(offset==6){
  if(sw->setup_written&&++sw->ready_reads>=2)sw->regs[6]|=ROUTER_CS_6_RR;
  if(sw->valid_written&&++sw->config_reads>=2)sw->regs[6]|=ROUTER_CS_6_CR;
 }
 memcpy(out,&sw->regs[offset],count*4);return 0;
}
static void log_write(unsigned port,unsigned space,unsigned offset,unsigned count,const void *in){
 if(nw>=16||count>4)abort();writes[nw].port=port;writes[nw].space=space;writes[nw].offset=offset;writes[nw].count=count;memcpy(writes[nw++].data,in,count*4);
}
static int tb_sw_write(struct tb_switch *sw,const void *in,int space,unsigned offset,unsigned count){
 if(space!=2||offset+count>8)abort();log_write(0,space,offset,count,in);memcpy(&sw->regs[offset],in,count*4);
 if(offset==5){sw->setup_written=true;if(sw->regs[5]&ROUTER_CS_5_CV)sw->valid_written=true;}
 return 0;
}
static int tb_port_read(struct tb_port *p,void *out,int space,unsigned offset,unsigned count){
 if(space!=1||count!=1)abort();u32 value;
 if(offset==p->cap_usb4+PORT_CS_18)value=(active->mask&16)?PORT_CS_18_TCM:0;
 else if(offset==5)value=p->hotplug;else abort();memcpy(out,&value,4);return 0;
}
static int tb_port_write(struct tb_port *p,const void *in,int space,unsigned offset,unsigned count){
 if(space!=1||offset!=5||count!=1)abort();log_write(p->port,space,offset,count,in);memcpy(&p->hotplug,in,4);return 0;
}
static int tb_plug_events_active(struct tb_switch *sw,bool active){(void)active;if(FIELD_GET(USB4_VERSION_MAJOR_MASK,sw->config.thunderbolt_version)==0)abort();return 0;}
'''
main=r'''
int main(void){
 struct tb tb={0};
 for(unsigned version=1;version<=2;version++)for(unsigned r=0;r<3;r++)for(unsigned mask=0;mask<128;mask++){
  u64 route=r==0?0:r==1?1:0x201;
  u32 header[5]={0x12348086,0x43808000U|(9<<8),0xdeadbeef,0x10203040,(version<<29)|0x00ab34cd};
  u32 cs5=0x00d5001f,cs6=0x00001202|((mask&32)?ROUTER_CS_6_HCI:0),hp1=0x92345678,hp2=0xabcdef01;
  struct tb_switch parent={.tb=&tb},sw={.tb=&tb,.parent=route?&parent:NULL,.route=route,.downport=r==2?2:1,.mask=mask};
  parent.config.max_port_number=5;parent.ports[3].config.type=(mask&4)?TB_TYPE_USB3_DOWN:TB_TYPE_INACTIVE;parent.ports[4].config.type=(mask&8)?TB_TYPE_PCIE_DOWN:TB_TYPE_INACTIVE;
  parent.ports[sw.downport].cap_usb4=(mask&64)?0x30:0;
  memcpy(&sw.config,header,20);memcpy(sw.regs,header,20);sw.regs[5]=cs5;sw.regs[6]=cs6;
  sw.config.upstream_port_number=route?1:0;sw.config.depth=tb_route_length(route);sw.config.route_lo=(u32)route;sw.config.route_hi=(u32)(route>>32);sw.config.enabled=0;
  for(unsigned i=1;i<=2;i++){sw.ports[i].sw=&sw;sw.ports[i].port=i;sw.ports[i].cap_usb4=i==1?0x30:0x40;sw.ports[i].hotplug=i==1?hp1:hp2;}
  active=&sw;nw=0;now=0;
  if(tb_switch_configure(&sw)||usb4_switch_configuration_valid(&sw)||tb_switch_port_hotplug_enable(&sw))abort();
  printf("R %llu %u %u",(unsigned long long)route,version,mask);
  for(unsigned i=0;i<5;i++)printf(" %u",header[i]);
  printf(" %u %u %u %u %u",cs5,cs6,hp1,hp2,nw);
  for(unsigned i=0;i<nw;i++){printf(" %u %u %u %u",writes[i].port,writes[i].space,writes[i].offset,writes[i].count);for(unsigned j=0;j<writes[i].count;j++)printf(" %u",writes[i].data[j]);}
  puts("");
 }
}
'''
parts=[prelude,declaration("enum tb_port_type"),declaration("struct tb_regs_switch_header",r" __packed;"),declaration("struct tb_regs_port_header",r" __packed;"),macros,stubs,
 function("tb.h","usb4_switch_version"),function("tb.h","tb_switch_is_usb4"),function("switch.c","tb_switch_wait_for_bit"),function("usb4.c","link_is_usb4"),function("usb4.c","usb4_switch_setup"),function("usb4.c","usb4_switch_configuration_valid"),function("usb4.c","usb4_port_hotplug_enable"),function("switch.c","tb_switch_port_hotplug_enable"),function("switch.c","tb_switch_configure"),main]
unit=out/"linux-thunderbolt-router.c";unit.write_text("\n".join(parts))
exe=out/"linux-thunderbolt-router"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with trace.open("wb") as stream:subprocess.run([str(exe.resolve())],stdout=stream,check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
