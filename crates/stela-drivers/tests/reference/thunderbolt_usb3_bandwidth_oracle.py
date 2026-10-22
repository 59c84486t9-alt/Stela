#!/usr/bin/env python3
"""Unchanged Linux USB3 CMR/HCA consumed/max/scale/allocation helpers.

Usage: thunderbolt_usb3_bandwidth_oracle.py PINNED_SOURCE_DIRECTORY FRESH_OUTPUT
Native controller/accounting/permission inputs are captures, not OS providers.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
    "usb4.c": "bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5",
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
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


def function(name):
    text = texts["usb4.c"]
    match = re.search(r"^(?:static )?(?:inline )?(?:int|u32|unsigned int)\s+" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t ktime_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define TB_CFG_PORT 1
#define USB4_PORT_DELAY 50
#define MEGA 1000000UL
#define DIV_ROUND_CLOSEST(n,d) (((n)+(d)/2)/(d))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define max(a,b) ((a)>(b)?(a):(b))
#define WARN_ON(x) ((x)?(abort(),1):0)
#define tb_port_dbg(...) ((void)0)
'''
macros = "\n".join(line for line in texts["tb_regs.h"].splitlines() if line.startswith("#define ADP_USB3_CS_"))
stubs = r'''
struct tb_switch {unsigned route;};
struct tb_port {struct tb_switch*sw;unsigned cap_adap;u32 regs[4];bool transition,target;unsigned polls;};
static ktime_t now;
static unsigned nw;
static struct {unsigned offset;u32 value;}writes[8];
static bool tb_port_is_usb3_down(struct tb_port*p){(void)p;return true;}
static unsigned tb_route(struct tb_switch*sw){return sw->route;}
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void fsleep(unsigned us){(void)us;now++;}
static int tb_port_read(struct tb_port*p,void*out,int space,int offset,int words){
 if(space!=TB_CFG_PORT||words!=1||offset<0x51||offset>0x53)abort();
 unsigned i=offset-p->cap_adap;if(i==1&&p->transition&&++p->polls>=2){p->regs[1]=(p->regs[1]&~ADP_USB3_CS_1_HCA)|(p->target?ADP_USB3_CS_1_HCA:0);p->transition=false;}
 *(u32*)out=p->regs[i];return 0;
}
static int tb_port_write(struct tb_port*p,const void*in,int space,int offset,int words){
 if(space!=TB_CFG_PORT||words!=1||offset<0x52||offset>0x53||nw>=8)abort();
 u32 value=*(const u32*)in;unsigned i=offset-p->cap_adap;writes[nw].offset=offset;writes[nw++].value=value;
 if(i==2&&((p->regs[2]^value)&ADP_USB3_CS_2_CMR)){p->transition=true;p->target=value&ADP_USB3_CS_2_CMR;p->polls=0;}
 p->regs[i]=value;return 0;
}
'''
main = r'''
int main(void){
 static const int requests[]={0,1,1023,8191,10000,16384,18000,20000};
 for(unsigned seed=0;seed<512;seed++){
  struct tb_switch sw={0};struct tb_port p={.sw=&sw,.cap_adap=0x50};
  p.regs[1]=(seed%256)|(((seed*3)%256)<<12);p.regs[2]=(0x12345678U^(seed*0x10201U))&~ADP_USB3_CS_2_CMR;p.regs[3]=(seed%4)|0x30000000U;
  u32 initial[3]={p.regs[1],p.regs[2],p.regs[3]};int up=requests[seed%8],down=requests[(seed/8)%8],wanted_up=up,wanted_down=down;now=0;nw=0;
  if(usb4_usb3_port_allocate_bandwidth(&p,&up,&down))abort();
  printf("B %u %u %u %u %u %u %u %u %u",seed,wanted_up,wanted_down,initial[0],initial[1],initial[2],up,down,nw);
  for(unsigned i=0;i<nw;i++)printf(" %u %u",writes[i].offset,writes[i].value);
  printf(" %u %u %u\n",p.regs[1],p.regs[2],p.regs[3]);
 }
}
'''
names = ["usb4_port_wait_for_bit", "usb4_usb3_port_cm_request", "usb4_usb3_port_set_cm_request", "usb4_usb3_port_clear_cm_request", "usb3_bw_to_mbps", "mbps_to_usb3_bw", "usb4_usb3_port_read_consumed_bandwidth", "usb4_usb3_port_write_allocated_bandwidth", "usb4_usb3_port_allocate_bandwidth"]
unit = out / "linux-usb3-bandwidth.c"
unit.write_text("\n".join([prelude, macros, stubs, *[function(name) for name in names], main]))
exe = out / "linux-usb3-bandwidth"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{len(names)} unchanged helpers; {trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
