#!/usr/bin/env python3
"""Execute unchanged pinned Linux USB4 router wake/sleep helper bodies.

Usage: thunderbolt_power_oracle.py PINNED_THUNDERBOLT_DIRECTORY OUTPUT_DIRECTORY
The capture boundary models register I/O, per-port PM policy and wait-for-bit.
It supplies no physical power, tunnel, native policy or device quiescence proof.
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
    "tb.h": "00cde540109b1d8ad0c0664745f5faa5e87f9e40a2c7ece93e373cc323fc6a94",
}
texts = {}
for name, expected in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)
trace = out / "trace.txt"
assert not trace.exists(), "preserve existing trace; choose a fresh output directory"

def function(name):
    text = texts["usb4.c"]
    match = re.search(r"^int " + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]

macros = "\n".join(line for line in texts["tb_regs.h"].splitlines()
                   if line.startswith(("#define ROUTER_CS_5", "#define ROUTER_CS_6", "#define PORT_CS_19")))
macros += "\n" + "\n".join(line for line in texts["tb.h"].splitlines()
                            if line.startswith("#define TB_WAKE_ON_"))
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define TB_CFG_PORT 1
#define TB_CFG_SWITCH 2
struct device { bool wake; };
struct usb4_port { struct device dev; };
struct tb_port { bool upstream; unsigned cap_usb4; u32 value; unsigned writes; struct usb4_port *usb4; };
struct tb_switch { u64 route; struct tb_port port; u32 value; unsigned writes; unsigned wait; };
#define tb_switch_for_each_port(sw,p) for ((p)=&(sw)->port;(p);(p)=NULL)
static u64 tb_route(struct tb_switch *sw) { return sw->route; }
static bool tb_port_is_null(struct tb_port *p) { (void)p; return true; }
static bool tb_is_upstream_port(struct tb_port *p) { return p->upstream; }
static bool device_may_wakeup(struct device *dev) { return dev->wake; }
static int tb_port_read(struct tb_port *p,void *out,int space,int offset,int count) {
 if(space!=1 || offset!=(int)p->cap_usb4+0x13 || count!=1) abort();
 memcpy(out,&p->value,4); return 0;
}
static int tb_port_write(struct tb_port *p,const void *in,int space,int offset,int count) {
 if(space!=1 || offset!=(int)p->cap_usb4+0x13 || count!=1) abort();
 memcpy(&p->value,in,4); p->writes++; return 0;
}
static int tb_sw_read(struct tb_switch *sw,void *out,int space,int offset,int count) {
 if(space!=2 || offset!=5 || count!=1) abort(); memcpy(out,&sw->value,4); return 0;
}
static int tb_sw_write(struct tb_switch *sw,const void *in,int space,int offset,int count) {
 if(space!=2 || offset!=5 || count!=1) abort(); memcpy(&sw->value,in,4); sw->writes++; return 0;
}
static int tb_switch_wait_for_bit(struct tb_switch *sw,int offset,u32 mask,u32 value,int timeout) {
 if(offset!=6 || mask!=1 || value!=1 || timeout!=500) abort(); sw->wait++; return 0;
}
static u32 random_word(u32 *state) { u32 x=*state; x^=x<<13; x^=x>>17; x^=x<<5; return *state=x; }
'''
main = r'''
int main(void) {
 u32 seed=0x4125ab98;
 for(unsigned shape=0;shape<4;shape++) for(unsigned flags=0;flags<64;flags++)
 for(unsigned runtime=0;runtime<2;runtime++) for(unsigned may=0;may<2;may++)
 for(unsigned configured=0;configured<2;configured++) for(unsigned sample=0;sample<4;sample++) {
  u32 before=(random_word(&seed)&~8U)|(configured<<3),router=random_word(&seed);
  struct usb4_port usb4={.dev={.wake=may}};
  struct tb_switch sw={.route=shape%2,.port={.upstream=shape>=2,.cap_usb4=0x30,.value=before,.usb4=&usb4},.value=router};
  if(usb4_switch_set_wake(&sw,flags,runtime)) abort();
  printf("W %u %u %u %u %u %u %u %u %u %u\n",shape,flags,runtime,may,before,sw.port.value,sw.port.writes,router,sw.value,sw.writes);
 }
 for(unsigned sample=0;sample<256;sample++) {
  u32 before=random_word(&seed); struct tb_switch sw={.value=before};
  if(usb4_switch_set_sleep(&sw)) abort();
  printf("S %u %u %u %u\n",before,sw.value,sw.writes,sw.wait);
 }
}
'''
unit = out / "linux-thunderbolt-power.c"
unit.write_text(prelude + macros + "\n" + function("usb4_switch_set_wake") + "\n"
                + function("usb4_switch_set_sleep") + main)
exe = out / "linux-thunderbolt-power"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                str(unit), "-o", str(exe)], check=True, timeout=60)
with trace.open("xb") as stream:
    subprocess.run([str(exe)], stdout=stream, check=True, timeout=60)
print(f"{hashlib.sha256(trace.read_bytes()).hexdigest()} {trace}")
