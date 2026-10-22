#!/usr/bin/env python3
"""Execute unchanged Linux lane/configured/NFC adapter helpers.

Usage: thunderbolt_adapter_oracle.py PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Captures actual source register writes with legal reserved positive credit
inputs. Does not emulate link training, tunnel allocation or native ownership.
Generated C/executable/trace remain ignored.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
    "switch.c": "cb3e11c220daa808183d072415e1904ea1b5bcf44ad37bb9db869e36a4b65c66",
    "usb4.c": "bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)
def function(filename, name):
    text = texts[filename]
    match = re.search(r"^(?:static )?int " + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]
structure = re.search(r"struct tb_regs_port_header \{.*?\n\} __packed;", texts["tb_regs.h"], re.S).group()
porttype = re.search(r"enum tb_port_type \{.*?\n\};", texts["tb_regs.h"], re.S).group()
macros = "\n".join(line for line in texts["tb_regs.h"].splitlines() if line.startswith((
    "#define ADP_CS_4", "#define LANE_ADP_CS_1_LD", "#define LANE_ADP_CS_1\t", "#define PORT_CS_19")))
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint16_t u16;
typedef uint32_t u32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define tb_port_dbg(...) ((void)0)
#define TB_CFG_PORT 1
'''
stubs = r'''
struct tb_switch {bool usb4,is_unplugged;};
struct tb_port {struct tb_switch *sw;struct tb_regs_port_header config;unsigned cap_phy,cap_usb4;u32 value,written;unsigned writes,offset;};
static bool tb_switch_is_usb4(const struct tb_switch *sw){return sw->usb4;}
static bool tb_port_is_null(const struct tb_port *p){return p->config.type==TB_TYPE_PORT;}
static int tb_port_read(struct tb_port *p,void *out,int space,int offset,int words){
 if(space!=1||words!=1||(offset!=9&&offset!=0x43)) abort();memcpy(out,&p->value,4);return 0;
}
static int tb_port_write(struct tb_port *p,const void *in,int space,int offset,int words){
 if(space!=1||words!=1||(offset!=4&&offset!=9&&offset!=0x43)) abort();
 memcpy(&p->value,in,4);p->written=p->value;p->offset=offset;p->writes++;return 0;
}
static u32 random_word(u32 *state){u32 x=*state;x^=x<<13;x^=x>>17;x^=x<<5;return *state=x;}
'''
main = r'''
int main(void){
 u32 state=0x312432ab;
 for(unsigned op=0;op<7;op++)for(unsigned n=0;n<1024;n++){
  u32 before=random_word(&state);int delta=0,ret;
  if(op>=4){
   unsigned current=random_word(&state)&1023,total=current+random_word(&state)%(1024-current);
   before=(before&~(0x3ff003ffU))|(total<<20)|current;
   if(op==4) delta=total>current?1+random_word(&state)%(total-current):0;
   if(op==5) delta=-(1+(int)(random_word(&state)%2048));
  }
  struct tb_switch sw={.usb4=true};struct tb_port p={.sw=&sw,.cap_phy=8,.cap_usb4=0x30,.value=before};
  p.config.type=TB_TYPE_PORT;p.config.nfc_credits=before;
  if(op<2)ret=__tb_port_enable(&p,op==1);
  else if(op<4)ret=usb4_port_set_configured(&p,op==3);
  else ret=tb_port_add_nfc_credits(&p,delta);
  if(ret)abort();
  printf("A %u %d %u %u %u %u %u\n",op,delta,before,p.value,p.writes,p.offset,p.written);
 }
}
'''
unit=out/"linux-thunderbolt-adapter.c"
unit.write_text(prelude+porttype+structure+"\n"+macros+stubs+"\n"+"\n".join([
    function("switch.c","__tb_port_enable"), function("switch.c","tb_port_add_nfc_credits"),
    function("usb4.c","usb4_port_set_configured"),main,
]))
exe=out/"linux-thunderbolt-adapter"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
trace=out/"trace.txt"
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())],stdout=stream,check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
