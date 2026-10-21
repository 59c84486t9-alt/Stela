#!/usr/bin/env python3
"""Run four unchanged pinned Linux RTL8153A receive/duplex routines.

Generated files remain ignored. Stubs supply register storage and MTU/descriptor
metadata; original C computes register effects. This is not full-init C proof.
Usage: python3 rtl8153a_link_oracle.py R8152_C OUTPUT_DIRECTORY
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:3])
b_mode = len(sys.argv) == 4 and sys.argv[3] == "--rtl8153b"
c_mode = len(sys.argv) == 4 and sys.argv[3] == "--rtl8153c"
assert hashlib.sha256(source.read_bytes()).hexdigest() == "9d766f203c7fdabe6449e8dd2b9e5dd4fccfa20a62aa5dbf00d64c0c475c5a9f"
text = source.read_text()
out.mkdir(parents=True, exist_ok=True)


def function(name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


names = ["rtl_set_ifg", "r8153_set_rx_early_timeout", "rx_reserved_size", "r8153_set_rx_early_size"]
macros = ["USB_RX_EARLY_TIMEOUT", "USB_RX_EARLY_SIZE", "USB_RX_EXTRA_AGGR_TMR", "PLA_TCR1", "PLA_MAC_PWR_CTRL4", "IFG_MASK", "IFG_144NS", "IFG_96NS", "TX10MIDLE_EN", "COALESCE_SUPER", "COALESCE_HIGH", "COALESCE_SLOW", "mtu_to_size"]
defines = []
for name in macros:
    match = re.search(r"^#define\s+" + name + r"\b[^\n]*", text, re.M)
    assert match, name
    defines.append(match.group())
version = re.search(r"enum rtl_version \{.*?\n\};", text, re.S).group()
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
#include <stdint.h>
#include <stdio.h>
typedef uint16_t u16; typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define MCU_TYPE_PLA 0x100
#define MCU_TYPE_USB 0
#define VLAN_ETH_HLEN 18
#define ETH_FCS_LEN 4
#define _10bps 4
#define _100bps 8
#define FULL_DUP 1
#define WARN_ON_ONCE(x) ((void)(x))
struct net_device {u32 mtu;};
struct r8152 {int version;u32 coalesce,rx_buf_sz;struct net_device *netdev;struct {u32 size,align;}rx_desc;};
static u16 registers[2][65536];
static void ocp_write_word(struct r8152 *t,int b,int a,u32 v){(void)t;registers[!!b][a]=v;}
static void ocp_word_w0w1(struct r8152 *t,int b,int a,u32 c,u32 s){(void)t;registers[!!b][a]=(registers[!!b][a]&~c)|s;}
static void ocp_word_clr_bits(struct r8152 *t,int b,int a,u32 c){ocp_word_w0w1(t,b,a,c,0);}
static void ocp_word_set_bits(struct r8152 *t,int b,int a,u32 s){ocp_word_w0w1(t,b,a,0,s);}
'''
main = r'''
int main(void){
  const unsigned speeds[]={1,3,4,5},statuses[]={0x0a,0x0b,0x06,0x07,0x13};
  for(unsigned r=0;r<4;r++)for(unsigned i=0;i<4;i++)for(unsigned j=0;j<5;j++){
    unsigned speed=speeds[i];struct net_device n={.mtu=1500};
    struct r8152 t={.version=RTL_VER_03+r,.coalesce=speed>=4?COALESCE_SUPER:(speed==3?COALESCE_HIGH:COALESCE_SLOW),.rx_buf_sz=speed>=4?32768:16384,.netdev=&n,.rx_desc={24,8}};
    registers[1][PLA_TCR1]=0xa55a;registers[1][PLA_MAC_PWR_CTRL4]=0xa55a;
    r8153_set_rx_early_timeout(&t);r8153_set_rx_early_size(&t);rtl_set_ifg(&t,statuses[j]);
    printf("%04x %u %u %u %u %u %u\n",0x5c00+r*0x10,speed,statuses[j],registers[0][USB_RX_EARLY_TIMEOUT],registers[0][USB_RX_EARLY_SIZE],registers[1][PLA_TCR1],registers[1][PLA_MAC_PWR_CTRL4]);
  }return 0;
}
'''
if b_mode:
    main = main.replace("r<4", "r<2").replace("RTL_VER_03+r", "RTL_VER_08+r").replace("speed>=4?COALESCE_SUPER:(speed==3?COALESCE_HIGH:COALESCE_SLOW)", "15000").replace("speed>=4?32768:16384", "32768").replace("0x5c00+r*0x10", "0x6000+r*0x10")
if c_mode:
    main = main.replace("r<4", "r<1").replace("RTL_VER_03+r", "RTL_VER_14").replace("speed>=4?COALESCE_SUPER:(speed==3?COALESCE_HIGH:COALESCE_SLOW)", "15000").replace("speed>=4?32768:16384", "32768").replace("0x5c00+r*0x10", "0x6400")
unit = out / "linux-rtl8153a-link.c"
unit.write_text(prelude + "\n" + "\n".join(defines) + "\n" + version + "\n" + "\n".join(function(n) for n in names) + main)
exe = out / "linux-rtl8153a-link"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True)
print(out / "trace.txt")
