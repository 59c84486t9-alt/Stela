#!/usr/bin/env python3
"""Compare revision-specific RTL8152 init and permanent-address source paths.

Usage: rtl8152_revision_oracle.py PINNED_R8152_C IGNORED_OUTPUT_DIRECTORY
Five donor functions are extracted unchanged. Register storage and platform,
network, MDIO and ALDPS services are explicit harness boundaries. This does not
execute the complete PHY/up sequence or qualify physical hardware.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
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


names = ["determine_ethernet_addr", "set_ethernet_addr", "r8152_power_cut_en", "rtl_tally_reset", "r8152b_init"]
macros = "PLA_IDR PLA_BACKUP PLA_LED_FEATURE LED_MODE_MASK USB_UPS_CTRL POWER_CUT USB_PM_CTRL_STATUS RESUME_INDICATE PLA_PHY_PWR TX_10M_IDLE_EN PFM_PWM_SWITCH PLA_MAC_PWR_CTRL MCU_CLK_RATIO_MASK MCU_CLK_RATIO D3_CLK_GATED_EN PLA_GPHY_INTR_IMR GPHY_STS_MSK SPEED_DOWN_MSK SPDWN_RXDV_MSK SPDWN_LINKCHG_MSK PLA_RSTTALLY TALLY_RESET USB_USB_CTRL RX_AGG_DISABLE RX_ZERO_EN".split()
defines = []
for name in macros:
    match = re.search(r"^#define\s+" + name + r"\b[^\n]*", text, re.M)
    assert match, name
    defines.append(match.group())
version = re.search(r"enum rtl_version \{.*?\n\};", text, re.S).group()
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint16_t u16; typedef uint32_t u32;
#define MCU_TYPE_PLA 0x100
#define MCU_TYPE_USB 0
#define MII_BMCR 0
#define BMCR_PDOWN 0x800
#define RTL8152_INACCESSIBLE 0
#define test_bit(bit,flags) 0
#define netif_err(...) ((void)0)
#define netif_info(...) ((void)0)
struct sockaddr_storage { unsigned ss_family; unsigned char __data[8]; };
struct net_device { unsigned type; unsigned char dev_addr[6]; };
struct usb_device { int dev; };
struct r8152 { unsigned version, flags; struct net_device *netdev; struct usb_device *udev; };
static unsigned char registers[2][65536]; static unsigned idr_writes;
static u32 read_register(int bank, int address, int width) {
 u32 value=0;for(int i=0;i<width;i++)value|=(u32)registers[!!bank][address+i]<<(8*i);return value;
}
static void write_register(int bank,int address,int width,u32 value) {
 for(int i=0;i<width;i++)registers[!!bank][address+i]=value>>(8*i);
}
static void ocp_word_clr_bits(struct r8152*t,int b,int a,u32 c){(void)t;write_register(b,a,2,read_register(b,a,2)&~c);}
static void ocp_word_set_bits(struct r8152*t,int b,int a,u32 s){(void)t;write_register(b,a,2,read_register(b,a,2)|s);}
static void ocp_write_word(struct r8152*t,int b,int a,u32 v){(void)t;write_register(b,a,2,v);}
static void ocp_dword_w0w1(struct r8152*t,int b,int a,u32 c,u32 s){(void)t;write_register(b,a,4,(read_register(b,a,4)&~c)|s);}
static void r8152_mdio_test_and_clr_bit(struct r8152*t,int a,int c){(void)t;(void)a;(void)c;}
static void r8152_aldps_en(struct r8152*t,bool enable){(void)t;(void)enable;}
static int eth_platform_get_mac_address(void*d,void*o){(void)d;(void)o;return -ENODEV;}
static int vendor_mac_passthru_addr_read(struct r8152*t,struct sockaddr_storage*s){(void)t;(void)s;return -ENODEV;}
static int pla_ocp_read(struct r8152*t,int a,int n,void*out){(void)t;memcpy(out,&registers[1][a],n);return 0;}
static bool is_valid_ether_addr(unsigned char*a){unsigned x=0;for(int i=0;i<6;i++)x|=a[i];return x && !(a[0]&1);}
static void eth_hw_addr_random(struct net_device*n){(void)n;}
static void ether_addr_copy(unsigned char*d,unsigned char*s){memcpy(d,s,6);}
static void eth_hw_addr_set(struct net_device*n,unsigned char*a){memcpy(n->dev_addr,a,6);}
static int __rtl8152_set_mac_address(struct net_device*n,struct sockaddr_storage*s,bool resume){(void)resume;memcpy(n->dev_addr,s->__data,6);idr_writes++;return 0;}
'''
main = r'''
int main(void) {
 const unsigned revisions[]={RTL_VER_01,RTL_VER_02,RTL_VER_07}, raw[]={0x4c00,0x4c10,0x4800};
 const unsigned addresses[]={PLA_LED_FEATURE,USB_UPS_CTRL,USB_PM_CTRL_STATUS,PLA_PHY_PWR,PLA_MAC_PWR_CTRL,PLA_GPHY_INTR_IMR,PLA_RSTTALLY,USB_USB_CTRL};
 const unsigned banks[]={1,0,0,1,1,1,1,0},widths[]={2,2,2,2,4,2,2,2};
 for(unsigned r=0;r<3;r++)for(unsigned p=0;p<4;p++){
  struct net_device n={.type=1};struct usb_device u={0};struct r8152 t={.version=revisions[r],.netdev=&n,.udev=&u};
  unsigned seed=(unsigned[]){0,0xffff,0xa55a,0x5aa5}[p];
  memset(registers,0,sizeof registers);idr_writes=0;
  for(unsigned j=0;j<8;j++)write_register(banks[j],addresses[j],widths[j],widths[j]==4?seed|(seed<<16):seed);
  const unsigned char idr[]={2,3,4,5,6,7,0,0},backup[]={2,0x11,0x22,0x33,0x44,0x55,0,0};
  memcpy(&registers[1][PLA_IDR],idr,8);memcpy(&registers[1][PLA_BACKUP],backup,8);
  r8152b_init(&t);if(set_ethernet_addr(&t,false))return 1;
  printf("%04x %u %u",raw[r],seed,idr_writes);
  for(unsigned j=0;j<6;j++)printf(" %u",n.dev_addr[j]);
  for(unsigned j=0;j<8;j++)printf(" %u",read_register(banks[j],addresses[j],widths[j]));puts("");
 }
 return 0;
}
'''
unit = out / "linux-rtl8152-revision.c"
unit.write_text(prelude + "\n" + "\n".join(defines) + "\n" + version + "\n" + "\n".join(function(n) for n in names) + main)
exe = out / "linux-rtl8152-revision"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True)
print(out / "trace.txt")
