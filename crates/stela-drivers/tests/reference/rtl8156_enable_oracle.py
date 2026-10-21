#!/usr/bin/env python3
"""Execute eleven unchanged pinned Linux receive/flow-control enable routines.

The harness supplies register storage, MTU/USB metadata, accessibility and host
queue bookkeeping. rtl_enable is an explicit no-op boundary after these fields:
this does not qualify MAC activation, firmware, PHY tuning or full startup.
Generated C, sanitizer executable and trace remain ignored.
Usage: python3 rtl8156_enable_oracle.py R8152_C OUTPUT_DIRECTORY
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:3])
b_mode=len(sys.argv)==4 and sys.argv[3]=="--rtl8156b"
assert hashlib.sha256(source.read_bytes()).hexdigest()=="9d766f203c7fdabe6449e8dd2b9e5dd4fccfa20a62aa5dbf00d64c0c475c5a9f"
text=source.read_text();out.mkdir(parents=True,exist_ok=True)
def function(name):
    m=re.search(r"^static[^;{}]*?\b"+name+r"\([^;{}]*?\)\n\{",text,re.M);assert m,name
    at,depth=m.end(),1
    while depth:
        depth+=(text[at]=="{")-(text[at]=="}");at+=1
    return text[m.start():at]
names=["rtl8152_get_speed","rtl_eee_plus_en","rtl_set_eee_plus","rtl_set_ifg","r8153_set_rx_early_timeout","rx_reserved_size","r8153_set_rx_early_size","fc_pause_on_auto","fc_pause_off_auto","r8156_fc_parameter","rtl8156_enable"]
macros="PLA_PHYSTATUS PLA_EEEP_CR EEEP_CR_EEEP_TX PLA_MAC_PWR_CTRL4 TX10MIDLE_EN IDLE_SPDWN_EN PLA_TCR1 IFG_MASK IFG_144NS IFG_96NS USB_RX_EARLY_TIMEOUT USB_RX_EXTRA_AGGR_TMR USB_RX_EARLY_SIZE PLA_RX_FIFO_FULL PLA_RX_FIFO_EMPTY USB_RX_AGGR_NUM RX_AGGR_NUM_MASK PLA_EEE_TXTWSYS USB_L1_CTRL USB_FW_TASK FC_PATCH_TASK mtu_to_size is_flow_control".split()
defines=[]
for name in macros:
    m=re.search(r"^#define\s+"+name+r"\b[^\n]*",text,re.M);assert m,name;defines.append(m.group())
version=re.search(r"enum rtl_version \{.*?\n\};",text,re.S).group()
speeds=re.search(r"enum rtl_register_content \{.*?\n\};",text,re.S).group()
prelude=r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define MCU_TYPE_PLA 0x100
#define MCU_TYPE_USB 0
#define USB_SPEED_HIGH 3
#define VLAN_ETH_HLEN 18
#define ETH_FCS_LEN 4
#define RTL8152_INACCESSIBLE 0
#define test_bit(bit,flags) 0
#define WARN_ON_ONCE(x) ((void)(x))
#define usleep_range(a,b) ((void)0)
struct net_device{u32 mtu;};struct usb_device{unsigned speed;};
struct r8152{int version;u32 coalesce,rx_buf_sz,flags,fc_pause_on,fc_pause_off;struct net_device*netdev;struct usb_device*udev;struct{u32 size,align;}rx_desc;};
static u16 registers[2][65536];
static u16 ocp_read_word(struct r8152*t,int b,int a){(void)t;return registers[!!b][a];}
static void ocp_write_word(struct r8152*t,int b,int a,u32 v){(void)t;registers[!!b][a]=v;}
static void ocp_word_w0w1(struct r8152*t,int b,int a,u32 c,u32 s){(void)t;registers[!!b][a]=(registers[!!b][a]&~c)|s;}
static void ocp_word_clr_bits(struct r8152*t,int b,int a,u32 c){ocp_word_w0w1(t,b,a,c,0);}
static void ocp_word_set_bits(struct r8152*t,int b,int a,u32 s){ocp_word_w0w1(t,b,a,0,s);}
static void set_tx_qlen(struct r8152*t){(void)t;}
static int rtl_enable(struct r8152*t){(void)t;return 0;}
'''
main=r'''
int main(void){
const unsigned statuses[]={0x06,0x07,0x0a,0x0b,0x13,0x103,0x403,0x473},speeds[]={1,3,4,5};
const unsigned addresses[]={USB_RX_EARLY_TIMEOUT,USB_RX_EXTRA_AGGR_TMR,USB_RX_EARLY_SIZE,PLA_TCR1,PLA_MAC_PWR_CTRL4,USB_L1_CTRL,PLA_EEE_TXTWSYS,PLA_RX_FIFO_FULL,PLA_RX_FIFO_EMPTY,USB_FW_TASK,PLA_EEEP_CR};
const unsigned banks[]={0,0,0,1,1,0,1,1,1,0,1};
for(unsigned r=0;r<2;r++)for(unsigned s=0;s<4;s++)for(unsigned p=0;p<8;p++){
 struct net_device n={1500};struct usb_device u={speeds[s]};struct r8152 t={.version=RTL_VER_10+r,.coalesce=15000,.rx_buf_sz=49152,.netdev=&n,.udev=&u,.rx_desc={24,8}};
 for(unsigned j=0;j<11;j++)registers[banks[j]][addresses[j]]=0xa55a;
 registers[1][PLA_PHYSTATUS]=statuses[p];
 if(rtl8156_enable(&t))return 1;
 printf("%04x %u %u",0x7020+r*0x10,speeds[s],statuses[p]);
 for(unsigned j=0;j<11;j++)printf(" %u",registers[banks[j]][addresses[j]]);puts("");
}return 0;}
'''
if b_mode:
    main=main.replace("r<2", "r<3").replace("RTL_VER_10+r", "(unsigned[]){RTL_VER_12,RTL_VER_13,RTL_VER_15}[r]").replace("0x7020+r*0x10", "(unsigned[]){0x7400,0x7410,0x7420}[r]")
    main=main.replace("USB_FW_TASK,PLA_EEEP_CR};", "USB_FW_TASK,PLA_EEEP_CR,USB_RX_AGGR_NUM};").replace("0,0,0,1,1,0,1,1,1,0,1};", "0,0,0,1,1,0,1,1,1,0,1,0};").replace("j<11", "j<12")
unit=out/"linux-rtl8156-enable.c";unit.write_text(prelude+"\n"+"\n".join(defines)+"\n"+version+"\n"+speeds+"\n"+"\n".join(function(n)for n in names)+main)
exe=out/"linux-rtl8156-enable"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"trace.txt").open("wb")as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
print(out/"trace.txt")
