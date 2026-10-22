#!/usr/bin/env python3
"""Compile unchanged pinned Linux Intel PMC mux packet/response helpers.

IPC/resource objects are stubs; original helpers produce actual request bytes.
This is not SCU firmware, native IRQ ownership, GPU signalling or a Linux probe.
Usage: python3 intel_pmc_mux_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
pins = {"intel_pmc_mux.c": "f23a63b9f866d6ed45976c72e94a4eaa84d6b9414284a96d61f036448072fe9e", "typec_altmode.h": "d934b5d661883983fd6bb662e059db007fb06d526bb31d05d45e6cf4a0a706be", "typec_dp.h": "601bc7daf26aee18d4efce18e18af659c9b5937ca59b16f4026e7cde04ba2c50", "typec_tbt.h": "4e7613286cc3e318736a794c30422fe236acef16c805f1665c4f6570ed7f109d", "pd.h": "c844b3db3f0e4f3cf760d68ba3ff96145d73988c8d030aad8c29b2c1e9a88b50"}
for name, digest in pins.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
text = (source / "intel_pmc_mux.c").read_text()
out.mkdir(parents=True, exist_ok=True)


def function(name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


def defines(text):
    lines = text.splitlines(keepends=True)
    selected = []
    at = 0
    while at < len(lines):
        if lines[at].startswith("#define"):
            selected.append(lines[at])
            while lines[at].rstrip().endswith("\\"):
                at += 1
                selected.append(lines[at])
        at += 1
    return "".join(selected)


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2020 Intel Corporation
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) (((~0U)>>(31-(h)))&((~0U)<<(l)))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define EIO 5
#define EBUSY 16
#define EINVAL 22
#define EOPNOTSUPP 95
#define __packed __attribute__((packed))
#define fallthrough __attribute__((fallthrough))
enum typec_orientation {TYPEC_ORIENTATION_NONE,TYPEC_ORIENTATION_NORMAL,TYPEC_ORIENTATION_REVERSE};
enum usb_role {USB_ROLE_NONE,USB_ROLE_HOST,USB_ROLE_DEVICE};
struct acpi_device {const char *hid;};
static bool acpi_dev_hid_uid_match(struct acpi_device *d,const char *h,const char *uid){(void)uid;return strcmp(d->hid,h)==0;}
struct intel_scu_ipc_dev {int unused;};
struct typec_altmode {unsigned int svid;};
struct typec_mux_state {unsigned long mode;struct typec_altmode *alt;void *data;};
struct typec_displayport_data {u32 status,conf;};
struct typec_thunderbolt_data {u32 device_mode,cable_mode,enter_vdo;};
struct enter_usb_data {u32 eudo;bool active_link_training;};
static unsigned int count,fail_mode,attempts;
static unsigned char messages[16][8];static unsigned int lengths[16];
static int intel_scu_ipc_dev_command(struct intel_scu_ipc_dev *d,int cmd,int sub,const void *input,size_t len,void *output,size_t outlen){(void)d;if(cmd!=0xa7||sub||outlen!=4||len>8||count>=16)return -EINVAL;memcpy(messages[count],input,len);lengths[count++]=len;unsigned char *reply=output;memset(reply,0,4);unsigned int index=(((const unsigned char *)input)[0]&15)<2?2:1;if(fail_mode==1&&attempts<2)reply[index]=1;else if(fail_mode==2)reply[index]=1;else if(fail_mode==3)reply[index]=3;attempts++;return 0;}
static void clear(void){count=attempts=fail_mode=0;memset(messages,0,sizeof(messages));}
static void emit(int ret){printf(" %d %u",ret,count);for(unsigned int n=0;n<count;n++){putchar(' ');for(unsigned int i=0;i<lengths[n];i++)printf("%02x",messages[n][i]);}putchar('\n');}
'''
headers = ""
for name in ["typec_altmode.h", "typec_dp.h"]:
    header = (source / name).read_text()
    headers += "\n".join(enum for enum in re.findall(r"enum \{.*?\n\};", header, re.S) if "TYPEC_STATE_SAFE" in enum or "TYPEC_MODE_USB2" in enum or "TYPEC_DP_STATE_A" in enum) + "\n"
for name in ["typec_dp.h", "typec_tbt.h", "pd.h"]:
    headers += defines((source / name).read_text())
# Two anonymous protocol enums are copied exactly from the donor.
enums = "\n".join(re.findall(r"enum \{.*?\n\};", text, re.S)) + "\n"
packet = re.search(r"struct altmode_req \{.*?\} __packed;", text, re.S).group() + "\n"
structs = r'''
struct pmc_usb {struct intel_scu_ipc_dev *ipc;struct acpi_device *iom_adev;};
struct pmc_usb_port {u32 iom_status;struct pmc_usb *pmc;enum typec_orientation orientation;enum usb_role role;u8 usb2_port,usb3_port;enum typec_orientation sbu_orientation,hsl_orientation;};
'''
names = ["sbu_orientation", "hsl_orientation", "is_pmc_mux_tbt", "pmc_usb_send_command", "pmc_usb_command", "pmc_usb_mux_dp_hpd", "pmc_usb_mux_dp", "pmc_usb_mux_tbt", "pmc_usb_mux_usb4", "pmc_usb_mux_safe_state", "pmc_usb_disconnect", "pmc_usb_connect"]
main = r'''
int main(void){
    const char *ids[]={"INTC1072","INTC1079","INTC107A","INTC10EA"};struct acpi_device adev={ids[0]};struct intel_scu_ipc_dev ipc={0};struct pmc_usb pmc={&ipc,&adev};struct pmc_usb_port p={.pmc=&pmc,.usb2_port=1,.usb3_port=1};
    for(unsigned int port=1;port<=3;port+=2)for(unsigned int o=1;o<3;o++)for(unsigned int r=1;r<3;r++)for(unsigned int h=0;h<3;h++)for(unsigned int s=0;s<3;s++)for(unsigned int state=0;state<3;state++){
        p.usb2_port=p.usb3_port=port;p.orientation=o;p.sbu_orientation=s;p.hsl_orientation=h;p.role=state==0?0:state==1?r:3-r;p.iom_status=state?(1U<<31)|(3U<<6)|(p.role==2?BIT(10):0):0;clear();printf("C %u %u %u %u %u %u %x",port,o,r,h,s,p.role,p.iom_status);emit(pmc_usb_connect(&p,r));
    }
    p.usb2_port=p.usb3_port=1;p.sbu_orientation=p.hsl_orientation=0;
    for(unsigned int k=0;k<4;k++)for(unsigned int o=1;o<3;o++)for(unsigned int r=1;r<3;r++){
        adev.hid=ids[k];p.orientation=o;p.role=r;
        for(unsigned int pin=2;pin<6;pin++)for(unsigned int cable=0;cable<4;cable++)for(unsigned int speed=0;speed<4;speed++)for(unsigned int hp=0;hp<3;hp++){
            struct typec_displayport_data dp={hp==0?0:hp==1?0x80:0x180,2|(1U<<(pin+8))|(cable<<28)|(speed<<2)};struct typec_mux_state st={TYPEC_STATE_MODAL+pin,NULL,&dp};p.iom_status=(1U<<31)|(3U<<6)|(r==2?BIT(10):0);clear();printf("D %u %u %u %u %x %x %x",k,o,r,pin,dp.conf,dp.status,p.iom_status);emit(pmc_usb_mux_dp(&p,&st));
        }
        for(unsigned int activity=5;activity<=6;activity++)for(unsigned int oldhp=0;oldhp<2;oldhp++)for(unsigned int hp=0;hp<3;hp++){
            struct typec_displayport_data dp={hp==0?0:hp==1?0x80:0x180,0x406};struct typec_mux_state st={TYPEC_DP_STATE_C,NULL,&dp};p.iom_status=(1U<<31)|(activity<<6)|(r==2?BIT(10):0)|(oldhp?BIT(12):0);clear();printf("D %u %u %u 2 %x %x %x",k,o,r,dp.conf,dp.status,p.iom_status);emit(pmc_usb_mux_dp(&p,&st));
        }
        for(unsigned int flags=0;flags<32;flags++)for(unsigned int speed=1;speed<4;speed++)for(unsigned int rounded=0;rounded<2;rounded++){
            struct typec_thunderbolt_data tb={.device_mode=(flags&1)?BIT(16):0,.cable_mode=(speed<<16)|(rounded<<19)|((flags&2)?BIT(21):0)|((flags&4)?BIT(22):0)|((flags&8)?BIT(23):0),.enter_vdo=(flags&16)?BIT(24):0};struct typec_mux_state st={TYPEC_TBT_MODE,NULL,&tb};p.iom_status=(1U<<31)|(3U<<6)|(r==2?BIT(10):0);clear();printf("T %u %u %u %x %x %x %x",k,o,r,tb.device_mode,tb.cable_mode,tb.enter_vdo,p.iom_status);emit(pmc_usb_mux_tbt(&p,&st));
        }
        for(unsigned int cable=0;cable<4;cable++)for(unsigned int speed=0;speed<4;speed++)for(unsigned int train=0;train<2;train++){
            struct enter_usb_data usb={.eudo=(2U<<28)|(cable<<19)|(speed<<21),.active_link_training=train};struct typec_mux_state st={TYPEC_MODE_USB4,NULL,&usb};p.iom_status=(1U<<31)|(3U<<6)|(r==2?BIT(10):0);clear();printf("U %u %u %u %x %u %x",k,o,r,usb.eudo,train,p.iom_status);emit(pmc_usb_mux_usb4(&p,&st));
        }
        for(unsigned int activity=7;activity<=13;activity+=6){struct typec_thunderbolt_data tb={0};struct enter_usb_data usb={0};struct typec_mux_state ts={TYPEC_TBT_MODE,NULL,&tb},us={TYPEC_MODE_USB4,NULL,&usb};p.iom_status=(1U<<31)|(activity<<6)|(r==2?BIT(10):0);clear();printf("T %u %u %u 0 0 0 %x",k,o,r,p.iom_status);emit(pmc_usb_mux_tbt(&p,&ts));clear();printf("U %u %u %u 0 0 %x",k,o,r,p.iom_status);emit(pmc_usb_mux_usb4(&p,&us));}
    }
    const u32 states[]={0,(1U<<31)|(3U<<6),(1U<<31)|(4U<<6),(1U<<31)|(5U<<6)|BIT(12),(1U<<31)|(7U<<6)|BIT(12)};
    for(unsigned int port=1;port<=3;port+=2)for(unsigned int i=0;i<5;i++){p.usb2_port=p.usb3_port=port;p.iom_status=states[i];struct typec_mux_state st={0};clear();printf("S %u %x",port,p.iom_status);emit(pmc_usb_mux_safe_state(&p,&st));clear();printf("X %u %x",port,p.iom_status);emit(pmc_usb_disconnect(&p));}
    const unsigned char requests[][8]={{0x10,1},{0x11,1},{0x12},{0x13,0x10,0,0,0,0,0,0},{0x14,0}};const unsigned int sizes[]={2,2,1,8,2};
    for(unsigned int req=0;req<5;req++)for(unsigned int failure=1;failure<=3;failure++){unsigned char message[8];memcpy(message,requests[req],8);clear();fail_mode=failure;printf("B %u %u",req,failure);emit(pmc_usb_command(&p,message,sizes[req]));}
    return 0;
}
'''
code = prelude + headers + defines(text) + enums + packet + structs + "\n".join(function(name) for name in names) + main
(out / "oracle.c").write_text(code)
subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
trace = subprocess.check_output([str(out / "oracle")]); (out / "trace.txt").write_bytes(trace)
counts = {}
for line in trace.splitlines():
    tag = chr(line[0]); counts[tag] = counts.get(tag, 0) + 1
manifest = {"linux_commit": "a804c5742bff224d4cb4d25dd383554d598be32b", "sources": pins, "functions": names, "cases": len(trace.splitlines()), "groups": counts, "trace_sha256": hashlib.sha256(trace).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n");print(json.dumps(manifest))
