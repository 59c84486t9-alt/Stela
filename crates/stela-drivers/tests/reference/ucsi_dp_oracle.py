#!/usr/bin/env python3
"""Unchanged pinned Linux DP source capability helper and UCSI CAM macro.

The native driver uses explicit pin policy. Cases restrict local capabilities to
one actual pin so the unchanged Linux initial-selection helper is comparable.
Status/ACPI/GPU objects are fixtures, not native attachment or physical evidence.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
pins = {"displayport.c": "bd64b70bf2e4c2200821c3c3a21b88c2a9c5212c494ed943bd60c6079d5067b0", "ucsi-displayport.c": "9382b0088b98cc95d2b25c3de8d7829db7073c26ac3d57e753f413a8f45a8852", "typec_dp.h": "601bc7daf26aee18d4efce18e18af659c9b5937ca59b16f4026e7cde04ba2c50"}
for name, digest in pins.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
text = (source / "displayport.c").read_text()
start = text.index("static int dp_altmode_configure(")
at = text.index("{", start) + 1
depth = 1
while depth:
    depth += (text[at] == "{") - (text[at] == "}")
    at += 1
function = text[start:at]
header = (source / "typec_dp.h").read_text()
lines = header.splitlines(keepends=True)
defines = []
for index, line in enumerate(lines):
    if line.startswith("#define"):
        defines.append(line)
        while lines[index].rstrip().endswith("\\"):
            index += 1
            defines.append(lines[index])
enums = "\n".join(re.findall(r"enum \{.*?\n\};", header, re.S))
ucsi = (source / "ucsi-displayport.c").read_text()
macro = re.search(r"#define UCSI_CMD_SET_NEW_CAM.*?\n\s*.*?\n\s*.*?\n", ucsi).group()
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2018 Intel Corporation
#include <stdint.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) (((~0U)>>(31-(h)))&((~0U)<<(l)))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define EINVAL 22
#define TYPEC_STATE_MODAL 2
#define UCSI_SET_NEW_CAM 0x0f
struct typec_altmode {u32 vdo;};
struct data {u32 status,conf;};
struct dp_altmode {struct typec_altmode *port,*alt,*plug_prime;struct data data,data_prime;};
#define DP_PIN_ASSIGN_MULTI_FUNC_MASK (BIT(DP_PIN_ASSIGN_B)|BIT(DP_PIN_ASSIGN_D)|BIT(DP_PIN_ASSIGN_F))
#define DP_PIN_ASSIGN_DP_ONLY_MASK (BIT(DP_PIN_ASSIGN_A)|BIT(DP_PIN_ASSIGN_C)|BIT(DP_PIN_ASSIGN_E))
'''
main = r'''
int main(void){
 struct typec_altmode local={0},partner={0},cable={0};struct dp_altmode dp={.port=&local,.alt=&partner};
 for(unsigned int lr=0;lr<2;lr++)for(unsigned int pr=0;pr<2;pr++)for(unsigned int pin=2;pin<6;pin++)for(unsigned int pm=0;pm<16;pm++)for(unsigned int ls=1;ls<4;ls++)for(unsigned int ps=1;ps<4;ps++)for(unsigned int active=0;active<2;active++)for(unsigned int cm=0;cm<(active?3:1);cm++)for(unsigned int cs=1;cs<(active?4:2);cs++){
  local.vdo=2|(ls<<2)|(lr?BIT(6):0)|(BIT(pin)<<(lr?8:16));partner.vdo=1|(ps<<2)|(pr?BIT(6):0)|((pm<<2)<<(pr?16:8));cable.vdo=(cs<<2)|((cm==0?0:cm==1?BIT(pin):0x3c)<<16);dp.plug_prime=active?&cable:NULL;dp.data=(struct data){.status=2};dp.data_prime=(struct data){0};int ret=dp_altmode_configure(&dp,2);printf("D %x %x %u %x %u %d %x\n",local.vdo,partner.vdo,active,cable.vdo,pin,ret,dp.data.conf);
 }
 const u32 confs[]={0,0xffffffff,0x80000000,0x406,0x806,0x10000406,0x40000406};
 for(unsigned int con=1;con<=127;con++)for(unsigned int cam=0;cam<30;cam++)for(unsigned int enter=0;enter<2;enter++)for(unsigned int n=0;n<7;n++)printf("C %u %u %u %x %llx\n",con,cam,enter,confs[n],(unsigned long long)UCSI_CMD_SET_NEW_CAM(con,enter,cam,confs[n]));
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
(out / "oracle.c").write_text(prelude + "".join(defines) + enums + "\n" + macro + function + main)
subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
trace = subprocess.check_output([str(out / "oracle")])
(out / "trace.txt").write_bytes(trace)
counts = {tag: sum(line.startswith(tag.encode()) for line in trace.splitlines()) for tag in ["D", "C"]}
manifest = {"linux_commit": "a804c5742bff224d4cb4d25dd383554d598be32b", "sources": pins, "functions": ["dp_altmode_configure"], "macros": ["UCSI_CMD_SET_NEW_CAM"], "cases": counts, "trace_sha256": hashlib.sha256(trace).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
