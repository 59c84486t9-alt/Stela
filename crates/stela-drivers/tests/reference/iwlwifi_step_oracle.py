#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2021-2026 Intel Corporation
"""Compile the unchanged Linux STEP wire struct and mailbox helper.
Usage: iwlwifi_step_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
No real UEFI capture, platform observation or DMA is modeled.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:])
expected={'fw/uefi.c':'7e57fe0ff11291e6f3c77aedd2f5ca539e825b279497f7a7e89f796d8f829738','fw/uefi.h':'68ec89d9660c9a7de8acde98af29abcabf00a8ed4cc8057def5e6fbcb452a1e0'}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
match=re.search(r'^static int iwl_uefi_step_parse\([^;{}]*?\)\n\{',texts['fw/uefi.c'],re.M);assert match
at,depth=match.end(),1
while depth:
 depth+=(texts['fw/uefi.c'][at]=='{')-(texts['fw/uefi.c'][at]=='}');at+=1
helper=texts['fw/uefi.c'][match.start():at]
structure=re.search(r'struct uefi_cnv_common_step_data \{.*?\} __packed;',texts['fw/uefi.h'],re.S);assert structure
prelude=r'''// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;
#define __packed __attribute__((packed))
struct iwl_trans {struct {u32 mbx_addr_0_step,mbx_addr_1_step;}conf;};
'''
main=r'''
int main(void){
 for(unsigned revision=0;revision<=255;revision++){
  struct uefi_cnv_common_step_data d={.revision=revision,.step_mode=0xfe,.cnvi_eq_channel=0x12,.cnvr_eq_channel=0x34,.radio1=0x56,.radio2=0x78};struct iwl_trans t={0};int rc=iwl_uefi_step_parse(&d,&t);
  printf("step %u %s %x %x\n",revision,rc==0?"ok":rc==-EINVAL?"invalid":"unexpected",t.conf.mbx_addr_0_step,t.conf.mbx_addr_1_step);
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-step.c';unit.write_text(prelude+structure.group(0)+'\n'+helper+'\n'+main);exe=out/'linux-iwlwifi-step'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
