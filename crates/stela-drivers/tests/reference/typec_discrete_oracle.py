#!/usr/bin/env python3
"""Run unchanged pinned CCG start and TPS block/task helpers under sanitizers.

Register/firmware peers, jiffies and kernel resource metadata are stubs; these
comparisons do not execute Linux I²C hardware, IRQ allocation or full probe.
Usage: python3 typec_discrete_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
pins = {"ucsi_ccg.c": "6f0fa002786ff6f66b8d3b524388769281133a1726240b2fad2a8289385ba115", "core.c": "d807af36db683a6ebe06e2cd0c3c3e508474f642f0ac6bd7a3596c2816d74726"}
for name, digest in pins.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
out.mkdir(parents=True, exist_ok=True)


def function(text, name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


def macros(text, names):
    result = []
    for name in names:
        match = re.search(r"^#define\s+" + re.escape(name) + r"\b[^\n]*", text, re.M)
        assert match, name
        result.append(match.group())
    return "\n".join(result) + "\n"


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (C) 2017-2018 NVIDIA Corporation. All rights reserved.
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define EINVAL 22
#define EIO 5
#define EBUSY 16
#define EPERM 1
#define ETIMEDOUT 110
'''
ccg_text = (source / "ucsi_ccg.c").read_text()
ccg_names = ["CCGX_RAB_UCSI_CONTROL_STOP", "CCGX_RAB_UCSI_CONTROL_START", "CCGX_RAB_UCSI_CONTROL", "CCGX_RAB_INTR_REG", "DEV_INT"]
ccg = prelude + macros(ccg_text, ccg_names) + r'''
struct ucsi_ccg {int op_lock;};
static unsigned int remaining, reads, writes, delay, control_bits;
static void spin_lock_init(int *lock){*lock=0;}
static void usleep_range(unsigned int lo,unsigned int hi){(void)hi;delay+=lo;}
static int ccg_read(struct ucsi_ccg *u,u16 reg,u8 *data,u32 len){(void)u;if(reg!=6||len!=1)return -EINVAL;reads++;*data=remaining?1:0;return 0;}
static int ccg_write(struct ucsi_ccg *u,u16 reg,const u8 *data,u32 len){(void)u;if(len!=1)return -EINVAL;writes++;if(reg==6){if(remaining)remaining--;}else if(reg==0x39){control_bits=(control_bits<<4)|*data;}else return -EINVAL;return 0;}
''' + function(ccg_text, "ucsi_ccg_init") + r'''
int main(void){for(unsigned int n=0;n<=11;n++){struct ucsi_ccg u;remaining=n;reads=writes=delay=control_bits=0;int ret=ucsi_ccg_init(&u);printf("C %u %d %u %u %u %x\n",n,ret,reads,writes,delay,control_bits);}return 0;}
'''
tps_text = (source / "core.c").read_text()
tps_names = ["TPS_MAX_LEN", "TPS_REG_CMD1", "TPS_REG_DATA1", "INVALID_CMD", "TPS_TASK_TIMEOUT", "TPS_TASK_REJECTED"]
tps = prelude + macros(tps_text, tps_names) + r'''
struct tps6598x {bool i2c_protocol;int *regmap;};
static unsigned long jiffies;
#define msecs_to_jiffies(t) (t)
#define time_is_before_jiffies(t) ((t)<jiffies)
static void mdelay(unsigned int t){jiffies+=t;}
static unsigned int scenario,submitted,command_writes,data_writes;
static unsigned char wire[66];static size_t wire_len;
static int regmap_raw_read(int *map,u8 reg,void *value,size_t len){
    (void)map;unsigned char *bytes=value;bytes[0]=64;
    if(reg==8){u32 cmd=0;if(scenario==1&&!submitted)cmd=0x12345678;if(submitted&&scenario==2)cmd=INVALID_CMD(0x444d4321)?0x444d4321:0;if(submitted&&scenario==3)cmd=0x46555753;jiffies++;memcpy(bytes+1,&cmd,len-1);}
    else if(reg==9){memset(bytes+1,0,len-1);bytes[1]=scenario==4?1:scenario==5?3:0;if(len>2)bytes[2]=0x42;}
    else {for(size_t i=1;i<len;i++)bytes[i]=(u8)(i-1);}
    return 0;
}
static int regmap_raw_write(int *map,u8 reg,const void *value,size_t len){(void)map;memcpy(wire,value,len);wire_len=len;if(reg==8){submitted=1;command_writes++;}if(reg==9)data_writes++;return 0;}
'''
tps_functions = ["tps6598x_block_read", "tps6598x_block_write", "tps6598x_read32", "tps6598x_write_4cc", "tps6598x_exec_cmd_tmo"]
tps += "\n".join(function(tps_text, name) for name in tps_functions) + r'''
int main(void){
    int map=0;struct tps6598x t={.i2c_protocol=true,.regmap=&map};
    for(unsigned int n=1;n<=64;n++){unsigned char read[64]={0},write[64];for(unsigned int i=0;i<n;i++)write[i]=i;int a=tps6598x_block_read(&t,0x40,read,n);int b=tps6598x_block_write(&t,0x40,write,n);printf("B %u %d %d %zu %u %u %u\n",n,a,b,wire_len,wire[0],read[n-1],wire[n]);}
    for(scenario=0;scenario<6;scenario++){unsigned char input[]={1,2,3},output[]={0xaa,0xaa};jiffies=0;submitted=command_writes=data_writes=0;int ret=tps6598x_exec_cmd_tmo(&t,"SWUF",3,input,2,output,1000,0);printf("T %u %d %u %u %u %u\n",scenario,ret,command_writes,data_writes,output[0],output[1]);}
    return 0;
}
'''
trace = bytearray()
for name, code in [("ccg", ccg), ("tps", tps)]:
    file = out / f"{name}-oracle.c"
    file.write_text(code)
    binary = out / f"{name}-oracle"
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(file), "-o", str(binary)], check=True)
    trace.extend(subprocess.check_output([str(binary)]))
(out / "trace.txt").write_bytes(trace)
manifest = {"linux_commit": "a804c5742bff224d4cb4d25dd383554d598be32b", "sources": pins, "functions": ["ucsi_ccg_init"] + tps_functions, "cases": 82, "trace_sha256": hashlib.sha256(trace).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
