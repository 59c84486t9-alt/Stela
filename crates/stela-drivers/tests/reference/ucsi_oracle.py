#!/usr/bin/env python3
"""Compile unchanged pinned Linux UCSI notification and command/ACK routines.

Only scalar metadata and sync_control transport are modeled. This proves helper
and command/ACK agreement; it does not execute Linux AML, scheduling or hardware.
Usage: python3 ucsi_oracle.py LINUX_UCSI_DIRECTORY OUTPUT_DIRECTORY
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
pins = {
    "ucsi.c": "a9574a273c1ae705a5b5c554ef18bf5a24e87aaaa22c058a2eea80ae0e7eda3a",
    "ucsi.h": "1aadb29e32c3ec7b2082018cb40da61a18b3329c3a5998db66d60b4ed033e2d5",
}
for name, digest in pins.items():
    if hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
        raise ValueError(f"source hash mismatch: {name}")
text = (source / "ucsi.c").read_text()
header = (source / "ucsi.h").read_text()
out.mkdir(parents=True, exist_ok=True)


def function(name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


names = ["ucsi_get_supported_notifications", "ucsi_acknowledge", "ucsi_run_command"]
macros = sorted(set(re.findall(r"\bUCSI_[A-Z0-9_]+", "\n".join(function(n) for n in names))))
# These additional constants are needed by the scripted firmware, not donors.
macros += ["UCSI_VERSION_1_2", "UCSI_CCI_CANCEL_COMPLETE", "UCSI_CCI_ACK_COMPLETE", "UCSI_CCI_CONNECTOR", "UCSI_SET_CCI_LENGTH"]
defines = []
for name in dict.fromkeys(macros):
    match = re.search(r"^#define\s+" + re.escape(name) + r"(?:\([^\n]*?\))?[^\n]*(?:\\\n[^\n]*)*", header, re.M)
    assert match, name
    defines.append(match.group())
# Macro expansion of MAX_DATA_LENGTH requires this version constant too.
defines.append(re.search(r"^#define UCSI_VERSION_2_0[^\n]*", header, re.M).group())
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
/* Linux errno values, independent of the host C library. */
#undef EOPNOTSUPP
#undef EBUSY
#undef EINVAL
#undef EIO
#undef ETIMEDOUT
#define EOPNOTSUPP 95
#define EBUSY 16
#define EINVAL 22
#define EIO 5
#define ETIMEDOUT 110
typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define BIT_ULL(n) (1ULL<<(n))
#define GENMASK(h,l) (((~0U)>>(31-(h)))&((~0U)<<(l)))
#define EVENT_PENDING 0
static void clear_bit(unsigned int bit, unsigned long *flags) {*flags &= ~(1UL<<bit);}
struct ucsi;
struct ucsi_ops {int (*sync_control)(struct ucsi *,u64,u32 *,void *,size_t,void *,size_t);};
struct ucsi {u16 version;struct {u16 features;}cap;unsigned long flags;const struct ucsi_ops *ops;};
'''
model = r'''
static u64 controls[8]; static unsigned int count, scenario;
static int sync_control(struct ucsi *u,u64 cmd,u32 *cci,void *data,size_t size,void *out,size_t out_size){
    (void)u;(void)out;(void)out_size; controls[count++]=cmd;
    if((cmd&255)==UCSI_ACK_CC_CI) return 0;
    if(scenario==3 && (cmd&255)!=UCSI_CANCEL){*cci=UCSI_CCI_BUSY;return -ETIMEDOUT;}
    *cci=UCSI_CCI_COMMAND_COMPLETE|(1U<<1);
    if(scenario==1)*cci|=UCSI_CCI_NOT_SUPPORTED;
    else if(scenario==2)*cci|=UCSI_CCI_ERROR;
    else if(scenario==3)*cci|=UCSI_CCI_CANCEL_COMPLETE;
    else {*cci|=UCSI_SET_CCI_LENGTH(3);if(data&&size>=3)memset(data,0x5a,3);}
    return 0;
}
int main(void){
    static const struct ucsi_ops ops={sync_control}; struct ucsi u={.ops=&ops};
    const u16 versions[]={0x100,0x110,0x120,0x200,0x210,0x300};
    for(unsigned int v=0;v<6;v++)for(unsigned int f=0;f<65536;f++){
        u.version=versions[v];u.cap.features=f;
        printf("N %x %x %llx\n",u.version,f,(unsigned long long)ucsi_get_supported_notifications(&u));
    }
    for(scenario=0;scenario<4;scenario++)for(unsigned int ack=0;ack<2;ack++){
        unsigned char bytes[4]={0};u32 cci;count=0;u.version=0x200;
        int ret=ucsi_run_command(&u,0x1000e,&cci,bytes,4,NULL,0,ack);
        printf("C %u %u %d %u",scenario,ack,ret,count);
        for(unsigned int i=0;i<count;i++)printf(" %llx",(unsigned long long)controls[i]);
        putchar('\n');
    }
    return 0;
}
'''
translation = prelude + "\n".join(defines) + "\n" + "\n".join(function(name) for name in names) + model
(out / "oracle.c").write_text(translation)
subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(out / "oracle")], stdout=trace, check=True)
manifest = {"linux_commit": "a804c5742bff224d4cb4d25dd383554d598be32b", "sources": pins, "functions": names, "trace_sha256": hashlib.sha256((out / "trace.txt").read_bytes()).hexdigest(), "notification_cases": 393216, "command_cases": 8}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
