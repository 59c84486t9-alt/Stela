#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2023-24 Advanced Micro Devices, Inc.
# SoundWire bus declarations: Copyright(c) 2015-17 Intel Corporation.
# Polling macros: Copyright(c) 2012-2014 The Linux Foundation.
"""Execute seven unchanged AMD SoundWire command functions and polling macros.

Usage: soundwire_amd_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT_DIRECTORY
This models register/peripheral/time boundaries, never physical link behavior.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "drivers/soundwire/amd_manager.c": "13ead1f7bc55eceea800786db2e6c32e436b323424d28788b02db9dc36b69291",
    "drivers/soundwire/amd_manager.h": "af12d349ba235aa0060947255bc958c3825c18ee42e0f4dc9873b0b5843b264d",
    "drivers/soundwire/bus.h": "c25915dc7b0b0357fd1260229b246c5edbf904e3f956bf8f5d7aa1473fe25663",
    "include/linux/soundwire/sdw.h": "789b9467f308ec95c6d0ec45564dd8dfac1d976bf4fbad01b438ba624c14ded2",
    "include/linux/soundwire/sdw_registers.h": "a8d67bb73e45506f66bb36bd3f8b54971eb807d1ebc6b90069b47fe502836e54",
    "include/linux/iopoll.h": "9edf274f8555e266233ba151942af51e83ad175d885478556075258044dd3a0b",
}
source, out = map(Path, sys.argv[1:])
digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
texts = {}
for p, expected in HASHES.items():
    assert digest(source / p) == expected, p
    texts[p] = (source / p).read_text()
out.mkdir(exist_ok=False, parents=True)
original = texts["drivers/soundwire/amd_manager.c"]
fragments = []


def function(name):
    match = re.search(r"\b" + name + r"\([^;{}]*\)\n\{", original)
    assert match, name
    first = original.rfind("\n\n", 0, match.start()) + 2
    end, depth = match.end(), 1
    while depth:
        depth += (original[end] == "{") - (original[end] == "}")
        end += 1
    body = original[first:end]
    fragments.append(dict(name=name, sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


functions = [function(n) for n in ["amd_sdw_ctl_word_prep", "amd_sdw_send_cmd_get_resp",
    "amd_program_scp_addr", "amd_prep_msg", "amd_sdw_fill_msg_resp", "_amd_sdw_xfer_msg", "amd_sdw_xfer_msg"]]
response_enum = re.search(r"enum sdw_command_response \{.*?\n\};", texts["include/linux/soundwire/sdw.h"], re.S).group()
flags = re.search(r"enum \{\n\s*SDW_MSG_FLAG_READ.*?\n\};", texts["drivers/soundwire/bus.h"], re.S).group()
msg = re.search(r"struct sdw_msg \{.*?\n\};", texts["drivers/soundwire/bus.h"], re.S).group()


def macro(path, name):
    lines = texts[path].splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if re.match(r"#define\s+" + name + r"[\s(]", line))
    end = start + 1
    while lines[end - 1].rstrip().endswith("\\"):
        end += 1
    text = "".join(lines[start:end])
    fragments.append(dict(name=name, path=path, sha256=hashlib.sha256(text.encode()).hexdigest()))
    return text


macros = "\n".join(macro("include/linux/iopoll.h", n) for n in ["poll_timeout_us", "read_poll_timeout", "readx_poll_timeout", "readl_poll_timeout"])
definitions = "\n".join(line for line in texts["drivers/soundwire/amd_manager.h"].splitlines()
    if line.startswith("#define ") and ("ACP_SW_IMM_" in line or "AMD_SDW_MCP_CMD_" in line
        or "AMD_SDW_MCP_RESP_" in line or "AMD_SDW_IMM_" in line or "AMD_SDW_TIMEOUT" in line or "ACP_DELAY_US" in line))
definitions += "\n" + "\n".join(line for line in texts["include/linux/soundwire/sdw_registers.h"].splitlines()
    if re.match(r"#define SDW_SCP_ADDRPAGE[12]\s", line))
prefix = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2023-24 Advanced Micro Devices, Inc.
// SoundWire declarations: Copyright(c) 2015-17 Intel Corporation.
// Polling macros: Copyright(c) 2012-2014 The Linux Foundation. All rights reserved.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64;typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
typedef uint64_t ktime_t;
#define BIT(n) (1u<<(n))
#define GENMASK(h,l) ((~0u<<(l))&(~0u>>(31-(h))))
#define FIELD_PREP(mask,v) (((u32)(v)<<__builtin_ctz(mask))&(mask))
#define FIELD_GET(mask,v) (((u64)(v)&(mask))>>__builtin_ctz(mask))
#define dev_err(...) ((void)0)
#define dev_err_ratelimited(...) ((void)0)
#define dev_dbg_ratelimited(...) ((void)0)
#define might_sleep_if(v) ((void)(v))
#define barrier() __asm__ __volatile__("" ::: "memory")
#define cpu_relax() ((void)0)
static u64 now;
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_us(ktime_t t,u64 us){return t+us;}
static int ktime_compare(ktime_t a,ktime_t b){return a>b?1:a<b?-1:0;}
static void usleep_range(unsigned low,unsigned high){(void)low;now+=high;}
struct sdw_bus {struct amd_sdw_manager *owner;};
struct amd_sdw_manager {struct sdw_bus bus;void *mmio,*dev;unsigned instance;};
#define to_amd_sdw(bus) ((bus)->owner)
struct effect{unsigned offset;u32 value;};
static struct effect effects[256];static unsigned ne,command_count;
static unsigned manager,page,write,device,address,length,fault;
static u32 upper,status;static u64 response,pending;
static bool has_pending;static unsigned delay;
static u8 pg[2];
static u8 aperture[0x4000];
static void record(unsigned at,u32 value){if(ne==256)abort();effects[ne++]=(struct effect){at,value};}
static u32 readl(void *pointer){
 unsigned at=(unsigned)((uintptr_t)pointer-(uintptr_t)aperture)-manager*0xc00;
 if(at==0x3240){if(has_pending&&now-pending>=delay){status=1;has_pending=false;}return status;}
 if(at==0x3238){if(!(status&1))abort();return response>>32;}
 if(at==0x323c){if(!(status&1))abort();return response;}
 abort();
}
static void writel(u32 value,void *pointer){
 unsigned absolute=(unsigned)((uintptr_t)pointer-(uintptr_t)aperture),at=absolute-manager*0xc00;
 record(absolute,value);
 if(at==0x3230){upper=value;return;}
 if(at==0x3240){if(value!=1||!(status&1))abort();status&=~1;return;}
 if(at!=0x3234||(status&3))abort();
 unsigned cmd=(upper>>12)&7,dev=(upper>>8)&15,addr=((upper&255)<<8)|(value>>24);u8 data=value>>7;
 if(dev!=device||(cmd!=2&&cmd!=3))abort();
 unsigned response_bits=1;
 bool last=command_count+1==length+(page?2:0);
 if(fault==3)response_bits=3;
 else if(last&&fault==1)response_bits=2;
 else if(last&&fault==2)response_bits=0;
 delay=last&&fault==4?2000:0;
 if(cmd==3&&(addr==0x48||addr==0x49))pg[addr-0x48]=data;
 u8 byte=cmd==2?(addr*37u+dev*13u+pg[0]*3u+pg[1]*7u)&255:0;
 response=0xa55a123400000000ULL|((u64)byte<<7)|response_bits;
 command_count++;status=2;has_pending=true;pending=now;
}
'''
suffix = r'''
int main(void){
 const unsigned devs[]={0,3,15},addresses[]={0,0x1234,0xffe0},lengths[]={1,2,8,17};unsigned cases=0;
 for(manager=0;manager<2;manager++)for(page=0;page<2;page++)for(write=0;write<2;write++)
 for(unsigned d=0;d<3;d++)for(unsigned a=0;a<3;a++)for(unsigned l=0;l<4;l++)for(fault=0;fault<5;fault++){
  device=devs[d];address=addresses[a];length=lengths[l];
  struct amd_sdw_manager m={.instance=manager,.mmio=aperture+manager*0xc00};m.bus.owner=&m;
  u8 bytes[17];for(unsigned i=0;i<length;i++)bytes[i]=write?((i*37u)^0x91):0xa5;
  struct sdw_msg msg={.addr=address,.len=length,.dev_num=device,.addr_page1=0x17,.addr_page2=0x23,
   .flags=write?SDW_MSG_FLAG_WRITE:SDW_MSG_FLAG_READ,.buf=bytes,.page=page};
  now=ne=command_count=upper=status=0;response=0;has_pending=false;pg[0]=pg[1]=0;
  int result=amd_sdw_xfer_msg(&m.bus,&msg);
  printf("A %u %u %u %u %u %u %u %d %u",manager,page,write,device,address,length,fault,result,ne);
  for(unsigned i=0;i<ne;i++)printf(" %u %u",effects[i].offset,effects[i].value);
  printf(" ");for(unsigned i=0;i<length;i++)printf("%02x",bytes[i]);puts("");cases++;
 }
 return cases==1440?0:1;
}
'''
unit = out / "linux-amd-soundwire.c"
unit.write_text(prefix + definitions + "\n" + response_enum + "\n" + flags + "\n" + msg
    + "\n" + macros + "\n\n".join(functions) + suffix)
compiler = Path(shutil.which("clang") or sys.exit("clang unavailable")).resolve()
binary = out / "linux-amd-soundwire"
command = [str(compiler), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
    "-Wno-sign-compare", "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
    str(unit.resolve()), "-o", str(binary.resolve())]
admission = dict(pin=PIN, sources=HASHES, fragments=fragments, script_sha256=digest(__file__),
    unit_sha256=digest(unit), compiler=str(compiler), compiler_sha256=digest(compiler), command=command,
    started=datetime.now(timezone.utc).isoformat(), limits=[
        "Seven whole unchanged command functions and four exact original polling macros;1440 immediate modeled message cases.",
        "Kernel/MMIO/peripheral/ktime/usleep/logging and manager owner layout are explicit modeled boundaries; no physical/ACP init/IRQ/stream/PM qualification.",
        "Comparison includes ACK1/NACK2/missing0/ACK+NACK3 and last-command response timeout. Native ACK-first matches donor; no physical response-validity claim.",
        "Native refuses foreign initialVALID instead of source discard, fails first page before second on bad firstpage, and stages whole reads instead of source partial publication.",
        "Native adds a whole transaction budget and refuses terminal observations at or after phase deadline; source macro performs one final observation after its greater-than deadline.",
        "Source SSP flag is ignored by these original functions; native API does not offer SSP synchronization. No silent support claim.",
    ])
(out / "admission.json").write_text(json.dumps(admission, indent=2) + "\n")
status = dict(compile="not started", execute="not started")
try:
    with (out / "compile.stdout").open("xb") as so, (out / "compile.stderr").open("xb") as se:
        result = subprocess.run(command, stdout=so, stderr=se, timeout=60)
    status["compile"] = result.returncode
    result.check_returncode()
    status["binary_before_execution_sha256"] = digest(binary)
    (out / "execution-admission.json").write_text(json.dumps(status, indent=2) + "\n")
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, env=env, timeout=60)
    status["execute"] = result.returncode
    (out / "stderr.log").write_text(result.stderr)
    (out / "records.txt").write_text(result.stdout)
    result.check_returncode()
    assert len(result.stdout.splitlines()) == 1440
    assert digest(binary) == status["binary_before_execution_sha256"]
finally:
    status["artifacts"] = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
    (out / "report.json").write_text(json.dumps(dict(admission=admission, status=status), indent=2) + "\n")
print(out)
