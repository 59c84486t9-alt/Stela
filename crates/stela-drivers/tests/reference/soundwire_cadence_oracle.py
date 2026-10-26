#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright(c) 2015-17 Intel Corporation.
"""Execute six unchanged Cadence SoundWire synchronous command functions.

Usage: soundwire_cadence_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT
Command MMIO, peripheral byte responses and completion/IRQ boundaries are
modeled. No physical link, kernel ABI, discovery or audio stream qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "drivers/soundwire/cadence_master.c": "0513bb7ae19ad5618adf693bda355980a09ba2749e126378b66cdcd2a6c0bb72",
    "drivers/soundwire/bus.h": "c25915dc7b0b0357fd1260229b246c5edbf904e3f956bf8f5d7aa1473fe25663",
    "include/linux/soundwire/sdw.h": "789b9467f308ec95c6d0ec45564dd8dfac1d976bf4fbad01b438ba624c14ded2",
    "include/linux/soundwire/sdw_registers.h": "a8d67bb73e45506f66bb36bd3f8b54971eb807d1ebc6b90069b47fe502836e54",
}
source, out = map(Path, sys.argv[1:])
digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
texts = {}
for p, expected in HASHES.items():
    assert digest(source / p) == expected, p
    texts[p] = (source / p).read_text()
out.mkdir(exist_ok=False, parents=True)
original = texts["drivers/soundwire/cadence_master.c"]
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


functions = [function(name) for name in [
    "cdns_fill_msg_resp", "cdns_read_response", "_cdns_xfer_msg",
    "cdns_program_scp_addr", "cdns_prep_msg", "cdns_xfer_msg",
]]
response_enum = re.search(r"enum sdw_command_response \{.*?\n\};", texts["include/linux/soundwire/sdw.h"], re.S).group()
bus = texts["drivers/soundwire/bus.h"]
flag_enum = re.search(r"enum \{\n\s*SDW_MSG_FLAG_READ.*?\n\};", bus, re.S).group()
message_struct = re.search(r"struct sdw_msg \{.*?\n\};", bus, re.S).group()
macros = "\n".join(line for line in original.splitlines() if line.startswith("#define CDNS_") and "\\" not in line)
macros += "\n" + "\n".join(line for line in texts["include/linux/soundwire/sdw_registers.h"].splitlines() if re.match(r"#define SDW_SCP_ADDRPAGE[12]\s", line))
prefix = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2015-17 Intel Corporation.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
#define BIT(n) (1u<<(n))
#define GENMASK(h,l) ((~0u<<(l)) & (~0u>>(31-(h))))
#define FIELD_PREP(mask,v) (((u32)(v)<<__builtin_ctz(mask))&(mask))
#define FIELD_GET(mask,v) (((u32)(v)&(mask))>>__builtin_ctz(mask))
#define ARRAY_SIZE(v) (sizeof(v)/sizeof((v)[0]))
#define BUILD_BUG_ON(v) _Static_assert(!(v), "original bound")
#define EXPORT_SYMBOL(v)
#define dev_vdbg(...) ((void)0)
#define dev_dbg_ratelimited(...) ((void)0)
#define dev_err_ratelimited(...) ((void)0)
#define dev_err(...) ((void)0)
#define dev_warn(...) ((void)0)
#define msecs_to_jiffies(v) (v)
struct sdw_bus {struct sdw_cdns *cdns;};
struct sdw_cdns {struct sdw_bus bus;unsigned ip_offset,msg_count,tx_complete;u32 response_buf[34];void *dev;};
struct effect {unsigned offset;u32 value;};
static struct effect effects[256];static unsigned ne;
static u32 queued[8],responses[8];static unsigned nq,nr,ri,wire_count,fail_at;
static unsigned response_fault,watermark;static u8 pg[2],device;
static struct sdw_cdns *active;
static struct sdw_cdns *bus_to_cdns(struct sdw_bus *bus) {return bus->cdns;}
static void record(unsigned offset,u32 value) {if(ne==256)abort();effects[ne++]=(struct effect){offset,value};}
static u32 cdns_readl(struct sdw_cdns *cdns,int offset) {(void)cdns;if(offset!=0x7c)abort();return nr;}
static void cdns_writel(struct sdw_cdns *cdns,int offset,u32 value) {
 (void)cdns;record(offset,value);if(offset==0x78)watermark=value;else if(offset!=0x44)abort();
}
static void cdns_ip_writel(struct sdw_cdns *cdns,int offset,u32 value) {
 if(offset!=0x80+(int)nq*4||nq==8)abort();record(cdns->ip_offset+offset,value);queued[nq++]=value;
}
static u32 cdns_ip_readl(struct sdw_cdns *cdns,int offset) {
 (void)cdns;if(offset!=0x80+(int)ri*4||ri>=nr)abort();u32 value=responses[ri++];if(ri==nr){nr=0;ri=0;}return value;
}
static unsigned long complete_transfer(void);
#define wait_for_completion_timeout(completion,timeout) ((void)(completion),(void)(timeout),complete_transfer())
'''
suffix = r'''
static unsigned long complete_transfer(void) {
 if(nq!=watermark||nq==0||nq>8)abort();nr=nq;ri=0;
 for(unsigned i=0;i<nq;i++){
  u32 word=queued[i];unsigned at=(word>>8)&65535,cmd=(word>>28)&7;u8 data=word;
  if(((word>>24)&15)!=device)abort();
  u32 response=1;
  if(response_fault&&wire_count==fail_at)response=response_fault==2?0:2;
  else if(cmd==3){if(at==0x48||at==0x49)pg[at-0x48]=data;}
  else if(cmd==2)response|=((at*37u+device*13u+pg[0]*3u+pg[1]*7u)&255)<<8;
  else abort();
  responses[i]=response;++wire_count;
 }
 nq=0;cdns_read_response(active);cdns_writel(active,0x44,4);return 1;
}
int main(void){
 const unsigned devs[]={0,3,15},addresses[]={0,0x1234,0xffd0},lengths[]={1,2,8,9,17};
 unsigned cases=0;
 for(unsigned layout=0;layout<2;layout++)for(unsigned page=0;page<2;page++)
 for(unsigned read=0;read<2;read++)for(unsigned sync=0;sync<2;sync++)
 for(unsigned d=0;d<3;d++)for(unsigned a=0;a<3;a++)for(unsigned l=0;l<5;l++)for(unsigned fault=0;fault<4;fault++){
  struct sdw_cdns cdns={0};cdns.bus.cdns=&cdns;cdns.ip_offset=layout?0x4000:0;active=&cdns;
  u8 bytes[17];for(unsigned i=0;i<lengths[l];i++)bytes[i]=read?0xa5:((i*37u)^0x91);
  struct sdw_msg msg={.addr=addresses[a],.len=lengths[l],.dev_num=devs[d],.addr_page1=0x17,.addr_page2=0x23,
   .flags=read?SDW_MSG_FLAG_READ:SDW_MSG_FLAG_WRITE,.buf=bytes,.ssp_sync=sync,.page=page};
  ne=nq=nr=ri=wire_count=watermark=0;pg[0]=pg[1]=0;device=msg.dev_num;response_fault=fault;
  fail_at=fault==3?lengths[l]+(page?2:0)-1:0;
  int result=cdns_xfer_msg(&cdns.bus,&msg);
  printf("C %u %u %u %u %u %u %u %u %d %u",layout,page,read,sync,device,addresses[a],lengths[l],fault,result,ne);
  for(unsigned i=0;i<ne;i++)printf(" %u %u",effects[i].offset,effects[i].value);
  printf(" ");for(unsigned i=0;i<lengths[l];i++)printf("%02x",bytes[i]);puts("");++cases;
 }
 return cases==2880?0:1;
}
'''
unit = out / "linux-cadence.c"
unit.write_text(prefix + response_enum + "\n" + flag_enum + "\n" + message_struct + "\n" + macros + "\n" + "\n\n".join(functions) + suffix)
compiler = Path(shutil.which("clang") or sys.exit("clang unavailable")).resolve()
binary = out / "linux-cadence"
command = [str(compiler), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(unit.resolve()), "-o", str(binary.resolve())]
admission = dict(pin=PIN, sources=HASHES, fragments=fragments, script_sha256=digest(__file__), unit_sha256=digest(unit), compiler=str(compiler), compiler_sha256=digest(compiler), command=command, started=datetime.now(timezone.utc).isoformat(),
    limits=["Six complete unchanged synchronous functions,2880 modeled message cases; no physical/kernel ABI/IRQ/frame/audio qualification", "Completion primitive models source IRQ response drain then RX_WL W1C; native adapts this to excluded-IRQ polling", "Comparison covers ACK1/NACK2/missing0 only. Native additionally refuses ACK+NACK3; donor page function accepts it because NACK is checked only when ACK is absent. No physical validity claim follows from that software anomaly.", "Native stages complete reads while source publishes completed prefixes; error rows compare effects/refusal, not identical partial caller outputs", "Native refuses address rollover and65536-byte messages; original sdw_msg.len is16bit", "Upstream signed loop comparisons compiled with Wno-sign-compare; full function bytes unchanged"])
(out / "admission.json").write_text(json.dumps(admission, indent=2) + "\n")
status = dict(compile="not started", execute="not started")
try:
    with (out / "compile.stdout").open("xb") as so, (out / "compile.stderr").open("xb") as se:
        result = subprocess.run(command, stdout=so, stderr=se, timeout=60)
    status["compile"] = result.returncode
    result.check_returncode()
    status["binary_before_execution_sha256"] = digest(binary)
    (out / "execution-admission.json").write_text(json.dumps(status, indent=2) + "\n")
    env = dict(os.environ, ASAN_OPTIONS="halt_on_error=1:detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    with (out / "records.txt").open("xb") as so, (out / "execute.stderr").open("xb") as se:
        result = subprocess.run([str(binary.resolve())], stdout=so, stderr=se, env=env, timeout=20)
    status["execute"] = result.returncode
    result.check_returncode()
    assert len((out / "records.txt").read_text().splitlines()) == 2880
    assert all(digest(source / p) == h for p, h in HASHES.items())
    assert digest(unit) == admission["unit_sha256"] and digest(binary) == status["binary_before_execution_sha256"]
    status.update(result="PASS", records=2880)
except BaseException as error:
    status.update(result="FAIL", error=repr(error))
    raise
finally:
    status["artifacts"] = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
    (out / "report.json").write_text(json.dumps(status, indent=2) + "\n")
print(out / "report.json")
