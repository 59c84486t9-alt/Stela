#!/usr/bin/env python3
"""Run unchanged Linux ICM driver-ready parsers and actual control TX.

Usage: thunderbolt_icm_oracle.py PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Firmware responses/request transport are capture stubs. This tests actual
source parsing and wire framing, not firmware startup, router reachability,
security authorization, native IOMMU attachment or physical qualification.
Generated C, executable and trace remain ignored. Requires SSE4.2 host CRC32C.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
hashes = {
    "icm.c": "cce0970d8ea1804fb6bf1e25319760d1988a642a3bce25221805479d147804dc",
    "ctl.c": "82454a95f67942bbe6a3990cb9f3f54a4e5d8229020f4c95d4277f2ae1aee808",
    "tb_msgs.h": "553b546d7945f268c08659863813e897bf12e7ebd89b6da9fb9805fcc067b602",
    "include_linux_thunderbolt.h": "77314f7a9762cbd0296024a1cfe7a1fc54c9ef2568db0229ad614758e1cd22eb",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)

def function(filename, name):
    text = texts[filename]
    match = re.search(r"^(?:static |int )[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]

def declaration(filename, prefix):
    return re.search(re.escape(prefix) + r" \{.*?\n\};", texts[filename], re.S).group()

prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2017-2018 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <nmmintrin.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint32_t __be32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define WARN_ON(v) do { if(v) abort(); } while(0)
#define TB_FRAME_SIZE 256
#define ICM_TIMEOUT 5000
#define ICM_RETRIES 3
#define tb_ctl_WARN(...) ((void)0)
#define tb_ctl_dbg(...) ((void)0)
#define trace_tb_tx(...) ((void)0)
static u32 cpu_to_be32(u32 v) { return __builtin_bswap32(v); }
static u32 crc32c(u32 crc,const void *data,size_t n) {
 const u8 *p=data; while(n--) crc=_mm_crc32_u8(crc,*p++); return crc;
}
static void cpu_to_be32_array(void *out,const void *in,size_t n) {
 while(n--) { u32 v;memcpy(&v,in,4);v=cpu_to_be32(v);memcpy(out,&v,4);in+=4;out+=4; }
}
struct tb_ring {};
struct ring_frame { unsigned size,sof,eof; void (*callback)(struct tb_ring *,struct ring_frame *,bool); };
struct tb_ctl { struct tb_ring *tx; int index; };
struct ctl_pkg { struct tb_ctl *ctl; void *buffer; struct ring_frame frame; };
static struct ctl_pkg capture;
static struct ctl_pkg *tb_ctl_pkg_alloc(struct tb_ctl *ctl) {
 static unsigned char buffer[256]; memset(&capture,0,sizeof(capture));memset(buffer,0,sizeof(buffer));
 capture.ctl=ctl;capture.buffer=buffer;return &capture;
}
static void tb_ctl_pkg_free(struct ctl_pkg *p) { (void)p; }
static void tb_ctl_tx_callback(struct tb_ring *r,struct ring_frame *f,bool c) { (void)r;(void)f;(void)c; }
static int tb_ring_tx(struct tb_ring *r,struct ring_frame *f) { (void)r;(void)f;return 0; }
struct tb { struct tb_ctl *ctl; };
static unsigned info,flags,deadline,retries;
'''
declarations = "\n".join([
    declaration("include_linux_thunderbolt.h", "enum tb_cfg_pkg_type"),
    declaration("include_linux_thunderbolt.h", "enum tb_security_level"),
    declaration("tb_msgs.h", "enum icm_pkg_code"),
    *[declaration("tb_msgs.h", "struct " + name) for name in [
        "icm_pkg_header", "icm_pkg_driver_ready", "icm_ar_pkg_driver_ready_response",
        "icm_tr_pkg_driver_ready_response"]],
])
macros = "\n".join(line for line in texts["tb_msgs.h"].splitlines() if line.startswith((
    "#define ICM_AR_FLAGS_RTD3", "#define ICM_AR_INFO_", "#define ICM_TR_FLAGS_RTD3", "#define ICM_TR_INFO_")))
request_stub = r'''
static int icm_request(struct tb *tb,const void *request,size_t request_size,void *reply,size_t reply_size,size_t packets,unsigned nr,unsigned timeout) {
 if(request_size!=4 || packets!=1 || (reply_size!=8 && reply_size!=16)) abort();
 if(tb_ctl_tx(tb->ctl,request,request_size,TB_CFG_PKG_ICM_CMD)) abort();
 u32 words[4]={3U|(flags<<8)|(1U<<24),info<<16,0x12345678,0xabcdef01};
 memcpy(reply,words,reply_size);deadline=timeout;retries=nr;return 0;
}
'''
main = r'''
int main(void) {
 struct tb_ctl ctl={0};struct tb tb={.ctl=&ctl};
 for(unsigned family=0;family<4;family++) for(unsigned i=0;i<512;i++) for(unsigned f=0;f<2;f++) {
  info=(i*40503U+0x0081U)&0xffffU;flags=f?64:0;
  enum tb_security_level security=99;u8 proto=99;size_t acl=999;bool rpm=false;int ret;
  if(family==0) ret=icm_ar_driver_ready(&tb,&security,&proto,&acl,&rpm);
  else if(family==2) ret=icm_icl_driver_ready(&tb,&security,&proto,&acl,&rpm);
  else ret=icm_tr_driver_ready(&tb,&security,&proto,&acl,&rpm);
  if(ret) abort();
  printf("I %u %u %u %u %u %zu %u %u %u %u %u %u ",family,info,flags,security,proto,acl,rpm,deadline,retries,capture.frame.eof,capture.frame.sof,capture.frame.size);
  for(unsigned j=0;j<capture.frame.size;j++) printf("%02x",((u8*)capture.buffer)[j]);
  puts("");
 }
}
'''
unit = out / "linux-thunderbolt-icm.c"
unit.write_text(prelude + declarations + "\n" + macros + "\n" + "\n".join([
    function("ctl.c", "tb_crc"), function("ctl.c", "tb_ctl_tx"), request_stub,
    function("icm.c", "icm_ar_driver_ready"), function("icm.c", "icm_tr_driver_ready"),
    function("icm.c", "icm_icl_driver_ready"), main,
]))
exe = out / "linux-thunderbolt-icm"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-msse4.2", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
trace = out / "trace.txt"
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
