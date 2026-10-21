#!/usr/bin/env python3
"""Run unchanged pinned Linux cdc_ncm_fix_modulus for ordinary Ethernet.

Usage: cdc_ncm_alignment_oracle.py CDC_NCM_C OUTPUT_DIRECTORY
Only admitted, valid power-of-two divisors/alignments are compared. The shim
supplies metadata, an ordinary 14-byte Ethernet header and discarded debug
logging. It does not execute USB traffic or full NCM initialization.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
source_bytes = source.read_bytes()
assert hashlib.sha256(source_bytes).hexdigest() == "4e6a3df21dd32c5b08695173fb9bc90744368ff6c657515991ff52d74572523b"
text = source_bytes.decode()
match = re.search(r"^static void cdc_ncm_fix_modulus\([^;{}]*\)\n\{", text, re.M)
assert match
at, depth = match.end(), 1
while depth:
    depth += (text[at] == "{") - (text[at] == "}")
    at += 1
function = text[match.start():at]
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) ST-Ericsson 2010-2012
// Original author: Hans Petter Selasky <hans.petter.selasky@stericsson.com>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
#define USB_CDC_NCM_NDP_ALIGN_MIN_SIZE 4
#define dev_dbg(...) ((void)0)
struct cdc_ncm_ctx {u32 tx_ndp_modulus,tx_modulus,tx_remainder,tx_max;};
struct usbnet {uintptr_t data[1];};
static u32 cdc_ncm_eth_hlen(struct usbnet *dev){(void)dev;return 14;}
'''
main = r'''
int main(void){
  for(u32 divisor=4;divisor<=1024;divisor*=2)
    for(u32 remainder=0;remainder<divisor;remainder++)
      for(u32 alignment=4;alignment<=8;alignment*=2){
        struct cdc_ncm_ctx ctx={alignment,divisor,remainder,8192};
        struct usbnet dev={{(uintptr_t)&ctx}};
        cdc_ncm_fix_modulus(&dev);
        printf("%u %u %u %u %u\n",divisor,remainder,alignment,ctx.tx_remainder,ctx.tx_ndp_modulus);
      }
  return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
c_file = out / "oracle.c"
c_file.write_text(prelude + function + "\n" + main)
subprocess.run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", str(c_file), "-o", str(out / "oracle")], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(out / "oracle")], stdout=trace, check=True)
trace_bytes = (out / "trace.txt").read_bytes()
manifest = {
    "linux_commit": "a804c5742bff224d4cb4d25dd383554d598be32b",
    "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
    "unchanged_function_sha256": hashlib.sha256(function.encode()).hexdigest(),
    "generated_c_sha256": hashlib.sha256(c_file.read_bytes()).hexdigest(),
    "trace_sha256": hashlib.sha256(trace_bytes).hexdigest(),
    "cases": len(trace_bytes.splitlines()),
    "limits": "Metadata-only cdc_ncm_fix_modulus; Ethernet header stub 14; no USB, MBIM or complete initialization",
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
