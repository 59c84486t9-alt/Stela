#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2015 Intel Corporation
"""Original classifier oracle for the native Intel bulk ISO comparison.

Compile the complete unchanged classifier and exact capability macros from
original pinned references, never a stand-in implementation or hardware test.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root, out = map(Path, sys.argv[1:])
paths = ["drivers/bluetooth/btintel.c", "include/net/bluetooth/hci_core.h", "include/net/bluetooth/hci.h"]
expected = [
    "9533d26e9815ce7fa5c6f3e88ec658cd34f4bf38b1cbed747c21d3f47ef5ed7c",
    "4e1e0c2928723997c8a3bba5de53ebe243048ad8225c3b36fffa47909bec1760",
    "856e428e37459ca08db49640a65dd5da50240a9ab641c3551b5466bd567ae83f",
]
for path, digest in zip(paths, expected):
    assert hashlib.sha256((root / path).read_bytes()).hexdigest() == digest, path
sources = {p: (root / p).read_text() for p in paths}


def definition(source, name):
    expression = r"^#define\s+" + re.escape(name) + r"(?=\(|[ \t])(?:\([^\n]*?\))?[^\n]*(?:\n[ \t]+[^\n]*)?"
    match = re.search(expression, source, re.M)
    if match is None:
        raise ValueError(name)
    # Only continuation lines belong to the macro; do not consume a following
    # independent indented declaration when a one-line definition was matched.
    lines = match[0].splitlines()
    return "\n".join(lines[:2] if lines[0].endswith("\\") else lines[:1])


driver = sources[paths[0]]
start = driver.index("static u8 btintel_classify_pkt_type(")
opening = driver.index("{", start)
depth = 0
for end in range(opening, len(driver)):
    depth += (driver[end] == "{") - (driver[end] == "}")
    if depth == 0:
        break
body = driver[start:end + 1]
definitions = [definition(driver, "BTINTEL_ISODATA_HANDLE_BASE")]
definitions += [definition(sources[paths[1]], n) for n in ["iso_capable", "cis_capable", "cis_central_capable", "cis_peripheral_capable", "bis_capable"]]
definitions += [definition(sources[paths[2]], n) for n in ["HCI_LE_CIS_CENTRAL", "HCI_LE_CIS_PERIPHERAL", "HCI_LE_ISO_BROADCASTER", "HCI_ACLDATA_PKT", "HCI_ISODATA_PKT", "hci_handle"]]
prelude = r'''
#include <stdint.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t __u16;
struct hci_dev { unsigned char le_features[8]; };
struct hci_acl_hdr { uint16_t handle,dlen; } __attribute__((packed));
struct sk_buff { unsigned char type; struct hci_acl_hdr header; };
#define hci_skb_pkt_type(s) ((s)->type)
#define hci_acl_hdr(s) (&(s)->header)
#define __le16_to_cpu(v) (v)
'''
runner = r'''
int main(void) {
    struct hci_dev d={0}; struct sk_buff s={0};
    const unsigned handles[]={0,1,0x8fe,0x8ff,0x900,0x901,0xeff,0xfff};
    for(unsigned feature=0;feature<256;feature++) {
        d.le_features[3]=feature;
        for(unsigned type=2;type<=5;type++) for(unsigned flags=0;flags<16;flags++) for(unsigned h=0;h<8;h++) {
            s.type=type;s.header.handle=handles[h]|(flags<<12);
            fputc(btintel_classify_pkt_type(&d,&s),stdout);
        }
    }
    return 0;
}
'''
out.mkdir(parents=True, exist_ok=False)
code = prelude + "\n".join(definitions) + "\n" + body + runner
(out / "oracle.c").write_text(code)
command = ["clang", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(out / "oracle.c"), "-o", str(out / "oracle")]
with (out / "compile.log").open("w") as log:
    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=30, check=True)
with (out / "run.log").open("w") as log:
    result = subprocess.run([str(out / "oracle")], stdout=subprocess.PIPE, stderr=log, timeout=10, check=True)
assert len(result.stdout) == 131072
(out / "classifier-records.bin").write_bytes(result.stdout)
(out / "receipt.json").write_text(json.dumps({
    "pin": "cc9de5d4b5ab6459f5774946aa3195ad51236fa8",
    "source": {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths},
    "function_sha256": hashlib.sha256(body.encode()).hexdigest(),
    "function_bytes": len(body.encode()), "compile_command": command,
    "records": len(result.stdout), "trace_sha256": hashlib.sha256(result.stdout).hexdigest(),
    "scope": "unchanged classifier/capability predicates on logical HCI objects; no Stela implementation, native USB or physical ISO qualification",
}, indent=2) + "\n")
