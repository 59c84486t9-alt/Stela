#!/usr/bin/env python3
"""Extract pinned unchanged hub link-request and suspend-status helpers.

Usage: xhci_hub_power_oracle.py FLAT_DONOR_DIRECTORY NEW_OUTPUT_DIRECTORY
The fixture records set_port_feature; it does not model Linux PM, hardware or
async request completion. Never accept a trace as physical suspend evidence.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
expected = {
    "hub.c": "423fb46bfc93821994a414e2e0511add525ef225dbc0dd3331d017452038988a",
    "hub.h": "285273ab8094f7495747805c989c9d49db83ae0d40927f70f93e4b39652c2e22",
    "ch11.h": "df7cbd5071e44fd2c9140541e99c00ac471d2f158ecd822273bff300c3c23256",
    "usb.h": "edfaedd90cbb28ff7d5058b09d473635d06c4f7a6a8d70f46b39f55fc1ca3750",
}
text = {}
for name, sha in expected.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sha, name
    text[name] = raw.decode()
fragments = []


def function(file, name):
    raw = text[file]
    match = re.search(r"^static\s+(?:inline\s+)?int\s+" + name + r"\([^;{}]*?\)\n\{", raw, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (raw[end] == "{") - (raw[end] == "}")
        end += 1
    body = raw[match.start():end]
    fragments.append(dict(file=file, name=name, start=match.start(), end=end,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


functions = "\n".join(function(file, name) for file, name in [
    ("hub.h", "hub_is_superspeed"),
    ("hub.c", "hub_set_port_link_state"),
    ("hub.c", "port_is_suspended"),
])
macros = []
for name in ["USB_HUB_PR_SS", "USB_PORT_FEAT_LINK_STATE", "USB_PORT_STAT_LINK_STATE",
             "USB_SS_PORT_LS_U3", "USB_PORT_STAT_SUSPEND", "USB_RESUME_TIMEOUT"]:
    found = [line for raw in text.values() for line in raw.splitlines()
             if re.match(r"^#define\s+" + name + r"\s+", line)]
    assert len(found) == 1, name
    macros.append(found[0])
c = r'''
#include <stdio.h>
struct usb_device { struct { unsigned bDeviceProtocol; } descriptor; };
struct usb_hub { struct usb_device *hdev; };
static unsigned request_index, request_feature;
static int set_port_feature(struct usb_device *dev, int index, int feature) {
 (void)dev; request_index=index; request_feature=feature; return 0;
}
'''
c += "\n".join(macros) + "\n" + functions
c += r'''
int main(void) {
 struct usb_device dev={0}; struct usb_hub hub={&dev};
 printf("T %u\n",USB_RESUME_TIMEOUT);
 for(unsigned ss=0;ss<2;ss++) {
  dev.descriptor.bDeviceProtocol=ss?USB_HUB_PR_SS:0;
  for(unsigned status=0;status<65536;status++)
   printf("S %u %u %u\n",ss,status,port_is_suspended(&hub,status));
 }
 for(unsigned port=1;port<=15;port++) for(unsigned suspend=0;suspend<2;suspend++) {
  if(hub_set_port_link_state(&hub,port,suspend?USB_SS_PORT_LS_U3:0))return 1;
  printf("L %u %u %u %u\n",port,suspend,request_feature,request_index);
 }
 return 0;
}
'''
out.mkdir(exist_ok=False, parents=True)
(out / "oracle.c").write_text(c)
(out / "fragments.json").write_text(json.dumps(fragments, indent=2) + "\n")
subprocess.run(["clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(out / "oracle")], stdout=trace, check=True)
raw = (out / "trace.txt").read_bytes()
assert len(raw.splitlines()) == 131103
print(json.dumps(dict(rows=131103, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())))
