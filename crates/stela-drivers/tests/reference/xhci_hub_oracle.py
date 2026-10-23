#!/usr/bin/env python3
"""Run pinned unchanged hub descriptor/power/status/depth and rate helpers.

Usage: xhci_hub_oracle.py FLAT_DONOR_DIRECTORY NEW_OUTPUT_DIRECTORY
Synchronous successful control requests, logical hub objects and bounded SSP
attributes are fixture boundaries. No Linux hardware, workqueue or LPM runs.
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
    "ch9.h": "56ac789006af0e76a0cdfc671540aabc8da3f1edcab0c034518e2314c3e72ff8",
}
text = {}
for name, sha in expected.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sha, name
    text[name] = raw.decode()
out.mkdir(exist_ok=False, parents=True)
fragments = []


def function(file, name):
    raw = text[file]
    match = re.search(r"^(?:static\s+)?(?:inline\s+)?(?:unsigned|bool|int|enum usb_ssp_rate)\s+" + name + r"\([^;{}]*?\)\n\{", raw, re.M)
    assert match, (file, name)
    stop, depth = match.end(), 1
    while depth:
        depth += (raw[stop] == "{") - (raw[stop] == "}")
        stop += 1
    body = raw[match.start():stop]
    fragments.append(dict(file=file, name=name, start=match.start(), end=stop,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


def structure(file, name):
    raw = text[file]
    start = raw.index("struct " + name + " {")
    stop, depth = raw.index("{", start) + 1, 1
    while depth:
        depth += (raw[stop] == "{") - (raw[stop] == "}")
        stop += 1
    return raw[start:raw.index(";", stop) + 1]


functions = "\n".join(function(file, name) for file, name in [
    ("hub.h", "hub_is_superspeed"), ("hub.h", "hub_is_superspeedplus"),
    ("hub.h", "hub_power_on_good_delay"), ("hub.c", "get_hub_descriptor"),
    ("hub.c", "get_port_status"), ("hub.c", "hub_port_warm_reset_required"),
    ("hub.c", "get_port_ssp_rate"),
])
depth_start = text["hub.c"].index("\t\t\tret = usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),\n\t\t\t\t\tHUB_SET_DEPTH")
depth_end = text["hub.c"].index(";", depth_start) + 1
depth_body = text["hub.c"][depth_start:depth_end]
fragments.append(dict(file="hub.c", name="hub_activate_set_depth", start=depth_start,
                      end=depth_end, sha256=hashlib.sha256(depth_body.encode()).hexdigest()))
structs = structure("ch11.h", "usb_hub_descriptor") + "\n" + structure("ch9.h", "usb_ssp_cap_descriptor")
definitions = {}
for raw in text.values():
    lines = raw.splitlines(keepends=True)
    at = 0
    while at < len(lines):
        match = re.match(r"^#define[ \t]+(\w+)", lines[at])
        body = lines[at]
        while body.endswith("\\\n"):
            at += 1
            body += lines[at]
        if match:
            definitions[match[1]] = body.rstrip("\n")
        at += 1
tokens = set(re.findall(r"\bUSB_[A-Z0-9_]+\b|\bHUB_SET_DEPTH\b", functions + structs + depth_body))
tokens.difference_update(["USB_CTRL_GET_TIMEOUT", "USB_CTRL_SET_TIMEOUT", "USB_SSP_GEN_UNKNOWN", "USB_SSP_GEN_2x1", "USB_SSP_GEN_2x2", "USB_SSP_GEN_1x2"])
todo = list(tokens)
while todo:
    name = todo.pop()
    assert name in definitions, name
    for dependency in re.findall(r"\bUSB_[A-Z0-9_]+\b", definitions[name]):
        if dependency not in tokens:
            tokens.add(dependency)
            todo.append(dependency)
macros = "\n".join(definitions[name] for name in sorted(tokens))
header = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t __u8; typedef uint16_t __le16; typedef uint32_t __le32;
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define __DECLARE_FLEX_ARRAY(T,N) T N[32]
#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)
#define FIELD_GET(mask,value) (((value)&(mask)) >> __builtin_ctz(mask))
#define max(a,b) ((a)>(b)?(a):(b))
#define USB_CTRL_GET_TIMEOUT 5000
#define USB_CTRL_SET_TIMEOUT 5000
enum usb_ssp_rate {USB_SSP_GEN_UNKNOWN,USB_SSP_GEN_2x1,USB_SSP_GEN_2x2,USB_SSP_GEN_1x2};
'''
logical = r'''
struct usb_host_bos {struct usb_ssp_cap_descriptor *ssp_cap;};
struct usb_device {struct {u8 bDeviceProtocol;__le16 bcdUSB;} descriptor;
 struct usb_device *parent;struct usb_host_bos *bos;unsigned level;};
struct usb_hub {struct usb_device *hdev;struct usb_hub_descriptor *descriptor;unsigned long warm_reset_bits[1];};
static int test_bit(int bit,unsigned long *bits) {return !!(*bits & (1ul<<bit));}
static int usb_rcvctrlpipe(struct usb_device *dev,int ep) {(void)dev;return ep;}
static int usb_sndctrlpipe(struct usb_device *dev,int ep) {(void)dev;return ep;}
static unsigned request_log[5];
static int usb_control_msg(struct usb_device *dev,int pipe,int request,int type,int value,int index,void *data,int length,int timeout) {
 (void)dev;(void)pipe;(void)data;(void)timeout;
 request_log[0]=type;request_log[1]=request;request_log[2]=value;request_log[3]=index;request_log[4]=length;return length;
}
'''
c = header + macros + "\n" + structs + "\n" + logical + functions
c += "\nstatic int set_depth(struct usb_device *hdev) { int ret;\n" + depth_body + "\nreturn ret;}\n"
c += r'''
static void wire(char tag) {printf("%c %u %u %u %u %u\n",tag,request_log[0],request_log[1],request_log[2],request_log[3],request_log[4]);}
int main(void) {
 struct usb_hub_descriptor descriptor={0};struct usb_device parent={0};
 struct usb_device dev={.descriptor={3,0x310},.parent=&parent};
 struct usb_hub hub={.hdev=&dev,.descriptor=&descriptor};
 for(unsigned p=0;p<256;p++){descriptor.bPwrOn2PwrGood=p;printf("D %u %u\n",p,hub_power_on_good_delay(&hub));}
 for(unsigned link=0;link<=10;link++)printf("W %u %u\n",link,hub_port_warm_reset_required(&hub,1,link<<5));
 get_hub_descriptor(&dev,&descriptor);wire('G');
 for(unsigned p=1;p<=15;p+=14)for(unsigned ext=0;ext<2;ext++){get_port_status(&dev,p,NULL,ext?2:0,ext?8:4);wire('P');}
 for(unsigned depth=0;depth<5;depth++){dev.level=depth+1;set_depth(&dev);wire('H');}
 const unsigned rates[]={0,1,4,5,9,10,20,100,255};
 for(unsigned r=0;r<sizeof(rates)/sizeof(*rates);r++)for(unsigned exponent=0;exponent<4;exponent++)
  for(unsigned lanes=1;lanes<=3;lanes++)for(unsigned asymmetric=0;asymmetric<2;asymmetric++){
   struct usb_ssp_cap_descriptor capability={.bmAttributes=1};struct usb_host_bos bos={.ssp_cap=&capability};dev.bos=&bos; if(!hub_is_superspeedplus(&dev))return 2;
   capability.bmSublinkSpeedAttr[0]=1|exponent<<4|asymmetric<<6|1<<14|rates[r]<<16;
   capability.bmSublinkSpeedAttr[1]=1|exponent<<4|(asymmetric+2)<<6|1<<14|rates[r]<<16;
   unsigned extended=0x11|(lanes-1)<<8|(lanes-1)<<12;
   printf("S %u %u %u %u %u\n",rates[r],exponent,lanes,asymmetric,get_port_ssp_rate(&dev,extended)!=USB_SSP_GEN_UNKNOWN);
  }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
(out / "fragments.json").write_text(json.dumps(fragments, indent=2) + "\n")
subprocess.run(["clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(out / "oracle")], stdout=trace, check=True)
raw = (out / "trace.txt").read_bytes()
assert len(raw.splitlines()) == 493
print(json.dumps(dict(rows=493,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())))
