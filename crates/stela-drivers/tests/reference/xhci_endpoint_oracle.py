#!/usr/bin/env python3
"""Run six unchanged pinned Linux endpoint interval/burst helpers under sanitizers.

Generated C, binary and trace must remain ignored. This compares valid bulk and
interrupt endpoint field mappings, not descriptor validation or controller I/O.
Usage: python3 xhci_endpoint_oracle.py XHCI_MEM_C OUTPUT_DIRECTORY
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
assert hashlib.sha256(source.read_bytes()).hexdigest() == "abfe6f6f70bdeaf7a279a734bdab034ef014f329785ccb8c5f5cf3e763320198"
text = source.read_text()
out.mkdir(parents=True, exist_ok=True)


def function(name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


names = ["xhci_parse_exponent_interval", "xhci_microframes_to_exponent", "xhci_parse_microframe_interval", "xhci_parse_frame_interval", "xhci_get_endpoint_interval", "xhci_get_endpoint_max_burst"]
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2008 Intel Corp. Author: Sarah Sharp.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#define USB_SPEED_LOW 1
#define USB_SPEED_FULL 2
#define USB_SPEED_HIGH 3
#define USB_SPEED_SUPER 4
#define USB_SPEED_SUPER_PLUS 5
#define clamp_val(v,a,b) ((v)<(a)?(a):((v)>(b)?(b):(v)))
#define dev_warn(...) ((void)0)
#define dev_dbg(...) ((void)0)
#define fallthrough __attribute__((fallthrough))
#define BUG() abort()
struct usb_endpoint_descriptor { unsigned char bEndpointAddress, bmAttributes, bInterval; unsigned short wMaxPacketSize; };
struct usb_host_endpoint { struct usb_endpoint_descriptor desc; struct { unsigned char bMaxBurst; } ss_ep_comp; };
struct usb_device { int speed; };
static unsigned fls(unsigned v) { return v ? 32-__builtin_clz(v) : 0; }
static bool usb_endpoint_xfer_control(const struct usb_endpoint_descriptor *d) { return (d->bmAttributes & 3)==0; }
static bool usb_endpoint_xfer_isoc(const struct usb_endpoint_descriptor *d) { return (d->bmAttributes & 3)==1; }
static bool usb_endpoint_xfer_bulk(const struct usb_endpoint_descriptor *d) { return (d->bmAttributes & 3)==2; }
static bool usb_endpoint_xfer_int(const struct usb_endpoint_descriptor *d) { return (d->bmAttributes & 3)==3; }
static bool usb_endpoint_is_hs_isoc_double(const struct usb_device *u, const struct usb_host_endpoint *e) { (void)u; (void)e; return false; }
static unsigned usb_endpoint_maxp_mult(const struct usb_endpoint_descriptor *d) { return 1+((d->wMaxPacketSize>>11)&3); }
'''
main = r'''
int main(void) {
    for (int speed=1; speed<=5; speed++) for(int kind=2;kind<=3;kind++) {
        if (speed==1 && kind==2) continue;
        for (int interval=kind==2?0:1;interval<=(kind==3 && speed>=3?16:255);interval++)
        for (int burst=0;burst<=(speed>=4?15:(speed==3 && kind==3?2:0));burst++) {
            struct usb_device u={.speed=speed};
            unsigned packet=speed>=4?1024:(speed==3?(kind==2?512:1024):8);
            if (speed==3 && kind==3) packet|=burst<<11;
            struct usb_host_endpoint e={.desc={.bEndpointAddress=0x81,.bmAttributes=kind,.bInterval=interval,.wMaxPacketSize=packet},.ss_ep_comp={.bMaxBurst=burst}};
            printf("%d %d %u %d %d %u %u\n",speed,kind,packet,interval,burst,xhci_get_endpoint_interval(&u,&e),xhci_get_endpoint_max_burst(&u,&e));
        }
    }
    return 0;
}
'''
unit = out / "linux-xhci-endpoint.c"
unit.write_text(prelude + "\n" + "\n".join(function(n) for n in names) + main)
exe = out / "linux-xhci-endpoint"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True)
print(out / "trace.txt")
