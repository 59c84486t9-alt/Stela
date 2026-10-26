#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
"""Run unchanged pinned btusb_work on bounded logical CVSD voice states.

Usage: realtek_sco_oracle.py BTUSB_C NEW_OUTPUT_DIRECTORY
No Cargo, download, USB or hardware access. Output directories are immutable.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == "7ec535a89ffda9cd0c9fb060ab0db7a45696816615e60dc395fc8f6297159030"
text = data.decode()
start = text.index("static void btusb_work(")
opening = text.index("{", start)
depth = 0
for end in range(opening, len(text)):
    if text[end] == "{":
        depth += 1
    elif text[end] == "}":
        depth -= 1
        if depth == 0:
            break
function = text[start:end + 1]
out.mkdir(parents=True, exist_ok=False)
pre = r'''
// Unchanged GPL-2.0-or-later Linux btusb_work below; logical stubs only.
#include <stddef.h>
#include <stdio.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define BTUSB_DID_ISO_RESUME 0
#define BTUSB_ISOC_RUNNING 1
#define BTUSB_USE_ALT3_FOR_WBS 2
#define HCI_NOTIFY_ENABLE_SCO_CVSD 1
#define HCI_NOTIFY_ENABLE_SCO_TRANSP 2
#define bt_dev_err(...) ((void)0)
struct work_struct { int unused; };
struct btusb_data;
struct hci_dev { unsigned voice_setting, sco_mtu; struct btusb_data *owner; };
struct btusb_data {
    struct work_struct work; struct hci_dev *hdev;
    unsigned sco_num, air_mode; unsigned long flags;
    void *isoc, *intf; int isoc_anchor, selected;
};
static int usb_autopm_get_interface(void*p) { return 0; }
static void usb_autopm_put_interface(void*p) {}
static void usb_kill_anchored_urbs(void*p) {}
static int test_bit(int b,unsigned long*p) { return (*p>>b)&1; }
static void clear_bit(int b,unsigned long*p) { *p &= ~(1ul<<b); }
static void set_bit(int b,unsigned long*p) { *p |= 1ul<<b; }
static int test_and_clear_bit(int b,unsigned long*p) { int n=test_bit(b,p); clear_bit(b,p); return n; }
static void *btusb_find_altsetting(struct btusb_data*d,int n) { return n<=6?d:NULL; }
static int btusb_switch_alt_setting(struct hci_dev*h,int n) { h->owner->selected=n; return 0; }
static int __set_isoc_interface(struct hci_dev*h,int n) { h->owner->selected=n; return 0; }
'''
main = r'''
int main(void) {
    struct btusb_data d={0}; struct hci_dev h={.owner=&d}; d.hdev=&h;
    for (unsigned bits=0; bits<2; bits++) for (unsigned links=0; links<=3; links++) {
        d.air_mode=HCI_NOTIFY_ENABLE_SCO_CVSD; d.sco_num=links;
        h.voice_setting=bits?32:0; d.flags=3; d.selected=-1;
        btusb_work(&d.work);
        printf("%u,%u,%d\n",h.voice_setting,links,d.selected);
    }
    return 0;
}
'''
(out / "linux-sco.c").write_text(pre + function + main)
subprocess.run([
    "clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer", str(out / "linux-sco.c"), "-o", str(out / "linux-sco"),
], check=True, timeout=30)
with (out / "linux-output.csv").open("wb") as output:
    subprocess.run([str(out / "linux-sco")], stdout=output, check=True, timeout=30)
fixture = Path(__file__).with_name("realtek-sco.csv").read_bytes()
assert (out / "linux-output.csv").read_bytes() == fixture
(out / "receipt.json").write_text(json.dumps({
    "linux_revision": "cc9de5d4b5ab6459f5774946aa3195ad51236fa8",
    "btusb_sha256": digest,
    "function_sha256": hashlib.sha256(function.encode()).hexdigest(),
    "function_bytes": len(function.encode()),
    "records": 8,
    "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
    "scope": "unchanged btusb_work CVSD voice selection; logical successful USB/PM stubs; no physical or HCI/radio qualification",
}, indent=2) + "\n")
