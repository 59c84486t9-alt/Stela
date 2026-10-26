#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
"""Unchanged Linux wideband alternate selection and actual ISO service lengths.

Usage: realtek_wideband_oracle.py ORIGINAL_REFERENCE_ROOT NEW_OUTPUT_DIRECTORY [qca]
No hardware/Cargo/download. Successful logical PM/USB boundaries only.
"""
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys

base, out = map(Path, sys.argv[1:3])
profile = "qca" if len(sys.argv) == 4 and sys.argv[3] == "qca" else "realtek"
aliases = []
donors = {
    "drivers/bluetooth/btusb.c": "7ec535a89ffda9cd0c9fb060ab0db7a45696816615e60dc395fc8f6297159030",
    "drivers/bluetooth/btrtl.c": "2698257fa53f3a17d5244b37be882428a4fac0f4726b0d58e92d850fd6784b53",
}
for path, digest in donors.items():
    assert hashlib.sha256((base / path).read_bytes()).hexdigest() == digest
source = (base / "drivers/bluetooth/btusb.c").read_text()


def function(signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start:end + 1]
    raise ValueError("unterminated original function")


parts = [function("static void btusb_work("), function("static inline void __fill_isoc_descriptor_msbc(")]
prelude = r'''
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define BTUSB_DID_ISO_RESUME 0
#define BTUSB_ISOC_RUNNING 1
#define BTUSB_USE_ALT3_FOR_WBS 2
#define BTUSB_ALT6_CONTINUOUS_TX 3
#define BTUSB_MAX_ISOC_FRAMES 10
#define HCI_NOTIFY_ENABLE_SCO_CVSD 1
#define HCI_NOTIFY_ENABLE_SCO_TRANSP 2
#define bt_dev_err(...) ((void)0)
#define BT_DBG(...) ((void)0)
struct work_struct { int unused; };
struct btusb_data;
struct hci_dev { unsigned voice_setting,sco_mtu;struct btusb_data *owner; };
struct btusb_data {struct work_struct work;struct hci_dev *hdev;unsigned sco_num,air_mode,mask;
    unsigned long flags;void *isoc,*intf;int isoc_anchor,selected;bool usb_alt6_packet_flow;};
struct urb {struct {int offset,length;} iso_frame_desc[10];int number_of_packets;};
static int usb_autopm_get_interface(void*p){return 0;}
static void usb_autopm_put_interface(void*p){}
static void usb_kill_anchored_urbs(void*p){}
static int test_bit(int b,unsigned long*p){return (*p>>b)&1;}
static void clear_bit(int b,unsigned long*p){*p &= ~(1ul<<b);}
static void set_bit(int b,unsigned long*p){*p |= 1ul<<b;}
static int test_and_clear_bit(int b,unsigned long*p){int n=test_bit(b,p);clear_bit(b,p);return n;}
static void *btusb_find_altsetting(struct btusb_data*d,int n){return d->mask&(1u<<n)?d:NULL;}
static int btusb_switch_alt_setting(struct hci_dev*h,int n){h->owner->selected=n;return 0;}
static int __set_isoc_interface(struct hci_dev*h,int n){h->owner->selected=n;return 0;}
'''
main = r'''
int main(void){
    struct btusb_data d={0};struct hci_dev h={.owner=&d};d.hdev=&h;
    unsigned masks[]={127,63,55},mtus[]={60,71,72,255};
    for(unsigned m=0;m<3;m++)for(unsigned t=0;t<4;t++)for(unsigned n=0;n<=3;n++){
        d.mask=masks[m];h.sco_mtu=mtus[t];d.sco_num=n;d.air_mode=2;d.flags=7;d.selected=-1;
        btusb_work(&d.work);printf("W %u %u %u %d\n",d.mask,h.sco_mtu,n,d.selected);
    }
    for(unsigned len=3;len<=63;len++){
        d.usb_alt6_packet_flow=false;d.flags=7;
        for(unsigned turn=0;turn<4;turn++){
            struct urb u={0};__fill_isoc_descriptor_msbc(&u,len,63,&d);
            printf("P %u %u %d",len,turn,u.number_of_packets);
            for(int i=0;i<u.number_of_packets;i++)printf(" %d",u.iso_frame_desc[i].length);
            printf("\n");
        }
    }
    return 0;
}
'''
out.mkdir(parents=True, exist_ok=False)
if profile == "qca":
    # QCA source probe does not set Realtek's USE_ALT3_FOR_WBS flag.
    main = main.replace("d.flags=7;", "d.flags=3;")
    root = Path(__file__).resolve().parents[4]
    identity = (root / "crates/stela-drivers/src/usb/bluetooth/qca/identity.rs").read_text()
    entries = {(int(v, 16), int(p, 16)): flags for v, p, flags in re.findall(
        r"\{\s*USB_DEVICE\(0x([0-9a-f]+),\s*0x([0-9a-f]+)\),\s*\.driver_info\s*=\s*([^}]+)\}", source)}
    for vendor, product, kind in re.findall(r"\(0x([0-9a-f]+), 0x([0-9a-f]+), Kind::(Rome|Wcn)\)", identity):
        key = (int(vendor, 16), int(product, 16))
        flags = entries[key]
        assert "BTUSB_WIDEBAND_SPEECH" in flags and "BTUSB_BROKEN_ISOC" not in flags
        assert ("BTUSB_QCA_ROME" if kind == "Rome" else "BTUSB_QCA_WCN6855") in flags
        aliases.append({"vendor": key[0], "product": key[1], "kind": kind, "source_flags": flags.strip()})
    assert len(aliases) == 75
(out / "oracle.c").write_text(prelude + "\n".join(parts) + main)
command = ["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
           str(out / "oracle.c"), "-o", str(out / "oracle")]
with (out / "compile.log").open("w") as log:
    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
with (out / "run.log").open("w") as log:
    result = subprocess.run([str(out / "oracle")], stdout=subprocess.PIPE, stderr=log, check=True, timeout=10)
(out / "trace.txt").write_bytes(result.stdout)
fixture = Path(__file__).with_name(f"{profile}-wideband.txt")
if fixture.exists():
    assert result.stdout == fixture.read_bytes()
(out / "receipt.json").write_text(json.dumps({
    "pin": "cc9de5d4b5ab6459f5774946aa3195ad51236fa8", "donors": donors, "profile": profile, "qca_aliases": aliases,
    "functions": [{"sha256": hashlib.sha256(p.encode()).hexdigest(), "bytes": len(p.encode())} for p in parts],
    "trace_sha256": hashlib.sha256(result.stdout).hexdigest(), "records": len(result.stdout.splitlines()),
    "compile_command": command,
    "scope": "unchanged wideband alternate selection and ALT6 6/7 empty service lengths; logical USB/PM only; no native DMA/clock or physical radio claim",
}, indent=2) + "\n")
