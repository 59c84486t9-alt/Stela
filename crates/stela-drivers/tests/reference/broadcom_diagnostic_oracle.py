#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
"""Unchanged original diagnostic-mode functions with logical USB callbacks."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root, out = map(Path, sys.argv[1:])
source = root / 'drivers/bluetooth/btusb.c'
raw = source.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '7ec535a89ffda9cd0c9fb060ab0db7a45696816615e60dc395fc8f6297159030'
text = raw.decode()
def function(prefix):
    begin = text.index(prefix)
    opening = text.index('{', begin)
    depth = 0
    for end in range(opening, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[begin:end+1]
    raise RuntimeError(prefix)
bodies = [function('static struct urb *alloc_diag_urb('), function('static int btusb_bcm_set_diag(')]
prelude = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
enum { GFP_KERNEL, HCI_RUNNING=0 };
struct sk_buff { unsigned char bytes[2], *data; unsigned len; void *dev; };
struct urb { unsigned char *data; unsigned len, pipe; };
struct usb_endpoint_descriptor { unsigned char bEndpointAddress; };
struct btusb_data { void *diag,*udev; struct usb_endpoint_descriptor *diag_tx_ep; };
struct hci_dev { unsigned long flags; struct btusb_data *driver; };
static struct urb allocation; static struct sk_buff packet;
static unsigned fault,submitted,wire0,wire1,pipe_seen;
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static struct btusb_data *hci_get_drvdata(struct hci_dev *h) { return h->driver; }
static int test_bit(unsigned n,const unsigned long *p) { return (*p >> n) & 1; }
static struct urb *usb_alloc_urb(unsigned packets,unsigned flags) {
    (void)packets;(void)flags;return fault==1 ? NULL : &allocation;
}
static struct sk_buff *bt_skb_alloc(unsigned size,unsigned flags) {
    (void)size;(void)flags;if(fault==2)return NULL;
    memset(&packet,0,sizeof(packet));packet.data=packet.bytes;return &packet;
}
static void usb_free_urb(struct urb *u) {(void)u;}
static void skb_put_u8(struct sk_buff *s,unsigned v) {s->data[s->len++]=v;}
static unsigned usb_sndbulkpipe(void *dev,unsigned ep) {(void)dev;return ep;}
static void btusb_tx_complete(void) {}
static void usb_fill_bulk_urb(struct urb *u,void *dev,unsigned pipe,unsigned char *data,unsigned len,void (*cb)(void),void *ctx) {
    (void)dev;(void)cb;(void)ctx;u->data=data;u->len=len;u->pipe=pipe;
}
static int submit_or_queue_tx_urb(struct hci_dev *h,struct urb *u) {
    (void)h;submitted++;wire0=u->data[0];wire1=u->data[1];pipe_seen=u->pipe;
    return fault==3 ? -EIO : 0;
}
'''
runner = r'''
int main(void) {
    struct usb_endpoint_descriptor ep={.bEndpointAddress=3};
    for(unsigned diag=0;diag<2;diag++)for(unsigned running=0;running<2;running++)
    for(unsigned tx=0;tx<2;tx++)for(unsigned enable=0;enable<2;enable++)for(fault=0;fault<4;fault++) {
        struct btusb_data data={.diag=diag ? &ep : NULL,.diag_tx_ep=tx ? &ep : NULL};
        struct hci_dev h={.flags=running,.driver=&data};
        submitted=wire0=wire1=pipe_seen=0;
        int result=btusb_bcm_set_diag(&h,enable);
        printf("%u %u %u %u %u %d %u %u %u %u\n",diag,running,tx,enable,fault,result,submitted,wire0,wire1,pipe_seen);
    }
    return 0;
}
'''
out.mkdir(parents=True, exist_ok=False)
(out / 'oracle.c').write_text(prelude + '\n'.join(bodies) + runner)
command = ['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(out/'oracle.c'),'-o',str(out/'oracle')]
with (out/'compile.log').open('w') as log:
    subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=30)
with (out/'run.log').open('w') as log:
    result = subprocess.run([str(out/'oracle')],stdout=subprocess.PIPE,stderr=log,check=True,timeout=10)
assert len(result.stdout.splitlines()) == 64
(out/'trace.txt').write_bytes(result.stdout)
(out/'receipt.json').write_text(json.dumps(dict(pin='cc9de5d4b5ab6459f5774946aa3195ad51236fa8',source_sha256=hashlib.sha256(raw).hexdigest(),functions=[dict(bytes=len(b.encode()),sha256=hashlib.sha256(b.encode()).hexdigest()) for b in bodies],compile_command=command,records=64,trace_sha256=hashlib.sha256(result.stdout).hexdigest(),oracle_limit=['USB/HCI state and allocation/publication callbacks supplied logically','No native DMA, firmware acknowledgement or physical diagnostic result']),indent=2)+'\n')
