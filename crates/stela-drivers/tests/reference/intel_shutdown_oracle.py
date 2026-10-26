#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2015 Intel Corporation
"""Unchanged complete Intel shutdown on logical synchronous-command callbacks."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
root,out=map(Path,sys.argv[1:])
data=(root/'drivers/bluetooth/btintel.c').read_bytes()
assert hashlib.sha256(data).hexdigest()=='9533d26e9815ce7fa5c6f3e88ec658cd34f4bf38b1cbed747c21d3f47ef5ed7c'
source=data.decode();begin=source.index('int btintel_shutdown_combined(');opening=source.index('{',begin);depth=0
for end in range(opening,len(source)):
    depth+=(source[end]=='{')-(source[end]=='}')
    if depth==0:break
body=source[begin:end+1]
prelude=r'''
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
struct hci_dev { unsigned led; }; struct sk_buff { int unused; };
enum {HCI_OP_RESET=0x0c03,HCI_INIT_TIMEOUT=1,INTEL_BROKEN_SHUTDOWN_LED=0};
static unsigned calls,fail_at,ops[2]; static struct sk_buff packet;
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define bt_dev_err(...) ((void)0)
static int btintel_test_flag(struct hci_dev *h,unsigned flag) {(void)flag;return h->led;}
static void kfree_skb(struct sk_buff *s) {(void)s;}
static struct sk_buff *__hci_cmd_sync(struct hci_dev *h,unsigned op,unsigned len,void *params,unsigned timeout) {
    (void)h;(void)len;(void)params;(void)timeout;ops[calls++]=op;
    return calls==fail_at ? (void *)(intptr_t)-EIO : &packet;
}
'''
runner=r'''
int main(void){
    for(unsigned led=0;led<2;led++) {
      for(fail_at=0;fail_at<3;fail_at++) {
        struct hci_dev h={.led=led};calls=ops[0]=ops[1]=0;
        int result=btintel_shutdown_combined(&h);
        printf("%u %u %d %u %u %u\n",led,fail_at,result,calls,ops[0],ops[1]);
      }
    }
    return 0;
}
'''
out.mkdir(parents=True,exist_ok=False);(out/'oracle.c').write_text(prelude+body+runner)
command=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(out/'oracle.c'),'-o',str(out/'oracle')]
with(out/'compile.log').open('w')as log:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=30)
with(out/'run.log').open('w')as log:result=subprocess.run([str(out/'oracle')],stdout=subprocess.PIPE,stderr=log,check=True,timeout=10)
(out/'trace.txt').write_bytes(result.stdout)
assert len(result.stdout.splitlines())==6
(out/'receipt.json').write_text(json.dumps(dict(pin='cc9de5d4b5ab6459f5774946aa3195ad51236fa8',source_sha256=hashlib.sha256(data).hexdigest(),function_sha256=hashlib.sha256(body.encode()).hexdigest(),function_bytes=len(body.encode()),records=6,trace_sha256=hashlib.sha256(result.stdout).hexdigest(),compile_command=command,oracle_limit=['Synchronous command callback is logical; actual HCI credits/CC and native retirement need separate Rust proof','LED-flag source aliases8087:07dc/0a2a/0aa7 are not currently admitted; no new profile qualification']),indent=2)+'\n')
