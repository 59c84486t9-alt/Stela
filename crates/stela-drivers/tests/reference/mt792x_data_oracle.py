#!/usr/bin/env python3
"""Build unchanged pinned mt76_dma_add_buf under ASan/UBSan.

Usage: mt792x_data_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
The executable reads little-endian [IOVA,count,old_head,old_queued] u32 records
and emits actual descriptor bytes + new head/queued/index/skip flags/WCID.
Only the admitted ordinary one-64-byte-TXWI path is exercised. DMA completion,
token ownership and MMIO are separately tested by the shared-requester model.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=False)
hashes = {
    'dma.c': 'e07630bbc96b237c4696186b1e9ff30776404ac32401f8566c5165c9db61458e',
    'dma.h': 'a566971580c731541a3d6a9dd278033d0367cab4b8c0160cc6cc6150bd9fb1c6',
    'mt76.h': 'b7e52e9559ff1bd5d256ccdbaa2b4c277d418955acd141708059af3161470bea',
    'tx.c': '2d9ce8780449dac79bb70fdbd18d16167cb3f7aaec07256971739220ac848de6',
    'mt7921/pci_mac.c': 'e32ba68b2dbc5d01419872bc849640e0a8fad3c7c1f1f5c78b5a1888d5991680',
    'mt7925/pci_mac.c': '6cd36e9132df84d040e72c96b1b5a25f340dc876f76476fbad862ee53370d844',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
s = texts['dma.c']
m = re.search(r'^static int\nmt76_dma_add_buf\([^;{}]*?\)\n\{', s, re.M)
assert m
at, depth = m.end(), 1
while depth:
    depth += (s[at] == '{') - (s[at] == '}')
    at += 1
helper = s[m.start():at]
h = texts['dma.h']
defines = ''
for name in ['DMA_DUMMY_DATA', 'MT_DMA_CTL_SD_LEN0', 'MT_DMA_CTL_SD_LEN1',
             'MT_DMA_CTL_LAST_SEC0', 'MT_DMA_CTL_LAST_SEC1',
             'MT_DMA_CTL_SDP0_H', 'MT_DMA_CTL_SDP1_H']:
    m = re.search(r'^#define ' + name + r'\s+[^\n]+', h, re.M)
    assert m, name
    defines += m.group() + '\n'
desc = re.search(r'struct mt76_desc \{[^}]+\} __packed __aligned\(4\);', h).group()
buf = re.search(r'struct mt76_queue_buf \{[^}]+\};', texts['mt76.h']).group()
entry_start = texts['mt76.h'].index('struct mt76_queue_entry {')
entry_end = texts['mt76.h'].index('\n};', entry_start) + 3
entry = texts['mt76.h'][entry_start:entry_end]
prelude = r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t dma_addr_t;
typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_PREP(mask,value) (((u32)(value)<<__builtin_ctz(mask))&(mask))
#define WRITE_ONCE(location,value) ((location)=(value))
#define cpu_to_le32(value) (value)
#define CONFIG_ARCH_DMA_ADDR_T_64BIT 1
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
struct mt76_dev {int unused;}; struct sk_buff {int unused;};
'''
queue = r'''
struct mt76_queue {struct mt76_queue_entry *entry; struct mt76_desc *desc;
 u16 head; int ndesc,queued;};
'''
main = r'''
int main(void) {
 u32 in[4];
 while(fread(in,sizeof(in),1,stdin)==1) {
  if(in[1]<4 || in[1]>2048 || in[2]>=in[1] || in[3]>=in[1]-2)abort();
  struct mt76_desc *desc=calloc(in[1],sizeof(*desc));
  struct mt76_queue_entry *entry=calloc(in[1],sizeof(*entry));
  if(!desc||!entry)abort();
  struct mt76_queue q={.entry=entry,.desc=desc,.head=in[2],.ndesc=in[1],.queued=in[3]};
  struct mt76_queue_buf buf[1]={{.addr=in[0],.len=64,.skip_unmap=1}};
  struct mt76_dev dev={0}; struct sk_buff skb={0}; int txwi=0;
  int idx=mt76_dma_add_buf(&dev,&q,buf,1,0,&skb,&txwi);
  u32 tail[]={q.head,(u32)q.queued,(u32)idx,entry[idx].skip_buf0,entry[idx].skip_buf1,entry[idx].wcid};
  if((void *)entry[idx].txwi!=&txwi || entry[idx].skb!=&skb)abort();
  if(fwrite(&desc[idx],sizeof(*desc),1,stdout)!=1 || fwrite(tail,sizeof(tail),1,stdout)!=1)abort();
  free(desc);free(entry);
 }
 if(ferror(stdin))abort(); return 0;
}
'''
code = prelude + defines + desc + '\n' + buf + '\n' + entry + '\n' + queue + helper + '\n' + main
(out / 'data.c').write_text(code)
subprocess.run(['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
                '-fno-omit-frame-pointer', str(out / 'data.c'), '-o', str(out / 'data')], check=True)
inputs = b''.join(v.to_bytes(4, 'little') for n in range(300)
                  for v in [0x10000000 + n * 0x10000, [4, 8, 2048][n % 3],
                            n % [4, 8, 2048][n % 3], 0])
(out / 'inputs.bin').write_bytes(inputs)
trace = subprocess.run([str(out / 'data')], input=inputs, capture_output=True, check=True).stdout
(out / 'descriptors.bin').write_bytes(trace)
manifest = {'linux_commit': 'a804c5742bff224d4cb4d25dd383554d598be32b',
            'source_sha256': hashes, 'c_sha256': hashlib.sha256(code.encode()).hexdigest(),
            'records': 300, 'input_sha256': hashlib.sha256(inputs).hexdigest(),
            'trace_bytes': len(trace), 'trace_sha256': hashlib.sha256(trace).hexdigest()}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
