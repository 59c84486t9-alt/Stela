#!/usr/bin/env python3
"""Extract unchanged Linux boot MCU encoders; emit immutable ASan/UBSan traces.

Usage: mt792x_mcu_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Then STELA_MT792X_MCU_ORACLE=FRESH_OUTPUT_DIRECTORY cargo test -p stela-drivers
unchanged_pinned_mcu -- --ignored
The skb/mcu state boundary is modeled; no PCIe or radio hardware is exercised.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
out.mkdir(parents=True,exist_ok=False)
hashes = {
 'mt76_connac_mcu.c':'52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
 'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
 'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
 'mt76_connac2_mac.h':'2a0a4bfe2aa5085d8976f69cbb135f0cde7b41eaa39cfbb83901ee2f30b22162',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest,name; texts[name]=raw.decode()


def function(file,name):
 text=texts[file]
 m=re.search(r'^int '+name+r'\([^;{}]*?\)\n\{',text,re.M); assert m,name
 at,depth=m.end(),1
 while depth:
  depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]


h=texts['mt76_connac_mcu.h'];mac=texts['mt76_connac2_mac.h']
structs=h[h.index('struct mt76_connac2_mcu_txd {'):h.index('struct mt76_connac2_mcu_rxd {')]
# Exact definitions referenced by unchanged encoder bodies; unrelated kernel
# layouts stay outside this focused compilation unit.
constants=[]
for name in ['MT_TXD0_TX_BYTES','MT_TXD0_PKT_FMT','MT_TXD0_Q_IDX','MT_TXD1_LONG_FORMAT','MT_TXD1_HDR_FORMAT']:
 m=re.search(r'^#define '+name+r'\s+[^\n]+',mac,re.M);assert m,name;constants.append(m.group())
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint16_t __le16; typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m)) & (m))
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error The target host is little endian.
#endif
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define HZ 1000
#define __MCU_CMD_FIELD_ID GENMASK(7,0)
#define __MCU_CMD_FIELD_EXT_ID GENMASK(15,8)
#define __MCU_CMD_FIELD_QUERY BIT(16)
#define __MCU_CMD_FIELD_UNI BIT(17)
#define __MCU_CMD_FIELD_CE BIT(18)
#define __MCU_CMD_FIELD_WA BIT(19)
#define MCU_CMD(x) MCU_CMD_##x
#define MCU_CMD_FW_SCATTER 0xee
#define MCU_UNI_CMD(x) (__MCU_CMD_FIELD_UNI|MCU_UNI_CMD_##x)
#define MCU_UNI_CMD_HIF_CTRL 0x07
#define MCU_UNI_CMD_CHIP_CONFIG 0x0e
#define MCU_UNI_CMD_TESTMODE_RX_STAT 0x32
#define MCU_UNI_CMD_TESTMODE_CTRL 0x46
#define MCU_CMD_ACK BIT(0)
#define MCU_CMD_UNI_EXT_ACK 7
#define MCU_CMD_UNI_QUERY_ACK 3
#define MCU_S2D_H2N 0
#define MCU_S2D_H2C 2
#define MCU_Q_QUERY 0
#define MCU_Q_SET 1
#define MCU_Q_NA 3
#define MCU_PKT_ID 0xa0
#define MCU_PQ_ID(p,q) (((p)<<15)|((q)<<10))
#define MT_TX_TYPE_CMD 2
#define MT_HDR_FORMAT_CMD 1
#define MT_TX_MCU_PORT_RX_Q0 0x20
#define MT_TX_PORT_IDX_MCU 1
struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; };
struct sk_buff { unsigned char *data; int len; };
static void *skb_push(struct sk_buff *s,int n) { s->data-=n;s->len+=n;return s->data; }
'''
main=r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1; int chip=atoi(argv[1]); struct mt76_dev d={0};
 u8 commands[]={1,2,5,7,0x10,0xee};
 for(int i=0;i<90;i++) {
  u8 cmd=commands[i%6]; int n=cmd==0xee?4096:cmd==2?8:(cmd==1||cmd==5)?12:4;
  u8 *allocation=calloc(1,n+128);if(!allocation)abort();
  struct sk_buff s={.data=allocation+128,.len=n};
  for(int j=0;j<n;j++)s.data[j]=(u8)(i*17+j);
  int seq=0;int rc=chip==7925?mt7925_mcu_fill_message(&d,&s,cmd,&seq):mt76_connac2_mcu_fill_message(&d,&s,cmd,&seq);
  if(rc)abort();u8 hdr[4]={cmd,(u8)seq,(u8)s.len,(u8)(s.len>>8)};
  if(fwrite(hdr,1,4,stdout)!=4 || fwrite(s.data,1,s.len,stdout)!=(size_t)s.len)abort();free(allocation);
 }
 return 0;
}
'''
unit=out/'linux-mt792x-mcu.c'
unit.write_text(prelude+'\n'.join(constants)+'\n'+structs+function('mt76_connac_mcu.c','mt76_connac2_mcu_fill_message')+'\n'+function('mt7925/mcu.c','mt7925_mcu_fill_message')+main)
exe=out/'linux-mt792x-mcu'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
cases=[]
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(exe.resolve()),str(chip)],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace)
 cases.append({'chip':chip,'messages':90,'trace_bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'cases':cases},indent=2)+'\n')
print(json.dumps(cases,indent=2))
