#!/usr/bin/env python3
"""Compile unchanged pinned hardware TXP emitter with ASan/UBSan.

Usage: mt792x_txp_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
The inputs are modeled IOVAs only. Canonical lease bounds/lifetime checks are
separately tested in Rust; encoding never qualifies native DMA publication.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt76_connac_mac.c':'d93fe180202e8ee6b3a4dc5926a5e1760a1f1dfaa9ec6eebe46c95bc918ea37e',
 'mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
s=texts['mt76_connac_mac.c'];m=re.search(r'^void mt76_connac_write_hw_txp\([^;{}]*?\)\n\{',s,re.M);assert m
at,depth=m.end(),1
while depth:depth+=(s[at]=='{')-(s[at]=='}');at+=1
helper=s[m.start():at]
h=texts['mt76_connac.h'];layouts=h[h.index('struct mt76_connac_txp_ptr {'):h.index('struct mt76_connac_txp_common {')]
names=['MT_HW_TXP_MAX_MSDU_NUM','MT_HW_TXP_MAX_BUF_NUM','MT_TXD_SIZE','MT_MSDU_ID_VALID','MT_TXD_LEN_LAST','MT_TXD_LEN_MASK','MT_TXD_LEN_AMSDU_LAST','MT_TXD_LEN_MSDU_LAST']
defines=''
for name in names:
 m=re.search(r'^#define '+name+r'\s+[^\n]+',h,re.M);assert m,name;defines+=m.group()+'\n'
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
struct mt76_dev { bool connac3; };
struct mt76_tx_info { struct {uint64_t addr;u32 len;} buf[5];int nbuf; };
static bool is_mt7663(struct mt76_dev *d) {(void)d;return false;}
static bool is_connac2(struct mt76_dev *d) {return !d->connac3;}
static bool is_connac3(struct mt76_dev *d) {return d->connac3;}
'''
main=r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;struct mt76_dev d={.connac3=atoi(argv[1])==7925};
 for(u32 c=0;c<100;c++) {
  u32 token=(c*137)%8192,n=1+c%4;struct mt76_tx_info info={.nbuf=n+1};
  struct mt76_connac_hw_txp txp={0};u32 header[]={token,n};
  if(fwrite(header,sizeof(header),1,stdout)!=1)abort();
  u32 lengths[]={1,14,64,4095};
  for(u32 i=0;i<n;i++) {
   u32 address=0x10000000+c*0x10000+i*0x1000,len=lengths[(c+i)%4];
   if(c%9==0 && n==1) {address=0xfffff001;len=4095;}
   info.buf[i+1].addr=address;info.buf[i+1].len=len;
   u32 span[]={address,len};if(fwrite(span,sizeof(span),1,stdout)!=1)abort();
  }
  mt76_connac_write_hw_txp(&d,&info,&txp,token);
  u32 tail[]={info.buf[0].len,info.nbuf};
  if(fwrite(&txp,sizeof(txp),1,stdout)!=1 || fwrite(tail,sizeof(tail),1,stdout)!=1)abort();
 }
 return 0;
}
'''
code=prelude+defines+layouts+helper+'\n'+main;(out/'txp.c').write_text(code)
subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(out/'txp.c'),'-o',str(out/'txp')],check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','source_sha256':hashes,'c_sha256':hashlib.sha256(code.encode()).hexdigest(),'traces':{}}
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(out/'txp'),str(chip)],check=True,capture_output=True).stdout;(out/f'mt{chip}.bin').write_bytes(trace)
 manifest['traces'][str(chip)]={'records':100,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest['traces'],indent=2))
