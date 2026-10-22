#!/usr/bin/env python3
"""Extract unchanged pinned TX-free helpers under bounded callback models.

Usage: mt792x_tx_free_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Only valid notifications are donor-equivalent; malformed/wrapped donor inputs
are deliberately tested as conservative Rust rejections/corrections separately.
No DMA unmapping, real firmware or air acknowledgements are demonstrated.
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
 'mt7921/mac.c':'c0181ddb14ec01b5a81116cd5fde2eb8cb6c7285336f09382cf99f0c0678d510',
 'mt7925/mac.c':'9a74d529f35484137e3c26af529a4af56ed45fdfd38ec5fd55523a196332f40c',
 'mt76_connac2_mac.h':'2a0a4bfe2aa5085d8976f69cbb135f0cde7b41eaa39cfbb83901ee2f30b22162',
 'mt76_connac3_mac.h':'65f970c7a5cd1868b047ce536710f0b103ea31d5f7dd7c9456b109fda204ecd2',
 'mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()


def function(file,name):
 text=texts[file];m=re.search(r'^static void\s*\n?'+name+r'\([^;{}]*?\)\n\{',text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:
  depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]


prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define le32_to_cpu(x) (x)
#define le32_get_bits(x,m) FIELD_GET(m,x)
#define le16_get_bits(x,m) FIELD_GET(m,x)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
#define WARN_ON_ONCE(x) (x)
#define LIST_HEAD(n) int n=0
#define list_for_each_entry_safe(s,t,h,m) for(s=NULL,t=NULL;false;)
#define MT_TXQ_PSD 0
#define MT_TXQ_BE 1
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
struct sk_buff { int unused; };
struct ieee80211_sta { int unused; };
struct mt76_txwi_cache { int unused; };
struct stats { u32 tx_retries,tx_failed; };
struct mt76_wcid { bool sta;struct stats stats; };
struct mt792x_link_sta { struct mt76_wcid wcid; };
struct mt76_dev { int tx_worker; };
struct mt792x_dev { struct mt76_dev mt76;struct {int q_tx[2];}mphy; };
static struct mt792x_link_sta links[20];
static struct ieee80211_sta dummy_sta;
static struct mt76_txwi_cache dummy_txwi;
static u32 released[128][2],nreleased,current=~0U;
static struct mt76_wcid *mt76_wcid_ptr(struct mt792x_dev *d,u32 index) {
 (void)d;current=index<20?index:~0U;return index<20?&links[index].wcid:NULL;
}
static struct ieee80211_sta *wcid_to_sta(struct mt76_wcid *w) { return w&&w->sta?&dummy_sta:NULL; }
static void mt76_wcid_add_poll(struct mt76_dev*d,struct mt76_wcid*w) { (void)d;(void)w; }
static struct mt76_txwi_cache *mt76_token_release(struct mt76_dev*d,u32 id,bool*wake) {
 (void)d;(void)wake;if(nreleased==128)abort();released[nreleased][0]=id;released[nreleased++][1]=current;return &dummy_txwi;
}
static void mt76_connac2_txwi_free(struct mt76_dev*d,struct mt76_txwi_cache*t,struct ieee80211_sta*s,void*l) {(void)d;(void)t;(void)s;(void)l;}
static void mt7925_txwi_free(struct mt792x_dev*d,struct mt76_txwi_cache*t,struct ieee80211_sta*s,struct mt76_wcid*w,void*l) {(void)d;(void)t;(void)s;(void)w;(void)l;}
#define mt76_queue_tx_cleanup(...) ((void)0)
#define mt76_set_tx_blocked(...) ((void)0)
#define mt76_worker_schedule(...) ((void)0)
#define mt7921_mac_sta_poll(...) ((void)0)
#define mt7925_mac_sta_poll(...) ((void)0)
#define skb_list_del_init(...) ((void)0)
#define napi_consume_skb(...) ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
'''
main=r'''
int main(void) {
 struct mt792x_dev d={0};
 for(u32 c=0;c<100;c++) {
  u32 packet[256]={0},n=2,total=c%16;
  memset(links,0,sizeof(links));for(int i=0;i<20;i++)links[i].wcid.sta=true;
  nreleased=0;current=~0U;
  if(CONNAC3) {
   packet[1]=(4+c%12)<<16;
   for(u32 j=0;j<total;) {
    if(j%6==0)packet[n++]=BIT(31)|(((c+j/3)%25)<<12);
    packet[n++]=BIT(30)|(((c+j)%4)<<28)|((j%16)<<24);
    u32 first=(c*19+j++)%8192,second=j<total?(c*19+j++)%8192:0x7fff;
    packet[n++]=first|(second<<15);
   }
  } else {
   packet[1]=0xdec0beef;
   for(u32 j=0;j<total;j++) {
    if(j%3==0)packet[n++]=BIT(31)|(((c+j/3)%25)<<14);
    packet[n++]=(((c*19+j)%8192)<<16)|(((c+j)%4)<<13)|(j%17);
   }
  }
  packet[0]=(6U<<27)|(total<<16)|(n*4);
  HELPER(&d,packet,n*4);
  u32 bytes=n*4;
  if(fwrite(&bytes,4,1,stdout)!=1 || fwrite(packet,4,n,stdout)!=n || fwrite(&nreleased,4,1,stdout)!=1 || fwrite(released,8,nreleased,stdout)!=nreleased)abort();
  for(int i=0;i<20;i++)if(fwrite(&links[i].wcid.stats,sizeof(struct stats),1,stdout)!=1)abort();
 }
 return 0;
}
'''
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','source_sha256':hashes,'traces':{}}
struct=texts['mt76_connac.h'];struct=struct[struct.index('struct mt76_connac_tx_free {'):struct.index('extern const struct wiphy_wowlan_support')]
for chip in [7921,7922,7925]:
 connac3=chip==7925;header=texts['mt76_connac3_mac.h' if connac3 else 'mt76_connac2_mac.h']
 prefix='MT_TXFREE' if connac3 else 'MT_TX_FREE'
 constants='\n'.join(re.findall(r'^#define '+prefix+r'[^\n]+',header,re.M))+'\n'
 name='mt7925_mac_tx_free' if connac3 else 'mt7921_mac_tx_free'
 helper=function('mt7925/mac.c' if connac3 else 'mt7921/mac.c',name)
 code=prelude+struct+constants+helper+'\n#define HELPER '+name+'\n#define CONNAC3 '+str(int(connac3))+'\n'+main
 cpath=out/f'mt{chip}.c';cpath.write_text(code);binary=out/f'mt{chip}'
 subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(cpath),'-o',str(binary)],check=True)
 trace=subprocess.run([str(binary)],check=True,capture_output=True).stdout;(out/f'mt{chip}.bin').write_bytes(trace)
 manifest['traces'][str(chip)]={'records':100,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest(),'c_sha256':hashlib.sha256(code.encode()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest['traces'],indent=2))
