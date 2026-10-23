#!/usr/bin/env python3
"""Compile unchanged pinned station-key/layout/cipher/TLV/header helpers.

Usage: mt792x_key_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY [--bip]
MT76_DIRECTORY also contains include/net/mac80211.h and include/linux/ieee80211.h
from the same kernel pin. ASan/UBSan exercise actual request bytes; modeled skb,
BSS/STA lookups and allocation do not establish real firmware state or ACK.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

bip=len(sys.argv)>3 and sys.argv[3]=="--bip"
source,out=map(Path,sys.argv[1:3]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt76_connac_mcu.c':'52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
 'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
 'mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0',
 'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
 'mt7925/mcu.h':'35855f4cdc673a7562241afd618fdd73fc181d210127e3ca2f762f3199cbc772',
 'include/net/mac80211.h':'3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9',
 'include/linux/ieee80211.h':'a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
def layout(file,kind,name):
 text=texts[file];m=re.search(r'\b'+kind+' '+name+r' \{',text);assert m,name
 end=text.index(';',text.index('}',m.end()))+1
 return text[m.start():end]+'\n'
h='mt76_connac_mcu.h';c='mt76_connac_mcu.c';h3='mt7925/mcu.h'
parts=[layout(h,'struct',n) for n in ['tlv','sta_ntlv_hdr','sta_req_hdr','sec_key','sta_rec_sec']]
parts += [layout(h,'enum','mcu_cipher_type'),layout(h3,'enum','connac3_mcu_cipher_type'),layout(h3,'struct','sta_rec_sec_uni'),layout('mt76_connac.h','struct','mt76_connac_sta_key_conf'),layout('include/net/mac80211.h','enum','set_key_cmd')]
# Exact source enum, rather than independently assumed KEY_V2/KEY_V3 ordinals.
t=texts[h];pos=t.rfind('enum {',0,t.index('STA_REC_KEY_V2'))
parts += [t[pos:t.index('};',pos)+2]+'\n']
ieee=texts['include/linux/ieee80211.h']
for name in ['SUITE','WLAN_CIPHER_SUITE_WEP40','WLAN_CIPHER_SUITE_TKIP','WLAN_CIPHER_SUITE_CCMP','WLAN_CIPHER_SUITE_WEP104','WLAN_CIPHER_SUITE_AES_CMAC','WLAN_CIPHER_SUITE_GCMP','WLAN_CIPHER_SUITE_GCMP_256','WLAN_CIPHER_SUITE_CCMP_256','WLAN_CIPHER_SUITE_BIP_GMAC_128','WLAN_CIPHER_SUITE_BIP_GMAC_256','WLAN_CIPHER_SUITE_BIP_CMAC_256','WLAN_CIPHER_SUITE_SMS4']:
 m=re.search(r'^#define '+name+r'(?:\([^\n]*?\))?\s+[^\n]+',ieee,re.M);assert m,name;parts += [m.group()+'\n']
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// MediaTek layouts/helpers BSD-3-Clause-Clear; kernel enum/constants GPL-2.0.
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;typedef uint16_t __le16;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define EOPNOTSUPP 95
#define ENOMEM 12
#define GFP_ATOMIC 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define ETH_ALEN 6
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define to_wcid_lo(id) FIELD_GET(GENMASK(7,0),(u16)(id))
#define to_wcid_hi(id) FIELD_GET(GENMASK(10,8),(u16)(id))
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
struct mt76_dev { int unused; };
struct sk_buff { u8 *data;size_t len; };
struct mt76_wcid { u16 idx;bool sta,sta_disabled;u8 link_id; };
struct mt76_vif_link { u8 idx,omac_idx; };
struct mt792x_bss_conf { struct mt76_vif_link mt76; };
struct mt792x_vif;
struct mt792x_sta { struct mt792x_vif *vif; };
struct mt792x_vif { struct mt792x_sta sta;struct mt792x_bss_conf conf; };
struct ieee80211_sta { struct mt792x_sta drv_priv;u8 addr[6]; };
struct ieee80211_vif { struct mt792x_vif drv_priv;u8 bssid[6]; };
struct ieee80211_key_conf { int cipher;u8 keyidx,keylen;u8 key[32]; };
struct ieee80211_link_sta { u8 addr[6]; };
struct ieee80211_bss_conf { u8 bssid[6]; };
#define container_of(ptr,type,member) ((type *)((u8 *)(ptr)-offsetof(type,member)))
static bool is_connac_v1(struct mt76_dev *d) { (void)d;return false; }
static void *skb_put_zero(struct sk_buff *s,int n) { if(s->len+n>256)abort();void *p=s->data+s->len;memset(p,0,n);s->len+=n;return p; }
static void skb_put_data(struct sk_buff *s,void *p,int n) { memcpy(skb_put_zero(s,n),p,n); }
static struct sk_buff *__mt76_mcu_msg_alloc(struct mt76_dev *d,void *p,int a,int b,int flags) {
 (void)d;(void)p;(void)a;(void)b;(void)flags;struct sk_buff *s=calloc(1,sizeof(*s));if(!s)abort();s->data=calloc(1,256);if(!s->data)abort();return s;
}
static struct mt792x_bss_conf *mt792x_vif_to_link(struct mt792x_vif *v,u8 link) { if(link)abort();return &v->conf; }
static struct ieee80211_link_sta *mt792x_sta_to_link_sta(struct ieee80211_vif *v,struct ieee80211_sta *s,u8 link) {
 (void)v;if(link)abort();return (struct ieee80211_link_sta *)&s->addr;
}
static struct ieee80211_bss_conf *mt792x_vif_to_bss_conf(struct ieee80211_vif *v,u8 link) { if(link)abort();return (struct ieee80211_bss_conf *)&v->bssid; }
'''
helpers=''.join(function(file,name) for file,name in [
 (h,'mt76_connac_mcu_get_wlan_idx'),(c,'mt76_connac_mcu_add_nested_tlv'),(h,'mt76_connac_mcu_add_tlv'),(c,'__mt76_connac_mcu_alloc_sta_req'),(h,'mt76_connac_mcu_get_cipher'),(h3,'mt7925_mcu_get_cipher'),(c,'mt76_connac_mcu_sta_key_tlv'),('mt7925/mcu.c','mt7925_mcu_sta_key_tlv')])
main=r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;int chip=atoi(argv[1]);struct mt76_dev d={0};
 int ciphers[]={WLAN_CIPHER_SUITE_CCMP,WLAN_CIPHER_SUITE_CCMP_256,WLAN_CIPHER_SUITE_GCMP,WLAN_CIPHER_SUITE_GCMP_256};
 for(u32 i=0;i<320;i++) {
  bool pairwise=(i/4)%2,disabled=(i/8)%2,remove=(i/16)%2;u8 peer[6];
  for(int j=0;j<6;j++)peer[j]=(u8)(2+i*7+j);
  peer[0]&=0xfe; // valid canonical unicast peer, matching actual supported scope
  struct ieee80211_vif vif={0};struct ieee80211_sta sta={0};
  struct mt792x_vif *mvif=&vif.drv_priv;mvif->sta.vif=mvif;sta.drv_priv.vif=mvif;
  memcpy(vif.bssid,peer,6);memcpy(sta.addr,peer,6);
  mvif->conf.mt76.idx=(u8)(i*13);mvif->conf.mt76.omac_idx=(i*7)%64;
  struct mt76_wcid w={.idx=(i*3)%20,.sta=pairwise,.sta_disabled=disabled};
  struct ieee80211_key_conf key={.cipher=ciphers[i%4],.keyidx=pairwise?0:(1+(i/32)%3),.keylen=(i%4==0||i%4==2)?16:32};
  for(int j=0;j<key.keylen;j++)key.key[j]=(u8)(i*17+j);
  struct mt76_connac_sta_key_conf conf={0};
  struct sk_buff *s=__mt76_connac_mcu_alloc_sta_req(&d,&mvif->conf.mt76,&w,256);
  int rc=chip==7925?mt7925_mcu_sta_key_tlv(&w,&conf,s,&key,remove?DISABLE_KEY:SET_KEY,pairwise?&sta.drv_priv:&mvif->sta):mt76_connac_mcu_sta_key_tlv(&conf,s,&key,remove?DISABLE_KEY:SET_KEY);
  if(rc)abort();u8 hdr[4]={i%4,pairwise,remove,(u8)s->len};
  if(fwrite(hdr,1,4,stdout)!=4||fwrite(s->data,1,s->len,stdout)!=s->len)abort();free(s->data);free(s);
 }
 return 0;
}
'''
if bip:
 main=r'''
int main(int argc,char **argv) {
 if(argc!=2 || atoi(argv[1])!=7925)return 1;struct mt76_dev d={0};
 for(u32 i=0;i<128;i++){
  struct ieee80211_vif vif={0};struct mt792x_vif*mvif=&vif.drv_priv;mvif->sta.vif=mvif;
  for(int j=0;j<6;j++)vif.bssid[j]=2+i*7+j;vif.bssid[0]&=0xfe;
  mvif->conf.mt76.idx=i*13;mvif->conf.mt76.omac_idx=(i*7)%64;
  struct mt76_wcid w={.idx=(i*3)%20,.sta=false,.sta_disabled=(i/8)%2};
  struct mt76_connac_sta_key_conf conf={0};
  struct ieee80211_key_conf gtk={.cipher=WLAN_CIPHER_SUITE_CCMP,.keyidx=(i/2)%4,.keylen=16};
  struct ieee80211_key_conf igtk={.cipher=WLAN_CIPHER_SUITE_AES_CMAC,.keyidx=4+i%2,.keylen=16};
  for(int j=0;j<16;j++){gtk.key[j]=i*17+j;igtk.key[j]=i*31+j;}
  for(int operation=0;operation<3;operation++){
   struct sk_buff*s=__mt76_connac_mcu_alloc_sta_req(&d,&mvif->conf.mt76,&w,256);
   struct ieee80211_key_conf*key=operation==1?&igtk:&gtk;
   if(mt7925_mcu_sta_key_tlv(&w,&conf,s,key,operation==2?DISABLE_KEY:SET_KEY,&mvif->sta))abort();
   u8 header[]={i,operation,s->len};if(fwrite(header,1,3,stdout)!=3 || fwrite(s->data,1,s->len,stdout)!=s->len)abort();
   free(s->data);free(s);
  }
 }
 return 0;
}
'''
unit=out/'linux-mt792x-key.c';unit.write_text(prelude+''.join(parts)+helpers+main)
exe=out/'linux-mt792x-key';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit),'-o',str(exe)],check=True)
cases=[]
for chip in ([7925] if bip else [7921,7922,7925]):
 trace=subprocess.run([str(exe.resolve()),str(chip)],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'cases':128 if bip else 320,'requests':384 if bip else 320,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'profile':'initial-gtk-igtk-batch' if bip else 'ordinary-data','helpers_sha256':{n:hashlib.sha256(function(f,n).encode()).hexdigest() for f,n in [('mt7925/mcu.c','mt7925_mcu_sta_key_tlv'),(c,'__mt76_connac_mcu_alloc_sta_req'),(h,'mt76_connac_mcu_add_tlv'),(h3,'mt7925_mcu_get_cipher')]},'cases':cases},indent=2)+'\n')
print(json.dumps(cases,indent=2))
