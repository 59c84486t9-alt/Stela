#!/usr/bin/env python3
"""Compile unchanged raw802.11 TXD writers under bounded metadata callbacks.

Usage: mt792x_txwi_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
mac80211 header/vif/rate/key metadata is modeled; rate selection, key install,
actual frame validation, BIP/ADDBA/802.3, publication and air delivery are outside
this oracle. Unsupported callback branches abort rather than fake success.
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
 'mt7925/mac.c':'9a74d529f35484137e3c26af529a4af56ed45fdfd38ec5fd55523a196332f40c',
 'mt76_connac2_mac.h':'2a0a4bfe2aa5085d8976f69cbb135f0cde7b41eaa39cfbb83901ee2f30b22162',
 'mt76_connac3_mac.h':'65f970c7a5cd1868b047ce536710f0b103ea31d5f7dd7c9456b109fda204ecd2',
 'mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0',
 'mt76.h':'b7e52e9559ff1bd5d256ccdbaa2b4c277d418955acd141708059af3161470bea',
 'mt792x.h':'8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()


def function(file,name):
 text=texts[file];m=re.search(r'^(?:static )?(?:inline )?(?:void|u8)\s*\n?'+name+r'\([^;{}]*?\)\n\{',text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
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
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m)) & (m))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define IEEE80211_SKB_CB(s) (&(s)->info)
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
#define IEEE80211_FCTL_FTYPE 0x000c
#define IEEE80211_FCTL_STYPE 0x00f0
#define IEEE80211_QOS_CTL_TID_MASK 15
#define IEEE80211_BAR_CTRL_TID_INFO_MASK 0xf000
#define IEEE80211_SEQ_TO_SN(x) ((x)>>4)
#define IEEE80211_TX_CTL_HW_80211_ENCAP BIT(0)
#define IEEE80211_TX_CTL_NO_ACK BIT(1)
#define IEEE80211_TX_CTL_INJECTED BIT(2)
#define IEEE80211_TX_CTL_USE_MINRATE BIT(3)
#define BSS_CHANGED_BEACON BIT(0)
#define BSS_CHANGED_BEACON_ENABLED BIT(1)
#define BSS_CHANGED_UNSOL_BCAST_PROBE_RESP BIT(2)
#define BSS_CHANGED_FILS_DISCOVERY BIT(3)
#define WLAN_CATEGORY_BACK 3
#define WLAN_ACTION_ADDBA_REQ 0
#define WLAN_CIPHER_SUITE_AES_CMAC 0x000fac06
#define MT_BAND1 1
#define MT_SDIO_TXD_SIZE 64
#define IEEE80211_AC_VO 0
#define IEEE80211_AC_VI 1
#define IEEE80211_AC_BE 2
#define IEEE80211_AC_BK 3
struct mt76_vif_link {u8 omac_idx,wmm_idx,band_idx;u8 mcast_rates_idx,beacon_rates_idx,basic_rates_idx;};
struct ieee80211_bss_conf {int unused;};
struct ieee80211_vif {void *drv_priv;struct ieee80211_bss_conf bss_conf;bool mld;};
struct ieee80211_tx_info {u8 hw_queue;u32 flags;struct {struct ieee80211_vif *vif;}control;};
struct sk_buff {u8 *data;u32 len;u8 priority,queue_mapping,hdrlen;struct ieee80211_tx_info info;};
struct ieee80211_key_conf {u32 cipher;};
struct ieee80211_hdr {__le16 frame_control,duration;u8 addr1[6],addr2[6],addr3[6];__le16 seq_ctrl;};
struct ieee80211_mgmt {u8 header[24];union {struct {u8 category,action_code;struct {__le16 capab;}addba_req;}action;}u;};
struct ieee80211_bar {u8 header[16];__le16 control,start_seq_num;};
#define IEEE80211_MIN_ACTION_SIZE(f) (offsetof(struct ieee80211_mgmt,u.action.f)+sizeof(((struct ieee80211_mgmt*)0)->u.action.f))
struct mt76_wcid {u16 idx;u8 link_id;bool amsdu;struct {u32 tx_packets,tx_bytes;}stats;};
struct mt76_phy {u8 antenna_mask;};
struct mt76_dev {struct mt76_phy phy,*phys[2];struct {int wed;}mmio;};
struct mt792x_vif {int unused;};
struct mt792x_bss_conf {struct mt76_vif_link mt76;};
static struct mt792x_bss_conf *mt792x_vif_to_link(struct mt792x_vif *v,u8 id) {(void)id;return (void*)v;}
static bool ieee80211_vif_is_mld(struct ieee80211_vif*v){return v->mld;}
static u8 skb_get_queue_mapping(struct sk_buff*s){return s->queue_mapping;}
static u8 ieee80211_get_hdrlen_from_skb(struct sk_buff*s){return s->hdrlen;}
static bool is_multicast_ether_addr(u8*a){return !!(a[0]&1);}
static bool ieee80211_is_data(__le16 f){return (f&0x000c)==8;}
static bool ieee80211_is_mgmt(__le16 f){return (f&0x000c)==0;}
static bool ieee80211_is_action(__le16 f){return (f&0x00fc)==0x00d0;}
static bool ieee80211_is_back_req(__le16 f){return (f&0x00fc)==0x0084;}
static bool ieee80211_is_beacon(__le16 f){return (f&0x00fc)==0x0080;}
static bool ieee80211_has_morefrags(__le16 f){return !!(f&0x0400);}
static bool ieee80211_is_first_frag(__le16 s){return !(s&15);}
static bool ieee80211_is_robust_mgmt_frame(struct sk_buff*s){(void)s;return false;}
static bool mt76_is_mmio(struct mt76_dev*d){(void)d;return true;}
static bool is_connac2(struct mt76_dev*d){(void)d;return true;}
static bool is_mt7915(struct mt76_dev*d){(void)d;return false;}
static bool is_mt7928(struct mt76_dev*d){(void)d;return false;}
static bool mtk_wed_device_active(void*w){(void)w;abort();}
static u8 mt76_connac_spe_idx(u8 m){(void)m;abort();}
static u16 rate_word;
static u16 mt76_connac2_mac_tx_rate_val(struct mt76_phy*p,struct ieee80211_bss_conf*c,bool b,bool m){(void)p;(void)c;(void)b;(void)m;return rate_word;}
static void mt76_connac2_mac_write_txwi_8023(__le32*t,struct sk_buff*s,struct mt76_wcid*w){(void)t;(void)s;(void)w;abort();}
static void mt7925_mac_write_txwi_8023(__le32*t,struct sk_buff*s,struct mt76_wcid*w){(void)t;(void)s;(void)w;abort();}
'''
main=r'''
int main(void) {
 for(u32 c=0;c<256;c++) {
  u32 kind=c%3,qkind=(c/3)%4,subtype=kind==2?8:11;
  if(qkind==2){kind=0;subtype=8;}else if(qkind==3){kind=0;subtype=5;}
  u32 band3[]={0,1,2,3,255};
  u32 has_vif=c&1,omac=(c>>2)%64,wmm=(c>>3)%4,band=CONNAC3?band3[(c>>5)%5]:((c>>4)&1),mld=CONNAC3?((c>>6)&1):0;
  u32 phy=CONNAC3?0:((c>>7)&1),ac=c%4,pid=c%17==0?255:c%4;
  u32 hdrlen=kind==2?26:kind==1?16:24,len=kind==1?16:128+c;
  u32 tid=CONNAC3?c%16:c%8,multicast=(c>>3)&1;
  u32 fragment=CONNAC3||kind!=2?0:(c>>2)%4;
  u32 explicit_seq=kind==1?0:((c>>1)&1),seq=(c*137)%4096;
  u32 protect=(c>>2)&1,noack=(c>>4)&1,amsdu=(c>>5)&1,minrate=(c>>6)&1;
  u32 rate=CONNAC3?14+c%16:0x4b;
  u32 input[]={c%20,has_vif,omac,wmm,band,mld,phy,qkind,ac,pid,len,hdrlen,kind,subtype,tid,multicast,fragment,explicit_seq,seq,protect,noack,amsdu,minrate,(CONNAC3&&!has_vif)?14:rate};
  if(fwrite(input,sizeof(input),1,stdout)!=1)abort();
  u32 storage[128]={0},txd[16]={0};struct ieee80211_hdr *hdr=(void*)storage;
  hdr->frame_control=(kind<<2)|(subtype<<4);if(fragment==1||fragment==2)hdr->frame_control|=0x400;
  hdr->seq_ctrl=(seq<<4)|((fragment==2||fragment==3)?1:0);hdr->addr1[0]=multicast;
  struct mt792x_bss_conf bss={.mt76={omac,wmm,band,rate,rate,rate}};
  struct ieee80211_vif vif={.drv_priv=&bss,.mld=mld};
  struct sk_buff skb={.data=(void*)storage,.len=len,.priority=tid,.queue_mapping=ac,.hdrlen=hdrlen};
  skb.info.hw_queue=phy<<2;skb.info.control.vif=has_vif?&vif:NULL;
  skb.info.flags=(noack?IEEE80211_TX_CTL_NO_ACK:0)|(explicit_seq?IEEE80211_TX_CTL_INJECTED:0)|(minrate?IEEE80211_TX_CTL_USE_MINRATE:0);
  struct mt76_dev d={.phy={.antenna_mask=1}};struct mt76_wcid w={.idx=c%20,.amsdu=amsdu};
  struct ieee80211_key_conf key={.cipher=0x000fac04};rate_word=rate;
  u32 changed=qkind==2?BSS_CHANGED_BEACON:qkind==3?BSS_CHANGED_UNSOL_BCAST_PROBE_RESP:0;
  HELPER(&d,txd,&skb,&w,protect?&key:NULL,pid,qkind?MT_TXQ_PSD:MT_TXQ_VO,changed);
  if(fwrite(txd,32,1,stdout)!=1)abort();
 }
 return 0;
}
'''
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','source_sha256':hashes,'traces':{}}
for chip in [7921,7922,7925]:
 connac3=chip==7925;h=texts['mt76_connac3_mac.h' if connac3 else 'mt76_connac2_mac.h']
 constants='\n'.join(re.findall(r'^#define MT_TXD[^\n]+',h,re.M))+'\n'
 for file,name in [('mt76.h','MT_PACKET_ID_FIRST'),('mt76.h','MT_TX_HW_QUEUE_PHY'),('mt76_connac.h','MT76_CONNAC_MAX_WMM_SETS'),('mt76_connac.h','MT_TXD_SIZE'),('mt792x.h','MT792x_BASIC_RATES_TBL')]:
  if name=='MT_TXD_SIZE' and connac3:continue
  m=re.search(r'^#define '+name+r'\s+[^\n]+',texts[file],re.M);assert m,name;constants+=m.group()+'\n'
 enums=''
 for e in re.findall(r'^enum[^;{]*\{.*?^\};',h,re.M|re.S):
  if any(name in e for name in ['MT_HDR_FORMAT_802_11','MT_TX_TYPE_CT','MT_LMAC_ALTX0','MT_TX_FRAG_NONE','MT_TX_NORMAL']):enums+=e+'\n'
 enums+=re.search(r'^enum mt76_txq_id \{.*?^\};',texts['mt76.h'],re.M|re.S).group()+'\n'
 name='mt7925_mac_write_txwi' if connac3 else 'mt76_connac2_mac_write_txwi';file='mt7925/mac.c' if connac3 else 'mt76_connac_mac.c'
 helpers=function('mt76_connac.h','mt76_connac_lmac_mapping')+'\n'+function(file,name+'_80211')+'\n'+function(file,name)
 code=prelude+constants+enums+helpers+'\n#define HELPER '+name+'\n#define CONNAC3 '+str(int(connac3))+'\n'+main
 cpath=out/f'mt{chip}.c';cpath.write_text(code);binary=out/f'mt{chip}'
 subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(cpath),'-o',str(binary)],check=True)
 trace=subprocess.run([str(binary)],check=True,capture_output=True).stdout;(out/f'mt{chip}.bin').write_bytes(trace)
 manifest['traces'][str(chip)]={'records':256,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest(),'c_sha256':hashlib.sha256(code.encode()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest['traces'],indent=2))
