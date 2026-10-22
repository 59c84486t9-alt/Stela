#!/usr/bin/env python3
"""Compile unchanged full pinned RX descriptor helpers under ASan/UBSan.

Usage: mt792x_rx_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Each executable reads a file of [frame_bytes, header_bytes] u32 records + RX
bytes. It emits flags, pulled offset, TSF/channel/WCID/RCPI/PN and normalized
payload. skb/header-length/rate/channel/firmware-station callbacks are models;
no PHY-rate interpretation, key association or hardware qualification claimed.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:]); out.mkdir(parents=True, exist_ok=False)
hashes = {
 'mt7921/mac.c':'c0181ddb14ec01b5a81116cd5fde2eb8cb6c7285336f09382cf99f0c0678d510',
 'mt7925/mac.c':'9a74d529f35484137e3c26af529a4af56ed45fdfd38ec5fd55523a196332f40c',
 'mt76_connac2_mac.h':'2a0a4bfe2aa5085d8976f69cbb135f0cde7b41eaa39cfbb83901ee2f30b22162',
 'mt76_connac3_mac.h':'65f970c7a5cd1868b047ce536710f0b103ea31d5f7dd7c9456b109fda204ecd2',
 'mt76.h':'b7e52e9559ff1bd5d256ccdbaa2b4c277d418955acd141708059af3161470bea',
 'mt792x.h':'8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
 'mt7921/mt7921.h':'370d21968a2fd423f4b745be820e83d06f336b17913616da487551a52797baab',
 'mt7925/mt7925.h':'b6fec2103954269927b44b095944120dd22a5a0503fa8930e49a8ecc044844dc',
}
texts = {}
for name, digest in hashes.items():
 raw=(source/name).read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest,name; texts[name]=raw.decode()
def function(s, name):
 m=re.search(r'^(?:static (?:inline )?)?(?:int|void)\n'+name+r'\([^;{}]*?\)\n\{',s,re.M); assert m,name
 at,depth=m.end(),1
 while depth: depth+=(s[at]=='{')-(s[at]=='}');at+=1
 return s[m.start():at]
def enum(name): return re.search(r'enum '+name+r' \{[^}]+\};',texts['mt76.h']).group()
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16;
typedef uint32_t u32; typedef uint64_t u64; typedef uint16_t __le16; typedef uint32_t __le32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_GET(mask,value) (((u32)(value)&(mask))>>__builtin_ctz(mask))
#define le32_get_bits(value,mask) FIELD_GET(mask,value)
#define le32_to_cpu(value) (value)
#define le16_to_cpu(value) (value)
#define cpu_to_le16(value) (value)
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define max(a,b) ((a)>(b)?(a):(b))
#define hweight8(value) __builtin_popcount((unsigned)(value))
#define fallthrough __attribute__((fallthrough))
#define test_bit(bit,ptr) ((*(ptr)&(1UL<<(bit)))!=0)
#define MT76_STATE_RUNNING 0
#define RX_FLAG_ONLY_MONITOR BIT(0)
#define RX_FLAG_FAILED_FCS_CRC BIT(1)
#define RX_FLAG_MMIC_ERROR BIT(2)
#define RX_FLAG_DECRYPTED BIT(3)
#define RX_FLAG_IV_STRIPPED BIT(4)
#define RX_FLAG_MMIC_STRIPPED BIT(5)
#define RX_FLAG_MIC_STRIPPED BIT(6)
#define RX_FLAG_MACTIME_START BIT(7)
#define RX_FLAG_AMPDU_DETAILS BIT(8)
#define RX_FLAG_8023 BIT(9)
#define RX_ENC_FLAG_LDPC BIT(0)
#define RX_ENC_EHT 3
#define RX_ENC_HE 2
#define CHECKSUM_UNNECESSARY 1
#define NL80211_BAND_2GHZ 0
#define NL80211_BAND_5GHZ 1
#define NL80211_BAND_6GHZ 2
#define ETH_P_8021Q 0x8100
#define IEEE80211_SEQ_TO_SN(value) ((value)>>4)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
struct mt76_wcid {int unused;}; struct mt76_phy;
struct mt76_rx_status {u64 flag; struct mt76_wcid *wcid; int band,freq;
 u32 timestamp,ampdu_ref,enc_flags;u8 iv[6],chains; s8 chain_signal[4],signal;
 bool amsdu,first_amsdu,last_amsdu,aggr; u16 seqno;u8 qos_ctl,encoding;};
struct ieee80211_supported_band {void *channels;};
struct mt76_phy {unsigned long state;u8 antenna_mask;struct {struct ieee80211_supported_band sband;} sband_2g,sband_5g,sband_6g;};
struct mt76_dev {struct mt76_phy phy;};
static bool mt76_is_mmio(struct mt76_dev *dev) {(void)dev;return true;}
struct mt792x_phy {u32 rx_ampdu_ts,ampdu_ref;};
struct mt792x_dev {struct mt76_dev mt76;struct mt792x_phy phy;};
struct mt792x_link_sta {struct mt76_wcid wcid;};
struct mt792x_sta {struct mt792x_link_sta deflink;void *vif;};
struct ieee80211_vif {int drv_priv;};
struct ieee80211_hdr {u16 frame_control,duration;u8 addr[18];u16 seq_ctrl;} __attribute__((packed));
struct sk_buff {u8 *data;size_t len;u64 cb[128];int ip_summed;size_t header_bytes;};
static u32 observed_wcid,observed_unicast;
static struct mt76_wcid *mt792x_rx_get_wcid(struct mt792x_dev *dev,int idx,bool unicast) {(void)dev;observed_wcid=idx;observed_unicast=unicast;return NULL;}
static void mt76_wcid_add_poll(struct mt76_dev *dev,struct mt76_wcid *wcid) {(void)dev;(void)wcid;abort();}
static int ieee80211_channel_to_frequency(u8 channel,int band) {(void)band;return channel;}
static void *skb_pull(struct sk_buff *skb,size_t n) {if(n>skb->len)abort();skb->data+=n;skb->len-=n;return skb->data;}
static size_t ieee80211_get_hdrlen_from_skb(struct sk_buff *skb) {if(skb->header_bytes>skb->len)abort();return skb->header_bytes;}
static bool ieee80211_has_morefrags(u16 fc) {return !!(fc&0x400);}
static bool ieee80211_is_data_qos(u16 fc) {return (fc&0x8c)==0x88;}
static bool ieee80211_is_qos_nullfunc(u16 fc) {return (fc&0xfc)==0xc8;}
static u8 *ieee80211_get_qos_ctl(struct ieee80211_hdr *hdr) {return (u8 *)hdr+24;}
static struct ieee80211_hdr *mt76_skb_get_hdr(struct sk_buff *skb) {if(skb->len<24)abort();return (void *)skb->data;}
static int mt76_connac2_reverse_frag0_hdr_trans(struct ieee80211_vif *vif,struct sk_buff *skb,u16 gap) {(void)vif;(void)skb;(void)gap;abort();}
static int mt7925_reverse_frag0_hdr_trans(struct sk_buff *skb,u16 gap) {(void)skb;(void)gap;abort();}
static void mt76_insert_ccmp_hdr(struct sk_buff *skb,u8 key) {(void)skb;(void)key;abort();}
static void mt792x_mac_assoc_rssi(struct mt792x_dev *dev,struct sk_buff *skb) {(void)dev;(void)skb;}
static int modeled_rate(struct mt76_rx_status *status,u8 *mode) {status->encoding=0;*mode=0;return 0;}
static int mt76_connac2_mac_fill_rx_rate(struct mt76_dev *dev,struct mt76_rx_status *status,struct ieee80211_supported_band *band,__le32 *rxv,u8 *mode) {(void)dev;(void)band;(void)rxv;return modeled_rate(status,mode);}
static int mt7925_mac_fill_rx_rate(struct mt792x_dev *dev,struct mt76_rx_status *status,struct ieee80211_supported_band *band,__le32 *rxv,u8 *mode) {(void)dev;(void)band;(void)rxv;return modeled_rate(status,mode);}
static void mt76_connac2_mac_decode_he_radiotap(struct mt76_dev *dev,struct sk_buff *skb,__le32 *rxv,u8 mode) {(void)dev;(void)skb;(void)rxv;(void)mode;abort();}
static void mt76_connac3_mac_decode_he_radiotap(struct sk_buff *skb,__le32 *rxv,u8 mode) {(void)skb;(void)rxv;(void)mode;abort();}
static void mt76_connac3_mac_decode_eht_radiotap(struct sk_buff *skb,__le32 *rxv,u8 mode) {(void)skb;(void)rxv;(void)mode;abort();}
static void skb_set_mac_header(struct sk_buff *skb,int offset) {(void)skb;if(offset)abort();}
static u16 get_unaligned_be16(void *ptr) {u8 *p=ptr;return (u16)p[0]<<8|p[1];}
'''
main=r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;FILE *input=fopen(argv[1],"rb");if(!input)abort();u32 header[2];
 while(fread(header,sizeof(header),1,input)==1) {
  if(header[0]<24 || header[0]>16384 || header[1]<10 || header[1]>62)abort();
  u8 *raw=calloc(1,header[0]);if(!raw || fread(raw,header[0],1,input)!=1)abort();
  struct sk_buff skb={.data=raw,.len=header[0],.header_bytes=header[1]};
  struct mt792x_dev dev={.mt76.phy={.state=1,.antenna_mask=15,.sband_2g.sband.channels=(void *)1,.sband_5g.sband.channels=(void *)1,.sband_6g.sband.channels=(void *)1}};
  observed_wcid=0;observed_unicast=0;
  int result=FILL_RX(&dev,&skb);if(result)abort();
  struct mt76_rx_status *s=(void *)skb.cb;
  u32 out[]={s->flag,(u32)(skb.data-raw),s->timestamp,(u32)s->band,(u32)s->freq,observed_wcid,observed_unicast,s->amsdu,s->first_amsdu,s->last_amsdu,(u32)skb.len};
  if(fwrite(out,sizeof(out),1,stdout)!=1 || fwrite(s->iv,6,1,stdout)!=1 || fwrite(s->chain_signal,4,1,stdout)!=1 || fwrite(skb.data,skb.len,1,stdout)!=1)abort();
  free(raw);
 }
 if(ferror(input))abort();fclose(input);return 0;
}
'''
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','source_sha256':hashes,'generated_c_sha256':{}}
for chip in [7921,7925]:
 helper=function(texts[f'mt{chip}/mac.c'],f'mt{chip}_mac_fill_rx')
 freq=function(texts['mt792x.h'],'mt792x_get_status_freq_info')
 h=texts[f'mt76_connac{3 if chip==7925 else 2}_mac.h']
 definitions={m.group(1):m.group() for m in re.finditer(r'^#define (\w+)[ \t]+[^\n]+',h,re.M)}
 selected=set(re.findall(r'\bMT_\w+',helper))&definitions.keys()
 previous=None
 while previous!=selected:
  previous=selected.copy()
  for name in previous:selected|=set(re.findall(r'\bMT_\w+',definitions[name]))&definitions.keys()
 constants='\n'.join(definitions[name] for name in sorted(selected))+'\n'
 rssi=re.search(r'^#define to_rssi\([^\n]+',texts[f'mt{chip}/mt{chip}.h'],re.M).group()+'\n'
 code=prelude+enum('mt76_cipher_type')+'\n'+enum('mt76_phy_type')+'\n'+rssi+constants+freq+'\n'+helper+'\n'+main.replace('FILL_RX',f'mt{chip}_mac_fill_rx')
 path=out/f'rx{chip}.c';path.write_text(code)
 subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(path),'-o',str(out/f'rx{chip}')],check=True)
 manifest['generated_c_sha256'][str(chip)]=hashlib.sha256(code.encode()).hexdigest()
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
