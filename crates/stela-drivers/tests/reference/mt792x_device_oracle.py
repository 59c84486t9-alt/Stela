#!/usr/bin/env python3
"""Run unchanged pinned initial DEV_INFO/BSS registration helper with sanitizers.

Usage: mt792x_device_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Firmware sends, native allocations and VIF types are modeled. This captures
source request bodies/order; it does not qualify a firmware ACK or native radio.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt76_connac_mcu.c':'52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
 'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
 'mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0',
 'mt792x.h':'8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
def block(text,start):
 start_at=text.index(start);at=text.index('{',start_at)+1;depth=1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start_at:text.index(';',at)+1]+'\n'
h=texts['mt76_connac_mcu.h'];hc=texts['mt76_connac.h']
parts=[block(h,'struct mt76_connac_bss_basic_tlv {')]
for needle in ['DEV_INFO_ACTIVE','UNI_BSS_INFO_BASIC','MCU_UNI_CMD_DEV_INFO_UPDATE']:
 pos=h.rfind('enum {',0,h.index(needle));parts += [h[pos:h.index('};',pos)+2]+'\n']
pos=hc.rfind('enum {',0,hc.index('EXT_BSSID_START'));parts += [hc[pos:hc.index('};',pos)+2]+'\n']
for name in ['STA_TYPE_STA','STA_TYPE_AP','STA_TYPE_ADHOC','STA_TYPE_BC','NETWORK_INFRA','NETWORK_P2P','NETWORK_IBSS','NETWORK_NAN','CONNECTION_INFRA_STA','CONNECTION_INFRA_AP','CONNECTION_P2P_GO','CONNECTION_IBSS_ADHOC','CONNECTION_NAN','MT76_CONNAC_MCU_STATUS_WLAN_FAILURE']:
 m=re.search(r'^#define '+name+r'\s+[^\n]+',h,re.M);assert m,name;parts += [m.group()+'\n']
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define ETH_ALEN 6
#define BIT(x) (1U<<(x))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define MCU_UNI_CMD(x) ((1<<17)|MCU_UNI_CMD_##x)
#define WARN_ON(x) do{if(x)abort();}while(0)
#define dev_dbg(...) do{}while(0)
#define dev_warn(...) do{}while(0)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
// Only station is exercised; this modeled VIF dispatch enum has no wire role.
enum { NL80211_IFTYPE_MESH_POINT,NL80211_IFTYPE_MONITOR,NL80211_IFTYPE_AP,NL80211_IFTYPE_STATION,NL80211_IFTYPE_P2P_DEVICE,NL80211_IFTYPE_ADHOC,NL80211_IFTYPE_NAN,NL80211_IFTYPE_NAN_DATA };
struct mt76_dev { int unused; };
struct mt76_phy { struct mt76_dev *dev; };
struct ieee80211_vif { int type; };
struct ieee80211_bss_conf { struct ieee80211_vif *vif;u8 addr[6]; };
struct mt76_vif_link { u8 idx,omac_idx,band_idx,wmm_idx,link_idx; };
struct mt76_wcid { u16 idx; };
static int mt76_mcu_send_msg(struct mt76_dev *dev,int cmd,void *p,int len,bool wait) {
 (void)dev;if(!wait||len>255)abort();u8 hdr[]={cmd&0xff,len};
 if(fwrite(hdr,1,2,stdout)!=2||fwrite(p,1,len,stdout)!=(size_t)len)abort();return 0;
}
'''
main=r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;int chip=atoi(argv[1]);struct mt76_dev dev={0};struct mt76_phy phy={.dev=&dev};
 struct ieee80211_vif vif={.type=NL80211_IFTYPE_STATION};
 for(u32 i=0;i<320;i++) {
  struct mt76_vif_link mvif={.idx=(i/2)%4,.omac_idx=(i*7)%64,.band_idx=chip==7925?0xff:0,.wmm_idx=(i/8)%4,.link_idx=0};
  struct mt76_wcid wcid={.idx=(i*3)%20};struct ieee80211_bss_conf conf={.vif=&vif};
  for(int j=0;j<6;j++)conf.addr[j]=(u8)(2+i*7+j);conf.addr[0]&=0xfe;
  if(mt76_connac_mcu_uni_add_dev(&phy,&conf,&mvif,&wcid,(i/64)%2))abort();
 }
 return 0;
}
'''
unit=out/'linux-mt792x-device.c';unit.write_text(prelude+''.join(parts)+function('mt76_connac_mcu.h','mt76_connac_mcu_bss_deact_err')+function('mt76_connac_mcu.c','mt76_connac_mcu_uni_add_dev')+main)
exe=out/'linux-mt792x-device';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
cases=[]
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(exe.resolve()),str(chip)],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'contexts':320,'requests':640,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'cases':cases},indent=2)+'\n')
print(json.dumps(cases,indent=2))
