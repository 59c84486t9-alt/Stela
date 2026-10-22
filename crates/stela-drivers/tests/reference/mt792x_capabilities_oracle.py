#!/usr/bin/env python3
"""Execute unchanged pinned PCI NIC/PHY/EML capability parsers under sanitizers.

Usage: mt792x_capabilities_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Firmware input, skb and device/PHY storage are modeled. Only valid known TLVs
are fed to Linux; Rust separately rejects malformed/short entries atomically.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt7921/mcu.c':'3b356eeef80727c27ad5f179e277a9d434297d14ac6df8297c98f4ce445e91b6',
 'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
 'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
 'mt7925/mcu.h':'35855f4cdc673a7562241afd618fdd73fc181d210127e3ca2f762f3199cbc772',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
h=texts['mt76_connac_mcu.h'];h3=texts['mt7925/mcu.h'];parts=[]
for text,needle in [(h,'MT_NIC_CAP_TX_RESOURCE'),(h,'MCU_CE_CMD_GET_NIC_CAPAB'),(h,'MCU_UNI_CMD_DEV_INFO_UPDATE'),(h3,'UNI_CHIP_CONFIG_NIC_CAPA')]:
 start=text.rfind('enum {',0,text.index(needle));parts += [text[start:text.index('};',start)+2]+'\n']
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define BIT(x) (1U<<(x))
#define EINVAL 22
#define ETH_ALEN 6
#define MCU_CE_CMD(x) ((1<<18)|MCU_CE_CMD_##x)
#define MCU_UNI_CMD(x) ((1<<17)|MCU_UNI_CMD_##x)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
struct mt76_dev;
struct mt76_phy { struct mt76_dev *dev;u8 macaddr[6],antenna_mask,chainmask;struct {bool has_2ghz,has_5ghz,has_6ghz;}cap; };
struct mt76_dev { struct mt76_phy phy; };
struct mt792x_phy { struct mt76_phy *mt76;u64 chip_cap;u16 eml_cap; };
struct mt792x_dev { struct mt76_dev mt76;struct mt792x_phy phy; };
struct tlv { __le16 tag,len;u8 data[]; } __packed;
struct sk_buff { u8 *data,*allocation;size_t len; };
static void skb_pull(struct sk_buff *s,int n){if(n<0||(size_t)n>s->len)abort();s->data+=n;s->len-=n;}
static void dev_kfree_skb(struct sk_buff *s){free(s->allocation);free(s);}
static bool mt76_is_sdio(struct mt76_dev *d){(void)d;return false;}
static void mt7921_mcu_parse_tx_resource(struct mt76_dev *d,struct sk_buff *s){(void)d;(void)s;abort();}
static u8 input[1024];static size_t input_len;
static int mt76_mcu_send_and_get_msg(struct mt76_dev *d,int cmd,void *p,int n,bool wait,struct sk_buff **out) {
 (void)d;if(!wait)abort();
 if(cmd==((1<<18)|0x8a)){if(p||n)abort();}
 else if(cmd==((1<<17)|14)){u8 expected[]={0,0,0,0,3,0,4,0};if(n!=8||memcmp(p,expected,8))abort();}
 else abort();
 struct sk_buff *s=calloc(1,sizeof(*s));if(!s)abort();s->allocation=malloc(input_len);if(!s->allocation)abort();
 memcpy(s->allocation,input,input_len);s->data=s->allocation;s->len=input_len;*out=s;return 0;
}
'''
helpers=''.join(function(file,name) for file,name in [
 ('mt7921/mcu.c','mt7921_mcu_parse_phy_cap'),('mt7921/mcu.c','mt7921_mcu_get_nic_capability'),
 ('mt7925/mcu.c','mt7925_mcu_parse_phy_cap'),('mt7925/mcu.c','mt7925_mcu_parse_eml_cap'),('mt7925/mcu.c','mt7925_mcu_get_nic_capability')])
main=r'''
static void append(bool c3,u32 tag,const u8 *p,u32 n){
 u32 h=c3?4:8;if(input_len+h+n>sizeof(input))abort();
 if(c3){u16 header[]={tag,n+4};memcpy(input+input_len,header,4);}else{u32 header[]={tag,n};memcpy(input+input_len,header,8);}
 input_len+=h;memcpy(input+input_len,p,n);input_len+=n;input[0]++;
}
int main(int argc,char **argv) {
 if(argc!=2)return 1;bool c3=atoi(argv[1])==7925;
 for(u32 i=0;i<1024;i++) {
  memset(input,0,sizeof(input));input_len=4;input[2]=0xa5;input[3]=0x5a;
  u8 phy[16],mac[6],six[]={i&255},flags[8],eml[12],unknown[]={9,8,7};
  for(int j=0;j<16;j++)phy[j]=(u8)(i*17+j);
  phy[4]=1+(i/32)%4;phy[10]=(i/128)%4;
  for(int j=0;j<6;j++)mac[j]=(u8)(i*7+j);mac[0]&=0xfe;
  for(int j=0;j<8;j++)flags[j]=(u8)(i*13+j);
  for(int j=0;j<12;j++)eml[j]=(u8)(i*23+j);
  if(i&1)append(c3,MT_NIC_CAP_MAC_ADDR,mac,6);
  if(i&2)append(c3,MT_NIC_CAP_PHY,phy,c3?16:12);
  if(i&4)append(c3,MT_NIC_CAP_6G,six,1);
  if(i&8)append(c3,MT_NIC_CAP_CHIP_CAP,flags,8);
  if(i&16)append(c3,MT_NIC_CAP_EML_CAP,eml,12);
  append(c3,c3?0xbeef:0xff01beef,unknown,3);
  if(i%3==0){for(int j=0;j<6;j++)mac[j]^=0x40;append(c3,MT_NIC_CAP_MAC_ADDR,mac,6);}
  // Source parsers retain no trailing view, but must not consume/misparse it.
  input[input_len++]=0x31;input[input_len++]=0x32;
  struct mt792x_dev dev={0};dev.mt76.phy.dev=&dev.mt76;dev.phy.mt76=&dev.mt76.phy;
  int rc=c3?mt7925_mcu_get_nic_capability(&dev):mt7921_mcu_get_nic_capability(&dev.phy);if(rc)abort();
  u8 count[]={input_len,input_len>>8};if(fwrite(count,1,2,stdout)!=2||fwrite(input,1,input_len,stdout)!=input_len)abort();
  u8 result[22]={0};memcpy(result,dev.mt76.phy.macaddr,6);result[6]=dev.mt76.phy.antenna_mask;result[7]=dev.mt76.phy.chainmask;
  result[8]=dev.mt76.phy.cap.has_2ghz;result[9]=dev.mt76.phy.cap.has_5ghz;result[10]=dev.mt76.phy.cap.has_6ghz;
  memcpy(result+12,&dev.phy.chip_cap,8);memcpy(result+20,&dev.phy.eml_cap,2);
  if(fwrite(result,1,22,stdout)!=22)abort();
 }
 return 0;
}
'''
unit=out/'linux-mt792x-capabilities.c';unit.write_text(prelude+''.join(parts)+helpers+main)
exe=out/'linux-mt792x-capabilities';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Wno-pointer-sign',str(unit),'-o',str(exe)],check=True)
cases=[]
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(exe.resolve()),str(chip)],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'reports':1024,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'cases':cases},indent=2)+'\n')
print(json.dumps(cases,indent=2))
