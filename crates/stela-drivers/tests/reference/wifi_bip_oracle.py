#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute complete pinned BIP CMAC/replay/classification helpers under sanitizers.

Usage: wifi_bip_oracle.py PINNED_LINUX_CACHE FRESH_OUTPUT_DIRECTORY
CommonCrypto supplies only the independent host AES block primitive. The complete
unchanged Linux CMAC subkeys/stream/final, BIP AAD/IPN/decrypt and key-ID helpers
remain the oracle. This models skb/key storage, not firmware ACK or PMF admission.
"""
from pathlib import Path
import re
import hashlib
import json
import subprocess
import sys
root,out=map(Path,sys.argv[1:3]);out.mkdir(parents=True,exist_ok=False)
files=['include/linux/ieee80211.h','include/crypto/aes-cbc-macs.h','lib/crypto/aes.c','net/mac80211/aes_cmac.c','net/mac80211/wpa.c','net/mac80211/rx.c','include/net/mac80211.h','include/net/dropreason-core.h','include/net/dropreason.h','net/mac80211/drop.h','net/mac80211/key.h']
sources={p:(root/p).read_text() for p in files}
EXPECTED_HASHES = {
  "include/linux/ieee80211.h": "a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa",
  "include/crypto/aes-cbc-macs.h": "e364557a22e2fb602d9827e9631e23e90868936c84d1bbe458005910c95a9535",
  "lib/crypto/aes.c": "4ad039b5ab0f48b39ee4a60b83dd769e4418ba7d7917fb719f0e1e72891133d0",
  "net/mac80211/aes_cmac.c": "67b8c12d66fe7a02f79c32781b1814625bd370fca42e245190c225c89be47e1d",
  "net/mac80211/wpa.c": "07087347278d9f01307c98bad12554a611a8b70f703af4e7ca31747713d365b5",
  "net/mac80211/rx.c": "58cb7a2c9019190faab4ac4af9c7c76cfbff34015c2b2e76005b429a21364cdf",
  "include/net/mac80211.h": "3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9",
  "include/net/dropreason-core.h": "06d0d26693b0c7864422232ba190214e9cecc8b5481c63ccd960d95cc2bb72d2",
  "include/net/dropreason.h": "8a0672b3e5921ea7bb76edbebdfc145b4c73f8ed1d55ff37ce7f544bc50bc69c",
  "net/mac80211/drop.h": "d5fb2bad111835c382ad7a6acc2e15d307102d2bb17f7ebd5857cb6e79b591a2",
  "net/mac80211/key.h": "a2d8b850487fe3df29fc8f00c9383ea7cef2e92137b15686b568351b9b163e12"
}
for name,digest in EXPECTED_HASHES.items():
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,name
def function(path,name):
 s=sources[path];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',s);assert m,name
 start=s.rfind('\n\n',0,m.start())+2
 while s[start:start+1]=='#':start=s.index('\n',start)+1
 at=m.end();depth=1
 while depth:depth+=(s[at]=='{')-(s[at]=='}');at+=1
 return s[start:at]+'\n'
def layout(path,name):
 s=sources[path];m=re.search(r'\bstruct '+name+r' \{',s);assert m,name
 at=m.end();depth=1
 while depth:depth+=(s[at]=='{')-(s[at]=='}');at+=1
 return s[m.start():s.index(';',at)+1]+'\n'
pre=r'''
// Source oracle only; no firmware ACK, PMF association or physical acceptance claim.
// Complete Linux CMAC/BIP helpers GPL-2.0, original full notices retained in donors.
// Copyright 2008 Jouni Malinen; 2020 Intel Corporation; 2026 Google LLC.
// Header: 2001-2003 SSH Communications Security Corp/Jouni Malinen;
// 2005 Devicescape Software; 2006 Michael Wu; 2013-2014 Intel Mobile Communications;
// 2016-2017 Intel Deutschland; 2018-2026 Intel Corporation.
// RX: 2002-2005 Instant802; 2005-2006 Devicescape; 2006-2007 Jiri Benc;
// 2007-2010 Johannes Berg; 2013-2014 Intel Mobile; 2015-2017 Intel Deutschland;
// 2018-2026 Intel Corporation. Drop reasons: 2023-2024,2026 Intel Corporation.
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonCryptor.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef int64_t s64;typedef uint64_t __be64;typedef uint16_t __le16;
#define __bitwise
#define __force
#define __rcu
#define BIT(n) (1ULL<<(n))
#define IEEE80211_CMAC_128_MIC_LEN 8
#define AES_BLOCK_SIZE 16
#define IEEE80211_CMAC_256_MIC_LEN 16
#define AAD_LEN 20
#define ETH_ALEN 6
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little-endian oracle host.
#endif
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_be64(x) __builtin_bswap64(x)
#define be64_to_cpu(x) __builtin_bswap64(x)
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define struct_group(name,...) union { struct { __VA_ARGS__ }; struct { __VA_ARGS__ } name; }
#define min(a,b) ((a)<(b)?(a):(b))
static void crypto_xor(u8*a,const u8*b,size_t n){while(n--)*a++^=*b++;}
static void memzero_explicit(void*p,size_t n){volatile u8*q=p;while(n--)*q++=0;}
#define put_unaligned(x,p) do{__typeof__(x) z=(x);memcpy((p),&z,sizeof(z));}while(0)
struct aes_enckey {u8 raw[32];size_t len;};
static int aes_prepareenckey(struct aes_enckey*k,const u8*raw,size_t len){if(len!=16 && len!=24 && len!=32)return -22;memcpy(k->raw,raw,len);k->len=len;return 0;}
// Host CommonCrypto AES primitive only: CMAC state/subkeys/BIP remain complete unchanged source.
static void aes_encrypt(const struct aes_enckey*k,u8*out,const u8*in){u8 tmp[16];size_t n=0;if(CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,k->raw,k->len,0,in,16,tmp,16,&n)!=kCCSuccess||n!=16)abort();memcpy(out,tmp,16);}
struct ieee80211_rx_status { u32 flag; };
struct sk_buff {u8*data;size_t len;struct ieee80211_rx_status status;};
#define IEEE80211_SKB_RXCB(s) (&(s)->status)
static void skb_trim(struct sk_buff*s,size_t n){if(n>s->len)abort();s->len=n;}
static int crypto_memneq(const void*a,const void*b,size_t n){const u8*p=a,*q=b;u8 d=0;while(n--)d|=*p++^*q++;return d;}
static bool is_multicast_ether_addr(const u8*p){return p[0]&1;}
// Exact ieee80211_mgmt header prefix; no helper casts into its variable union.
struct ieee80211_mgmt {__le16 frame_control,duration;u8 da[6],sa[6],bssid[6];__le16 seq;};
#define IEEE80211_MIN_ACTION_SIZE(member) 25

static const u8 zero[16];
'''
parts=[]
for name in ['IEEE80211_FCTL_PROTECTED','IEEE80211_STYPE_DISASSOC','IEEE80211_STYPE_DEAUTH','IEEE80211_STYPE_ACTION','IEEE80211_FCTL_FTYPE','IEEE80211_FCTL_STYPE','IEEE80211_FCTL_RETRY','IEEE80211_FCTL_PM','IEEE80211_FCTL_MOREDATA','IEEE80211_FTYPE_MGMT','IEEE80211_STYPE_BEACON']:
 m=re.search(r'^#define '+name+r'\s+[^\n]+',sources[files[0]],re.M);assert m;parts.append(m.group()+'\n')
parts += [layout(files[0],'ieee80211_mmie'),layout(files[0],'ieee80211_mmie_16'),layout(files[0],'ieee80211_mmie_var'),layout(files[0],'ieee80211_hdr'),layout(files[1],'aes_cmac_key'),layout(files[1],'aes_cmac_ctx')]
for name in ['WLAN_CATEGORY_PUBLIC','WLAN_CATEGORY_HT','WLAN_CATEGORY_WNM_UNPROTECTED','WLAN_CATEGORY_SELF_PROTECTED','WLAN_CATEGORY_UNPROT_DMG','WLAN_CATEGORY_VHT','WLAN_CATEGORY_S1G','WLAN_CATEGORY_VENDOR_SPECIFIC','WLAN_EID_MMIE']:
 match=re.search(r'\b'+name+r'\s*=\s*([0-9]+)',sources[files[0]]);assert match,name
 parts.append('#define '+name+' '+match[1]+'\n')
for name in ['include/net/dropreason-core.h','include/net/dropreason.h','net/mac80211/drop.h']:
 parts.append(re.sub(r'^#include[^\n]*\n','',sources[name],flags=re.M))
flags=sources['include/net/mac80211.h'];at=flags.index('enum mac80211_rx_flags {');parts.append(flags[at:flags.index('};',at)+2]+'\n')
parts.append('struct ieee80211_key {union {struct {u8 rx_pn[6];struct aes_cmac_key key;u32 replays,icverrors;} aes_cmac;} u;};\nstruct ieee80211_rx_data {struct sk_buff*skb;struct ieee80211_key*key;};\n')
helpers=[(files[0],'ieee80211_is_beacon'),(files[1],'aes_cmac_init'),(files[2],'aes_cbcmac_blocks_arch'),(files[2],'aes_cbcmac_blocks'),(files[2],'aes_cmac_preparekey'),(files[2],'aes_cmac_update'),(files[2],'aes_cmac_final'),(files[3],'ieee80211_aes_cmac'),(files[4],'bip_aad'),(files[4],'bip_ipn_set64'),(files[4],'bip_ipn_swap'),(files[0],'ieee80211_is_mgmt'),(files[0],'ieee80211_is_disassoc'),(files[0],'ieee80211_is_deauth'),(files[0],'ieee80211_is_action'),(files[0],'ieee80211_has_protected'),(files[0],'_ieee80211_is_robust_mgmt_frame'),(files[0],'ieee80211_is_robust_mgmt_frame'),('net/mac80211/rx.c','ieee80211_get_mmie_keyidx'),(files[4],'ieee80211_crypto_aes_cmac_decrypt')]
main=r'''
static void mac_matrix(void){
 const u8 key0[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
 const u8 empty[16]={0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
 struct aes_cmac_key key;struct aes_cmac_ctx ctx;u8 mic[16];
 if(aes_cmac_preparekey(&key,key0,16))abort();aes_cmac_init(&ctx,&key);aes_cmac_final(&ctx,mic);if(memcmp(mic,empty,16))abort();
 for(size_t i=0;i<384;i++){
  u8 raw[16],frame[24+130+18]={0},aad[20],ipn[6];size_t body=i%131,len=24+body+18;
  for(size_t j=0;j<16;j++)raw[j]=i*17+j;
  u16_unused: ;
  uint16_t fc=(i%3==0?0x00c0:i%3==1?0x00a0:0x00d0)|((i/3)%8)*0x0800;
  memcpy(frame,&fc,2);for(size_t j=4;j<24;j++)frame[j]=i*7+j;
  for(size_t j=0;j<body;j++)frame[24+j]=i*31+j;
  u8*mmie=frame+24+body;mmie[0]=76;mmie[1]=16;mmie[2]=4+i%2;bip_ipn_set64(mmie+4,i*1000003ULL+1);
  struct sk_buff skb={frame,len};bip_aad(&skb,aad);bip_ipn_swap(ipn,mmie+4);
  if(aes_cmac_preparekey(&key,raw,16))abort();ieee80211_aes_cmac(&key,aad,frame+24,len-24,mmie+10,8);
  u8 hdr[]={i%256,i/256,len%256,len/256};if(fwrite(hdr,1,4,stdout)!=4||fwrite(frame,1,len,stdout)!=len||fwrite(aad,1,20,stdout)!=20||fwrite(ipn,1,6,stdout)!=6)abort();
 }
}
'''.replace('  u16_unused: ;\n','')

extra=r'''
static size_t make_frame(u8*frame,size_t i,u64 pn){
 memset(frame,0,200);size_t body=i%3==2?6+i%61:2+i%65,len=24+body+18;
 u16 fc=(i%3==0?0x00c0:i%3==1?0x00a0:0x00d0)|(((i/3)%8)<<11);
 memcpy(frame,&fc,2);memset(frame+4,0xff,6);u8 peer[]={2,6,7,8,9,10};memcpy(frame+10,peer,6);memcpy(frame+16,peer,6);
 frame[22]=i<<4;frame[23]=i>>4;
 for(size_t j=0;j<body;j++)frame[24+j]=i*31+j;
 frame[24]=i%3==2?3:7;frame[25]=i%3==2?2:0;
 u8*mmie=frame+24+body;mmie[0]=76;mmie[1]=16;mmie[2]=4+i%2;bip_ipn_set64(mmie+4,pn);
 u8 raw[16],aad[20];memset(raw,0x55,16);struct aes_cmac_key key;struct sk_buff skb={.data=frame,.len=len};
 if(aes_cmac_preparekey(&key,raw,16))abort();bip_aad(&skb,aad);ieee80211_aes_cmac(&key,aad,frame+24,len-24,mmie+10,8);return len;
}
static void rx_matrix(void){
 u64 floors[]={0,1,100,0xfffffffffffeULL,0xffffffffffffULL};
 u64 pns[]={0,1,2,101,0xfffffffffffeULL,0xffffffffffffULL};
 for(size_t i=0;i<128;i++)for(size_t f=0;f<5;f++)for(size_t p=0;p<6;p++)for(size_t mode=0;mode<7;mode++){
  u8 frame[200],raw[16];memset(raw,0x55,16);size_t len=make_frame(frame,i,pns[p]);u8*mmie=frame+len-18;
  if(mode==1)frame[len-1]^=1;
  if(mode==2)mmie[0]^=1;
  if(mode==3)mmie[1]^=1;
  if(mode==4)mmie[2]^=1;
  if(mode==5)frame[24]^=1;
  struct ieee80211_key key={0};if(aes_cmac_preparekey(&key.u.aes_cmac.key,raw,16))abort();
  u8 le[6];bip_ipn_set64(le,floors[f]);bip_ipn_swap(key.u.aes_cmac.rx_pn,le);
  key.u.aes_cmac.replays=i%7==0?UINT32_MAX:0;key.u.aes_cmac.icverrors=i%11==0?UINT32_MAX:0;
  struct sk_buff skb={.data=frame,.len=len,.status={.flag=mode==6?RX_FLAG_DECRYPTED:0}};
  struct ieee80211_rx_data rx={.skb=&skb,.key=&key};
  bool accepted=false;
  if(ieee80211_get_mmie_keyidx(&skb)==4+i%2)accepted=ieee80211_crypto_aes_cmac_decrypt(&rx,8)==RX_CONTINUE;
  u8 hdr[]={i,f,p,mode,accepted};u16 after_len=skb.len;
  if(fwrite(hdr,1,5,stdout)!=5||fwrite(key.u.aes_cmac.rx_pn,1,6,stdout)!=6||fwrite(&key.u.aes_cmac.replays,1,4,stdout)!=4||fwrite(&key.u.aes_cmac.icverrors,1,4,stdout)!=4||fwrite(&after_len,1,2,stdout)!=2||fwrite(frame,1,skb.len,stdout)!=skb.len)abort();
 }
}
static void robust_matrix(void){
 u16 types[]={0x00c0,0x00a0,0x00d0,0x0080,0x00b0,0x0008};
 for(size_t t=0;t<6;t++)for(size_t protect=0;protect<2;protect++)for(size_t category=0;category<256;category++){
  u8 frame[32]={0};u16 fc=types[t]|(protect?0x4000:0);memcpy(frame,&fc,2);frame[24]=category;
  struct sk_buff skb={.data=frame,.len=25};u8 value=ieee80211_is_robust_mgmt_frame(&skb);if(fwrite(&value,1,1,stdout)!=1)abort();
 }
}
int main(int argc,char**argv){
 if(argc!=2)return 1;
 if(!strcmp(argv[1],"mac"))mac_matrix();
 else if(!strcmp(argv[1],"rx"))rx_matrix();
 else if(!strcmp(argv[1],"robust"))robust_matrix();
 else if(!strcmp(argv[1],"native")){u8 frame[200];size_t len=make_frame(frame,0,101);if(fwrite(frame,1,len,stdout)!=len)abort();}
 else return 1;return 0;
}
'''

unit=out/'source.c';unit.write_text(pre+''.join(parts)+''.join(function(*p) for p in helpers)+main+extra)
exe=out/'source';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit),'-o',str(exe)],check=True)
cases=[]
for profile,count in [('mac',384),('rx',26880),('robust',3072),('native',1)]:
 trace=subprocess.check_output([str(exe.resolve()),profile]);(out/(profile+'.trace')).write_bytes(trace)
 cases.append({'profile':profile,'cases':count,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':EXPECTED_HASHES,'helpers':{n:hashlib.sha256(function(p,n).encode()).hexdigest() for p,n in helpers},'cases':cases,'oracle_limits':['Independent host CommonCrypto AES primitive; full unchanged pinned CMAC/BIP helper bodies','Modeled typed key/skb storage; no PMF association, native ACK or physical qualification','Selected-key cryptographic helper contract, not full Linux RX dispatch: its DECRYPTED+IV_STRIPPED early return is deliberately outside this software-authentication API; mode6 uses DECRYPTED only on valid MICs','RX helper receives source-selected key; native still must bind actual owner/peer/association and frame integrity observations','Beacon BIGTK, CMAC256/GMAC and fragment/aggregate handling outside the current native BIP128 scope']}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(cases,indent=2))
