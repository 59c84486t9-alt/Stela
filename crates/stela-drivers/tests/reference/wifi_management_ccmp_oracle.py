#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run complete pinned hardware-decrypted CCMP management receive helpers.

Usage: wifi_management_ccmp_oracle.py VERIFIED_LINUX_CACHE FRESH_OUTPUT_DIRECTORY
The complete selected-key mac80211 CCMP helper checks PN and strips IV/MIC.
No software AES-CCM is substituted: every unreachable software-crypto branch
aborts. Modeled hardware verification is an input, not a physical MIC proof.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from wifi_mac_oracle import PIN

root, out = map(Path, sys.argv[1:3])
out.mkdir(parents=True, exist_ok=False)
pins = {
 'include/linux/ieee80211.h': 'a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa',
 'net/wireless/util.c': '634e0be5dc138ee467b2b08a287480cd7b639cd0c498ba742b0c7a703621ae22',
 'net/mac80211/wpa.c': '07087347278d9f01307c98bad12554a611a8b70f703af4e7ca31747713d365b5',
 'net/mac80211/rx.c': '58cb7a2c9019190faab4ac4af9c7c76cfbff34015c2b2e76005b429a21364cdf',
 'include/net/mac80211.h': '3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9',
 'include/net/dropreason-core.h': '06d0d26693b0c7864422232ba190214e9cecc8b5481c63ccd960d95cc2bb72d2',
 'include/net/dropreason.h': '8a0672b3e5921ea7bb76edbebdfc145b4c73f8ed1d55ff37ce7f544bc50bc69c',
 'net/mac80211/drop.h': 'd5fb2bad111835c382ad7a6acc2e15d307102d2bb17f7ebd5857cb6e79b591a2',
 'net/mac80211/ieee80211_i.h': 'f8875ff901826b64ed2b5131f955c9861c91430d3c5b81e0d794a93569029e5a',
}
sources = {}
for name, pin in pins.items():
 data = (root / name).read_bytes()
 assert hashlib.sha256(data).hexdigest() == pin, name
 sources[name] = data.decode()

def function(path, name):
 s = sources[path]
 m = re.search(r'\b' + name + r'\([^;{}]*?\)\n\{', s)
 assert m, name
 start = s.rfind('\n\n', 0, m.start()) + 2
 while s[start:start+1] == '#':
  start = s.index('\n', start) + 1
 end, depth = m.end(), 1
 while depth:
  depth += (s[end] == '{') - (s[end] == '}')
  end += 1
 return s[start:end] + '\n'

header = 'include/linux/ieee80211.h'
pre = r'''
// Complete unchanged source helpers; original GPL-2.0 notices retained in donors.
// Copyright 2002-2004 Instant802 Networks; 2008 Jouni Malinen;
// 2007-2009 Johannes Berg; 2013-2014 Intel Mobile Communications;
// 2016-2017 Intel Deutschland; 2018-2026 Intel Corporation.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint16_t __le16;
#define __attribute_const__
#define __bitwise
#define __force
#define __rcu
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define struct_group(name,...) union {struct {__VA_ARGS__};struct {__VA_ARGS__} name;}
#define BIT(n) (1ULL << (n))
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define unlikely(x) (x)
#define IEEE80211_CCMP_HDR_LEN 8
#define IEEE80211_CCMP_PN_LEN 6
#define IEEE80211_NUM_TIDS 16
#define IEEE80211_MIN_ACTION_SIZE(member) 25
#define IEEE80211_QOS_CTL_LEN 2
#define IEEE80211_HT_CTL_LEN 4
#define ETH_ALEN 6
#define AES_BLOCK_SIZE 16
#define IEEE80211_KEY_FLAG_SPP_AMSDU 1
struct ieee80211_rx_status {u64 flag;u32 rx_flags;};
struct sk_buff {u8*data;size_t len;unsigned priority;struct ieee80211_rx_status status;};
#define IEEE80211_SKB_RXCB(s) (&(s)->status)
struct ieee80211_key {struct{unsigned flags;}conf;union{struct{u8 rx_pn[17][6];u32 replays;void*tfm;}ccmp;}u;};
struct ieee80211_rx_data {struct sk_buff*skb;struct ieee80211_key*key;void*sta;int security_idx,seqno_idx;u8 link_addrs[18];struct{u8 pn[6];}ccm_gcm;};
static bool pskb_may_pull(struct sk_buff*s,size_t n){return s->len>=n;}
static int pskb_trim(struct sk_buff*s,size_t n){if(n>s->len)abort();s->len=n;return 0;}
static void skb_pull(struct sk_buff*s,size_t n){if(n>s->len)abort();s->data+=n;s->len-=n;}
static int skb_linearize(struct sk_buff*s){(void)s;abort();}
static bool ieee80211_require_encrypted_assoc(u16 fc,void*sta){(void)fc;(void)sta;abort();}
static bool is_unicast_ether_addr(const u8*a){return !(a[0]&1);}
static void ether_addr_copy(u8*a,const u8*b){memcpy(a,b,6);}
static void ccmp_special_blocks(struct sk_buff*s,u8*pn,u8*b,u8*aad,bool spp,bool computed){(void)s;(void)pn;(void)b;(void)aad;(void)spp;(void)computed;abort();}
static int ieee80211_aes_ccm_decrypt(void*tfm,u8*b,u8*aad,u8*data,int len,u8*mic){(void)tfm;(void)b;(void)aad;(void)data;(void)len;(void)mic;abort();}
'''
parts = []
amsdu = re.search(r'IEEE80211_RX_AMSDU\s*=\s*(BIT\([0-9]+\))', sources['net/mac80211/ieee80211_i.h'])
assert amsdu
parts.append('#define IEEE80211_RX_AMSDU '+amsdu[1]+'\n')
layouts = {}
for name in ['ieee80211_hdr','ieee80211_qos_hdr','ieee80211_qos_hdr_4addr']:
 text = sources[header]; start=text.index('struct '+name+' {'); end=text.index('\n}',start)
 layout=text[start:text.index(';',end)+1]+'\n'
 layouts[name]=hashlib.sha256(layout.encode()).hexdigest();parts.append(layout)
for name in ['IEEE80211_FCTL_FTYPE','IEEE80211_FCTL_STYPE','IEEE80211_FCTL_TODS','IEEE80211_FCTL_FROMDS','IEEE80211_FCTL_ORDER','IEEE80211_FCTL_MOREFRAGS','IEEE80211_FCTL_PROTECTED','IEEE80211_FTYPE_MGMT','IEEE80211_FTYPE_CTL','IEEE80211_FTYPE_DATA','IEEE80211_FTYPE_EXT','IEEE80211_STYPE_QOS_DATA','IEEE80211_STYPE_DISASSOC','IEEE80211_STYPE_DEAUTH','IEEE80211_STYPE_ACTION','IEEE80211_SCTL_FRAG','IEEE80211_QOS_CTL_TID_MASK','IEEE80211_QOS_CTL_A_MSDU_PRESENT']:
 m = re.search(r'^#define ' + name + r'\s+[^\n]+', sources[header], re.M)
 assert m, name
 parts.append(m.group() + '\n')
for name in ['WLAN_CATEGORY_PUBLIC','WLAN_CATEGORY_HT','WLAN_CATEGORY_WNM_UNPROTECTED','WLAN_CATEGORY_SELF_PROTECTED','WLAN_CATEGORY_UNPROT_DMG','WLAN_CATEGORY_VHT','WLAN_CATEGORY_S1G','WLAN_CATEGORY_VENDOR_SPECIFIC']:
 m = re.search(r'\b' + name + r'\s*=\s*([0-9]+)', sources[header]); assert m, name
 parts.append('#define ' + name + ' ' + m[1] + '\n')
for name in ['include/net/dropreason-core.h','include/net/dropreason.h','net/mac80211/drop.h']:
 parts.append(re.sub(r'^#include[^\n]*\n','',sources[name],flags=re.M))
flags = sources['include/net/mac80211.h']; at = flags.index('enum mac80211_rx_flags {')
parts.append(flags[at:flags.index('};',at)+2]+'\n')
helpers = [(header,n) for n in ['ieee80211_has_a4','ieee80211_has_order','ieee80211_has_morefrags','ieee80211_has_protected','ieee80211_is_mgmt','ieee80211_is_ctl','ieee80211_is_data','ieee80211_is_ext','ieee80211_is_data_qos','ieee80211_is_disassoc','ieee80211_is_deauth','ieee80211_is_action','ieee80211_is_frag','ieee80211_get_qos_ctl','_ieee80211_is_robust_mgmt_frame','ieee80211_is_robust_mgmt_frame']]
helpers += [('net/wireless/util.c','ieee80211_hdrlen'),('net/mac80211/rx.c','ieee80211_parse_qos'),('net/mac80211/wpa.c','ccmp_pn2hdr'),('net/mac80211/wpa.c','ccmp_hdr2pn'),('net/mac80211/wpa.c','ieee80211_crypto_ccmp_decrypt')]
main = r'''
static void pn_set(u8 out[6],u64 pn){for(unsigned q=0;q<6;q++)out[q]=pn>>(8*(5-q));}
int main(void){
 const u64 floors[]={0,1,17,0xfffffffffffeULL,0xffffffffffffULL};
 const u64 pns[]={0,1,2,18,0xfffffffffffeULL,0xffffffffffffULL};
 for(unsigned kind=0;kind<3;kind++)for(unsigned f=0;f<5;f++)for(unsigned p=0;p<6;p++)for(unsigned stripped=0;stripped<2;stripped++)for(unsigned body=2;body<66;body++){
  u8 bytes[128]={0},pn[6];u16 fc=kind==0?0x40c0:kind==1?0x40a0:0x40d0;memcpy(bytes,&fc,2);
  u8 local[]={2,1,2,3,4,5},peer[]={2,6,7,8,9,10};memcpy(bytes+4,local,6);memcpy(bytes+10,peer,6);memcpy(bytes+16,peer,6);
  pn_set(pn,pns[p]);ccmp_pn2hdr(bytes+24,pn,0);for(unsigned q=0;q<body;q++)bytes[32+q]=q*3+kind;
  struct sk_buff skb={.data=bytes,.len=32+body+(stripped?0:8),.status.flag=RX_FLAG_DECRYPTED|(stripped?RX_FLAG_MIC_STRIPPED:0)};
  struct ieee80211_key key={0};pn_set(key.u.ccmp.rx_pn[16],floors[f]);
  struct ieee80211_rx_data rx={.skb=&skb,.key=&key,.sta=&key};ieee80211_parse_qos(&rx);
  bool accepted=ieee80211_crypto_ccmp_decrypt(&rx,8)==RX_CONTINUE;
  u16 length=accepted?skb.len:0;u8 prefix[]={accepted,rx.security_idx,length&255,length>>8};
  if(fwrite(prefix,1,4,stdout)!=4||fwrite(key.u.ccmp.rx_pn,1,sizeof(key.u.ccmp.rx_pn),stdout)!=sizeof(key.u.ccmp.rx_pn))abort();
  if(accepted&&fwrite(skb.data,1,length,stdout)!=length)abort();
 }
 return 0;
}
'''
bodies = [function(path,name) for path,name in helpers]
code = pre + '\n'.join(parts+bodies) + main
unit = out/'management-ccmp.c';unit.write_text(code);binary=out/'management-ccmp'
subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit),'-o',str(binary)],check=True,timeout=120)
trace = subprocess.check_output([str(binary.resolve())],timeout=60);assert len(trace)==1_508_160
(out/'management-ccmp.trace').write_bytes(trace)
receipt = {'linux_commit':PIN,'sources':pins,'layouts':layouts,'rx_flags_sha256':hashlib.sha256(parts[-1].encode()).hexdigest(),'helpers':{name:hashlib.sha256(body.encode()).hexdigest() for (_,name),body in zip(helpers,bodies)},'harness_sha256':hashlib.sha256(code.encode()).hexdigest(),'cases':3*5*6*2*64,'trace_bytes':len(trace),'trace_sha256':hashlib.sha256(trace).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'oracle_limit':['Complete source selected-key CCMP helper under modeled DECRYPTED status and real source parse_qos counter16; actual IV retained, MIC retained/stripped, all17 replay counters and successful output bytes.','Software crypto and encrypted-association branches trap if reached. No AES-CCM crypto substitute, hardware MIC proof, whole RX dispatcher, PMF association, frame fragmentation/aggregation or physical radio acceptance. Native additionally requires current PTK/peer/local/BSSID/integrity and rejects hardware replay failures before committing its PN.']}
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
