#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pinned complete RX crypto/create-SKB helpers with explicit mock boundaries.
Usage: SCRIPT SOURCE_DIRECTORY OUTPUT_DIRECTORY
Uses shared MAC's unchanged header helpers only in this research fixture.
No real keys, DMA, security acknowledgement or kernel SKB allocator executes.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'mvm/rxmq.c':'aa35ae948dd468ee78cb870c2d9f4bc7d99fe5e8e5ff23eeef53b36ac7fdc32d',
'fw/api/rx.h':'5bfbab2457de067f13c01158014d336b09803024d96e17dea58742293bbd57dc',
'iwl-trans.h':'96d1daa1a251e4c1c4d96a3f625db7cc207d0051375010aa7790830cf730a3c4',
'fw/file.h':'f3859d195bd190427e490f6b7c82e924b6e79f2e9cc7243ea2f5097a3195b1c3',
'linux/include/linux/ieee80211.h':'a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa',
'linux/net/wireless/util.c':'634e0be5dc138ee467b2b08a287480cd7b639cd0c498ba742b0c7a703621ae22',
}
texts={}
for name,sha in expected.items():
 b=(source/name).read_bytes();assert hashlib.sha256(b).hexdigest()==sha,name;texts[name]=b.decode()
def extract(file,pattern):
 text=texts[file];m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
prelude='/* SPDX-License-Identifier: GPL-2.0-only */\n'
for file in ['mvm/rxmq.c','linux/include/linux/ieee80211.h','linux/net/wireless/util.c']:
 prelude+='\n'.join(l for l in texts[file][:texts[file].index('#include')].splitlines() if not l.startswith('#'))+'\n'
prelude+=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;typedef uint16_t __be16;
#define __packed __attribute__((packed))
#define __attribute_const__
#define BIT(n) (1U<<(n))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define u8_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))
#define unlikely(x) (x)
#define fallthrough __attribute__((fallthrough))
#define BUILD_BUG_ON(x) ((void)sizeof(char[(x)?-1:1]))
#define IWL_DEBUG_DROP(...)
#define IWL_WARN(...)
#define RX_FLAG_DECRYPTED 1
#define RX_FLAG_MIC_STRIPPED 2
#define RX_FLAG_MMIC_ERROR 4
#define RX_FLAG_ICV_STRIPPED 8
#define RX_FLAG_MMIC_STRIPPED 16
#define IEEE80211_CCMP_PN_LEN 6
#define IEEE80211_GCMP_PN_LEN 6
#define IEEE80211_CCMP_HDR_LEN 8
#define IEEE80211_TKIP_IV_LEN 8
#define IEEE80211_WEP_IV_LEN 4
#define IWL_UCODE_TLV_API_DEPRECATE_TTAK 41
#define FH_RSCSR_RADA_EN BIT(26)
#define IWL_DEVICE_FAMILY_BZ 2
#define CHECKSUM_NONE 0
#define CHECKSUM_COMPLETE 1
#define RX_INCLUDES_FCS 0
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_PAE 0x888e
#define ETH_P_TDLS 0x890d
struct ieee80211_hdr {__le16 frame_control,duration;u8 addr1[6],addr2[6],addr3[6];__le16 sequence;u8 addr4[6];} __packed;
struct ieee80211_sta {int unused;};struct ieee80211_rx_status {unsigned flag;};struct fw {struct {bool deprecated;}ucode_capa;};struct mac_cfg {bool gen2;int device_family;};struct trans {struct mac_cfg *mac_cfg;};struct hw {bool includes_fcs;};struct iwl_mvm {struct fw *fw;struct trans *trans;struct hw *hw;bool monitor_on;};
static bool fw_has_api(const void *c,unsigned api){(void)api;return ((const typeof(((struct fw*)0)->ucode_capa)*)c)->deprecated;}
static bool net_ratelimit(void){return false;}
static bool is_multicast_ether_addr(const u8 *p){return p[0]&1;}
static bool ieee80211_hw_check(struct hw *h,unsigned flag){(void)flag;return h->includes_fcs;}
struct sk_buff {u8 bytes[8192];unsigned len,tailroom;int ip_summed;};
struct iwl_rx_packet {u32 flags;u8 hdr[4];u8 data[];};struct iwl_rx_cmd_buffer {u8 *raw;};
static void *rxb_addr(struct iwl_rx_cmd_buffer *r){return r->raw;}
static unsigned rxb_offset(struct iwl_rx_cmd_buffer *r){(void)r;return 0;}
static void *rxb_steal_page(struct iwl_rx_cmd_buffer *r){return r->raw;}
static unsigned skb_tailroom(struct sk_buff *s){return s->tailroom-s->len;}
static void skb_set_mac_header(struct sk_buff *s,unsigned n){(void)s;(void)n;}
static void skb_put_data(struct sk_buff *s,const void *p,unsigned n){if(s->len+n>sizeof(s->bytes))abort();memcpy(s->bytes+s->len,p,n);s->len+=n;}
static void skb_add_rx_frag(struct sk_buff *s,int nr,void *page,unsigned offset,unsigned len,unsigned size){(void)nr;(void)size;skb_put_data(s,(u8*)page+offset,len);}
static void skb_postpush_rcsum(struct sk_buff *s,void *p,unsigned n){(void)s;(void)p;(void)n;abort();}
static bool ether_addr_equal(const u8 *a,const u8 *b){return memcmp(a,b,6)==0;}
static const u8 rfc1042_header[6]={0xaa,0xaa,3,0,0,0};
'''
prelude=prelude.replace('struct iwl_rx_cmd_buffer {u8 *raw;}', 'struct iwl_rx_cmd_buffer {u8 *raw;unsigned truesize;}')
header=texts['linux/include/linux/ieee80211.h']
for name in ['IEEE80211_FCTL_FTYPE','IEEE80211_FCTL_STYPE','IEEE80211_FCTL_TODS','IEEE80211_FCTL_FROMDS','IEEE80211_FCTL_ORDER','IEEE80211_FCTL_PROTECTED','IEEE80211_FTYPE_MGMT','IEEE80211_FTYPE_CTL','IEEE80211_FTYPE_DATA','IEEE80211_FTYPE_EXT','IEEE80211_STYPE_QOS_DATA','IEEE80211_QOS_CTL_LEN','IEEE80211_HT_CTL_LEN']:
 prelude+=('#define IEEE80211_HT_CTL_LEN 4' if name=='IEEE80211_HT_CTL_LEN' else next(l for l in header.splitlines() if re.match(r'^#define '+name+r'\b',l)))+'\n'
for name in ['ieee80211_has_a4','ieee80211_has_order','ieee80211_has_protected','ieee80211_is_mgmt','ieee80211_is_ctl','ieee80211_is_data','ieee80211_is_ext','ieee80211_is_data_qos']:
 prelude+=extract('linux/include/linux/ieee80211.h',r'^static inline bool '+name+r'\([^{};]*?\)\n\{')+'\n'
prelude+=extract('linux/net/wireless/util.c',r'^unsigned int __attribute_const__ ieee80211_hdrlen\([^{};]*?\)\n\{')+'\n'
for name in ['iwl_mvm_rx_status','iwl_rx_mpdu_status','iwl_rx_mpdu_phy_info','iwl_rx_mpdu_mac_flags1','iwl_rx_mpdu_mac_flags2']:
 prelude+=extract('fw/api/rx.h',r'^enum '+name+r'\s*\{')+';\n'
for name in ['iwl_rx_mpdu_desc_v1','iwl_rx_mpdu_desc_v3','iwl_rx_mpdu_desc']:
 prelude+=extract('fw/api/rx.h',r'^struct '+name+r'\s*\{')+' __packed;\n'
# Initial path has no MFP. Only plaintext management is admitted here; an
# attempted use of the fixture as management-protection authority aborts.
prelude+='static int iwl_mvm_rx_mgmt_prot(struct ieee80211_sta *s,struct ieee80211_hdr *h,struct iwl_rx_mpdu_desc *d,u32 status,struct ieee80211_rx_status *r){(void)s;(void)h;(void)d;(void)r;if(status&IWL_RX_MPDU_STATUS_SEC_MASK)abort();return 0;}\n'
prelude+=extract('mvm/rxmq.c',r'^static int iwl_mvm_rx_crypto\([^{};]*?\)\n\{')+'\n'
prelude+=extract('mvm/rxmq.c',r'^static int iwl_mvm_create_skb\([^{};]*?\)\n\{')+'\n'
main=r'''
int main(void){
 struct mac_cfg cfg={true,0};struct trans tr={&cfg};struct fw fw={0};struct hw hw={false};struct iwl_mvm m={&fw,&tr,&hw,false};struct ieee80211_hdr hdr={0};
 for(unsigned cipher=0;cipher<8;cipher++)for(unsigned flags=0;flags<32;flags++)for(unsigned dep=0;dep<2;dep++)for(unsigned ampdu=0;ampdu<2;ampdu++)for(unsigned monitor=0;monitor<2;monitor++)for(unsigned protected=0;protected<2;protected++)for(unsigned rada=0;rada<2;rada++){
  unsigned status=3|(cipher<<8)|((flags&1)?BIT(3):0)|((flags&2)?BIT(5):0)|((flags&4)?BIT(6):0)|((flags&8)?BIT(7):0)|((flags&16)?BIT(11):0);
  struct iwl_rx_mpdu_desc desc={.status=status};struct ieee80211_rx_status stats={0};u8 crypt=0;fw.ucode_capa.deprecated=dep;m.monitor_on=monitor;hdr.frame_control=0x208|(protected?0x4000:0);
  int ret=iwl_mvm_rx_crypto(&m,NULL,&hdr,&stats,ampdu?IWL_RX_MPDU_PHY_AMPDU:0,&desc,rada?FH_RSCSR_RADA_EN:0,0,&crypt);
  printf("crypto %u %u %u %u %u %u %u %d %u %u\n",cipher,flags,dep,ampdu,monitor,protected,rada,ret,stats.flag,crypt);
 }
 u16 frames[]={0x208,0x288,0x308,0x388};unsigned payloads[]={0,8,200};
 for(unsigned family=0;family<2;family++)for(unsigned frame=0;frame<4;frame++)for(unsigned cryptcase=0;cryptcase<3;cryptcase++)for(unsigned pad=0;pad<2;pad++)for(unsigned tail=0;tail<16;tail++)for(unsigned body=0;body<3;body++){
  unsigned crypt=cryptcase==0?0:cryptcase==1?4:8,headers=ieee80211_hdrlen(frames[frame]),descsize=family?64:48;
  u8 packet[4096]={0};struct iwl_rx_packet *pkt=(void*)packet;struct iwl_rx_mpdu_desc *d=(void*)pkt->data;unsigned len=headers+crypt+pad*2+tail*2+payloads[body];d->mpdu_len=len;d->mac_flags1=tail<<4;d->mac_flags2=pad?IWL_RX_MPDU_MFLG2_PAD:0;
  u8 *wire=pkt->data+descsize;unsigned scene=family*71+frame*59+cryptcase*43+pad*37+tail*23+body*17;for(unsigned i=0;i<len;i++)wire[i]=(u8)(i*29+scene);memcpy(wire,&frames[frame],2);
  struct sk_buff skb={.tailroom=128-pad*2,.ip_summed=CHECKSUM_NONE};struct iwl_rx_cmd_buffer rxb={packet,sizeof(packet)};cfg.device_family=family;
  int ret=iwl_mvm_create_skb(&m,&skb,(void*)wire,len,crypt,&rxb);printf("normalize %u %u %u %u %u %u %u %d %u ",family,frame,cryptcase,pad,tail,body,scene,ret,skb.len);for(unsigned i=0;i<skb.len;i++)printf("%02x",skb.bytes[i]);puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-rx-crypto.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-rx-crypto'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
