#!/usr/bin/env python3
"""Execute complete pinned mt76 CCMP PN helper across mixed QoS/non-QoS data.

Usage: wifi_mixed_replay_oracle.py MT76_MAC80211_C KERNEL_MAC80211_H FRESH_OUTPUT [--management]
The source helper receives actual source-shaped decrypted/IV-stripped observations.
This checks replay indexing/counter effects, not physical integrity or crypto.
"""
import hashlib,json,subprocess,sys
from pathlib import Path
from wifi_data_oracle import complete_function
from wifi_mac_oracle import PIN

source,header,out=map(Path,sys.argv[1:4]);out.mkdir(parents=True,exist_ok=False)
management='--management' in sys.argv[4:]
kinds=20 if management else 17
pins=['4a88a2105def248340f237377f698300478e1352dfc81a955e8a5e61f91d07df','3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9']
texts=[]
for path,pin in zip([source,header],pins):
 b=path.read_bytes();assert hashlib.sha256(b).hexdigest()==pin,path;texts.append(b.decode())
helper=complete_function(texts[0],'static void\nmt76_check_ccmp_pn(')
flags=complete_function(texts[1],'enum mac80211_rx_flags {')+';'
code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint64_t u64;
#define BIT(x) (1ULL << (x))
#define BUILD_BUG_ON(x) do{_Static_assert(!(x),#x);}while(0)
#define IEEE80211_QOS_CTL_TID_MASK 15
#define IEEE80211_NUM_TIDS 16
'''+flags+r'''
struct mt76_wcid{bool rx_check_pn;u8 rx_key_pn[17][6];};
struct mt76_rx_status{u64 flag;struct mt76_wcid*wcid;u16 qos_ctl;u8 iv[6];};
struct ieee80211_hdr{u16 frame_control,duration;u8 addresses[18];u16 seq_ctrl;};
struct sk_buff{u8 cb[128] __attribute__((aligned(8)));struct ieee80211_hdr header;};
static struct ieee80211_hdr*mt76_skb_get_hdr(struct sk_buff*s){return &s->header;}
static bool ieee80211_is_frag(struct ieee80211_hdr*h){return (h->frame_control&0x400)||(h->seq_ctrl&15);}
static bool ieee80211_is_first_frag(u16 seq){return !(seq&15);}
static bool ieee80211_is_mgmt(u16 fc){return !(fc&12);}
static bool ieee80211_has_tods(u16 fc){return !!(fc&0x100);}
'''+helper+r'''
static void pn(u8 out[6],u64 value){for(unsigned i=0;i<6;i++)out[i]=value>>(8*(5-i));}
static bool receive(struct mt76_wcid*w,unsigned kind,u64 value){
 struct sk_buff skb={0};struct mt76_rx_status*s=(void*)skb.cb;
 skb.header.frame_control=kind==16?0x4208:0x4288;
 s->flag=RX_FLAG_DECRYPTED|RX_FLAG_IV_STRIPPED;s->wcid=w;s->qos_ctl=kind==16?0:kind;pn(s->iv,value);
 mt76_check_ccmp_pn(&skb);
 u8 result[]={!(s->flag&RX_FLAG_ONLY_MONITOR),!!(s->flag&RX_FLAG_PN_VALIDATED)};
 if(fwrite(result,1,2,stdout)!=2)abort();
 return result[0];
}
int main(void){
 const u64 maximum=(1ULL<<48)-1;
 const u64 seeds[]={0,1,17,maximum};const u64 values[]={0,1,2,17,18,maximum-1,maximum};
 for(unsigned a=0;a<17;a++)for(unsigned b=0;b<17;b++)for(unsigned si=0;si<4;si++)for(unsigned i=0;i<7;i++)for(unsigned j=0;j<7;j++){
  struct mt76_wcid w={.rx_check_pn=true};for(unsigned q=0;q<17;q++)pn(w.rx_key_pn[q],seeds[si]);
  receive(&w,a,values[i]);receive(&w,b,values[j]);
  if(fwrite(w.rx_key_pn,1,sizeof(w.rx_key_pn),stdout)!=sizeof(w.rx_key_pn))abort();
 }
 return 0;
}
'''
if management:
 code=code.replace('skb.header.frame_control=kind==16?0x4208:0x4288;',
  'skb.header.frame_control=kind<16?0x4288:kind==16?0x4208:kind==17?0x40c0:kind==18?0x40a0:0x40d0;')
 code=code.replace('s->qos_ctl=kind==16?0:kind;', 's->qos_ctl=kind<16?kind:0;')
 code=code.replace('a<17;a++)for(unsigned b=0;b<17', 'a<20;a++)for(unsigned b=0;b<20')
unit=out/'mixed-replay.c';unit.write_text(code);binary=out/'mixed-replay'
subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit),'-o',str(binary)],check=True)
trace=subprocess.check_output([str(binary.resolve())]);assert len(trace)==kinds*kinds*4*7*7*106
(out/'mixed-replay.trace').write_bytes(trace)
receipt={'linux_commit':PIN,'sources':dict(zip(['drivers/net/wireless/mediatek/mt76/mac80211.c','include/net/mac80211.h'],pins)),'helper_sha256':hashlib.sha256(helper.encode()).hexdigest(),'flags_sha256':hashlib.sha256(flags.encode()).hexdigest(),'harness_sha256':hashlib.sha256(code.encode()).hexdigest(),'cases':kinds*kinds*4*7*7,'trace_sha256':hashlib.sha256(trace).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'oracle_limit':['Accepted profile is ordinary protected unfragmented data with actual modeled decrypted/IV-stripped PN observations. No physical MIC verification, fragments, aggregation or protected management authority is established.','Non-QoS source status qos_ctl is zero, matching native source parsing; the complete PN helper chooses its own counter and mutates all 17 modeled queues.']}
if management:
 receipt['profile']='unicast robust management + ordinary data, IV/MIC stripped and hardware verified'
 receipt['oracle_limit']=[
  'This executes the complete source replay helper under modeled decrypted/IV-stripped observations, not MIC verification, firmware installation, current-association delivery or PMF negotiation.',
  'Non-QoS and management source qos_ctl is zero; the unchanged source helper selects management counter16 itself and mutates all17 modeled counters. Fragments/aggregation/ToDS management are outside the native accepted profile.'
 ]
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
