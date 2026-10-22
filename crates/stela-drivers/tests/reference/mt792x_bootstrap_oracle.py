#!/usr/bin/env python3
"""Unchanged initial MCU helpers, real full writers, MAC/WTBL/rate helpers.
Usage: mt792x_bootstrap_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Only bounded host alloc/register/channel boundaries are modeled. No physical
controller, native regulatory authority, ACK or association is qualified.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
'mt7921/main.c':'c32e0debf40160f8c332efcd7cdffc554db56081edd76add5072be7e3b5f7eee',
'mt7925/main.c':'93023cfa7f7bc57efcf64b2a4fe55d932a60c0128942ff911b2e0d792a0de588',
'mt7921/pci_mcu.c':'3245b5e72efb6913a99a20dcaae14c5f5748fc0b2ac8f47c4b43fb17e4c0057b',
'mt7925/pci_mcu.c':'9569a85ab5888050b4afef34a061d555c41b89835f6ed38c8f1d5ceff3b7d290',
'mt792x_core.c':'6bbd6b23ef25cf30fdc6c8a1396850dfdfd2b5e876a7ca85a1a89b641f9cb716',
'mt792x_dma.c':'8c017d74ba5890665b4f38ad694d9dcde5c680b4683b0d07fbfce61b4a98098e',
'mt7921/mt7921.h':'370d21968a2fd423f4b745be820e83d06f336b17913616da487551a52797baab',
'mt7925/mt7925.h':'b6fec2103954269927b44b095944120dd22a5a0503fa8930e49a8ecc044844dc',
'mt76_connac2_mac.h':'2a0a4bfe2aa5085d8976f69cbb135f0cde7b41eaa39cfbb83901ee2f30b22162',
'mt76_connac3_mac.h':'65f970c7a5cd1868b047ce536710f0b103ea31d5f7dd7c9456b109fda204ecd2',
'mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0',
'mt76_connac_mcu.c':'52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
'mt7921/mcu.c':'3b356eeef80727c27ad5f179e277a9d434297d14ac6df8297c98f4ce445e91b6',
'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
'mt7925/mcu.h':'35855f4cdc673a7562241afd618fdd73fc181d210127e3ca2f762f3199cbc772',
'mt792x_mac.c':'472d899597f5da141a9fba4d9d38d202cd8ac13ba53677e2e527f0b4e1884a45',
'mt792x_regs.h':'6c3d946ff97e6952d8ff702cc0f74c6cc77f64c2e04129d1fdd2ed0024869557',
'mt792x.h':'8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
'mt7921/init.c':'784d38fdd6ee621fe188e7d3e5253c675f80eda8f5420af0c5e861a71bf8c3c5',
'mt7925/init.c':'9463c70eebaa7156d427c914aee04568eca2a564b230cc7928474b81ed1698cb',
'mt7921/mac.c':'c0181ddb14ec01b5a81116cd5fde2eb8cb6c7285336f09382cf99f0c0678d510',
'mt7925/mac.c':'9a74d529f35484137e3c26af529a4af56ed45fdfd38ec5fd55523a196332f40c',
'mt7921/regs.h':'4a7633c0304b8db77c4fd6c5b2786dd6af08b7ae2331a8b31757b9750173cf1c',
'mt7925/regs.h':'5232f74ab0c131ec36084ddd6a44b231b1cc7a1c6171a26f21e5949060a8fdab',
'mac80211.c':'4a88a2105def248340f237377f698300478e1352dfc81a955e8a5e61f91d07df',
'util.c':'9d0a6a93f4b4835e1cacaa4261345eafef5fe1813a138925ba95cc6d0899caf4',
}
t={}
for f,h in hashes.items():
 b=(source/f).read_bytes();assert hashlib.sha256(b).hexdigest()==h,f;t[f]=b.decode()
def function(f,n):
 x=t[f];m=re.search(r'\b'+n+r'\([^;{}]*?\)\n\{',x);assert m,n
 start=x.rfind('\n\n',0,m.start())+2;at,d=m.end(),1
 while d:d+=(x[at]=='{')-(x[at]=='}');at+=1
 return x[start:at]+'\n'
def enum(f,n):
 x=t[f];a=x.rfind('enum {',0,x.index(n));return x[a:x.index('};',a)+2]+'\n'
subprocess.run([sys.executable,str(Path(__file__).with_name('mt792x_mcu_oracle.py')),str(source),str(out/'fill')],check=True,stdout=subprocess.PIPE)
unit=(out/'fill/linux-mt792x-mcu.c').read_text().split('int main(',1)[0]
unit=unit.replace('struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; };','struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; struct {struct {unsigned flags;} conf;void *wiphy;} *hw; };')
unit=unit.replace('struct sk_buff { unsigned char *data; int len; };','struct sk_buff { unsigned char *data; int len; };')
constants=''.join(enum(f,n) for f,n in [('mt76_connac_mcu.h','MCU_CMD_NIC_POWER_CTRL'),('mt76_connac_mcu.h','MCU_EXT_CMD_MAC_INIT_CTRL'),('mt76_connac_mcu.h','MCU_CE_CMD_FWLOG_2_HOST'),('mt76_connac_mcu.h','EE_MODE_EFUSE'),('mt76_connac_mcu.h','EE_FORMAT_WHOLE'),('mt76_connac_mcu.h','CH_SWITCH_NORMAL'),('mt7925/mcu.h','UNI_WSYS_CONFIG_FW_LOG_CTRL'),('mt7925/mcu.h','UNI_EFUSE_BUFFER_MODE'),('mt7925/mcu.h','UNI_BAND_CONFIG_RTS_THRESHOLD')])
# The writer fixture predefines only FW_SCATTER for its own boot cases.
constants=constants.replace('MCU_CMD_FW_SCATTER = 0xee,','')
model=r'''
#include <errno.h>
#define MCU_EXT_CMD(x) (MCU_CMD_EXT_CID | (MCU_EXT_CMD_##x<<8))
#define MCU_CE_CMD(x) (__MCU_CMD_FIELD_CE|MCU_CE_CMD_##x)
#define hweight8(x) __builtin_popcount((unsigned char)(x))
// This boundary models only the admitted normal20 primary-PHY profile; the
// complete unchanged source helper still selects all actual output fields.
#define NL80211_BAND_6GHZ 3
#define NL80211_CHAN_WIDTH_80P80 4
#define IEEE80211_CONF_MONITOR 1
#define NL80211_IFTYPE_AP 1
struct ieee80211_channel {u8 hw_value,band;};
struct cfg80211_chan_def {struct ieee80211_channel *chan;int center_freq1,width,center_freq2;};
struct mt76_phy {struct cfg80211_chan_def chandef;u8 antenna_mask,band_idx;bool offchannel;};
struct mt792x_dev;
struct mt792x_phy {struct mt792x_dev *dev;struct mt76_phy *mt76;bool offchannel;};
struct mt792x_dev {struct mt76_dev mt76;struct mt792x_phy phy;};
static int chip;
static int ieee80211_frequency_to_channel(int f){if(f==2484)return 14;if(f<2484)return(f-2407)/5;if(f==5935)return 2;if(f>=5955)return(f-5950)/5;return(f-5000)/5;}
static u8 mt76_connac_chan_bw(struct cfg80211_chan_def *d){if(d->width!=0)abort();return 0;}
static bool cfg80211_reg_can_beacon(void *a,void *b,int c){(void)a;(void)b;(void)c;abort();}
#define mt76_hw(d) (&(struct {void *wiphy;}){0})
static void output(const void *p,size_t n){if(fwrite(p,1,n,stdout)!=n)abort();}
static int mt76_mcu_send_msg(struct mt76_dev *d,int cmd,const void *p,int n,bool wait){
 u32 c=cmd;u8 w=wait;u16 len=n;output(&c,4);output(&w,1);output(&len,2);output(p,n);
 u8 buffer[1024]={0};if(n+128>sizeof(buffer))abort();memcpy(buffer+128,p,n);struct sk_buff s={buffer+128,n};int seq;
 if(chip==7925?mt7925_mcu_fill_message(d,&s,cmd,&seq):mt76_connac2_mcu_fill_message(d,&s,cmd,&seq))abort();len=s.len;output(&len,2);output(s.data,len);return 0;
}
static int mt76_mcu_send_and_get_msg(struct mt76_dev *d,int c,const void *p,int n,bool w,void *r){if(r)abort();return mt76_mcu_send_msg(d,c,p,n,w);}
'''
helpers=''.join(function(f,n) for f,n in [('mt76_connac_mcu.c','mt76_connac_mcu_restart'),('mt76_connac_mcu.c','mt76_connac_mcu_set_mac_enable'),('mt76_connac_mcu.c','mt76_connac_mcu_set_rts_thresh'),('mt7921/mcu.c','mt7921_mcu_fw_log_2_host'),('mt7921/mcu.c','mt7921_mcu_set_eeprom'),('mt7921/mcu.c','mt7921_mcu_set_chan_info'),('mt7921/mcu.c','mt7921_mcu_radio_led_ctrl'),('mt7925/mcu.c','mt7925_mcu_fw_log_2_host'),('mt7925/mcu.c','mt7925_mcu_set_eeprom'),('mt7925/mcu.c','mt7925_mcu_set_rts_thresh')])
main=r'''
int main(int argc,char **argv){if(argc!=2)return 1;chip=atoi(argv[1]);struct mt792x_dev d={0};struct mt76_phy m={0};d.phy=(struct mt792x_phy){.dev=&d,.mt76=&m};
 for(int i=0;i<32;i++){
  if(mt76_connac_mcu_restart(&d.mt76))abort();
  if(chip==7925){if(mt7925_mcu_fw_log_2_host(&d,1)||mt7925_mcu_set_eeprom(&d)||mt7925_mcu_set_rts_thresh(&d.phy,0x92b))abort();}
  else{if(mt7921_mcu_fw_log_2_host(&d,1)||mt7921_mcu_set_eeprom(&d)||mt76_connac_mcu_set_rts_thresh(&d.mt76,0x92b,0)||mt76_connac_mcu_set_mac_enable(&d.mt76,0,i%2,false))abort();
   struct ieee80211_channel ch={.hw_value=(i%2)?36:1,.band=(i%2)?1:0};m.chandef=(struct cfg80211_chan_def){&ch,(i%2)?5180:2412,0,0};m.antenna_mask=1+(i%15);if(mt7921_mcu_set_chan_info(&d.phy,MCU_EXT_CMD(SET_RX_PATH)))abort();
   if(mt7921_mcu_radio_led_ctrl(&d,1)||mt7921_mcu_radio_led_ctrl(&d,2))abort();
  }
 }
 return 0;}
'''
# Export declarations are outside extracted complete helper bodies.
code=unit+constants+model+helpers+main
path=out/'commands.c';path.write_text(code)
exe=out/'commands';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'commands':[]}
for chip in [7921,7922,7925]:
 b=subprocess.run([str(exe.resolve()),str(chip)],check=True,stdout=subprocess.PIPE).stdout;(out/f'{chip}-commands.trace').write_bytes(b);manifest['commands'].append({'chip':chip,'cases':32*(4 if chip==7925 else 8),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
# Complete source MAC initializers, nested band/WTBL/rate helpers and exact
# source poll loop. Fixed mapping triples come from the pinned PCI source.
extra={
'mt76.h':'b7e52e9559ff1bd5d256ccdbaa2b4c277d418955acd141708059af3161470bea',
'mt7921/pci.c':'271c5d4e04f28b9508d700c986a3a797d8d6e78f2b6f9fa7611df145a1614ff1',
'mt7925/pci.c':'82a03775d716db6f65e0dc25960a19773e08f8a31aeb77cb91a30fe1da508937',
}
for f,h in extra.items():
 b=(source/f).read_bytes();assert hashlib.sha256(b).hexdigest()==h,f;t[f]=b.decode();hashes[f]=h
macpre=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m)) & (m))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))
struct ieee80211_rate{int bitrate,flags,hw_value,hw_value_short;};
#define IEEE80211_RATE_SHORT_PREAMBLE 1
struct mt76_phy{u32 aggr_stats[64];u32 survey_time;};
struct mt76_dev{struct mt76_phy phy;u8 alpha2[2];};
struct mt792x_dev{struct mt76_dev mt76;};
struct mt792x_phy{struct mt792x_dev *dev;struct mt76_phy *mt76;};
static bool is_mt7928(struct mt76_dev *d){(void)d;return false;}
struct mt76_connac_reg_map{u32 phys,maps,size;};
struct operation{u32 kind,address,value;};static struct operation operations[4096];static u32 nop;
static u32 regs[0x200000/4];
static u32 mapped(u32 a);
static u32 rr(void *d,u32 a){(void)d;a=mapped(a);if(a%4||a>=sizeof(regs)||nop==4096)abort();u32 v=regs[a/4];operations[nop++]=(struct operation){0,a,v};return v;}
static void wr(void *d,u32 a,u32 v){(void)d;a=mapped(a);if(a%4||a>=sizeof(regs)||nop==4096)abort();operations[nop++]=(struct operation){1,a,v};regs[a/4]=v;}
#define mt76_rr(d,a) rr(d,a)
#define __mt76_rr(d,a) rr(d,a)
#define mt76_wr(d,a,v) wr(d,a,v)
#define mt76_rmw(d,a,m,v) wr(d,a,(rr(d,a)&~(m))|(v))
#define mt76_rmw_field(d,a,m,v) mt76_rmw(d,a,m,FIELD_PREP(m,v))
#define mt76_set(d,a,v) mt76_rmw(d,a,0,v)
#define mt76_clear(d,a,m) mt76_rmw(d,a,m,0)
#define mt76_poll(d,a,m,v,t) __mt76_poll(&(d)->mt76,a,m,v,t)
#define ktime_get_boottime() 1234
#define memzero_explicit(p,n) memset(p,0,n)
static void udelay(unsigned t){if(t!=10)abort();}
static int mt76_connac_mcu_set_rts_thresh(struct mt76_dev*d,u32 v,u8 b){(void)d;operations[nop++]=(struct operation){2,b,v};return 0;}
'''
def defs(files,helpers):
 all={}
 for f in files:
  lines=iter(t[f].splitlines(keepends=True))
  for line in lines:
   while line.rstrip().endswith('\\'):line+=next(lines)
   m=re.match(r'^#define ([A-Za-z0-9_]+)(?:\([^\n]*?\))?\s+(.+)',line,re.S)
   if m and not m[1].startswith(('mt76_','__mt76_')):all[m[1]]=(line,m[2])
 names=set(re.findall(r'\b[A-Za-z0-9_]+\b',helpers)) & all.keys()
 while True:
  more=names|{x for n in names for x in re.findall(r'\b[A-Za-z0-9_]+\b',all[n][1]) if x in all}
  if more==names:break
  names=more
 return ''.join(all[n][0] for n in sorted(names))
manifest['mac']=[]
for chip in [7921,7922,7925]:
 c3=chip==7925;sub='mt7925' if c3 else 'mt7921';name='default_fixed_map' if c3 else 'fixed_map'
 x=t[sub+'/pci.c'];a=x.index('static const struct mt76_connac_reg_map '+name+'[]');b=x.index('};',a)+2
 maps=x[a:b]+'\n'
 mapfn='static u32 mapped(u32 a){if(a<0x100000)return a;for(unsigned i=0;i<ARRAY_SIZE('+name+');i++){if(a>='+name+'[i].phys&&a-'+name+'[i].phys+4<='+name+'[i].size)return '+name+'[i].maps+a-'+name+'[i].phys;}abort();}\n'
 helpers=function('util.c','__mt76_poll')+function(sub+'/mac.c',sub+'_mac_wtbl_update')
 helpers+=function('mt792x_mac.c','mt792x_mac_init_band')
 if c3:helpers+=function('mt7925/mac.c','mt7925_mac_set_fixed_rate_table')+function('mt7925/init.c','mt7925_mac_init_basic_rates')
 helpers+=function(sub+'/init.c',sub+'_mac_init')+function('mt792x_mac.c','mt792x_mac_reset_counters')
 rates=t['mac80211.c'];a=rates.index('struct ieee80211_rate mt76_rates[] =');rates=rates[a:rates.index('};',a)+2]+'\n'
 macros=defs(['mt76.h','mt792x.h','mt792x_regs.h','mt76_connac2_mac.h',sub+'/regs.h'],helpers+rates)
 x=t['mt76.h'];a=x.index('enum mt76_phy_type {');phyenum=x[a:x.index('};',a)+2]+'\n'
 main='int main(int argc,char **argv){u32 seed=argc==2?atoi(argv[1]):0;for(u32 a=0;a<sizeof(regs);a+=4)regs[a/4]=seed?((a*0x10203u)^(seed*0x9e3779b9u)):0;regs[mapped('+('MT7925_WTBL_UPDATE' if c3 else 'MT_WTBL_UPDATE')+')/4]&=~BIT(31);struct mt792x_dev d={0};struct mt792x_phy p={&d,&d.mt76.phy};if('+sub+'_mac_init(&d))abort();mt792x_mac_reset_counters(&p);if(fwrite(&nop,4,1,stdout)!=1||fwrite(operations,sizeof(*operations),nop,stdout)!=nop)abort();return 0;}\n'
 code=macpre+maps+mapfn+phyenum+macros+rates+helpers+main
 path=out/f'{chip}-mac.c';path.write_text(code);exe=out/f'{chip}-mac'
 subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
 b=subprocess.run([str(exe.resolve())],check=True,stdout=subprocess.PIPE).stdout;(out/f'{chip}-mac.trace').write_bytes(b);manifest['mac'].append({'chip':chip,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
# Source raw-header translation helpers, including actual WMWA command flags.
def layout(f,n):
 x=t[f];a=x.index('struct '+n+' {');b=x.index(';',x.index('}',a))+1;return x[a:b]+'\n'
rawconstants=''.join(layout(f,n) for f,n in [('mt76_connac_mcu.h','tlv'),('mt76_connac_mcu.h','sta_ntlv_hdr'),('mt76_connac_mcu.h','sta_req_hdr'),('mt76_connac_mcu.h','wtbl_req_hdr'),('mt76_connac_mcu.h','wtbl_hdr_trans'),('mt7925/mcu.h','sta_rec_hdr_trans')])
rawconstants+=''.join(enum('mt76_connac_mcu.h',n) for n in ['STA_REC_WTBL','WTBL_HDR_TRANS','WTBL_RESET_AND_SET'])
x=t['mt76.h'];a=x.index('enum mt76_wcid_flags {');rawconstants+=x[a:x.index('};',a)+2]+'\n'
rawmodel=r'''
#define ETH_ALEN 6
#define GFP_ATOMIC 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x)>(uintptr_t)-4096)
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define WARN_ON_ONCE(x) (x)
#define le16_to_cpu(x) (x)
static void le16_add_cpu(void*p,u16 v){u16 x;memcpy(&x,p,2);x+=v;memcpy(p,&x,2);}
#define to_wcid_lo(id) FIELD_GET(GENMASK(7,0),(u16)(id))
#define to_wcid_hi(id) FIELD_GET(GENMASK(10,8),(u16)(id))
#define MT76_CONNAC_WTBL_UPDATE_MAX_SIZE 256
#define MT7925_STA_UPDATE_MAX_SIZE 256
#define NL80211_IFTYPE_STATION 2
#define MCU_WMWA_UNI_CMD(x) (MCU_UNI_CMD(x)|(1<<19)|(1<<20))
struct mt76_wcid {u16 idx;bool sta,sta_disabled;unsigned long flags;};
struct mt76_vif_link {u8 idx,omac_idx;};
struct mt792x_bss_conf {struct mt76_vif_link mt76;};
struct mt792x_link_sta {struct mt76_wcid wcid;};
struct ieee80211_vif {u8 drv_priv[sizeof(struct mt76_vif_link)];int type;};
static bool test_bit(unsigned b,unsigned long *p){return (*p>>b)&1;}
static bool is_connac_v1(struct mt76_dev*d){(void)d;return false;}
static void *skb_put_zero(struct sk_buff*s,int n){if(s->len+n>256)abort();void *p=s->data+s->len;memset(p,0,n);s->len+=n;return p;}
static void *skb_put_data(struct sk_buff*s,const void*p,int n){void*r=skb_put_zero(s,n);memcpy(r,p,n);return r;}
static struct sk_buff *__mt76_mcu_msg_alloc(struct mt76_dev*d,void*p,int a,int b,int g){(void)d;(void)p;(void)a;(void)b;(void)g;struct sk_buff*s=calloc(1,sizeof(*s));if(!s)abort();s->data=calloc(1,256);if(!s->data)abort();return s;}
static struct sk_buff *mt76_mcu_msg_alloc(struct mt76_dev*d,void*p,int n){return __mt76_mcu_msg_alloc(d,p,n,n,0);}
static int mt76_mcu_skb_send_msg(struct mt76_dev*d,struct sk_buff*s,int c,bool w){int r=mt76_mcu_send_msg(d,c,s->data,s->len,w);free(s->data);free(s);return r;}
#define mt76_connac_mcu_alloc_sta_req(d,v,w) __mt76_connac_mcu_alloc_sta_req(d,v,w,256)
'''
rawhelpers=''.join(function(f,n) for f,n in [('mt76_connac_mcu.h','mt76_connac_mcu_get_wlan_idx'),('mt76_connac_mcu.c','mt76_connac_mcu_add_nested_tlv'),('mt76_connac_mcu.h','mt76_connac_mcu_add_tlv'),('mt76_connac_mcu.c','__mt76_connac_mcu_alloc_sta_req'),('mt76_connac_mcu.c','mt76_connac_mcu_alloc_wtbl_req'),('mt76_connac_mcu.c','mt76_connac_mcu_wtbl_hdr_trans_tlv'),('mt76_connac_mcu.c','mt76_connac_mcu_sta_update_hdr_trans'),('mt7925/mcu.c','mt7925_mcu_sta_hdr_trans_tlv'),('mt7925/mcu.c','mt7925_mcu_wtbl_update_hdr_trans')])
rawmain=r'''
int main(int argc,char **argv){if(argc!=2)return 1;chip=atoi(argv[1]);struct mt792x_dev d={0};
 for(int i=0;i<128;i++){
  struct mt76_vif_link mvif={.idx=i%4,.omac_idx=i%64};struct ieee80211_vif v={.type=NL80211_IFTYPE_STATION};memcpy(v.drv_priv,&mvif,sizeof(mvif));
  struct mt792x_bss_conf conf={mvif};struct mt792x_link_sta link={.wcid={.idx=i%20,.sta=i%2}};
  if(chip==7925){if(mt7925_mcu_wtbl_update_hdr_trans(&d,&v,&conf,&link))abort();}
  else if(mt76_connac_mcu_sta_update_hdr_trans(&d.mt76,&v,&link.wcid,MCU_UNI_CMD(STA_REC_UPDATE)))abort();
 }
 return 0;
}
'''
code=unit+constants+model+rawconstants+rawmodel+rawhelpers+rawmain
path=out/'raw.c';path.write_text(code);exe=out/'raw'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
manifest['raw']=[]
for chip in [7921,7922,7925]:
 b=subprocess.run([str(exe.resolve()),str(chip)],check=True,stdout=subprocess.PIPE).stdout;(out/f'{chip}-raw.trace').write_bytes(b);manifest['raw'].append({'chip':chip,'cases':128,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
# Full unchanged parsers distinguish plain UNI from the actual WMWA form,
# even when the on-wire CID is identical. Keep the generic zero return as a
# parser path observation, never an invented peer installation status.
f='mt7921/mcu.h';h='b5ce3ab4d77fb541b1c52f478bf0d7ed4c289daa41e72b0bc3c9105d3a9e39ca';b=(source/f).read_bytes();assert hashlib.sha256(b).hexdigest()==h;t[f]=b.decode();hashes[f]=h
parsemodel=r'''
#define struct_group_tagged(tag,name,...) __VA_ARGS__
#define le32_to_cpu(x) (x)
#define dev_err(...) ((void)0)
#define MCU_CE_QUERY(x) (MCU_CE_CMD(x)|__MCU_CMD_FIELD_QUERY)
static bool is_mt7928(struct mt76_dev*d){(void)d;return false;}
static void mt792x_reset(struct mt76_dev*d){(void)d;abort();}
static void *skb_pull(struct sk_buff*s,int n){if(n<0||n>s->len)abort();s->data+=n;s->len-=n;return s->data;}
'''
parselayouts=''.join(layout(f,n) for f,n in [('mt76_connac_mcu.h','mt76_connac2_mcu_rxd'),('mt76_connac_mcu.h','mt76_connac_mcu_uni_event'),('mt76_connac_mcu.h','mt76_connac_mcu_reg_event'),('mt7925/mcu.h','mt7925_mcu_rxd'),('mt7925/mcu.h','mt7925_mcu_uni_event'),('mt7921/mcu.h','mt7921_wf_rf_pin_ctrl_event')])
parsemain=r'''
int main(int argc,char**argv){if(argc!=2)return 1;chip=atoi(argv[1]);struct mt76_dev d={0};
 for(u32 i=0;i<64;i++){
  bool plain=(i%2)==0,wrongcid=(i/2)%2,wrongseq=(i/4)%2;u8 bytes[80]={0};u32 base=chip==7925?32:24,header=base+12,status=i*0x1020304;u8 cid=wrongcid?4:3;
  bytes[base+5]=wrongseq?4:3;bytes[header]=cid;memcpy(bytes+header+4,&status,4);
  u32 cmd=MCU_UNI_CMD(STA_REC_UPDATE)|(plain?0:((1<<19)|(1<<20)));struct sk_buff skb={bytes,header+8};
  int result=chip==7925?mt7925_mcu_parse_response(&d,cmd,&skb,3):mt7921_mcu_parse_response(&d,cmd,&skb,3);u16 pulled=skb.data-bytes;
  output(&cmd,4);output(&status,4);output(&cid,1);u8 seq=bytes[base+5];output(&seq,1);output(&result,4);output(&pulled,2);
 }
 return 0;
}
'''
code=unit+constants+model+parsemodel+parselayouts+function('mt7921/mcu.c','mt7921_mcu_parse_response')+function('mt7925/mcu.c','mt7925_mcu_parse_response')+parsemain
path=out/'parse.c';path.write_text(code);exe=out/'parse'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
manifest['parse']=[]
for chip in [7921,7922,7925]:
 b=subprocess.run([str(exe.resolve()),str(chip)],check=True,stdout=subprocess.PIPE).stdout;(out/f'{chip}-parse.trace').write_bytes(b);manifest['parse'].append({'chip':chip,'cases':64,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
manifest['seeded_mac']=[]
for chip in [7921,7922,7925]:
 aggregate=b''
 for seed in range(1,17):
  b=subprocess.run([str((out/f'{chip}-mac').resolve()),str(seed)],check=True,stdout=subprocess.PIPE).stdout
  (out/f'{chip}-mac-{seed}.trace').write_bytes(b);aggregate+=b
 manifest['seeded_mac'].append({'chip':chip,'seeds':16,'bytes':len(aggregate),'sha256':hashlib.sha256(aggregate).hexdigest()})
manifest['sources']=hashes
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'commands':manifest['commands'],'mac':manifest['mac'],'raw':manifest['raw'],'parse':manifest['parse']},indent=2))
