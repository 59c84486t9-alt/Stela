"""Full pinned MT7925 HE/EHT/PPE and common HT/VHT local capability helpers.
The retained NIC/CLC/regulatory inputs are modeled; this is no physical probe.
"""
from pathlib import Path
import hashlib,re

PINS={
'mt792x.h':'8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
'mac80211.c':'4a88a2105def248340f237377f698300478e1352dfc81a955e8a5e61f91d07df',
'mt76_connac_mac.c':'d93fe180202e8ee6b3a4dc5926a5e1760a1f1dfaa9ec6eebe46c95bc918ea37e',
'mt7925/init.c':'9463c70eebaa7156d427c914aee04568eca2a564b230cc7928474b81ed1698cb',
'mt7925/regd.c':'c867565f575aa316c89f80f79c6c1ff10c55f5814b75e0887dd2fdb465c2b400',
'mt792x_acpi_sar.h':'63da29d34497ce6b7df7c512101ddc47bb3a8966466b5df7a21b3341f621f71a',
}
HEADERS={
'include/linux/ieee80211-ht.h':'0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b',
'include/linux/ieee80211-vht.h':'eaae1e52bcaed0ecb9bbcf1c87a65e03a7ac5ea29733111a90e92bb993741775',
'include/linux/ieee80211-he.h':'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e',
'include/linux/ieee80211-eht.h':'3301a09629b7efafe791abcbc9346c7b20a515dc1e254826f03e71c602052f5e',
}
def extend_local(pre,parts,helpers,main,function,layout,t,hashes,source,headers):
 for f,h in PINS.items():
  b=(source/f).read_bytes();assert hashlib.sha256(b).hexdigest()==h,f;hashes[f]=h;t[f]=b.decode()
 header_text=''
 for f,h in HEADERS.items():
  b=(headers/f).read_bytes();assert h and hashlib.sha256(b).hexdigest()==h,f;hashes['kernel/'+f]=h;header_text+=b.decode()+'\n'
 # Flatten complete multiline macro definitions before copying their unchanged
 # expressions. Source enums supply the actual HE MCS support encodings.
 flattened=header_text.replace('\\\n',' ')
 defs=re.findall(r'^#define[ \t]+IEEE80211_[^\n]*',flattened,re.M)
 enums=[e for e in re.findall(r'enum\s*\w*\s*\{[^}]*\};',header_text,re.S)if any(n in e for n in ['IEEE80211_HE_MCS_SUPPORT_0_11','IEEE80211_VHT_MCS_SUPPORT_0_9','IEEE80211_HT_MAX_AMPDU_64K','IEEE80211_VHT_MAX_AMPDU_1024K','IEEE80211_HT_MPDU_DENSITY_2'])]
 pre=re.sub(r'^[ \t]*#define[ \t]+IEEE80211_[^\n]*\n','',pre,flags=re.M)
 pre+='\n'+'\n'.join(defs+enums)+'\n'
 def replace(old,new):
  nonlocal pre
  assert pre.count(old)==1,old;pre=pre.replace(old,new)
 replace('struct ieee80211_sta_he_cap{bool has_he;', 'struct ieee80211_sta_he_cap{u8 ppe_thres[25];bool has_he;')
 replace('struct ieee80211_sta_ht_cap{u16 cap;','struct ieee80211_sta_ht_cap{u16 cap;') # documentary shape check
 replace('struct{u8 rx_mask[10];}mcs;','struct{u8 rx_mask[10];u16 rx_highest;u8 tx_params;}mcs;')
 replace('struct{u16 rx_mcs_map,tx_mcs_map;}vht_mcs;','struct{u16 rx_mcs_map,rx_highest,tx_mcs_map,tx_highest;}vht_mcs;')
 replace('struct ieee80211_supported_band{','struct ieee80211_supported_band{struct ieee80211_channel*channels;int n_channels,n_bitrates;struct ieee80211_rate*bitrates;')
 replace('struct mt76_phy{','struct mt76_sband{struct ieee80211_channel*chan;struct ieee80211_supported_band sband;};struct mt76_phy{u16 chainmask;struct cfg80211_chan_def chandef;struct mt76_sband sband_2g,sband_5g,sband_6g;')
 replace('struct mt76_dev{','struct mt76_dev{void*dev;')
 replace('struct mt792x_dev{','struct mt792x_dev{bool has_eht;')
 replace('struct mt792x_phy{','struct mt792x_phy{void*clc[4];')
 replace('struct ieee80211_eht_mcs_nss_supp{union{u8 only_20mhz[4];struct{u8 _80[3],_160[3],_320[3];}bw;};}__packed;',
 '''struct ieee80211_eht_mcs_nss_supp_bw{u8 rx_tx_mcs9_max_nss,rx_tx_mcs11_max_nss,rx_tx_mcs13_max_nss;}__packed;
 struct ieee80211_eht_mcs_nss_supp{union{u8 only_20mhz[4];struct{struct ieee80211_eht_mcs_nss_supp_bw _80,_160,_320;}bw;};}__packed;''')
 pre+=r'''
 enum nl80211_iftype{_iftype_station=0,_iftype_ap=1};enum nl80211_chan_width{_width_dummy};
 #define GFP_KERNEL 0
 #define SUPPORTS_VHT_EXT_NSS_BW 0
 #define ieee80211_hw_check(hw,flag) ((void)(hw),(void)(flag),true)
 #define u8_encode_bits(v,m) ((u8)FIELD_PREP(m,v))
 #define u16_encode_bits(v,m) ((u16)FIELD_PREP(m,v))
 #define u8_get_bits(v,m) ((u8)FIELD_GET(m,v))
 #define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
 static bool is_320mhz_supported(struct mt76_dev*d){(void)d;return false;}
 struct ieee80211_sband_iftype_data{struct ieee80211_sta_he_cap he_cap;struct ieee80211_sta_eht_cap eht_cap;struct ieee80211_he_6ghz_capa he_6ghz_capa;};
 static void* allocations[16];static int allocated;
 static void*devm_kmemdup(void*d,const void*p,size_t n,int f){(void)d;(void)f;void*q=malloc(n);memcpy(q,p,n);allocations[allocated++]=q;return q;}
 static void*devm_kcalloc(void*d,size_t n,size_t size,int f){(void)d;(void)f;void*q=calloc(n,size);allocations[allocated++]=q;return q;}
 '''
 # Discard unrelated peer/scan command execution for this pure local model;
 # complete local source helpers below own every capability/stream/PPE effect.
 helpers=''.join(function(f,n)for f,n in [('mac80211.c','mt76_init_stream_cap'),('mac80211.c','mt76_init_sband'),('mt76_connac_mac.c','mt76_connac_gen_ppe_thresh'),('mt7925/main.c','mt7925_init_he_caps'),('mt7925/main.c','mt7925_init_eht_caps')])
 original=t['mt7925/init.c'];start=original.index('\n\tdev->mphy.sband_2g.sband.ht_cap.cap |=');end=original.index('\n\tdev->mphy.hw->wiphy->available_antennas_rx',start)
 overrides='static void source_overrides(struct mt792x_dev*dev){'+original[start:end]+'}\n'
 helpers+=overrides
 pre+=r'''
 static u32 mtcl_observed;static int capability_changes;
 static u32 mt792x_acpi_get_mtcl_conf(struct mt792x_phy*p,u8*alpha){(void)p;assert(alpha[0]=='U'&&alpha[1]=='S');return mtcl_observed;}
 static void mt7925_set_stream_he_eht_caps(struct mt792x_phy*p){(void)p;capability_changes++;}
 '''
 pre+=re.search(r'^#define MT792X_ACPI_MTCL_INVALID[^\n]*',t['mt792x_acpi_sar.h'],re.M).group()+'\n'
 at=t['mt792x.h'].rfind('enum {',0,t['mt792x.h'].index('MT792x_CLC_POWER,'));pre+=t['mt792x.h'][at:t['mt792x.h'].index('};',at)+2]+'\n'
 local_parts=[layout('mt7925/mt7925.h',n)for n in ['mt7925_clc_type0','mt7925_clc_type2','mt7925_clc','mt7925_clc_rule_v2']]
 helpers+=function('mt7925/regd.c','mt7925_regd_be_ctrl')
 main=r'''
 static void ie(u8 id,const void*data,u8 n){output(&id,1);output(&n,1);output(data,n);}
 static void ext(u8 id,const void*data,u8 n){u8 e=255,len=n+1;output(&e,1);output(&len,1);output(&id,1);output(data,n);}
 int main(void){for(int band=0;band<4;band++){if(band==2)continue;
 for(int nss=1;nss<=4;nss++)for(int wi=0;wi<4;wi++){if(band==0&&wi>1)continue;
 for(int enabled=0;enabled<2;enabled++){
 struct mt792x_dev d={0};struct mt792x_dev*dev=&d;struct ieee80211_hw hw={0};
 d.mphy.dev=&d.mt76;d.mphy.hw=&hw;d.mphy.antenna_mask=(1U<<nss)-1;d.mphy.chainmask=d.mphy.antenna_mask;d.phy.mt76=&d.mphy;d.phy.dev=&d;d.has_eht=enabled;
 int widths[]={NL80211_CHAN_WIDTH_20,NL80211_CHAN_WIDTH_40,NL80211_CHAN_WIDTH_80,NL80211_CHAN_WIDTH_160};d.mphy.chandef.width=widths[wi];
 struct ieee80211_channel channel={0};allocated=0;
 assert(!mt76_init_sband(&d.mphy,&d.mphy.sband_2g,&channel,1,NULL,0,true,false));
 assert(!mt76_init_sband(&d.mphy,&d.mphy.sband_5g,&channel,1,NULL,0,true,true));source_overrides(dev);
 struct ieee80211_sband_iftype_data data={0};mt7925_init_he_caps(&d.phy,band,&data,NL80211_IFTYPE_STATION);mt7925_init_eht_caps(&d.phy,band,&data);
 u8 header[]={band,nss,wi,enabled};output(header,4);
 static const u8 rates[]={2,4,11,22,12,18,24,36,48,72,96,108};
 if(band==0){ie(1,rates,8);ie(50,rates+8,4);}else if(band==1)ie(1,rates+4,8);
 if(band!=3){struct ieee80211_sta_ht_cap*h=band==0?&d.mphy.sband_2g.sband.ht_cap:&d.mphy.sband_5g.sband.ht_cap;
 u8 bytes[26]={0};memcpy(bytes,&h->cap,2);bytes[2]=h->ampdu_factor|(h->ampdu_density<<2);memcpy(bytes+3,h->mcs.rx_mask,10);memcpy(bytes+13,&h->mcs.rx_highest,2);bytes[15]=h->mcs.tx_params;ie(45,bytes,26);
 if(band==1){struct ieee80211_sta_vht_cap*v=&d.mphy.sband_5g.sband.vht_cap;u8 bytes[12]={0};memcpy(bytes,&v->cap,4);memcpy(bytes+4,&v->vht_mcs,8);ie(191,bytes,12);}}
 struct ieee80211_sta_he_cap*h=&data.he_cap;u8 he[64];memcpy(he,h->he_cap_elem.mac_cap_info,6);memcpy(he+6,h->he_cap_elem.phy_cap_info,11);int maps=band==0?4:8;memcpy(he+17,&h->he_mcs_nss_supp,maps);int ppe=(6*nss*(band==0?2:4)+7+7)/8;memcpy(he+17+maps,h->ppe_thres,ppe);ext(35,he,17+maps+ppe);
 if(band==3)ext(59,&data.he_6ghz_capa.capa,2);
 if(enabled){struct ieee80211_sta_eht_cap*e=&data.eht_cap;u8 eht[32];memcpy(eht,e->eht_cap_elem.mac_cap_info,2);memcpy(eht+2,e->eht_cap_elem.phy_cap_info,9);int maps=band==0?3:6;memcpy(eht+11,&e->eht_mcs_nss_supp,maps);ext(108,eht,11+maps);}
 static const u8 wmm[]={0,0x50,0xf2,2,0,1,0};ie(221,wmm,7);
 output(&h->he_mcs_nss_supp,12);
 for(int a=0;a<allocated;a++)free(allocations[a]);
 }}}
 u32 configs[]={0xffffffff,0,0x10,0x20,0x30,0x80};
 for(int ci=0;ci<6;ci++)for(int rows=0;rows<=4;rows++)for(int match=0;match<=(rows?rows:0);match++)for(int old=0;old<2;old++){
 struct mt792x_dev d={.has_eht=old};d.phy.dev=&d;u8 alpha[]={'U','S'};mtcl_observed=configs[ci];capability_changes=0;
 struct mt7925_clc*clc=calloc(1,sizeof(*clc)+16*rows);if(rows){d.phy.clc[MT792x_CLC_BE_CTRL]=clc;for(int i=0;i<rows;i++){struct mt7925_clc_rule_v2*r=(void*)(clc->data+16*i);r->flag=i==rows-1;r->alpha2[0]=i==match?'U':'A'+i;r->alpha2[1]=i==match?'S':'a'+i;}}
 mt7925_regd_be_ctrl(&d,alpha);output(&configs[ci],4);u8 result[]={rows,match,old,!!rows,d.has_eht,capability_changes};output(result,6);free(clc);
 }
 return 0;}
 '''
 return pre,local_parts,helpers,main
