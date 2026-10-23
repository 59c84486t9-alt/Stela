"""Unchanged full mac80211 probe helpers over full source-issued MT7925 caps.

The accepted native profile has no custom IEs, S1G or UHR. Those unexecuted
branches assert if called; HT/VHT/HE/EHT/HE6/rates and the full band writer run.
"""
import hashlib,re

def extend_probe(pre,parts,helpers,main,function,layout,t,hashes,headers):
 files=['net/wireless/chan.c','net/mac80211/util.c','include/linux/ieee80211.h','include/linux/ieee80211-ht.h','include/linux/ieee80211-he.h','include/linux/ieee80211-eht.h','include/net/mac80211.h','include/net/cfg80211.h']
 pins=['a58880f0b3225a5790e1874e6a88675e4ac0eb8098df432d597ca1549d79ded0','40be00a3ec50e372842238c4fbd6c1f61e5f6554ac205a2d55c905dd0d848bed', 'a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa', '0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b', 'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e', '3301a09629b7efafe791abcbc9346c7b20a515dc1e254826f03e71c602052f5e', '3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9', '972ae23f32259859b54c4b93fa46fb60cba8c879da888b2751014a6cd27bfcf3']
 for f,h in zip(files,pins):
  b=(headers/f).read_bytes();assert hashlib.sha256(b).hexdigest()==h,(f,hashlib.sha256(b).hexdigest());t['kernel/'+f]=b.decode();hashes['kernel/'+f]=h
 def replace(old,new):
  nonlocal pre
  assert pre.count(old)==1,old;pre=pre.replace(old,new)
 replace('u8 tx_params;}mcs;','u8 tx_params;u8 reserved[3];}__packed mcs;')
 replace('u8 phy_cap_info[9] __attribute__((aligned(8)));};','u8 phy_cap_info[9];}__packed;')
 replace('struct ieee80211_sta_eht_cap{bool has_eht;', 'struct ieee80211_sta_eht_cap{u8 eht_ppe_thres[32];bool has_eht;')
 replace('struct ieee80211_supported_band{','struct ieee80211_supported_band{int band;struct ieee80211_sband_iftype_data *iftype_data;')
 replace('struct ieee80211_channel{','struct ieee80211_channel{u32 flags;')
 # Source scan casts drv_priv's actual prefix directly to mt76_vif_link.
 # Preserve that prefix when combining the older modern model's queue fields.
 replace('struct mt792x_bss_conf{struct ieee80211_tx_queue_params queue_params[4];struct mt76_vif_link mt76;',
         'struct mt792x_bss_conf{struct mt76_vif_link mt76;struct ieee80211_tx_queue_params queue_params[4];')
 # WLAN element IDs and source SMPS/connection flag values retain their enums.
 for f,symbol in [('include/linux/ieee80211.h','WLAN_EID_SSID'),('include/linux/ieee80211.h','WLAN_EID_EXT_HE_CAPABILITY'),('include/net/mac80211.h','IEEE80211_SMPS_AUTOMATIC'),('include/net/cfg80211.h','IEEE80211_CHAN_DISABLED')]:
  x=t['kernel/'+f]
  enums=re.findall(r'enum\s*\w*\s*\{[^}]*\};',x,re.S)
  matches=[e for e in enums if re.search(r'\b'+symbol+r'\b',e)]
  assert len(matches)==1,symbol;pre+='\n'+matches[0]+'\n'
 for f in ['include/linux/ieee80211-ht.h']:
  text=t['kernel/'+f].replace('\\\n',' ')
  pre+='\n'+'\n'.join(re.findall(r'^#define[ \t]+WLAN_[^\n]*',text,re.M))+'\n'
 pre+=r'''
 #define IEEE80211_MAX_SSID_LEN 32
 #define NUM_NL80211_BANDS 4
 #define for_each_set_bit(i,mask,n) for((i)=0;(i)<(n);(i)++)if((*(mask))&BIT(i))
 #define NL80211_BAND_S1GHZ 4
 #define IEEE80211_PROBE_FLAG_MIN_CONTENT 1
 #define IEEE80211_CONN_BW_LIMIT_20 0
 #define IEEE80211_CONN_BW_LIMIT_40 1
 #define IEEE80211_CONN_BW_LIMIT_80 2
 #define IEEE80211_CONN_BW_LIMIT_160 3
 #define IEEE80211_CONN_BW_LIMIT_320 4
 #define min(a,b) ((a)<(b)?(a):(b))
 #define u16_get_bits(v,m) ((u16)FIELD_GET(m,v))
 #define le16_encode_bits(v,m) ((u16)FIELD_PREP(m,v))
 #define WARN_ON_ONCE(x) WARN_ON(x)
 #define WARN(x,...) WARN_ON(x)
 struct ieee80211_rate{int bitrate;};
 struct ieee80211_ht_cap{u8 bytes[26];};struct ieee80211_vht_cap{u8 bytes[12];};
 struct ieee80211_conn_settings{unsigned bw_limit;};
 static const struct ieee80211_conn_settings ieee80211_conn_settings_unlimited={.bw_limit=255};
 struct ieee80211_local{struct ieee80211_hw hw;};
 struct ieee80211_sub_if_data{struct ieee80211_local*local;struct ieee80211_vif vif;};
 static int skb_tailroom(struct sk_buff*s){return 4096-s->len;}
 static u8*skb_tail_pointer(struct sk_buff*s){return s->data+s->len;}
 static void skb_put_u8(struct sk_buff*s,u8 b){skb_put_data(s,&b,1);}
 static int ieee80211_vif_type_p2p(struct ieee80211_vif*v){return v->type;}
 static const struct ieee80211_sband_iftype_data*ieee80211_get_sband_iftype_data(const struct ieee80211_supported_band*s,int type){assert(type==NL80211_IFTYPE_STATION);return s->iftype_data;}
 static const struct ieee80211_sta_he_cap*ieee80211_get_he_iftype_cap_vif(const struct ieee80211_supported_band*s,struct ieee80211_vif*v){(void)v;return s->iftype_data&&s->iftype_data->he_cap.has_he?&s->iftype_data->he_cap:NULL;}
 static const struct ieee80211_sta_eht_cap*ieee80211_get_eht_iftype_cap_vif(const struct ieee80211_supported_band*s,struct ieee80211_vif*v){(void)v;return s->iftype_data&&s->iftype_data->eht_cap.has_eht?&s->iftype_data->eht_cap:NULL;}
 static int ieee80211_put_s1g_cap(struct sk_buff*s,void*c){(void)s;(void)c;abort();}
 static size_t ieee80211_ie_split(const u8*ie,size_t n,const u8*ids,size_t count,size_t at){(void)ie;(void)n;(void)ids;(void)count;(void)at;abort();}
 static int ieee80211_put_uhr_cap(struct sk_buff*s,struct ieee80211_sub_if_data*d,const struct ieee80211_supported_band*b){(void)s;(void)d;(void)b;abort();}
 '''
 replace('int band;struct ieee80211_sband_iftype_data *iftype_data;','int band;u8 s1g_cap;struct ieee80211_sband_iftype_data *iftype_data;')
 def source_function(f,n):
  x=t[f];clean=re.sub(r'/\*.*?\*/',lambda m:' '*len(m.group()),x,flags=re.S)
  m=re.search(r'\b'+n+r'\([^;{}]*?\)\n\{',clean);assert m,n
  start=x.rfind('\n\n',0,m.start())+2;at,d=m.end(),1
  while d:d+=(x[at]=='{')-(x[at]=='}');at+=1
  return x[start:at]+'\n'
 functions=[('net/wireless/chan.c','cfg80211_any_usable_channels')]+[('include/linux/ieee80211-he.h',n)for n in ['ieee80211_he_mcs_nss_size','ieee80211_he_ppe_size']]+[('include/linux/ieee80211-eht.h',n)for n in ['ieee80211_eht_mcs_nss_size','ieee80211_eht_ppe_size']]+[('net/mac80211/util.c',n)for n in ['ieee80211_ie_build_ht_cap','ieee80211_ie_build_vht_cap','ieee80211_get_adjusted_he_cap','ieee80211_put_he_cap','ieee80211_put_eht_cap','ieee80211_put_he_6ghz_cap','ieee80211_put_srates_elem','ieee80211_put_preq_ies_band']]
 helpers+=''.join(source_function('kernel/'+f,n)for f,n in functions)
 helpers+=''.join(function(f,n)for f,n in [('mt76_connac_mcu.c','mt76_connac_mcu_add_nested_tlv'),('mt76_connac_mcu.h','mt76_connac_mcu_add_tlv'),('mt7925/mcu.c','mt7925_mcu_build_scan_ie_tlv'),('mt7925/mcu.c','mt7925_mcu_hw_scan')])
 # Keep the source local capability initialization matrix, replacing only its
 # manual output projection with the entire unchanged ordinary band writer.
 a=main.index(' u8 header[]={band,nss,wi,enabled};');b=main.index(' for(int a=0;a<allocated;a++)',a)
 main=main[:a]+r'''
 u32 profiles[]={0,IEEE80211_CHAN_NO_80MHZ,IEEE80211_CHAN_NO_HE,IEEE80211_CHAN_NO_EHT,IEEE80211_CHAN_NO_80MHZ|IEEE80211_CHAN_NO_HE|IEEE80211_CHAN_NO_EHT};
 for(int profile=0;profile<5;profile++){channel.flags=profiles[profile]|IEEE80211_CHAN_NO_UHR;
 struct ieee80211_sband_iftype_data six={0};mt7925_init_he_caps(&d.phy,NL80211_BAND_6GHZ,&six,NL80211_IFTYPE_STATION);
 static struct ieee80211_rate rates[12];static const u8 rate_values[]={2,4,11,22,12,18,24,36,48,72,96,108};for(int i=0;i<12;i++)rates[i].bitrate=rate_values[i]*5;
 struct ieee80211_supported_band six_band={.band=NL80211_BAND_6GHZ,.iftype_data=&six,.bitrates=rates+4,.n_bitrates=8,.channels=&channel,.n_channels=1};
 struct wiphy w={0};w.bands[0]=&d.mphy.sband_2g.sband;w.bands[1]=&d.mphy.sband_5g.sband;w.bands[3]=&six_band;
 w.bands[0]->channels[0].flags=channel.flags;w.bands[1]->channels[0].flags=channel.flags;
 w.bands[0]->band=0;w.bands[1]->band=1;w.bands[0]->bitrates=rates;w.bands[0]->n_bitrates=12;w.bands[1]->bitrates=rates+4;w.bands[1]->n_bitrates=8;
 w.bands[band]->iftype_data=&data;
 struct ieee80211_local local={.hw={.wiphy=&w}};struct ieee80211_sub_if_data sdata={.local=&local,.vif={.type=NL80211_IFTYPE_STATION}};
 struct sk_buff*skb=mt76_mcu_msg_alloc(&d.mt76,NULL,4096);size_t offset=0;struct cfg80211_chan_def chandef={0};
 assert(!ieee80211_put_preq_ies_band(skb,&sdata,NULL,0,&offset,band,~0U,&chandef,0));
 u8 header[]={band,nss,wi,enabled};output(header,4);u16 length=skb->len;output(&length,2);output(skb->data,skb->len);
 struct ieee80211_channel scan_ch={.band=band,.hw_value=band==1?36:1,.center_freq=band==0?2412:band==1?5180:5955};struct ieee80211_channel*channels[]={&scan_ch};
 struct ieee80211_vif v={.type=NL80211_IFTYPE_STATION};v.drv_priv[0].phy=&d.phy;v.drv_priv[0].bss_conf.mt76.band_idx=255;
 struct ieee80211_scan_request scan={.req={.n_channels=1,.channels=channels}};memset(scan.req.bssid,255,6);scan.ies.ies[band]=skb->data;scan.ies.len[band]=skb->len;
 d.mphy.state=0;assert(!mt7925_mcu_hw_scan(&d.mphy,&v,&scan));free(skb->data);free(skb);}

 '''+main[b:]
 main=main[:main.index(' u32 configs[]')]+ 'return 0;}\n'
 probe_hashes={n:hashlib.sha256(source_function('kernel/'+f,n).encode()).hexdigest()for f,n in functions}
 probe_hashes.update({n:hashlib.sha256(function(f,n).encode()).hexdigest()for f,n in [('mt76_connac_mcu.c','mt76_connac_mcu_add_nested_tlv'),('mt76_connac_mcu.h','mt76_connac_mcu_add_tlv'),('mt7925/mcu.c','mt7925_mcu_build_scan_ie_tlv'),('mt7925/mcu.c','mt7925_mcu_hw_scan')]})
 return pre,parts,helpers,main,probe_hashes
