"""Modern extension of the full pinned MT7925 client source fixture.

The legacy recipe is unchanged unless --modern is explicitly selected. This
extension runs complete HT/VHT/HE/EHT/BSS/EDCA/BA/puncture writers on source-state
inputs serialized by the Rust integration test. It does not replace helpers or
execute physical hardware. The nine-byte EHT source union is an actual input,
independent of selected-width directional common NSS limits.
"""
import re

def extend(pre, parts, helpers, main, function, layout):
 def replace(old,new):
  nonlocal pre
  assert pre.count(old)==1,old
  pre=pre.replace(old,new)
 replace('typedef uint32_t __le32;','typedef uint32_t __le32;typedef uint64_t __le64;')
 replace('#define cpu_to_le32(x) (x)','#define cpu_to_le32(x) (x)\n#define cpu_to_le64(x) (x)')
 replace('#define IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP 7','#define IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP 0x38')
 replace('#define IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START 0x38','#define IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START 7')
 for name,value in [('8080MHZ',6),('160MHZ',3),('320MHZ',7),('5MHZ',5),('10MHZ',4)]:
  pre=re.sub(r'(#define CMD_CBW_'+name+r') \d+',rf'\g<1> {value}',pre)
 replace('struct cfg80211_chan_def{','struct cfg80211_chan_def{u16 punctured;')
 replace('struct mt76_wcid{','struct mt76_wcid{bool amsdu;')
 replace('struct ieee80211_sta_ht_cap{','struct ieee80211_sta_ht_cap{u16 cap;')
 replace('struct ieee80211_sta_vht_cap{bool vht_supported;u32 cap;};',
         'struct ieee80211_sta_vht_cap{bool vht_supported;u32 cap;struct{u16 rx_mcs_map,tx_mcs_map;}vht_mcs;};')
 replace('struct ieee80211_sta_he_cap{bool has_he;};struct ieee80211_sta_eht_cap{bool has_eht;};',r'''
 struct ieee80211_he_cap_elem{u8 mac_cap_info[6],phy_cap_info[11];};
 struct ieee80211_he_mcs_nss_supp{u16 rx_mcs_80,tx_mcs_80,rx_mcs_160,tx_mcs_160,rx_mcs_80p80,tx_mcs_80p80;};
 struct ieee80211_sta_he_cap{bool has_he;struct ieee80211_he_cap_elem he_cap_elem;struct ieee80211_he_mcs_nss_supp he_mcs_nss_supp;};
 struct ieee80211_eht_mcs_nss_supp{union{u8 only_20mhz[4];struct{u8 _80[3],_160[3],_320[3];}bw;};}__packed;
 /* Value-only fixture: align the source helper's explicit u64/u16 accesses.
    Actual wire union remains the exact packed nine-byte source layout. */
 struct ieee80211_eht_cap_elem_fixed{u8 mac_cap_info[2];u8 phy_cap_info[9] __attribute__((aligned(8)));};
 struct ieee80211_sta_eht_cap{bool has_eht;struct ieee80211_eht_cap_elem_fixed eht_cap_elem;struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp;};
 static struct ieee80211_sta_he_cap local_he;
 ''')
 replace('struct mt792x_bss_conf{','struct ieee80211_tx_queue_params{u16 cw_min,cw_max,txop;u8 aifs;};struct mt792x_bss_conf{struct ieee80211_tx_queue_params queue_params[4];')
 replace('struct ieee80211_bss_conf{','struct ieee80211_bss_conf{u8 htc_trig_based_pkt_ext;u16 frame_time_rts_th;struct{bool enabled;u8 color;}he_bss_color;')
 replace('struct ieee80211_link_sta{','struct ieee80211_link_sta{struct{u16 max_amsdu_len;}agg;')
 replace('struct ieee80211_sta{','struct ieee80211_sta{u8 uapsd_queues,max_sp;')
 # All actual capability handlers below now run; only the non-MLD early-return
 # boundary remains an explicit fixture assertion until MLO is implemented.
 for name in ['mt7925_mcu_sta_ht_tlv','mt7925_mcu_sta_vht_tlv','mt76_connac_mcu_sta_uapsd','mt7925_mcu_sta_amsdu_tlv','mt7925_mcu_sta_he_tlv','mt7925_mcu_sta_he_6g_tlv','mt7925_mcu_sta_eht_tlv','mt7925_mcu_bss_he_tlv','mt7925_mcu_bss_color_tlv']:
  pre,n=re.subn(r'static void '+name+r'\([^\n]+\}\n','',pre);assert n==1,name
 pre+=r'''
 #define IEEE80211_NUM_ACS 4
 #define fallthrough __attribute__((fallthrough))
 #define fls(x) ((x)?32-__builtin_clz((unsigned)(x)):0)
 #define IEEE80211_STA_RX_BW_20 0
 #define IEEE80211_STA_RX_BW_160 3
 #define IEEE80211_MAX_MPDU_LEN_HT_7935 7935
 #define IEEE80211_MAX_MPDU_LEN_VHT_11454 11454
 #define IEEE80211_MAX_MPDU_LEN_VHT_7991 7991
 #define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 2
 #define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991 1
 #define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895 0
 #define IEEE80211_WMM_IE_STA_QOSINFO_AC_VO 1
 #define IEEE80211_WMM_IE_STA_QOSINFO_AC_VI 2
 #define IEEE80211_WMM_IE_STA_QOSINFO_AC_BE 8
 #define IEEE80211_WMM_IE_STA_QOSINFO_AC_BK 4
 #define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G 16
 #define IEEE80211_HE_PHY_CAP9_NOMINAL_PKT_PADDING_16US 2
 #define CMD_HE_MCS_BW80 0
 #define CMD_HE_MCS_BW160 1
 #define CMD_HE_MCS_BW8080 2
 #define CMD_HE_MCS_BW_NUM 3
 struct ieee80211_ampdu_params{struct ieee80211_sta *sta;u8 tid;u16 ssn,buf_size;bool amsdu;};
 static const struct ieee80211_sta_he_cap *mt76_connac_get_he_phy_cap(struct mt76_phy*p,struct ieee80211_vif*v){(void)p;(void)v;return local_he.has_he?&local_he:NULL;}
 '''
 for f,n in [('mt76_connac_mcu.h',n)for n in ['sta_rec_ht','sta_rec_vht','sta_rec_he_v2','sta_rec_he_6g_capa','sta_rec_amsdu','sta_rec_uapsd','bss_info_uni_he','bss_info_uni_bss_color']]+[('mt7925/mcu.h',n)for n in ['sta_rec_eht','sta_rec_ba_uni','bss_eht_tlv','edca']]:
  parts.append(layout(f,n))
 parts.append('enum{MT_BA_TYPE_INVALID,MT_BA_TYPE_ORIGINATOR,MT_BA_TYPE_RECIPIENT};\n')
 extra=''.join(function(f,n)for f,n in [('mt76_connac_mcu.c','mt76_connac_mcu_sta_uapsd'),('mt76_connac_mcu.c','mt76_connac_mcu_sta_he_tlv_v2')]+[('mt7925/mcu.c',n)for n in ['mt7925_mcu_sta_ht_tlv','mt7925_mcu_sta_vht_tlv','mt7925_mcu_sta_amsdu_tlv','mt7925_mcu_sta_he_tlv','mt7925_mcu_sta_he_6g_tlv','mt7925_mcu_sta_eht_tlv','mt7925_mcu_bss_he_tlv','mt7925_mcu_bss_color_tlv']])
 # Complete add_tlv precedes modern helpers; all source callers follow them.
 anchor=helpers.index('static int\nmt7925_mcu_sta_cmd(')
 helpers=helpers[:anchor]+extra+helpers[anchor:]
 helpers+=''.join(function('mt7925/mcu.c',n)for n in ['mt7925_mcu_set_tx','mt7925_mcu_sta_ba','mt7925_mcu_bss_eht_tlv','mt7925_mcu_set_eht_pp'])
 main=r'''
 static u8 r8(void){u8 v;assert(fread(&v,1,1,stdin)==1);return v;}
 static u16 r16(void){u16 v=r8();return v|((u16)r8()<<8);}
 static u32 r32(void){u32 v=r16();return v|((u32)r16()<<16);}
 static void readn(void*p,size_t n){assert(fread(p,1,n,stdin)==n);}
 int main(void){int first;while((first=fgetc(stdin))!=EOF){
 struct mt792x_dev d={0};struct mt76_phy m={.dev=&d.mt76};d.phy=(struct mt792x_phy){.dev=&d,.mt76=&m};
 struct ieee80211_vif v={.type=NL80211_IFTYPE_STATION};struct ieee80211_sta s={0};v.drv_priv[0].phy=&d.phy;v.drv_priv[0].bss_conf.vif=&v.drv_priv[0];s.drv_priv[0].deflink_id=255;
 struct mt76_vif_link*r=&v.drv_priv[0].bss_conf.mt76;struct ieee80211_bss_conf*b=&v.bss_conf; b->vif=&v;
 struct ieee80211_channel ch={.band=first,.hw_value=r8()};u8 center=r8(),center2=r8();
 int width=r8();s.deflink.bandwidth=r8();
 readn(v.addr,6);readn(s.addr,6);memcpy(s.deflink.addr,s.addr,6);memcpy(b->bssid,s.addr,6);
 r->idx=r8();r->omac_idx=r8();r->band_idx=r8();r->wmm_idx=r8();s.drv_priv[0].deflink.wcid.idx=r16();s.drv_priv[0].deflink.wcid.sta=true;u16 bcmc=r16();s.aid=v.cfg.aid=r16();
 b->basic_rates=r16();s.deflink.supp_rates[first]=r16();b->beacon_int=r16();b->dtim_period=r8();d.phy.slottime=r16();m.antenna_mask=r8();r->cipher=r8();
 r->basic_rates_idx=(first==0?14:18)+__builtin_ctz(b->basic_rates);
 u8 flags=r8();s.deflink.ht_cap.ht_supported=flags&1;s.deflink.vht_cap.vht_supported=flags&2;s.deflink.he_cap.has_he=flags&4;s.deflink.eht_cap.has_eht=flags&8;
 s.deflink.ht_cap.cap=r16();s.deflink.ht_cap.ampdu_factor=r8();s.deflink.ht_cap.ampdu_density=r8();readn(s.deflink.ht_cap.mcs.rx_mask,10);
 s.deflink.vht_cap.cap=r32();s.deflink.vht_cap.vht_mcs.rx_mcs_map=r16();s.deflink.vht_cap.vht_mcs.tx_mcs_map=r16();
 readn(&s.deflink.he_cap.he_cap_elem,17);readn(&s.deflink.he_cap.he_mcs_nss_supp,12);s.deflink.he_6ghz_capa.capa=r16();
 readn(s.deflink.eht_cap.eht_cap_elem.mac_cap_info,2);readn(s.deflink.eht_cap.eht_cap_elem.phy_cap_info,9);readn(&s.deflink.eht_cap.eht_mcs_nss_supp,9);
 s.deflink.rx_nss=r8();s.deflink.agg.max_amsdu_len=r16();
 local_he=(struct ieee80211_sta_he_cap){.has_he=s.deflink.he_cap.has_he};readn(&local_he.he_cap_elem,17);readn(&local_he.he_mcs_nss_supp,12);
 b->he_support=local_he.has_he;b->htc_trig_based_pkt_ext=r8();b->frame_time_rts_th=r16();b->he_bss_color.enabled=r8();b->he_bss_color.color=r8();b->bssid_indicator=r8();b->bssid_index=r8();u16 punctured=r16();
 s.wme=b->qos=true;s.deflink.sta=&s;
 for(int ac=0;ac<4;ac++){struct ieee80211_tx_queue_params*q=&v.drv_priv[0].bss_conf.queue_params[ac];q->aifs=r8();q->cw_min=(1U<<r8())-1;q->cw_max=(1U<<r8())-1;q->txop=r16();}
 struct ieee80211_ampdu_params ba={.sta=&s};ba.tid=r8();ba.ssn=r16();ba.buf_size=r16();ba.amsdu=r8();bool enable=r8(),transmit=r8();
 int base=first==0?2407:first==1?5000:5950;ch.center_freq=base+5*ch.hw_value;
 b->chanreq.oper=(struct cfg80211_chan_def){.chan=&ch,.center_freq1=base+5*center,.center_freq2=center2?base+5*center2:0,.width=width,.punctured=punctured};
 struct mt76_sta_cmd_info info={.link_sta=&s.deflink,.vif=&v,.link_conf=b,.wcid=&s.drv_priv[0].deflink.wcid,.enable=true,.newly=true,.cmd=MCU_UNI_CMD(STA_REC_UPDATE)};
 if(mt7925_mcu_sta_cmd(&m,&info))abort();info.state=MT76_STA_INFO_STATE_ASSOC;info.newly=false;if(mt7925_mcu_sta_cmd(&m,&info))abort();
 for(int enabled=0;enabled<2;enabled++)if(mt7925_mcu_add_bss_info_sta(&d.phy,NULL,b,&s.deflink,bcmc,s.drv_priv[0].deflink.wcid.idx,enabled))abort();
 if(mt7925_mcu_set_tx(&d,b)||mt7925_mcu_sta_ba(&d.mt76,r,&ba,&s.drv_priv[0].deflink.wcid,enable,transmit))abort();
 if(s.deflink.eht_cap.has_eht&&mt7925_mcu_set_eht_pp(&m,r,b,NULL))abort();
 }return 0;}
 '''
 # Frequency helper in the original legacy fixture only covered2.4/5GHz.
 pre=pre.replace('return f==2484?14:f<2484?(f-2407)/5:(f-5000)/5;', 'return f==0?0:f==2484?14:f<2484?(f-2407)/5:f>=5950?(f-5950)/5:(f-5000)/5;')
 return pre,parts,helpers,main
