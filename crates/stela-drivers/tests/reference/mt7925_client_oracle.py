#!/usr/bin/env python3
"""Pinned full legacy-profile STA/BSS/scan request source helpers under sanitizers.
Usage: mt7925_client_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Only the explicit non-MLO station legacy20 profile is modeled. Optional advanced
capability handlers assert that the source's early-return conditions hold; they
are not feature oracles. Actual complete mandatory helpers and caller order run.
No firmware ACK, physical authority, encryption or radio execution is established.
"""
from pathlib import Path
import re,hashlib,json,subprocess,sys
source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={'mt792x_mac.c':'472d899597f5da141a9fba4d9d38d202cd8ac13ba53677e2e527f0b4e1884a45','mt76_connac_mcu.c':'52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec','mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed','mt76_connac.h':'fef14ff63ab1a098b8fe90b5c2e28811cf7fcaf78a7bf5753818b05acf2414b0','mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6','mt7925/mcu.h':'35855f4cdc673a7562241afd618fdd73fc181d210127e3ca2f762f3199cbc772','mt7925/main.c':'93023cfa7f7bc57efcf64b2a4fe55d932a60c0128942ff911b2e0d792a0de588','mt7925/mt7925.h':'b6fec2103954269927b44b095944120dd22a5a0503fa8930e49a8ecc044844dc'}
t={}
for f,h in hashes.items():b=(source/f).read_bytes();assert hashlib.sha256(b).hexdigest()==h,f;t[f]=b.decode()
def function(f,n):
 x=t[f];m=re.search(r'\b'+n+r'\([^;{}]*?\)\n\{',x);assert m,n
 start=x.rfind('\n\n',0,m.start())+2;at,d=m.end(),1
 while d:d+=(x[at]=='{')-(x[at]=='}');at+=1
 return x[start:at]+'\n'
def layout(f,n):
 x=t[f];m=re.search(r'\bstruct '+n+r' \{',x);assert m,n
 at,d=m.end(),1
 while d:d+=(x[at]=='{')-(x[at]=='}');at+=1
 return x[m.start():x.index(';',at)+1]+'\n'
def enum(f,n):x=t[f];at=x.rfind('enum {',0,x.index(n));return x[at:x.index('};',at)+2]+'\n'
h='mt76_connac_mcu.h';c='mt76_connac_mcu.c';h3='mt7925/mcu.h';c3='mt7925/mcu.c'
pre=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
typedef uint64_t u64;typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define ETH_ALEN 6
#define BIT(x) (1U<<(x))
#define MT76_HW_SCANNING 0
#define set_bit(n,p) (*(p)|=1UL<<(n))
#define test_and_clear_bit(n,p) ({bool found=test_bit(n,p);clear_bit(n,p);found;})
#define clear_bit(n,p) (*(p)&=~(1UL<<(n)))
#define MT7925_RNR_SCAN_MAX_BSSIDS 10
#define MT76_CONNAC_SCAN_IE_LEN 600
#define IEEE80211_MAX_SSID_LEN 32
#define NL80211_SCAN_FLAG_RANDOM_ADDR 1
#define get_random_mask_addr(...) abort()
#define ether_addr_copy(a,b) memcpy(a,b,6)
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define le16_to_cpu(x) (x)
#define le16_add_cpu(p,v) (*(p)+=(v))
#define GFP_ATOMIC 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define IS_ERR(x) ((intptr_t)(x)<0)
#define PTR_ERR(x) ((intptr_t)(x))
#define MCU_UNI_CMD(x) ((1<<17)|MCU_UNI_CMD_##x)
#define dev_dbg(...) do{}while(0)
#define dev_warn(...) do{}while(0)
#define MT76_CONNAC_MCU_STATUS_WLAN_FAILURE 0xc0000001
#define WARN_ON(x) (assert(!(x)),0)
#define WARN_ON_ONCE(x) WARN_ON(x)
#define dev_warn_ratelimited(...) abort()
#define test_bit(n,p) (!!(*(p)&(1UL<<(n))))
#define hweight8(x) __builtin_popcount((u8)(x))
#define hweight16(x) __builtin_popcount((u16)(x))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define container_of(p,t,m) ((t *)((u8 *)(p)-offsetof(t,m)))
#define to_wcid_lo(x) ((x)&255)
#define to_wcid_hi(x) (((x)>>8)&7)
enum nl80211_band { _band0, _band1, _band2, _band3 };
#define NL80211_BAND_2GHZ 0
#define NL80211_BAND_5GHZ 1
#define NL80211_BAND_60GHZ 2
#define NL80211_BAND_6GHZ 3
#define NL80211_CHAN_WIDTH_20 0
#define NL80211_CHAN_WIDTH_20_NOHT 1
#define NL80211_CHAN_WIDTH_40 2
#define NL80211_CHAN_WIDTH_80 3
#define NL80211_CHAN_WIDTH_80P80 4
#define NL80211_CHAN_WIDTH_160 5
#define NL80211_CHAN_WIDTH_320 6
#define NL80211_CHAN_WIDTH_5 7
#define NL80211_CHAN_WIDTH_10 8
#define IEEE80211_LINK_UNSPECIFIED 255
#define MT7925_STA_UPDATE_MAX_SIZE 2048
#define MT7925_BSS_UPDATE_MAX_SIZE 2048
#define IEEE80211_HT_AMPDU_PARM_FACTOR 3
#define IEEE80211_HT_AMPDU_PARM_DENSITY 28
#define IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK 0x03800000
#define IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP 7
#define IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START 0x38
#define IEEE80211_OPMODE_NOTIF_RX_NSS_SHIFT 4
#define le16_get_bits(v,m) FIELD_GET(m,v)
#define MT_WCID_FLAG_HDR_TRANS 0
#define MT_WCID_FLAG_4ADDR 1
#define MT_WCID_FLAG_TDLS_PEER 2
#define MT792x_CHIP_CAP_MLO_EML_EN 1
#define IEEE80211_EML_CAP_EMLSR_SUPP 1
#define NL80211_IFTYPE_STATION 0
#define NL80211_IFTYPE_AP 1
#define NL80211_IFTYPE_MESH_POINT 2
#define NL80211_IFTYPE_ADHOC 3
#define NL80211_IFTYPE_NAN 4
#define NL80211_IFTYPE_NAN_DATA 5
#define CMD_CBW_20MHZ 0
#define CMD_CBW_40MHZ 1
#define CMD_CBW_80MHZ 2
#define CMD_CBW_8080MHZ 3
#define CMD_CBW_160MHZ 4
#define CMD_CBW_320MHZ 5
#define CMD_CBW_5MHZ 6
#define CMD_CBW_10MHZ 7
#define EXT_BSSID_START 0x10
#define HW_BSSID_0 0
struct sk_buff{u8 *data;size_t len;};struct mt76_dev{struct{int bssid_num;u8 bssid[10][6],channel[10];}rnr;};struct ieee80211_vif;struct ieee80211_sta;struct mt792x_dev;
struct ieee80211_channel{u8 band,hw_value;int center_freq;};struct cfg80211_chan_def{struct ieee80211_channel *chan;int center_freq1,center_freq2,width;};struct ieee80211_chanctx_conf{struct cfg80211_chan_def def;};
struct mt76_wcid{u16 idx;u8 link_id;bool sta,sta_disabled;unsigned long flags;};struct mt76_vif_link{u8 idx,omac_idx,band_idx,wmm_idx,scan_seq_num;u8 cipher,mcast_rates_idx,basic_rates_idx;struct ieee80211_chanctx_conf *ctx;};
struct ieee80211_sta_ht_cap{bool ht_supported;u8 ampdu_factor,ampdu_density;struct{u8 rx_mask[10];}mcs;};
struct ieee80211_sta_vht_cap{bool vht_supported;u32 cap;};struct ieee80211_sta_he_cap{bool has_he;};struct ieee80211_sta_eht_cap{bool has_eht;};struct ieee80211_he_6ghz_capa{u16 capa;};
struct ieee80211_supported_band{struct ieee80211_sta_ht_cap ht_cap;struct ieee80211_sta_vht_cap vht_cap;};
struct wiphy{struct ieee80211_supported_band *bands[4];};struct ieee80211_hw{struct wiphy*wiphy;};
static const struct ieee80211_sta_he_cap *ieee80211_get_he_iftype_cap(struct ieee80211_supported_band*s,int type){(void)s;(void)type;return NULL;}
static const struct ieee80211_sta_eht_cap *ieee80211_get_eht_iftype_cap(struct ieee80211_supported_band*s,int type){(void)s;(void)type;return NULL;}
static u16 ieee80211_get_he_6ghz_capa(struct ieee80211_supported_band*s,int type){(void)s;(void)type;return 0;}
struct mt76_phy{struct mt76_dev *dev;u8 antenna_mask,band_idx;unsigned long state;struct ieee80211_hw *hw;};struct mt792x_phy{struct mt76_phy *mt76;struct mt792x_dev *dev;u16 slottime;u64 chip_cap;};
struct mt792x_sta;
struct mt792x_link_sta{struct mt76_wcid wcid;struct mt792x_sta *sta;};
struct mt792x_vif;struct mt792x_bss_conf{struct mt76_vif_link mt76;struct mt792x_vif *vif;};
struct mt792x_sta{struct mt792x_link_sta deflink;u8 deflink_id;struct mt792x_vif *vif;};
struct mt792x_vif{struct mt792x_bss_conf bss_conf;struct mt792x_sta sta;struct mt792x_phy *phy;u16 valid_links;};
struct ieee80211_bss_conf{struct ieee80211_vif *vif;u8 bssid[6],link_id;struct{struct cfg80211_chan_def oper;}chanreq;u16 basic_rates,beacon_int;u8 dtim_period;bool qos,he_support;u8 bssid_indicator,bssid_index;};
struct ieee80211_vif{struct mt792x_vif drv_priv[1];struct ieee80211_bss_conf bss_conf;int type;bool p2p;u8 addr[6];struct{u16 aid,eml_cap;bool ps;}cfg;};
struct ieee80211_link_sta{struct ieee80211_sta *sta;u8 addr[6],link_id;u16 supp_rates[4];struct ieee80211_sta_ht_cap ht_cap;struct ieee80211_sta_vht_cap vht_cap;struct ieee80211_he_6ghz_capa he_6ghz_capa;struct ieee80211_sta_he_cap he_cap;struct ieee80211_sta_eht_cap eht_cap;u8 bandwidth,rx_nss;};
struct ieee80211_sta{struct mt792x_sta drv_priv[1];struct ieee80211_link_sta deflink;u8 addr[6];bool wme;u16 aid;};
struct mt792x_dev{struct mt76_wcid *wcid[20];struct mt76_dev mt76;struct mt792x_phy phy;struct mt76_phy mphy;};
struct mt76_sta_cmd_info{struct ieee80211_link_sta *link_sta;struct ieee80211_vif *vif;struct ieee80211_bss_conf *link_conf;struct mt76_wcid *wcid;bool enable,newly,offload_fw;int cmd;u8 state,rcpi;};
static struct mt76_wcid *mt76_wcid_ptr(struct mt792x_dev*d,u16 i){return i<20?d->wcid[i]:NULL;}
static bool is_connac2(struct mt76_dev*d){(void)d;return false;}static bool is_connac_v1(struct mt76_dev*d){(void)d;return false;}
static bool mt7925_vif_is_nan(struct ieee80211_vif*v){return v->type==NL80211_IFTYPE_NAN||v->type==NL80211_IFTYPE_NAN_DATA;}
static bool ieee80211_vif_is_mld(struct ieee80211_vif*v){(void)v;return false;}
static bool is_zero_ether_addr(const u8*p){static const u8 z[6]={0};return !memcmp(p,z,6);}static void eth_broadcast_addr(u8*p){memset(p,255,6);}
static struct mt792x_bss_conf *mt792x_vif_to_link(struct mt792x_vif*v,u8 l){assert(l==0);return &v->bss_conf;}
static struct ieee80211_bss_conf *mt792x_vif_to_bss_conf(struct ieee80211_vif*v,u8 l){assert(l==0);return &v->bss_conf;}
static struct mt792x_bss_conf *mt792x_link_conf_to_mconf(struct ieee80211_bss_conf*c){return &c->vif->drv_priv[0].bss_conf;}
static struct sk_buff *__mt76_mcu_msg_alloc(struct mt76_dev*d,void*p,int a,int b,int f){(void)d;(void)p;(void)a;(void)b;(void)f;struct sk_buff*s=calloc(1,sizeof(*s));s->data=calloc(1,4096);return s;}
static struct sk_buff *mt76_mcu_msg_alloc(struct mt76_dev*d,void*p,int n){return __mt76_mcu_msg_alloc(d,p,n,n,0);}
static void *skb_put_zero(struct sk_buff*s,int n){assert(s->len+n<=4096);void*p=s->data+s->len;memset(p,0,n);s->len+=n;return p;}
static void *skb_put(struct sk_buff*s,int n){return skb_put_zero(s,n);}static void skb_put_data(struct sk_buff*s,const void*p,int n){memcpy(skb_put_zero(s,n),p,n);}
struct cfg80211_scan_info{bool aborted;};
static void ieee80211_scan_completed(void *hw,struct cfg80211_scan_info*i){(void)hw;assert(i->aborted);}
struct cfg80211_ssid {u8 ssid[32];int ssid_len;};
struct cfg80211_scan_request {int n_ssids,n_channels,n_6ghz_params;struct cfg80211_ssid *ssids;struct ieee80211_channel **channels;u8 bssid[6],mac_addr[6],mac_addr_mask[6];unsigned flags;};
struct ieee80211_scan_ies{const u8 *ies[4];size_t len[4];};
struct ieee80211_scan_request{struct cfg80211_scan_request req;struct ieee80211_scan_ies ies;};
static void mt76_connac_mcu_build_rnr_scan_param(struct mt76_dev*d,struct cfg80211_scan_request*s){(void)d;assert(!s->n_6ghz_params);}
static bool is_mt7928(struct mt76_dev*d){(void)d;return false;}
#define ALIGN(x,n) (((x)+(n)-1)&~((n)-1))
static void output(const void*p,size_t n){assert(fwrite(p,1,n,stdout)==n);}
static int mt76_mcu_skb_send_msg(struct mt76_dev*d,struct sk_buff*s,int cmd,bool wait){(void)d;assert(wait);u16 len=s->len;u8 c=cmd&255;output(&c,1);output(&len,2);output(s->data,s->len);free(s->data);free(s);return 0;}
static int mt76_mcu_send_msg(struct mt76_dev*d,int cmd,const void*p,int n,bool wait){struct sk_buff*s=mt76_mcu_msg_alloc(d,NULL,n);skb_put_data(s,p,n);return mt76_mcu_skb_send_msg(d,s,cmd,wait);}
// These are only optional profile boundaries, never replacement feature logic.
static void mt7925_mcu_sta_ht_tlv(struct sk_buff*s,struct ieee80211_link_sta*l){(void)s;assert(!l->ht_cap.ht_supported);}
static void mt7925_mcu_sta_vht_tlv(struct sk_buff*s,struct ieee80211_link_sta*l){(void)s;assert(!l->vht_cap.vht_supported);}
static void mt76_connac_mcu_sta_uapsd(struct sk_buff*s,struct ieee80211_vif*v,struct ieee80211_sta*l){(void)s;(void)l;assert(v->type==NL80211_IFTYPE_STATION);}
static void mt7925_mcu_sta_amsdu_tlv(struct sk_buff*s,struct ieee80211_vif*v,struct ieee80211_link_sta*l,struct mt792x_link_sta*m){(void)s;(void)v;assert(!l->ht_cap.ht_supported);(void)m;}
static void mt7925_mcu_sta_he_tlv(struct sk_buff*s,struct ieee80211_link_sta*l){(void)s;assert(!l->he_cap.has_he);}
static void mt7925_mcu_sta_he_6g_tlv(struct sk_buff*s,struct ieee80211_link_sta*l){(void)s;assert(!l->he_6ghz_capa.capa);}
static void mt7925_mcu_sta_eht_tlv(struct sk_buff*s,struct ieee80211_link_sta*l){(void)s;assert(!l->eht_cap.has_eht);}
static void mt7925_mcu_sta_eht_mld_tlv(struct sk_buff*s,struct ieee80211_vif*v,struct ieee80211_sta*l){(void)s;(void)l;assert(!ieee80211_vif_is_mld(v));}
static void mt7925_mcu_bss_basic_tlv_nan(struct mt76_phy*p,struct ieee80211_vif*v,struct ieee80211_link_sta*s,void*b){(void)p;(void)v;(void)s;(void)b;abort();}
static void mt7925_mcu_bss_he_tlv(struct sk_buff*s,struct ieee80211_bss_conf*c,struct mt792x_phy*p){(void)s;(void)p;assert(!c->he_support);}
static void mt7925_mcu_bss_color_tlv(struct sk_buff*s,struct ieee80211_bss_conf*c,bool e){(void)s;(void)e;assert(!c->he_support);}
static int ieee80211_frequency_to_channel(int f){return f==2484?14:f<2484?(f-2407)/5:(f-5000)/5;}
'''
parts=[]
for f,names in[(h,['tlv','sta_ntlv_hdr','sta_req_hdr','sta_rec_basic','sta_rec_phy','sta_rec_ra_info','sta_rec_remove','mt76_connac_bss_basic_tlv','mt76_connac_bss_qos_tlv','bss_info_uni_mbssid','mt76_connac_mcu_scan_ssid','mt76_connac_mcu_scan_channel']),(h3,['scan_hdr_tlv','scan_req_tlv','scan_ssid_tlv','scan_bssid_tlv','scan_chan_info_tlv','scan_ie_tlv','scan_misc_tlv','roc_acquire_tlv','bss_req_hdr','sta_rec_hdr_trans','sta_rec_mld','bss_rate_tlv','bss_mld_tlv','bss_ifs_time_tlv','bss_rlm_tlv'])]:
 for n in names:parts.append(layout(f,n))
for f,n in[(h3,'UNI_SCAN_REQ'),('mt7925/mt7925.h','UNI_ROC_ACQUIRE'),(h3,'UNI_BAND_CONFIG_RADIO_ENABLE'),(h,'PHY_TYPE_HR_DSSS_INDEX'),(h,'STA_REC_BASIC'),(h,'UNI_BSS_INFO_BASIC'),(h,'MCU_UNI_CMD_DEV_INFO_UPDATE'),('mt7925/mt7925.h','MODE_OPEN'),(h3,'CONNAC3_CIPHER_NONE')]:
 if n=='CONNAC3_CIPHER_NONE':x=t[f];a=x.index('enum connac3_mcu_cipher_type');parts.append(x[a:x.index('};',a)+2]+'\n')
 else:parts.append(enum(f,n))
for n in ['STA_TYPE_STA','STA_TYPE_AP','STA_TYPE_BC','STA_TYPE_ADHOC','NETWORK_INFRA','NETWORK_P2P','NETWORK_IBSS','NETWORK_NAN','CONNECTION_INFRA_STA','CONNECTION_INFRA_AP','CONNECTION_P2P_GC','CONNECTION_P2P_GO','CONNECTION_INFRA_BC','CONNECTION_IBSS_ADHOC','CONNECTION_NAN','CONN_STATE_PORT_SECURE','CONN_STATE_DISCONNECT','HR_DSSS_ERP_BASIC_RATE','OFDM_BASIC_RATE','PHY_MODE_A','PHY_MODE_B','PHY_MODE_G','PHY_MODE_GN','PHY_MODE_AN','PHY_MODE_AC','PHY_MODE_AX_24G','PHY_MODE_AX_5G','PHY_MODE_AX_6G','PHY_MODE_BE_24G','PHY_MODE_BE_5G','PHY_MODE_BE_6G','PHY_TYPE_BIT_HR_DSSS','PHY_TYPE_BIT_ERP','PHY_TYPE_BIT_OFDM','PHY_TYPE_BIT_HT','PHY_TYPE_BIT_VHT','PHY_TYPE_BIT_HE','PHY_TYPE_BIT_BE','SCAN_FUNC_SPLIT_SCAN','SCAN_FUNC_RANDOM_MAC','SCAN_FUNC_RNR_SCAN']:
 m=re.search(r'^#define '+n+r'\s+[^\n]+',t[h],re.M);assert m,n;parts.append(m.group()+'\n')
parts.append('#define HT_MCS_MASK_NUM 10\n#define RA_LEGACY_OFDM GENMASK(13,6)\n#define RA_LEGACY_CCK GENMASK(3,0)\n')
x=t['mt7925/mt7925.h'];a=x.index('enum mt7925_roc_req {');parts.append(x[a:x.index('};',a)+2]+'\n')
parts.append(t[h][t[h].index('enum mt76_sta_info_state {'):t[h].index('};',t[h].index('enum mt76_sta_info_state {'))+2]+'\n')
helpers=''.join(function(f,n)for f,n in[('mt792x_mac.c','mt792x_rx_get_wcid'),(h,'mt76_connac_mcu_get_wlan_idx'),(c,'mt76_connac_mcu_add_nested_tlv'),(h,'mt76_connac_mcu_add_tlv'),(c,'__mt76_connac_mcu_alloc_sta_req'),(c,'mt76_connac_mcu_sta_basic_tlv'),(c,'mt76_connac_get_phy_mode_v2'),(c,'mt76_connac_get_phy_mode'),(c3,'mt7925_get_phy_mode_ext'),(c3,'mt7925_mcu_sta_phy_tlv'),(c3,'mt7925_mcu_sta_rate_ctrl_tlv'),(c3,'mt7925_mcu_sta_state_v2_tlv'),(c3,'mt7925_mcu_sta_mld_tlv'),(c3,'mt7925_mcu_sta_hdr_trans_tlv'),(c3,'mt7925_mcu_sta_remove_tlv'),(c3,'mt7925_mcu_sta_cmd'),(c3,'__mt7925_mcu_alloc_bss_req'),(c3,'mt7925_mcu_bss_basic_tlv'),(c3,'mt7925_mcu_bss_sec_tlv'),(c3,'mt7925_mcu_bss_bmc_tlv'),(c3,'mt7925_mcu_bss_qos_tlv'),(c3,'mt7925_mcu_bss_mld_tlv'),(c3,'mt7925_mcu_bss_ifs_tlv'),(c3,'mt7925_mcu_bss_rlm_tlv'),(c3,'mt7925_mcu_bss_mbssid_tlv'),(h,'mt76_connac_mcu_bss_deact_err'),(c3,'mt7925_mcu_add_bss_info_sta'),(c3,'mt7925_mcu_set_roc'),(c3,'mt7925_mcu_abort_roc'),(c3,'mt7925_mcu_uni_bss_bcnft'),(c3,'mt7925_mcu_uni_bss_ps'),(c3,'mt7925_mcu_set_bss_pm'),(c3,'mt7925_mcu_set_rxfilter'),(c3,'mt7925_mcu_build_scan_ie_tlv'),(c3,'mt7925_mcu_hw_scan'),(c3,'mt7925_mcu_cancel_hw_scan')])
main=r'''
int main(void){struct mt792x_dev d={0};struct mt76_phy m={.dev=&d.mt76};d.phy=(struct mt792x_phy){.dev=&d,.mt76=&m};
for(int i=0;i<128;i++){
 struct ieee80211_vif v={.type=NL80211_IFTYPE_STATION};struct ieee80211_sta s={0};v.drv_priv[0].phy=&d.phy;v.drv_priv[0].bss_conf.vif=&v.drv_priv[0];s.drv_priv[0].deflink_id=255;
 struct mt76_vif_link *r=&v.drv_priv[0].bss_conf.mt76;r->idx=i%4;r->omac_idx=(i*7)%64;r->band_idx=255;r->wmm_idx=(i/4)%4;
 bool two=i%2==0;struct ieee80211_channel ch={.band=two?0:1,.hw_value=two?6:36,.center_freq=two?2437:5180};v.bss_conf=(struct ieee80211_bss_conf){.vif=&v,.beacon_int=100+i,.dtim_period=1+i%4,.basic_rates=two?0xf:0x15};v.bss_conf.chanreq.oper=(struct cfg80211_chan_def){.chan=&ch,.center_freq1=two?2437:5180};
 d.phy.slottime=(i/8)%2?9:20;m.antenna_mask=1+i%15;r->cipher=(i/16)%2?4:0;r->basic_rates_idx=two?14:18;
 for(int j=0;j<6;j++){v.addr[j]=2+i+j;s.addr[j]=4+i+j;v.bss_conf.bssid[j]=s.addr[j];s.deflink.addr[j]=s.addr[j];}v.addr[0]&=254;s.addr[0]&=254;v.bss_conf.bssid[0]&=254;s.deflink.addr[0]&=254;
 s.deflink.sta=&s;s.deflink.supp_rates[two?0:1]=two?0xfff:0xff;v.cfg.aid=1+i;s.drv_priv[0].deflink.wcid=(struct mt76_wcid){.idx=i%14,.sta=true};
 struct mt76_sta_cmd_info info={.link_sta=&s.deflink,.vif=&v,.link_conf=&v.bss_conf,.wcid=&s.drv_priv[0].deflink.wcid,.enable=true,.newly=true,.cmd=MCU_UNI_CMD(STA_REC_UPDATE),.offload_fw=true};
 if(mt7925_mcu_sta_cmd(&m,&info))abort();info.state=MT76_STA_INFO_STATE_ASSOC;info.newly=false;if(mt7925_mcu_sta_cmd(&m,&info))abort();info.enable=false;if(mt7925_mcu_sta_cmd(&m,&info))abort();
 for(int enable=0;enable<2;enable++)if(mt7925_mcu_add_bss_info_sta(&d.phy,NULL,&v.bss_conf,&s.deflink,19-r->idx,s.drv_priv[0].deflink.wcid.idx,enable))abort();
 if(mt7925_mcu_set_roc(&d.phy,&v.drv_priv[0].bss_conf,&ch,1000,0,i+1)||mt7925_mcu_abort_roc(&d.phy,&v.drv_priv[0].bss_conf,i+1))abort();
 if(mt7925_mcu_uni_bss_bcnft(&d,&v.bss_conf,true)||mt7925_mcu_uni_bss_ps(&d,&v.bss_conf)||mt7925_mcu_set_bss_pm(&d,&v.bss_conf,false))abort();
 if(mt7925_mcu_set_rxfilter(&d,0,1,1U<<11)||mt7925_mcu_set_rxfilter(&d,0,2,1U<<11))abort();
 struct ieee80211_channel *channels[]={&ch};struct cfg80211_ssid ssids[4]={0};for(int k=0;k<4;k++){ssids[k].ssid_len=k;memset(ssids[k].ssid,65+k,k);}
 u8 ies[]={1,1,0x8c};struct ieee80211_scan_request scan={.req={.n_ssids=i%5,.n_channels=1,.ssids=ssids,.channels=channels}};memset(scan.req.bssid,255,6);scan.ies.ies[two?0:1]=ies;scan.ies.len[two?0:1]=(i/4)%2?sizeof(ies):0;
 m.state=0;r->scan_seq_num=i%127;if(mt7925_mcu_hw_scan(&m,&v,&scan)||mt7925_mcu_cancel_hw_scan(&m,&v))abort();
}
struct ieee80211_vif v={0};struct mt792x_sta sta={.vif=&v.drv_priv[0]};struct mt792x_link_sta link={.wcid={.idx=1,.sta=true},.sta=&sta};v.drv_priv[0].sta.deflink.wcid.idx=19;d.wcid[1]=&link.wcid;d.wcid[19]=&v.drv_priv[0].sta.deflink.wcid;
for(int i=0;i<22;i++)for(int unicast=0;unicast<2;unicast++){struct mt76_wcid*w=mt792x_rx_get_wcid(&d,i,unicast);u16 idx=w?w->idx:65535;output(&idx,2);}
return 0;}
'''
# Definitions used by complete layouts precede them; model follows layouts only
# where sizeof/layout names are needed by extracted functions.
pre=pre.replace('typedef uint16_t __le16;','typedef uint16_t __le16;')
unit=out/'client.c';unit.write_text(pre+'\n#define HT_MCS_MASK_NUM 10\n'+''.join(parts)+helpers+main)
exe=out/'client';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit),'-o',str(exe)],check=True)
b=subprocess.run([str(exe.resolve())],stdout=subprocess.PIPE,check=True).stdout;(out/'client.trace').write_bytes(b)
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'cases':128,'requests':1792,'trace_sha256':hashlib.sha256(b).hexdigest()},indent=2)+'\n');print(hashlib.sha256(b).hexdigest())
