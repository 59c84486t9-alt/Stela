#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2015, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged original station/TLC/flush routines in an exclusive legacy seam.

Usage: iwlwifi_peer_oracle.py IWLWIFI_SOURCE OUTPUT_DIRECTORY
No firmware, DMA, frame or RF executes. HT/VHT/HE/EHT and actual TX queues are
excluded, with explicit aborting callbacks for those out-of-scope paths.
The source legacy zero results for config flags/AMSDU/SGI/density are harness
preconditions reviewed separately, not executed whole-function evidence.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
source, out = map(Path, sys.argv[1:])
expected = {
    'mvm/sta.c': '0335c897c356d1c923b850139c97634a1f4299c08e6b1eaa289ee994d830a095',
    'mvm/rs-fw.c': '523b62293d2258d463aa153b4731bfccecfe4196bc6c34ecfa4457e5dadf92f9',
    'mvm/tx.c': '925c237647eeaa1977703f4462374fb708e04c985b1953409dc674beefb5a59a',
    'fw/api/sta.h': '4d3d22ef177b25dcdc828c61b78d84f643cc4ed592fd7e1b7a2834a31a74639c',
    'fw/api/rs.h': 'd747d8143570c613208c30eb450eddb222546e4bad545d7d43791ebed95bb860',
    'fw/api/tx.h': '4cd296f5c4f4c9706745192247e7e531d996c5db8d6743e3367f438cf71fb886',
    'fw/api/datapath.h': '746573de706f6fbc936183670792d4a50ee72c7ceebd72140d7e91b15bbb1a54',
    'fw/api/commands.h': '4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
    'fw/file.h': '148a5f3b2ac6afd9e6b0c2bbc255773482dd7fd6890e70ccd65bca17f3ea9a6c',
}
texts = {}
for name, digest in expected.items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    texts[name] = data.decode()


def extract(file, pattern):
    text = texts[file]
    match = re.search(pattern, text, re.M)
    assert match, pattern
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


def function(file, name):
    return extract(file, r'^(?:static )?(?:inline )?(?:void|int|u8)\s+' + name + r'\([^{};]*?\)\n\{') + '\n'


prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define fallthrough __attribute__((fallthrough))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define le16_to_cpu(x) ((u16)(x))
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define IWL_DEBUG_ASSOC(...)
#define IWL_DEBUG_RATE(...)
#define IWL_DEBUG_TX_QUEUES(...)
#define IWL_DEBUG_INFO(...)
#define IWL_ERR(...)
#define lockdep_assert_held(...)
#define lockdep_is_held(...) true
#define rcu_read_lock()
#define rcu_read_unlock()
#define rcu_dereference(x) (x)
#define rcu_dereference_protected(x,...) (x)
#define ETH_ALEN 6
#define BITS_PER_LONG 64
#define for_each_set_bit(i,p,n) for((i)=0;(i)<(n);(i)++)if((*(p)>>i)&1)
#define WIDE_ID(g,o) (((g)<<8)|(o))
#define LONG_GROUP 1
#define DATA_PATH_GROUP 5
#define CMD_ASYNC 1
#define CMD_WANT_SKB 2
#define CMD_SEND_IN_RFKILL 4
#define IWL_MGMT_TID 15
#define IWL_MAX_TID_COUNT 16
enum{NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_6GHZ};
enum nl80211_band{DUMMY_BAND};
enum{IEEE80211_STA_RX_BW_20,IEEE80211_STA_RX_BW_40,IEEE80211_STA_RX_BW_80,IEEE80211_STA_RX_BW_160,IEEE80211_STA_RX_BW_320};
enum{IEEE80211_SMPS_AUTOMATIC,IEEE80211_SMPS_NUM_MODES,IEEE80211_SMPS_STATIC,IEEE80211_SMPS_DYNAMIC,IEEE80211_SMPS_OFF};
#define IEEE80211_STA_ASSOC 2
'''
for name in ['iwl_sta_flags', 'iwl_sta_mode', 'iwl_sta_modify_flag', 'iwl_mvm_add_sta_rsp_status']:
    prelude += extract('fw/api/sta.h', r'^enum ' + name + r'\s*\{') + ';\n'
prelude += re.search(r'^#define IWL_ADD_STA_STATUS_MASK[^\n]+', texts['fw/api/sta.h'], re.M)[0] + '\n'
for name in ['iwl_mvm_add_sta_cmd_v7', 'iwl_mvm_add_sta_cmd', 'iwl_mvm_rm_sta_cmd']:
    prelude += extract('fw/api/sta.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
for name in ['iwl_tlc_mng_cfg_flags', 'iwl_tlc_mng_cfg_cw', 'iwl_tlc_mng_cfg_chains', 'iwl_tlc_mng_cfg_mode', 'IWL_TLC_MNG_NSS', 'IWL_TLC_MCS_PER_BW']:
    prelude += extract('fw/api/rs.h', r'^enum ' + name + r'\s*\{') + ';\n'
for name in ['iwl_tlc_config_cmd_v3', 'iwl_tlc_config_cmd_v4']:
    prelude += extract('fw/api/rs.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
prelude += re.search(r'^#define IWL_TX_FLUSH_QUEUE_RSP[^\n]+', texts['fw/api/tx.h'], re.M)[0] + '\n'
for name in ['iwl_tx_path_flush_cmd', 'iwl_flush_queue_info', 'iwl_tx_path_flush_cmd_rsp']:
    prelude += extract('fw/api/tx.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
for name, value in [('ADD_STA', 0x18), ('REMOVE_STA', 0x19), ('TXPATH_FLUSH', 0x1e)]:
    assert re.search(name + r'\s*=\s*' + hex(value), texts['fw/api/commands.h'])
    prelude += f'#define {name} {value}\n'
assert re.search(r'TLC_MNG_CONFIG_CMD\s*=\s*0xF', texts['fw/api/datapath.h'])
prelude += '#define TLC_MNG_CONFIG_CMD 15\n'
assert re.search(r'IWL_UCODE_TLV_API_STA_TYPE\s*=\s*\(__force iwl_ucode_tlv_api_t\)30', texts['fw/file.h'])
prelude += '#define IWL_UCODE_TLV_API_STA_TYPE 30\n'
prelude += r'''
struct iwl_mvm;struct ieee80211_vif;
struct ieee80211_sta_ht_cap{bool ht_supported;struct{u8 rx_mask[2];}mcs;};
struct ieee80211_sta_vht_cap{bool vht_supported;};
struct ieee80211_sta_he_cap{bool has_he;};
struct ieee80211_sta_eht_cap{bool has_eht;struct{u8 phy_cap_info[6];}eht_cap_elem;};
struct ieee80211_link_sta{unsigned bandwidth,rx_nss,smps_mode,link_id;unsigned long supp_rates[3];
 struct ieee80211_sta_ht_cap ht_cap;struct ieee80211_sta_vht_cap vht_cap;
 struct ieee80211_sta_he_cap he_cap;struct ieee80211_sta_eht_cap eht_cap;
 struct{u16 max_amsdu_len;}agg;};
struct ieee80211_channel{unsigned band;};
struct ieee80211_bss_conf{struct{struct{struct ieee80211_channel *chan;}oper;}chanreq;unsigned link_id;};
struct iwl_lq_sta_rs_fw{u8 current[8];struct{unsigned preserved;}pers;};
struct iwl_mvm_link_sta{u8 sta_id;struct{struct iwl_lq_sta_rs_fw rs_fw;}lq_sta;};
struct iwl_mvm_sta{struct iwl_mvm_link_sta deflink;u32 mac_id_n_color,tfd_queue_msk;
 u16 tid_disable_agg;u8 sta_type;unsigned sta_state;bool authorized;struct ieee80211_vif *vif;
 struct iwl_mvm_link_sta *link[1];};
struct ieee80211_sta{u8 addr[6];u16 aid;bool wme;u8 max_sp;struct ieee80211_link_sta deflink;struct iwl_mvm_sta *priv;};
struct iwl_mvm_vif{u16 max_tx_op;};
struct ieee80211_vif{struct ieee80211_bss_conf bss_conf;struct iwl_mvm_vif *priv;};
struct ieee80211_rate{u8 hw_value;};
struct ieee80211_supported_band{unsigned band;struct ieee80211_rate *bitrates;};
struct wiphy{struct ieee80211_supported_band *bands[3];};struct ieee80211_hw{struct wiphy *wiphy;};
struct caps{bool sta_type;};struct fw{struct caps ucode_capa;};
struct iwl_mvm{struct fw *fw;struct ieee80211_hw *hw;struct ieee80211_sta *fw_id_to_mac_id[1];};
struct ieee80211_tx_info{u32 unused;};
struct iwl_rx_packet{u8 data[132];};
struct iwl_host_cmd{u32 id,flags;u16 len[1];const void *data[1];struct iwl_rx_packet *resp_pkt;};
static bool fw_has_api(struct caps *c,unsigned bit){if(bit!=30)abort();return c->sta_type;}
static bool iwl_mvm_has_new_rx_api(struct iwl_mvm *m){(void)m;return true;}
static bool iwl_mvm_has_new_tx_api(struct iwl_mvm *m){(void)m;return true;}
static struct iwl_mvm_sta *iwl_mvm_sta_from_mac80211(struct ieee80211_sta *s){return s->priv;}
static struct iwl_mvm_vif *iwl_mvm_vif_from_mac80211(struct ieee80211_vif *v){return v->priv;}
static u32 iwl_mvm_get_sta_ampdu_dens(struct ieee80211_link_sta *s,struct ieee80211_bss_conf *b,u32 *size){
 if(s->ht_cap.ht_supported||s->vht_cap.vht_supported||s->he_cap.has_he||s->eht_cap.has_eht||b->chanreq.oper.chan->band==2)abort();*size=0;return 0;}
static u8 iwl_mvm_get_sta_uapsd_acs(struct ieee80211_sta *s){(void)s;abort();}
static u8 next_cmd_ver,next_notif_ver;static u32 next_status;static int failure;
static unsigned length,sends;static u8 wire[256];static struct iwl_rx_packet response;
static void capture(u32 id,unsigned n,const void *p){if(id!=ADD_STA&&id!=REMOVE_STA&&id!=TXPATH_FLUSH&&id!=WIDE_ID(5,15))abort();if(n>sizeof(wire))abort();length=n;sends++;memcpy(wire,p,n);}
static int iwl_mvm_send_cmd_pdu_status(struct iwl_mvm *m,u32 id,unsigned n,void *p,u32 *status){(void)m;capture(id,n,p);*status=next_status;return failure;}
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned n,const void *p){(void)m;if(flags!=(id==WIDE_ID(5,15)?CMD_ASYNC:0))abort();capture(id,n,p);return failure;}
static int iwl_mvm_send_cmd(struct iwl_mvm *m,struct iwl_host_cmd *c){(void)m;capture(c->id,c->len[0],c->data[0]);c->resp_pkt=&response;return failure;}
static unsigned iwl_fw_lookup_cmd_ver(struct fw *f,u32 id,unsigned fallback){(void)f;(void)id;(void)fallback;return next_cmd_ver;}
static unsigned iwl_fw_lookup_notif_ver(struct fw *f,unsigned group,u32 id,unsigned fallback){(void)f;(void)group;(void)id;(void)fallback;return next_notif_ver;}
static unsigned iwl_rx_packet_payload_len(struct iwl_rx_packet *p){(void)p;return 132;}
static void iwl_free_resp(struct iwl_host_cmd *c){(void)c;}
static void iwl_mvm_tx_reclaim(struct iwl_mvm *m,u32 s,int t,int q,int r,struct ieee80211_tx_info *i,unsigned a,bool f){(void)m;(void)s;(void)t;(void)q;(void)r;(void)i;(void)a;(void)f;abort();}
static void rs_fw_eht_set_enabled_rates(struct ieee80211_vif *v,struct ieee80211_link_sta *s,const struct ieee80211_sta_he_cap *h,const struct ieee80211_sta_eht_cap *e,struct iwl_tlc_config_cmd_v4 *c){(void)v;(void)s;(void)h;(void)e;(void)c;abort();}
static void rs_fw_he_set_enabled_rates(struct ieee80211_link_sta *s,const struct ieee80211_sta_he_cap *h,struct iwl_tlc_config_cmd_v4 *c){(void)s;(void)h;(void)c;abort();}
static void rs_fw_vht_set_enabled_rates(struct ieee80211_link_sta *s,const struct ieee80211_sta_vht_cap *v,struct iwl_tlc_config_cmd_v4 *c){(void)s;(void)v;(void)c;abort();}
static const struct ieee80211_sta_he_cap *ieee80211_get_he_iftype_cap_vif(struct ieee80211_supported_band *s,struct ieee80211_vif *v){(void)s;(void)v;return NULL;}
static const struct ieee80211_sta_eht_cap *ieee80211_get_eht_iftype_cap_vif(struct ieee80211_supported_band *s,struct ieee80211_vif *v){(void)s;(void)v;return NULL;}
static u16 rs_fw_get_max_amsdu_len(struct ieee80211_sta *s,struct ieee80211_bss_conf *b,struct ieee80211_link_sta *l){(void)s;(void)b;if(l->ht_cap.ht_supported||l->vht_cap.vht_supported||l->he_cap.has_he||l->eht_cap.has_eht)abort();return 0;}
static u16 rs_fw_get_config_flags(struct iwl_mvm *m,struct ieee80211_vif *v,struct ieee80211_link_sta *s,const struct ieee80211_sta_he_cap *h){(void)m;(void)v;(void)h;if(s->ht_cap.ht_supported||s->vht_cap.vht_supported||s->he_cap.has_he||s->eht_cap.has_eht)abort();return 0;}
static u8 rs_fw_sgi_cw_support(struct ieee80211_link_sta *s){if(s->ht_cap.ht_supported||s->vht_cap.vht_supported||s->he_cap.has_he)abort();return 0;}
static bool iwl_mvm_is_csum_supported(struct iwl_mvm *m){(void)m;return true;}
static u8 antennas;static u8 iwl_mvm_get_valid_tx_ant(struct iwl_mvm *m){(void)m;return antennas;}
static void ieee80211_sta_recalc_aggregates(struct ieee80211_sta *s){(void)s;}
#define ANT_A 1
#define ANT_B 2
#define IEEE80211_EHT_PHY_CAP5_SUPP_EXTRA_EHT_LTF 1
'''
prelude += function('mvm/sta.c', 'iwl_mvm_add_sta_cmd_size')
prelude += function('mvm/sta.c', 'iwl_mvm_sta_send_to_fw')
prelude += function('mvm/sta.c', 'iwl_mvm_drain_sta')
prelude += function('mvm/sta.c', 'iwl_mvm_rm_sta_common')
prelude += function('mvm/tx.c', 'iwl_mvm_flush_sta_tids')
prelude += function('mvm/rs-fw.c', 'rs_fw_bw_from_sta_bw')
prelude += function('mvm/rs-fw.c', 'rs_fw_set_active_chains')
prelude += function('mvm/rs-fw.c', 'rs_fw_set_supp_rates')
prelude += function('mvm/rs-fw.c', 'iwl_mvm_rs_fw_rate_init')
main = r'''
static void hex(void){if(!length){printf("-");return;}for(unsigned i=0;i<length;i++)printf("%02x",wire[i]);}
int main(void){
 struct fw fw={0};struct ieee80211_channel channel={0};struct iwl_mvm_vif mvif={0};
 struct ieee80211_vif vif={.priv=&mvif,.bss_conf={.chanreq={.oper={.chan=&channel}}}};
 struct iwl_mvm_link_sta link={0};struct iwl_mvm_sta ms={.vif=&vif,.tid_disable_agg=0xffff,.link={&link}};
 struct ieee80211_sta sta={.priv=&ms,.addr={2,3,4,5,6,7},.deflink={.rx_nss=1,.smps_mode=IEEE80211_SMPS_OFF}};
 struct ieee80211_rate bitrates[12];for(unsigned i=0;i<12;i++)bitrates[i].hw_value=i;
 struct ieee80211_supported_band bands[2]={{.band=0,.bitrates=bitrates},{.band=1,.bitrates=bitrates+4}};
 struct wiphy wiphy={.bands={&bands[0],&bands[1]}};struct ieee80211_hw hw={.wiphy=&wiphy};
 struct iwl_mvm m={.fw=&fw,.hw=&hw,.fw_id_to_mac_id={&sta}};
 for(unsigned kind=0;kind<3;kind++)for(unsigned s=0;s<4;s++){
  static u32 statuses[]={0,1,0x101,2};next_status=statuses[s];length=sends=0;
  int r=kind==0?iwl_mvm_sta_send_to_fw(&m,&sta,false,0):iwl_mvm_drain_sta(&m,&ms,kind==1);
  printf("S %u %u %d %u ",kind,next_status,r,length);hex();puts("");
 }
 for(unsigned version=1;version<=4;version++)for(unsigned ant=1;ant<=3;ant++)
 for(unsigned band=0;band<2;band++)for(unsigned mask=0;mask<3;mask++){
  static unsigned masks[2][3]={{1,0x15f,0xfff},{0x10,0x150,0xff0}};
  unsigned rates=masks[band][mask];next_cmd_ver=version;antennas=ant;channel.band=band;
  sta.deflink.supp_rates[band]=band?rates>>4:rates;length=sends=0;
  iwl_mvm_rs_fw_rate_init(&m,&vif,&sta,&vif.bss_conf,&sta.deflink,band);
  printf("T %u %u %u %u %u ",version,ant,band,rates,length);hex();puts("");
 }
 for(unsigned notification=0;notification<2;notification++)for(unsigned failed=0;failed<2;failed++)
 for(unsigned station=0;station<2;station++)for(unsigned queue=0;queue<2;queue++){
  next_notif_ver=notification;failure=failed?-5:0;memset(&response,0,sizeof(response));
  struct iwl_tx_path_flush_cmd_rsp *rsp=(void*)response.data;rsp->sta_id=station;rsp->num_flushed_queues=queue?17:0;
  length=sends=0;int r=iwl_mvm_flush_sta_tids(&m,0,0xffff);
  printf("F %u %u %u %u %d %u ",notification,failed,station,queue?17:0,r,length);hex();puts("");
 }
 failure=0;length=sends=0;int r=iwl_mvm_rm_sta_common(&m,0);printf("R %d %u ",r,length);hex();puts("");
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
unit = out / 'linux-iwlwifi-peer.c'
unit.write_text(prelude + main)
exe = out / 'linux-iwlwifi-peer'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
data = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'sources': expected,
            'records': len(data.splitlines()), 'trace_sha256': hashlib.sha256(data).hexdigest(),
            'scope': __doc__}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
