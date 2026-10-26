#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Original LINK_CHANGED/ACK/QOS/session-stop and complete unassign callback.

Usage: SCRIPT IWLWIFI_SOURCE QUALIFIED_COLD_MLD_ORACLE_DIRECTORY OUTPUT_DIRECTORY
Reuse only the hash-bound cold C environment, not a behavioral substitute.
Every appended original function is read unchanged from the pinned source.
Mock declaration expansion never edits an original function or wire structure.
MAC-power bytes retain their separately qualified original cold power trace;
the callback here records that mandatory operation, without fabricating bytes.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
source,cold,out=map(Path,sys.argv[1:])
unit=(cold/'linux-iwlwifi-mld-mac.c').read_bytes()
assert hashlib.sha256(unit).hexdigest()=='83c945954eb4800fdc5bbd22c516d73d0aa53e6d955abc6de9e929d7f7de5a23'
manifest=(cold/'manifest.json').read_bytes()
assert hashlib.sha256(manifest).hexdigest()=='cbbaa0497c7006272dbb93c0232e5f51788145d568197562f1e64c5c32f35b6b'
expected=json.loads(manifest)['sources']
expected.update({
 'mvm/utils.c':'bf94624889244fa7f87a9295ea15b771235efbd7fb66e692305421270c1f57bc',
 'mvm/phy-ctxt.c':'5b5bc999db3b4a6089b6261b5890b45b4d9c8682363f4947f701f4442d91f4ec',
 'mvm/time-event.c':'73b3e03c8543dfbab0877aaf10c8635f631e7b93d50ed2916ee42ff387fcb7a8',
 'fw/api/time-event.h':'f62a382f45cc9ddd246c471ac77a09cbaa727f6328c2858b03feea4e85b2a5a3',
 'fw/api/rs.h':'d747d8143570c613208c30eb450eddb222546e4bad545d7d43791ebed95bb860',
 'fw/api/txq.h':'99c49fca97b83a092ca3017c2c6ee34c52ee68ce2b7f016e10fa8b35d9aceeb5',
 'iwl-config.h':'b37b175d2b80eb7a9309792d22f41e8cc94a60246420948e1e7a5b5aff65c4c9',
 'fw/api/phy-ctxt.h':'5f40dde9483551f27859e0a9bf8d782220d4d51ec03673b4118a416198e32b92',
 'fw/api/phy.h':'a4c17fc7e3cf8445649a12abede1ed91cbce96ff5b79c0293c101fd76a20dde6',
 'fw/api/power.h':'8182c5583306e9c35628991815d63233c70c333a58f14eac42069af75b1fe7f4',
})
texts={}
for name,digest in expected.items():
    data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
root=source.parents[4]
headers={'include/uapi/linux/nl80211.h':'5b67257da9911fbffa2d5a3689c629f69e628dbf3147ddf30c65606b251f493b',
 'include/net/mac80211.h':'aa6fab3b830cb56fcfa20b1090a6f947aeef19ad0f81ed9153b517944bd4a740',
 'include/linux/ieee80211-ht.h':'0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b',
 'include/linux/ieee80211-he.h':'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e'}
headers['include/net/cfg80211.h']='0aea8e24b0d1677ba3764ed9f495de463675b2249ccc577b89ca2d925bc5f3fa'
for name,digest in headers.items():
    data=(root/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()


def extract(file,pattern):
    text=texts[file];m=re.search(pattern,text,re.M);assert m,pattern
    at,depth=m.end(),1
    while depth:
        depth+=(text[at]=='{')-(text[at]=='}');at+=1
    return text[m.start():at]


def function(file,name):
    return extract(file,r'^(?:static )?(?:inline )?(?:void|bool|int|u8)\s+'+name+r'\([^{};]*?\)\s*\n\{')+'\n'


prefix=unit.decode().split('static void record(')[0]
def replace(old,new):
    global prefix
    assert prefix.count(old)==1,old
    prefix=prefix.replace(old,new)

# Expand only authored fixture declarations. Original packed wire types and
# all original cold function bodies remain byte-exact, checked below.
declarations=''
for file,name in [('include/uapi/linux/nl80211.h','nl80211_band'),('include/uapi/linux/nl80211.h','nl80211_chan_width'),
 ('include/uapi/linux/nl80211.h','nl80211_channel_type'),
 ('include/net/mac80211.h','ieee80211_ac_numbers'),('iwl-config.h','iwl_device_family'),
 ('fw/api/mac-cfg.h','iwl_link_ctx_modify_flags'),('fw/api/mac-cfg.h','iwl_link_ctx_protection_flags'),
 ('fw/api/mac-cfg.h','iwl_link_ctx_flags'),('fw/api/mac.h','iwl_mac_qos_flags'),
 ('fw/api/txq.h','iwl_mvm_tx_fifo'),('fw/api/txq.h','iwl_gen2_tx_fifo'),('fw/api/txq.h','iwl_bz_tx_fifo'),
 ('fw/api/time-event.h','iwl_time_event_type'),('fw/api/time-event.h','iwl_session_prot_conf_id')]:
    declarations+=extract(file,r'^enum '+name+r'\s*\{')+';\n'
rate=re.search(r'^enum\s*\{\n\s*IWL_RATE_1M_INDEX[^}]+\};',texts['fw/api/rs.h'],re.M);assert rate
declarations+=rate[0]+'\n#define IWL_RATE_BIT_MSK(r) BIT(IWL_RATE_##r##M_INDEX)\n'
for line in texts['include/linux/ieee80211-ht.h'].splitlines():
    if re.match(r'^#define\s+IEEE80211_HT_OP_MODE_PROTECTION',line):declarations+=line+'\n'
declarations+=re.search(r'^#define IEEE80211_HE_MAC_CAP5_OM_CTRL_UL_MU_DATA_DIS_RX[^\n]+',texts['include/linux/ieee80211-he.h'],re.M)[0]+'\n'
match=re.search(r'IWL_UCODE_TLV_CAPA_SESSION_PROT_CMD\s*=\s*\(__force iwl_ucode_tlv_capa_t\)(\d+)',texts['fw/file.h']);assert match
declarations+=f'#define IWL_UCODE_TLV_CAPA_SESSION_PROT_CMD {match[1]}\n'
declarations+=extract('fw/api/power.h',r'^enum iwl_6ghz_ap_type\s*\{')+';\n'
declarations+=extract('include/net/cfg80211.h',r'^enum ieee80211_ap_reg_power\s*\{')+';\n'
for name in ['DEFAULT_TPE_TX_POWER','IWL_MAX_TX_EIRP_PWR_MAX_SIZE','IWL_MAX_TX_EIRP_PSD_PWR_MAX_SIZE']:
    declarations+=re.search(r'^#define '+name+r'[^\n]+',texts['fw/api/power.h'],re.M)[0]+'\n'
declarations+='typedef int8_t __s8;\n'+extract('fw/api/power.h',r'^struct iwl_txpower_constraints_cmd\s*\{')+' __packed;\n'
declarations+=re.search(r'^#define IWL_FW_CMD_VER_UNKNOWN[^\n]+',texts['fw/file.h'],re.M)[0]+'\n'
declarations+=re.search(r'^#define NUM_PHY_CTX[^\n]+',texts['fw/api/phy-ctxt.h'],re.M)[0]+'\n'
match=re.search(r'AP_TX_POWER_CONSTRAINTS_CMD\s*=\s*(0x\w+)',texts['fw/api/phy.h']);assert match
declarations+=f'#define AP_TX_POWER_CONSTRAINTS_CMD {match[1]}\n'
declarations+=r'''
#define BITS_PER_LONG 64
#define IEEE80211_NUM_ACS AC_NUM
#define for_each_set_bit(i,p,n) for((i)=0;(i)<(n);(i)++)if((*(p)>>i)&1)
#define BUILD_BUG_ON(x) _Static_assert(!(x),#x)
#define IWL_DEBUG_RATE(...)
#define IWL_DEBUG_MAC80211(...)
#define IWL_DEBUG_TE(...)
#define lockdep_assert_held(...)
#define spin_lock_bh(...)
#define spin_unlock_bh(...)
#define mutex_lock(...)
#define mutex_unlock(...)
#define guard(k) fixture_guard
#define rcu_assign_pointer(...) abort()
#define ether_addr_copy(d,s) memcpy(d,s,6)
#define PHY_CONTEXT_CMD 8
struct ieee80211_channel{enum nl80211_band band;};
struct cfg80211_chan_def{struct ieee80211_channel *chan;enum nl80211_chan_width width;u16 punctured;u32 center_freq1;};
struct ieee80211_chanctx_conf{u8 drv_priv[2];struct cfg80211_chan_def def,ap;u8 rx_chains_static,rx_chains_dynamic;};
struct iwl_mvm_phy_ctxt{u32 id,ref;struct ieee80211_channel *channel;unsigned width,center_freq1;};
struct ieee80211_tx_queue_params{unsigned cw_min,cw_max,aifs,txop;};
struct iwl_mvm_time_event_data{u32 id;};
struct cfg{enum iwl_device_family device_family;bool gen2;};struct trans{struct cfg *mac_cfg;};
'''
replace('#define NL80211_BAND_2GHZ 0\n','')
replace('struct ieee80211_sta;\n',declarations+'struct ieee80211_sta;\n')
replace('struct ieee80211_sta_he_cap{struct{u8 mac_cap_info[6];}he_cap_elem;};',
 'struct ieee80211_sta_he_cap{bool has_he;struct{u8 mac_cap_info[6];}he_cap_elem;};')
replace('struct ieee80211_supported_band{struct ieee80211_sta_he_cap *he;};',
 'struct ieee80211_link_sta{struct ieee80211_sta_he_cap he_cap;};struct ieee80211_rate{u8 hw_value;};\nstruct ieee80211_supported_band{struct ieee80211_sta_he_cap *he;struct ieee80211_rate *bitrates;};')
replace('struct wiphy{struct ieee80211_supported_band *bands[1];};struct ieee80211_hw{struct wiphy *wiphy;};',
 'struct wiphy{struct ieee80211_supported_band *bands[4];};struct ieee80211_hw{struct wiphy *wiphy;struct iwl_mvm *adapter;};\n#define IWL_MAC80211_GET_MVM(hw) ((hw)->adapter)')
replace('struct ieee80211_bss_conf{unsigned link_id;bool he_support,eht_support;u8 addr[6];const u8 *bssid;unsigned dtim_period;};',r'''
struct ieee80211_bss_conf{unsigned link_id;bool he_support,eht_support;u8 addr[6];const u8 *bssid;
 unsigned dtim_period,beacon_int;unsigned long basic_rates;bool use_short_preamble,use_short_slot,use_cts_prot,qos;
 unsigned ht_operation_mode;struct{struct cfg80211_chan_def oper;}chanreq;
 u8 htc_trig_based_pkt_ext,uora_ocw_range;bool uora_exists;struct ieee80211_chanctx_conf *chanctx_conf;
 struct{u8 color;bool enabled;}he_bss_color;u16 frame_time_rts_th;bool nontransmitted;u8 transmitter_bssid[6],bssid_index;enum ieee80211_ap_reg_power power_type;};
''')
replace('struct iwl_mvm_vif_link_info{u32 fw_link_id,listen_lmac;void *phy_ctxt;};',
 'struct iwl_mvm_vif_link_info{u32 fw_link_id,listen_lmac;struct iwl_mvm_phy_ctxt *phy_ctxt;bool active,csa_block_tx,he_ru_2mhz_block;struct ieee80211_tx_queue_params queue_params[4];};')
replace('struct iwl_mvm_vif{u32 id;bool uploaded,authorized;struct iwl_mvm_vif_link_info *link[1];struct ieee80211_sta *ap_sta;};',
 'struct iwl_mvm_vif{u32 id;bool uploaded,authorized,csa_countdown,ap_ibss_active;struct iwl_mvm_vif_link_info *link[1];struct ieee80211_sta *ap_sta;struct iwl_mvm_time_event_data time_event_data;};')
replace('struct ieee80211_vif{unsigned type;bool p2p,probe_req_reg;struct{bool assoc;u16 aid;}cfg;',
 'struct ieee80211_vif{unsigned type;bool p2p,probe_req_reg;u16 valid_links,active_links;struct{bool assoc;u16 aid;}cfg;')
replace('struct caps{bool offload;};','struct caps{bool offload,session;};')
replace('struct iwl_mvm{struct fw *fw;struct ieee80211_hw *hw;unsigned long status;enum iwl_sf_state sf_state;};',
 'struct iwl_mvm{struct fw *fw;struct ieee80211_hw *hw;unsigned long status;enum iwl_sf_state sf_state;struct trans *trans;struct iwl_mvm_phy_ctxt phy_ctxts[NUM_PHY_CTX];};')
replace('static struct{bool disable_11ax;}iwlwifi_mod_params;','static struct{bool disable_11ax,disable_11be;}iwlwifi_mod_params;')
replace('static bool fw_has_capa(struct caps *c,unsigned bit){(void)c;(void)bit;abort();}',
 'static bool fw_has_capa(struct caps *c,unsigned bit){if(bit!=54)abort();return c->session;}')
replace('length=n;memcpy(wire,p,n);return 0;}',
 'length=n;memcpy(wire,p,n);return fixture_failure;}')
replace('static unsigned mac_version,link_version,length,sf_commands;static u8 wire[256];',
 'static int fixture_failure;static unsigned mac_version,link_version,length,sf_commands;static u8 wire[256];')
replace('static unsigned iwl_fw_lookup_cmd_ver(struct fw *f,u32 id,unsigned fallback){(void)f;(void)fallback;if(id==WIDE_ID(MAC_CONF_GROUP,8))return mac_version;if(id==WIDE_ID(MAC_CONF_GROUP,9))return link_version;abort();}',
 'static unsigned iwl_fw_lookup_cmd_ver(struct fw *f,u32 id,unsigned fallback){(void)f;(void)fallback;if(id==WIDE_ID(PHY_OPS_GROUP,AP_TX_POWER_CONSTRAINTS_CMD))return 1;if(id==WIDE_ID(MAC_CONF_GROUP,8))return mac_version;if(id==WIDE_ID(MAC_CONF_GROUP,9))return link_version;abort();}')
replace('static int iwl_mvm_send_cmd_pdu(', 'static void fixture_capture(u32,unsigned,const void*);\nstatic int iwl_mvm_send_cmd_pdu(')
replace('length=n;memcpy(wire,p,n);return fixture_failure;}', 'length=n;memcpy(wire,p,n);fixture_capture(id,n,p);return fixture_failure;}')
new=r'''
static unsigned remove_events,power_calls;
static bool history;static unsigned nh,ids[16],sizes[16],refs[16];static u8 payloads[16][256];static struct iwl_mvm_phy_ctxt *history_phy;
static void fixture_capture(u32 id,unsigned n,const void *p){if(!history)return;if(nh>=16)abort();ids[nh]=id;sizes[nh]=n;refs[nh]=history_phy->ref;if(n)memcpy(payloads[nh],p,n);nh++;}
static void fixture_guard(struct iwl_mvm *m){(void)m;}
static void iwl_mvm_remove_time_event(struct iwl_mvm *m,struct iwl_mvm_vif *v,struct iwl_mvm_time_event_data *d){(void)m;(void)v;(void)d;remove_events++;abort();}
static bool iwl_mvm_has_new_tx_api(struct iwl_mvm *m){return m->trans->mac_cfg->gen2;}
static struct ieee80211_link_sta *link_sta_dereference_check(struct ieee80211_sta *s,unsigned i){(void)s;(void)i;abort();}
static bool iwl_mvm_set_fw_mu_edca_params(struct iwl_mvm *m,struct iwl_mvm_vif_link_info *l,struct iwl_he_backoff_conf *c){(void)m;(void)l;(void)c;abort();}
static struct cfg80211_chan_def *iwl_mvm_chanctx_def(struct iwl_mvm *m,struct ieee80211_chanctx_conf *c){(void)m;return &c->def;}
static int iwl_mvm_power_update_mac(struct iwl_mvm *m){(void)m;power_calls++;fixture_capture(0xa9,0,NULL);return 0;}
static int iwl_mvm_mld_add_snif_sta(struct iwl_mvm *m,struct ieee80211_vif *v,struct ieee80211_bss_conf *b){(void)m;(void)v;(void)b;abort();}
static void iwl_mvm_mld_rm_snif_sta(struct iwl_mvm *m,struct ieee80211_vif *v){(void)m;(void)v;abort();}
static void iwl_mvm_modify_all_sta_disable_tx(struct iwl_mvm *m,struct iwl_mvm_vif *v,bool d){(void)m;(void)v;(void)d;abort();}
static void iwl_mvm_tpe_sta_cmd_data(struct iwl_txpower_constraints_cmd *c,const struct ieee80211_bss_conf *b){(void)c;(void)b;abort();}
static int iwl_mvm_phy_ctxt_apply(struct iwl_mvm *m,struct iwl_mvm_phy_ctxt *c,const struct cfg80211_chan_def *d,u8 s,u8 y,u32 action){(void)m;(void)c;(void)d;if(s!=1||y!=1)abort();if(action==FW_CTXT_ACTION_REMOVE)fixture_capture(PHY_CONTEXT_CMD,0,NULL);else if(action!=FW_CTXT_ACTION_ADD)abort();return 0;}
static void cfg80211_chandef_create(struct cfg80211_chan_def *d,struct ieee80211_channel *c,unsigned type){(void)type;d->chan=c;d->width=NL80211_CHAN_WIDTH_20_NOHT;}
'''
for name in ['iwl_mvm_ac_to_tx_fifo','iwl_mvm_ac_to_gen2_tx_fifo','iwl_mvm_ac_to_bz_tx_fifo']:
    match=re.search(r'^const u8 '+name+r'\[\]\s*=\s*\{[^}]+\};',texts['mvm/mac-ctxt.c'],re.M);assert match;new+=match[0]+'\n'
for file,name in [('mvm/mvm.h','iwl_mvm_mac_ac_to_tx_fifo'),('mvm/utils.c','iwl_mvm_mac80211_ac_to_ucode_ac'),
 ('mvm/mac-ctxt.c','iwl_mvm_ack_rates'),('mvm/mac-ctxt.c','iwl_mvm_set_fw_basic_rates'),
 ('mvm/mac-ctxt.c','iwl_mvm_set_fw_protection_flags'),('mvm/mac-ctxt.c','iwl_mvm_set_fw_qos_params'),
 ('mvm/time-event.c','iwl_mvm_stop_session_protection'),('mvm/link.c','iwl_mvm_link_changed')]:new+=function(file,name)
for file,name in [('include/net/mac80211.h','ieee80211_vif_is_mld'),('include/net/mac80211.h','ieee80211_vif_link_active'),
 ('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_changed'),
 ('mvm/mld-mac80211.c','iwl_mvm_send_ap_tx_power_constraint_cmd'),
 ('mvm/mld-mac80211.c','__iwl_mvm_mld_assign_vif_chanctx'),('mvm/mld-mac80211.c','iwl_mvm_mld_assign_vif_chanctx'),
 ('mvm/mld-mac80211.c','__iwl_mvm_mld_unassign_vif_chanctx'),('mvm/mld-mac80211.c','iwl_mvm_mld_unassign_vif_chanctx'),
 ('mvm/phy-ctxt.c','iwl_mvm_phy_ctxt_add'),('mvm/phy-ctxt.c','iwl_mvm_phy_ctxt_unref')]:new+=function(file,name)
new+=extract('mvm/mac80211.c',r'^struct iwl_mvm_phy_ctxt \*iwl_mvm_get_free_phy_ctxt\([^{};]*?\)\n\{')+'\n'
new+=function('mvm/mac80211.c','__iwl_mvm_add_chanctx')+function('mvm/mac80211.c','__iwl_mvm_remove_chanctx')
main=r'''
int main(void){
 struct fw fw={0};struct iwl_mvm_vif_link_info link={.fw_link_id=0};struct iwl_mvm_vif mvif={.link={&link}};
 struct ieee80211_vif vif={.type=NL80211_IFTYPE_STATION,.priv=&mvif};
 struct ieee80211_channel channel={0};struct iwl_mvm_phy_ctxt phy={.channel=&channel};link.phy_ctxt=&phy;
 struct ieee80211_rate rates[12];for(unsigned i=0;i<12;i++)rates[i].hw_value=i;
 struct ieee80211_supported_band bands[2]={{.bitrates=rates},{.bitrates=rates+4}};
 struct wiphy wiphy={.bands={&bands[0],&bands[1]}};struct ieee80211_hw hw={.wiphy=&wiphy};
 struct cfg cfg={.device_family=IWL_DEVICE_FAMILY_22000,.gen2=true};struct trans trans={.mac_cfg=&cfg};
 struct iwl_mvm m={.fw=&fw,.hw=&hw,.trans=&trans,.sf_state=SF_INIT_OFF};hw.adapter=&m;
 vif.bss_conf.chanreq.oper.chan=&channel;vif.bss_conf.chanreq.oper.width=NL80211_CHAN_WIDTH_20_NOHT;
 for(unsigned i=0;i<6;i++)vif.bss_conf.addr[i]=i+2;
 for(link_version=1;link_version<=8;link_version++)for(unsigned band=0;band<2;band++)
 for(unsigned session=0;session<2;session++)for(unsigned stage=0;stage<3;stage++)for(unsigned failed=0;failed<2;failed++){
  channel.band=band;fw.ucode_capa.session=session;mvif.time_event_data.id=TE_MAX;
  link.active=stage==2;remove_events=length=0;fixture_failure=failed?-5:0;
  u32 changes=stage==0?0:stage==1?(LINK_CONTEXT_MODIFY_ACTIVE|LINK_CONTEXT_MODIFY_RATES_INFO):LINK_CONTEXT_MODIFY_ACTIVE;
  int result=iwl_mvm_link_changed(&m,&vif,&vif.bss_conf,changes,stage==1);
  printf("B %u %u %u %u %u %d %u %u %u ",link_version,band,session,stage,failed,result,link.active,remove_events,length);
  for(unsigned i=0;i<length;i++)printf("%02x",wire[i]);puts("");
 }
 if(TE_MAX==SESSION_PROTECT_CONF_ASSOC||TE_MAX==TE_BSS_STA_AGGRESSIVE_ASSOC)abort();
 fixture_failure=0;mac_version=1;
 for(link_version=1;link_version<=8;link_version++)for(unsigned band=0;band<2;band++)for(unsigned session=0;session<2;session++){
  channel.band=band;fw.ucode_capa.session=session;mvif.time_event_data.id=TE_MAX;
  link.active=false;link.phy_ctxt=NULL;link.fw_link_id=IWL_MVM_FW_LINK_ID_INVALID;mvif.uploaded=false;
  if(iwl_mvm_mld_mac_ctxt_add(&m,&vif)||iwl_mvm_add_link(&m,&vif,&vif.bss_conf))abort();
  for(unsigned i=0;i<NUM_PHY_CTX;i++){m.phy_ctxts[i].id=i;m.phy_ctxts[i].ref=0;}
  struct ieee80211_chanctx_conf ctx={.def={.chan=&channel,.width=NL80211_CHAN_WIDTH_20_NOHT},.rx_chains_static=1,.rx_chains_dynamic=1};
  if(__iwl_mvm_add_chanctx(&m,&ctx))abort();history_phy=&m.phy_ctxts[0];nh=0;history=true;power_calls=0;
  if(iwl_mvm_mld_assign_vif_chanctx(&hw,&vif,&vif.bss_conf,&ctx))abort();
  iwl_mvm_mld_unassign_vif_chanctx(&hw,&vif,&vif.bss_conf,&ctx);__iwl_mvm_remove_chanctx(&m,&ctx);history=false;
  if(nh!=8||power_calls!=2||m.phy_ctxts[0].ref||link.active||link.phy_ctxt||link.fw_link_id!=0)abort();
  for(unsigned step=0;step<nh;step++){
   printf("W %u %u %u %u %u %u %u ",link_version,band,session,step,ids[step],sizes[step],refs[step]);
   if(!sizes[step])printf("-");else for(unsigned i=0;i<sizes[step];i++)printf("%02x",payloads[step][i]);puts("");
  }
 }
 return 0;
}
'''
# Ensure fixture expansion did not alter any previous complete original body.
for file,name in [('mvm/mac-ctxt.c','iwl_mvm_get_mac_type'),('mvm/mac80211.c','iwl_mvm_is_nic_ack_enabled'),
 ('mvm/sf.c','iwl_mvm_sf_config'),('mvm/sf.c','iwl_mvm_sf_update'),('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_cmd_common'),
 ('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_cmd_sta'),('mvm/link.c','iwl_mvm_add_link'),('mvm/link.c','iwl_mvm_remove_link')]:assert function(file,name) in prefix,name
out.mkdir(parents=True,exist_ok=True);path=out/'linux-iwlwifi-mld-link.c';path.write_text(prefix+new+main)
exe=out/'linux-iwlwifi-mld-link'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(path),'-o',str(exe)],check=True,timeout=60)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True,timeout=60)
data=(out/'trace.txt').read_bytes();receipt={'linux_commit':'cc9de5d4b5ab6459f5774946aa3195ad51236fa8','sources':expected,'headers':headers,
 'base_unit_sha256':hashlib.sha256(unit).hexdigest(),'records':len(data.splitlines()),'trace_sha256':hashlib.sha256(data).hexdigest(),
 'scope':__doc__,'session_values_extracted':'TE_MAX, SESSION_PROTECT_CONF_ASSOC, TE_BSS_STA_AGGRESSIVE_ASSOC; untouched cold id differs from both active protection kinds',
 'scope_note':'B records are full LINK_CHANGED wire/error/host-state comparisons; W records preserve complete selected assign/unassign/remove-readd and source PHY reference callbacks. Power and PHY backend tokens have no fabricated bytes: their separate original wire oracles and native owner tests supply that proof.'}
(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
